package engine

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/fsutil"
	"github.com/rahuldhali/hull/internal/layer"
	"github.com/rahuldhali/hull/internal/oci/imagespec"
	"github.com/rahuldhali/hull/internal/oci/reference"
	"github.com/rahuldhali/hull/internal/types"
)

// CopyTo extracts a tar stream into a path inside a container.
//
// Every path in the archive is resolved with fsutil.SecureOpen against the
// container's merged rootfs, so a symlink planted inside the container — the
// root of every recent runtime breakout — cannot redirect a write onto the
// host. The daemon never calls filepath.Join on a container-controlled path.
func (e *Engine) CopyTo(ctx context.Context, idOrName, dstPath string, r io.Reader, opts CopyOptions) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()

	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	root, err := e.rootfsOf(c)
	if err != nil {
		return err
	}
	base, err := containerRelPath(dstPath)
	if err != nil {
		return err
	}
	if fi, serr := fsutil.SecureStat(root, base); serr == nil && !fi.IsDir() && !opts.AllowOverwriteDirWithFile {
		// Docker allows extracting onto a file only when the archive holds
		// exactly one file with the same name; refusing is the safe default.
		return fmt.Errorf("%w: %s inside %s is not a directory", ErrInvalid, dstPath, idShort(id))
	}

	tr := tar.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("engine: read the archive for %s: %w", idShort(id), err)
		}
		rel, err := containerRelPath(path.Join(base, hdr.Name))
		if err != nil {
			return err
		}
		if err := e.extractEntry(root, rel, hdr, tr); err != nil {
			return err
		}
	}
	e.emit(events.ActionCopy, c, map[string]string{"path": dstPath, "direction": "in"})
	return nil
}

// extractEntry writes one archive entry into the container, fd-relative.
func (e *Engine) extractEntry(root, rel string, hdr *tar.Header, tr io.Reader) error {
	mode := hdr.FileInfo().Mode()
	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := fsutil.SecureMkdirAll(root, rel, mode.Perm()); err != nil {
			return fmt.Errorf("engine: create %s in the container: %w", rel, err)
		}
		return nil
	case tar.TypeReg:
		if dir := path.Dir(rel); dir != "." && dir != "/" {
			if err := fsutil.SecureMkdirAll(root, dir, 0o755); err != nil {
				return fmt.Errorf("engine: create %s in the container: %w", dir, err)
			}
		}
		f, err := fsutil.SecureOpen(root, rel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode.Perm())
		if err != nil {
			return fmt.Errorf("engine: create %s in the container: %w", rel, err)
		}
		defer f.Close()
		if _, err := io.Copy(f, tr); err != nil {
			return fmt.Errorf("engine: write %s in the container: %w", rel, err)
		}
		return f.Close()
	case tar.TypeSymlink, tar.TypeLink:
		// A symlink or hardlink inside an uploaded archive is the exact shape
		// of a path-traversal attack, and hull has no fd-relative symlinkat
		// helper it can trust here, so it is refused rather than guessed at.
		return fmt.Errorf("%w: the archive contains a link (%s); hull refuses to create links inside a container's filesystem from an upload",
			ErrInvalid, hdr.Name)
	default:
		return fmt.Errorf("%w: the archive entry %s is of a type hull will not create inside a container",
			ErrInvalid, hdr.Name)
	}
}

// CopyFrom streams a path out of a container as a tar archive.
//
// The path is resolved with fsutil.SecureOpen against the merged rootfs, so a
// symlink inside the container cannot be used to read a host file.
func (e *Engine) CopyFrom(ctx context.Context, idOrName, srcPath string) (io.ReadCloser, CopyStat, error) {
	var stat CopyStat
	if err := e.checkOpen(); err != nil {
		return nil, stat, err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return nil, stat, err
	}
	c, err := e.lookup(id)
	if err != nil {
		return nil, stat, err
	}
	root, err := e.rootfsOf(c)
	if err != nil {
		return nil, stat, err
	}
	rel, err := containerRelPath(srcPath)
	if err != nil {
		return nil, stat, err
	}
	fi, err := fsutil.SecureStat(root, rel)
	if err != nil {
		return nil, stat, fmt.Errorf("%w: %s in %s: %w", ErrNotFound, srcPath, idShort(id), err)
	}
	stat = CopyStat{
		Name:  path.Base(rel),
		Size:  fi.Size(),
		Mode:  uint32(fi.Mode().Perm()),
		Mtime: fi.ModTime(),
	}

	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		err := e.tarPath(ctx, root, rel, tw)
		if cerr := tw.Close(); err == nil {
			err = cerr
		}
		_ = pw.CloseWithError(err)
	}()
	e.emit(events.ActionCopy, c, map[string]string{"path": srcPath, "direction": "out"})
	return pr, stat, nil
}

// tarPath writes one in-container path, and its contents when it is a
// directory, into tw.
func (e *Engine) tarPath(ctx context.Context, root, rel string, tw *tar.Writer) error {
	fi, err := fsutil.SecureStat(root, rel)
	if err != nil {
		return err
	}
	base := path.Base(rel)
	if !fi.IsDir() {
		return e.tarFile(root, rel, base, fi, tw)
	}
	prefix := path.Dir(rel)
	return walkSecure(ctx, root, rel, func(child string, cfi os.FileInfo) error {
		name := strings.TrimPrefix(child, prefix+"/")
		if prefix == "." || prefix == "/" {
			name = child
		}
		return e.tarFile(root, child, name, cfi, tw)
	})
}

// tarFile writes one entry.
func (e *Engine) tarFile(root, rel, name string, fi os.FileInfo, tw *tar.Writer) error {
	hdr, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return fmt.Errorf("engine: describe %s: %w", rel, err)
	}
	hdr.Name = name
	hdr.Format = tar.FormatPAX
	if fi.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
		hdr.Name += "/"
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("engine: write the header for %s: %w", rel, err)
	}
	if !fi.Mode().IsRegular() {
		return nil
	}
	f, err := fsutil.SecureOpen(root, rel, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("engine: open %s: %w", rel, err)
	}
	defer f.Close()
	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("engine: read %s: %w", rel, err)
	}
	return nil
}

// walkSecure walks a directory inside a container root, resolving every step
// through fsutil so a symlink cannot lead the walk out.
func walkSecure(ctx context.Context, root, rel string, fn func(string, os.FileInfo) error) error {
	fi, err := fsutil.SecureStat(root, rel)
	if err != nil {
		return err
	}
	if err := fn(rel, fi); err != nil {
		return err
	}
	if !fi.IsDir() {
		return nil
	}
	dir, err := fsutil.SecureOpen(root, rel, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	names, err := dir.Readdirnames(-1)
	dir.Close()
	if err != nil {
		return fmt.Errorf("engine: list %s: %w", rel, err)
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := walkSecure(ctx, root, path.Join(rel, name), fn); err != nil {
			return err
		}
	}
	return nil
}

// containerRelPath turns an in-container path into the root-relative form
// fsutil's secure helpers require.
//
// A path that climbs out with ".." is clamped to the container root rather
// than reaching the host, because the path is cleaned as if it were absolute:
// "../../etc/passwd" becomes "etc/passwd" inside the container. The explicit
// check that follows is belt and braces for a path Clean cannot absorb.
func containerRelPath(p string) (string, error) {
	clean := path.Clean("/" + filepath.ToSlash(p))
	rel := strings.TrimPrefix(clean, "/")
	if rel == "" {
		rel = "."
	}
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("%w: %q escapes the container filesystem", ErrInvalid, p)
	}
	return rel, nil
}

// rootfsOf returns a container's merged rootfs, mounting it if a crash or a
// daemon restart left it unmounted.
func (e *Engine) rootfsOf(c *types.Container) (string, error) {
	if mounted, err := e.snaps.IsMounted(c.ID); err == nil && mounted && c.RootFS != "" {
		return c.RootFS, nil
	}
	root, err := e.snaps.Mount(context.Background(), c.ID, c.SnapshotID, false)
	if err != nil {
		return "", fmt.Errorf("engine: mount the rootfs of %s: %w", idShort(c.ID), err)
	}
	return root, nil
}

// Export writes a container's whole filesystem to w as a tar archive, which is
// what "hull export" produces.
func (e *Engine) Export(ctx context.Context, idOrName string, w io.Writer) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	root, err := e.rootfsOf(c)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			if link, ierr = os.Readlink(p); ierr != nil {
				return ierr
			}
		}
		hdr, herr := tar.FileInfoHeader(info, link)
		if herr != nil {
			return herr
		}
		hdr.Name = filepath.ToSlash(rel)
		hdr.Format = tar.FormatPAX
		if info.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, oerr := os.Open(p)
		if oerr != nil {
			return oerr
		}
		defer f.Close()
		_, cerr := io.Copy(tw, f)
		return cerr
	})
	if cerr := tw.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("engine: export %s: %w", idShort(id), err)
	}
	e.emit(events.ActionExport, c, nil)
	return nil
}

// Commit turns a container's writable layer into a new image layer.
//
// The container is frozen for the duration unless the caller says otherwise,
// so the captured filesystem is a consistent point in time. The new layer is
// stored uncompressed, which the OCI image-spec allows and which makes its
// digest and its DiffID the same value.
func (e *Engine) Commit(ctx context.Context, idOrName string, opts CommitOptions) (*types.Image, error) {
	if err := e.checkOpen(); err != nil {
		return nil, err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return nil, err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return nil, err
	}
	defer unlock()

	c, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	base, err := e.images.Get(c.Image)
	if err != nil {
		return nil, err
	}
	pause := opts.Pause == nil || *opts.Pause
	froze := false
	if pause && c.State == types.StateRunning {
		if ferr := e.freeze(id); ferr != nil {
			e.log.Warn("hull: committing without freezing the container",
				"container", idShort(id), "err", ferr)
		} else {
			froze = true
		}
	}
	defer func() {
		if froze {
			if terr := e.thaw(id); terr != nil {
				e.log.Error("hull: a container was left frozen after a commit",
					"container", idShort(id), "err", terr)
			}
		}
	}()

	upper, err := e.snaps.UpperPath(id)
	if err != nil {
		return nil, mapSnapshotError(err)
	}
	writer, err := e.content.Writer(ctx, "", content.SizeUnknown)
	if err != nil {
		return nil, fmt.Errorf("engine: open a blob writer: %w", err)
	}
	defer writer.Close()
	if _, err := layer.Diff(ctx, upper, "", writer); err != nil {
		return nil, fmt.Errorf("engine: diff the writable layer of %s: %w", idShort(id), err)
	}
	layerInfo, err := writer.Commit()
	if err != nil {
		return nil, fmt.Errorf("engine: store the committed layer: %w", err)
	}

	img, err := e.buildCommittedImage(ctx, c, base, layerInfo, opts)
	if err != nil {
		return nil, err
	}
	e.emit(events.ActionCommit, c, map[string]string{"image": img.ID})
	return img, nil
}

// buildCommittedImage writes the config and manifest of a committed image and
// registers it.
func (e *Engine) buildCommittedImage(ctx context.Context, c *types.Container, base *types.Image, layerInfo content.Info, opts CommitOptions) (*types.Image, error) {
	cfgRaw, err := e.content.ReadAll(base.ID)
	if err != nil {
		return nil, fmt.Errorf("engine: read the config of %s: %w", idShort(base.ID), err)
	}
	var cfg imagespec.ImageConfig
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return nil, fmt.Errorf("engine: parse the config of %s: %w", idShort(base.ID), err)
	}

	// The committed image inherits the container's effective configuration,
	// which is what makes "run it, change it, commit it, run it again" behave.
	cfg.Config.Env = append([]string(nil), c.Config.Env...)
	cfg.Config.Entrypoint = append([]string(nil), c.Config.Entrypoint...)
	cfg.Config.Cmd = append([]string(nil), c.Config.Cmd...)
	cfg.Config.User = c.Config.User
	cfg.Config.WorkingDir = c.Config.WorkingDir
	cfg.Config.Labels = copyStringMap(c.Config.Labels)
	cfg.Config.ExposedPorts = copySet(c.Config.ExposedPorts)
	cfg.Config.Volumes = copySet(c.Config.Volumes)
	cfg.Config.StopSignal = c.Config.StopSignal
	if err := applyCommitChanges(&cfg.Config, opts.Changes); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	cfg.Created = &now
	if opts.Author != "" {
		cfg.Author = opts.Author
	}
	cfg.RootFS.Type = imagespec.RootFSTypeLayers
	cfg.RootFS.DiffIDs = append(append([]string(nil), base.DiffIDs...), layerInfo.Digest)
	cfg.History = append(cfg.History, imagespec.History{
		Created:   &now,
		CreatedBy: "hull commit",
		Author:    opts.Author,
		Comment:   opts.Comment,
	})

	newCfgRaw, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("engine: encode the committed config: %w", err)
	}
	cfgDigest := content.DigestBytes(newCfgRaw)
	if !e.content.Exists(cfgDigest) {
		if _, err := e.content.WriteBlob(ctx, bytes.NewReader(newCfgRaw), cfgDigest, int64(len(newCfgRaw))); err != nil {
			return nil, fmt.Errorf("engine: store the committed config: %w", err)
		}
	}

	baseLayers, err := e.manifestLayers(base)
	if err != nil {
		return nil, err
	}
	m := imagespec.Manifest{
		SchemaVersion: imagespec.SchemaVersion,
		MediaType:     imagespec.MediaTypeImageManifest,
		Config: types.Descriptor{
			MediaType: imagespec.MediaTypeImageConfig,
			Digest:    cfgDigest,
			Size:      int64(len(newCfgRaw)),
		},
		Layers: append(append([]types.Descriptor(nil), baseLayers...), types.Descriptor{
			MediaType: imagespec.MediaTypeImageLayer,
			Digest:    layerInfo.Digest,
			Size:      layerInfo.Size,
		}),
	}
	manifestRaw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("engine: encode the committed manifest: %w", err)
	}
	manifestDigest := content.DigestBytes(manifestRaw)
	if !e.content.Exists(manifestDigest) {
		if _, err := e.content.WriteBlob(ctx, bytes.NewReader(manifestRaw), manifestDigest, int64(len(manifestRaw))); err != nil {
			return nil, fmt.Errorf("engine: store the committed manifest: %w", err)
		}
	}

	img, err := imageFromManifest(manifestRaw, newCfgRaw, m.MediaType, m.Layers)
	if err != nil {
		return nil, err
	}
	if opts.Repo != "" {
		ref := opts.Repo
		if opts.Tag != "" {
			ref += ":" + opts.Tag
		}
		parsed, perr := reference.Parse(ref)
		if perr != nil {
			return nil, fmt.Errorf("%w: commit target %q: %w", ErrInvalid, ref, perr)
		}
		img.RepoTags = []string{parsed.FamiliarString()}
	}

	// Extracting the new layer makes the image immediately runnable, which is
	// the whole point of committing it.
	if err := e.snaps.Unpack(ctx, img, e.content, m.Layers, nil); err != nil {
		return nil, fmt.Errorf("engine: unpack the committed image: %w", err)
	}
	return e.images.Put(img)
}

// applyCommitChanges applies the build instructions "hull commit --change"
// accepts to an image config.
func applyCommitChanges(cfg *imagespec.ConfigBlock, changes []string) error {
	for _, raw := range changes {
		instr, arg, _ := strings.Cut(strings.TrimSpace(raw), " ")
		arg = strings.TrimSpace(arg)
		switch strings.ToUpper(instr) {
		case "ENV":
			k, v, ok := strings.Cut(arg, "=")
			if !ok {
				k, v, ok = strings.Cut(arg, " ")
			}
			if !ok || k == "" {
				return fmt.Errorf("%w: --change %q is not ENV KEY=VALUE", ErrInvalid, raw)
			}
			cfg.Env = setEnv(cfg.Env, strings.TrimSpace(k), strings.TrimSpace(v))
		case "LABEL":
			k, v, ok := strings.Cut(arg, "=")
			if !ok || k == "" {
				return fmt.Errorf("%w: --change %q is not LABEL key=value", ErrInvalid, raw)
			}
			if cfg.Labels == nil {
				cfg.Labels = map[string]string{}
			}
			cfg.Labels[strings.TrimSpace(k)] = strings.TrimSpace(v)
		case "CMD":
			list, err := parseJSONOrShell(arg)
			if err != nil {
				return err
			}
			cfg.Cmd = list
		case "ENTRYPOINT":
			list, err := parseJSONOrShell(arg)
			if err != nil {
				return err
			}
			cfg.Entrypoint = list
		case "USER":
			cfg.User = arg
		case "WORKDIR":
			cfg.WorkingDir = arg
		case "STOPSIGNAL":
			if _, err := ParseSignal(arg); err != nil {
				return err
			}
			cfg.StopSignal = arg
		case "EXPOSE":
			if cfg.ExposedPorts == nil {
				cfg.ExposedPorts = map[string]struct{}{}
			}
			spec := arg
			if !strings.Contains(spec, "/") {
				spec += "/tcp"
			}
			cfg.ExposedPorts[spec] = struct{}{}
		case "VOLUME":
			list, err := parseJSONOrShell(arg)
			if err != nil {
				return err
			}
			if cfg.Volumes == nil {
				cfg.Volumes = map[string]struct{}{}
			}
			for _, v := range list {
				cfg.Volumes[v] = struct{}{}
			}
		default:
			return fmt.Errorf("%w: --change %q; hull understands ENV, LABEL, CMD, ENTRYPOINT, USER, WORKDIR, STOPSIGNAL, EXPOSE and VOLUME",
				ErrInvalid, raw)
		}
	}
	return nil
}

// setEnv replaces or appends one KEY=VALUE entry.
func setEnv(env []string, key, value string) []string {
	entry := key + "=" + value
	for i, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			env[i] = entry
			return env
		}
	}
	return append(env, entry)
}

// parseJSONOrShell reads either a JSON array (the exec form) or a bare string
// (the shell form) as a command list.
func parseJSONOrShell(arg string) ([]string, error) {
	arg = strings.TrimSpace(arg)
	if strings.HasPrefix(arg, "[") {
		var list []string
		if err := json.Unmarshal([]byte(arg), &list); err != nil {
			return nil, fmt.Errorf("%w: %q is not a JSON array: %w", ErrInvalid, arg, err)
		}
		return list, nil
	}
	if arg == "" {
		return nil, nil
	}
	return []string{"/bin/sh", "-c", arg}, nil
}
