package cli

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// tarOptions configures [tarPath].
type tarOptions struct {
	// Rename replaces the top-level name every entry is written under, which
	// is how "hull cp ./dir ctr:/dst/newname" works.
	Rename string
	// Exclude reports whether a slash-separated relative path should be left
	// out. A directory that is excluded is not descended into.
	Exclude func(rel string) bool
	// FollowLinks resolves a symlink at the root instead of archiving the
	// link itself, which is what "cp -L" asks for.
	FollowLinks bool
}

// tarPath writes a host file or directory as a tar stream.
//
// The archive's entry names are relative and rooted at the source's base name,
// which is the shape the engine's PUT /archive endpoint expects: the contents
// land inside the destination directory rather than replacing it.
func tarPath(w io.Writer, src string, opts tarOptions) error {
	src = filepath.Clean(src)
	info, err := statPath(src, opts.FollowLinks)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	base := filepath.Base(src)
	if opts.Rename != "" {
		base = opts.Rename
	}
	if !info.IsDir() {
		if err := writeTarEntry(tw, src, base, info); err != nil {
			return err
		}
		return tw.Close()
	}
	root := src
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return fmt.Errorf("resolving %s: %w", p, relErr)
		}
		rel = filepath.ToSlash(rel)
		name := base
		if rel != "." {
			name = path.Join(base, rel)
		}
		if opts.Exclude != nil && rel != "." && opts.Exclude(rel) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		fi, infoErr := d.Info()
		if infoErr != nil {
			return fmt.Errorf("stat %s: %w", p, infoErr)
		}
		return writeTarEntry(tw, p, name, fi)
	})
	if walkErr != nil {
		_ = tw.Close()
		return walkErr
	}
	return tw.Close()
}

// newTarWriter starts a tar writer on an existing buffer, which is how a
// build appends an out-of-context Dockerfile to a finished archive.
func newTarWriter(w io.Writer) *tar.Writer { return tar.NewWriter(w) }

// statPath stats a path, following a symlink only when asked.
func statPath(p string, follow bool) (os.FileInfo, error) {
	var (
		info os.FileInfo
		err  error
	)
	if follow {
		info, err = os.Stat(p)
	} else {
		info, err = os.Lstat(p)
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p, err)
	}
	return info, nil
}

// writeTarEntry writes one file, directory or symlink into the archive.
func writeTarEntry(tw *tar.Writer, srcPath, name string, fi os.FileInfo) error {
	link := ""
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(srcPath)
		if err != nil {
			return fmt.Errorf("reading symlink %s: %w", srcPath, err)
		}
		link = target
	}
	hdr, err := tar.FileInfoHeader(fi, link)
	if err != nil {
		return fmt.Errorf("building header for %s: %w", srcPath, err)
	}
	hdr.Name = name
	if fi.IsDir() {
		hdr.Name += "/"
	}
	// Windows has no uid/gid and no executable bit; normalising here keeps an
	// archive built on Windows from landing in the container owned by nobody
	// with a mode of 0666.
	hdr.Uid, hdr.Gid = 0, 0
	hdr.Uname, hdr.Gname = "", ""
	if hdr.ModTime.IsZero() {
		hdr.ModTime = time.Now()
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("writing header for %s: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", srcPath, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("copying %s: %w", srcPath, err)
	}
	return nil
}

// untarTo extracts a tar stream into a host directory.
//
// Every entry name is resolved against the destination and rejected if it
// escapes, because the archive comes from inside a container and a container's
// filesystem is attacker-controlled by assumption. The check is on the cleaned
// relative path, and a symlink is written as a symlink but never followed
// during extraction.
func untarTo(r io.Reader, dst string, rename string) error {
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return fmt.Errorf("resolving %s: %w", dst, err)
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading archive: %w", err)
		}
		name := hdr.Name
		if rename != "" {
			name = replaceFirstSegment(name, rename)
		}
		target, err := securePath(dstAbs, name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, dirMode(hdr.FileInfo().Mode())); err != nil {
				return fmt.Errorf("creating %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("creating %s: %w", filepath.Dir(target), err)
			}
			if err := writeRegular(target, tr, hdr.FileInfo().Mode()); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("creating %s: %w", filepath.Dir(target), err)
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				// A Windows host without developer mode cannot create
				// symlinks. That is worth a warning, not a failed copy.
				return fmt.Errorf("creating symlink %s: %w", target, err)
			}
		case tar.TypeLink:
			source, err := securePath(dstAbs, hdr.Linkname)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Link(source, target); err != nil {
				return fmt.Errorf("creating hard link %s: %w", target, err)
			}
		default:
			// Devices, fifos and sockets cannot be recreated on a host that
			// may be Windows, and silently dropping them is better than
			// aborting a directory copy over one entry.
			continue
		}
	}
}

// writeRegular creates one regular file from the archive.
func writeRegular(target string, r io.Reader, mode os.FileMode) error {
	f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm())
	if err != nil {
		return fmt.Errorf("creating %s: %w", target, err)
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing %s: %w", target, err)
	}
	return f.Close()
}

// dirMode gives a directory a usable mode even when the archive recorded none.
func dirMode(m os.FileMode) os.FileMode {
	if m.Perm() == 0 {
		return 0o755
	}
	return m.Perm()
}

// securePath joins one archive entry name onto the destination and refuses
// anything that would land outside it.
func securePath(dst, name string) (string, error) {
	// Backslashes are checked as separators even on Linux: the same archive
	// may be extracted on a Windows host, where they are, and an entry that
	// only escapes on one platform is still an entry designed to escape.
	normalised := strings.ReplaceAll(name, `\`, "/")
	for _, segment := range strings.Split(normalised, "/") {
		if segment == ".." {
			return "", Errorf("refusing archive entry %q: it escapes %s", name, dst)
		}
	}
	// A leading slash is neutralised rather than refused: an archive with
	// absolute names is merely sloppy, and rooting it at the destination is
	// what every tar tool does.
	clean := path.Clean("/" + normalised)
	rel := strings.TrimPrefix(clean, "/")
	if rel == "" {
		return dst, nil
	}
	target := filepath.Join(dst, filepath.FromSlash(rel))
	if target != dst && !strings.HasPrefix(target, dst+string(filepath.Separator)) {
		return "", Errorf("refusing archive entry %q: it escapes %s", name, dst)
	}
	return target, nil
}

// replaceFirstSegment swaps the leading path element of an archive entry,
// which is how a copy renames what it extracts.
func replaceFirstSegment(name, with string) string {
	name = strings.TrimPrefix(name, "./")
	first, rest, ok := strings.Cut(name, "/")
	_ = first
	if !ok {
		return with
	}
	if rest == "" {
		return with
	}
	return with + "/" + rest
}

// dockerIgnore is a compiled .dockerignore, used to keep a build context from
// carrying a .git directory or a node_modules tree to the engine.
type dockerIgnore struct {
	patterns []ignorePattern
}

// ignorePattern is one .dockerignore line.
type ignorePattern struct {
	// pattern is the slash-separated glob.
	pattern string
	// negate marks a "!" line, which re-includes a previously excluded path.
	negate bool
}

// loadDockerIgnore reads the .dockerignore beside a build context, returning
// an empty matcher when there is none.
func loadDockerIgnore(dir string) (*dockerIgnore, error) {
	buf, err := os.ReadFile(filepath.Join(dir, ".dockerignore"))
	if err != nil {
		if os.IsNotExist(err) {
			return &dockerIgnore{}, nil
		}
		return nil, fmt.Errorf("reading .dockerignore: %w", err)
	}
	di := &dockerIgnore{}
	for _, line := range strings.Split(string(buf), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := ignorePattern{}
		if strings.HasPrefix(line, "!") {
			p.negate = true
			line = strings.TrimSpace(line[1:])
		}
		p.pattern = path.Clean(strings.ReplaceAll(line, `\`, "/"))
		if p.pattern == "." || p.pattern == "" {
			continue
		}
		di.patterns = append(di.patterns, p)
	}
	return di, nil
}

// Match reports whether a slash-separated relative path is excluded. Later
// patterns win, which is what makes a "!" line able to re-include a path.
func (d *dockerIgnore) Match(rel string) bool {
	if d == nil {
		return false
	}
	excluded := false
	for _, p := range d.patterns {
		if matchIgnore(p.pattern, rel) {
			excluded = !p.negate
		}
	}
	return excluded
}

// matchIgnore applies one pattern to a path, matching a directory pattern
// against everything beneath it as .dockerignore does.
func matchIgnore(pattern, rel string) bool {
	if ok, _ := path.Match(pattern, rel); ok {
		return true
	}
	if strings.HasPrefix(rel, pattern+"/") {
		return true
	}
	// "**/x" matches x at any depth.
	if strings.HasPrefix(pattern, "**/") {
		tail := pattern[3:]
		segments := strings.Split(rel, "/")
		for i := range segments {
			if ok, _ := path.Match(tail, strings.Join(segments[i:], "/")); ok {
				return true
			}
		}
	}
	return false
}
