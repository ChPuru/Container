//go:build linux

package snapshot

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/fsutil"
	"github.com/rahuldhali/hull/internal/layer"
	"github.com/rahuldhali/hull/internal/types"
)

// New opens (creating if necessary) a snapshotter rooted at root.
//
// feat carries the overlay facts. Passing the zero Features makes New probe the
// host itself with Detect, which mounts a throwaway overlay *under root* — the
// only honest way to learn both whether overlayfs works at all and whether it
// works on the filesystem hull's root actually lives on. A caller that already
// probed (hull doctor, say) can pass its own Features and skip the mount.
//
// A failed probe is not a failed New: pulling and unpacking images needs no
// mount privileges at all, so the snapshotter opens anyway and records the
// diagnosis. Mount is where it surfaces, as an error wrapping
// ErrOverlayUnsupported; Features().Err() returns the same diagnosis at any
// time, which is what a daemon should report at startup.
func New(root string, feat Features) (*Snapshotter, error) {
	if root == "" {
		return nil, errors.New("snapshot: root must not be empty")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("snapshot: absolute path for %q: %w", root, err)
	}
	abs = filepath.Clean(abs)
	if err := checkOptionPath("root", abs); err != nil {
		return nil, err
	}
	for _, d := range []struct {
		name string
		perm os.FileMode
	}{
		{"", dirPerm},
		{DirSnapshots, dirPerm},
		{DirContainers, dirPerm},
		{DirCheckpoints, dirPerm},
		{DirLinks, layerDirPerm},
	} {
		p := abs
		if d.name != "" {
			p = filepath.Join(abs, d.name)
		}
		if err := os.MkdirAll(p, d.perm); err != nil {
			return nil, fmt.Errorf("snapshot: create %s: %w", p, err)
		}
	}

	if !feat.MountTested {
		probed, perr := Detect(context.Background(), abs)
		if perr != nil {
			return nil, fmt.Errorf("snapshot: probing overlayfs under %s: %w", abs, perr)
		}
		// Keep anything the caller had already filled in that the probe cannot
		// discover, then take the probe's verdict.
		if feat.KernelRelease != "" {
			probed.KernelRelease = feat.KernelRelease
		}
		feat = probed
	}

	return &Snapshotter{root: abs, feat: feat, preps: make(map[string]*prep)}, nil
}

// Detect probes overlayfs on this host.
//
// probeDir chooses where the throwaway mount is built; pass hull's root so the
// probe exercises the filesystem the snapshotter will actually use, because
// overlayfs refuses an upperdir on 9p/drvfs (a Windows drive under /mnt) and on
// another overlay. An empty probeDir falls back to the system temporary
// directory, which tests a different filesystem and is therefore only a hint.
//
// Detect never returns an error for "overlay does not work here"; that is
// reported in the returned Features, and Features.Err turns it into an
// actionable message. It returns an error only when the probe itself could not
// be carried out.
func Detect(ctx context.Context, probeDir string) (Features, error) {
	var f Features
	if err := ctx.Err(); err != nil {
		return f, err
	}

	f.Supported = procFilesystemsHas("overlay")
	f.Redirect = moduleParam("redirect_dir")
	f.Metacopy = moduleParam("metacopy")
	f.Index = moduleParam("index")
	f.Xino = moduleParam("xino_auto")
	f.RedirectAlwaysFollow = moduleParam("redirect_always_follow")
	f.UserNS = inUserNamespace()

	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		f.KernelRelease = nulTerminated(uts.Release[:])
	}
	f.LowerdirPlus = kernelAtLeast(f.KernelRelease, 6, 7)
	f.IdmappedLayers = kernelAtLeast(f.KernelRelease, 5, 19)

	if !f.Supported {
		return f, nil
	}

	base := probeDir
	if base == "" {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, ".hull-overlay-probe-")
	if err != nil {
		return f, fmt.Errorf("snapshot: create overlay probe directory under %s: %w", base, err)
	}
	defer os.RemoveAll(dir)

	for _, sub := range []string{"l1", "up", "work", "merged"} {
		if err := os.Mkdir(filepath.Join(dir, sub), layerDirPerm); err != nil {
			return f, fmt.Errorf("snapshot: create overlay probe directory: %w", err)
		}
	}
	merged := filepath.Join(dir, "merged")

	// Inside a user namespace overlayfs must be told to use user.* xattrs, so
	// that is the first thing to try there; everywhere else the plain form is
	// correct and userxattr would only make the kernel reject the mount.
	attempts := []bool{false}
	if f.UserNS {
		attempts = []bool{true, false}
	}
	f.MountTested = true
	var lastErr error
	for _, ux := range attempts {
		opts, berr := buildOverlayOptions(
			[]string{filepath.Join(dir, "l1")},
			filepath.Join(dir, "up"),
			filepath.Join(dir, "work"),
			ux,
		)
		if berr != nil {
			return f, berr
		}
		if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
			lastErr = fmt.Errorf("mount -t overlay -o %s: %w", opts, err)
			continue
		}
		_ = unix.Unmount(merged, unix.MNT_DETACH)
		f.MountOK = true
		f.UserXattr = ux
		return f, nil
	}
	if lastErr != nil {
		f.MountError = lastErr.Error()
	}
	return f, nil
}

// procFilesystemsHas reports whether /proc/filesystems lists a filesystem.
func procFilesystemsHas(name string) bool {
	b, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(strings.TrimPrefix(line, "nodev")) == name {
			return true
		}
	}
	return false
}

// moduleParam reads one overlay module parameter, returning "" when the kernel
// has overlayfs built in without exposing it.
func moduleParam(name string) string {
	b, err := os.ReadFile(filepath.Join("/sys/module/overlay/parameters", name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// inUserNamespace reports whether the process is in a user namespace other than
// the initial one, which is what decides between trusted.* and user.* overlay
// xattrs. The initial namespace has exactly the identity mapping.
func inUserNamespace() bool {
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false
	}
	return strings.Join(strings.Fields(string(b)), " ") != "0 0 4294967295"
}

// nulTerminated turns a NUL-padded C string from Utsname into a Go string.
func nulTerminated(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// kernelAtLeast reports whether a uname release such as
// "5.15.167.4-microsoft-standard-WSL2" is at least major.minor.
func kernelAtLeast(release string, major, minor int) bool {
	if release == "" {
		return false
	}
	nums := strings.SplitN(release, ".", 3)
	if len(nums) < 2 {
		return false
	}
	maj, err := strconv.Atoi(strings.TrimSpace(nums[0]))
	if err != nil {
		return false
	}
	minStr := nums[1]
	for i := 0; i < len(minStr); i++ {
		if minStr[i] < '0' || minStr[i] > '9' {
			minStr = minStr[:i]
			break
		}
	}
	min, err := strconv.Atoi(minStr)
	if err != nil {
		return false
	}
	return maj > major || (maj == major && min >= minor)
}

// opaqueXattr names the xattr that marks a directory opaque, which differs
// between a privileged and a rootless overlay.
func (s *Snapshotter) opaqueXattr() string {
	if s.feat.UserXattr {
		return layer.OpaqueXattrUser
	}
	return layer.OpaqueXattrTrusted
}

// ---------- locking ----------

// lockWait takes an exclusive flock on path, retrying with backoff until it is
// free or ctx is done. It exists because fsutil.FileLock blocks in the kernel
// with no way to cancel, and hull never wants an uninterruptible daemon.
func lockWait(ctx context.Context, path string) (func() error, error) {
	delay := 2 * time.Millisecond
	const maxDelay = 100 * time.Millisecond
	for {
		l, err := fsutil.TryFileLock(path)
		if err == nil {
			return l.Unlock, nil
		}
		if !errors.Is(err, fsutil.ErrLocked) {
			return nil, fmt.Errorf("snapshot: lock %s: %w", path, err)
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, fmt.Errorf("snapshot: waiting for lock %s: %w", path, ctx.Err())
		case <-t.C:
		}
		if delay < maxDelay {
			delay *= 2
		}
	}
}

// ---------- prepare / commit ----------

// Prepare creates the directory a layer will be extracted into and returns it.
//
// The returned path is <root>/snapshots/<chainID>/fs. It is empty on return: a
// partial extraction left by a previous crash is discarded, because a snapshot
// without its .complete marker cannot be trusted.
//
// Prepare takes a lock on the chain ID and holds it until Commit or Abort, so
// two concurrent pulls that share a base layer cannot extract into the same
// directory. The lock is both in-process (a second Prepare for the same chain
// ID in this process waits) and cross-process (an flock, so a second hulld
// waits too). Every Prepare must therefore be paired with exactly one Commit or
// Abort; the usual shape is a deferred Abort that Commit makes a no-op.
//
// parentChainID must already be committed, or be empty for a base layer.
func (s *Snapshotter) Prepare(ctx context.Context, chainID string, parentChainID string) (string, error) {
	cid, err := NormalizeDigest(chainID)
	if err != nil {
		return "", fmt.Errorf("snapshot: prepare: %w", err)
	}
	parent := ""
	if parentChainID != "" {
		parent, err = NormalizeDigest(parentChainID)
		if err != nil {
			return "", fmt.Errorf("snapshot: prepare %s: parent: %w", cid, err)
		}
		if !s.Exists(parent) {
			return "", fmt.Errorf("snapshot: prepare %s: parent %s is not committed: %w", cid, parent, ErrNotFound)
		}
	}

	// Serialise inside this process first, so that the flock below is only ever
	// contended by another process and never spins against ourselves.
	if err := s.waitForPrep(ctx, cid); err != nil {
		return "", err
	}
	release := func() { s.releasePrep(cid, nil) }

	dir, err := s.SnapshotDir(cid)
	if err != nil {
		release()
		return "", err
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		release()
		return "", fmt.Errorf("snapshot: create %s: %w", dir, err)
	}
	unlock, err := lockWait(ctx, filepath.Join(dir, FileLock))
	if err != nil {
		release()
		return "", err
	}
	fail := func(e error) (string, error) {
		_ = unlock()
		release()
		return "", e
	}

	if s.Exists(cid) {
		return fail(fmt.Errorf("snapshot: prepare %s: %w", cid, ErrExists))
	}

	fsDir := filepath.Join(dir, DirFS)
	if err := os.RemoveAll(fsDir); err != nil {
		return fail(fmt.Errorf("snapshot: discard partial snapshot %s: %w", cid, err))
	}
	if err := os.Mkdir(fsDir, layerDirPerm); err != nil {
		return fail(fmt.Errorf("snapshot: create %s: %w", fsDir, err))
	}
	// chmod explicitly: mkdir is filtered by the umask, and a layer directory
	// that is not world-traversable breaks a container running as a plain uid.
	if err := os.Chmod(fsDir, layerDirPerm); err != nil {
		return fail(fmt.Errorf("snapshot: chmod %s: %w", fsDir, err))
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, FileParent), []byte(parent), filePerm); err != nil {
		return fail(fmt.Errorf("snapshot: record parent of %s: %w", cid, err))
	}

	s.mu.Lock()
	if p := s.preps[cid]; p != nil {
		p.parent = parent
		p.unlock = unlock
	}
	s.mu.Unlock()
	return fsDir, nil
}

// waitForPrep claims the in-process prepare slot for cid, waiting for any other
// goroutine that already holds it.
func (s *Snapshotter) waitForPrep(ctx context.Context, cid string) error {
	for {
		s.mu.Lock()
		p, busy := s.preps[cid]
		if !busy {
			s.preps[cid] = &prep{done: make(chan struct{})}
			s.mu.Unlock()
			return nil
		}
		wait := p.done
		s.mu.Unlock()

		select {
		case <-wait:
		case <-ctx.Done():
			return fmt.Errorf("snapshot: waiting to prepare %s: %w", cid, ctx.Err())
		}
		if s.Exists(cid) {
			return fmt.Errorf("snapshot: prepare %s: %w", cid, ErrExists)
		}
	}
}

// releasePrep drops the in-process slot and the flock, waking anyone waiting.
// It returns the first error, preferring the caller's.
func (s *Snapshotter) releasePrep(cid string, err error) error {
	s.mu.Lock()
	p := s.preps[cid]
	delete(s.preps, cid)
	s.mu.Unlock()
	if p == nil {
		return err
	}
	if p.unlock != nil {
		if uerr := p.unlock(); uerr != nil && err == nil {
			err = fmt.Errorf("snapshot: release lock for %s: %w", cid, uerr)
		}
	}
	close(p.done)
	return err
}

// Commit marks a prepared snapshot complete.
//
// It writes meta.json first and the .complete marker second, each atomically
// and each followed by an fsync of the directory, so a crash between the two
// leaves a snapshot that Exists still reports as absent and that Prepare will
// discard and extract again. Commit releases the lock Prepare took.
func (s *Snapshotter) Commit(ctx context.Context, chainID string, diffID string, size int64) error {
	cid, err := NormalizeDigest(chainID)
	if err != nil {
		return fmt.Errorf("snapshot: commit: %w", err)
	}
	did, err := NormalizeDigest(diffID)
	if err != nil {
		return fmt.Errorf("snapshot: commit %s: diff ID: %w", cid, err)
	}
	if size < 0 {
		return fmt.Errorf("snapshot: commit %s: negative size %d", cid, size)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := s.SnapshotDir(cid)
	if err != nil {
		return err
	}
	if !fsutil.IsDir(filepath.Join(dir, DirFS)) {
		return fmt.Errorf("snapshot: commit %s: %s was never prepared: %w", cid, dir, ErrNotFound)
	}

	s.mu.Lock()
	p := s.preps[cid]
	s.mu.Unlock()

	parent := ""
	if p != nil {
		parent = p.parent
	} else if b, rerr := os.ReadFile(filepath.Join(dir, FileParent)); rerr == nil {
		parent = strings.TrimSpace(string(b))
	}

	info := Info{
		ChainID: cid,
		DiffID:  did,
		Parent:  parent,
		Size:    size,
		Created: time.Now().UTC(),
		Kind:    SnapshotKindLayer,
	}
	if err := fsutil.WriteJSONAtomic(filepath.Join(dir, FileMeta), info, filePerm); err != nil {
		return s.releasePrep(cid, fmt.Errorf("snapshot: write %s for %s: %w", FileMeta, cid, err))
	}
	if err := fsutil.FSync(dir); err != nil {
		return s.releasePrep(cid, fmt.Errorf("snapshot: fsync %s: %w", dir, err))
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, FileComplete), []byte(cid+"\n"), filePerm); err != nil {
		return s.releasePrep(cid, fmt.Errorf("snapshot: write %s for %s: %w", FileComplete, cid, err))
	}
	if err := fsutil.FSync(dir); err != nil {
		return s.releasePrep(cid, fmt.Errorf("snapshot: fsync %s: %w", dir, err))
	}
	_ = os.Remove(filepath.Join(dir, FileParent))
	return s.releasePrep(cid, nil)
}

// Abort discards a prepared but uncommitted snapshot and releases its lock. It
// is safe to call after Commit, where it does nothing, so the idiomatic use is
// a deferred Abort right after Prepare.
func (s *Snapshotter) Abort(ctx context.Context, chainID string) error {
	cid, err := NormalizeDigest(chainID)
	if err != nil {
		return fmt.Errorf("snapshot: abort: %w", err)
	}
	s.mu.Lock()
	_, busy := s.preps[cid]
	s.mu.Unlock()
	if !busy {
		return nil
	}
	dir, err := s.SnapshotDir(cid)
	if err != nil {
		return s.releasePrep(cid, err)
	}
	var rerr error
	if !s.Exists(cid) {
		if err := os.RemoveAll(filepath.Join(dir, DirFS)); err != nil {
			rerr = fmt.Errorf("snapshot: discard partial snapshot %s: %w", cid, err)
		}
		_ = os.Remove(filepath.Join(dir, FileParent))
		_ = os.Remove(filepath.Join(dir, FileMeta))
	}
	return s.releasePrep(cid, rerr)
}

// ---------- unpack ----------

// Unpack materialises every layer of an image as a snapshot.
//
// For each descriptor in order it computes the layer's chain ID from the
// image's DiffIDs, skips the layer when that chain ID is already committed,
// and otherwise prepares a fresh directory, streams the blob out of the content
// store, decompresses it and applies it.
//
// Each layer is extracted into its own directory, holding only that layer's own
// files, the way containerd stores them; Mount is what stacks them into a
// parent's contents at run time. The AUFS deletion markers inside the tar are
// therefore translated into the on-disk overlayfs form — a character device
// 0:0, and the opaque xattr for ".wh..wh..opq" — instead of being applied as
// deletions, which in a per-layer directory would delete nothing and silently
// lose the layer's semantics.
//
// The DiffID of every applied layer is verified against the image config before
// it is committed, so a registry that serves a blob whose digest matches but
// whose contents were swapped for a different layer is caught here. A layer
// that fails for any reason leaves no partial snapshot behind.
//
// progress, when non-nil, is called with each layer's blob digest and one of
// "exists", "extracting" or "extracted".
func (s *Snapshotter) Unpack(ctx context.Context, img *types.Image, store *content.Store, layers []types.Descriptor, progress func(string, string)) error {
	if img == nil {
		return errors.New("snapshot: unpack: nil image")
	}
	if store == nil {
		return errors.New("snapshot: unpack: nil content store")
	}
	if len(layers) != len(img.DiffIDs) {
		return fmt.Errorf("snapshot: unpack %s: image config lists %d diff IDs but the manifest has %d layers",
			img.ID, len(img.DiffIDs), len(layers))
	}
	if progress == nil {
		progress = func(string, string) {}
	}

	chain := ""
	for i, desc := range layers {
		if err := ctx.Err(); err != nil {
			return err
		}
		parent := chain
		var err error
		chain, err = ChainID(parent, img.DiffIDs[i])
		if err != nil {
			return fmt.Errorf("snapshot: unpack %s: layer %d: %w", img.ID, i, err)
		}
		if s.Exists(chain) {
			progress(desc.Digest, "exists")
			continue
		}
		progress(desc.Digest, "extracting")
		if err := s.unpackLayer(ctx, chain, parent, img.DiffIDs[i], desc, store); err != nil {
			return fmt.Errorf("snapshot: unpack %s: layer %d (%s): %w", img.ID, i, desc.Digest, err)
		}
		progress(desc.Digest, "extracted")
	}
	if img.ChainID == "" {
		img.ChainID = chain
	}
	return nil
}

// unpackLayer extracts and commits exactly one layer.
func (s *Snapshotter) unpackLayer(ctx context.Context, chain, parent, diffID string, desc types.Descriptor, store *content.Store) (err error) {
	fsDir, err := s.Prepare(ctx, chain, parent)
	if err != nil {
		if errors.Is(err, ErrExists) {
			return nil
		}
		return err
	}
	defer func() {
		if err != nil {
			if aerr := s.Abort(ctx, chain); aerr != nil {
				err = errors.Join(err, aerr)
			}
			return
		}
	}()

	blob, err := store.Open(desc.Digest)
	if err != nil {
		return fmt.Errorf("open blob: %w", err)
	}
	defer blob.Close()

	plan := &whiteoutPlan{}
	opts := layer.ApplyOptions{
		Filter:   plan.filter,
		MaxBytes: layer.DefaultMaxBytes,
	}
	res, err := layer.ApplyCompressed(ctx, fsDir, blob, desc.MediaType, opts)
	if err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	want, err := NormalizeDigest(diffID)
	if err != nil {
		return err
	}
	if res.DiffID != want {
		return fmt.Errorf("%w: applied %s, the image config promised %s", ErrDiffIDMismatch, res.DiffID, want)
	}
	if err := s.materialiseWhiteouts(fsDir, plan); err != nil {
		return err
	}
	if err := s.Commit(ctx, chain, want, res.Size); err != nil {
		return err
	}
	return nil
}

// whiteoutPlan collects the AUFS markers a layer tar carries so they can be
// materialised as real overlayfs whiteouts once the layer is unpacked.
type whiteoutPlan struct {
	deleted []string
	opaque  []string
	invalid error
}

// filter is an layer.ApplyOptions.Filter that intercepts whiteout entries. It
// returns false for every marker so the applier never tries to delete anything
// out of a per-layer directory, and records what the marker meant.
func (p *whiteoutPlan) filter(hdr *tar.Header) bool {
	rel := strings.TrimSuffix(hdr.Name, "/")
	if rel == "" {
		return true
	}
	dir, base := path.Split(rel)
	dir = strings.TrimSuffix(dir, "/")
	switch {
	case base == layer.WhiteoutOpaqueDir:
		p.opaque = append(p.opaque, dir)
		return false
	case strings.HasPrefix(base, layer.WhiteoutMetaPrefix):
		// .wh..wh.plnk and friends are AUFS bookkeeping with no overlay meaning.
		return false
	case strings.HasPrefix(base, layer.WhiteoutPrefix):
		target := strings.TrimPrefix(base, layer.WhiteoutPrefix)
		if target == "" || target == "." || target == ".." {
			if p.invalid == nil {
				p.invalid = fmt.Errorf("layer contains the unusable whiteout %q", hdr.Name)
			}
			return false
		}
		p.deleted = append(p.deleted, path.Join(dir, target))
		return false
	}
	return true
}

// materialiseWhiteouts writes the recorded markers into the unpacked layer.
//
// Every path is resolved with openat2(RESOLVE_IN_ROOT) through fsutil, so a
// layer that plants a symlink and then whiteouts a path through it cannot make
// hull mknod outside the snapshot.
func (s *Snapshotter) materialiseWhiteouts(fsDir string, p *whiteoutPlan) error {
	if p.invalid != nil {
		return p.invalid
	}
	for _, rel := range p.deleted {
		dir, base := path.Split(rel)
		dir = strings.TrimSuffix(dir, "/")
		if dir != "" {
			if err := fsutil.SecureMkdirAll(fsDir, dir, layerDirPerm); err != nil {
				return fmt.Errorf("create parent of whiteout %q: %w", rel, err)
			}
		}
		df, err := fsutil.SecureOpen(fsDir, dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open parent of whiteout %q: %w", rel, err)
		}
		dfd := int(df.Fd())
		// A layer may carry both a file and its whiteout; the marker wins.
		if uerr := unix.Unlinkat(dfd, base, 0); uerr != nil && !errors.Is(uerr, unix.ENOENT) {
			if errors.Is(uerr, unix.EISDIR) || errors.Is(uerr, unix.EPERM) {
				_ = unix.Unlinkat(dfd, base, unix.AT_REMOVEDIR)
			}
		}
		merr := unix.Mknodat(dfd, base, unix.S_IFCHR|0o600, 0)
		df.Close()
		if merr != nil {
			if errors.Is(merr, unix.EPERM) || errors.Is(merr, unix.EACCES) {
				return fmt.Errorf("%w: mknod of the whiteout %q was refused (%v); creating an overlay "+
					"whiteout needs CAP_MKNOD in the mount's user namespace, so run hulld as root or "+
					"inside a user namespace it owns", ErrWhiteoutUnsupported, rel, merr)
			}
			return fmt.Errorf("create whiteout %q: %w", rel, merr)
		}
	}

	xattr := s.opaqueXattr()
	for _, dir := range p.opaque {
		if dir != "" {
			if err := fsutil.SecureMkdirAll(fsDir, dir, layerDirPerm); err != nil {
				return fmt.Errorf("create opaque directory %q: %w", dir, err)
			}
		}
		df, err := fsutil.SecureOpen(fsDir, dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open opaque directory %q: %w", dir, err)
		}
		serr := unix.Fsetxattr(int(df.Fd()), xattr, []byte("y"), 0)
		df.Close()
		if serr != nil {
			return fmt.Errorf("%w: setting %s on %q was refused (%v); a privileged overlay needs "+
				"CAP_SYS_ADMIN for trusted.* xattrs, a rootless one needs the userxattr mount option",
				ErrWhiteoutUnsupported, xattr, dir, serr)
		}
	}
	return nil
}

// ---------- inspection ----------

// readInfo reads one snapshot's meta.json.
func (s *Snapshotter) readInfo(chainID string) (Info, error) {
	dir, err := s.SnapshotDir(chainID)
	if err != nil {
		return Info{}, err
	}
	var info Info
	if err := fsutil.ReadJSON(filepath.Join(dir, FileMeta), &info); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Info{}, fmt.Errorf("snapshot: %s: %w", chainID, ErrNotFound)
		}
		return Info{}, fmt.Errorf("snapshot: read %s for %s: %w", FileMeta, chainID, err)
	}
	if info.ChainID == "" {
		info.ChainID, _ = NormalizeDigest(chainID)
	}
	return info, nil
}

// Stat returns the recorded Info for one committed snapshot.
func (s *Snapshotter) Stat(chainID string) (Info, error) {
	if !s.Exists(chainID) {
		cid, err := NormalizeDigest(chainID)
		if err != nil {
			return Info{}, err
		}
		return Info{}, fmt.Errorf("snapshot: %s: %w", cid, ErrNotFound)
	}
	return s.readInfo(chainID)
}

// chainOf walks from chainID down to the base layer and returns the chain
// newest first, which is overlayfs's lowerdir order.
func (s *Snapshotter) chainOf(chainID string) ([]Info, error) {
	var out []Info
	seen := make(map[string]struct{})
	cur := chainID
	for cur != "" {
		cid, err := NormalizeDigest(cur)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[cid]; dup {
			return nil, fmt.Errorf("snapshot: layer chain through %s is a cycle", cid)
		}
		seen[cid] = struct{}{}
		if !s.Exists(cid) {
			return nil, fmt.Errorf("snapshot: %s in the layer chain is missing or incomplete: %w", cid, ErrNotFound)
		}
		info, err := s.readInfo(cid)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
		cur = info.Parent
		if len(out) > 4096 {
			return nil, fmt.Errorf("snapshot: layer chain through %s is longer than 4096 layers", chainID)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("snapshot: empty chain ID: %w", ErrNotFound)
	}
	return out, nil
}

// Chain returns the chain IDs from chainID down to the base layer, newest
// first. Every entry is verified to be committed.
func (s *Snapshotter) Chain(chainID string) ([]string, error) {
	infos, err := s.chainOf(chainID)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(infos))
	for i, in := range infos {
		out[i] = in.ChainID
	}
	return out, nil
}

// List returns every committed snapshot, oldest first, with Refs counting the
// container mounts whose layer chain includes it.
func (s *Snapshotter) List() ([]Info, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, DirSnapshots))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("snapshot: list snapshots: %w", err)
	}
	refs := map[string]int{}
	if recs, rerr := s.loadMounts(); rerr == nil {
		for _, r := range recs.Mounts {
			for _, l := range r.Lowers {
				refs[l]++
			}
		}
	}
	out := make([]Info, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cid, err := NormalizeDigest(e.Name())
		if err != nil {
			continue
		}
		if !s.Exists(cid) {
			continue
		}
		info, err := s.readInfo(cid)
		if err != nil {
			continue
		}
		info.Refs = refs[info.ChainID]
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Created.Equal(out[j].Created) {
			return out[i].ChainID < out[j].ChainID
		}
		return out[i].Created.Before(out[j].Created)
	})
	return out, nil
}

// Usage returns the disk space one snapshot's extracted layer occupies, in
// bytes. It sums st_blocks rather than file sizes, so a sparse file costs what
// it really costs, and counts a hardlinked inode once.
func (s *Snapshotter) Usage(chainID string) (int64, error) {
	fsDir, err := s.FSDir(chainID)
	if err != nil {
		return 0, err
	}
	if !fsutil.IsDir(fsDir) {
		cid, _ := NormalizeDigest(chainID)
		return 0, fmt.Errorf("snapshot: %s: %w", cid, ErrNotFound)
	}
	return diskUsage(context.Background(), fsDir)
}

// diskUsage totals the blocks used by a tree, counting each inode once.
func diskUsage(ctx context.Context, root string) (int64, error) {
	seen := make(map[[2]uint64]struct{})
	var total int64
	err := walkTree(ctx, root, func(_ string, _ int, _ string, st *unix.Stat_t) error {
		if st.Nlink > 1 {
			key := [2]uint64{st.Dev, st.Ino}
			if _, dup := seen[key]; dup {
				return nil
			}
			seen[key] = struct{}{}
		}
		total += int64(st.Blocks) * 512
		return nil
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}

// ---------- removal and cleanup ----------

// RemoveSnapshot deletes one committed layer.
//
// It refuses while anything still needs the layer: a container mount whose
// lower chain contains it, or another snapshot stacked on top of it. Both are
// reported as ErrInUse, naming what holds it.
func (s *Snapshotter) RemoveSnapshot(ctx context.Context, chainID string) error {
	cid, err := NormalizeDigest(chainID)
	if err != nil {
		return err
	}
	dir, err := s.SnapshotDir(cid)
	if err != nil {
		return err
	}
	if !fsutil.Exists(dir) {
		return fmt.Errorf("snapshot: %s: %w", cid, ErrNotFound)
	}

	recs, err := s.loadMounts()
	if err != nil {
		return err
	}
	for id, r := range recs.Mounts {
		for _, l := range r.Lowers {
			if l == cid {
				return fmt.Errorf("snapshot: %s is a layer of container %s: %w", cid, id, ErrInUse)
			}
		}
	}
	children, err := s.List()
	if err != nil {
		return err
	}
	for _, c := range children {
		if c.Parent == cid {
			return fmt.Errorf("snapshot: %s is the parent of snapshot %s: %w", cid, c.ChainID, ErrInUse)
		}
	}

	unlock, err := lockWait(ctx, filepath.Join(dir, FileLock))
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()

	if name, rerr := os.ReadFile(filepath.Join(dir, FileLink)); rerr == nil {
		if n := strings.TrimSpace(string(name)); n != "" {
			_ = os.Remove(filepath.Join(s.root, DirLinks, n))
		}
	}
	// Drop the marker first so a crash mid-delete leaves a partial snapshot
	// that Cleanup will finish removing, never one that looks complete.
	if err := os.Remove(filepath.Join(dir, FileComplete)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("snapshot: remove %s for %s: %w", FileComplete, cid, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("snapshot: remove %s: %w", dir, err)
	}
	return nil
}

// Cleanup brings the root back to a consistent state after a crash or restart.
//
// It drops every partial snapshot whose lock it can take (a snapshot another
// process is extracting right now is left alone), removes short links that no
// longer point at a live layer, and reconciles the mount record with
// /proc/self/mountinfo so that a container whose overlay died with the previous
// daemon is no longer described as mounted. It is safe to call at any time, and
// a daemon should call it at startup.
func (s *Snapshotter) Cleanup(ctx context.Context) error {
	var errs []error

	entries, err := os.ReadDir(filepath.Join(s.root, DirSnapshots))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("snapshot: cleanup: list snapshots: %w", err)
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !e.IsDir() {
			continue
		}
		cid, nerr := NormalizeDigest(e.Name())
		if nerr != nil {
			continue
		}
		if s.Exists(cid) {
			continue
		}
		dir := filepath.Join(s.root, DirSnapshots, e.Name())
		l, lerr := fsutil.TryFileLock(filepath.Join(dir, FileLock))
		if lerr != nil {
			// Someone is extracting into it; leave it be.
			continue
		}
		rerr := os.RemoveAll(dir)
		_ = l.Unlock()
		if rerr != nil {
			errs = append(errs, fmt.Errorf("snapshot: cleanup: remove partial %s: %w", dir, rerr))
		}
	}

	if err := s.cleanupLinks(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := s.reconcileMounts(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// cleanupLinks removes short links whose snapshot is gone or which the snapshot
// no longer claims.
func (s *Snapshotter) cleanupLinks(ctx context.Context) error {
	linkDir := filepath.Join(s.root, DirLinks)
	entries, err := os.ReadDir(linkDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("snapshot: cleanup: list %s: %w", linkDir, err)
	}
	var errs []error
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := e.Name()
		p := filepath.Join(linkDir, name)
		target, rerr := os.Readlink(p)
		if rerr != nil {
			errs = append(errs, fmt.Errorf("snapshot: cleanup: %s is not a symlink", p))
			continue
		}
		resolved := target
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(linkDir, target)
		}
		stale := !fsutil.IsDir(resolved)
		if !stale {
			// The link must also still be the one its snapshot claims.
			snapDir := filepath.Dir(resolved)
			claimed, cerr := os.ReadFile(filepath.Join(snapDir, FileLink))
			if cerr != nil || strings.TrimSpace(string(claimed)) != name {
				stale = true
			}
		}
		if stale {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("snapshot: cleanup: remove stale link %s: %w", p, err))
			}
		}
	}
	return errors.Join(errs...)
}

// ---------- fd-safe tree walk ----------

// walkFunc is called for every entry below a walked root. rel is the
// slash-separated path relative to the root, dirfd is an open descriptor on the
// entry's parent directory and name is the entry's own name, so the callback
// can act on it with *at syscalls rather than by path. Returning
// filepath.SkipDir from a directory entry skips its contents.
type walkFunc func(rel string, dirfd int, name string, st *unix.Stat_t) error

// walkTree walks root depth-first without ever following a symlink: every
// descent is an openat with O_NOFOLLOW from the parent's descriptor, so a
// container that replaces a directory with a symlink mid-walk cannot redirect
// it out of the tree. The root itself is not passed to fn.
func walkTree(ctx context.Context, root string, fn walkFunc) error {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("snapshot: open %s: %w", root, err)
	}
	f := os.NewFile(uintptr(fd), root)
	defer f.Close()
	return walkDirFD(ctx, f, "", fn, 0)
}

// maxWalkDepth bounds recursion so a pathological tree cannot exhaust the stack.
const maxWalkDepth = 1024

// walkDirFD is walkTree's recursion. It takes ownership of nothing: the caller
// closes dir.
func walkDirFD(ctx context.Context, dir *os.File, rel string, fn walkFunc, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > maxWalkDepth {
		return fmt.Errorf("snapshot: directory tree deeper than %d levels at %q", maxWalkDepth, rel)
	}
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("snapshot: read directory %q: %w", dir.Name(), err)
	}
	sort.Strings(names)
	dirfd := int(dir.Fd())
	for _, name := range names {
		if name == "." || name == ".." {
			continue
		}
		child := name
		if rel != "" {
			child = rel + "/" + name
		}
		var st unix.Stat_t
		if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return fmt.Errorf("snapshot: stat %q: %w", child, err)
		}
		err := fn(child, dirfd, name, &st)
		if errors.Is(err, filepath.SkipDir) {
			continue
		}
		if err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		cfd, oerr := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if oerr != nil {
			if errors.Is(oerr, unix.ENOENT) || errors.Is(oerr, unix.ELOOP) {
				continue
			}
			return fmt.Errorf("snapshot: open directory %q: %w", child, oerr)
		}
		cf := os.NewFile(uintptr(cfd), child)
		werr := walkDirFD(ctx, cf, child, fn, depth+1)
		cf.Close()
		if werr != nil {
			return werr
		}
	}
	return nil
}

// isWhiteout reports whether a stat describes an overlayfs whiteout: a
// character device with device number 0:0.
func isWhiteout(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFCHR && st.Rdev == 0
}
