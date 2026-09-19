//go:build linux

package snapshot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahuldhali/hull/internal/explain"
	"github.com/rahuldhali/hull/internal/fsutil"
)

// mountsVersion is the schema version of mounts.json.
const mountsVersion = 1

// mountRecord is what the snapshotter remembers about one container's rootfs,
// so that a daemon restart can unmount what the previous process left behind
// and so that Changes can still name the image the container came from after
// the overlay is gone.
type mountRecord struct {
	// ContainerID is the container the mount belongs to.
	ContainerID string `json:"containerID"`
	// ChainID is the image chain the rootfs was built from.
	ChainID string `json:"chainID"`
	// Lowers are the chain IDs of the lower layers, newest first.
	Lowers []string `json:"lowers"`
	// LowerDirs are the short-link paths that were actually mounted, newest first.
	LowerDirs []string `json:"lowerDirs"`
	// Upper and Work are the overlay upperdir and workdir; empty when readonly.
	Upper string `json:"upper,omitempty"`
	Work  string `json:"work,omitempty"`
	// Merged is the mountpoint, which is the container rootfs.
	Merged string `json:"merged"`
	// Stack holds the intermediate read-only overlay mountpoints created when
	// the lowerdir list did not fit in one page, in the order they were mounted.
	Stack []string `json:"stack,omitempty"`
	// Readonly records whether the mount has an upperdir.
	Readonly bool `json:"readonly"`
	// Mounted is the snapshotter's belief about whether Merged is live. Cleanup
	// reconciles it with /proc/self/mountinfo.
	Mounted bool `json:"mounted"`
	// Created is when the mount was first made.
	Created time.Time `json:"created"`
}

// mountsFile is the on-disk shape of mounts.json.
type mountsFile struct {
	Version int                     `json:"version"`
	Mounts  map[string]*mountRecord `json:"mounts"`
}

// mountsPath is where the record lives.
func (s *Snapshotter) mountsPath() string { return filepath.Join(s.root, FileMounts) }

// loadMounts reads mounts.json. A missing file is an empty record, not an error.
func (s *Snapshotter) loadMounts() (*mountsFile, error) {
	mf := &mountsFile{Version: mountsVersion, Mounts: map[string]*mountRecord{}}
	err := fsutil.ReadJSON(s.mountsPath(), mf)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return mf, nil
		}
		return nil, fmt.Errorf("snapshot: read %s: %w", s.mountsPath(), err)
	}
	if mf.Mounts == nil {
		mf.Mounts = map[string]*mountRecord{}
	}
	return mf, nil
}

// withMounts runs fn against the mount record under an exclusive cross-process
// lock and writes the result back atomically. fn must not call back into any
// method that takes the same lock.
func (s *Snapshotter) withMounts(ctx context.Context, fn func(*mountsFile) error) error {
	unlock, err := lockWait(ctx, filepath.Join(s.root, FileMountsLock))
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()

	mf, err := s.loadMounts()
	if err != nil {
		return err
	}
	if err := fn(mf); err != nil {
		return err
	}
	mf.Version = mountsVersion
	if err := fsutil.WriteJSONAtomic(s.mountsPath(), mf, filePerm); err != nil {
		return fmt.Errorf("snapshot: write %s: %w", s.mountsPath(), err)
	}
	return nil
}

// record returns one container's mount record.
func (s *Snapshotter) record(containerID string) (*mountRecord, error) {
	mf, err := s.loadMounts()
	if err != nil {
		return nil, err
	}
	r, ok := mf.Mounts[containerID]
	if !ok {
		return nil, fmt.Errorf("snapshot: container %s has no mount record: %w", containerID, ErrNotFound)
	}
	return r, nil
}

// IsMounted reports whether a container's rootfs is mounted right now. It asks
// the kernel rather than trusting the record.
func (s *Snapshotter) IsMounted(containerID string) (bool, error) {
	merged, err := s.MergedPath(containerID)
	if err != nil {
		return false, err
	}
	if !fsutil.IsDir(merged) {
		return false, nil
	}
	return fsutil.IsMountpoint(merged)
}

// ---------- short links ----------

// shortLink returns the absolute path of the short symlink standing in for a
// snapshot's fs directory, allocating one if the snapshot does not have it yet.
//
// This is what keeps the lowerdir list inside a page: a chain-ID path costs 78
// bytes under /var/lib/hull and a short link costs 18, so a 60-layer image goes
// from about 4.7 KB of options to roughly 1.1 KB.
func (s *Snapshotter) shortLink(ctx context.Context, chainID string) (string, error) {
	hexID, err := chainHex(chainID)
	if err != nil {
		return "", err
	}
	snapDir := filepath.Join(s.root, DirSnapshots, hexID)
	linkDir := filepath.Join(s.root, DirLinks)
	target := filepath.Join("..", DirSnapshots, hexID, DirFS)
	want := filepath.Join(snapDir, DirFS)

	if b, rerr := os.ReadFile(filepath.Join(snapDir, FileLink)); rerr == nil {
		if name := strings.TrimSpace(string(b)); name != "" {
			p := filepath.Join(linkDir, name)
			if got, lerr := os.Readlink(p); lerr == nil && got == target {
				return p, nil
			}
		}
	}

	if err := os.MkdirAll(linkDir, layerDirPerm); err != nil {
		return "", fmt.Errorf("snapshot: create %s: %w", linkDir, err)
	}
	unlock, err := lockWait(ctx, filepath.Join(s.root, FileLinksLock))
	if err != nil {
		return "", err
	}
	defer func() { _ = unlock() }()

	// Another process may have allocated one while we waited for the lock.
	if b, rerr := os.ReadFile(filepath.Join(snapDir, FileLink)); rerr == nil {
		if name := strings.TrimSpace(string(b)); name != "" {
			p := filepath.Join(linkDir, name)
			if got, lerr := os.Readlink(p); lerr == nil && got == target {
				return p, nil
			}
		}
	}

	start := linkStartIndex(chainID)
	const maxProbes = 1 << 20
	for k := 0; k < maxProbes; k++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		name := nameForIndex(start + k)
		p := filepath.Join(linkDir, name)
		serr := os.Symlink(target, p)
		if serr != nil {
			if !errors.Is(serr, os.ErrExist) {
				return "", fmt.Errorf("snapshot: create short link %s: %w", p, serr)
			}
			// Adopt an identical link left by an earlier run; otherwise probe on.
			if got, lerr := os.Readlink(p); lerr != nil || got != target {
				continue
			}
		}
		if err := fsutil.WriteFileAtomic(filepath.Join(snapDir, FileLink), []byte(name+"\n"), filePerm); err != nil {
			_ = os.Remove(p)
			return "", fmt.Errorf("snapshot: record short link for %s: %w", chainID, err)
		}
		if _, serr := os.Stat(want); serr != nil {
			return "", fmt.Errorf("snapshot: short link for %s points at %s, which is missing: %w", chainID, want, serr)
		}
		return p, nil
	}
	return "", fmt.Errorf("snapshot: no free short link name after %d probes; the %s directory is full",
		maxProbes, filepath.Join(s.root, DirLinks))
}

// lowerDirsFor resolves a chain into the short-link paths to mount, newest first.
func (s *Snapshotter) lowerDirsFor(ctx context.Context, chainID string) (chains []string, dirs []string, err error) {
	infos, err := s.chainOf(chainID)
	if err != nil {
		return nil, nil, err
	}
	chains = make([]string, 0, len(infos))
	dirs = make([]string, 0, len(infos))
	for _, in := range infos {
		p, lerr := s.shortLink(ctx, in.ChainID)
		if lerr != nil {
			return nil, nil, lerr
		}
		chains = append(chains, in.ChainID)
		dirs = append(dirs, p)
	}
	return chains, dirs, nil
}

// ---------- mounting ----------

// Mount assembles a container's rootfs and returns the merged path.
//
// The lower layers are the chain from chainID down to the base layer, listed
// newest first because that is overlayfs's own lowerdir order: the first entry
// wins. Each one is referred to through its short link so that the option
// string stays inside the one page mount(2) will copy.
//
// A writable mount gets containers/<id>/upper as its upperdir and
// containers/<id>/work as its workdir. A read-only mount has neither, which
// overlayfs only allows with two or more lower layers; a single-layer read-only
// rootfs is served by a read-only bind mount of that layer instead.
//
// redirect_dir=off, metacopy=off and index=off are always passed explicitly.
// The WSL 6.6 kernel is configured with OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW=y,
// and leaving these to the module defaults would change what ends up in the
// upperdir and therefore what a diff, a checkpoint and `hull commit` mean.
//
// If the option string still does not fit — which takes an implausible number
// of layers with short links in play — the oldest layers are folded into
// intermediate read-only overlay mounts and the result is used as a single
// lower. If even that fails the error says so and wraps ErrOptionsTooLong.
//
// Mount is idempotent: calling it for a container whose merged directory is
// already a mountpoint returns that path unchanged.
func (s *Snapshotter) Mount(ctx context.Context, containerID string, chainID string, readonly bool) (string, error) {
	if err := validateName("container ID", containerID); err != nil {
		return "", err
	}
	if err := s.feat.Err(); err != nil {
		return "", err
	}
	cdir, err := s.ContainerDir(containerID)
	if err != nil {
		return "", err
	}
	merged := filepath.Join(cdir, DirMerged)

	if mounted, merr := s.IsMounted(containerID); merr == nil && mounted {
		return merged, nil
	}

	chains, lowerDirs, err := s.lowerDirsFor(ctx, chainID)
	if err != nil {
		return "", fmt.Errorf("snapshot: mount %s: %w", containerID, err)
	}

	upper, work := "", ""
	dirs := []string{cdir, merged}
	if !readonly {
		upper = filepath.Join(cdir, DirUpper)
		work = filepath.Join(cdir, DirWork)
		dirs = append(dirs, upper, work)
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, layerDirPerm); err != nil {
			return "", fmt.Errorf("snapshot: create %s: %w", d, err)
		}
	}

	rec := &mountRecord{
		ContainerID: containerID,
		Merged:      merged,
		Upper:       upper,
		Work:        work,
		Readonly:    readonly,
		Created:     time.Now().UTC(),
		Lowers:      chains,
		LowerDirs:   lowerDirs,
	}
	if cid, nerr := NormalizeDigest(chainID); nerr == nil {
		rec.ChainID = cid
	}

	if readonly && len(lowerDirs) == 1 {
		if err := bindReadonly(lowerDirs[0], merged); err != nil {
			return "", fmt.Errorf("snapshot: mount %s read-only: %w", containerID, err)
		}
	} else {
		stack, err := s.mountOverlay(ctx, cdir, lowerDirs, upper, work, merged, readonly)
		rec.Stack = stack
		if err != nil {
			s.tearDownStack(stack)
			return "", fmt.Errorf("snapshot: mount %s: %w", containerID, err)
		}
	}
	rec.Mounted = true

	if err := s.withMounts(ctx, func(mf *mountsFile) error {
		mf.Mounts[containerID] = rec
		return nil
	}); err != nil {
		// The mount is live but unrecorded, which would leak it across a
		// restart. Undo it rather than lie about the state on disk.
		_ = umountRetry(merged)
		s.tearDownStack(rec.Stack)
		return "", err
	}
	return merged, nil
}

// bindReadonly bind-mounts src at dst and then remounts it read-only, which is
// the only way to get a read-only bind: MS_RDONLY is ignored on the initial
// MS_BIND and has to be applied by a second MS_REMOUNT|MS_BIND call.
func bindReadonly(src, dst string) error {
	if err := unix.Mount(src, dst, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s at %s: %w", src, dst, err)
	}
	if err := unix.Mount("", dst, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
		_ = unix.Unmount(dst, unix.MNT_DETACH)
		return fmt.Errorf("remount %s read-only: %w", dst, err)
	}
	return nil
}

// mountOverlay performs the overlay mount, folding the oldest layers into
// nested read-only overlays if the option string would not fit in one page. It
// returns the intermediate mountpoints it created, in mount order, so the
// caller can unmount them in reverse.
func (s *Snapshotter) mountOverlay(ctx context.Context, cdir string, lowerDirs []string, upper, work, merged string, readonly bool) ([]string, error) {
	var stack []string
	lowers := append([]string(nil), lowerDirs...)

	for {
		if err := ctx.Err(); err != nil {
			return stack, err
		}
		opts, err := buildOverlayOptions(lowers, upper, work, s.feat.UserXattr)
		if err != nil {
			return stack, err
		}
		if fitsOnePage(opts) {
			var flags uintptr
			if readonly {
				flags |= unix.MS_RDONLY
			}
			explain.FromContext(ctx).Step(explain.KindMount, "mount(\"overlay\", %q, \"overlay\", %#x, %q)", merged, flags, opts)
			if merr := unix.Mount("overlay", merged, "overlay", flags, opts); merr != nil {
				return stack, fmt.Errorf("mount -t overlay overlay -o %s %s: %w", opts, merged, merr)
			}
			return stack, nil
		}
		if len(lowers) < 3 {
			return stack, fmt.Errorf("%w: %d lower layers still need %d bytes of options, and folding them "+
				"into nested read-only overlays cannot shrink it further; the layer paths under %s are too long",
				ErrOptionsTooLong, len(lowers), len(opts), s.root)
		}

		// Fold the largest possible suffix (the oldest layers) into one
		// read-only overlay and use that mount as a single lower layer.
		n := 2
		for n < len(lowers)-1 {
			trial, terr := buildOverlayOptions(lowers[len(lowers)-(n+1):], "", "", s.feat.UserXattr)
			if terr != nil || !fitsOnePage(trial) {
				break
			}
			n++
		}
		chunk := lowers[len(lowers)-n:]
		mp := filepath.Join(cdir, DirStack, fmt.Sprintf("%d", len(stack)))
		if err := os.MkdirAll(mp, layerDirPerm); err != nil {
			return stack, fmt.Errorf("create nested lower mountpoint %s: %w", mp, err)
		}
		chunkOpts, cerr := buildOverlayOptions(chunk, "", "", s.feat.UserXattr)
		if cerr != nil {
			return stack, cerr
		}
		explain.FromContext(ctx).Step(explain.KindMount, "the option string exceeds one page, so %d lower layers fold into a nested read-only overlay at %q", len(chunk), mp)
		if merr := unix.Mount("overlay", mp, "overlay", unix.MS_RDONLY, chunkOpts); merr != nil {
			return stack, fmt.Errorf("%w: folding %d lower layers into the nested mount %s failed: %v",
				ErrOptionsTooLong, len(chunk), mp, merr)
		}
		stack = append(stack, mp)
		lowers = append(append([]string(nil), lowers[:len(lowers)-n]...), mp)
	}
}

// tearDownStack unmounts intermediate lower mounts in reverse order.
func (s *Snapshotter) tearDownStack(stack []string) {
	for i := len(stack) - 1; i >= 0; i-- {
		_ = umountRetry(stack[i])
	}
}

// umountRetry unmounts path, falling back to a lazy detach when the mount is
// busy, and then verifies with /proc/self/mountinfo that it really is gone. A
// path that was never mounted is not an error.
func umountRetry(path string) error {
	err := unix.Unmount(path, 0)
	switch {
	case err == nil:
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOENT):
		// Not a mountpoint (any more).
	case errors.Is(err, unix.EBUSY):
		if derr := unix.Unmount(path, unix.MNT_DETACH); derr != nil && !errors.Is(derr, unix.EINVAL) {
			return fmt.Errorf("snapshot: lazily unmount %s: %w", path, derr)
		}
	default:
		if derr := unix.Unmount(path, unix.MNT_DETACH); derr != nil {
			return fmt.Errorf("snapshot: unmount %s: %w", path, err)
		}
	}
	still, merr := fsutil.IsMountpoint(path)
	if merr != nil {
		if errors.Is(merr, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("snapshot: verify %s is unmounted: %w", path, merr)
	}
	if still {
		return fmt.Errorf("snapshot: %s is still a mountpoint after unmounting it", path)
	}
	return nil
}

// Unmount tears down a container's rootfs.
//
// It unmounts with umount2, retries with MNT_DETACH when the kernel reports
// EBUSY — which on WSL happens routinely, because another distro or Docker
// Desktop may be holding a reference through the shared mount namespace — and
// then confirms against /proc/self/mountinfo that the mountpoint is gone.
// Unmounting a container that is not mounted succeeds.
func (s *Snapshotter) Unmount(ctx context.Context, containerID string) error {
	if err := validateName("container ID", containerID); err != nil {
		return err
	}
	merged, err := s.MergedPath(containerID)
	if err != nil {
		return err
	}
	var stack []string
	if r, rerr := s.record(containerID); rerr == nil {
		stack = r.Stack
		if r.Merged != "" {
			merged = r.Merged
		}
	} else if !errors.Is(rerr, ErrNotFound) {
		return rerr
	}

	var errs []error
	if fsutil.Exists(merged) {
		if err := umountRetry(merged); err != nil {
			errs = append(errs, err)
		}
	}
	for i := len(stack) - 1; i >= 0; i-- {
		if !fsutil.Exists(stack[i]) {
			continue
		}
		if err := umountRetry(stack[i]); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return s.withMounts(ctx, func(mf *mountsFile) error {
		if r, ok := mf.Mounts[containerID]; ok {
			r.Mounted = false
			r.Stack = nil
		}
		return nil
	})
}

// Remove unmounts a container's rootfs and deletes its overlay directories.
//
// Only upper, work, merged and the nested-lower stack are removed. The rest of
// containers/<id> belongs to other subsystems — the bundle, the state file, the
// logs — and is left for them. Checkpoints survive too, so that a removed
// container's history can still be inspected; use DeleteCheckpoint to drop them.
func (s *Snapshotter) Remove(ctx context.Context, containerID string) error {
	if err := s.Unmount(ctx, containerID); err != nil {
		return err
	}
	cdir, err := s.ContainerDir(containerID)
	if err != nil {
		return err
	}
	var errs []error
	for _, sub := range []string{DirMerged, DirUpper, DirWork, DirStack} {
		p := filepath.Join(cdir, sub)
		if err := os.RemoveAll(p); err != nil {
			errs = append(errs, fmt.Errorf("snapshot: remove %s: %w", p, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return s.withMounts(ctx, func(mf *mountsFile) error {
		delete(mf.Mounts, containerID)
		return nil
	})
}

// reconcileMounts makes the record agree with the kernel after a restart.
func (s *Snapshotter) reconcileMounts(ctx context.Context) error {
	return s.withMounts(ctx, func(mf *mountsFile) error {
		ids := make([]string, 0, len(mf.Mounts))
		for id := range mf.Mounts {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			r := mf.Mounts[id]
			if r == nil || r.Merged == "" {
				delete(mf.Mounts, id)
				continue
			}
			if !fsutil.Exists(r.Merged) {
				r.Mounted = false
				r.Stack = nil
				continue
			}
			live, err := fsutil.IsMountpoint(r.Merged)
			if err != nil {
				return fmt.Errorf("snapshot: cleanup: check %s: %w", r.Merged, err)
			}
			r.Mounted = live
			if !live {
				r.Stack = nil
			}
		}
		return nil
	})
}
