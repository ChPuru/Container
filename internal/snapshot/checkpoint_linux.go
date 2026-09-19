//go:build linux

package snapshot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahuldhali/hull/internal/fsutil"
	"github.com/rahuldhali/hull/internal/layer"
)

// checkpointMeta is the on-disk form of a Checkpoint.
const checkpointMeta = "meta.json"

// checkpointDir returns where one container's checkpoints live.
func (s *Snapshotter) checkpointDir(containerID string) (string, error) {
	if err := validateName("container ID", containerID); err != nil {
		return "", err
	}
	return filepath.Join(s.root, DirCheckpoints, containerID), nil
}

// checkpointPath returns one named checkpoint's directory.
func (s *Snapshotter) checkpointPath(containerID, name string) (string, error) {
	d, err := s.checkpointDir(containerID)
	if err != nil {
		return "", err
	}
	if err := validateName("checkpoint name", name); err != nil {
		return "", err
	}
	return filepath.Join(d, name), nil
}

// Checkpoint captures a container's overlay upperdir under a name.
//
// It freezes nothing: the engine is responsible for having the container
// quiesced (cgroup.freeze) before it calls, and for keeping it that way until
// this returns. What Checkpoint does is copy containers/<id>/upper into
// checkpoints/<id>/<name>/upper as cheaply as the filesystem allows: a reflink
// when FICLONE succeeds (btrfs, and XFS with reflink=1), otherwise a hardlink,
// otherwise a real copy. Directory modes, ownership, timestamps, xattrs,
// symlinks and overlay whiteout device nodes are all preserved, because all of
// them carry meaning in an upperdir.
//
// The copy is assembled in a temporary directory and renamed into place, so a
// crash never leaves a half-written checkpoint that ListCheckpoints would show.
//
// One honest caveat about the cheap path: a hardlink shares an inode with the
// live upperdir, and overlayfs modifies an upper file in place. If the engine
// resumes the container and it writes to a file that was hardlinked, the
// checkpoint sees the new bytes. Only the reflink path is true copy-on-write.
// Callers that need isolation on a non-reflink filesystem must checkpoint a
// container they will not resume, or take the cost of CheckpointCopy.
func (s *Snapshotter) Checkpoint(ctx context.Context, containerID string, name string) (Checkpoint, error) {
	return s.checkpoint(ctx, containerID, name, true)
}

// CheckpointCopy is Checkpoint without the cheap paths: every regular file is
// copied byte for byte, so the result is independent of the live upperdir even
// on a filesystem with no reflink support. It is what to use before resuming a
// container whose checkpoint has to stay stable.
func (s *Snapshotter) CheckpointCopy(ctx context.Context, containerID string, name string) (Checkpoint, error) {
	return s.checkpoint(ctx, containerID, name, false)
}

// checkpoint is the shared body of Checkpoint and CheckpointCopy.
func (s *Snapshotter) checkpoint(ctx context.Context, containerID, name string, share bool) (Checkpoint, error) {
	dest, err := s.checkpointPath(containerID, name)
	if err != nil {
		return Checkpoint{}, err
	}
	upper, err := s.UpperPath(containerID)
	if err != nil {
		return Checkpoint{}, err
	}
	if !fsutil.IsDir(upper) {
		return Checkpoint{}, fmt.Errorf("snapshot: container %s has no upperdir at %s: %w", containerID, upper, ErrNotFound)
	}
	if fsutil.Exists(dest) {
		return Checkpoint{}, fmt.Errorf("snapshot: checkpoint %s of container %s: %w", name, containerID, ErrExists)
	}
	parentDir := filepath.Dir(dest)
	if err := os.MkdirAll(parentDir, dirPerm); err != nil {
		return Checkpoint{}, fmt.Errorf("snapshot: create %s: %w", parentDir, err)
	}

	tmp, err := os.MkdirTemp(parentDir, "."+name+".tmp-")
	if err != nil {
		return Checkpoint{}, fmt.Errorf("snapshot: create temporary checkpoint directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tmp)
		}
	}()

	size, err := s.copyTree(ctx, upper, filepath.Join(tmp, DirUpper), share)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("snapshot: checkpoint %s of container %s: %w", name, containerID, err)
	}

	cp := Checkpoint{
		Name:        name,
		ContainerID: containerID,
		Created:     time.Now().UTC(),
		Size:        size,
	}
	if r, rerr := s.record(containerID); rerr == nil {
		cp.Parent = r.ChainID
	} else if !errors.Is(rerr, ErrNotFound) {
		return Checkpoint{}, rerr
	}
	if err := fsutil.WriteJSONAtomic(filepath.Join(tmp, checkpointMeta), cp, filePerm); err != nil {
		return Checkpoint{}, fmt.Errorf("snapshot: write checkpoint metadata: %w", err)
	}
	if err := fsutil.FSync(tmp); err != nil {
		return Checkpoint{}, fmt.Errorf("snapshot: fsync %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return Checkpoint{}, fmt.Errorf("snapshot: publish checkpoint %s: %w", name, err)
	}
	committed = true
	if err := fsutil.FSync(parentDir); err != nil {
		return Checkpoint{}, fmt.Errorf("snapshot: fsync %s: %w", parentDir, err)
	}
	return cp, nil
}

// ListCheckpoints returns a container's checkpoints, oldest first. A container
// that never had one yields an empty slice and no error.
func (s *Snapshotter) ListCheckpoints(containerID string) ([]Checkpoint, error) {
	dir, err := s.checkpointDir(containerID)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("snapshot: list checkpoints of %s: %w", containerID, err)
	}
	out := make([]Checkpoint, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		var cp Checkpoint
		if err := fsutil.ReadJSON(filepath.Join(dir, e.Name(), checkpointMeta), &cp); err != nil {
			continue
		}
		cp.Name = e.Name()
		cp.ContainerID = containerID
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Created.Equal(out[j].Created) {
			return out[i].Name < out[j].Name
		}
		return out[i].Created.Before(out[j].Created)
	})
	return out, nil
}

// StatCheckpoint returns one checkpoint's metadata.
func (s *Snapshotter) StatCheckpoint(containerID, name string) (Checkpoint, error) {
	p, err := s.checkpointPath(containerID, name)
	if err != nil {
		return Checkpoint{}, err
	}
	var cp Checkpoint
	if err := fsutil.ReadJSON(filepath.Join(p, checkpointMeta), &cp); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Checkpoint{}, fmt.Errorf("snapshot: checkpoint %s of container %s: %w", name, containerID, ErrNotFound)
		}
		return Checkpoint{}, err
	}
	cp.Name = name
	cp.ContainerID = containerID
	return cp, nil
}

// DeleteCheckpoint removes one checkpoint. Deleting a checkpoint that is not
// there reports ErrNotFound rather than succeeding quietly, because time travel
// is the kind of feature where a silent no-op is a data-loss bug.
func (s *Snapshotter) DeleteCheckpoint(ctx context.Context, containerID string, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := s.checkpointPath(containerID, name)
	if err != nil {
		return err
	}
	if !fsutil.Exists(p) {
		return fmt.Errorf("snapshot: checkpoint %s of container %s: %w", name, containerID, ErrNotFound)
	}
	if err := os.RemoveAll(p); err != nil {
		return fmt.Errorf("snapshot: remove checkpoint %s: %w", name, err)
	}
	return nil
}

// Restore swaps a container's live upperdir for a checkpoint's.
//
// The container must be stopped and its rootfs unmounted: overlayfs caches the
// upperdir's dentries, so replacing it under a live mount would give the
// container a view that matches neither the old nor the new contents. Restore
// refuses with ErrMounted rather than allowing that.
//
// The live upperdir is moved aside first and only deleted once the checkpoint
// has been materialised, so a failure mid-restore puts the original back. The
// overlay workdir is emptied, because its leftovers belong to the upperdir that
// just went away.
func (s *Snapshotter) Restore(ctx context.Context, containerID string, name string) error {
	src, err := s.checkpointPath(containerID, name)
	if err != nil {
		return err
	}
	srcUpper := filepath.Join(src, DirUpper)
	if !fsutil.IsDir(srcUpper) {
		return fmt.Errorf("snapshot: checkpoint %s of container %s: %w", name, containerID, ErrNotFound)
	}
	mounted, err := s.IsMounted(containerID)
	if err != nil {
		return err
	}
	if mounted {
		merged, _ := s.MergedPath(containerID)
		return fmt.Errorf("snapshot: restore %s into container %s: %s is still mounted; stop the container "+
			"and unmount its rootfs first: %w", name, containerID, merged, ErrMounted)
	}

	cdir, err := s.ContainerDir(containerID)
	if err != nil {
		return err
	}
	upper := filepath.Join(cdir, DirUpper)
	if err := os.MkdirAll(cdir, dirPerm); err != nil {
		return fmt.Errorf("snapshot: create %s: %w", cdir, err)
	}

	aside := filepath.Join(cdir, fmt.Sprintf(".upper.replaced-%d", time.Now().UnixNano()))
	haveOld := false
	if fsutil.Exists(upper) {
		if err := os.Rename(upper, aside); err != nil {
			return fmt.Errorf("snapshot: move the live upperdir of %s aside: %w", containerID, err)
		}
		haveOld = true
	}
	restoreOld := func() {
		if haveOld {
			_ = os.RemoveAll(upper)
			_ = os.Rename(aside, upper)
		}
	}

	if _, err := s.copyTree(ctx, srcUpper, upper, true); err != nil {
		restoreOld()
		return fmt.Errorf("snapshot: restore %s into container %s: %w", name, containerID, err)
	}
	work := filepath.Join(cdir, DirWork)
	if fsutil.Exists(work) {
		if err := os.RemoveAll(work); err != nil {
			restoreOld()
			return fmt.Errorf("snapshot: clear the overlay workdir of %s: %w", containerID, err)
		}
	}
	if err := os.MkdirAll(work, layerDirPerm); err != nil {
		restoreOld()
		return fmt.Errorf("snapshot: recreate the overlay workdir of %s: %w", containerID, err)
	}
	if haveOld {
		if err := os.RemoveAll(aside); err != nil {
			return fmt.Errorf("snapshot: remove the replaced upperdir %s: %w", aside, err)
		}
	}
	return nil
}

// ---------- diffs ----------

// entryState is what a diff needs to know about one path in an upperdir.
type entryState struct {
	mode   uint32
	size   int64
	mtime  unix.Timespec
	rdev   uint64
	dev    uint64
	ino    uint64
	opaque bool
}

// isDir reports whether the entry is a directory.
func (e entryState) isDir() bool { return e.mode&unix.S_IFMT == unix.S_IFDIR }

// isWhiteout reports whether the entry is an overlay whiteout.
func (e entryState) isWhiteout() bool {
	return e.mode&unix.S_IFMT == unix.S_IFCHR && e.rdev == 0
}

// differs reports whether two entries for the same path are not the same
// content. The same inode on the same device is the same file, which is what a
// reflinked or hardlinked checkpoint produces for everything it did not touch.
func (e entryState) differs(o entryState) bool {
	if e.dev == o.dev && e.ino == o.ino {
		return false
	}
	if e.mode != o.mode || e.rdev != o.rdev || e.opaque != o.opaque {
		return true
	}
	if e.isDir() {
		return false
	}
	return e.size != o.size || e.mtime.Sec != o.mtime.Sec || e.mtime.Nsec != o.mtime.Nsec
}

// scanUpper indexes an upperdir by path.
func (s *Snapshotter) scanUpper(ctx context.Context, dir string) (map[string]entryState, error) {
	out := make(map[string]entryState)
	err := walkTree(ctx, dir, func(rel string, dirfd int, name string, st *unix.Stat_t) error {
		e := entryState{
			mode:  st.Mode,
			size:  st.Size,
			mtime: unix.Timespec{Sec: st.Mtim.Sec, Nsec: st.Mtim.Nsec},
			rdev:  st.Rdev,
			dev:   st.Dev,
			ino:   st.Ino,
		}
		if e.isDir() {
			e.opaque = s.readOpaque(dirfd, name)
		}
		out[rel] = e
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// readOpaque reports whether a directory carries an overlay opaque marker,
// checking both the privileged and the rootless xattr name so the answer does
// not depend on which mode wrote it.
func (s *Snapshotter) readOpaque(dirfd int, name string) bool {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	var buf [16]byte
	for _, x := range []string{layer.OpaqueXattrTrusted, layer.OpaqueXattrUser} {
		n, xerr := unix.Fgetxattr(fd, x, buf[:])
		if xerr == nil && n > 0 && buf[0] == 'y' {
			return true
		}
	}
	return false
}

// DiffCheckpoints reports how a container's filesystem differs between two of
// its checkpoints, as the change set that turns a into b.
//
// Both sides are overlay upperdirs over the same image, so the comparison is
// between two sets of changes rather than between two filesystems:
//
//   - a path that is a whiteout in b, and was not already one in a, is Deleted
//   - a path present in b but absent from a, or whited out in a, is Added
//   - a path present in both with different metadata or contents is Modified
//   - a path present in a but absent from b has gone back to the image's
//     version: Deleted if a had changed it, Added if a had deleted it
//
// The result is sorted by path.
func (s *Snapshotter) DiffCheckpoints(ctx context.Context, containerID string, a string, b string) ([]Change, error) {
	aDir, err := s.checkpointUpper(containerID, a)
	if err != nil {
		return nil, err
	}
	bDir, err := s.checkpointUpper(containerID, b)
	if err != nil {
		return nil, err
	}
	left, err := s.scanUpper(ctx, aDir)
	if err != nil {
		return nil, fmt.Errorf("snapshot: scan checkpoint %s: %w", a, err)
	}
	right, err := s.scanUpper(ctx, bDir)
	if err != nil {
		return nil, fmt.Errorf("snapshot: scan checkpoint %s: %w", b, err)
	}

	paths := make([]string, 0, len(left)+len(right))
	for p := range left {
		paths = append(paths, p)
	}
	for p := range right {
		if _, dup := left[p]; !dup {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)

	out := make([]Change, 0, len(paths))
	for _, p := range paths {
		l, inA := left[p]
		r, inB := right[p]
		var kind ChangeKind
		switch {
		case inB && r.isWhiteout():
			if inA && l.isWhiteout() {
				continue
			}
			kind = KindDeleted
		case inB && (!inA || l.isWhiteout()):
			kind = KindAdded
		case inB && inA:
			if !l.differs(r) {
				continue
			}
			kind = KindModified
		case inA && l.isWhiteout():
			kind = KindAdded
		default:
			kind = KindDeleted
		}
		out = append(out, Change{Path: "/" + p, Kind: kind})
	}
	return out, nil
}

// checkpointUpper resolves one checkpoint's captured upperdir.
func (s *Snapshotter) checkpointUpper(containerID, name string) (string, error) {
	p, err := s.checkpointPath(containerID, name)
	if err != nil {
		return "", err
	}
	up := filepath.Join(p, DirUpper)
	if !fsutil.IsDir(up) {
		return "", fmt.Errorf("snapshot: checkpoint %s of container %s: %w", name, containerID, ErrNotFound)
	}
	return up, nil
}

// Changes reports what a container has done to its filesystem since it was
// created, by reading its live overlay upperdir against the image layers below
// it. It is what `docker diff` shows.
//
// An overlay whiteout — a character device 0:0 — is a deletion. Anything else
// in the upperdir is a modification when the image also has that path and an
// addition when it does not; that includes directories, which overlayfs
// materialises in the upperdir as soon as anything inside them changes.
//
// The result is sorted by path. A container with no upperdir yet (never
// started, or read-only) has no changes.
func (s *Snapshotter) Changes(ctx context.Context, containerID string) ([]Change, error) {
	upper, err := s.UpperPath(containerID)
	if err != nil {
		return nil, err
	}
	if !fsutil.IsDir(upper) {
		return nil, nil
	}
	rec, err := s.record(containerID)
	if err != nil {
		return nil, fmt.Errorf("snapshot: changes for %s: the container has no mount record, so hull cannot "+
			"tell which image layers to compare against: %w", containerID, err)
	}
	lowers := make([]string, 0, len(rec.Lowers))
	for _, c := range rec.Lowers {
		d, derr := s.FSDir(c)
		if derr != nil {
			return nil, derr
		}
		lowers = append(lowers, d)
	}

	var out []Change
	err = walkTree(ctx, upper, func(rel string, dirfd int, name string, st *unix.Stat_t) error {
		if isWhiteout(st) {
			out = append(out, Change{Path: "/" + rel, Kind: KindDeleted})
			return nil
		}
		found, lerr := lookupLower(lowers, rel)
		if lerr != nil {
			return lerr
		}
		kind := KindAdded
		if found {
			kind = KindModified
		}
		out = append(out, Change{Path: "/" + rel, Kind: kind})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("snapshot: changes for %s: %w", containerID, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// lookupLower reports whether a path is visible in a stack of lower layers
// listed newest first. A whiteout in a layer hides the path from everything
// below it, which is exactly what the search stops on.
//
// Each lookup goes through openat2(RESOLVE_IN_ROOT), so a symlink planted in an
// image layer resolves inside that layer and can never reach the host.
func lookupLower(lowers []string, rel string) (bool, error) {
	for _, d := range lowers {
		f, err := fsutil.SecureOpen(d, rel, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			switch {
			case errors.Is(err, unix.ENOENT), errors.Is(err, os.ErrNotExist),
				errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ELOOP),
				errors.Is(err, fsutil.ErrUnsafePath):
				continue
			}
			return false, fmt.Errorf("snapshot: look up %q in %s: %w", rel, d, err)
		}
		var st unix.Stat_t
		serr := unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if serr != nil {
			return false, fmt.Errorf("snapshot: stat %q in %s: %w", rel, d, serr)
		}
		if isWhiteout(&st) {
			return false, nil
		}
		return true, nil
	}
	return false, nil
}

// ---------- cheap tree copy ----------

// copyTree replicates src at dst, preserving everything an overlay upperdir
// can carry: modes, ownership, timestamps, xattrs (including the overlay
// opaque marker), symlinks, fifos and whiteout device nodes.
//
// When share is true, regular files are reflinked with FICLONE where the
// filesystem supports it, then hardlinked, and only copied byte for byte as a
// last resort. When it is false every file is copied.
//
// The source is walked fd-relative with O_NOFOLLOW and each destination path is
// resolved with openat2(RESOLVE_IN_ROOT), so a symlink inside a container's
// upperdir cannot make the copy write outside dst.
//
// It returns the apparent size of everything it copied.
func (s *Snapshotter) copyTree(ctx context.Context, src, dst string, share bool) (int64, error) {
	srcFi, err := os.Stat(src)
	if err != nil {
		return 0, fmt.Errorf("snapshot: stat %s: %w", src, err)
	}
	if err := os.MkdirAll(dst, srcFi.Mode().Perm()); err != nil {
		return 0, fmt.Errorf("snapshot: create %s: %w", dst, err)
	}
	if err := os.Chmod(dst, srcFi.Mode().Perm()); err != nil {
		return 0, fmt.Errorf("snapshot: chmod %s: %w", dst, err)
	}

	var total int64
	links := make(map[[2]uint64]string)
	// Directory timestamps are applied in a second pass: creating a child
	// updates its parent's mtime, so stamping a directory during the walk
	// would be undone by the very next entry.
	type dirTime struct {
		rel  string
		atim unix.Timespec
		mtim unix.Timespec
	}
	var dirTimes []dirTime

	err = walkTree(ctx, src, func(rel string, dirfd int, name string, st *unix.Stat_t) error {
		parent := path.Dir(rel)
		if parent == "." {
			parent = ""
		}
		dp, derr := fsutil.SecureOpen(dst, parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if derr != nil {
			return fmt.Errorf("snapshot: open %q under %s: %w", parent, dst, derr)
		}
		defer dp.Close()
		dfd := int(dp.Fd())

		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if err := unix.Mkdirat(dfd, name, st.Mode&0o7777); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("snapshot: mkdir %q under %s: %w", rel, dst, err)
			}
			cfd, oerr := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if oerr != nil {
				return fmt.Errorf("snapshot: reopen %q under %s: %w", rel, dst, oerr)
			}
			sfd, serr := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if serr == nil {
				cerr := copyXattrs(sfd, cfd)
				unix.Close(sfd)
				if cerr != nil {
					unix.Close(cfd)
					return fmt.Errorf("snapshot: copy xattrs of %q: %w", rel, cerr)
				}
			}
			applyOwnerMode(cfd, st)
			unix.Close(cfd)
			dirTimes = append(dirTimes, dirTime{rel: rel, atim: st.Atim, mtim: st.Mtim})

		case unix.S_IFREG:
			if st.Nlink > 1 {
				key := [2]uint64{st.Dev, st.Ino}
				if prev, ok := links[key]; ok {
					if err := linkInto(dst, prev, dfd, name); err != nil {
						return fmt.Errorf("snapshot: link %q to %q: %w", rel, prev, err)
					}
					total += st.Size
					return nil
				}
				links[key] = rel
			}
			if err := copyRegular(dirfd, name, dfd, name, st, share); err != nil {
				return fmt.Errorf("snapshot: copy %q: %w", rel, err)
			}
			total += st.Size

		case unix.S_IFLNK:
			target, rerr := readlinkAt(dirfd, name, int(st.Size))
			if rerr != nil {
				return fmt.Errorf("snapshot: read link %q: %w", rel, rerr)
			}
			if err := unix.Symlinkat(target, dfd, name); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("snapshot: create link %q: %w", rel, err)
			}
			_ = unix.Fchownat(dfd, name, int(st.Uid), int(st.Gid), unix.AT_SYMLINK_NOFOLLOW)
			applyTimes(dfd, name, st)
			total += st.Size

		default:
			// Character and block devices (an overlay whiteout is one), fifos
			// and sockets. Recreating a whiteout is what makes a checkpoint of
			// a container that deleted a file mean anything at all.
			if err := unix.Mknodat(dfd, name, st.Mode, int(st.Rdev)); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("snapshot: create device or fifo %q: %w", rel, err)
			}
			_ = unix.Fchownat(dfd, name, int(st.Uid), int(st.Gid), unix.AT_SYMLINK_NOFOLLOW)
			applyTimes(dfd, name, st)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	// Deepest first, so a parent is stamped after every child that would have
	// touched its mtime.
	for i := len(dirTimes) - 1; i >= 0; i-- {
		d := dirTimes[i]
		parent := path.Dir(d.rel)
		if parent == "." {
			parent = ""
		}
		pf, oerr := fsutil.SecureOpen(dst, parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if oerr != nil {
			continue
		}
		_ = unix.UtimesNanoAt(int(pf.Fd()), path.Base(d.rel), []unix.Timespec{d.atim, d.mtim}, unix.AT_SYMLINK_NOFOLLOW)
		pf.Close()
	}
	return total, nil
}

// linkInto hardlinks an already-copied file at rel under root to name in dfd.
func linkInto(root, rel string, dfd int, name string) error {
	parent := path.Dir(rel)
	if parent == "." {
		parent = ""
	}
	pf, err := fsutil.SecureOpen(root, parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer pf.Close()
	return unix.Linkat(int(pf.Fd()), path.Base(rel), dfd, name, 0)
}

// readlinkAt reads a symlink relative to a directory descriptor.
func readlinkAt(dirfd int, name string, hint int) (string, error) {
	size := hint
	if size <= 0 || size > unix.PathMax {
		size = unix.PathMax
	}
	for {
		buf := make([]byte, size+1)
		n, err := unix.Readlinkat(dirfd, name, buf)
		if err != nil {
			return "", err
		}
		if n < len(buf) {
			return string(buf[:n]), nil
		}
		if size >= unix.PathMax {
			return "", fmt.Errorf("symlink target longer than %d bytes", unix.PathMax)
		}
		size *= 2
	}
}

// copyRegular materialises one regular file in the destination directory.
//
// The order is deliberate: FICLONE first, because a reflink is free and gives
// real copy-on-write isolation; then a hardlink, which is free but shares the
// inode; then a byte copy, which always works.
func copyRegular(srcdirfd int, srcname string, dstdirfd int, dstname string, st *unix.Stat_t, share bool) error {
	sfd, err := unix.Openat(srcdirfd, srcname, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer unix.Close(sfd)
	perm := st.Mode & 0o7777

	if share {
		dfd, derr := unix.Openat(dstdirfd, dstname, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, perm)
		if derr == nil {
			cerr := unix.IoctlFileClone(dfd, sfd)
			if cerr == nil {
				_ = copyXattrs(sfd, dfd)
				applyOwnerMode(dfd, st)
				unix.Close(dfd)
				applyTimes(dstdirfd, dstname, st)
				return nil
			}
			unix.Close(dfd)
			_ = unix.Unlinkat(dstdirfd, dstname, 0)
		} else if !errors.Is(derr, unix.EEXIST) {
			return fmt.Errorf("create destination: %w", derr)
		}
		if lerr := unix.Linkat(srcdirfd, srcname, dstdirfd, dstname, 0); lerr == nil {
			return nil
		}
	}

	dfd, derr := unix.Openat(dstdirfd, dstname, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, perm)
	if derr != nil {
		return fmt.Errorf("create destination: %w", derr)
	}
	sf := os.NewFile(uintptr(dupFD(sfd)), srcname)
	df := os.NewFile(uintptr(dfd), dstname)
	_, cerr := io.Copy(df, sf)
	sf.Close()
	if cerr != nil {
		df.Close()
		return fmt.Errorf("copy contents: %w", cerr)
	}
	_ = copyXattrs(sfd, dfd)
	applyOwnerMode(dfd, st)
	if err := df.Close(); err != nil {
		return fmt.Errorf("close destination: %w", err)
	}
	applyTimes(dstdirfd, dstname, st)
	return nil
}

// dupFD duplicates a descriptor so an os.File wrapper can own its copy.
func dupFD(fd int) int {
	n, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return fd
	}
	return n
}

// applyOwnerMode stamps ownership and mode onto an open descriptor.
//
// Both are best-effort: an unprivileged copy cannot give a file away, and
// failing a whole checkpoint over a uid it was never allowed to set would be
// worse than the drift. Setuid bits survive because the full mode is passed.
func applyOwnerMode(fd int, st *unix.Stat_t) {
	_ = unix.Fchown(fd, int(st.Uid), int(st.Gid))
	_ = unix.Fchmod(fd, st.Mode&0o7777)
}

// applyTimes stamps access and modification times on an entry named inside a
// directory descriptor.
//
// It deliberately goes through the parent rather than the entry's own
// descriptor: utimensat's AT_EMPTY_PATH form is not portable across the kernels
// hull targets, while the name-relative form is, and the parent descriptor is
// already open at every call site.
func applyTimes(dirfd int, name string, st *unix.Stat_t) {
	_ = unix.UtimesNanoAt(dirfd, name, []unix.Timespec{st.Atim, st.Mtim}, unix.AT_SYMLINK_NOFOLLOW)
}

// copyXattrs copies every extended attribute from one descriptor to another.
//
// Failures are tolerated for ordinary attributes, because an unprivileged
// process cannot write trusted.* or security.* and hull would rather make the
// checkpoint than refuse it. The one exception is the overlay opaque marker: it
// changes what the directory means, so losing it is reported.
func copyXattrs(src, dst int) error {
	size, err := unix.Flistxattr(src, nil)
	if err != nil || size <= 0 {
		return nil
	}
	buf := make([]byte, size)
	n, err := unix.Flistxattr(src, buf)
	if err != nil {
		return nil
	}
	for _, name := range splitNUL(string(buf[:n])) {
		vlen, verr := unix.Fgetxattr(src, name, nil)
		if verr != nil || vlen < 0 {
			continue
		}
		val := make([]byte, vlen)
		if vlen > 0 {
			got, gerr := unix.Fgetxattr(src, name, val)
			if gerr != nil {
				continue
			}
			val = val[:got]
		}
		if serr := unix.Fsetxattr(dst, name, val, 0); serr != nil {
			if name == layer.OpaqueXattrTrusted || name == layer.OpaqueXattrUser {
				return fmt.Errorf("%w: could not copy %s: %v", ErrWhiteoutUnsupported, name, serr)
			}
		}
	}
	return nil
}

// splitNUL splits the NUL-separated xattr name list the kernel returns.
func splitNUL(s string) []string {
	parts := strings.Split(s, "\x00")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
