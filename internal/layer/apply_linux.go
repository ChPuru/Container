//go:build linux

package layer

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Apply unpacks an uncompressed layer tar from r into the directory dest.
//
// dest must already exist and is assumed to be hull-controlled; everything
// inside it is treated as attacker-controlled. Entries are materialised in
// stream order, whiteouts are honoured, and directory modes and timestamps are
// applied last (deepest first) so that writing a directory's children cannot
// clobber the metadata the layer asked for.
//
// The whole stream is read, including any trailing padding after the tar
// end-of-archive marker, so Result.DiffID is the digest of the complete blob
// and can be compared against the image config's rootfs.diff_ids.
//
// Apply is not atomic: on error the destination holds a partial layer and the
// caller must discard it (hull's snapshotter does this with the .complete
// marker).
func Apply(ctx context.Context, dest string, r io.Reader, opts ApplyOptions) (Result, error) {
	opts = opts.withDefaults()
	var res Result
	if err := ctxErr(ctx); err != nil {
		return res, err
	}

	rootFd, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return res, fmt.Errorf("layer: open destination %q: %w", dest, err)
	}
	defer unix.Close(rootFd)

	dig := sha256.New()
	cr := &countingReader{r: io.TeeReader(r, dig), max: opts.MaxBytes}
	tr := tar.NewReader(cr)

	a := &applier{
		opts:   opts,
		res:    &res,
		rs:     newResolver(rootFd),
		isRoot: os.Geteuid() == 0,
	}
	defer a.rs.Close()

	for {
		if err := ctxErr(ctx); err != nil {
			return res, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return res, fmt.Errorf("layer: read tar entry %d: %w", res.Entries+1, err)
		}
		res.Entries++
		if opts.MaxEntries > 0 && res.Entries > opts.MaxEntries {
			return res, fmt.Errorf("%w: more than %d entries", ErrTooManyEntries, opts.MaxEntries)
		}
		if err := a.entry(hdr, tr); err != nil {
			return res, fmt.Errorf("layer: entry %q: %w", hdr.Name, err)
		}
	}

	// Drain whatever follows the end-of-archive marker so the digest covers the
	// whole blob, not just the part archive/tar bothered to read.
	if _, err := io.Copy(io.Discard, cr); err != nil {
		return res, fmt.Errorf("layer: drain tar stream: %w", err)
	}
	res.Size = cr.n
	res.DiffID = "sha256:" + hex.EncodeToString(dig.Sum(nil))

	if err := a.finishDirs(); err != nil {
		return res, err
	}
	return res, nil
}

// dirAttr is a directory's metadata, held back until all of its children exist.
type dirAttr struct {
	rel   string
	mode  uint32
	atime time.Time
	mtime time.Time
}

// applier carries the mutable state of one Apply call.
type applier struct {
	opts   ApplyOptions
	res    *Result
	rs     *resolver
	dirs   []dirAttr
	isRoot bool

	warnedChown bool
	warnedMknod bool
	warnedXattr bool
}

// warnf records a non-fatal fidelity problem.
func (a *applier) warnf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if a.opts.Logf != nil {
		a.opts.Logf("%s", msg)
	}
	if len(a.res.Warnings) < maxWarnings {
		a.res.Warnings = append(a.res.Warnings, msg)
	}
}

// entry dispatches one tar header.
func (a *applier) entry(hdr *tar.Header, tr io.Reader) error {
	switch hdr.Typeflag {
	case tar.TypeXHeader, tar.TypeXGlobalHeader:
		// archive/tar folds real PAX records into the following header; if one
		// still surfaces here there is nothing to materialise.
		a.res.Skipped++
		return nil
	}

	rel, err := cleanName(hdr.Name)
	if err != nil {
		return err
	}
	if rel == "" {
		// "." or "./": the destination itself. It already exists, and applying
		// an attacker-chosen mode to the snapshot root is not something hull
		// wants, so the entry is skipped for directories and refused for
		// anything else.
		if hdr.Typeflag == tar.TypeDir {
			a.res.Skipped++
			return nil
		}
		return fmt.Errorf("%w: %q names the destination itself", ErrInvalidPath, hdr.Name)
	}

	if a.opts.Filter != nil {
		h := *hdr
		h.Name = rel
		if hdr.Typeflag == tar.TypeDir {
			h.Name = rel + "/"
		}
		if !a.opts.Filter(&h) {
			a.res.Skipped++
			return nil
		}
	}

	dir, base := splitPath(rel)
	if strings.HasPrefix(base, WhiteoutPrefix) {
		return a.whiteout(dir, base)
	}
	return a.create(hdr, tr, dir, base, rel)
}

// whiteout applies a ".wh." marker.
func (a *applier) whiteout(dir, base string) error {
	switch {
	case base == WhiteoutOpaqueDir:
		fd, err := a.rs.dir(dir, true)
		if err != nil {
			return err
		}
		if err := removeChildren(fd); err != nil {
			return fmt.Errorf("apply opaque marker: %w", err)
		}
		a.res.Whiteouts++
		return nil

	case strings.HasPrefix(base, WhiteoutMetaPrefix):
		// .wh..wh.plnk, .wh..wh.aufs, .wh..wh..orph: AUFS bookkeeping.
		a.res.Skipped++
		return nil

	default:
		target := strings.TrimPrefix(base, WhiteoutPrefix)
		if target == "" || target == "." || target == ".." || strings.Contains(target, "/") {
			return fmt.Errorf("%w: whiteout of %q", ErrInvalidPath, target)
		}
		fd, err := a.rs.dir(dir, true)
		if err != nil {
			return err
		}
		if err := removeAt(fd, target); err != nil {
			return fmt.Errorf("apply whiteout of %q: %w", target, err)
		}
		a.res.Whiteouts++
		return nil
	}
}

// ids resolves the owner for an entry. It returns (-1, -1) when ownership
// should be left alone.
func (a *applier) ids(hdr *tar.Header) (int, int, error) {
	if a.opts.NoSameOwner {
		return -1, -1, nil
	}
	uid := hdr.Uid + a.opts.UIDOffset
	gid := hdr.Gid + a.opts.GIDOffset
	if uid < 0 || gid < 0 {
		return -1, -1, fmt.Errorf("layer: uid/gid offset maps %d/%d to %d/%d, which is out of range",
			hdr.Uid, hdr.Gid, uid, gid)
	}
	return uid, gid, nil
}

// create materialises one non-whiteout entry.
func (a *applier) create(hdr *tar.Header, tr io.Reader, dir, base, rel string) error {
	uid, gid, err := a.ids(hdr)
	if err != nil {
		return err
	}
	mode := uint32(hdr.Mode) & 0o7777

	dirfd, err := a.rs.dir(dir, true)
	if err != nil {
		return err
	}

	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := a.mkdir(dirfd, base, uid, gid, hdr); err != nil {
			return err
		}
		a.dirs = append(a.dirs, dirAttr{rel: rel, mode: mode, atime: hdr.AccessTime, mtime: hdr.ModTime})

	case tar.TypeReg:
		if err := a.regular(hdr, tr, dirfd, base, mode, uid, gid); err != nil {
			return err
		}

	case tar.TypeSymlink:
		if strings.IndexByte(hdr.Linkname, 0) >= 0 {
			return fmt.Errorf("%w: NUL byte in symlink target", ErrInvalidPath)
		}
		if err := removeAt(dirfd, base); err != nil {
			return fmt.Errorf("replace existing entry: %w", err)
		}
		if err := unix.Symlinkat(hdr.Linkname, dirfd, base); err != nil {
			return fmt.Errorf("symlinkat: %w", err)
		}
		a.chownAt(dirfd, base, uid, gid, rel)
		a.utimesAt(dirfd, base, hdr, rel)

	case tar.TypeLink:
		if err := a.hardlink(hdr, dirfd, base, rel); err != nil {
			return err
		}

	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		applied, err := a.node(hdr, dirfd, base, mode, rel)
		if err != nil {
			return err
		}
		if !applied {
			a.res.Skipped++
			return nil
		}
		a.chownAt(dirfd, base, uid, gid, rel)
		a.chmodAt(dirfd, base, mode, rel)
		a.utimesAt(dirfd, base, hdr, rel)

	default:
		a.warnf("layer: %s: unsupported tar type %q, skipped", rel, string(hdr.Typeflag))
		a.res.Skipped++
		return nil
	}

	a.res.Files++
	return nil
}

// mkdir creates or reuses a directory, applying ownership and xattrs now and
// leaving mode and timestamps to finishDirs.
func (a *applier) mkdir(dirfd int, base string, uid, gid int, hdr *tar.Header) error {
	var st unix.Stat_t
	switch err := unix.Fstatat(dirfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case err == nil:
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			if st.Mode&unix.S_IFMT == unix.S_IFLNK {
				// Refuse rather than unlink: the existing symlink may point
				// anywhere, and tar asked for a directory here.
				if err := unix.Unlinkat(dirfd, base, 0); err != nil {
					return fmt.Errorf("replace symlink with directory: %w", err)
				}
			} else if err := removeAt(dirfd, base); err != nil {
				return fmt.Errorf("replace existing entry with directory: %w", err)
			}
			if err := unix.Mkdirat(dirfd, base, 0o755); err != nil {
				return fmt.Errorf("mkdirat: %w", err)
			}
		}
	case errors.Is(err, unix.ENOENT):
		if err := unix.Mkdirat(dirfd, base, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("mkdirat: %w", err)
		}
	default:
		return fmt.Errorf("fstatat: %w", err)
	}

	a.chownAt(dirfd, base, uid, gid, hdr.Name)
	if xs := xattrsOf(hdr); len(xs) > 0 {
		fd, err := unix.Openat(dirfd, base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			a.warnf("layer: %s: open directory for xattrs: %v", hdr.Name, err)
			return nil
		}
		a.setXattrs(fd, hdr.Name, xs)
		_ = unix.Close(fd)
	}
	return nil
}

// regular writes a regular file. The file is created O_EXCL after any existing
// entry is removed, so an existing symlink can never be written through.
func (a *applier) regular(hdr *tar.Header, tr io.Reader, dirfd int, base string, mode uint32, uid, gid int) error {
	if err := removeAt(dirfd, base); err != nil {
		return fmt.Errorf("replace existing entry: %w", err)
	}
	fd, err := unix.Openat(dirfd, base,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	f := os.NewFile(uintptr(fd), hdr.Name)
	if _, err := io.Copy(f, tr); err != nil {
		f.Close()
		return fmt.Errorf("write file: %w", err)
	}
	// Ownership first: chown clears setuid and setgid, so the mode has to land
	// after it or a setuid binary in the layer loses its bits.
	if uid >= 0 && a.isRoot {
		if err := unix.Fchown(fd, uid, gid); err != nil {
			a.warnChown(hdr.Name, err)
		}
	} else if uid >= 0 && !a.isRoot {
		a.warnChown(hdr.Name, unix.EPERM)
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		a.warnf("layer: %s: fchmod %#o: %v", hdr.Name, mode, err)
	}
	if xs := xattrsOf(hdr); len(xs) > 0 {
		a.setXattrs(fd, hdr.Name, xs)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}
	a.utimesAt(dirfd, base, hdr, hdr.Name)
	return nil
}

// hardlink creates a link whose target is resolved by exactly the same rules as
// any other entry, so a layer cannot link to something outside dest.
func (a *applier) hardlink(hdr *tar.Header, dirfd int, base, rel string) error {
	tRel, err := cleanName(hdr.Linkname)
	if err != nil {
		return fmt.Errorf("hardlink target: %w", err)
	}
	if tRel == "" {
		return fmt.Errorf("%w: hardlink target %q", ErrInvalidPath, hdr.Linkname)
	}
	tDir, tBase := splitPath(tRel)
	// Resolved out of the resolver's cache on purpose: this fd is owned here,
	// so taking it cannot invalidate the cached parent directory of the entry.
	tFd, err := a.rs.open(tDir, false)
	if err != nil {
		return fmt.Errorf("hardlink target %q: %w", hdr.Linkname, err)
	}
	defer unix.Close(tFd)

	if err := removeAt(dirfd, base); err != nil {
		return fmt.Errorf("replace existing entry: %w", err)
	}
	// flags == 0: never follow a final symlink in the target.
	if err := unix.Linkat(tFd, tBase, dirfd, base, 0); err != nil {
		return fmt.Errorf("linkat %q -> %q: %w", rel, tRel, err)
	}
	return nil
}

// node creates a device node or FIFO. It reports whether anything was created;
// device nodes need CAP_MKNOD, which rootless hull does not have, and those are
// skipped with a warning rather than failing the pull.
func (a *applier) node(hdr *tar.Header, dirfd int, base string, mode uint32, rel string) (bool, error) {
	var kind uint32
	var dev int
	switch hdr.Typeflag {
	case tar.TypeChar:
		kind = unix.S_IFCHR
		dev = int(unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor)))
	case tar.TypeBlock:
		kind = unix.S_IFBLK
		dev = int(unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor)))
	default:
		kind = unix.S_IFIFO
	}
	if kind != unix.S_IFIFO && !a.isRoot {
		if !a.warnedMknod {
			a.warnedMknod = true
			a.warnf("layer: %s: device nodes need CAP_MKNOD; skipping them (run the engine as root for full fidelity)", rel)
		}
		return false, nil
	}
	if err := removeAt(dirfd, base); err != nil {
		return false, fmt.Errorf("replace existing entry: %w", err)
	}
	if err := unix.Mknodat(dirfd, base, kind|mode, dev); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			if !a.warnedMknod {
				a.warnedMknod = true
				a.warnf("layer: %s: mknod refused by the kernel (%v); skipping device nodes", rel, err)
			}
			return false, nil
		}
		return false, fmt.Errorf("mknodat: %w", err)
	}
	return true, nil
}

// setXattrs applies the layer's xattrs to an open file descriptor. Namespaces
// that need privilege are skipped, not fought over, and every failure is a
// warning rather than a fatal error: an image is still usable without them.
func (a *applier) setXattrs(fd int, name string, xs map[string]string) {
	keys := make([]string, 0, len(xs))
	for k := range xs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !a.isRoot && (strings.HasPrefix(k, "security.") || strings.HasPrefix(k, "trusted.")) {
			if !a.warnedXattr {
				a.warnedXattr = true
				a.warnf("layer: %s: skipping privileged xattr %q (not running as root)", name, k)
			}
			continue
		}
		if err := unix.Fsetxattr(fd, k, []byte(xs[k]), 0); err != nil {
			if !a.warnedXattr {
				a.warnedXattr = true
				a.warnf("layer: %s: set xattr %q: %v", name, k, err)
			}
		}
	}
}

// chownAt applies ownership without following symlinks.
func (a *applier) chownAt(dirfd int, base string, uid, gid int, name string) {
	if uid < 0 {
		return
	}
	if !a.isRoot {
		a.warnChown(name, unix.EPERM)
		return
	}
	if err := unix.Fchownat(dirfd, base, uid, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		a.warnChown(name, err)
	}
}

// warnChown reports the first ownership failure only; a whole layer extracted
// unprivileged would otherwise produce one warning per file.
func (a *applier) warnChown(name string, err error) {
	if a.warnedChown {
		return
	}
	a.warnedChown = true
	a.warnf("layer: %s: cannot set ownership (%v); files will be owned by the current user. "+
		"Use ApplyOptions.NoSameOwner or a user namespace to silence this.", name, err)
}

// chmodAt applies a mode. fchmodat on Linux cannot act on a symlink, so callers
// must not use it for one.
func (a *applier) chmodAt(dirfd int, base string, mode uint32, name string) {
	if err := unix.Fchmodat(dirfd, base, mode, 0); err != nil {
		a.warnf("layer: %s: chmod %#o: %v", name, mode, err)
	}
}

// utimesAt applies mtime (and atime, falling back to mtime) without following
// symlinks.
func (a *applier) utimesAt(dirfd int, base string, hdr *tar.Header, name string) {
	if hdr.ModTime.IsZero() {
		return
	}
	atime := hdr.AccessTime
	if atime.IsZero() {
		atime = hdr.ModTime
	}
	ts := []unix.Timespec{
		unix.NsecToTimespec(atime.UnixNano()),
		unix.NsecToTimespec(hdr.ModTime.UnixNano()),
	}
	if err := unix.UtimesNanoAt(dirfd, base, ts, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		a.warnf("layer: %s: set times: %v", name, err)
	}
}

// finishDirs applies directory modes and timestamps, deepest first, once every
// child has been written. Doing it in stream order would let a later child
// write bump its parent's mtime back to now.
func (a *applier) finishDirs() error {
	sort.Slice(a.dirs, func(i, j int) bool { return a.dirs[i].rel > a.dirs[j].rel })
	for _, d := range a.dirs {
		parent, base := splitPath(d.rel)
		fd, err := a.rs.dir(parent, false)
		if err != nil {
			a.warnf("layer: %s: reopen parent to finalise directory: %v", d.rel, err)
			continue
		}
		if err := unix.Fchmodat(fd, base, d.mode, 0); err != nil {
			a.warnf("layer: %s: chmod %#o: %v", d.rel, d.mode, err)
		}
		if d.mtime.IsZero() {
			continue
		}
		atime := d.atime
		if atime.IsZero() {
			atime = d.mtime
		}
		ts := []unix.Timespec{
			unix.NsecToTimespec(atime.UnixNano()),
			unix.NsecToTimespec(d.mtime.UnixNano()),
		}
		if err := unix.UtimesNanoAt(fd, base, ts, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			a.warnf("layer: %s: set times: %v", d.rel, err)
		}
	}
	return nil
}
