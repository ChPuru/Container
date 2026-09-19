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
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Diff writes an OCI layer tar of the changes held in upper to w.
//
// upper is normally an overlayfs upperdir, which already contains only the
// changes a container made. In that mode lower must be empty: every entry in
// upper is a change, an on-disk overlay whiteout (a character device with
// device number 0:0) becomes a ".wh.<name>" entry, and a directory carrying
// trusted.overlay.opaque (or user.overlay.opaque, which is what a rootless
// overlay sets) gains a ".wh..wh..opq" entry.
//
// When lower is non-empty, Diff instead compares the two trees entry by entry,
// which is what hull needs for snapshots that were not produced by overlayfs:
// entries that are byte-identical in metadata are omitted, entries present only
// in lower become ".wh.<name>" deletions, and directories are emitted only when
// they changed or contain something that did. Passing an overlayfs upperdir
// together with its lowerdir would be wrong, because unchanged files simply do
// not exist in an upperdir and would be reported as deletions.
//
// The returned Result.DiffID is the digest of the tar Diff produced, so the
// caller can register the new layer without re-reading it.
func Diff(ctx context.Context, upper, lower string, w io.Writer) (Result, error) {
	var res Result
	if err := ctxErr(ctx); err != nil {
		return res, err
	}
	upFd, err := unix.Open(upper, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return res, fmt.Errorf("layer: open upper %q: %w", upper, err)
	}
	defer unix.Close(upFd)

	loFd := -1
	if lower != "" {
		loFd, err = unix.Open(lower, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return res, fmt.Errorf("layer: open lower %q: %w", lower, err)
		}
		defer unix.Close(loFd)
	}

	dig := sha256.New()
	cw := &countingWriter{w: w}
	tw := tar.NewWriter(io.MultiWriter(cw, dig))

	d := &differ{
		tw:     tw,
		res:    &res,
		inodes: make(map[inodeKey]string),
		isRoot: os.Geteuid() == 0,
	}
	if err := d.walk(ctx, upFd, loFd, ""); err != nil {
		return res, err
	}
	if err := tw.Close(); err != nil {
		return res, fmt.Errorf("layer: close tar: %w", err)
	}
	res.Size = cw.n
	res.DiffID = "sha256:" + hex.EncodeToString(dig.Sum(nil))
	return res, nil
}

// inodeKey identifies a file for hardlink detection.
type inodeKey struct {
	dev uint64
	ino uint64
}

// differ carries the mutable state of one Diff call.
type differ struct {
	tw      *tar.Writer
	res     *Result
	inodes  map[inodeKey]string
	pending []*tar.Header
	isRoot  bool
}

// queueDir records a directory header that is only written if something below
// it turns out to have changed.
func (d *differ) queueDir(hdr *tar.Header) {
	d.pending = append(d.pending, hdr)
}

// flush writes any queued ancestor directory headers.
func (d *differ) flush() error {
	for _, hdr := range d.pending {
		if err := d.tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("layer: write %q: %w", hdr.Name, err)
		}
		d.res.Files++
	}
	d.pending = d.pending[:0]
	return nil
}

// emit writes one header, first flushing any queued ancestors.
func (d *differ) emit(hdr *tar.Header) error {
	if err := d.flush(); err != nil {
		return err
	}
	if err := d.tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("layer: write %q: %w", hdr.Name, err)
	}
	return nil
}

// emitWhiteout writes a ".wh.<name>" deletion marker inside rel.
func (d *differ) emitWhiteout(rel, name string) error {
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     path.Join(rel, WhiteoutPrefix+name),
		Mode:     0,
		Size:     0,
		ModTime:  time.Unix(0, 0),
		Format:   tar.FormatPAX,
	}
	if err := d.emit(hdr); err != nil {
		return err
	}
	d.res.Whiteouts++
	return nil
}

// walk compares one directory level. loFd is -1 when there is no lower tree,
// which puts Diff in pure overlay-upperdir mode.
func (d *differ) walk(ctx context.Context, upFd, loFd int, rel string) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	upNames, err := readNames(upFd)
	if err != nil {
		return fmt.Errorf("layer: read %q: %w", rel, err)
	}
	var loNames []string
	if loFd >= 0 {
		loNames, err = readNames(loFd)
		if err != nil {
			return fmt.Errorf("layer: read lower %q: %w", rel, err)
		}
	}
	upSet := make(map[string]struct{}, len(upNames))
	for _, n := range upNames {
		upSet[n] = struct{}{}
	}

	// Deletions first, so a directory's removal is recorded before anything
	// that replaces it.
	for _, n := range loNames {
		if _, ok := upSet[n]; ok {
			continue
		}
		if err := d.emitWhiteout(rel, n); err != nil {
			return err
		}
	}

	for _, n := range upNames {
		if err := ctxErr(ctx); err != nil {
			return err
		}
		if err := d.entry(ctx, upFd, loFd, rel, n); err != nil {
			return err
		}
	}
	return nil
}

// entry diffs a single name below upFd.
func (d *differ) entry(ctx context.Context, upFd, loFd int, rel, name string) error {
	var up unix.Stat_t
	if err := unix.Fstatat(upFd, name, &up, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil // vanished under us
		}
		return fmt.Errorf("layer: stat %q: %w", path.Join(rel, name), err)
	}

	// An overlayfs deletion is a 0:0 character device. Translate it back to the
	// AUFS marker the wire format uses, and never descend into it.
	if up.Mode&unix.S_IFMT == unix.S_IFCHR && unix.Major(uint64(up.Rdev)) == 0 && unix.Minor(uint64(up.Rdev)) == 0 {
		return d.emitWhiteout(rel, name)
	}

	var lo unix.Stat_t
	haveLo := false
	if loFd >= 0 {
		if err := unix.Fstatat(loFd, name, &lo, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			haveLo = true
		}
	}

	childRel := path.Join(rel, name)

	if up.Mode&unix.S_IFMT == unix.S_IFDIR {
		return d.directory(ctx, upFd, loFd, childRel, name, &up, &lo, haveLo)
	}

	if haveLo && sameEntry(&up, &lo) {
		return nil
	}
	hdr, body, err := d.header(upFd, name, childRel, &up)
	if err != nil {
		return err
	}
	if hdr == nil {
		d.res.Skipped++
		return nil
	}
	if body != nil {
		defer body.Close()
	}
	if err := d.emit(hdr); err != nil {
		return err
	}
	d.res.Files++
	if body != nil && hdr.Size > 0 {
		if _, err := io.CopyN(d.tw, body, hdr.Size); err != nil {
			return fmt.Errorf("layer: copy %q: %w", childRel, err)
		}
	}
	return nil
}

// directory handles a directory entry: opaque marker, deferred header, recursion.
func (d *differ) directory(ctx context.Context, upFd, loFd int, childRel, name string, up, lo *unix.Stat_t, haveLo bool) error {
	subUp, err := unix.Openat(upFd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("layer: open %q: %w", childRel, err)
	}
	defer unix.Close(subUp)

	subLo := -1
	if haveLo && lo.Mode&unix.S_IFMT == unix.S_IFDIR {
		if fd, err := unix.Openat(loFd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); err == nil {
			subLo = fd
			defer unix.Close(subLo)
		}
	}

	opaque := d.isOpaque(subUp)
	hdr, err := d.dirHeader(subUp, childRel, up)
	if err != nil {
		return err
	}

	mark := len(d.pending)
	changed := !haveLo || lo.Mode&unix.S_IFMT != unix.S_IFDIR || !sameEntry(up, lo) || opaque
	if changed {
		if err := d.emit(hdr); err != nil {
			return err
		}
		d.res.Files++
	} else {
		d.queueDir(hdr)
	}

	if opaque {
		opq := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     path.Join(childRel, WhiteoutOpaqueDir),
			Mode:     0,
			Size:     0,
			ModTime:  time.Unix(0, 0),
			Format:   tar.FormatPAX,
		}
		if err := d.emit(opq); err != nil {
			return err
		}
		d.res.Whiteouts++
	}

	if err := d.walk(ctx, subUp, subLo, childRel); err != nil {
		return err
	}
	if len(d.pending) > mark {
		// Nothing below this directory was emitted; drop its queued header.
		d.pending = d.pending[:mark]
	}
	return nil
}

// isOpaque reports whether an open directory carries an overlayfs opaque mark.
// The trusted namespace needs CAP_SYS_ADMIN to read, so the rootless user.*
// spelling is checked too.
func (d *differ) isOpaque(fd int) bool {
	for _, attr := range []string{OpaqueXattrTrusted, OpaqueXattrUser} {
		buf := make([]byte, 8)
		n, err := unix.Fgetxattr(fd, attr, buf)
		if err == nil && n > 0 && buf[0] == 'y' {
			return true
		}
	}
	return false
}

// dirHeader builds the tar header for a directory.
func (d *differ) dirHeader(fd int, rel string, st *unix.Stat_t) (*tar.Header, error) {
	hdr := baseHeader(rel+"/", st)
	hdr.Typeflag = tar.TypeDir
	hdr.Size = 0
	xs, err := listXattrs(fd)
	if err != nil {
		return nil, fmt.Errorf("layer: read xattrs of %q: %w", rel, err)
	}
	applyXattrs(hdr, xs)
	return hdr, nil
}

// header builds the tar header for a non-directory entry, returning an open
// file for regular-file bodies. A nil header means the entry has no tar
// representation (a socket) and should be skipped.
func (d *differ) header(dirfd int, name, rel string, st *unix.Stat_t) (*tar.Header, *os.File, error) {
	hdr := baseHeader(rel, st)

	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		key := inodeKey{dev: uint64(st.Dev), ino: st.Ino}
		if st.Nlink > 1 {
			if first, ok := d.inodes[key]; ok {
				hdr.Typeflag = tar.TypeLink
				hdr.Linkname = first
				hdr.Size = 0
				return hdr, nil, nil
			}
			d.inodes[key] = rel
		}
		hdr.Typeflag = tar.TypeReg
		hdr.Size = st.Size
		fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("layer: open %q: %w", rel, err)
		}
		f := os.NewFile(uintptr(fd), rel)
		xs, err := listXattrs(fd)
		if err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("layer: read xattrs of %q: %w", rel, err)
		}
		applyXattrs(hdr, xs)
		return hdr, f, nil

	case unix.S_IFLNK:
		buf := make([]byte, unix.PathMax)
		n, err := unix.Readlinkat(dirfd, name, buf)
		if err != nil {
			return nil, nil, fmt.Errorf("layer: readlink %q: %w", rel, err)
		}
		hdr.Typeflag = tar.TypeSymlink
		hdr.Linkname = string(buf[:n])
		hdr.Size = 0
		hdr.Mode = 0o777
		return hdr, nil, nil

	case unix.S_IFIFO:
		hdr.Typeflag = tar.TypeFifo
		hdr.Size = 0
		return hdr, nil, nil

	case unix.S_IFCHR, unix.S_IFBLK:
		if st.Mode&unix.S_IFMT == unix.S_IFCHR {
			hdr.Typeflag = tar.TypeChar
		} else {
			hdr.Typeflag = tar.TypeBlock
		}
		hdr.Devmajor = int64(unix.Major(uint64(st.Rdev)))
		hdr.Devminor = int64(unix.Minor(uint64(st.Rdev)))
		hdr.Size = 0
		return hdr, nil, nil

	default:
		// Sockets and anything else have no representation in a layer tar.
		return nil, nil, nil
	}
}

// baseHeader fills in the fields every entry type shares.
func baseHeader(name string, st *unix.Stat_t) *tar.Header {
	sec, nsec := st.Mtim.Unix()
	return &tar.Header{
		Name:    name,
		Mode:    int64(st.Mode & 0o7777),
		Uid:     int(st.Uid),
		Gid:     int(st.Gid),
		ModTime: time.Unix(sec, nsec),
		Format:  tar.FormatPAX,
	}
}

// applyXattrs records xattrs on a header as SCHILY.xattr.* PAX records.
func applyXattrs(hdr *tar.Header, xs map[string]string) {
	if len(xs) == 0 {
		return
	}
	if hdr.PAXRecords == nil {
		hdr.PAXRecords = make(map[string]string, len(xs))
	}
	keys := make([]string, 0, len(xs))
	for k := range xs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		hdr.PAXRecords[xattrPAXPrefix+k] = xs[k]
	}
}

// listXattrs reads every xattr of an open file, dropping the overlayfs
// bookkeeping ones: they describe the storage, not the content, and copying
// them into a layer would make the layer lie about itself.
func listXattrs(fd int) (map[string]string, error) {
	size, err := unix.Flistxattr(fd, nil)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM) {
			return nil, nil
		}
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	size, err = unix.Flistxattr(fd, buf)
	if err != nil {
		if errors.Is(err, unix.ERANGE) {
			return nil, nil // raced with a change; not worth failing a commit
		}
		return nil, err
	}
	var out map[string]string
	for _, name := range strings.Split(strings.TrimRight(string(buf[:size]), "\x00"), "\x00") {
		if name == "" {
			continue
		}
		if strings.HasPrefix(name, "trusted.overlay.") || strings.HasPrefix(name, "user.overlay.") {
			continue
		}
		vsize, err := unix.Fgetxattr(fd, name, nil)
		if err != nil || vsize < 0 {
			continue
		}
		val := make([]byte, vsize)
		if vsize > 0 {
			n, err := unix.Fgetxattr(fd, name, val)
			if err != nil {
				continue
			}
			val = val[:n]
		}
		if out == nil {
			out = make(map[string]string, 4)
		}
		out[name] = string(val)
	}
	return out, nil
}

// sameEntry reports whether two stat results describe an unchanged entry.
func sameEntry(a, b *unix.Stat_t) bool {
	if a.Mode != b.Mode || a.Uid != b.Uid || a.Gid != b.Gid {
		return false
	}
	switch a.Mode & unix.S_IFMT {
	case unix.S_IFCHR, unix.S_IFBLK:
		return a.Rdev == b.Rdev
	case unix.S_IFDIR:
		return a.Mtim == b.Mtim
	default:
		return a.Size == b.Size && a.Mtim == b.Mtim
	}
}
