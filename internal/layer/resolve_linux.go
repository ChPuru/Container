//go:build linux

package layer

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"

	"golang.org/x/sys/unix"
)

// openat2Resolve is the resolution policy hull uses for every container-
// controlled path. RESOLVE_IN_ROOT scopes the walk to the anchoring directory
// fd, RESOLVE_NO_MAGICLINKS keeps /proc/*/fd style magic links out of it, and
// RESOLVE_NO_SYMLINKS makes any symlink component a hard failure rather than
// something to be followed. Layer entries never legitimately traverse a
// symlink, so refusing outright is both safe and correct.
const openat2Resolve = unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS

var (
	openat2Once sync.Once
	openat2OK   bool
)

// haveOpenat2 probes openat2(2) once per process and caches the answer.
// Kernels before 5.6 return ENOSYS; a seccomp policy that does not know the
// syscall may return EPERM instead, and either way hull falls back to the
// O_NOFOLLOW openat walk, which gives the same guarantees more slowly.
func haveOpenat2() bool {
	openat2Once.Do(func() {
		fd, err := unix.Openat2(unix.AT_FDCWD, ".", &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: openat2Resolve,
		})
		if err == nil {
			_ = unix.Close(fd)
			openat2OK = true
			return
		}
		openat2OK = false
	})
	return openat2OK
}

// resolver turns destination-relative paths into directory file descriptors
// without ever following a symlink. It caches the most recently used directory,
// which is what makes applying a real layer cheap: tar streams are grouped by
// directory, so the cache hits for almost every entry.
//
// The zero value is not usable; call newResolver. A resolver is not safe for
// concurrent use.
type resolver struct {
	root       int // not owned; the caller closes it
	cachePath  string
	cacheFd    int
	useOpenat2 bool
}

// newResolver anchors a resolver at the already-open directory fd root.
func newResolver(root int) *resolver {
	return &resolver{root: root, cacheFd: -1, useOpenat2: haveOpenat2()}
}

// Close releases the resolver's cached descriptor. The root fd is not closed.
func (r *resolver) Close() error {
	if r.cacheFd >= 0 {
		err := unix.Close(r.cacheFd)
		r.cacheFd = -1
		r.cachePath = ""
		return err
	}
	return nil
}

// openChild opens a single path component relative to dirfd. name must not
// contain a slash. The returned fd is owned by the caller.
func (r *resolver) openChild(dirfd int, name string, flags int) (int, error) {
	if r.useOpenat2 {
		fd, err := unix.Openat2(dirfd, name, &unix.OpenHow{
			Flags:   uint64(flags) | unix.O_CLOEXEC,
			Resolve: openat2Resolve,
		})
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.ENOSYS) {
			return -1, err
		}
		r.useOpenat2 = false
	}
	return unix.Openat(dirfd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

// dirFlags is how intermediate directories are opened: O_PATH needs no read
// permission on the directory itself, which matters because hull creates
// directories 0755 and only applies their real (possibly 0000) mode at the end.
const dirFlags = unix.O_PATH | unix.O_DIRECTORY

// open resolves rel to a directory fd owned by the caller. When create is true
// missing components are created 0755; a component that exists as a symlink is
// always a fatal ErrPathEscape, and a component that exists as a non-directory
// is replaced only when create is set (tar layers do replace files with
// directories).
func (r *resolver) open(rel string, create bool) (int, error) {
	cur, err := r.openChild(r.root, ".", dirFlags)
	if err != nil {
		return -1, fmt.Errorf("layer: reopen destination: %w", err)
	}
	if rel == "" {
		return cur, nil
	}
	for _, comp := range splitComponents(rel) {
		next, err := r.step(cur, comp, create)
		_ = unix.Close(cur)
		if err != nil {
			return -1, fmt.Errorf("layer: resolve %q: %w", rel, err)
		}
		cur = next
	}
	return cur, nil
}

// step opens or creates one directory component below dirfd.
func (r *resolver) step(dirfd int, name string, create bool) (int, error) {
	fd, err := r.openChild(dirfd, name, dirFlags)
	if err == nil {
		return fd, nil
	}
	switch {
	case errors.Is(err, unix.ELOOP):
		return -1, fmt.Errorf("%w: component %q is a symlink", ErrPathEscape, name)
	case errors.Is(err, unix.ENOENT):
		if !create {
			return -1, err
		}
		if merr := unix.Mkdirat(dirfd, name, 0o755); merr != nil && !errors.Is(merr, unix.EEXIST) {
			return -1, fmt.Errorf("mkdir %q: %w", name, merr)
		}
		fd, err = r.openChild(dirfd, name, dirFlags)
		if err != nil {
			return -1, fmt.Errorf("open %q after mkdir: %w", name, err)
		}
		return fd, nil
	case errors.Is(err, unix.ENOTDIR):
		// O_PATH|O_NOFOLLOW on a symlink opens the link itself, so the fallback
		// walk reports a symlink component as ENOTDIR rather than ELOOP. Decide
		// which it is before doing anything else: a symlink is always a refusal,
		// never something to unlink, or a layer could delete a path outside dest
		// merely by pointing at it.
		var st unix.Stat_t
		if serr := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); serr != nil {
			return -1, fmt.Errorf("stat %q: %w", name, serr)
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return -1, fmt.Errorf("%w: component %q is a symlink", ErrPathEscape, name)
		}
		if !create {
			return -1, err
		}
		// A previous layer left a plain non-directory here; tar semantics say
		// the directory wins.
		if uerr := removeAt(dirfd, name); uerr != nil {
			return -1, fmt.Errorf("replace %q with a directory: %w", name, uerr)
		}
		if merr := unix.Mkdirat(dirfd, name, 0o755); merr != nil {
			return -1, fmt.Errorf("mkdir %q: %w", name, merr)
		}
		return r.openChild(dirfd, name, dirFlags)
	default:
		return -1, fmt.Errorf("open %q: %w", name, err)
	}
}

// dir returns a directory fd for rel, cached across calls. The returned fd is
// owned by the resolver and must not be closed by the caller, and it stays
// valid only until the next call to dir.
func (r *resolver) dir(rel string, create bool) (int, error) {
	if rel == "" {
		return r.root, nil
	}
	if r.cacheFd >= 0 && r.cachePath == rel {
		return r.cacheFd, nil
	}
	fd, err := r.open(rel, create)
	if err != nil {
		return -1, err
	}
	_ = r.Close()
	r.cachePath, r.cacheFd = rel, fd
	return fd, nil
}

// splitComponents splits a cleaned relative path into its components.
func splitComponents(rel string) []string {
	out := make([]string, 0, 8)
	start := 0
	for i := 0; i < len(rel); i++ {
		if rel[i] == '/' {
			if i > start {
				out = append(out, rel[start:i])
			}
			start = i + 1
		}
	}
	if start < len(rel) {
		out = append(out, rel[start:])
	}
	return out
}

// readNames lists the entries of the directory dirfd refers to. dirfd may be an
// O_PATH descriptor; a fresh readable descriptor is opened for the read so the
// caller's file offset is untouched. The result is sorted.
func readNames(dirfd int) ([]string, error) {
	fd, err := unix.Openat(dirfd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "hull-layer-dir")
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// removeAt deletes name below dirfd, recursing into directories. A missing
// entry is not an error. Nothing is ever followed: directories are reopened
// with O_NOFOLLOW and every unlink is relative to a descriptor.
func removeAt(dirfd int, name string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(dirfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
		return nil
	}
	sub, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	err = removeChildren(sub)
	_ = unix.Close(sub)
	if err != nil {
		return err
	}
	if err := unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

// removeChildren empties the directory dirfd refers to, leaving it in place.
// This is what an opaque-directory marker means when a layer is applied onto a
// plain directory rather than onto an overlay upperdir.
func removeChildren(dirfd int) error {
	names, err := readNames(dirfd)
	if err != nil {
		return err
	}
	for _, n := range names {
		if n == "." || n == ".." {
			continue
		}
		if err := removeAt(dirfd, n); err != nil {
			return fmt.Errorf("remove %q: %w", n, err)
		}
	}
	return nil
}
