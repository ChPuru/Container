package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// maxSymlinkHops bounds symlink expansion in the fallback resolver. The kernel
// uses 40 for the same purpose, so a path that resolves natively also resolves
// here, and a symlink loop terminates instead of spinning.
const maxSymlinkHops = 40

var (
	openat2Once     sync.Once
	openat2Have     bool
	openat2Disabled atomic.Bool
)

// ProbeOpenat2 reports whether this kernel implements openat2(2) with the
// RESOLVE_* flags hull depends on. The probe runs once and the answer is
// cached, because it is consulted on every path resolution during a layer
// extraction.
//
// WSL 5.15 has openat2; the fallback exists for seccomp-filtered or older
// environments, and for the forced-fallback unit tests.
func ProbeOpenat2() bool {
	if openat2Disabled.Load() {
		return false
	}
	openat2Once.Do(func() { openat2Have = probeOpenat2() })
	return openat2Have
}

func probeOpenat2() bool {
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECTORY),
		Resolve: unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, "/", how)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// setOpenat2Disabled forces (or restores) use of the fd-relative walk instead
// of openat2. It exists so the unit tests can exercise both resolvers on the
// same kernel; nothing outside tests may call it.
func setOpenat2Disabled(v bool) { openat2Disabled.Store(v) }

// SecureOpen opens path strictly inside root and returns the open file.
//
// path must be relative to root: an absolute path or one that lexically climbs
// out with ".." is rejected with ErrUnsafePath before any syscall runs. Symlink
// escapes are contained rather than trusted — a link to /etc/passwd resolves to
// root/etc/passwd, which usually does not exist, so the open fails instead of
// reaching the host file. Crossing a mount point inside root is refused
// (EXDEV), and magic links such as /proc/*/fd/* are never followed.
//
// flags and mode are the usual openat(2) arguments; mode is honoured only with
// O_CREAT or O_TMPFILE, matching the kernel. An empty path opens root itself.
//
// On a kernel with openat2(2) this is a single syscall with
// RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV, which is race-free by
// construction. Otherwise it walks the path component by component from a
// directory fd with O_NOFOLLOW, reading and re-anchoring each symlink itself.
func SecureOpen(root string, path string, flags int, mode os.FileMode) (*os.File, error) {
	if err := checkSecureArgs(root, path, "SecureOpen"); err != nil {
		return nil, err
	}
	if ProbeOpenat2() {
		f, err := secureOpenat2(root, path, flags, mode)
		if err == nil || !errors.Is(err, unix.ENOSYS) {
			return f, err
		}
		// The probe succeeded but this call was refused: fall through to the
		// walk rather than failing the operation.
	}
	return secureOpenFallback(root, path, flags, mode)
}

// SecureStat stats path inside root with the same containment rules as
// SecureOpen, following symlinks but never letting one leave root.
func SecureStat(root, path string) (os.FileInfo, error) {
	f, err := SecureOpen(root, path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("fsutil: stat %s in %s: %w", path, root, err)
	}
	return fi, nil
}

// SecureMkdirAll creates path and every missing parent inside root, one
// component at a time, resolving each prefix through SecureOpen so that a
// symlink planted halfway down cannot redirect the mkdir out of root.
//
// Components that already exist are accepted if they are directories (or
// symlinks to directories inside root) and rejected otherwise. perm is applied
// with an explicit fchmod after creation, so the umask does not silently
// weaken or strengthen it.
func SecureMkdirAll(root, path string, perm os.FileMode) error {
	if err := checkSecureArgs(root, path, "SecureMkdirAll"); err != nil {
		return err
	}
	cur := ""
	for _, c := range splitComponents(path) {
		if c == ".." {
			// Unreachable: checkSecureArgs rejects lexical escapes. Kept as a
			// belt-and-braces guard so a future caller cannot slip one past.
			return fmt.Errorf("fsutil: SecureMkdirAll %q under %s: %w", path, root, ErrUnsafePath)
		}
		parent := cur
		cur = pathJoin(cur, c)

		dirf, err := SecureOpen(root, parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("fsutil: SecureMkdirAll: open parent %q of %q: %w", parent, cur, err)
		}
		dirfd := int(dirf.Fd())
		mkErr := unix.Mkdirat(dirfd, c, uint32(perm.Perm()))
		if mkErr == nil {
			// Re-open what we just made, by fd, to defeat the umask without a
			// path-based chmod that a racing symlink could redirect.
			if fd, oerr := unix.Openat(dirfd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); oerr == nil {
				cerr := unix.Fchmod(fd, uint32(perm.Perm()))
				unix.Close(fd)
				if cerr != nil {
					dirf.Close()
					return fmt.Errorf("fsutil: SecureMkdirAll: chmod %q in %s: %w", cur, root, cerr)
				}
			}
			dirf.Close()
			continue
		}
		dirf.Close()
		if !errors.Is(mkErr, unix.EEXIST) {
			return fmt.Errorf("fsutil: SecureMkdirAll: mkdir %q in %s: %w", cur, root, mkErr)
		}
		fi, serr := SecureStat(root, cur)
		if serr != nil {
			return fmt.Errorf("fsutil: SecureMkdirAll: stat existing %q: %w", cur, serr)
		}
		if !fi.IsDir() {
			return fmt.Errorf("fsutil: SecureMkdirAll: %q in %s exists and is not a directory: %w", cur, root, unix.ENOTDIR)
		}
	}
	return nil
}

// checkSecureArgs performs the cheap, purely lexical rejections shared by every
// Secure* entry point.
func checkSecureArgs(root, p, op string) error {
	if root == "" {
		return fmt.Errorf("fsutil: %s: empty root", op)
	}
	if !filepath.IsAbs(root) {
		return fmt.Errorf("fsutil: %s: root %q must be absolute", op, root)
	}
	if strings.HasPrefix(filepath.ToSlash(p), "/") {
		return fmt.Errorf("fsutil: %s: %q is absolute, pass a path relative to %s: %w", op, p, root, ErrUnsafePath)
	}
	if IsEscape(root, p) {
		return fmt.Errorf("fsutil: %s: %q leaves %s: %w", op, p, root, ErrUnsafePath)
	}
	return nil
}

// pathJoin joins two in-root components with forward slashes, without ever
// producing a leading slash.
func pathJoin(a, b string) string {
	if a == "" {
		return b
	}
	return path.Join(a, b)
}

// forError builds a display path for error messages only. It is never used to
// open anything.
func forError(root, rel string) string {
	if rel == "" {
		return root
	}
	return root + "/" + rel
}

// secureOpenat2 resolves rel inside root in one syscall.
func secureOpenat2(root, rel string, flags int, mode os.FileMode) (*os.File, error) {
	rootFd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: root, Err: err}
	}
	defer unix.Close(rootFd)

	name := rel
	if name == "" {
		name = "."
	}
	how := &unix.OpenHow{
		Flags:   uint64(flags) | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	}
	if flags&unix.O_CREAT != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE {
		how.Mode = uint64(mode.Perm())
	}
	fd, err := unix.Openat2(rootFd, name, how)
	if err != nil {
		return nil, &os.PathError{Op: "openat2", Path: forError(root, rel), Err: err}
	}
	return os.NewFile(uintptr(fd), forError(root, rel)), nil
}

// walker holds the directory-fd stack of an in-progress fallback resolution.
// stack[0] is the caller's root fd and is never closed here.
type walker struct {
	rootDev uint64
	stack   []int
	hops    int
}

func (w *walker) top() int { return w.stack[len(w.stack)-1] }

func (w *walker) push(fd int) { w.stack = append(w.stack, fd) }

// pop moves to the parent directory. At the root it is a no-op, which is
// exactly RESOLVE_IN_ROOT semantics: root is its own parent.
func (w *walker) pop() {
	if len(w.stack) > 1 {
		unix.Close(w.stack[len(w.stack)-1])
		w.stack = w.stack[:len(w.stack)-1]
	}
}

// reset returns to the root, used when a symlink target is absolute.
func (w *walker) reset() {
	for len(w.stack) > 1 {
		w.pop()
	}
}

func (w *walker) close() { w.reset() }

// readlink reads the symlink named name in the current directory.
func (w *walker) readlink(name string) (string, error) {
	buf := make([]byte, 256)
	for {
		n, err := unix.Readlinkat(w.top(), name, buf)
		if err != nil {
			return "", err
		}
		if n < len(buf) {
			return string(buf[:n]), nil
		}
		if len(buf) >= unix.PathMax*2 {
			return "", unix.ENAMETOOLONG
		}
		buf = make([]byte, len(buf)*2)
	}
}

// follow expands a symlink target in front of the components still to walk. An
// absolute target is re-anchored at the root, which contains the escape instead
// of trusting it.
func (w *walker) follow(target string, remaining []string) ([]string, error) {
	w.hops++
	if w.hops > maxSymlinkHops {
		return nil, unix.ELOOP
	}
	if strings.HasPrefix(target, "/") {
		w.reset()
	}
	tc := splitComponents(target)
	out := make([]string, 0, len(tc)+len(remaining))
	out = append(out, tc...)
	out = append(out, remaining...)
	return out, nil
}

// openFinal opens the last component from the current directory fd. O_NOFOLLOW
// is always added so the kernel never follows a link behind our back; a link
// found here is reported as ELOOP for the caller to resolve, unless the caller
// asked for O_NOFOLLOW itself.
func (w *walker) openFinal(name string, flags int, mode os.FileMode) (*os.File, error) {
	var m uint32
	if flags&unix.O_CREAT != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE {
		m = uint32(mode.Perm())
	}
	fd, err := unix.Openat(w.top(), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, m)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Dev != w.rootDev {
		unix.Close(fd)
		return nil, unix.EXDEV
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK && flags&unix.O_NOFOLLOW == 0 {
		// Only reachable with O_PATH, which opens the link itself. The caller
		// wanted the target, so report it like a non-O_PATH open would.
		unix.Close(fd)
		return nil, unix.ELOOP
	}
	return os.NewFile(uintptr(fd), name), nil
}

// secureOpenFallback resolves rel inside root without openat2, by opening each
// component from a directory fd with O_NOFOLLOW and handling symlinks itself.
func secureOpenFallback(root, rel string, flags int, mode os.FileMode) (*os.File, error) {
	rootFd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: root, Err: err}
	}
	defer unix.Close(rootFd)

	var rst unix.Stat_t
	if err := unix.Fstat(rootFd, &rst); err != nil {
		return nil, &os.PathError{Op: "fstat", Path: root, Err: err}
	}
	w := &walker{rootDev: rst.Dev, stack: []int{rootFd}}
	defer w.close()

	display := forError(root, rel)
	remaining := splitComponents(rel)
	for {
		if len(remaining) == 0 {
			f, err := w.openFinal(".", flags, mode)
			if err != nil {
				return nil, &os.PathError{Op: "openat", Path: display, Err: err}
			}
			f2 := os.NewFile(f.Fd(), display)
			_ = f // f and f2 share the descriptor; only f2 escapes.
			return f2, nil
		}
		c := remaining[0]
		remaining = remaining[1:]

		if c == ".." {
			w.pop()
			continue
		}

		if len(remaining) == 0 {
			f, ferr := w.openFinal(c, flags, mode)
			if ferr == nil {
				return os.NewFile(f.Fd(), display), nil
			}
			if !errors.Is(ferr, unix.ELOOP) || flags&unix.O_NOFOLLOW != 0 {
				return nil, &os.PathError{Op: "openat", Path: display, Err: ferr}
			}
			target, rerr := w.readlink(c)
			if rerr != nil {
				return nil, &os.PathError{Op: "readlinkat", Path: display, Err: rerr}
			}
			next, lerr := w.follow(target, remaining)
			if lerr != nil {
				return nil, &os.PathError{Op: "openat", Path: display, Err: lerr}
			}
			remaining = next
			continue
		}

		fd, oerr := unix.Openat(w.top(), c, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if oerr != nil {
			return nil, &os.PathError{Op: "openat", Path: display, Err: oerr}
		}
		var st unix.Stat_t
		if serr := unix.Fstat(fd, &st); serr != nil {
			unix.Close(fd)
			return nil, &os.PathError{Op: "fstat", Path: display, Err: serr}
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			unix.Close(fd)
			target, rerr := w.readlink(c)
			if rerr != nil {
				return nil, &os.PathError{Op: "readlinkat", Path: display, Err: rerr}
			}
			next, lerr := w.follow(target, remaining)
			if lerr != nil {
				return nil, &os.PathError{Op: "openat", Path: display, Err: lerr}
			}
			remaining = next
		case unix.S_IFDIR:
			if st.Dev != w.rootDev {
				unix.Close(fd)
				return nil, &os.PathError{Op: "openat", Path: display, Err: unix.EXDEV}
			}
			w.push(fd)
		default:
			unix.Close(fd)
			return nil, &os.PathError{Op: "openat", Path: display, Err: unix.ENOTDIR}
		}
	}
}
