package initspec

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// openat2Broken records that openat2(2) answered ENOSYS, so the fd-relative
// walk is used instead. It is a one-way latch: a kernel does not grow the
// syscall halfway through a container start.
var openat2Broken atomic.Bool

// HaveOpenat2 probes openat2(2) once and caches the answer. The probe has no
// side effects: it opens "." on AT_FDCWD with an empty resolve mask.
func HaveOpenat2() bool {
	if openat2Broken.Load() {
		return false
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, ".",
		&unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC | unix.O_DIRECTORY})
	if err != nil {
		if errors.Is(err, unix.ENOSYS) {
			openat2Broken.Store(true)
			return false
		}
		// EPERM from a seccomp filter is not a missing syscall, but hull
		// cannot use it either.
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			openat2Broken.Store(true)
			return false
		}
		return true
	}
	unix.Close(fd)
	return true
}

// OpenInRoot opens rel strictly inside the directory rootFD refers to and
// returns a raw descriptor the caller owns.
//
// This is the only path resolution the container stage ever does against
// container-controlled data. It uses openat2 with
// RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS so that:
//
//   - an absolute symlink such as /etc -> / resolves inside the container,
//     never on the host (the runc CVE-2019-16884 / CVE-2021-30465 class);
//   - ".." can never climb above rootFD, even mid-resolution;
//   - a magic link under /proc/<pid>/fd cannot be traversed, which is what
//     CVE-2024-21626 turned into a working escape.
//
// Unlike fsutil.SecureOpen it does NOT set RESOLVE_NO_XDEV, because the stage
// legitimately resolves paths that cross mounts it has just made itself, such
// as /proc/kcore for the masked-paths pass.
//
// rel may be absolute; it is always interpreted relative to rootFD.
func OpenInRoot(rootFD int, rel string, flags int, mode uint32) (int, error) {
	name := strings.TrimPrefix(rel, "/")
	if name == "" {
		name = "."
	}
	if !HaveOpenat2() {
		return openInRootWalk(rootFD, name, flags, mode)
	}
	how := &unix.OpenHow{
		Flags:   uint64(flags) | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	if flags&unix.O_CREAT != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE {
		how.Mode = uint64(mode & 0o7777)
	}
	fd, err := unix.Openat2(rootFD, name, how)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) {
			openat2Broken.Store(true)
			return openInRootWalk(rootFD, name, flags, mode)
		}
		return -1, &os.PathError{Op: "openat2", Path: rel, Err: err}
	}
	return fd, nil
}

// maxWalkHops bounds symlink resolution in the fallback walk, matching the
// kernel's own SYMLOOP_MAX.
const maxWalkHops = 40

// openInRootWalk resolves rel one component at a time from rootFD with
// O_NOFOLLOW, re-anchoring every symlink at rootFD. It is the pre-5.6 fallback
// for OpenInRoot and gives the same containment guarantee, only not atomically:
// a component swapped between the lstat and the openat is caught by
// O_NOFOLLOW, so the worst case is a failed start, never an escape.
func openInRootWalk(rootFD int, rel string, flags int, mode uint32) (int, error) {
	parts := splitPath(rel)
	stack := []int{rootFD}
	hops := 0
	closeStack := func() {
		for _, fd := range stack[1:] {
			unix.Close(fd)
		}
		stack = stack[:1]
	}
	defer func() { closeStack() }()

	for len(parts) > 0 {
		c := parts[0]
		parts = parts[1:]
		top := stack[len(stack)-1]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(stack) > 1 {
				unix.Close(stack[len(stack)-1])
				stack = stack[:len(stack)-1]
			}
			continue
		}
		last := len(parts) == 0

		var st unix.Stat_t
		if err := unix.Fstatat(top, c, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil &&
			st.Mode&unix.S_IFMT == unix.S_IFLNK {
			hops++
			if hops > maxWalkHops {
				return -1, &os.PathError{Op: "open", Path: rel, Err: unix.ELOOP}
			}
			buf := make([]byte, unix.PathMax)
			n, err := unix.Readlinkat(top, c, buf)
			if err != nil {
				return -1, &os.PathError{Op: "readlinkat", Path: rel, Err: err}
			}
			target := string(buf[:n])
			if strings.HasPrefix(target, "/") {
				closeStack()
			}
			parts = append(splitPath(target), parts...)
			continue
		}

		openFlags := unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW
		var m uint32
		if last {
			openFlags = flags | unix.O_CLOEXEC | unix.O_NOFOLLOW
			if flags&unix.O_CREAT != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE {
				m = mode & 0o7777
			}
		} else {
			openFlags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(top, c, openFlags, m)
		if err != nil {
			return -1, &os.PathError{Op: "openat", Path: rel, Err: err}
		}
		if last {
			return fd, nil
		}
		stack = append(stack, fd)
	}
	// The whole path resolved to the root itself.
	fd, err := unix.Openat(stack[len(stack)-1], ".", flags|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, &os.PathError{Op: "openat", Path: rel, Err: err}
	}
	return fd, nil
}

func splitPath(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// MkdirAllInRoot creates rel and every missing parent inside rootFD, resolving
// each prefix through OpenInRoot so a symlink planted halfway down cannot
// redirect the mkdir out of the container.
func MkdirAllInRoot(rootFD int, rel string, perm uint32) error {
	parts := splitPath(rel)
	cur := ""
	for i, c := range parts {
		if c == "" || c == "." {
			continue
		}
		if c == ".." {
			return fmt.Errorf("initspec: refusing to create %q: it climbs out of the container root", rel)
		}
		parent := cur
		cur = cur + "/" + c
		pfd, err := OpenInRoot(rootFD, parent, unix.O_PATH|unix.O_DIRECTORY, 0)
		if err != nil {
			return fmt.Errorf("initspec: mkdir %q: open parent %q: %w", rel, parent, err)
		}
		// mkdirat needs a real directory fd, not O_PATH, on older kernels;
		// go through /proc/self/fd to get one that always works.
		err = unix.Mkdirat(pfd, c, perm&0o7777)
		unix.Close(pfd)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("initspec: mkdirat %q (component %d of %q): %w", cur, i, rel, err)
		}
	}
	return nil
}

// EnsureFileInRoot makes sure rel exists inside rootFD as a regular file,
// creating it and any missing parent directory. It is how a bind-mount
// destination for a file is prepared.
func EnsureFileInRoot(rootFD int, rel string, perm uint32) error {
	dir, base := splitDir(rel)
	if base == "" {
		return fmt.Errorf("initspec: %q has no final component", rel)
	}
	if dir != "" {
		if err := MkdirAllInRoot(rootFD, dir, 0o755); err != nil {
			return err
		}
	}
	fd, err := OpenInRoot(rootFD, rel, unix.O_RDONLY|unix.O_CREAT|unix.O_NOFOLLOW, perm)
	if err != nil {
		return fmt.Errorf("initspec: create %q: %w", rel, err)
	}
	unix.Close(fd)
	return nil
}

func splitDir(p string) (dir, base string) {
	p = strings.TrimSuffix(p, "/")
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return "", p
	}
	return p[:i], p[i+1:]
}

// ProcFD renders the /proc/self/fd path for a descriptor. It is used only for
// syscalls that take a path and have no ...at form (mount(2) targets, mostly);
// the descriptor it names was opened with OpenInRoot, so the path it stands for
// cannot have been switched under us.
func ProcFD(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

// HaveCloseRange probes close_range(2) with a deliberately inverted range,
// which a kernel that implements it rejects with EINVAL and one that does not
// rejects with ENOSYS.
func HaveCloseRange() bool {
	err := unix.CloseRange(2, 1, 0)
	return !errors.Is(err, unix.ENOSYS)
}

// CloseRangeFrom closes every descriptor from first upwards.
//
// This is the CVE-2024-21626 mitigation: a descriptor leaked into the
// container - especially one pointing at a host directory - lets the container
// walk out through /proc/self/fd. Every fd above stderr is closed immediately
// before execve, whether hull knows what it is or not.
func CloseRangeFrom(first uint) error {
	if err := unix.CloseRange(first, ^uint(0), 0); err != nil {
		if !errors.Is(err, unix.ENOSYS) {
			return fmt.Errorf("initspec: close_range(%d, ~0): %w", first, err)
		}
		return closeRangeFallback(first)
	}
	return nil
}

// closeRangeFallback closes descriptors one at a time by reading
// /proc/self/fd, for kernels older than 5.9.
func closeRangeFallback(first uint) error {
	d, err := os.Open("/proc/self/fd")
	if err != nil {
		return fmt.Errorf("initspec: close_range fallback: open /proc/self/fd: %w", err)
	}
	names, err := d.Readdirnames(-1)
	selfFD := int(d.Fd())
	d.Close()
	if err != nil {
		return fmt.Errorf("initspec: close_range fallback: read /proc/self/fd: %w", err)
	}
	fds := make([]int, 0, len(names))
	for _, n := range names {
		v, err := strconv.Atoi(n)
		if err != nil || v == selfFD || uint(v) < first {
			continue
		}
		fds = append(fds, v)
	}
	sort.Ints(fds)
	for _, fd := range fds {
		unix.Close(fd)
	}
	return nil
}

// SanitizeFDs closes every inherited descriptor above stderr except the ones
// listed in keep, which must be small and sorted-by-nothing. It is used early
// in the container stage, before any container-controlled code could observe
// them; CloseRangeFrom(3) runs again immediately before execve.
func SanitizeFDs(keep ...int) error {
	set := map[int]bool{}
	for _, fd := range keep {
		if fd >= 3 {
			set[fd] = true
		}
	}
	ordered := make([]int, 0, len(set))
	for fd := range set {
		ordered = append(ordered, fd)
	}
	sort.Ints(ordered)

	next := uint(3)
	for _, fd := range ordered {
		if uint(fd) > next {
			if err := closeRangeBetween(next, uint(fd)-1); err != nil {
				return err
			}
		}
		next = uint(fd) + 1
	}
	return CloseRangeFrom(next)
}

func closeRangeBetween(first, last uint) error {
	if first > last {
		return nil
	}
	if err := unix.CloseRange(first, last, 0); err != nil {
		if !errors.Is(err, unix.ENOSYS) {
			return fmt.Errorf("initspec: close_range(%d, %d): %w", first, last, err)
		}
		for fd := first; fd <= last; fd++ {
			unix.Close(int(fd))
		}
	}
	return nil
}

// SendMessage writes one handshake frame to a SOCK_SEQPACKET socket.
func SendMessage(fd int, m *Message) error {
	b, err := m.Encode()
	if err != nil {
		return err
	}
	if len(b) > MaxMessage {
		return fmt.Errorf("initspec: %s message is %d bytes, over the %d-byte limit", m.Type, len(b), MaxMessage)
	}
	for {
		n, err := unix.Write(fd, b)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("initspec: send %s message: %w", m.Type, err)
		}
		if n != len(b) {
			return fmt.Errorf("initspec: send %s message: short write %d of %d", m.Type, n, len(b))
		}
		return nil
	}
}

// RecvMessage reads one handshake frame from a SOCK_SEQPACKET socket. A frame
// of length zero means the peer closed the socket, which is reported as
// io.EOF-like error text rather than an empty message.
func RecvMessage(fd int) (*Message, error) {
	buf := make([]byte, MaxMessage)
	for {
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("initspec: receive message: %w", err)
		}
		if n == 0 {
			return nil, fmt.Errorf("initspec: receive message: peer closed the handshake socket")
		}
		return DecodeMessage(buf[:n])
	}
}

// SealedMemfd creates an anonymous, sealed, in-memory file holding data and
// returns it as an *os.File the caller owns.
//
// The seals matter: F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK make the contents
// permanently immutable even to the creator, and F_SEAL_SEAL stops anyone
// removing the other three. Passing this fd to a container and exec'ing
// /proc/self/fd/<n> is what lets hull never re-exec /proc/self/exe, which is
// the whole of CVE-2019-5736: a container that can write to the runtime binary
// it is about to be re-exec'd from owns the host.
func SealedMemfd(name string, data []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("initspec: memfd_create(%q): %w", name, err)
	}
	f := os.NewFile(uintptr(fd), "memfd:"+name)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return nil, fmt.Errorf("initspec: write %d bytes to memfd %q: %w", len(data), name, err)
	}
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		f.Close()
		return nil, fmt.Errorf("initspec: seal memfd %q: %w", name, err)
	}
	return f, nil
}

// MemfdSeals returns the seals currently set on fd, for tests and for the
// runtime's own assertion that the init binary really is immutable.
func MemfdSeals(fd uintptr) (int, error) {
	s, err := unix.FcntlInt(fd, unix.F_GET_SEALS, 0)
	if err != nil {
		return 0, fmt.Errorf("initspec: F_GET_SEALS: %w", err)
	}
	return s, nil
}

// AllSeals is the seal set SealedMemfd applies.
const AllSeals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
