package shim

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// OpenPTY allocates a pseudoterminal pair and returns the master and the
// slave.
//
// This is posix_openpt/grantpt/unlockpt without libc: /dev/ptmx is opened,
// TIOCSPTLCK unlocks the slave (grantpt is a no-op on Linux with devpts, where
// the kernel already gives the slave the right owner and mode) and TIOCGPTN
// names it. Both fds are opened O_NOCTTY so the shim, which is not a session
// leader, can never acquire the terminal by accident, and O_CLOEXEC so neither
// leaks across an exec.
func OpenPTY() (master, slave *os.File, err error) {
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("shim: open /dev/ptmx: %w", err)
	}
	defer func() {
		if err != nil {
			unix.Close(mfd)
		}
	}()

	// unlockpt: clear the slave's lock. Without this, opening the slave fails
	// with EIO.
	if err := unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		return nil, nil, fmt.Errorf("shim: unlock pty slave (TIOCSPTLCK): %w", err)
	}
	n, err := unix.IoctlGetInt(mfd, unix.TIOCGPTN)
	if err != nil {
		return nil, nil, fmt.Errorf("shim: get pty number (TIOCGPTN): %w", err)
	}
	slavePath := "/dev/pts/" + strconv.Itoa(n)
	sfd, err := unix.Open(slavePath, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("shim: open pty slave %s: %w", slavePath, err)
	}
	return os.NewFile(uintptr(mfd), "ptmx"), os.NewFile(uintptr(sfd), slavePath), nil
}

// SetWinsize applies a window size to a terminal fd with TIOCSWINSZ. h is rows
// and w is columns; both must be non-zero or the kernel reports a 0x0 terminal
// and full-screen programs draw nothing.
func SetWinsize(f *os.File, h, w uint16) error {
	if f == nil {
		return ErrNoTerminal
	}
	if h == 0 || w == 0 {
		return fmt.Errorf("shim: refusing a %dx%d terminal size: both dimensions must be non-zero", h, w)
	}
	ws := &unix.Winsize{Row: h, Col: w}
	if err := unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ, ws); err != nil {
		return fmt.Errorf("shim: set terminal size to %dx%d (TIOCSWINSZ): %w", h, w, err)
	}
	return nil
}

// ConsoleSocket is the receiving half of the OCI --console-socket protocol.
//
// The runtime is handed the path of a unix SOCK_STREAM socket; it allocates
// the container's pty, connects, and sends the *master* fd over SCM_RIGHTS
// before it execs the container. The shim keeps that master for the life of
// the container, which is precisely why the container's terminal survives a
// hulld restart: the fd never belonged to hulld in the first place.
type ConsoleSocket struct {
	path string
	l    *net.UnixListener
}

// NewConsoleSocket creates and listens on a console socket at path. The path
// must be short: it goes into sockaddr_un.sun_path, which is 108 bytes.
func NewConsoleSocket(path string) (*ConsoleSocket, error) {
	if len(path) >= 108 {
		return nil, fmt.Errorf("shim: console socket path %s is %d bytes, over the 108 byte sockaddr_un limit", path, len(path))
	}
	// A socket left by a crashed shim would make Listen fail with EADDRINUSE.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("shim: remove stale console socket %s: %w", path, err)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("shim: listen on console socket %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, fmt.Errorf("shim: chmod console socket %s: %w", path, err)
	}
	return &ConsoleSocket{path: path, l: l}, nil
}

// Path is the socket path to pass to the runtime as --console-socket.
func (cs *ConsoleSocket) Path() string { return cs.path }

// Receive waits up to timeout for the runtime to connect and send the pty
// master, and returns it.
func (cs *ConsoleSocket) Receive(timeout time.Duration) (*os.File, error) {
	if err := cs.l.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("shim: set console socket deadline: %w", err)
	}
	conn, err := cs.l.AcceptUnix()
	if err != nil {
		return nil, fmt.Errorf("shim: the runtime did not hand over the container terminal within %s: %w", timeout, err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("shim: set console read deadline: %w", err)
	}
	return RecvFD(conn)
}

// Close stops listening and removes the socket.
func (cs *ConsoleSocket) Close() error {
	err := cs.l.Close()
	if rerr := os.Remove(cs.path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) && err == nil {
		err = rerr
	}
	return err
}

// RecvFD reads one file descriptor from conn's ancillary data (SCM_RIGHTS).
// Any ordinary payload sent alongside it — runc and crun send a short name —
// is read and discarded.
func RecvFD(conn *net.UnixConn) (*os.File, error) {
	name := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(name, oob)
	if err != nil {
		return nil, fmt.Errorf("shim: read file descriptor from unix socket: %w", err)
	}
	if oobn == 0 {
		return nil, fmt.Errorf("shim: peer sent %d bytes but no file descriptor", n)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("shim: parse socket control message: %w", err)
	}
	if len(msgs) != 1 {
		return nil, fmt.Errorf("shim: expected one control message, got %d", len(msgs))
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil {
		return nil, fmt.Errorf("shim: parse SCM_RIGHTS: %w", err)
	}
	if len(fds) != 1 {
		// Close whatever did arrive rather than leaking it.
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, fmt.Errorf("shim: expected exactly one file descriptor, got %d", len(fds))
	}
	unix.CloseOnExec(fds[0])
	label := string(name[:n])
	if label == "" {
		label = "console"
	}
	return os.NewFile(uintptr(fds[0]), label), nil
}

// SendFD writes f to conn as SCM_RIGHTS ancillary data, with its name as the
// ordinary payload. It is the sending half of the same protocol, used when
// hull's own runtime asks the shim for a terminal instead of allocating one.
func SendFD(conn *net.UnixConn, f *os.File) error {
	if f == nil {
		return errors.New("shim: SendFD needs a file")
	}
	rights := unix.UnixRights(int(f.Fd()))
	name := []byte(f.Name())
	if len(name) == 0 {
		name = []byte("fd")
	}
	if _, _, err := conn.WriteMsgUnix(name, rights, nil); err != nil {
		return fmt.Errorf("shim: send file descriptor over unix socket: %w", err)
	}
	return nil
}
