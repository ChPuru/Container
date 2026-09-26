package runtime

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/runtime/initspec"
)

// openPTY allocates a UNIX98 pseudo-terminal pair and returns the master and
// the peer.
//
// The peer is opened by number under /dev/pts on the host, before the
// container's mount namespace exists, and is handed to the container stage as
// a descriptor. The stage confirms it with fstat and never re-opens it by
// path, which is the shape of the 2025 runc console CVEs
// (CVE-2025-31133 / 52565 / 52881).
func openPTY() (master, peer *os.File, err error) {
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("runtime: open /dev/ptmx: %w", err)
	}
	master = os.NewFile(uintptr(mfd), "pty-master")
	defer func() {
		if err != nil {
			master.Close()
		}
	}()

	// unlockpt
	if err = unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		return nil, nil, fmt.Errorf("runtime: unlock pty: %w", err)
	}
	n, err := unix.IoctlGetInt(mfd, unix.TIOCGPTN)
	if err != nil {
		return nil, nil, fmt.Errorf("runtime: read pty number: %w", err)
	}
	name := "/dev/pts/" + strconv.Itoa(n)
	pfd, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("runtime: open pty peer %s: %w", name, err)
	}
	peer = os.NewFile(uintptr(pfd), name)
	if verr := initspec.VerifyConsoleFD(pfd); verr != nil {
		peer.Close()
		return nil, nil, verr
	}
	return master, peer, nil
}

// ResizePTY sets the window size of a pty master.
func ResizePTY(master *os.File, rows, cols uint16) error {
	ws := unix.Winsize{Row: rows, Col: cols}
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &ws); err != nil {
		return fmt.Errorf("runtime: resize pty to %dx%d: %w", cols, rows, err)
	}
	return nil
}

// sendConsoleMaster hands the pty master to a listener on an AF_UNIX socket as
// SCM_RIGHTS, which is the protocol every OCI runtime uses for
// --console-socket. hull's shim is normally the listener.
func sendConsoleMaster(socketPath string, master *os.File) error {
	conn, err := net.DialTimeout("unix", socketPath, 10*time.Second)
	if err != nil {
		return fmt.Errorf("runtime: dial console socket %s: %w", socketPath, err)
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("runtime: console socket %s is not a unix socket", socketPath)
	}
	rights := syscall.UnixRights(int(master.Fd()))
	// The payload is the pty name, which is what runc sends and what
	// existing console-socket receivers expect to see.
	if _, _, err := uc.WriteMsgUnix([]byte(master.Name()), rights, nil); err != nil {
		return fmt.Errorf("runtime: send console master over %s: %w", socketPath, err)
	}
	return nil
}

// Console returns the pty master of a container created with Terminal set and
// no ConsoleSocket, so the caller can read from and write to it. It returns
// nil when the container has no terminal or the master was handed to a console
// socket.
func (r *NativeRuntime) Console(id string) (*os.File, error) {
	c, err := r.lookup(id)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.console, nil
}
