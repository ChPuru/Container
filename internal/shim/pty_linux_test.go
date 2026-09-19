package shim

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// readWithTimeout does one blocking read in a goroutine. A pty master is a
// character device, which Go's runtime poller will not take, so SetReadDeadline
// is not available on it and a plain read has to be bounded this way.
func readWithTimeout(t *testing.T, f *os.File, d time.Duration) string {
	t.Helper()
	type result struct {
		s   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, 256)
		n, err := f.Read(buf)
		ch <- result{string(buf[:n]), err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("read %s: %v", f.Name(), res.err)
		}
		return res.s
	case <-time.After(d):
		t.Fatalf("timed out reading %s", f.Name())
		return ""
	}
}

func TestOpenPTY(t *testing.T) {
	t.Parallel()
	master, slave, err := OpenPTY()
	if err != nil {
		t.Fatalf("OpenPTY: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	if !strings.HasPrefix(slave.Name(), "/dev/pts/") {
		t.Errorf("slave name = %q, want a /dev/pts/N path", slave.Name())
	}
	// Both ends must be close-on-exec so neither leaks into a container.
	for _, f := range []*os.File{master, slave} {
		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
		if err != nil {
			t.Fatalf("F_GETFD on %s: %v", f.Name(), err)
		}
		if flags&unix.FD_CLOEXEC == 0 {
			t.Errorf("%s is not close-on-exec", f.Name())
		}
	}

	// Bytes written to the slave come out of the master.
	if _, err := slave.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write to slave: %v", err)
	}
	// A pty in canonical mode translates \n on output into \r\n.
	if got := readWithTimeout(t, master, 2*time.Second); got != "hello\r\n" && got != "hello\n" {
		t.Errorf("master read %q, want the slave's line", got)
	}
}

func TestSetWinsize(t *testing.T) {
	t.Parallel()
	master, slave, err := OpenPTY()
	if err != nil {
		t.Fatalf("OpenPTY: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	if err := SetWinsize(master, 40, 132); err != nil {
		t.Fatalf("SetWinsize: %v", err)
	}
	ws, err := unix.IoctlGetWinsize(int(slave.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		t.Fatalf("TIOCGWINSZ on the slave: %v", err)
	}
	if ws.Row != 40 || ws.Col != 132 {
		t.Fatalf("slave sees %dx%d, want 40x132", ws.Row, ws.Col)
	}

	if err := SetWinsize(nil, 24, 80); !errors.Is(err, ErrNoTerminal) {
		t.Errorf("SetWinsize(nil) = %v, want ErrNoTerminal", err)
	}
	for _, tc := range [][2]uint16{{0, 80}, {24, 0}, {0, 0}} {
		if err := SetWinsize(master, tc[0], tc[1]); err == nil {
			t.Errorf("SetWinsize(%d, %d) was accepted; a zero dimension blanks the terminal", tc[0], tc[1])
		}
	}
}

func TestSendAndReceiveFD(t *testing.T) {
	t.Parallel()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	sendFile := os.NewFile(uintptr(fds[0]), "send")
	recvFile := os.NewFile(uintptr(fds[1]), "recv")
	defer sendFile.Close()
	defer recvFile.Close()

	sendConn, err := net.FileConn(sendFile)
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	defer sendConn.Close()
	recvConn, err := net.FileConn(recvFile)
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	defer recvConn.Close()

	// Send one end of a pipe and prove the received fd is really it.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer pr.Close()
	defer pw.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- SendFD(sendConn.(*net.UnixConn), pr)
	}()

	got, err := RecvFD(recvConn.(*net.UnixConn))
	if err != nil {
		t.Fatalf("RecvFD: %v", err)
	}
	defer got.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("SendFD: %v", err)
	}

	if _, err := pw.Write([]byte("through the socket")); err != nil {
		t.Fatalf("write to the pipe: %v", err)
	}
	buf := make([]byte, 64)
	n, err := got.Read(buf)
	if err != nil {
		t.Fatalf("read from the received fd: %v", err)
	}
	if string(buf[:n]) != "through the socket" {
		t.Fatalf("received fd read %q", buf[:n])
	}

	flags, err := unix.FcntlInt(got.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD: %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Error("a received fd must be close-on-exec so it cannot leak into a container")
	}
}

func TestRecvFDRejectsAPlainMessage(t *testing.T) {
	t.Parallel()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	a := os.NewFile(uintptr(fds[0]), "a")
	b := os.NewFile(uintptr(fds[1]), "b")
	defer a.Close()
	defer b.Close()

	if _, err := a.Write([]byte("no fd here")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn, err := net.FileConn(b)
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	defer conn.Close()
	if _, err := RecvFD(conn.(*net.UnixConn)); err == nil {
		t.Fatal("RecvFD accepted a message with no file descriptor")
	}
}

func TestConsoleSocketReceivesTheMaster(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cs, err := NewConsoleSocket(filepath.Join(dir, "c.sock"))
	if err != nil {
		t.Fatalf("NewConsoleSocket: %v", err)
	}
	defer cs.Close()

	st, err := os.Stat(cs.Path())
	if err != nil {
		t.Fatalf("stat console socket: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("console socket mode = %o, want 600", perm)
	}

	master, slave, err := OpenPTY()
	if err != nil {
		t.Fatalf("OpenPTY: %v", err)
	}
	defer slave.Close()

	// Stand in for the runtime: connect and hand the master over.
	go func() {
		conn, err := net.Dial("unix", cs.Path())
		if err != nil {
			return
		}
		defer conn.Close()
		_ = SendFD(conn.(*net.UnixConn), master)
		master.Close()
	}()

	got, err := cs.Receive(5 * time.Second)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	defer got.Close()

	if _, err := slave.Write([]byte("from the container\n")); err != nil {
		t.Fatalf("write to slave: %v", err)
	}
	if line := readWithTimeout(t, got, 2*time.Second); !strings.HasPrefix(line, "from the container") {
		t.Fatalf("received master read %q", line)
	}
}

func TestConsoleSocketTimesOut(t *testing.T) {
	t.Parallel()
	cs, err := NewConsoleSocket(filepath.Join(t.TempDir(), "c.sock"))
	if err != nil {
		t.Fatalf("NewConsoleSocket: %v", err)
	}
	defer cs.Close()
	start := time.Now()
	if _, err := cs.Receive(100 * time.Millisecond); err == nil {
		t.Fatal("Receive should have timed out")
	} else if !strings.Contains(err.Error(), "did not hand over") {
		t.Fatalf("err = %v, want a clear hand-over timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Receive took %v to time out", elapsed)
	}
}

func TestConsoleSocketRejectsALongPath(t *testing.T) {
	t.Parallel()
	long := "/" + strings.Repeat("d", 120) + "/c.sock"
	if _, err := NewConsoleSocket(long); err == nil || !strings.Contains(err.Error(), "sockaddr_un") {
		t.Fatalf("err = %v, want a sockaddr_un length refusal", err)
	}
}

func TestConsoleSocketReplacesAStaleSocket(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "c.sock")
	first, err := NewConsoleSocket(path)
	if err != nil {
		t.Fatalf("NewConsoleSocket: %v", err)
	}
	// Leak the listener's socket file the way a crashed shim would.
	if err := first.l.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("recreate stale socket: %v", err)
	}
	second, err := NewConsoleSocket(path)
	if err != nil {
		t.Fatalf("NewConsoleSocket over a stale socket: %v", err)
	}
	second.Close()
}

func TestPidFD(t *testing.T) {
	t.Parallel()
	if _, err := OpenPidFD(0); err == nil {
		t.Error("OpenPidFD(0) should fail")
	}
	p, err := OpenPidFD(os.Getpid())
	if err != nil {
		t.Fatalf("OpenPidFD(self): %v", err)
	}
	defer p.Close()
	if p.Pid() != os.Getpid() {
		t.Errorf("Pid = %d, want %d", p.Pid(), os.Getpid())
	}
	if !p.Alive() {
		t.Error("this process should be alive")
	}
	// Signal 0 checks permission without delivering anything.
	if err := p.Signal(0); err != nil {
		t.Errorf("Signal(0) on self: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("a second Close returned %v, want nil", err)
	}
	if p.Alive() {
		t.Error("a closed pidfd should not report alive")
	}
	if err := p.Signal(unix.SIGTERM); err == nil {
		t.Error("signalling through a closed pidfd should fail")
	}
}
