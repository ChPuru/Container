//go:build windows

package wslbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// AF_HYPERV constants. x/sys/windows does not define them, and there is no
// reason to wait for it to: they are fixed numbers in the Windows SDK.
const (
	// afHyperV is AF_HYPERV.
	afHyperV = 34
	// hvProtocolRaw is HV_PROTOCOL_RAW, the only protocol AF_HYPERV defines.
	hvProtocolRaw = 1
	// sockaddrHVSize is sizeof(SOCKADDR_HV): family, reserved, and two GUIDs.
	sockaddrHVSize = 2 + 2 + 16 + 16
)

// hcsVolatileStore is where the Host Compute Service records the compute
// systems currently running. WSL2's utility VM is one of them, and its key name
// is the runtime ID an AF_HYPERV connect needs.
//
// This is an implementation detail of a component Microsoft does not document,
// and it has moved before. That is why this whole transport is optional.
const hcsVolatileStore = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\HostComputeService\VolatileStore\ComputeSystem`

// terminalServerClient is the second route. WSLg drives the VM's GUI over an
// RDP connection addressed by VM GUID, and the client leaves the GUID behind
// here. It is even less of a contract than the first route, which is why it is
// only consulted when the first finds nothing.
const terminalServerClient = `SOFTWARE\Microsoft\Terminal Server Client\Default\AddIns\WSLg`

// sockaddrHV is SOCKADDR_HV.
type sockaddrHV struct {
	Family    uint16
	Reserved  uint16
	VMID      windows.GUID
	ServiceID windows.GUID
}

// modws2_32 and procConnect reach ws2_32's connect directly: x/sys/windows'
// Connect takes a Sockaddr interface whose implementations are a closed set, so
// an AF_HYPERV address cannot be expressed through it.
var (
	modws2_32   = windows.NewLazySystemDLL("ws2_32.dll")
	procConnect = modws2_32.NewProc("connect")
)

// DiscoverVMIDs returns candidate runtime IDs for the WSL2 utility VM, most
// likely first. It never fails merely because a route is absent: an empty slice
// with a nil error means "nothing found here", which is an ordinary outcome.
func DiscoverVMIDs(ctx context.Context) ([]string, error) {
	_ = ctx
	var candidates []string
	var errs []error

	if ids, err := vmIDsFromHCS(); err != nil {
		errs = append(errs, err)
	} else {
		candidates = append(candidates, ids...)
	}
	if ids, err := vmIDsFromTerminalServer(); err != nil {
		errs = append(errs, err)
	} else {
		candidates = append(candidates, ids...)
	}

	candidates = dedupeGUIDs(candidates)
	if len(candidates) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return candidates, nil
}

// vmIDsFromHCS reads the Host Compute Service's volatile store.
func vmIDsFromHCS() ([]string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, hcsVolatileStore, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: open %s: %w", hcsVolatileStore, err)
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: enumerate %s: %w", hcsVolatileStore, err)
	}
	var out []string
	for _, name := range names {
		// The subkey name is itself the compute system's runtime ID on every
		// build seen so far. A RuntimeId value has also existed, so read it too
		// and let the race sort out which one answers.
		out = append(out, name)
		sub, err := registry.OpenKey(key, name, registry.READ)
		if err != nil {
			continue
		}
		if s, _, err := sub.GetStringValue("RuntimeId"); err == nil {
			out = append(out, s)
		} else if b, _, err := sub.GetBinaryValue("RuntimeId"); err == nil && len(b) == 16 {
			out = append(out, guidFromBytes(b).String())
		}
		sub.Close()
	}
	return out, nil
}

// vmIDsFromTerminalServer reads the GUID WSLg's RDP client leaves behind.
func vmIDsFromTerminalServer() ([]string, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, terminalServerClient, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: open HKCU\\%s: %w", terminalServerClient, err)
	}
	defer key.Close()

	var out []string
	names, err := key.ReadValueNames(-1)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: enumerate HKCU\\%s: %w", terminalServerClient, err)
	}
	for _, name := range names {
		if s, _, err := key.GetStringValue(name); err == nil && looksLikeGUID(normaliseGUID(s)) {
			out = append(out, s)
		}
	}
	return out, nil
}

// guidFromBytes reads a little-endian GUID out of its 16-byte binary form.
func guidFromBytes(b []byte) windows.GUID {
	var g windows.GUID
	g.Data1 = uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	g.Data2 = uint16(b[4]) | uint16(b[5])<<8
	g.Data3 = uint16(b[6]) | uint16(b[7])<<8
	copy(g.Data4[:], b[8:16])
	return g
}

// dialHVSock connects to one candidate VM on an AF_HYPERV port.
//
// The connect itself is blocking, so the timeout is enforced by closing the
// socket from another goroutine -- which is what unblocks a connect on Windows.
// That is crude, and it is deliberate: this transport must never be the reason
// a bridge takes longer than a second to start.
func dialHVSock(ctx context.Context, vmID string, port uint32, timeout time.Duration) (net.Conn, error) {
	vm, err := windows.GUIDFromString(braced(vmID))
	if err != nil {
		return nil, fmt.Errorf("wslbridge: parse VM id %q: %w", vmID, err)
	}
	service, err := windows.GUIDFromString(braced(HVServiceGUID(port)))
	if err != nil {
		return nil, fmt.Errorf("wslbridge: build service id for port %d: %w", port, err)
	}

	sock, err := windows.WSASocket(afHyperV, windows.SOCK_STREAM, hvProtocolRaw, nil, 0, windows.WSA_FLAG_OVERLAPPED)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: AF_HYPERV socket: %w", err)
	}

	sa := sockaddrHV{Family: afHyperV, VMID: vm, ServiceID: service}
	done := make(chan error, 1)
	go func() {
		r0, _, e1 := syscall.SyscallN(procConnect.Addr(),
			uintptr(sock), uintptr(unsafe.Pointer(&sa)), uintptr(sockaddrHVSize))
		if int32(r0) == -1 {
			done <- fmt.Errorf("wslbridge: connect to %s port %d: %w", vmID, port, error(e1))
			return
		}
		done <- nil
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			windows.Closesocket(sock)
			return nil, err
		}
	case <-timer.C:
		windows.Closesocket(sock)
		<-done
		return nil, fmt.Errorf("wslbridge: connect to %s port %d: %w", vmID, port, context.DeadlineExceeded)
	case <-ctx.Done():
		windows.Closesocket(sock)
		<-done
		return nil, ctx.Err()
	}

	conn, err := newHVSockConn(sock, fmt.Sprintf("%s:%d", vmID, port))
	if err != nil {
		windows.Closesocket(sock)
		return nil, err
	}
	return conn, nil
}

// hvsockConn is a net.Conn over a connected AF_HYPERV socket.
//
// The socket is created WSA_FLAG_OVERLAPPED, and an overlapped socket handle is
// an ordinary overlapped kernel handle: ReadFile and WriteFile drive it exactly
// as they drive a named pipe. Only teardown differs -- a socket is released with
// closesocket, so Winsock drops its own bookkeeping too.
//
// This does not reuse the named pipe's connection type on purpose. hvsock is the
// transport hull must never depend on, and coupling it to the one that carries
// every byte in the default configuration would be the wrong direction of
// dependency.
type hvsockConn struct {
	sock windows.Handle
	name string

	rmu sync.Mutex
	rev windows.Handle
	rdl atomic.Int64 // read deadline in unix nanoseconds; 0 means none

	wmu sync.Mutex
	wev windows.Handle
	wdl atomic.Int64

	mu     sync.Mutex
	closed bool
}

var _ net.Conn = (*hvsockConn)(nil)

// newHVSockConn wraps a connected AF_HYPERV socket.
func newHVSockConn(sock windows.Handle, name string) (*hvsockConn, error) {
	rev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: create hvsock read event: %w", err)
	}
	wev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(rev)
		return nil, fmt.Errorf("wslbridge: create hvsock write event: %w", err)
	}
	return &hvsockConn{sock: sock, name: name, rev: rev, wev: wev}, nil
}

// Read implements net.Conn.
func (c *hvsockConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()

	if c.isClosed() {
		return 0, net.ErrClosed
	}
	n, err := c.await(c.rev, hvDeadline(&c.rdl), false, p)
	if err != nil {
		return n, c.wrap("read", err)
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// Write implements net.Conn.
func (c *hvsockConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()

	if c.isClosed() {
		return 0, net.ErrClosed
	}
	total := 0
	for total < len(p) {
		n, err := c.await(c.wev, hvDeadline(&c.wdl), true, p[total:])
		total += n
		if err != nil {
			return total, c.wrap("write", err)
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

// await issues one overlapped operation and waits for it, cancelling the I/O
// rather than abandoning it when the deadline expires -- the kernel would
// otherwise still be writing into the caller's buffer.
func (c *hvsockConn) await(event windows.Handle, deadline time.Time, write bool, p []byte) (int, error) {
	windows.ResetEvent(event)
	ov := &windows.Overlapped{HEvent: event}

	var (
		done uint32
		err  error
	)
	if write {
		err = windows.WriteFile(c.sock, p, &done, ov)
	} else {
		err = windows.ReadFile(c.sock, p, &done, ov)
	}
	if err == nil {
		return int(done), nil
	}
	if err != windows.ERROR_IO_PENDING {
		return int(done), err
	}

	timeout := uint32(windows.INFINITE)
	if !deadline.IsZero() {
		if remaining := time.Until(deadline); remaining <= 0 {
			timeout = 0
		} else {
			timeout = uint32(remaining.Milliseconds()) + 1
		}
	}
	which, werr := windows.WaitForSingleObject(event, timeout)
	if werr != nil {
		return 0, werr
	}
	if which == uint32(windows.WAIT_TIMEOUT) {
		windows.CancelIoEx(c.sock, ov)
		var transferred uint32
		windows.GetOverlappedResult(c.sock, ov, &transferred, true)
		if transferred > 0 {
			return int(transferred), nil
		}
		return 0, os.ErrDeadlineExceeded
	}
	var transferred uint32
	if err := windows.GetOverlappedResult(c.sock, ov, &transferred, false); err != nil {
		return int(transferred), err
	}
	return int(transferred), nil
}

// isClosed reports whether Close has run.
func (c *hvsockConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// wrap turns Winsock errors into the ones Go code expects.
func (c *hvsockConn) wrap(op string, err error) error {
	switch err {
	case nil:
		return nil
	case os.ErrDeadlineExceeded:
		return os.ErrDeadlineExceeded
	case windows.ERROR_OPERATION_ABORTED, windows.WSAECONNRESET, windows.WSAENOTSOCK:
		return net.ErrClosed
	case windows.ERROR_BROKEN_PIPE, windows.ERROR_NETNAME_DELETED:
		return io.EOF
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return fmt.Errorf("wslbridge: hvsock %s %s: %w", c.name, op, err)
}

// Close implements net.Conn.
func (c *hvsockConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	// Cancel first so a Read or Write blocked in await wakes up, then wait for
	// it to let go of its direction lock before the event it was waiting on is
	// destroyed. Closing an event under a live WaitForSingleObject is
	// undefined behaviour rather than an error that would show up in testing.
	windows.CancelIoEx(c.sock, nil)
	err := windows.Closesocket(c.sock)
	c.rmu.Lock()
	c.wmu.Lock()
	windows.CloseHandle(c.rev)
	windows.CloseHandle(c.wev)
	c.wmu.Unlock()
	c.rmu.Unlock()
	return err
}

// CloseWrite half-closes the send side, which AF_HYPERV supports and a named
// pipe does not. hull's proxy checks for this method rather than assuming.
func (c *hvsockConn) CloseWrite() error {
	return windows.Shutdown(c.sock, windows.SHUT_WR)
}

// LocalAddr implements net.Conn.
func (c *hvsockConn) LocalAddr() net.Addr { return hvsockAddr(c.name) }

// RemoteAddr implements net.Conn.
func (c *hvsockConn) RemoteAddr() net.Addr { return hvsockAddr(c.name) }

// SetDeadline implements net.Conn.
func (c *hvsockConn) SetDeadline(t time.Time) error {
	hvSetDeadline(&c.rdl, t)
	hvSetDeadline(&c.wdl, t)
	return nil
}

// SetReadDeadline implements net.Conn.
func (c *hvsockConn) SetReadDeadline(t time.Time) error {
	hvSetDeadline(&c.rdl, t)
	return nil
}

// SetWriteDeadline implements net.Conn.
func (c *hvsockConn) SetWriteDeadline(t time.Time) error {
	hvSetDeadline(&c.wdl, t)
	return nil
}

// hvSetDeadline stores an absolute deadline as unix nanoseconds, zero for none.
func hvSetDeadline(slot *atomic.Int64, t time.Time) {
	if t.IsZero() {
		slot.Store(0)
		return
	}
	slot.Store(t.UnixNano())
}

// hvDeadline reads a deadline stored by hvSetDeadline.
func hvDeadline(slot *atomic.Int64) time.Time {
	ns := slot.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// braced wraps a GUID in the braces windows.GUIDFromString expects.
func braced(s string) string {
	s = normaliseGUID(s)
	return "{" + s + "}"
}

// hvsockAddr is the net.Addr an AF_HYPERV connection reports.
type hvsockAddr string

// Network implements net.Addr.
func (a hvsockAddr) Network() string { return "hvsock" }

// String implements net.Addr.
func (a hvsockAddr) String() string { return string(a) }
