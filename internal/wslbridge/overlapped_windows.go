//go:build windows

package wslbridge

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

// Both Windows transports end up holding a kernel handle that Go's network
// poller knows nothing about: a named-pipe instance created with
// FILE_FLAG_OVERLAPPED, and an AF_HYPERV socket that net.FileConn refuses
// (fileConn returns EWINDOWS on this platform). Neither can be turned into a
// net.Conn by the standard library, so this is that net.Conn: overlapped
// ReadFile and WriteFile, one event per direction so a read and a write can be
// in flight at once, and deadlines implemented by waiting on the event with a
// timeout and cancelling the I/O when it expires.

// sdSend is SD_SEND for shutdown(2): stop sending, keep receiving.
const sdSend = 1

// errNoHalfClose is returned by CloseWrite on a handle that has no half-close.
// A named pipe is such a handle: the kernel offers no way to signal end-of-write
// without closing the instance. The proxy checks for this rather than assuming,
// and falls back to closing both ends.
var errNoHalfClose = errors.New("wslbridge: this connection cannot half-close")

// overlappedConn is a net.Conn over a Windows handle opened for overlapped I/O.
type overlappedConn struct {
	h      windows.Handle
	name   string
	kind   string
	addr   net.Addr
	closer func(windows.Handle) error

	rmu sync.Mutex
	rev windows.Handle
	wmu sync.Mutex
	wev windows.Handle

	rdl atomic.Int64 // read deadline in unix nanoseconds; 0 means none
	wdl atomic.Int64

	state  sync.Mutex
	closed bool
	wshut  bool
}

var _ net.Conn = (*overlappedConn)(nil)

// newOverlappedConn wraps a connected handle as a net.Conn.
//
// kind is "npipe" or "hvsock" and decides whether half-close is possible. closer
// runs on Close and owns whatever teardown the handle needs — a pipe server
// instance has to be flushed and disconnected before it is closed, a socket just
// closed — so this type never has to know which it is holding.
func newOverlappedConn(h windows.Handle, name, kind string, addr net.Addr, closer func(windows.Handle) error) (net.Conn, error) {
	read, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: create %s read event: %w", kind, err)
	}
	write, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(read)
		return nil, fmt.Errorf("wslbridge: create %s write event: %w", kind, err)
	}
	if closer == nil {
		closer = windows.CloseHandle
	}
	return &overlappedConn{
		h:      h,
		name:   name,
		kind:   kind,
		addr:   addr,
		closer: closer,
		rev:    read,
		wev:    write,
	}, nil
}

// Read implements net.Conn.
func (c *overlappedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()

	if c.isClosed() {
		// The event handles are gone once Close has run, so this has to be
		// answered here rather than by the kernel.
		return 0, net.ErrClosed
	}
	_ = windows.ResetEvent(c.rev)
	ov := &windows.Overlapped{HEvent: c.rev}
	var done uint32
	err := windows.ReadFile(c.h, p, &done, ov)
	n, err := c.await(ov, c.rev, done, err, loadDeadline(&c.rdl))
	if err != nil {
		return n, c.wrap("read", err)
	}
	if n == 0 {
		// Zero bytes with no error is end of stream on both a byte pipe and a
		// stream socket.
		return 0, io.EOF
	}
	return n, nil
}

// Write implements net.Conn. It loops until every byte is accepted, because a
// pipe instance with a full buffer takes what it can and returns.
func (c *overlappedConn) Write(p []byte) (int, error) {
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
		_ = windows.ResetEvent(c.wev)
		ov := &windows.Overlapped{HEvent: c.wev}
		var done uint32
		err := windows.WriteFile(c.h, p[total:], &done, ov)
		n, err := c.await(ov, c.wev, done, err, loadDeadline(&c.wdl))
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

// await completes one overlapped operation.
//
// A deadline is enforced by waiting on the operation's event with a timeout and
// then cancelling the I/O. The result is collected even after cancelling: the
// kernel may have completed the transfer in the gap, and those bytes are real —
// dropping them would silently corrupt an API stream.
func (c *overlappedConn) await(ov *windows.Overlapped, event windows.Handle, done uint32, err error, deadline time.Time) (int, error) {
	if err == nil {
		return int(done), nil
	}
	if err != windows.ERROR_IO_PENDING {
		return int(done), err
	}

	timeout := uint32(windows.INFINITE)
	if !deadline.IsZero() {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			timeout = 0
		} else if ms := remaining.Milliseconds(); ms >= int64(windows.INFINITE) {
			timeout = windows.INFINITE - 1
		} else {
			timeout = uint32(ms) + 1
		}
	}
	which, werr := windows.WaitForSingleObject(event, timeout)
	if werr != nil {
		return 0, werr
	}
	if which == uint32(windows.WAIT_TIMEOUT) {
		_ = windows.CancelIoEx(c.h, ov)
		var transferred uint32
		_ = windows.GetOverlappedResult(c.h, ov, &transferred, true)
		if transferred > 0 {
			return int(transferred), nil
		}
		return 0, os.ErrDeadlineExceeded
	}
	var transferred uint32
	if err := windows.GetOverlappedResult(c.h, ov, &transferred, false); err != nil {
		return int(transferred), err
	}
	return int(transferred), nil
}

// isClosed reports whether Close has run.
func (c *overlappedConn) isClosed() bool {
	c.state.Lock()
	defer c.state.Unlock()
	return c.closed
}

// wrap translates Windows handle errors into the ones Go code expects, so the
// proxy and the multiplexer can treat a pipe, a socket and a stream alike.
func (c *overlappedConn) wrap(op string, err error) error {
	switch err {
	case nil:
		return nil
	case os.ErrDeadlineExceeded:
		return os.ErrDeadlineExceeded
	case windows.ERROR_BROKEN_PIPE, windows.ERROR_PIPE_NOT_CONNECTED, windows.ERROR_NO_DATA:
		// The client went away. For a byte relay that is end of stream, not a
		// fault: docker exits the moment it has its answer.
		return io.EOF
	case windows.ERROR_OPERATION_ABORTED, windows.ERROR_INVALID_HANDLE:
		return net.ErrClosed
	case windows.WSAECONNRESET, windows.WSAECONNABORTED, windows.WSAESHUTDOWN:
		return io.EOF
	case windows.WSAETIMEDOUT:
		return os.ErrDeadlineExceeded
	}
	c.state.Lock()
	closed := c.closed
	c.state.Unlock()
	if closed {
		return net.ErrClosed
	}
	return fmt.Errorf("wslbridge: %s %s %s: %w", c.kind, c.name, op, err)
}

// CloseWrite half-closes a connection that can, and reports errNoHalfClose for
// one that cannot.
func (c *overlappedConn) CloseWrite() error {
	if c.kind != "hvsock" {
		return errNoHalfClose
	}
	c.state.Lock()
	if c.wshut || c.closed {
		c.state.Unlock()
		return nil
	}
	c.wshut = true
	c.state.Unlock()
	if err := windows.Shutdown(c.h, sdSend); err != nil {
		return fmt.Errorf("wslbridge: shutdown %s: %w", c.name, err)
	}
	return nil
}

// Close implements net.Conn. Pending reads and writes are cancelled first, so a
// blocked goroutine returns instead of waiting on a handle that is closing.
func (c *overlappedConn) Close() error {
	c.state.Lock()
	if c.closed {
		c.state.Unlock()
		return nil
	}
	c.closed = true
	c.state.Unlock()

	// CancelIoEx with no overlapped structure aborts every pending operation
	// on the handle, whichever thread issued it, so a blocked Read or Write
	// wakes with ERROR_OPERATION_ABORTED.
	_ = windows.CancelIoEx(c.h, nil)
	err := c.closer(c.h)
	// Only now take both direction locks: a Read or Write still in await is
	// waiting on these event handles, and closing an event out from under
	// WaitForSingleObject is undefined rather than merely an error. The
	// cancellation above is what guarantees this does not block.
	c.rmu.Lock()
	c.wmu.Lock()
	_ = windows.CloseHandle(c.rev)
	_ = windows.CloseHandle(c.wev)
	c.wmu.Unlock()
	c.rmu.Unlock()
	if err != nil {
		return fmt.Errorf("wslbridge: close %s %s: %w", c.kind, c.name, err)
	}
	return nil
}

// LocalAddr implements net.Conn.
func (c *overlappedConn) LocalAddr() net.Addr { return c.addr }

// RemoteAddr implements net.Conn.
func (c *overlappedConn) RemoteAddr() net.Addr { return c.addr }

// SetDeadline implements net.Conn.
func (c *overlappedConn) SetDeadline(t time.Time) error {
	storeDeadline(&c.rdl, t)
	storeDeadline(&c.wdl, t)
	return nil
}

// SetReadDeadline implements net.Conn.
func (c *overlappedConn) SetReadDeadline(t time.Time) error {
	storeDeadline(&c.rdl, t)
	return nil
}

// SetWriteDeadline implements net.Conn.
func (c *overlappedConn) SetWriteDeadline(t time.Time) error {
	storeDeadline(&c.wdl, t)
	return nil
}

// storeDeadline records an absolute deadline; the zero time means none.
func storeDeadline(slot *atomic.Int64, t time.Time) {
	if t.IsZero() {
		slot.Store(0)
		return
	}
	slot.Store(t.UnixNano())
}

// loadDeadline reads back a stored deadline.
func loadDeadline(slot *atomic.Int64) time.Time {
	ns := slot.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}
