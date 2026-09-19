//go:build windows

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// pipeBusyRetry is how long dialNamedPipe waits before retrying a pipe that
// exists but has no free instance. Windows answers ERROR_PIPE_BUSY for that,
// and the relay creates a new instance as soon as it accepts the previous one,
// so a short retry loop is all that is needed.
const pipeBusyRetry = 50 * time.Millisecond

// dialNamedPipe opens a client handle on a Windows named pipe.
//
// The handle is synchronous rather than overlapped: hull's relay is a
// connection-per-request design, and a synchronous handle wrapped in an
// os.File gives blocking Read and Write without the completion-port dance.
// Deadlines are therefore unavailable, which pipeConn tolerates.
func dialNamedPipe(ctx context.Context, name string) (net.Conn, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("client: bad pipe name %q: %w", name, err)
	}
	for {
		h, err := windows.CreateFile(p,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			f := os.NewFile(uintptr(h), name)
			return &pipeConn{f: f, addr: pipeAddr{network: string(SchemeNamedPipe), addr: name}}, nil
		}
		if errors.Is(err, windows.ERROR_PIPE_BUSY) {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("client: dial %s: %w", name, ctx.Err())
			case <-time.After(pipeBusyRetry):
				continue
			}
		}
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, fmt.Errorf("client: nothing is serving %s: start the engine with 'hull engine start', or set HULL_HOST=wsl://%s to bypass the relay: %w",
				name, DefaultDistro, err)
		}
		return nil, fmt.Errorf("client: dial %s: %w", name, err)
	}
}

// pipeConn presents a synchronous named-pipe handle as a net.Conn. One handle
// carries both directions, so Close must only fire once.
type pipeConn struct {
	f    *os.File
	addr pipeAddr
}

// Read implements net.Conn.
func (c *pipeConn) Read(p []byte) (int, error) { return c.f.Read(p) }

// Write implements net.Conn.
func (c *pipeConn) Write(p []byte) (int, error) { return c.f.Write(p) }

// Close implements net.Conn.
func (c *pipeConn) Close() error {
	if err := c.f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}

// LocalAddr implements net.Conn.
func (c *pipeConn) LocalAddr() net.Addr { return c.addr }

// RemoteAddr implements net.Conn.
func (c *pipeConn) RemoteAddr() net.Addr { return c.addr }

// SetDeadline implements net.Conn on a best-effort basis.
func (c *pipeConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn on a best-effort basis. A synchronous
// pipe handle has no kernel deadline, and net/http only ever sets deadlines it
// can live without, so ErrNoDeadline is swallowed rather than surfaced.
func (c *pipeConn) SetReadDeadline(t time.Time) error {
	if err := c.f.SetReadDeadline(t); err != nil && !errors.Is(err, os.ErrNoDeadline) {
		return err
	}
	return nil
}

// SetWriteDeadline implements net.Conn on a best-effort basis.
func (c *pipeConn) SetWriteDeadline(t time.Time) error {
	if err := c.f.SetWriteDeadline(t); err != nil && !errors.Is(err, os.ErrNoDeadline) {
		return err
	}
	return nil
}
