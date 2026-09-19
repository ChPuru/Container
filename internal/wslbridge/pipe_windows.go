//go:build windows

package wslbridge

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Named-pipe flags that x/sys/windows does not name, or names only in pieces.
const (
	// pipeAccessDuplex is PIPE_ACCESS_DUPLEX: both ends read and write.
	pipeAccessDuplex = windows.PIPE_ACCESS_DUPLEX

	// pipeModeByte is PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT. A byte pipe,
	// not a message pipe: the Docker Engine API is an HTTP stream, and message
	// mode would chop it into datagrams with a maximum size.
	pipeModeByte = windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT

	// pipeDefaultTimeout is the CreateNamedPipe default timeout in
	// milliseconds, used only by clients that call WaitNamedPipe with
	// NMPWAIT_USE_DEFAULT_WAIT. Zero selects the system default of 50ms.
	pipeDefaultTimeout = 0

	// dialRetryInterval is how long DialPipe waits before retrying a pipe whose
	// instances are all busy.
	dialRetryInterval = 25 * time.Millisecond
)

// CurrentUserSID returns the SID of the user this process runs as, in string
// form, for the pipe's security descriptor.
func CurrentUserSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("wslbridge: look up the current user SID: %w", err)
	}
	return user.User.Sid.String(), nil
}

// listenPipe creates a named pipe and serves it as a net.Listener.
//
// The listener always keeps one unconnected instance in hand, created before the
// previous one is handed to the caller, so there is never a window in which a
// client's CreateFile finds the name but no instance to connect to. Instances
// are unlimited (PIPE_UNLIMITED_INSTANCES), because "docker compose up" opens
// several connections at once and a bounded pipe would make them queue.
func listenPipe(cfg PipeConfig) (net.Listener, error) {
	sddl := cfg.SDDL
	if sddl == "" {
		sid, err := CurrentUserSID()
		if err != nil {
			// PipeSDDL degrades to SYSTEM and Administrators only, which is
			// more restrictive than the default, never less.
			cfg.Logger.Warn("wslbridge: could not resolve the current user SID; the pipe will admit SYSTEM and Administrators only", "error", err)
		}
		sddl = PipeSDDL(sid)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: parse pipe security descriptor %q: %w", sddl, err)
	}
	name, err := windows.UTF16PtrFromString(cfg.Name)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: pipe name %q: %w", cfg.Name, err)
	}
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: create pipe stop event: %w", err)
	}

	l := &pipeListener{
		cfg:  cfg,
		name: name,
		sa: &windows.SecurityAttributes{
			Length:             uint32(sizeofSecurityAttributes()),
			SecurityDescriptor: sd,
		},
		stop: stop,
	}

	// The first instance is created here rather than on the first Accept, so
	// that ownership of the name — and the ErrPipeInUse answer hull needs
	// before it claims \\.\pipe\docker_engine — is settled before Listen
	// returns.
	h, err := l.createInstance(cfg.RequireFirstInstance)
	if err != nil {
		_ = windows.CloseHandle(stop)
		return nil, err
	}
	l.next = h
	cfg.Logger.Debug("wslbridge: serving named pipe", "pipe", cfg.Name, "sddl", sddl)
	return l, nil
}

// sizeofSecurityAttributes is the struct size Windows expects in
// SECURITY_ATTRIBUTES.nLength.
func sizeofSecurityAttributes() uintptr {
	var sa windows.SecurityAttributes
	return unsafe.Sizeof(sa)
}

// pipeListener is a net.Listener over a Windows named pipe.
type pipeListener struct {
	cfg  PipeConfig
	name *uint16
	sa   *windows.SecurityAttributes
	stop windows.Handle

	acceptMu sync.Mutex     // one Accept at a time, as net.Listener allows
	next     windows.Handle // the instance waiting for the next client

	mu     sync.Mutex
	closed bool
}

var _ net.Listener = (*pipeListener)(nil)

// createInstance makes one new pipe instance.
func (l *pipeListener) createInstance(first bool) (windows.Handle, error) {
	flags := uint32(pipeAccessDuplex | windows.FILE_FLAG_OVERLAPPED)
	if first {
		// FILE_FLAG_FIRST_PIPE_INSTANCE turns "somebody else already owns this
		// name" into ERROR_ACCESS_DENIED here, instead of silently joining
		// their pipe and serving the Docker API to their clients.
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	h, err := windows.CreateNamedPipe(
		l.name,
		flags,
		pipeModeByte,
		windows.PIPE_UNLIMITED_INSTANCES,
		l.cfg.OutBufferSize,
		l.cfg.InBufferSize,
		pipeDefaultTimeout,
		l.sa,
	)
	if err != nil {
		if err == windows.ERROR_ACCESS_DENIED || err == windows.ERROR_PIPE_BUSY {
			return windows.InvalidHandle, fmt.Errorf("wslbridge: %s: %w", l.cfg.Name, ErrPipeInUse)
		}
		return windows.InvalidHandle, fmt.Errorf("wslbridge: create pipe %s: %w", l.cfg.Name, err)
	}
	return h, nil
}

// Accept implements net.Listener.
func (l *pipeListener) Accept() (net.Conn, error) {
	l.acceptMu.Lock()
	defer l.acceptMu.Unlock()

	if l.isClosed() {
		return nil, net.ErrClosed
	}
	h := l.next
	l.next = windows.InvalidHandle
	if h == windows.InvalidHandle {
		var err error
		if h, err = l.createInstance(false); err != nil {
			return nil, err
		}
	}

	if err := l.connect(h); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}

	// Have the next instance listening before this one is handed over, so a
	// client that connects in the meantime is never told the pipe is gone.
	if next, err := l.createInstance(false); err == nil {
		l.next = next
	} else {
		l.cfg.Logger.Warn("wslbridge: could not pre-create the next pipe instance", "pipe", l.cfg.Name, "error", err)
	}

	conn, err := newOverlappedConn(h, l.cfg.Name, "npipe", pipeAddr(l.cfg.Name), pipeCloser(true))
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return conn, nil
}

// connect waits for a client on an unconnected instance. The wait is on an
// event rather than a blocking ConnectNamedPipe so that Close can interrupt it,
// which is what makes the accept loop cancellable.
func (l *pipeListener) connect(h windows.Handle) error {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("wslbridge: create pipe connect event: %w", err)
	}
	defer windows.CloseHandle(event)

	ov := &windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(h, ov)
	switch err {
	case nil:
		return nil
	case windows.ERROR_PIPE_CONNECTED:
		// A client connected between CreateNamedPipe and ConnectNamedPipe.
		return nil
	case windows.ERROR_IO_PENDING:
	default:
		return fmt.Errorf("wslbridge: connect pipe %s: %w", l.cfg.Name, err)
	}

	which, err := windows.WaitForMultipleObjects([]windows.Handle{event, l.stop}, false, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("wslbridge: wait for a pipe client: %w", err)
	}
	switch which - windows.WAIT_OBJECT_0 {
	case 0:
		var done uint32
		if err := windows.GetOverlappedResult(h, ov, &done, false); err != nil {
			if err == windows.ERROR_PIPE_CONNECTED {
				return nil
			}
			return fmt.Errorf("wslbridge: connect pipe %s: %w", l.cfg.Name, err)
		}
		return nil
	default:
		_ = windows.CancelIoEx(h, ov)
		return net.ErrClosed
	}
}

// Close implements net.Listener. It wakes a blocked Accept and drops the
// unconnected instance, which releases the name; connections already accepted
// keep working until their own Close.
func (l *pipeListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()

	_ = windows.SetEvent(l.stop)

	l.acceptMu.Lock()
	if l.next != windows.InvalidHandle {
		_ = windows.CloseHandle(l.next)
		l.next = windows.InvalidHandle
	}
	l.acceptMu.Unlock()

	_ = windows.CloseHandle(l.stop)
	return nil
}

// isClosed reports whether Close has been called.
func (l *pipeListener) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// Addr implements net.Listener.
func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.cfg.Name) }

// DialPipe connects to a named pipe. hull uses it to check whether its own pipe
// is answering, and the CLI uses it as the client side of the bridge.
func DialPipe(ctx context.Context, name string) (net.Conn, error) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: pipe name %q: %w", name, err)
	}
	for {
		h, err := windows.CreateFile(
			name16,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED,
			0,
		)
		if err == nil {
			conn, cerr := newOverlappedConn(h, name, "npipe", pipeAddr(name), pipeCloser(false))
			if cerr != nil {
				_ = windows.CloseHandle(h)
				return nil, cerr
			}
			return conn, nil
		}
		// Every instance is busy: the server has not looped round to its next
		// Accept yet. Retrying is correct and usually takes microseconds.
		if err != windows.ERROR_PIPE_BUSY {
			return nil, fmt.Errorf("wslbridge: dial %s: %w", name, err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(dialRetryInterval):
		}
	}
}

// pipeCloser builds the teardown a pipe handle needs. A server instance is
// flushed and disconnected first, so the client sees the bytes already written
// rather than a broken pipe, and the instance is reusable by the kernel.
func pipeCloser(server bool) func(windows.Handle) error {
	return func(h windows.Handle) error {
		if server {
			_ = windows.FlushFileBuffers(h)
			_ = windows.DisconnectNamedPipe(h)
		}
		return windows.CloseHandle(h)
	}
}
