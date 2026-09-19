package shim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// server exposes one supervisor over the control socket.
type server struct {
	cfg Config
	sup *supervisor

	l  net.Listener
	wg sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce sync.Once
}

// listenControl creates the shim's control socket.
//
// The socket is created with a umask so tight that nobody but the owner can
// connect, and then chmod'ed explicitly, because the daemon's umask is not
// something the shim can rely on: anyone who can connect to this socket can
// send signals into the container and read everything it prints.
func listenControl(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("shim: remove stale control socket %s: %w", path, err)
	}
	old := syscall.Umask(0o077)
	l, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("shim: listen on control socket %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, fmt.Errorf("shim: chmod control socket %s: %w", path, err)
	}
	if ul, ok := l.(*net.UnixListener); ok {
		// The shim removes the socket itself in Close, after it has stopped
		// answering, so Go's own unlink-on-close must stay out of the way.
		ul.SetUnlinkOnClose(false)
	}
	return l, nil
}

// newServer wraps a listener and a supervisor.
func newServer(ctx context.Context, cfg Config, sup *supervisor, l net.Listener) *server {
	ctx, cancel := context.WithCancel(ctx)
	return &server{cfg: cfg, sup: sup, l: l, ctx: ctx, cancel: cancel}
}

// Serve accepts connections until the listener is closed.
func (s *server) Serve() {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("shim: accept on control socket: %v", err)
			// A transient accept failure should not spin the CPU.
			select {
			case <-time.After(50 * time.Millisecond):
			case <-s.ctx.Done():
				return
			}
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

// Close stops accepting, waits for in-flight connections and removes the
// socket.
func (s *server) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.l.Close()
		// Unlink only after the listener is shut, so a client that dials in
		// the meantime gets a refused connection rather than a stale socket.
		_ = os.Remove(s.cfg.SocketPath())
		s.wg.Wait()
	})
}

// handle serves one connection: one request, one response, and for the three
// streaming operations an upgraded byte stream afterwards.
func (s *server) handle(conn net.Conn) {
	closeConn := true
	defer func() {
		if closeConn {
			conn.Close()
		}
	}()

	// Bound only the request itself; a stream may then sit idle for hours.
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	req, err := ReadRequest(conn)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			log.Printf("shim: read request: %v", err)
		}
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	switch req.Op {
	case OpPing:
		s.reply(conn, Response{})
	case OpStart:
		ctx, cancel := context.WithTimeout(s.ctx, 60*time.Second)
		err := s.sup.Start(ctx)
		cancel()
		s.replyErr(conn, err)
	case OpState:
		st := s.sup.State()
		s.reply(conn, Response{State: &st})
	case OpKill:
		ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
		err := s.sup.Kill(ctx, syscall.Signal(req.Signal), req.All)
		cancel()
		s.replyErr(conn, err)
	case OpWait:
		s.handleWait(conn)
	case OpResize:
		s.replyErr(conn, s.sup.Resize(req.Height, req.Width))
	case OpStats:
		st := s.sup.Stats()
		s.reply(conn, Response{Stats: &st})
	case OpAck:
		s.sup.Ack()
		s.reply(conn, Response{})
	case OpShutdown:
		s.reply(conn, Response{})
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			s.sup.Stop(ctx)
		}()
	case OpAttach:
		if s.handleAttach(conn, req) {
			closeConn = false
		}
	case OpExec:
		if s.handleExec(conn, req) {
			closeConn = false
		}
	case OpExecWait:
		s.handleExecWait(conn, req)
	case OpExecResize:
		e, err := s.sup.lookupExec(req.ExecID)
		if err != nil {
			s.replyErr(conn, err)
			return
		}
		s.replyErr(conn, e.Resize(req.Height, req.Width))
	case OpEvents:
		if s.handleEvents(conn) {
			closeConn = false
		}
	default:
		s.reply(conn, Response{Error: fmt.Sprintf("shim: unknown operation %q", req.Op)})
	}
}

// reply writes one response frame.
func (s *server) reply(conn net.Conn, resp Response) {
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := WriteJSONFrame(conn, KindResponse, resp); err != nil {
		log.Printf("shim: write response: %v", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})
}

// replyErr writes a success or an error response.
func (s *server) replyErr(conn net.Conn, err error) {
	s.reply(conn, errorResponse(err))
}

// handleWait blocks until the container exits, or until the client goes away.
func (s *server) handleWait(conn net.Conn) {
	// Notice a client that disconnects while waiting, so a daemon restart
	// does not leave a goroutine per abandoned wait.
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		var b [1]byte
		_, _ = conn.Read(b[:])
	}()

	select {
	case <-s.sup.Exited():
		code := s.sup.State().ExitCode
		s.reply(conn, Response{ExitCode: &code})
	case <-gone:
	case <-s.ctx.Done():
		s.reply(conn, Response{Error: "shim: shutting down before the container exited"})
	}
}

// handleExecWait blocks until one exec'd process exits.
func (s *server) handleExecWait(conn net.Conn, req Request) {
	e, err := s.sup.lookupExec(req.ExecID)
	if err != nil {
		s.replyErr(conn, err)
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	go func() {
		var b [1]byte
		_, _ = conn.Read(b[:])
		cancel()
	}()
	code, err := e.Wait(ctx)
	if err != nil {
		return
	}
	s.reply(conn, Response{ExitCode: &code})
}

// handleAttach upgrades the connection to the container's streams. It reports
// whether the connection has been handed to the stream goroutines, in which
// case the caller must not close it.
func (s *server) handleAttach(conn net.Conn, req Request) bool {
	opts := AttachOptions{Stdout: true, Stderr: true}
	if req.Attach != nil {
		opts = *req.Attach
	}
	if s.sup.hub == nil {
		s.replyErr(conn, ErrNotRunning)
		return false
	}
	keys, err := ParseDetachKeys(opts.DetachKeys)
	if err != nil {
		s.replyErr(conn, err)
		return false
	}
	a := NewAttacher(opts)
	if err := s.sup.hub.Attach(a); err != nil {
		s.replyErr(conn, err)
		return false
	}
	s.reply(conn, Response{Terminal: s.cfg.Terminal})
	s.startStream(conn, a, keys)
	return true
}

// handleExec starts a process and upgrades the connection to its streams.
func (s *server) handleExec(conn net.Conn, req Request) bool {
	opts := AttachOptions{Stdout: true, Stderr: true}
	if req.Attach != nil {
		opts = *req.Attach
	}
	keys, err := ParseDetachKeys(opts.DetachKeys)
	if err != nil {
		s.replyErr(conn, err)
		return false
	}
	terminal := execSpecTerminal(req.Spec)
	ctx, cancel := context.WithTimeout(s.ctx, 60*time.Second)
	e, err := s.sup.Exec(ctx, req.ExecID, req.Spec, terminal, opts.Stdin)
	cancel()
	if err != nil {
		s.replyErr(conn, err)
		return false
	}
	a := NewAttacher(opts)
	if err := e.hub.Attach(a); err != nil {
		s.replyErr(conn, err)
		return false
	}
	s.reply(conn, Response{Pid: e.pid, Terminal: terminal})
	s.startStream(conn, a, keys)
	return true
}

// startStream runs the two halves of an upgraded connection: output frames
// out, stdin frames in. The writer goroutine is the only writer on conn, so
// frames never interleave.
func (s *server) startStream(conn net.Conn, a *Attacher, detachKeys []byte) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer conn.Close()
		defer a.Detach(nil)

		var writerDone sync.WaitGroup
		writerDone.Add(1)
		go func() {
			defer writerDone.Done()
			for c := range a.Chunks() {
				if err := WriteFrame(conn, c.Stream, c.Data); err != nil {
					a.Detach(nil)
					return
				}
			}
			// Tell the client why the stream ended, then end it.
			if err := a.Err(); err != nil && errors.Is(err, ErrDetached) {
				_ = WriteJSONFrame(conn, KindResponse, errorResponse(ErrDetached))
			}
			_ = WriteFrame(conn, KindEOF, nil)
		}()

		s.readStdin(conn, a, detachKeys)
		// The client is gone or detached: drop the attacher so the writer
		// goroutine's channel closes.
		a.Detach(a.Err())
		writerDone.Wait()
	}()
}

// readStdin pumps the client's stdin frames into the container, watching for
// the detach sequence on the way.
func (s *server) readStdin(conn net.Conn, a *Attacher, detachKeys []byte) {
	filter := newDetachFilter(nil)
	if a.StdinGranted() {
		filter = newDetachFilter(detachKeys)
	}
	for {
		kind, body, err := ReadFrame(conn)
		if err != nil {
			// Release a half-typed detach prefix rather than swallowing it.
			if rest := filter.Flush(); len(rest) > 0 && a.StdinGranted() {
				_, _ = a.Write(rest)
			}
			return
		}
		switch kind {
		case KindStdin:
			if !a.StdinGranted() {
				continue // this attacher never asked for, or was refused, stdin
			}
			out, detached := filter.Filter(body)
			if len(out) > 0 {
				if _, werr := a.Write(out); werr != nil {
					return
				}
			}
			if detached {
				a.Detach(ErrDetached)
				return
			}
		case KindEOF:
			if a.StdinGranted() {
				_ = a.CloseStdin()
			}
		}
		select {
		case <-a.Done():
			return
		case <-s.ctx.Done():
			return
		default:
		}
	}
}

// handleEvents upgrades the connection to the shim's event stream.
func (s *server) handleEvents(conn net.Conn) bool {
	ch := s.sup.events.Subscribe()
	s.reply(conn, Response{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer conn.Close()
		defer s.sup.events.Unsubscribe(ch)

		gone := make(chan struct{})
		go func() {
			defer close(gone)
			var b [1]byte
			_, _ = conn.Read(b[:])
		}()

		for {
			select {
			case ev, ok := <-ch:
				if !ok {
					return
				}
				if err := WriteJSONFrame(conn, KindEvent, ev); err != nil {
					return
				}
			case <-gone:
				return
			case <-s.ctx.Done():
				return
			}
		}
	}()
	return true
}

// execSpecTerminal reports whether an OCI process spec asks for a terminal.
func execSpecTerminal(spec []byte) bool {
	var p struct {
		Terminal bool `json:"terminal"`
	}
	if err := unmarshalJSON(spec, &p); err != nil {
		return false
	}
	return p.Terminal
}
