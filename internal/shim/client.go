package shim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

// dialTimeout bounds a single connection attempt to the shim socket.
const dialTimeout = 5 * time.Second

// Client talks to one shim over its control socket.
//
// Every RPC uses a fresh connection, so a blocked Wait can never delay a
// State, and a daemon may hold as many concurrent attach streams as it likes.
// A Client is safe for concurrent use.
type Client struct {
	socket string

	mu      sync.Mutex
	closed  bool
	streams map[io.Closer]struct{}
}

// Connect opens a Client for the shim listening at socketPath and probes it
// with a ping, so a socket left behind by a dead shim is reported immediately
// rather than at the first real call.
func Connect(socketPath string) (*Client, error) {
	c := &Client{socket: socketPath, streams: make(map[io.Closer]struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := roundTrip(ctx, conn, Request{Op: OpPing}); err != nil {
		return nil, fmt.Errorf("shim: ping %s: %w", socketPath, err)
	}
	return c, nil
}

// SocketPath reports the control socket this client talks to.
func (c *Client) SocketPath() string { return c.socket }

// dial opens one connection to the shim, honouring ctx's deadline.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("%w: %s: %v", ErrShimGone, c.socket, err)
		}
		return nil, fmt.Errorf("shim: dial %s: %w", c.socket, err)
	}
	return conn, nil
}

// call performs one request/response exchange on a fresh connection.
func (c *Client) call(ctx context.Context, req Request) (Response, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	return roundTrip(ctx, conn, req)
}

// roundTrip writes req and reads the response, applying ctx's deadline to both
// halves and unblocking a blocked read when ctx is cancelled.
func roundTrip(ctx context.Context, conn net.Conn, req Request) (Response, error) {
	stop := applyDeadline(ctx, conn)
	defer stop()
	if err := WriteJSONFrame(conn, KindRequest, req); err != nil {
		return Response{}, err
	}
	resp, err := ReadResponse(conn)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Response{}, ctxErr
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Response{}, fmt.Errorf("%w: it closed the connection during %q", ErrShimGone, req.Op)
		}
		return Response{}, err
	}
	if err := responseError(resp); err != nil {
		return resp, err
	}
	return resp, nil
}

// applyDeadline wires ctx cancellation to conn by setting its deadline, and
// returns a function that undoes the wiring.
func applyDeadline(ctx context.Context, conn net.Conn) func() {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if ctx.Done() == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// Force any blocked read or write to return at once.
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() { close(done) }
}

// Start starts the container the shim created.
func (c *Client) Start(ctx context.Context) error {
	_, err := c.call(ctx, Request{Op: OpStart})
	return err
}

// State reports the container's current state.
func (c *Client) State(ctx context.Context) (State, error) {
	resp, err := c.call(ctx, Request{Op: OpState})
	if err != nil {
		return State{}, err
	}
	if resp.State == nil {
		return State{}, fmt.Errorf("%w: state response carried no state", ErrProtocol)
	}
	return *resp.State, nil
}

// Kill sends sig to the container. With all set it goes to every process in
// the container's cgroup rather than to its init alone.
//
// The shim delivers the signal through the container's pidfd, so it can never
// reach an unrelated process that inherited a recycled pid.
func (c *Client) Kill(ctx context.Context, sig syscall.Signal, all bool) error {
	_, err := c.call(ctx, Request{Op: OpKill, Signal: int(sig), All: all})
	return err
}

// Wait blocks until the container exits and returns its exit code. A process
// killed by signal N reports 128+N. Wait is safe to call after the container
// has already exited: the shim keeps serving the status for its grace period,
// and returns it immediately.
func (c *Client) Wait(ctx context.Context) (int, error) {
	resp, err := c.call(ctx, Request{Op: OpWait})
	if err != nil {
		return 0, err
	}
	if resp.ExitCode == nil {
		return 0, fmt.Errorf("%w: wait response carried no exit code", ErrProtocol)
	}
	return *resp.ExitCode, nil
}

// Resize sets the container pty's window size to h rows by w columns. It
// returns ErrNoTerminal for a container created without a terminal.
func (c *Client) Resize(ctx context.Context, h, w uint16) error {
	_, err := c.call(ctx, Request{Op: OpResize, Height: h, Width: w})
	return err
}

// Stats samples the container's cgroup. On a host with no cgroup v2
// delegation the sample is mostly zeroes; the shim reports what it can read
// rather than failing, and hull doctor is where the missing delegation is
// explained.
func (c *Client) Stats(ctx context.Context) (types.Stats, error) {
	resp, err := c.call(ctx, Request{Op: OpStats})
	if err != nil {
		return types.Stats{}, err
	}
	if resp.Stats == nil {
		return types.Stats{}, fmt.Errorf("%w: stats response carried no sample", ErrProtocol)
	}
	return *resp.Stats, nil
}

// Ack tells the shim the daemon has durably recorded the container's exit
// status, releasing the shim from its grace period so it can exit at once.
func (c *Client) Ack(ctx context.Context) error {
	_, err := c.call(ctx, Request{Op: OpAck})
	return err
}

// Shutdown asks the shim to stop the container with its stop signal and exit.
func (c *Client) Shutdown(ctx context.Context) error {
	_, err := c.call(ctx, Request{Op: OpShutdown})
	return err
}

// Attach opens a stream carrying the container's output and, when granted,
// its input.
//
// Any number of clients may attach at once and all of them receive output.
// Stdin is granted to the first attacher that asks for it; a later one gets
// ErrStdinInUse. Typing the detach sequence (AttachOptions.DetachKeys,
// defaulting to DefaultDetachKeys) ends the stream with ErrDetached without
// signalling the container.
func (c *Client) Attach(ctx context.Context, opts AttachOptions) (*AttachStream, error) {
	return c.openStream(ctx, Request{Op: OpAttach, Attach: &opts}, opts)
}

// Exec starts an additional process described by spec, an OCI runtime-spec
// Process object as JSON, and returns its stream. id names the exec so it can
// be waited on and resized.
func (c *Client) Exec(ctx context.Context, id string, spec []byte, opts AttachOptions) (*ExecSession, error) {
	if id == "" {
		return nil, fmt.Errorf("shim: Exec needs a non-empty exec id")
	}
	if len(spec) == 0 {
		return nil, fmt.Errorf("shim: Exec for %s needs a process spec", id)
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	resp, stream, err := c.upgrade(ctx, conn, Request{
		Op: OpExec, ExecID: id, Spec: spec, Attach: &opts,
	}, opts)
	if err != nil {
		return nil, err
	}
	return &ExecSession{ID: id, Pid: resp.Pid, Stream: stream, client: c}, nil
}

// openStream dials, sends req and upgrades the connection to a byte stream.
func (c *Client) openStream(ctx context.Context, req Request, opts AttachOptions) (*AttachStream, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	_, stream, err := c.upgrade(ctx, conn, req, opts)
	return stream, err
}

// upgrade performs the request half of a stream operation and, on success,
// hands the connection to an AttachStream.
func (c *Client) upgrade(ctx context.Context, conn net.Conn, req Request, opts AttachOptions) (Response, *AttachStream, error) {
	// Only the handshake is deadlined; the stream itself must be able to sit
	// idle for as long as the container is quiet.
	handshake, cancel := context.WithTimeout(ctx, dialTimeout)
	stop := applyDeadline(handshake, conn)
	if err := WriteJSONFrame(conn, KindRequest, req); err != nil {
		stop()
		cancel()
		conn.Close()
		return Response{}, nil, err
	}
	resp, err := ReadResponse(conn)
	stop()
	cancel()
	if err != nil {
		conn.Close()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Response{}, nil, fmt.Errorf("%w: it closed the connection during %q", ErrShimGone, req.Op)
		}
		return Response{}, nil, err
	}
	if err := responseError(resp); err != nil {
		conn.Close()
		return resp, nil, err
	}
	_ = conn.SetDeadline(time.Time{})

	s := newAttachStream(conn, resp.Terminal, opts)
	c.track(s)
	go func() {
		<-s.done
		c.untrack(s)
	}()
	return resp, s, nil
}

// Events streams container lifecycle events until ctx is cancelled or the shim
// exits. The channel is closed when the stream ends.
func (c *Client) Events(ctx context.Context) (<-chan Event, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	handshake, cancel := context.WithTimeout(ctx, dialTimeout)
	stop := applyDeadline(handshake, conn)
	err = WriteJSONFrame(conn, KindRequest, Request{Op: OpEvents})
	var resp Response
	if err == nil {
		resp, err = ReadResponse(conn)
	}
	stop()
	cancel()
	if err == nil {
		err = responseError(resp)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	c.track(conn)

	ch := make(chan Event, 16)
	go func() {
		defer close(ch)
		defer c.untrack(conn)
		defer conn.Close()
		go func() {
			<-ctx.Done()
			_ = conn.SetDeadline(time.Now())
		}()
		for {
			kind, body, err := ReadFrame(conn)
			if err != nil {
				return
			}
			if kind != KindEvent {
				continue
			}
			var ev Event
			if err := unmarshalJSON(body, &ev); err != nil {
				return
			}
			select {
			case ch <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

// track records a long-lived stream so Close can tear it down.
func (c *Client) track(x io.Closer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		go x.Close()
		return
	}
	c.streams[x] = struct{}{}
}

// untrack forgets a stream that ended on its own.
func (c *Client) untrack(x io.Closer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.streams, x)
}

// Close releases the client and every stream it opened. The shim and the
// container are unaffected.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	streams := make([]io.Closer, 0, len(c.streams))
	for x := range c.streams {
		streams = append(streams, x)
	}
	c.streams = nil
	c.mu.Unlock()

	var firstErr error
	for _, x := range streams {
		if err := x.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ExecSession is one process started with Exec.
type ExecSession struct {
	// ID is the exec id the caller chose.
	ID string
	// Pid is the exec'd process's pid in the shim's pid namespace.
	Pid int
	// Stream carries the process's stdio.
	Stream *AttachStream

	client *Client
}

// Wait blocks until the exec'd process exits and returns its exit code.
func (e *ExecSession) Wait(ctx context.Context) (int, error) {
	resp, err := e.client.call(ctx, Request{Op: OpExecWait, ExecID: e.ID})
	if err != nil {
		return 0, err
	}
	if resp.ExitCode == nil {
		return 0, fmt.Errorf("%w: exec-wait response carried no exit code", ErrProtocol)
	}
	return *resp.ExitCode, nil
}

// Resize sets this exec's pty window size.
func (e *ExecSession) Resize(ctx context.Context, h, w uint16) error {
	_, err := e.client.call(ctx, Request{Op: OpExecResize, ExecID: e.ID, Height: h, Width: w})
	return err
}

// Close tears the exec's stream down. The process itself keeps running.
func (e *ExecSession) Close() error {
	if e.Stream == nil {
		return nil
	}
	return e.Stream.Close()
}
