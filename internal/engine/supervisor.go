package engine

import (
	"context"
	"io"
	"syscall"

	"github.com/rahuldhali/hull/internal/shim"
	"github.com/rahuldhali/hull/internal/types"
)

// Stream is one attached set of container standard streams.
//
// It exists so the engine does not depend on *shim.AttachStream directly: the
// shim's stream type owns a live socket and cannot be constructed in a test,
// while every lifecycle path in this package has to be exercisable without
// root, a kernel namespace or a real shim.
type Stream interface {
	// Terminal reports that output is a single merged pty stream, so Stderr
	// is nil and everything arrives on Stdout.
	Terminal() bool
	// Stdin writes to the container. It is nil when stdin was not requested.
	// Closing it half-closes the container's stdin without ending the stream.
	Stdin() io.WriteCloser
	// Stdout carries container stdout, or the merged pty stream.
	Stdout() io.Reader
	// Stderr carries container stderr; nil for a terminal container or when
	// stderr was not requested.
	Stderr() io.Reader
	// Done is closed when the stream ends.
	Done() <-chan struct{}
	// Err reports why the stream ended: nil for a clean end, shim.ErrDetached
	// when the detach sequence was typed, or a transport error.
	Err() error
	// Close detaches. The container keeps running.
	Close() error
}

// ExecHandle is one process started inside a running container.
type ExecHandle interface {
	Stream
	// Pid is the exec'd process's pid as the shim sees it.
	Pid() int
	// Wait blocks until the process exits and returns its exit code.
	Wait(ctx context.Context) (int, error)
	// Resize sets this exec's pty window size.
	Resize(ctx context.Context, h, w uint16) error
}

// Supervisor is the engine's view of the shim that owns one container.
//
// Every method maps onto one shim control-socket operation. The engine never
// signals a container process directly: pids are recycled, and the shim holds
// a pidfd, so going through the shim is the only way a signal cannot land on
// an unrelated process.
type Supervisor interface {
	// Start releases the created container into its entrypoint.
	Start(ctx context.Context) error
	// State reports the container's current lifecycle state.
	State(ctx context.Context) (shim.State, error)
	// Kill sends one signal, to the container init or, with all set, to every
	// process in its cgroup.
	Kill(ctx context.Context, sig syscall.Signal, all bool) error
	// Wait blocks until the container exits and returns its exit code.
	Wait(ctx context.Context) (int, error)
	// Resize sets the container pty's window size.
	Resize(ctx context.Context, h, w uint16) error
	// Stats samples the container's cgroup.
	Stats(ctx context.Context) (types.Stats, error)
	// Ack tells the shim the daemon has durably recorded the exit status, so
	// it may stop serving and exit at once.
	Ack(ctx context.Context) error
	// Shutdown asks the shim to stop the container and exit.
	Shutdown(ctx context.Context) error
	// Attach opens a stream carrying the container's output and, when
	// granted, its input.
	Attach(ctx context.Context, opts shim.AttachOptions) (Stream, error)
	// Exec starts an additional process from an OCI process spec.
	Exec(ctx context.Context, execID string, spec []byte, opts shim.AttachOptions) (ExecHandle, error)
	// Close releases the client and its streams. The shim and the container
	// are unaffected: containers outlive the daemon by design.
	Close() error
}

// Spawner creates and re-adopts supervisors. The production implementation
// drives the real hull-shim binary; tests substitute an in-memory one.
type Spawner interface {
	// Spawn starts a shim for cfg. The shim creates the container before it
	// reports ready, so a broken bundle surfaces here rather than as a
	// container stuck in "created" forever.
	Spawn(ctx context.Context, cfg shim.Config) (Supervisor, error)
	// Reconnect re-adopts the live shim recorded in containerDir/shim.json.
	// It returns an error wrapping shim.ErrShimGone when there is no live
	// shim, in which case the caller falls back to ReadExit.
	Reconnect(ctx context.Context, containerDir string) (Supervisor, error)
	// ReadExit reads the exit status a shim durably recorded before it left.
	ReadExit(containerDir string) (shim.ExitStatus, error)
}

// shimSpawner is the production Spawner: it drives the real hull-shim binary.
type shimSpawner struct {
	// binary is the absolute path of the hull-shim executable.
	binary string
}

// newShimSpawner returns a Spawner that spawns binary.
func newShimSpawner(binary string) Spawner { return &shimSpawner{binary: binary} }

// Spawn starts a real shim and wraps its client.
func (s *shimSpawner) Spawn(ctx context.Context, cfg shim.Config) (Supervisor, error) {
	c, err := shim.Spawn(ctx, s.binary, cfg)
	if err != nil {
		return nil, err
	}
	return &shimSupervisor{c: c}, nil
}

// Reconnect re-adopts a live shim.
func (s *shimSpawner) Reconnect(_ context.Context, containerDir string) (Supervisor, error) {
	c, err := shim.Reconnect(containerDir)
	if err != nil {
		return nil, err
	}
	return &shimSupervisor{c: c}, nil
}

// ReadExit reads the shim's durable exit record.
func (s *shimSpawner) ReadExit(containerDir string) (shim.ExitStatus, error) {
	return shim.ReadExitStatus(shim.ExitPath(containerDir))
}

// shimSupervisor adapts *shim.Client to Supervisor.
type shimSupervisor struct {
	c *shim.Client
}

// Start releases the container into its entrypoint.
func (s *shimSupervisor) Start(ctx context.Context) error { return s.c.Start(ctx) }

// State reports the shim's view of the container.
func (s *shimSupervisor) State(ctx context.Context) (shim.State, error) { return s.c.State(ctx) }

// Kill sends one signal through the container's pidfd.
func (s *shimSupervisor) Kill(ctx context.Context, sig syscall.Signal, all bool) error {
	return s.c.Kill(ctx, sig, all)
}

// Wait blocks until the container exits.
func (s *shimSupervisor) Wait(ctx context.Context) (int, error) { return s.c.Wait(ctx) }

// Resize sets the container pty's window size.
func (s *shimSupervisor) Resize(ctx context.Context, h, w uint16) error {
	return s.c.Resize(ctx, h, w)
}

// Stats samples the container's cgroup.
func (s *shimSupervisor) Stats(ctx context.Context) (types.Stats, error) { return s.c.Stats(ctx) }

// Ack releases the shim from its exit grace period.
func (s *shimSupervisor) Ack(ctx context.Context) error { return s.c.Ack(ctx) }

// Shutdown asks the shim to stop the container and exit.
func (s *shimSupervisor) Shutdown(ctx context.Context) error { return s.c.Shutdown(ctx) }

// Attach opens an attach stream.
func (s *shimSupervisor) Attach(ctx context.Context, opts shim.AttachOptions) (Stream, error) {
	st, err := s.c.Attach(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &shimStream{s: st}, nil
}

// Exec starts an additional process inside the container.
func (s *shimSupervisor) Exec(ctx context.Context, execID string, spec []byte, opts shim.AttachOptions) (ExecHandle, error) {
	sess, err := s.c.Exec(ctx, execID, spec, opts)
	if err != nil {
		return nil, err
	}
	return &shimExec{sess: sess, stream: shimStream{s: sess.Stream}}, nil
}

// Close releases the client without touching the container.
func (s *shimSupervisor) Close() error { return s.c.Close() }

// shimStream adapts *shim.AttachStream to Stream.
type shimStream struct {
	s *shim.AttachStream
}

// Terminal reports a merged pty stream.
func (s *shimStream) Terminal() bool { return s.s != nil && s.s.Terminal }

// Stdin returns the container's input side, or nil.
func (s *shimStream) Stdin() io.WriteCloser {
	if s.s == nil {
		return nil
	}
	return s.s.Stdin
}

// Stdout returns the container's output side, or nil.
func (s *shimStream) Stdout() io.Reader {
	if s.s == nil {
		return nil
	}
	return s.s.Stdout
}

// Stderr returns the container's error stream, or nil.
func (s *shimStream) Stderr() io.Reader {
	if s.s == nil {
		return nil
	}
	return s.s.Stderr
}

// Done is closed when the stream ends.
func (s *shimStream) Done() <-chan struct{} {
	if s.s == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return s.s.Done()
}

// Err reports why the stream ended.
func (s *shimStream) Err() error {
	if s.s == nil {
		return nil
	}
	return s.s.Err()
}

// Close detaches without signalling the container.
func (s *shimStream) Close() error {
	if s.s == nil {
		return nil
	}
	return s.s.Close()
}

// shimExec adapts *shim.ExecSession to ExecHandle.
type shimExec struct {
	sess   *shim.ExecSession
	stream shimStream
}

// Terminal reports a merged pty stream.
func (e *shimExec) Terminal() bool { return e.stream.Terminal() }

// Stdin returns the exec's input side.
func (e *shimExec) Stdin() io.WriteCloser { return e.stream.Stdin() }

// Stdout returns the exec's output side.
func (e *shimExec) Stdout() io.Reader { return e.stream.Stdout() }

// Stderr returns the exec's error stream.
func (e *shimExec) Stderr() io.Reader { return e.stream.Stderr() }

// Done is closed when the exec's stream ends.
func (e *shimExec) Done() <-chan struct{} { return e.stream.Done() }

// Err reports why the exec's stream ended.
func (e *shimExec) Err() error { return e.stream.Err() }

// Close tears the exec's stream down; the process keeps running.
func (e *shimExec) Close() error { return e.stream.Close() }

// Pid is the exec'd process's pid.
func (e *shimExec) Pid() int { return e.sess.Pid }

// Wait blocks until the exec'd process exits.
func (e *shimExec) Wait(ctx context.Context) (int, error) { return e.sess.Wait(ctx) }

// Resize sets the exec's pty window size.
func (e *shimExec) Resize(ctx context.Context, h, w uint16) error { return e.sess.Resize(ctx, h, w) }
