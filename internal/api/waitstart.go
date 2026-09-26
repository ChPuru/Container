package api

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ChPuru/hull/internal/engine"
	"github.com/ChPuru/hull/internal/events"
	"github.com/ChPuru/hull/internal/logbuf"
	"github.com/ChPuru/hull/internal/types"
)

// attachStartTimeout bounds how long an attach on a created container will wait
// for someone to start it. A client that attaches and then never starts the
// container would otherwise hold the connection, and a shim, forever.
const attachStartTimeout = 2 * time.Minute

// attachStartPoll is a backstop re-check interval. The event bus is the primary
// signal; polling only covers the case where an event was dropped because this
// subscriber's buffer was full, which the bus does deliberately rather than
// block a publisher.
const attachStartPoll = 200 * time.Millisecond

// waitForStart blocks until the container leaves the "created" state, and
// returns its record as it then stands.
//
// It subscribes to the event bus *before* re-reading the state, so a start that
// lands between the two is still seen: subscribing afterwards would be a lost
// wakeup, and the caller would wait out the whole timeout for an event that had
// already gone by.
//
// A container that goes straight from created to exited — a fast command, or a
// start that failed — is not an error here. The caller still wants the stream,
// because the logs it wrote before exiting are what the client is waiting for.
func (s *Server) waitForStart(ctx context.Context, id string) (*types.Container, error) {
	ctx, cancel := context.WithTimeout(ctx, attachStartTimeout)
	defer cancel()

	ch, unsubscribe := s.backend.Events().Subscribe(ctx, events.Filter{
		Types:      []string{"container"},
		Containers: []string{id},
	}, time.Time{}, time.Time{})
	defer unsubscribe()

	ticker := time.NewTicker(attachStartPoll)
	defer ticker.Stop()

	for {
		c, err := s.backend.Inspect(ctx, id)
		if err != nil {
			return nil, err
		}
		if c.State != types.StateCreated {
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for container %s to start: %w", id, ctx.Err())
		case <-ch:
		case <-ticker.C:
		}
	}
}

// replayLog writes a finished container's log to an already-hijacked connection.
//
// It exists because attach and start are two separate requests: a container that
// runs for a few milliseconds is reliably gone before the attach can reach it,
// and a live attach to an exited container is an error. Replaying the log gives
// the client exactly the bytes it would have seen had it been attached, with the
// same framing, so neither `hull run` nor `docker run` can tell the difference.
//
// Only the streams the client asked for are sent, and the connection is flushed
// and left for the caller to close, which is what signals end-of-output.
func (s *Server) replayLog(ctx context.Context, brw *bufio.ReadWriter, c *types.Container, wantStdout, wantStderr bool) error {
	s.log.Debug("hull: attach replaying the log of a container that already exited",
		"container", c.ID[:12], "exitCode", c.ExitCode)

	opts := logbuf.ReadOptions{
		Tail:   -1,
		Stdout: wantStdout,
		Stderr: wantStderr,
	}
	w := hijackedStdout{w: brw}
	if err := s.backend.Logs(ctx, c.ID, opts, w, !c.Config.Tty); err != nil {
		// The hijack is done, so there is no status line left to send; log it
		// and close, which the client reads as end-of-stream.
		s.log.Debug("hull: replaying the log failed", "container", c.ID[:12], "err", err)
	}
	return brw.Flush()
}

// lostAttachGrace bounds how long an attach that lost the race with a fast
// exit waits for the engine to record that exit before replaying the log.
const lostAttachGrace = 10 * time.Second

// exitedAfterLostAttach reports the container's final record when an attach
// failed only because the process had already gone. The shim notices the exit
// before the engine records it, so the state is briefly still "running"; this
// waits for the engine to catch up. It returns nil for any other failure.
func (s *Server) exitedAfterLostAttach(ctx context.Context, id string, attachErr error) *types.Container {
	if errors.Is(attachErr, engine.ErrConflict) || errors.Is(attachErr, engine.ErrNotFound) {
		return nil
	}
	wctx, cancel := context.WithTimeout(ctx, lostAttachGrace)
	defer cancel()
	if _, err := s.backend.Wait(wctx, id, engine.WaitNotRunning); err != nil {
		return nil
	}
	c, err := s.backend.Inspect(ctx, id)
	if err != nil || (c.State != types.StateExited && c.State != types.StateDead) {
		return nil
	}
	return c
}
