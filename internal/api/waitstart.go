package api

import (
	"context"
	"fmt"
	"time"

	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/types"
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
