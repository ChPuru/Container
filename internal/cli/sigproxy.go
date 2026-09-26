package cli

import (
	"context"
	"os"
	"os/signal"
	"sync"

	"github.com/ChPuru/hull/internal/client"
)

// proxySignals forwards the signals this process receives to a container,
// returning a function that stops forwarding.
//
// It is what --sig-proxy means, and it only applies without a TTY: with one,
// the terminal is in raw mode and Ctrl-C is a byte the container's own line
// discipline sees, so no signal is raised here at all.
//
// A signal the container cannot be sent is reported and swallowed rather than
// unwinding the CLI, because the user's intent was to reach the container and
// an error message is more use than a dead client next to a live container.
func proxySignals(ctx context.Context, env *Env, cli *client.Client, container string) func() {
	ch := make(chan os.Signal, 4)
	notifySignals(ch)

	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			signal.Stop(ch)
			close(done)
		})
	}

	go func() {
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case sig := <-ch:
				name := signalName(sig)
				if name == "" {
					continue
				}
				if err := cli.ContainerKill(ctx, container, name); err != nil {
					if client.IsNotFound(err) || client.IsConflict(err) {
						// The container is already gone or already stopped;
						// there is nothing left to signal.
						return
					}
					env.Warnf("could not forward %s to %s: %v", name, container, err)
				}
			}
		}
	}()
	return stop
}
