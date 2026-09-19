//go:build linux

package tui

import (
	"context"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

// watchResize reports terminal size changes to the render loop.
//
// On Linux the kernel tells us: SIGWINCH arrives on every resize, so the
// dashboard re-lays out immediately rather than up to half a second later.
func watchResize(ctx context.Context, t *terminal, out chan<- msg) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGWINCH)
	defer signal.Stop(sigs)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sigs:
			w, h, err := t.size()
			if err != nil {
				continue
			}
			if !send(ctx, out, msg{kind: msgResize, w: w, h: h}) {
				return
			}
		}
	}
}
