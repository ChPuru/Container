//go:build !linux

package tui

import (
	"context"
	"time"
)

// resizePollInterval is how often the size is re-read where there is no
// resize signal. Twice a second is below the threshold at which a redraw
// after a drag feels late, and costs one console call.
const resizePollInterval = 500 * time.Millisecond

// watchResize reports terminal size changes to the render loop.
//
// Windows has no SIGWINCH - the console sends a window-buffer-size record on
// the input queue, which x/term does not surface - so the size is polled and
// only a real change is reported.
func watchResize(ctx context.Context, t *terminal, out chan<- msg) {
	tick := time.NewTicker(resizePollInterval)
	defer tick.Stop()
	lastW, lastH, _ := t.size()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w, h, err := t.size()
			if err != nil || (w == lastW && h == lastH) {
				continue
			}
			lastW, lastH = w, h
			if !send(ctx, out, msg{kind: msgResize, w: w, h: h}) {
				return
			}
		}
	}
}
