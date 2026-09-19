//go:build windows

package cli

import (
	"context"
	"time"
)

// resizePoll is how often the Windows build re-reads the console size. There
// is no SIGWINCH on Windows, and the console API's resize events are only
// delivered to a process that owns the input handle in event mode — which the
// attached container's raw stdin does not.
const resizePoll = 250 * time.Millisecond

// watchResize polls the console size and reports every change.
func watchResize(ctx context.Context, t *Terminal, fn func(height, width int)) {
	go func() {
		ticker := time.NewTicker(resizePoll)
		defer ticker.Stop()
		lastW, lastH := 0, 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w, h, err := t.Size()
				if err != nil || w <= 0 || h <= 0 {
					continue
				}
				if w != lastW || h != lastH {
					lastW, lastH = w, h
					fn(h, w)
				}
			}
		}
	}()
}
