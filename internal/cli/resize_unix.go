//go:build !windows

package cli

import (
	"context"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

// watchResize waits on SIGWINCH, which the kernel raises on the controlling
// terminal's process group whenever the window changes size.
func watchResize(ctx context.Context, t *Terminal, fn func(height, width int)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGWINCH)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				w, h, err := t.Size()
				if err == nil && h > 0 && w > 0 {
					fn(h, w)
				}
			}
		}
	}()
}
