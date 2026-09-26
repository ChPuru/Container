package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/term"

	"github.com/ChPuru/hull/internal/client"
	"github.com/ChPuru/hull/internal/types"
)

// DefaultShellCommand is what the "e" key runs inside a container: bash when
// the image has it, and sh otherwise.
//
// The probe runs inside the container rather than here, in one command, so it
// costs no extra round trip and cannot be fooled by what the host happens to
// have. It is a fixed literal, never built from user input, so there is
// nothing to quote.
var DefaultShellCommand = []string{
	"/bin/sh", "-c",
	"if [ -x /bin/bash ]; then exec /bin/bash; fi; exec /bin/sh",
}

// execResizeInterval is how often an interactive exec re-reads the terminal
// size while it holds the screen. There is no portable resize signal to hang
// this off - Windows has none at all - and half a second is below the point
// where a resized shell feels stale.
const execResizeInterval = 500 * time.Millisecond

// ExecShell returns the [ExecFunc] the dashboard's "e" key runs: an
// interactive shell inside the selected container, on the real terminal.
//
// The dashboard has already suspended itself by the time this is called -
// cooked mode, cursor back, primary screen - so the returned function owns the
// terminal until it returns, and puts back exactly what it changed.
//
// With no cmd it runs [DefaultShellCommand]. Pass one to run something else,
// such as a fixed shell for an image you know.
func ExecShell(c *client.Client, cmd ...string) ExecFunc {
	command := DefaultShellCommand
	if len(cmd) > 0 {
		command = cmd
	}
	return func(ctx context.Context, ctr types.Container) error {
		return execShell(ctx, c, ctr, command)
	}
}

// execShell runs one interactive exec on the process's own terminal.
func execShell(ctx context.Context, c *client.Client, ctr types.Container, cmd []string) error {
	if c == nil {
		return errors.New("tui: exec: no client")
	}
	if ctr.State != types.StateRunning {
		return fmt.Errorf("tui: exec %s: container is %s, not running", ctr.Name, ctr.State)
	}

	in, out := os.Stdin, os.Stdout
	tty := term.IsTerminal(int(in.Fd())) && term.IsTerminal(int(out.Fd()))

	created, err := c.ExecCreate(ctx, ctr.ID, client.ExecCreateRequest{
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          tty,
		Cmd:          cmd,
	})
	if err != nil {
		return fmt.Errorf("tui: exec %s: %w", ctr.Name, err)
	}

	resp, err := c.ExecAttach(ctx, created.ID, tty)
	if err != nil {
		return fmt.Errorf("tui: exec %s: %w", ctr.Name, err)
	}
	defer func() { _ = resp.Close() }()

	if tty {
		state, rerr := term.MakeRaw(int(in.Fd()))
		if rerr != nil {
			return fmt.Errorf("tui: exec %s: raw mode: %w", ctr.Name, rerr)
		}
		defer func() { _ = term.Restore(int(in.Fd()), state) }()

		if w, h, serr := term.GetSize(int(out.Fd())); serr == nil {
			_ = c.ExecResize(ctx, created.ID, h, w)
		}
		stop := make(chan struct{})
		defer close(stop)
		go watchExecResize(ctx, c, created.ID, out, stop)
	}

	// The stdin pump has to be stoppable. io.Copy on os.Stdin cannot be
	// interrupted, so a copy left parked in Read after the shell exits
	// swallows the first keystroke the user gives back to the dashboard.
	stdin := newInterruptibleReader(in)
	defer stdin.stop()

	if err := resp.Stream(ctx, stdin, out, os.Stderr); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("tui: exec %s: %w", ctr.Name, err)
	}
	// A shell that exits non-zero is the user's business, not a dashboard
	// failure, so the exit status is deliberately not turned into an error.
	return nil
}

// watchExecResize keeps the exec's pseudo-terminal the same size as the real
// one for as long as the exec holds the screen.
func watchExecResize(ctx context.Context, c *client.Client, execID string, out *os.File, stop <-chan struct{}) {
	lastW, lastH, err := term.GetSize(int(out.Fd()))
	if err != nil {
		return
	}
	tick := time.NewTicker(execResizeInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-tick.C:
			w, h, err := term.GetSize(int(out.Fd()))
			if err != nil || (w == lastW && h == lastH) {
				continue
			}
			lastW, lastH = w, h
			_ = c.ExecResize(ctx, execID, h, w)
		}
	}
}

// interruptibleReader reads from a terminal in a way that can be stopped.
//
// Where the platform lets an *os.File carry a read deadline - Linux does for a
// tty - the reader wakes regularly and returns io.EOF once it has been
// stopped, so nothing is left parked in Read holding the keyboard. Where it
// does not, Windows being the case that matters, the final Read is not
// interruptible and one keystroke may be consumed on the way out; that is a
// visible hiccup rather than a broken terminal.
type interruptibleReader struct {
	f         *os.File
	deadlines bool
	stopped   atomic.Bool
}

// newInterruptibleReader wraps f, probing once whether read deadlines work on
// it.
func newInterruptibleReader(f *os.File) *interruptibleReader {
	r := &interruptibleReader{f: f}
	if err := f.SetReadDeadline(time.Now().Add(time.Hour)); err == nil {
		r.deadlines = true
	}
	_ = f.SetReadDeadline(time.Time{})
	return r
}

// Read copies from the terminal until the reader is stopped.
func (r *interruptibleReader) Read(p []byte) (int, error) {
	for {
		if r.stopped.Load() {
			return 0, io.EOF
		}
		if !r.deadlines {
			return r.f.Read(p)
		}
		_ = r.f.SetReadDeadline(time.Now().Add(inputPollInterval))
		n, err := r.f.Read(p)
		if n > 0 {
			return n, nil
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		return n, err
	}
}

// stop makes the next Read return io.EOF and wakes one that is already
// waiting. The deadline it leaves behind is harmless: every other reader of
// this terminal sets its own before reading.
func (r *interruptibleReader) stop() {
	r.stopped.Store(true)
	if r.deadlines {
		_ = r.f.SetReadDeadline(time.Now())
	}
}
