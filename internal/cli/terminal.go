package cli

import (
	"context"
	"fmt"
	"os"
	"sync"

	"golang.org/x/term"
)

// isTerminal reports whether f is a terminal. A nil file never is, which keeps
// the tests from having to fabricate one.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// terminalSize returns the width and height of f in character cells.
func terminalSize(f *os.File) (width, height int, err error) {
	if f == nil {
		return 0, 0, fmt.Errorf("cli: no terminal")
	}
	return term.GetSize(int(f.Fd()))
}

// Terminal owns the local terminal's mode for the duration of an interactive
// command, and guarantees it is handed back.
//
// Restore is idempotent and safe to call from a defer, from a signal handler
// and from a panic recovery at the same time. That matters: a container
// attached with -it leaves the terminal in raw mode if any exit path misses
// the restore, and the user is left with a shell that does not echo.
type Terminal struct {
	in  *os.File
	out *os.File

	mu    sync.Mutex
	state *term.State
}

// NewTerminal wraps the local terminal's input and output files.
func NewTerminal(in, out *os.File) *Terminal {
	return &Terminal{in: in, out: out}
}

// IsTerminal reports whether input is a terminal, which is the precondition
// for raw mode.
func (t *Terminal) IsTerminal() bool { return isTerminal(t.in) }

// Size returns the output terminal's size, falling back to the input side when
// output is redirected.
func (t *Terminal) Size() (width, height int, err error) {
	if isTerminal(t.out) {
		return terminalSize(t.out)
	}
	return terminalSize(t.in)
}

// MakeRaw puts the input terminal into raw mode so every keystroke, including
// Ctrl-C and the detach sequence, reaches the container rather than the local
// shell. It is a no-op when input is not a terminal.
func (t *Terminal) MakeRaw() error {
	if !t.IsTerminal() {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state != nil {
		return nil
	}
	state, err := term.MakeRaw(int(t.in.Fd()))
	if err != nil {
		return fmt.Errorf("cli: entering raw mode: %w", err)
	}
	t.state = state
	return nil
}

// Restore puts the terminal back the way it was. It may be called any number
// of times from any number of goroutines.
func (t *Terminal) Restore() {
	t.mu.Lock()
	state := t.state
	t.state = nil
	t.mu.Unlock()
	if state == nil {
		return
	}
	_ = term.Restore(int(t.in.Fd()), state)
}

// RawGuard runs fn with the terminal in raw mode, restoring it on every exit
// path: a normal return, an error, or a panic that is re-raised afterwards.
func (t *Terminal) RawGuard(fn func() error) (err error) {
	if rawErr := t.MakeRaw(); rawErr != nil {
		return rawErr
	}
	defer func() {
		t.Restore()
		if p := recover(); p != nil {
			panic(p)
		}
	}()
	return fn()
}

// WatchResize reports the terminal's size to fn once immediately and then
// whenever it changes, until ctx is cancelled. On Unix it waits on SIGWINCH;
// elsewhere it polls, because Windows has no such signal.
func (t *Terminal) WatchResize(ctx context.Context, fn func(height, width int)) {
	if w, h, err := t.Size(); err == nil && h > 0 && w > 0 {
		fn(h, w)
	}
	watchResize(ctx, t, fn)
}
