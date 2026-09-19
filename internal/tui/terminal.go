package tui

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/term"
)

// Terminal control sequences. They are written by hand rather than looked up
// in a terminfo database because hull targets VT-compatible terminals only -
// Windows Terminal, conhost with virtual-terminal processing on, and every
// Linux terminal emulator - and a terminfo dependency would be a new module.
const (
	// seqAltScreenOn switches to the alternate screen buffer, so quitting
	// restores whatever the user had in their scrollback. A dashboard that
	// scribbles over the primary buffer destroys the output of whatever
	// they were doing before.
	seqAltScreenOn = "\x1b[?1049h"
	// seqAltScreenOff returns to the primary buffer.
	seqAltScreenOff = "\x1b[?1049l"
	// seqHideCursor and seqShowCursor manage the cursor.
	seqHideCursor = "\x1b[?25l"
	seqShowCursor = "\x1b[?25h"
	// seqReset clears every graphic attribute.
	seqReset = "\x1b[m"
	// seqClear erases the screen and homes the cursor.
	seqClear = "\x1b[2J\x1b[H"
)

// terminal owns the real terminal: raw mode, the alternate screen, the cursor
// and, on Windows, the console's virtual-terminal mode.
//
// Every method is safe to call from any goroutine and every restore is
// idempotent, because [terminal.leave] is called from three places that can
// race: the deferred cleanup in [Run], the signal handler, and the panic
// recovery. Leaving a user in raw mode with no cursor is the one failure this
// package must never have.
type terminal struct {
	in  *os.File
	out *os.File

	inFD  int
	outFD int

	mu        sync.Mutex
	raw       *term.State
	entered   bool
	restoreVT func()
}

// newTerminal wraps an input and an output file. Both must be terminals.
func newTerminal(in, out *os.File) (*terminal, error) {
	if in == nil || out == nil {
		return nil, fmt.Errorf("tui: %w", ErrNotTerminal)
	}
	t := &terminal{
		in:    in,
		out:   out,
		inFD:  int(in.Fd()),
		outFD: int(out.Fd()),
	}
	if !term.IsTerminal(t.outFD) || !term.IsTerminal(t.inFD) {
		return nil, fmt.Errorf("tui: %w", ErrNotTerminal)
	}
	return t, nil
}

// enter puts the terminal into the state the dashboard needs: raw input, the
// alternate screen, no cursor, and virtual-terminal processing on Windows.
func (t *terminal) enter() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entered {
		return nil
	}
	restoreVT, err := enableVT(t.out)
	if err != nil {
		return fmt.Errorf("tui: enable virtual terminal: %w", err)
	}
	state, err := term.MakeRaw(t.inFD)
	if err != nil {
		restoreVT()
		return fmt.Errorf("tui: raw mode: %w", err)
	}
	t.raw = state
	t.restoreVT = restoreVT
	t.entered = true
	if _, err := t.out.WriteString(seqAltScreenOn + seqHideCursor + seqReset + seqClear); err != nil {
		t.leaveLocked()
		return fmt.Errorf("tui: enter alternate screen: %w", err)
	}
	return nil
}

// leave restores the terminal. It is idempotent and never returns an error:
// there is nothing useful to do with one, and every caller is already on its
// way out.
func (t *terminal) leave() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.leaveLocked()
}

// leaveLocked is leave with the mutex already held.
func (t *terminal) leaveLocked() {
	if !t.entered {
		return
	}
	t.entered = false
	// Write the screen restoration before dropping raw mode: the sequences
	// are the terminal's business and cooked mode may translate them.
	_, _ = t.out.WriteString(seqShowCursor + seqReset + seqAltScreenOff)
	if t.raw != nil {
		_ = term.Restore(t.inFD, t.raw)
		t.raw = nil
	}
	if t.restoreVT != nil {
		t.restoreVT()
		t.restoreVT = nil
	}
}

// size returns the terminal's current size in cells.
func (t *terminal) size() (int, int, error) {
	w, h, err := term.GetSize(t.outFD)
	if err != nil {
		return 0, 0, fmt.Errorf("tui: terminal size: %w", err)
	}
	return w, h, nil
}

// suspend hands the terminal back to the user - cooked mode, cursor shown,
// primary screen - so a child process such as an interactive shell can have
// it. Pair it with [terminal.resume].
func (t *terminal) suspend() { t.leave() }

// resume takes the terminal back after a suspend.
func (t *terminal) resume() error { return t.enter() }
