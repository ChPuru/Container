//go:build windows

package tui

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVT turns on virtual-terminal processing for the console attached to
// out, and returns a function that puts the mode back.
//
// Windows consoles do not interpret ANSI escape sequences unless the mode bit
// is set, and conhost still starts without it in some configurations. Without
// this the dashboard paints escape sequences as literal text, which looks like
// a rendering bug rather than a console mode.
//
// A handle that is not a console - a redirected stdout - is left alone and the
// returned restore function does nothing; [newTerminal] has already refused
// that case, so this is belt and braces.
func enableVT(out *os.File) (func(), error) {
	handle := windows.Handle(out.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return func() {}, nil
	}
	want := mode | windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	if want == mode {
		return func() {}, nil
	}
	if err := windows.SetConsoleMode(handle, want); err != nil {
		// An old console that cannot do VT at all: report it rather than
		// drawing garbage.
		return func() {}, err
	}
	return func() { _ = windows.SetConsoleMode(handle, mode) }, nil
}
