//go:build !windows

package tui

import "os"

// enableVT is a no-op everywhere but Windows: a POSIX terminal interprets
// escape sequences without being asked.
func enableVT(out *os.File) (func(), error) { return func() {}, nil }
