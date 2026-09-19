//go:build !linux

package logbuf

import "os"

// lockFile is a no-op off Linux. hull only ever writes container logs inside
// the engine distro; the Windows build of the CLI links this package for the
// stream framing helpers alone.
func lockFile(f *os.File, exclusive bool) error { return nil }

// unlockFile is a no-op off Linux.
func unlockFile(f *os.File) error { return nil }
