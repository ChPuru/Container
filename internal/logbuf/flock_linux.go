//go:build linux

package logbuf

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes a BSD advisory lock on f, exclusive for a rotation and shared
// for a tailer's read, so a reader never observes a half-shifted generation
// set. It blocks until the lock is granted.
func lockFile(f *os.File, exclusive bool) error {
	how := unix.LOCK_SH
	if exclusive {
		how = unix.LOCK_EX
	}
	for {
		err := unix.Flock(int(f.Fd()), how)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("logbuf: flock %s: %w", f.Name(), err)
		}
		return nil
	}
}

// unlockFile releases a lock taken by lockFile.
func unlockFile(f *os.File) error {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_UN)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("logbuf: unlock %s: %w", f.Name(), err)
		}
		return nil
	}
}
