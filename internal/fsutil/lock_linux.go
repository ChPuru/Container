package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lockPerm is the mode a lock file is created with. Lock files carry no data,
// only the flock; 0o644 keeps them readable for debugging.
const lockPerm os.FileMode = 0o644

// FileLock takes an exclusive advisory lock (flock LOCK_EX) on path, creating
// the file if it does not exist, and blocks until the lock is available.
//
// The lock is attached to the open file description, so a second holder in this
// same process (a different open of the same path) blocks exactly like a holder
// in another process would. It is released by Unlock, and by the kernel if the
// process dies, which is what makes it safe for hull's crash-recovery paths.
//
// Because flock blocks in the kernel, the calling goroutine occupies an OS
// thread for the duration; use TryFileLock in hot paths where that matters.
func FileLock(path string) (*Lock, error) { return lockFile(path, false) }

// TryFileLock is FileLock without the wait: if another holder owns the lock it
// returns ErrLocked immediately instead of blocking.
func TryFileLock(path string) (*Lock, error) { return lockFile(path, true) }

func lockFile(path string, nonblock bool) (*Lock, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("fsutil: create lock dir %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_CLOEXEC, lockPerm)
	if err != nil {
		return nil, fmt.Errorf("fsutil: open lock %s: %w", path, err)
	}
	how := unix.LOCK_EX
	if nonblock {
		how |= unix.LOCK_NB
	}
	for {
		err = unix.Flock(int(f.Fd()), how)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("fsutil: lock %s: %w", path, ErrLocked)
		}
		return nil, fmt.Errorf("fsutil: lock %s: %w", path, err)
	}
	return &Lock{f: f, path: path}, nil
}

// Unlock releases the lock and closes its descriptor. It is safe to call on a
// nil Lock and returns an error if called twice.
func (l *Lock) Unlock() error {
	if l == nil || l.f == nil {
		return fmt.Errorf("fsutil: unlock: lock is not held")
	}
	f := l.f
	l.f = nil
	// Closing the descriptor already drops the flock; unlocking first makes
	// the release explicit and reports a broken descriptor loudly.
	if err := unix.Flock(int(f.Fd()), unix.LOCK_UN); err != nil {
		f.Close()
		return fmt.Errorf("fsutil: unlock %s: %w", l.path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("fsutil: close lock %s: %w", l.path, err)
	}
	return nil
}
