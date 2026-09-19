//go:build linux

package content

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// lockPollInterval is how often a blocked lock attempt re-checks the context.
const lockPollInterval = 50 * time.Millisecond

// fileLock is an advisory exclusive lock held on a lock file for as long as the
// file descriptor is open. flock(2) locks are released by the kernel if the
// holder dies, so a crashed daemon never wedges the store.
type fileLock struct {
	f *os.File
}

// acquireLock takes an exclusive flock on path, creating the file if needed. It
// polls rather than blocking in the kernel so a cancelled context is honoured.
func acquireLock(ctx context.Context, path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("content: opening lock file %q: %w", path, err)
	}
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return &fileLock{f: f}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			f.Close()
			return nil, fmt.Errorf("content: locking %q: %w", path, err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("content: waiting for lock %q: %w", path, ctx.Err())
		case <-time.After(lockPollInterval):
		}
	}
}

// release drops the lock.
func (l *fileLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	unlockErr := unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	closeErr := l.f.Close()
	l.f = nil
	if unlockErr != nil {
		return fmt.Errorf("content: unlocking: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("content: closing lock file: %w", closeErr)
	}
	return nil
}
