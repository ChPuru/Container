//go:build unix

package state

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// errWouldBlock is returned by tryLockFile when the lock is held elsewhere.
var errWouldBlock = errors.New("file lock is held by another process")

// lockFileExclusive takes a blocking exclusive advisory lock (flock LOCK_EX) on
// f. flock locks are attached to the open file description, so two goroutines
// that opened the same path through different *os.File values still exclude
// each other, which is exactly what UpdateContainer needs.
func lockFileExclusive(f *os.File) error {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if err == nil {
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

// tryLockFileExclusive attempts a non-blocking exclusive lock (LOCK_EX|LOCK_NB).
// It returns errWouldBlock when the lock is already held.
func tryLockFileExclusive(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EACCES):
		return errWouldBlock
	default:
		return err
	}
}

// unlockFile releases an advisory lock held on f.
func unlockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}

// syncDir fsyncs a directory so that a rename into it is durable. On Linux this
// is required: renaming a file is only guaranteed to survive a power cut once
// the parent directory's metadata has been flushed.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		// Some filesystems (notably 9p, which backs /mnt/c inside WSL) reject
		// fsync on a directory. Treat that as "nothing to flush" rather than a
		// hard failure; on those filesystems there is no durability to gain.
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EBADF) {
			return nil
		}
		return err
	}
	return nil
}

// isNotSymlink reports whether err is the kernel's way of saying readlink was
// called on something that is not a symbolic link (EINVAL).
func isNotSymlink(err error) bool { return errors.Is(err, unix.EINVAL) }
