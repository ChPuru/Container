//go:build windows

package state

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// errWouldBlock is returned by tryLockFileExclusive when the lock is held.
var errWouldBlock = errors.New("file lock is held by another process")

// lockRegionLen is the byte range locked on Windows. LockFileEx locks a byte
// range rather than a whole file, so hull always locks the same maximal range.
const lockRegionLen = ^uint32(0)

func lockFileEx(f *os.File, flags uint32) error {
	ol := new(windows.Overlapped)
	return windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, lockRegionLen, lockRegionLen, ol)
}

// lockFileExclusive takes a blocking exclusive lock on f.
func lockFileExclusive(f *os.File) error {
	return lockFileEx(f, windows.LOCKFILE_EXCLUSIVE_LOCK)
}

// tryLockFileExclusive attempts a non-blocking exclusive lock on f. It returns
// errWouldBlock when another process already holds it.
func tryLockFileExclusive(f *os.File) error {
	err := lockFileEx(f, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY)
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return errWouldBlock
	}
	return err
}

// unlockFile releases a lock held on f.
func unlockFile(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, lockRegionLen, lockRegionLen, ol)
}

// syncDir is a no-op on Windows, where directories cannot be fsynced and
// NTFS metadata ordering already makes a rename durable once the file is
// flushed.
func syncDir(string) error { return nil }

// isNotSymlink reports whether err says the target is not a reparse point.
func isNotSymlink(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_A_REPARSE_POINT)
}
