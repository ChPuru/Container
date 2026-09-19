//go:build !linux

package fsutil

import "fmt"

// FileLock is not implemented off Linux; the engine, which is the only
// component that takes state locks, runs only inside the WSL distro. It returns
// an error wrapping ErrUnsupported so the Windows CLI still links.
func FileLock(path string) (*Lock, error) {
	return nil, fmt.Errorf("fsutil: lock %s: %w", path, ErrUnsupported)
}

// TryFileLock is not implemented off Linux. See FileLock.
func TryFileLock(path string) (*Lock, error) {
	return nil, fmt.Errorf("fsutil: lock %s: %w", path, ErrUnsupported)
}

// Unlock is unreachable off Linux, because no Lock can be created there.
func (l *Lock) Unlock() error {
	return fmt.Errorf("fsutil: unlock: %w", ErrUnsupported)
}
