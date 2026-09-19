//go:build !linux

package fsutil

import (
	"fmt"
	"os"
)

// SecureOpen is not implemented off Linux. Safe resolution of a container path
// needs openat2 or fd-relative openat; Windows has neither, and no hull code
// path on Windows touches a container rootfs. The stub keeps the CLI building.
func SecureOpen(root string, path string, flags int, mode os.FileMode) (*os.File, error) {
	return nil, fmt.Errorf("fsutil: SecureOpen %q in %s: %w", path, root, ErrUnsupported)
}

// SecureStat is not implemented off Linux. See SecureOpen.
func SecureStat(root, path string) (os.FileInfo, error) {
	return nil, fmt.Errorf("fsutil: SecureStat %q in %s: %w", path, root, ErrUnsupported)
}

// SecureMkdirAll is not implemented off Linux. See SecureOpen.
func SecureMkdirAll(root, path string, perm os.FileMode) error {
	return fmt.Errorf("fsutil: SecureMkdirAll %q in %s: %w", path, root, ErrUnsupported)
}

// ProbeOpenat2 always reports false off Linux: there is no openat2 syscall.
func ProbeOpenat2() bool { return false }
