//go:build !linux

package fsutil

import "fmt"

// FreeSpace is not implemented off Linux. The engine, which is the only caller,
// runs inside the WSL distro.
func FreeSpace(path string) (free, total uint64, err error) {
	return 0, 0, fmt.Errorf("fsutil: free space for %s: %w", path, ErrUnsupported)
}

// IsMountpoint is not implemented off Linux; Windows has no mountinfo and hull
// never inspects mounts from the CLI side.
func IsMountpoint(path string) (bool, error) {
	return false, fmt.Errorf("fsutil: mountpoint check for %s: %w", path, ErrUnsupported)
}
