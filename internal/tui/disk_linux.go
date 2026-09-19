//go:build linux

package tui

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// localDiskUsage reports free and total bytes of the filesystem holding path.
//
// It is only ever reached when the dashboard is running inside the engine
// distro, where the data root really is a local path. The Windows client
// cannot see /var/lib/hull at all, which is why the status bar prefers the
// engine's own answer through [DiskReporter] and treats this as the fallback.
func localDiskUsage(path string) (free, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, fmt.Errorf("tui: statfs %s: %w", path, err)
	}
	bsize := uint64(st.Bsize)
	return st.Bavail * bsize, st.Blocks * bsize, nil
}
