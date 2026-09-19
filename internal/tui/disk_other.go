//go:build !linux && !windows

package tui

import "errors"

// localDiskUsage has no implementation on this platform, so the status bar
// falls back to naming the data root without a free-space figure.
func localDiskUsage(path string) (free, total uint64, err error) {
	return 0, 0, errors.New("tui: disk usage is not supported on this platform")
}
