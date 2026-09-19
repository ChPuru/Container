//go:build windows

package tui

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// localDiskUsage reports free and total bytes of the volume holding path.
//
// On Windows this only ever answers for a Windows path. The engine's data root
// lives inside the WSL distro, so the status bar's figure comes from the
// engine through [DiskReporter]; this exists so a client pointed at a Windows
// directory still gets an answer rather than a silent dash.
func localDiskUsage(path string) (free, total uint64, err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, fmt.Errorf("tui: disk usage %s: %w", path, err)
	}
	var freeToCaller, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &freeToCaller, &totalBytes, &totalFree); err != nil {
		return 0, 0, fmt.Errorf("tui: disk usage %s: %w", path, err)
	}
	return freeToCaller, totalBytes, nil
}
