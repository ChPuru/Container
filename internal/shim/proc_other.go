//go:build !linux

package shim

import (
	"errors"
	"runtime"
)

// ProcessStartTime is Linux-only: it reads /proc/<pid>/stat. On other systems
// it reports an error so ShimState.Validate conservatively answers "gone".
func ProcessStartTime(pid int) (uint64, error) {
	return 0, errors.New("shim: process start time is only available on linux, not " + runtime.GOOS)
}
