package shim

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProcessStartTime returns field 22 of /proc/<pid>/stat, the process start
// time in clock ticks since boot. Paired with the pid it identifies a process
// for the life of the boot, which is what makes a recycled pid detectable.
//
// The comm field (2) is wrapped in parentheses and may itself contain spaces
// and parentheses, so the parse starts after the last ')'.
func ProcessStartTime(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("shim: invalid pid %d", pid)
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, fmt.Errorf("shim: read /proc/%d/stat: %w", pid, err)
	}
	s := string(data)
	end := strings.LastIndexByte(s, ')')
	if end < 0 || end+2 >= len(s) {
		return 0, fmt.Errorf("shim: /proc/%d/stat is malformed", pid)
	}
	// Fields after comm start at 3, so starttime (22) is index 19 here.
	fields := strings.Fields(s[end+2:])
	const startTimeIndex = 19
	if len(fields) <= startTimeIndex {
		return 0, fmt.Errorf("shim: /proc/%d/stat has %d fields after comm, need %d", pid, len(fields), startTimeIndex+1)
	}
	v, err := strconv.ParseUint(fields[startTimeIndex], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("shim: parse starttime from /proc/%d/stat: %w", pid, err)
	}
	return v, nil
}
