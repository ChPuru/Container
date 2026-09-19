//go:build linux

package engine

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// bootTime reads the kernel's boot instant from /proc/stat, which is what
// turns a process's starttime field into a wall-clock time.
func bootTime() (time.Time, bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		rest, ok := strings.CutPrefix(line, "btime ")
		if !ok {
			continue
		}
		secs, cerr := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		if cerr != nil {
			return time.Time{}, false
		}
		return time.Unix(secs, 0), true
	}
	return time.Time{}, false
}

// statOwner renders the owning uid of a /proc entry, which is the uid the
// process runs as.
func statOwner(fi os.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "?"
	}
	return strconv.FormatUint(uint64(st.Uid), 10)
}
