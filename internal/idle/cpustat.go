package idle

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// cpuStatFile is the cgroup v2 interface file the CPU activity signal is read
// from. Its usage_usec line is cumulative CPU time for the whole subtree, in
// microseconds, and it is the only counter hull needs here: two readings and
// the time between them say whether anything ran.
const cpuStatFile = "cpu.stat"

// ReadCPUUsageUsec reads cumulative CPU time, in microseconds, from
// <cgroupPath>/cpu.stat. It is the default Config.CPUUsage.
//
// It reports ok == false, never an error, when the counter cannot be read:
// an empty path (the engine hands one over when the host has no usable
// unified hierarchy), a cgroup that has been removed under us, or a kernel
// that exposes no cpu controller at all — which is the normal case on the
// hybrid-cgroup WSL 5.15 kernel, where /sys/fs/cgroup/unified delegates
// nothing. A missing CPU signal is not activity and is not idleness; it simply
// leaves the decision to the attach, port and Touch signals, and the watcher
// reports it once through the logger and in Stats.CPUSampling.
func ReadCPUUsageUsec(cgroupPath string) (uint64, bool) {
	if cgroupPath == "" {
		return 0, false
	}
	b, err := os.ReadFile(filepath.Join(cgroupPath, cpuStatFile))
	if err != nil {
		return 0, false
	}
	return parseCPUUsageUsec(string(b))
}

// parseCPUUsageUsec pulls usage_usec out of a cpu.stat body. The file is a
// flat "key value" list whose first line is usage_usec on every kernel that
// has the cpu controller, but nothing guarantees the order, so it is searched
// rather than indexed.
func parseCPUUsageUsec(text string) (uint64, bool) {
	for len(text) > 0 {
		var line string
		line, text, _ = strings.Cut(text, "\n")
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || key != "usage_usec" {
			continue
		}
		usec, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, false
		}
		return usec, true
	}
	return 0, false
}
