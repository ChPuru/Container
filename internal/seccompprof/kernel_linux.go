//go:build linux

package seccompprof

import (
	"os"
	"strings"
	"sync"
)

// osReleasePath holds the running kernel version. It is a variable so tests
// can point it at a fixture instead of depending on the host kernel.
var osReleasePath = "/proc/sys/kernel/osrelease"

var (
	kernelOnce sync.Once
	kernelMaj  int
	kernelMin  int
	kernelOK   bool
)

// kernelVersion returns the running kernel's major and minor version, and
// whether they could be determined. It is cached: the kernel does not change
// under a running daemon.
func kernelVersion() (int, int, bool) {
	kernelOnce.Do(func() {
		data, err := os.ReadFile(osReleasePath)
		if err != nil {
			return
		}
		maj, min, perr := parseKernelVersion(strings.TrimSpace(string(data)))
		if perr != nil {
			return
		}
		kernelMaj, kernelMin, kernelOK = maj, min, true
	})
	return kernelMaj, kernelMin, kernelOK
}
