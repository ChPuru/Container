//go:build !linux

package bundle

import "fmt"

// statDevice is not implemented off Linux. --device describes a Linux device
// node, and the Windows CLI never generates a bundle; it only translates paths
// before handing them to the daemon.
func statDevice(hostPath string) (deviceInfo, error) {
	return deviceInfo{}, fmt.Errorf("device nodes can only be inspected on Linux, not while running on this platform (%s)", hostPath)
}
