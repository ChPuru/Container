//go:build !linux

package capabilities

import (
	"fmt"
	"runtime"
)

// geteuid has no meaningful answer off Linux; the hull CLI only ever uses the
// capability table for validation there, never to build a live spec.
func geteuid() int { return 0 }

// BoundingSet is Linux-only: it reads the CapBnd line of /proc/self/status.
// On every other platform it returns an error rather than a guess, so a
// caller cannot accidentally treat "all capabilities" as the answer.
func BoundingSet() ([]Cap, error) {
	return nil, fmt.Errorf("capabilities: the capability bounding set is only readable on linux, not %s", runtime.GOOS)
}
