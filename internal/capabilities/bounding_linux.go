//go:build linux

package capabilities

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// statusPath is the file BoundingSet reads. It is a variable so tests can
// point it at a fixture without needing root or a particular kernel.
var statusPath = "/proc/self/status"

// geteuid returns the effective uid of the current process.
func geteuid() int { return os.Geteuid() }

// BoundingSet returns the capability bounding set of the calling process,
// parsed from the CapBnd line of /proc/self/status.
//
// This is the ceiling on what any child can ever hold, so it is what
// --privileged actually grants. Bits above LastCap are ignored: a kernel
// newer than hull's table may set them, and inventing a name for a capability
// hull does not understand would be worse than omitting it.
func BoundingSet() ([]Cap, error) {
	f, err := os.Open(statusPath)
	if err != nil {
		return nil, fmt.Errorf("capabilities: open %s: %w", statusPath, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		rest, ok := strings.CutPrefix(line, "CapBnd:")
		if !ok {
			continue
		}
		hex := strings.TrimSpace(rest)
		mask, perr := strconv.ParseUint(hex, 16, 64)
		if perr != nil {
			return nil, fmt.Errorf("capabilities: parse CapBnd %q from %s: %w", hex, statusPath, perr)
		}
		return fromMask(mask), nil
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("capabilities: read %s: %w", statusPath, err)
	}
	return nil, fmt.Errorf("capabilities: no CapBnd line in %s; this kernel does not report the bounding set", statusPath)
}

// fromMask expands a capability bitmask into the capabilities hull knows.
func fromMask(mask uint64) []Cap {
	out := make([]Cap, 0, len(capNames))
	for i := 0; i <= int(LastCap); i++ {
		if mask&(1<<uint(i)) != 0 {
			out = append(out, Cap(i))
		}
	}
	return out
}
