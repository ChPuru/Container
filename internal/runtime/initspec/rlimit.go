package initspec

import (
	"fmt"
	"strings"
)

// rlimitNames maps the runtime-spec rlimit token to its resource number. The
// numbers are identical on every Linux architecture hull targets.
var rlimitNames = map[string]int{
	"RLIMIT_CPU":        0,
	"RLIMIT_FSIZE":      1,
	"RLIMIT_DATA":       2,
	"RLIMIT_STACK":      3,
	"RLIMIT_CORE":       4,
	"RLIMIT_RSS":        5,
	"RLIMIT_NPROC":      6,
	"RLIMIT_NOFILE":     7,
	"RLIMIT_MEMLOCK":    8,
	"RLIMIT_AS":         9,
	"RLIMIT_LOCKS":      10,
	"RLIMIT_SIGPENDING": 11,
	"RLIMIT_MSGQUEUE":   12,
	"RLIMIT_NICE":       13,
	"RLIMIT_RTPRIO":     14,
	"RLIMIT_RTTIME":     15,
}

// RlimitNumber resolves an rlimit token such as RLIMIT_NOFILE to its resource
// number. Lookup is case-insensitive and a missing RLIMIT_ prefix is
// tolerated, matching what Docker accepts in --ulimit.
func RlimitNumber(name string) (int, bool) {
	n := strings.ToUpper(strings.TrimSpace(name))
	if !strings.HasPrefix(n, "RLIMIT_") {
		n = "RLIMIT_" + n
	}
	v, ok := rlimitNames[n]
	return v, ok
}

// RlimitNames returns every rlimit token hull knows, in resource order.
func RlimitNames() []string {
	out := make([]string, len(rlimitNames))
	for name, n := range rlimitNames {
		out[n] = name
	}
	return out
}

// ValidateRlimitName returns a clear error for an unknown rlimit token.
func ValidateRlimitName(name string) error {
	if _, ok := RlimitNumber(name); !ok {
		return fmt.Errorf("initspec: unknown rlimit %q (known: %s)", name, strings.Join(RlimitNames(), ", "))
	}
	return nil
}
