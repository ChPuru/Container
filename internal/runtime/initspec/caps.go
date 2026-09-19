package initspec

import (
	"fmt"
	"strings"
)

// capNames maps the runtime-spec capability token to its bit number in
// linux/capability.h. The table is checked in rather than derived from
// golang.org/x/sys/unix so the CLI can validate a spec on a host that is not
// Linux at all.
var capNames = map[string]int{
	"CAP_CHOWN":              0,
	"CAP_DAC_OVERRIDE":       1,
	"CAP_DAC_READ_SEARCH":    2,
	"CAP_FOWNER":             3,
	"CAP_FSETID":             4,
	"CAP_KILL":               5,
	"CAP_SETGID":             6,
	"CAP_SETUID":             7,
	"CAP_SETPCAP":            8,
	"CAP_LINUX_IMMUTABLE":    9,
	"CAP_NET_BIND_SERVICE":   10,
	"CAP_NET_BROADCAST":      11,
	"CAP_NET_ADMIN":          12,
	"CAP_NET_RAW":            13,
	"CAP_IPC_LOCK":           14,
	"CAP_IPC_OWNER":          15,
	"CAP_SYS_MODULE":         16,
	"CAP_SYS_RAWIO":          17,
	"CAP_SYS_CHROOT":         18,
	"CAP_SYS_PTRACE":         19,
	"CAP_SYS_PACCT":          20,
	"CAP_SYS_ADMIN":          21,
	"CAP_SYS_BOOT":           22,
	"CAP_SYS_NICE":           23,
	"CAP_SYS_RESOURCE":       24,
	"CAP_SYS_TIME":           25,
	"CAP_SYS_TTY_CONFIG":     26,
	"CAP_MKNOD":              27,
	"CAP_LEASE":              28,
	"CAP_AUDIT_WRITE":        29,
	"CAP_AUDIT_CONTROL":      30,
	"CAP_SETFCAP":            31,
	"CAP_MAC_OVERRIDE":       32,
	"CAP_MAC_ADMIN":          33,
	"CAP_SYSLOG":             34,
	"CAP_WAKE_ALARM":         35,
	"CAP_BLOCK_SUSPEND":      36,
	"CAP_AUDIT_READ":         37,
	"CAP_PERFMON":            38,
	"CAP_BPF":                39,
	"CAP_CHECKPOINT_RESTORE": 40,
}

// CapLast is the highest capability bit hull knows about. Bits above it are
// still dropped from the bounding set by ApplyCapabilities, up to the number
// the running kernel reports.
const CapLast = 40

// CapNumber resolves a capability token such as CAP_NET_ADMIN to its bit
// number. Lookup is case-insensitive and a missing CAP_ prefix is tolerated,
// because both spellings occur in the wild.
func CapNumber(name string) (int, bool) {
	n := strings.ToUpper(strings.TrimSpace(name))
	if !strings.HasPrefix(n, "CAP_") {
		n = "CAP_" + n
	}
	v, ok := capNames[n]
	return v, ok
}

// CapNames returns every capability token hull knows, in bit order. The CLI
// uses it to validate --cap-add and --cap-drop.
func CapNames() []string {
	out := make([]string, CapLast+1)
	for name, bit := range capNames {
		out[bit] = name
	}
	return out
}

// capMask is a 64-bit capability set, split into the two 32-bit halves the
// capset(2) version 3 ABI uses.
type capMask uint64

func maskOf(names []string) (capMask, error) {
	var m capMask
	for _, n := range names {
		bit, ok := CapNumber(n)
		if !ok {
			return 0, fmt.Errorf("initspec: unknown capability %q", n)
		}
		m |= 1 << uint(bit)
	}
	return m, nil
}

func (m capMask) lo() uint32 { return uint32(m & 0xffffffff) }
func (m capMask) hi() uint32 { return uint32(m >> 32) }
func (m capMask) has(bit int) bool {
	if bit < 0 || bit > 63 {
		return false
	}
	return m&(1<<uint(bit)) != 0
}
