// Package capabilities is hull's Linux capability table and the policy that
// turns a container's --cap-add/--cap-drop/--privileged request into the five
// capability sets of an OCI runtime spec.
//
// The table itself is portable: the hull CLI is built for windows/amd64 too
// and must be able to validate capability names before it ever talks to the
// daemon. Only BoundingSet, which reads /proc/self/status, is Linux-only.
package capabilities

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ChPuru/hull/internal/oci/runtimespec"
)

// Cap is a Linux capability, represented by its bit index in the capability
// bitmask (the value you would pass to prctl(PR_CAPBSET_DROP)).
type Cap int

// The complete Linux capability set as of kernel 6.x: CAP_CHOWN (0) through
// CAP_CHECKPOINT_RESTORE (40), which is still CAP_LAST_CAP.
const (
	CAP_CHOWN              Cap = 0
	CAP_DAC_OVERRIDE       Cap = 1
	CAP_DAC_READ_SEARCH    Cap = 2
	CAP_FOWNER             Cap = 3
	CAP_FSETID             Cap = 4
	CAP_KILL               Cap = 5
	CAP_SETGID             Cap = 6
	CAP_SETUID             Cap = 7
	CAP_SETPCAP            Cap = 8
	CAP_LINUX_IMMUTABLE    Cap = 9
	CAP_NET_BIND_SERVICE   Cap = 10
	CAP_NET_BROADCAST      Cap = 11
	CAP_NET_ADMIN          Cap = 12
	CAP_NET_RAW            Cap = 13
	CAP_IPC_LOCK           Cap = 14
	CAP_IPC_OWNER          Cap = 15
	CAP_SYS_MODULE         Cap = 16
	CAP_SYS_RAWIO          Cap = 17
	CAP_SYS_CHROOT         Cap = 18
	CAP_SYS_PTRACE         Cap = 19
	CAP_SYS_PACCT          Cap = 20
	CAP_SYS_ADMIN          Cap = 21
	CAP_SYS_BOOT           Cap = 22
	CAP_SYS_NICE           Cap = 23
	CAP_SYS_RESOURCE       Cap = 24
	CAP_SYS_TIME           Cap = 25
	CAP_SYS_TTY_CONFIG     Cap = 26
	CAP_MKNOD              Cap = 27
	CAP_LEASE              Cap = 28
	CAP_AUDIT_WRITE        Cap = 29
	CAP_AUDIT_CONTROL      Cap = 30
	CAP_SETFCAP            Cap = 31
	CAP_MAC_OVERRIDE       Cap = 32
	CAP_MAC_ADMIN          Cap = 33
	CAP_SYSLOG             Cap = 34
	CAP_WAKE_ALARM         Cap = 35
	CAP_BLOCK_SUSPEND      Cap = 36
	CAP_AUDIT_READ         Cap = 37
	CAP_PERFMON            Cap = 38
	CAP_BPF                Cap = 39
	CAP_CHECKPOINT_RESTORE Cap = 40
)

// LastCap is the highest capability bit hull knows about. Bits above this in
// a kernel-reported bounding set are skipped by BoundingSet rather than
// guessed at, so a newer kernel cannot make hull invent capability names.
const LastCap = CAP_CHECKPOINT_RESTORE

// capNames maps every known capability to its canonical CAP_-prefixed name.
// The slice is indexed by bit, so its order is the kernel's order.
var capNames = [...]string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE",
	"CAP_NET_BROADCAST",
	"CAP_NET_ADMIN",
	"CAP_NET_RAW",
	"CAP_IPC_LOCK",
	"CAP_IPC_OWNER",
	"CAP_SYS_MODULE",
	"CAP_SYS_RAWIO",
	"CAP_SYS_CHROOT",
	"CAP_SYS_PTRACE",
	"CAP_SYS_PACCT",
	"CAP_SYS_ADMIN",
	"CAP_SYS_BOOT",
	"CAP_SYS_NICE",
	"CAP_SYS_RESOURCE",
	"CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG",
	"CAP_MKNOD",
	"CAP_LEASE",
	"CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL",
	"CAP_SETFCAP",
	"CAP_MAC_OVERRIDE",
	"CAP_MAC_ADMIN",
	"CAP_SYSLOG",
	"CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND",
	"CAP_AUDIT_READ",
	"CAP_PERFMON",
	"CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

// byName is the reverse of capNames, built once at package init.
var byName = func() map[string]Cap {
	m := make(map[string]Cap, len(capNames))
	for i, n := range capNames {
		m[n] = Cap(i)
	}
	return m
}()

// String returns the canonical CAP_-prefixed name of c, or a
// "CAP_UNKNOWN(<n>)" placeholder for a bit hull does not know.
func (c Cap) String() string {
	if !c.Valid() {
		return fmt.Sprintf("CAP_UNKNOWN(%d)", int(c))
	}
	return capNames[c]
}

// Valid reports whether c is a capability hull knows about.
func (c Cap) Valid() bool { return c >= 0 && int(c) < len(capNames) }

// Parse resolves a capability name to its Cap. It is case-insensitive and the
// CAP_ prefix is optional, so "CAP_NET_ADMIN", "net_admin" and "NET_ADMIN" all
// resolve to CAP_NET_ADMIN. Surrounding whitespace is ignored.
func Parse(name string) (Cap, error) {
	n := normalizeName(name)
	if n == "" {
		return 0, fmt.Errorf("capabilities: empty capability name")
	}
	c, ok := byName[n]
	if !ok {
		return 0, fmt.Errorf("capabilities: unknown capability %q", strings.TrimSpace(name))
	}
	return c, nil
}

// normalizeName upper-cases a capability name and gives it the CAP_ prefix,
// without checking that the result is a real capability.
func normalizeName(name string) string {
	n := strings.ToUpper(strings.TrimSpace(name))
	if n == "" {
		return ""
	}
	if !strings.HasPrefix(n, "CAP_") {
		n = "CAP_" + n
	}
	return n
}

// All returns every capability hull knows about, in kernel bit order.
func All() []Cap {
	out := make([]Cap, len(capNames))
	for i := range capNames {
		out[i] = Cap(i)
	}
	return out
}

// Known returns every capability name, sorted lexicographically. It is the
// list the CLI prints when the user asks what --cap-add accepts.
func Known() []string {
	out := make([]string, len(capNames))
	copy(out, capNames[:])
	sort.Strings(out)
	return out
}

// defaultSet is the Docker/OCI default capability set: the fourteen
// capabilities a container gets when the user asks for nothing special. It is
// deliberately identical to Docker's so images that work under Docker work
// under hull. Notably CAP_NET_RAW is included (ping works) and CAP_SYS_ADMIN
// is not.
var defaultSet = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FSETID",
	"CAP_FOWNER",
	"CAP_MKNOD",
	"CAP_NET_RAW",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETFCAP",
	"CAP_SETPCAP",
	"CAP_NET_BIND_SERVICE",
	"CAP_SYS_CHROOT",
	"CAP_KILL",
	"CAP_AUDIT_WRITE",
}

// Default returns a copy of the default capability set, in the canonical
// order Docker documents it in. Resolve sorts its own output; this does not.
func Default() []string {
	out := make([]string, len(defaultSet))
	copy(out, defaultSet)
	return out
}

// Resolve computes the final capability set for a container.
//
// The semantics match Docker's:
//
//   - privileged ignores add and drop entirely and grants the daemon's full
//     bounding set, because a capability the daemon does not hold cannot be
//     handed to a child. On a platform with no readable bounding set this is
//     an error, never a quiet fallback to "all".
//   - "ALL" is accepted in either list, case-insensitively. "ALL" in add wins
//     over "ALL" in drop, matching Docker's TweakCapabilities.
//   - every other entry must be a real capability name or Resolve fails; hull
//     never silently ignores a misspelled capability.
//
// The returned names are canonical (CAP_-prefixed, upper case) and sorted, so
// the result is stable and diffable in a container's config.json.
func Resolve(add, drop []string, privileged bool) ([]string, error) {
	if privileged {
		bnd, err := BoundingSet()
		if err != nil {
			return nil, fmt.Errorf("capabilities: privileged container needs the daemon bounding set: %w", err)
		}
		names := make([]string, 0, len(bnd))
		for _, c := range bnd {
			names = append(names, c.String())
		}
		sort.Strings(names)
		return names, nil
	}

	addAll, addCaps, err := classify(add, "cap-add")
	if err != nil {
		return nil, err
	}
	dropAll, dropCaps, err := classify(drop, "cap-drop")
	if err != nil {
		return nil, err
	}

	set := make(map[string]bool, len(capNames))
	switch {
	case addAll:
		for _, n := range capNames {
			set[n] = true
		}
	case dropAll:
		// Start from the empty set; explicit adds below build it back up.
	default:
		for _, n := range defaultSet {
			set[n] = true
		}
	}
	for _, c := range dropCaps {
		delete(set, c.String())
	}
	for _, c := range addCaps {
		set[c.String()] = true
	}

	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// classify splits a user-supplied list into the "ALL" marker and the parsed
// capabilities, reporting which flag an unknown name came from.
func classify(list []string, flag string) (all bool, caps []Cap, err error) {
	for _, raw := range list {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.EqualFold(s, "ALL") || strings.EqualFold(s, "CAP_ALL") {
			all = true
			continue
		}
		c, perr := Parse(s)
		if perr != nil {
			return false, nil, fmt.Errorf("--%s: %w", flag, perr)
		}
		caps = append(caps, c)
	}
	return all, caps, nil
}

// ToSpec builds the OCI capability block for a process running as the current
// effective uid. Bundle generation should normally call ToSpecForUID with the
// uid the container process will actually run as; ToSpec is the convenience
// form for a caller that is already running as that user.
func ToSpec(caps []string) runtimespec.LinuxCapabilities {
	return ToSpecForUID(caps, geteuid())
}

// ToSpecForUID builds the OCI capability block for a process that will run as
// uid.
//
// Bounding, Effective and Permitted are all set to caps. Ambient is set only
// when uid != 0: ambient capabilities exist to survive a transition to an
// unprivileged user, and runc raises them only in that case — for a root
// process they are redundant and widen the blast radius. Inheritable is left
// empty on purpose: runc stopped populating it in 1.0.0-rc94 because an
// inheritable set combined with a file carrying the inheritable bit is a
// documented privilege-escalation path. hull does not reintroduce that
// footgun.
func ToSpecForUID(caps []string, uid int) runtimespec.LinuxCapabilities {
	set := make([]string, 0, len(caps))
	seen := make(map[string]bool, len(caps))
	for _, c := range caps {
		n := normalizeName(c)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		set = append(set, n)
	}
	sort.Strings(set)

	lc := runtimespec.LinuxCapabilities{
		Bounding:  set,
		Effective: append([]string(nil), set...),
		Permitted: append([]string(nil), set...),
	}
	if uid != 0 {
		lc.Ambient = append([]string(nil), set...)
	}
	return lc
}
