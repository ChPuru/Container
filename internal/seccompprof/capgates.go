package seccompprof

import (
	"sort"
	"strings"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

// capGate is one capability-conditioned addition to the default profile: the
// syscalls it unlocks, plus an optional second capability that must also be
// held (bpf needs both CAP_NET_ADMIN and CAP_BPF).
type capGate struct {
	cap       string
	alsoNeeds string
	names     []string
	why       string
}

// capGates is the full set of capability-gated additions, in a fixed order so
// the generated profile is byte-stable and diffable in a bundle's config.json.
//
// The principle: a syscall appears here when the kernel itself gates it on a
// capability. Blocking it in seccomp as well is defence in depth for the case
// where the capability check can be satisfied inside a nested user namespace,
// and it keeps the attack surface of a default container small. Granting the
// capability without the syscall would just produce confusing EPERMs.
var capGates = []capGate{
	{
		cap: "CAP_SYS_ADMIN",
		names: []string{
			// Classic and new-API mount plumbing.
			"mount",
			"umount",
			"umount2",
			"mount_setattr",
			"open_tree",
			"move_mount",
			"fsopen",
			"fsconfig",
			"fsmount",
			"fspick",
			"pivot_root",
			// Namespace manipulation.
			"setns",
			"unshare",
			// UTS namespace edits, which are what sethostname is for.
			"sethostname",
			"setdomainname",
			// Misc CAP_SYS_ADMIN-gated interfaces real workloads use.
			"quotactl",
			"lookup_dcookie",
			"fanotify_init",
			"open_by_handle_at",
			"perf_event_open",
			"bpf",
		},
		why: "container asked for CAP_SYS_ADMIN, which is the capability these syscalls are gated on",
	},
	{
		cap:   "CAP_SYS_MODULE",
		names: []string{"init_module", "finit_module", "delete_module"},
		why:   "loading kernel modules",
	},
	{
		cap:   "CAP_SYS_TIME",
		names: []string{"clock_settime", "clock_settime64", "settimeofday", "stime", "adjtimex"},
		why:   "setting the system clock",
	},
	{
		cap:   "CAP_SYS_PTRACE",
		names: []string{"process_vm_readv", "process_vm_writev", "kcmp"},
		why:   "cross-process memory access; ptrace itself is already allowed",
	},
	{
		cap:   "CAP_SYS_BOOT",
		names: []string{"reboot"},
		why:   "rebooting, which in a pid namespace means signalling init",
	},
	{
		cap:   "CAP_SYS_CHROOT",
		names: []string{"chroot"},
		why:   "chroot(2)",
	},
	{
		cap:   "CAP_SYS_RAWIO",
		names: []string{"iopl", "ioperm"},
		why:   "direct port I/O",
	},
	{
		cap:   "CAP_SYSLOG",
		names: []string{"syslog"},
		why:   "reading the kernel ring buffer",
	},
	{
		cap:       "CAP_NET_ADMIN",
		alsoNeeds: "CAP_BPF",
		names:     []string{"bpf"},
		why:       "loading BPF programs needs CAP_BPF as well as CAP_NET_ADMIN on kernels >= 5.8",
	},
	{
		cap:   "CAP_SYS_PACCT",
		names: []string{"acct"},
		why:   "BSD process accounting",
	},
	{
		cap:   "CAP_SYS_NICE",
		names: []string{"get_mempolicy", "set_mempolicy", "mbind", "migrate_pages", "move_pages"},
		why:   "NUMA placement",
	},
	{
		cap: "CAP_WAKE_ALARM",
		names: []string{
			"clock_nanosleep",
			"clock_nanosleep_time64",
			"timer_create",
		},
		// These are already on the unconditional allowlist because ordinary
		// sleeping and POSIX timers need them. The rule is restated here so
		// the profile documents the link; CLOCK_REALTIME_ALARM and
		// CLOCK_BOOTTIME_ALARM are enforced by the kernel's own
		// CAP_WAKE_ALARM check, which seccomp cannot usefully duplicate
		// (the clockid is an argument seccomp can read, but denying it would
		// break the far more common non-alarm clocks).
		why: "alarm-class clockids; the kernel enforces the capability itself",
	},
}

// ForCapabilities returns the seccomp profile for a container holding caps.
//
// A privileged container gets nil: no filter at all, matching Docker. That is
// not a hull opinion, it is what --privileged means, and pretending otherwise
// by installing a permissive filter would only be theatre.
//
// Otherwise the result is Default() plus one allow rule per capability gate
// the container qualifies for, and the clone and socket restrictions are
// relaxed when the container holds CAP_SYS_ADMIN — a container that can call
// unshare(CLONE_NEWUSER) gains nothing from a masked clone rule, so keeping
// it would cost compatibility for no security.
//
// Capability names are matched case-insensitively and the CAP_ prefix is
// optional, so the same spellings the CLI accepts work here.
func ForCapabilities(caps []string, privileged bool) *runtimespec.LinuxSeccomp {
	if privileged {
		return nil
	}

	held := make(map[string]bool, len(caps))
	for _, c := range caps {
		n := strings.ToUpper(strings.TrimSpace(c))
		if n == "" {
			continue
		}
		if !strings.HasPrefix(n, "CAP_") {
			n = "CAP_" + n
		}
		held[n] = true
	}

	p := Default()

	if held["CAP_SYS_ADMIN"] {
		// Replace the masked clone rule and the AF_VSOCK-excluding socket
		// rule with unconditional allows.
		kept := p.Syscalls[:0]
		for _, s := range p.Syscalls {
			if len(s.Names) == 1 && (s.Names[0] == "clone" || s.Names[0] == "socket") && len(s.Args) > 0 {
				continue
			}
			kept = append(kept, s)
		}
		p.Syscalls = kept
		p.Syscalls = append(p.Syscalls, runtimespec.LinuxSyscall{
			Names:  []string{"clone", "socket"},
			Action: runtimespec.ActAllow,
		})
	}

	for _, g := range capGates {
		if !held[g.cap] {
			continue
		}
		if g.alsoNeeds != "" && !held[g.alsoNeeds] {
			continue
		}
		names := append([]string(nil), g.names...)
		sort.Strings(names)
		p.Syscalls = append(p.Syscalls, runtimespec.LinuxSyscall{
			Names:  names,
			Action: runtimespec.ActAllow,
		})
	}

	return p
}

// GatedSyscalls reports which syscalls a given capability unlocks, for
// `hull doctor` and for the --explain trace mode. It returns nil for a
// capability that unlocks nothing.
func GatedSyscalls(capName string) []string {
	n := strings.ToUpper(strings.TrimSpace(capName))
	if !strings.HasPrefix(n, "CAP_") {
		n = "CAP_" + n
	}
	var out []string
	for _, g := range capGates {
		if g.cap == n {
			out = append(out, g.names...)
		}
	}
	if out == nil {
		return nil
	}
	sort.Strings(out)
	return out
}
