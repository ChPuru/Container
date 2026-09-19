package bundle

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/rahuldhali/hull/internal/explain"
	"github.com/rahuldhali/hull/internal/oci/runtimespec"
	"github.com/rahuldhali/hull/internal/seccompprof"
)

// ---------- capabilities ----------

// AllCapabilities returns every Linux capability hull knows about, newest last.
// A privileged container gets this whole set; --cap-add ALL resolves to it too.
func AllCapabilities() []string {
	out := make([]string, len(allCaps))
	copy(out, allCaps)
	return out
}

// allCaps is the kernel's capability list through CAP_CHECKPOINT_RESTORE (5.9),
// which is the newest capability any kernel hull targets defines.
var allCaps = []string{
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

var capSet = func() map[string]bool {
	m := make(map[string]bool, len(allCaps))
	for _, c := range allCaps {
		m[c] = true
	}
	return m
}()

// NormalizeCapability upper-cases a capability name and adds the CAP_ prefix,
// so "net_admin", "NET_ADMIN" and "CAP_NET_ADMIN" all mean the same thing, and
// rejects anything the kernel does not define.
func NormalizeCapability(name string) (string, error) {
	n := strings.ToUpper(strings.TrimSpace(name))
	if n == "" {
		return "", errors.New("bundle: empty capability name")
	}
	if n == "ALL" {
		return "ALL", nil
	}
	if !strings.HasPrefix(n, "CAP_") {
		n = "CAP_" + n
	}
	if !capSet[n] {
		return "", fmt.Errorf("bundle: unknown capability %q", name)
	}
	return n, nil
}

// ResolveCapabilities computes the final capability set: the base set (the OCI
// default, or everything for a privileged container) with --cap-drop removed
// and --cap-add restored, in that order, which is Docker's precedence. "ALL" is
// accepted in either list.
//
// The result is ordered the way AllCapabilities orders it, so two equivalent
// requests always produce byte-identical config.json output.
func ResolveCapabilities(base, add, drop []string, privileged bool) ([]string, error) {
	set := make(map[string]bool)
	if privileged {
		for _, c := range allCaps {
			set[c] = true
		}
	} else {
		for _, c := range base {
			n, err := NormalizeCapability(c)
			if err != nil {
				return nil, err
			}
			set[n] = true
		}
	}

	for _, c := range drop {
		n, err := NormalizeCapability(c)
		if err != nil {
			return nil, err
		}
		if n == "ALL" {
			set = make(map[string]bool)
			continue
		}
		delete(set, n)
	}
	for _, c := range add {
		n, err := NormalizeCapability(c)
		if err != nil {
			return nil, err
		}
		if n == "ALL" {
			for _, c := range allCaps {
				set[c] = true
			}
			continue
		}
		set[n] = true
	}

	out := make([]string, 0, len(set))
	for _, c := range allCaps {
		if set[c] {
			out = append(out, c)
		}
	}
	return out, nil
}

func (b *builder) resolveCapabilities() ([]string, error) {
	return ResolveCapabilities(
		runtimespec.DefaultCapabilities(),
		b.c.HostConfig.CapAdd,
		b.c.HostConfig.CapDrop,
		b.privileged,
	)
}

// capsToSpec fills the five capability sets. Inheritable and ambient stay empty
// on purpose: an ambient capability survives execve into a non-privileged
// binary, which is exactly the escalation no_new_privs exists to prevent.
func capsToSpec(caps []string) *runtimespec.LinuxCapabilities {
	cp := func() []string { return append([]string(nil), caps...) }
	return &runtimespec.LinuxCapabilities{
		Bounding:  cp(),
		Effective: cp(),
		Permitted: cp(),
	}
}

// ---------- masked and read-only paths ----------

// MaskedPaths is the OCI default list of /proc and /sys entries that are
// covered with /dev/null (files) or an empty read-only tmpfs (directories), so
// a container cannot read host state or wedge the kernel.
func MaskedPaths() []string {
	return []string{
		"/proc/acpi",
		"/proc/asound",
		"/proc/kcore",
		"/proc/keys",
		"/proc/latency_stats",
		"/proc/timer_list",
		"/proc/timer_stats",
		"/proc/sched_debug",
		"/proc/scsi",
		"/sys/firmware",
		"/sys/devices/virtual/powercap",
	}
}

// ReadonlyPaths is the OCI default list of /proc entries remounted read-only
// inside the container.
func ReadonlyPaths() []string {
	return []string{
		"/proc/bus",
		"/proc/fs",
		"/proc/irq",
		"/proc/sys",
		"/proc/sysrq-trigger",
	}
}

// ---------- security options ----------

// securityOptions is the parsed form of HostConfig.SecurityOpt.
type securityOptions struct {
	noNewPrivileges  bool
	seccompUnconfine bool
	seccompProfile   string
	apparmor         string
	ignored          []string
}

// parseSecurityOpt understands the --security-opt forms Docker accepts, with
// either "=" or ":" as the separator:
//
//	no-new-privileges[=true|false]
//	seccomp=unconfined | seccomp=<path or json>
//	apparmor=<profile>        (recorded; WSL has no AppArmor)
//	label=<opt>               (recorded; WSL has no SELinux)
//
// Anything else is an error rather than a silent no-op, because a misspelled
// security option that does nothing is worse than one that fails.
func parseSecurityOpt(opts []string) (securityOptions, error) {
	out := securityOptions{noNewPrivileges: true}
	for _, raw := range opts {
		opt := strings.TrimSpace(raw)
		if opt == "" {
			continue
		}
		key, val := opt, ""
		if i := strings.IndexAny(opt, "=:"); i >= 0 {
			key, val = opt[:i], opt[i+1:]
		}
		switch strings.ToLower(key) {
		case "no-new-privileges":
			switch strings.ToLower(val) {
			case "", "true", "1":
				out.noNewPrivileges = true
			case "false", "0":
				out.noNewPrivileges = false
			default:
				return out, fmt.Errorf("bundle: --security-opt %q: expected true or false", raw)
			}
		case "seccomp":
			if val == "" {
				return out, fmt.Errorf("bundle: --security-opt %q: seccomp needs a value (unconfined or a profile)", raw)
			}
			if strings.EqualFold(val, "unconfined") {
				out.seccompUnconfine = true
			} else {
				out.seccompProfile = val
			}
		case "apparmor":
			out.apparmor = val
			if !strings.EqualFold(val, "unconfined") {
				out.ignored = append(out.ignored, raw)
			}
		case "label":
			out.ignored = append(out.ignored, raw)
		default:
			return out, fmt.Errorf("bundle: --security-opt %q is not supported; hull understands no-new-privileges, seccomp, apparmor and label", raw)
		}
	}
	return out, nil
}

// buildSeccomp picks the seccomp filter for the container.
//
// A privileged container gets none, by definition. An explicit
// "--security-opt seccomp=unconfined" gets none. A kernel without
// CONFIG_SECCOMP_FILTER gets none plus a warning, because the alternative is
// refusing to run any container at all on that kernel.
//
// no_new_privs is set on the process independently and before the filter is
// installed by the runtime; a filter without it is not a hardening measure.
func (b *builder) buildSeccomp(caps []string, sec securityOptions) (*runtimespec.LinuxSeccomp, error) {
	if b.privileged {
		return nil, nil
	}
	if sec.seccompUnconfine {
		b.warnf("seccomp is disabled for this container (--security-opt seccomp=unconfined); the whole syscall surface of the kernel is reachable from inside it")
		return nil, nil
	}
	if sec.seccompProfile != "" {
		return nil, fmt.Errorf("bundle: --security-opt seccomp=%s: custom seccomp profiles are not implemented yet; use seccomp=unconfined or the default profile", sec.seccompProfile)
	}
	if !b.opts.Features.Seccomp {
		b.warnf("this kernel reports no seccomp filter support, so the container runs with no syscall filter")
		return nil, nil
	}
	if !sec.noNewPrivileges {
		// Loading a filter without no_new_privs requires CAP_SYS_ADMIN and
		// lets a setuid binary inside the container escape the filter.
		return nil, errors.New("bundle: --security-opt no-new-privileges=false cannot be combined with a seccomp profile; add --security-opt seccomp=unconfined if that is really what you want")
	}
	fn := b.opts.SeccompProfile
	if fn == nil {
		fn = seccompprof.ForCapabilities
	}
	prof := fn(caps, b.privileged)
	if prof == nil {
		return nil, errors.New("bundle: the seccomp profile provider returned no filter for an unprivileged container; refusing to start it unconfined")
	}
	explain.OrNop(b.opts.Tracer).Step(explain.KindSeccomp, "loaded %d-rule filter, default %s, after no_new_privs=1", len(prof.Syscalls), prof.DefaultAction)
	return prof, nil
}

// ---------- sysctls ----------

// namespacedSysctlPrefixes are the sysctl trees that are per-namespace and can
// therefore be set for one container without affecting the host or its
// neighbours.
var namespacedSysctlPrefixes = []string{
	"net.",
	"fs.mqueue.",
}

// namespacedSysctls are the individually namespaced keys outside those trees.
var namespacedSysctls = map[string]bool{
	"kernel.shmmax":          true,
	"kernel.shmall":          true,
	"kernel.shmmni":          true,
	"kernel.shm_rmid_forced": true,
	"kernel.msgmax":          true,
	"kernel.msgmnb":          true,
	"kernel.msgmni":          true,
	"kernel.sem":             true,
	"kernel.domainname":      true,
	"kernel.hostname":        true,
}

// IsNamespacedSysctl reports whether key may be set per container. Anything
// else is a host-wide knob: writing it from a container would change the
// kernel for every other container and for Windows.
func IsNamespacedSysctl(key string) bool {
	if namespacedSysctls[key] {
		return true
	}
	for _, p := range namespacedSysctlPrefixes {
		if strings.HasPrefix(key, p) && len(key) > len(p) {
			return true
		}
	}
	return false
}

// buildSysctls validates and copies HostConfig.Sysctls. Non-namespaced keys are
// rejected outright, and a net.* sysctl is rejected when the container does not
// own its network namespace, because writing it would leak into the host.
func (b *builder) buildSysctls() (map[string]string, error) {
	if len(b.c.HostConfig.Sysctls) == 0 {
		return nil, nil
	}
	mode := b.c.HostConfig.NetworkMode
	sharesNetns := mode == "host" || strings.HasPrefix(mode, "container:")

	keys := make([]string, 0, len(b.c.HostConfig.Sysctls))
	for k := range b.c.HostConfig.Sysctls {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]string, len(keys))
	for _, k := range keys {
		if !IsNamespacedSysctl(k) {
			return nil, fmt.Errorf("bundle: sysctl %q is not namespaced and cannot be set for a single container; "+
				"hull allows net.*, fs.mqueue.*, kernel.{shmmax,shmall,shmmni,shm_rmid_forced,msgmax,msgmnb,msgmni,sem,domainname,hostname}", k)
		}
		if strings.HasPrefix(k, "net.") && sharesNetns {
			return nil, fmt.Errorf("bundle: sysctl %q cannot be set with network mode %q: the container shares another network namespace, so the change would affect the host", k, mode)
		}
		out[k] = b.c.HostConfig.Sysctls[k]
	}
	return out, nil
}
