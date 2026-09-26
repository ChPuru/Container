package seccompprof

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/ChPuru/hull/internal/capabilities"
	"github.com/ChPuru/hull/internal/oci/runtimespec"
)

// dockerProfile is the on-disk JSON shape Docker uses for seccomp profiles.
// hull parses it verbatim so that the profiles people already have — from
// Docker, from containerd, from a hardening guide — load unchanged.
//
// It is deliberately a separate type from runtimespec.LinuxSeccomp: the
// Docker format carries conditions ("includes"/"excludes") that are resolved
// at load time against the host architecture, the kernel version and the
// container's capability set, and must not survive into the runtime spec.
type dockerProfile struct {
	DefaultAction    string               `json:"defaultAction"`
	DefaultErrnoRet  *uint                `json:"defaultErrnoRet,omitempty"`
	Architectures    []string             `json:"architectures,omitempty"`
	ArchMap          []dockerArchMap      `json:"archMap,omitempty"`
	Flags            []string             `json:"flags,omitempty"`
	ListenerPath     string               `json:"listenerPath,omitempty"`
	ListenerMetadata string               `json:"listenerMetadata,omitempty"`
	Syscalls         []dockerSyscallEntry `json:"syscalls"`
}

// dockerArchMap expands one native architecture into the sub-architectures a
// process on it can issue syscalls through.
type dockerArchMap struct {
	Arch      string   `json:"architecture"`
	SubArches []string `json:"subArchitectures,omitempty"`
}

// dockerSyscallEntry is one rule of a Docker profile. Both the singular
// "name" and the plural "names" spellings are accepted, as Docker does.
type dockerSyscallEntry struct {
	Name     string        `json:"name,omitempty"`
	Names    []string      `json:"names,omitempty"`
	Action   string        `json:"action"`
	ErrnoRet *uint         `json:"errnoRet,omitempty"`
	Args     []dockerArg   `json:"args,omitempty"`
	Comment  string        `json:"comment,omitempty"`
	Includes *dockerFilter `json:"includes,omitempty"`
	Excludes *dockerFilter `json:"excludes,omitempty"`
}

// dockerArg is one argument predicate.
type dockerArg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo,omitempty"`
	Op       string `json:"op"`
}

// dockerFilter is the condition attached to a rule. An "includes" filter
// keeps the rule only when every populated field matches; an "excludes"
// filter drops the rule when any populated field matches. That asymmetry is
// Docker's, and profiles in the wild depend on it.
type dockerFilter struct {
	Caps      []string `json:"caps,omitempty"`
	Arches    []string `json:"arches,omitempty"`
	MinKernel string   `json:"minKernel,omitempty"`
}

// validActions is the set of seccomp actions a loaded profile may name.
var validActions = map[string]runtimespec.LinuxSeccompAction{
	"SCMP_ACT_KILL":         runtimespec.ActKill,
	"SCMP_ACT_KILL_PROCESS": runtimespec.ActKillProcess,
	"SCMP_ACT_KILL_THREAD":  runtimespec.ActKillThread,
	"SCMP_ACT_TRAP":         runtimespec.ActTrap,
	"SCMP_ACT_ERRNO":        runtimespec.ActErrno,
	"SCMP_ACT_TRACE":        runtimespec.ActTrace,
	"SCMP_ACT_ALLOW":        runtimespec.ActAllow,
	"SCMP_ACT_LOG":          runtimespec.ActLog,
	"SCMP_ACT_NOTIFY":       runtimespec.ActNotify,
}

// validOps is the set of argument comparison operators a loaded profile may
// name.
var validOps = map[string]runtimespec.LinuxSeccompOperator{
	"SCMP_CMP_NE":        runtimespec.OpNotEqual,
	"SCMP_CMP_LT":        runtimespec.OpLessThan,
	"SCMP_CMP_LE":        runtimespec.OpLessEqual,
	"SCMP_CMP_EQ":        runtimespec.OpEqualTo,
	"SCMP_CMP_GE":        runtimespec.OpGreaterEqual,
	"SCMP_CMP_GT":        runtimespec.OpGreaterThan,
	"SCMP_CMP_MASKED_EQ": runtimespec.OpMaskedEqual,
}

// validFlags is the set of seccomp(2) filter flags a loaded profile may name.
var validFlags = map[string]runtimespec.LinuxSeccompFlag{
	"SECCOMP_FILTER_FLAG_LOG":                runtimespec.FlagLog,
	"SECCOMP_FILTER_FLAG_SPEC_ALLOW":         runtimespec.FlagSpecAllow,
	"SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV": runtimespec.FlagWaitKillableRecv,
}

// Load reads a user-supplied seccomp profile in Docker's JSON format from
// path and translates it into a runtime spec, resolving its "includes" and
// "excludes" conditions against this host and the default capability set.
//
// Use LoadProfile when the container's capability set is known — the
// condition evaluation depends on it, and a profile whose CAP_SYS_ADMIN rules
// were resolved against the wrong set is silently wrong.
func Load(path string) (*runtimespec.LinuxSeccomp, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seccompprof: read profile %s: %w", path, err)
	}
	p, err := LoadProfile(data, capabilities.Default())
	if err != nil {
		return nil, fmt.Errorf("seccompprof: %s: %w", path, err)
	}
	return p, nil
}

// LoadProfile parses a Docker-format seccomp profile from data and resolves
// its conditions against the host architecture, the running kernel version
// and caps, the capability set the container will hold.
//
// On a platform where hull cannot read the kernel version (anything but
// Linux) a rule carrying a minKernel condition is kept, and the caller is
// expected to be validating rather than about to install the filter.
func LoadProfile(data []byte, caps []string) (*runtimespec.LinuxSeccomp, error) {
	var dp dockerProfile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&dp); err != nil {
		// Retry permissively: profiles in the wild carry extra keys, and
		// refusing them outright is worse than ignoring them. The strict
		// pass exists only to catch our own typos during development.
		if err2 := json.Unmarshal(data, &dp); err2 != nil {
			return nil, fmt.Errorf("parse seccomp profile: %w", err2)
		}
	}

	action, ok := validActions[strings.ToUpper(strings.TrimSpace(dp.DefaultAction))]
	if !ok {
		return nil, fmt.Errorf("unknown defaultAction %q", dp.DefaultAction)
	}

	out := &runtimespec.LinuxSeccomp{
		DefaultAction:    action,
		ListenerPath:     dp.ListenerPath,
		ListenerMetadata: dp.ListenerMetadata,
	}
	if dp.DefaultErrnoRet != nil {
		v := *dp.DefaultErrnoRet
		out.DefaultErrnoRet = &v
	}

	for _, f := range dp.Flags {
		flag, ok := validFlags[strings.ToUpper(strings.TrimSpace(f))]
		if !ok {
			return nil, fmt.Errorf("unknown seccomp flag %q", f)
		}
		out.Flags = append(out.Flags, flag)
	}

	arches, err := resolveArchitectures(&dp)
	if err != nil {
		return nil, err
	}
	out.Architectures = arches

	held := capabilitySet(caps)
	hostArches := hostArchTokens()
	kmaj, kmin, haveKernel := kernelVersion()

	for i, e := range dp.Syscalls {
		names := e.Names
		if e.Name != "" {
			names = append([]string{e.Name}, names...)
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("syscalls[%d]: neither name nor names is set", i)
		}

		keep, err := matchFilter(e.Includes, e.Excludes, held, hostArches, kmaj, kmin, haveKernel)
		if err != nil {
			return nil, fmt.Errorf("syscalls[%d]: %w", i, err)
		}
		if !keep {
			continue
		}

		act, ok := validActions[strings.ToUpper(strings.TrimSpace(e.Action))]
		if !ok {
			return nil, fmt.Errorf("syscalls[%d]: unknown action %q", i, e.Action)
		}
		rule := runtimespec.LinuxSyscall{
			Names:  append([]string(nil), names...),
			Action: act,
		}
		if e.ErrnoRet != nil {
			v := *e.ErrnoRet
			rule.ErrnoRet = &v
		}
		for j, a := range e.Args {
			op, ok := validOps[strings.ToUpper(strings.TrimSpace(a.Op))]
			if !ok {
				return nil, fmt.Errorf("syscalls[%d].args[%d]: unknown op %q", i, j, a.Op)
			}
			if a.Index > 5 {
				return nil, fmt.Errorf("syscalls[%d].args[%d]: index %d out of range, seccomp sees only args 0-5", i, j, a.Index)
			}
			rule.Args = append(rule.Args, runtimespec.LinuxSeccompArg{
				Index:    a.Index,
				Value:    a.Value,
				ValueTwo: a.ValueTwo,
				Op:       op,
			})
		}
		out.Syscalls = append(out.Syscalls, rule)
	}

	return out, nil
}

// resolveArchitectures turns the profile's "architectures" and "archMap"
// blocks into the architecture list for this host.
func resolveArchitectures(dp *dockerProfile) ([]runtimespec.Arch, error) {
	var out []runtimespec.Arch
	for _, a := range dp.Architectures {
		arch, err := parseArch(a)
		if err != nil {
			return nil, err
		}
		out = append(out, arch)
	}
	if len(out) > 0 {
		return out, nil
	}

	native := hostArchTokens()
	for _, m := range dp.ArchMap {
		if !native[strings.ToLower(strings.TrimPrefix(strings.ToUpper(m.Arch), "SCMP_ARCH_"))] {
			continue
		}
		arch, err := parseArch(m.Arch)
		if err != nil {
			return nil, err
		}
		out = append(out, arch)
		for _, s := range m.SubArches {
			sub, err := parseArch(s)
			if err != nil {
				return nil, err
			}
			out = append(out, sub)
		}
	}
	if len(out) == 0 {
		// A profile that names no architecture applies to the native one
		// only, which is what an empty list means in the runtime spec.
		return nil, nil
	}
	return out, nil
}

// parseArch accepts both the SCMP_ARCH_* spelling and the bare one.
func parseArch(s string) (runtimespec.Arch, error) {
	n := strings.ToUpper(strings.TrimSpace(s))
	if n == "" {
		return "", fmt.Errorf("empty architecture")
	}
	if !strings.HasPrefix(n, "SCMP_ARCH_") {
		n = "SCMP_ARCH_" + n
	}
	switch runtimespec.Arch(n) {
	case runtimespec.ArchX86, runtimespec.ArchX86_64, runtimespec.ArchX32,
		runtimespec.ArchARM, runtimespec.ArchAARCH64,
		runtimespec.ArchMIPS, runtimespec.ArchMIPS64, runtimespec.ArchMIPS64N32,
		runtimespec.ArchMIPSEL, runtimespec.ArchMIPSEL64, runtimespec.ArchMIPSEL64N32,
		runtimespec.ArchPPC, runtimespec.ArchPPC64, runtimespec.ArchPPC64LE,
		runtimespec.ArchS390, runtimespec.ArchS390X, runtimespec.ArchRISCV64:
		return runtimespec.Arch(n), nil
	}
	return "", fmt.Errorf("unknown architecture %q", s)
}

// matchFilter applies the includes/excludes pair of one rule.
func matchFilter(inc, exc *dockerFilter, held map[string]bool, hostArches map[string]bool, kmaj, kmin int, haveKernel bool) (bool, error) {
	if inc != nil {
		if len(inc.Arches) > 0 && !anyArch(inc.Arches, hostArches) {
			return false, nil
		}
		if len(inc.Caps) > 0 && !allCaps(inc.Caps, held) {
			return false, nil
		}
		if inc.MinKernel != "" {
			maj, min, err := parseKernelVersion(inc.MinKernel)
			if err != nil {
				return false, err
			}
			if haveKernel && (kmaj < maj || (kmaj == maj && kmin < min)) {
				return false, nil
			}
		}
	}
	if exc != nil {
		if len(exc.Arches) > 0 && anyArch(exc.Arches, hostArches) {
			return false, nil
		}
		if len(exc.Caps) > 0 && anyCap(exc.Caps, held) {
			return false, nil
		}
		if exc.MinKernel != "" {
			maj, min, err := parseKernelVersion(exc.MinKernel)
			if err != nil {
				return false, err
			}
			if haveKernel && !(kmaj < maj || (kmaj == maj && kmin < min)) {
				return false, nil
			}
		}
	}
	return true, nil
}

// anyArch reports whether any listed architecture token matches this host.
func anyArch(list []string, host map[string]bool) bool {
	for _, a := range list {
		if host[normalizeArchToken(a)] {
			return true
		}
	}
	return false
}

// allCaps reports whether every listed capability is held. Docker's
// "includes.caps" is an AND.
func allCaps(list []string, held map[string]bool) bool {
	for _, c := range list {
		if !held[normalizeCap(c)] {
			return false
		}
	}
	return true
}

// anyCap reports whether any listed capability is held. Docker's
// "excludes.caps" is an OR.
func anyCap(list []string, held map[string]bool) bool {
	for _, c := range list {
		if held[normalizeCap(c)] {
			return true
		}
	}
	return false
}

// capabilitySet normalizes a capability list into a lookup set.
func capabilitySet(caps []string) map[string]bool {
	m := make(map[string]bool, len(caps))
	for _, c := range caps {
		n := normalizeCap(c)
		if n != "" {
			m[n] = true
		}
	}
	return m
}

// normalizeCap upper-cases and CAP_-prefixes a capability name.
func normalizeCap(c string) string {
	n := strings.ToUpper(strings.TrimSpace(c))
	if n == "" {
		return ""
	}
	if !strings.HasPrefix(n, "CAP_") {
		n = "CAP_" + n
	}
	return n
}

// normalizeArchToken reduces "SCMP_ARCH_X86_64", "X86_64" and "amd64" to a
// single lower-case token so profiles written either way compare equal.
func normalizeArchToken(s string) string {
	n := strings.ToUpper(strings.TrimSpace(s))
	n = strings.TrimPrefix(n, "SCMP_ARCH_")
	return strings.ToLower(n)
}

// hostArchTokens is the set of architecture tokens that describe this host,
// covering both the Go spelling and the seccomp spelling, plus the
// sub-architectures a process here can issue syscalls through.
func hostArchTokens() map[string]bool {
	m := map[string]bool{}
	add := func(names ...string) {
		for _, n := range names {
			m[strings.ToLower(n)] = true
		}
	}
	switch runtime.GOARCH {
	case "amd64":
		add("amd64", "x86_64", "x86", "x32", "386", "i386")
	case "386":
		add("386", "i386", "x86")
	case "arm64":
		add("arm64", "aarch64", "arm")
	case "arm":
		add("arm")
	case "ppc64le":
		add("ppc64le")
	case "s390x":
		add("s390x", "s390")
	case "riscv64":
		add("riscv64")
	case "mips64le":
		add("mips64le", "mipsel64", "mipsel64n32", "mipsel")
	default:
		add(runtime.GOARCH)
	}
	return m
}

// parseKernelVersion parses a "major.minor" string as Docker writes it in a
// minKernel condition. A trailing patch level is ignored.
func parseKernelVersion(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("malformed minKernel %q, want major.minor", s)
	}
	maj, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("malformed minKernel %q: %w", s, err)
	}
	minorField := strings.TrimSpace(parts[1])
	for i, r := range minorField {
		if r < '0' || r > '9' {
			minorField = minorField[:i]
			break
		}
	}
	min, err := strconv.Atoi(minorField)
	if err != nil {
		return 0, 0, fmt.Errorf("malformed minKernel %q: %w", s, err)
	}
	return maj, min, nil
}
