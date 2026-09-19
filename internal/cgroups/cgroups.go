// Package cgroups is hull's cgroup v2 driver.
//
// It creates one cgroup per container under a hull-owned subtree of the
// unified hierarchy, applies types.Resources to the v2 knobs, reads stats
// back, and implements freeze/kill/delete.
//
// hull only ever writes cgroup v2. The WSL kernels hull targets are not all
// alike: WSL 2.4.13 (kernel 5.15) boots a *hybrid* hierarchy where cgroup v1
// owns every controller and the cgroup2 mount at /sys/fs/cgroup/unified lists
// no controllers at all. Nothing can be limited in that configuration, so
// Detect reports it and New refuses with HybridRemedy rather than pretending
// the limits were applied. Everything else is feature-probed: a missing knob
// produces a descriptive error, never a silent no-op.
//
// All types and the pure unit-conversion helpers in this file build on every
// GOOS so cross-platform callers (the CLI) can reference them; the Manager
// implementation is Linux-only.
package cgroups

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrUnsupported is returned by every operation in this package when it is
// built for a GOOS other than linux, or when the running kernel exposes no
// usable cgroup v2 hierarchy.
var ErrUnsupported = errors.New("cgroups: cgroup v2 is not available on this platform")

// Mode describes which cgroup hierarchies the running kernel has mounted.
type Mode int

const (
	// ModeUnavailable means neither a cgroup v1 nor a cgroup v2 hierarchy is mounted.
	ModeUnavailable Mode = iota
	// ModeLegacy means only cgroup v1 hierarchies are mounted. hull cannot use them.
	ModeLegacy
	// ModeHybrid means a cgroup2 mount exists alongside cgroup v1 hierarchies.
	// The v1 side usually owns every controller, leaving cgroup.controllers empty.
	ModeHybrid
	// ModeUnified means cgroup v2 is mounted on /sys/fs/cgroup and owns the controllers.
	ModeUnified
)

// String returns the lowercase name of the mode.
func (m Mode) String() string {
	switch m {
	case ModeLegacy:
		return "legacy"
	case ModeHybrid:
		return "hybrid"
	case ModeUnified:
		return "unified"
	default:
		return "unavailable"
	}
}

// HybridRemedy is the exact, actionable message hull shows when the host has
// no usable cgroup v2 controllers. Detect attaches it to Info.Warnings and New
// wraps it into the error it returns.
const HybridRemedy = "cgroup v2 controllers are not available. " +
	"Run 'wsl --update' (WSL 2.5.1+ removes cgroup v1), " +
	"or add 'kernelCommandLine = cgroup_no_v1=all' under [wsl2] in %USERPROFILE%\\.wslconfig and " +
	"run 'wsl --shutdown'."

// DefaultCPUPeriod is the cpu.max period, in microseconds, that hull uses when
// the caller does not ask for one. It matches Docker's default.
const DefaultCPUPeriod int64 = 100000

// Info is the result of probing the host's cgroup configuration.
type Info struct {
	// Mode is which hierarchies are mounted.
	Mode Mode
	// Root is the absolute mount point of the cgroup2 filesystem, or "" if none.
	Root string
	// Controllers is the content of <Root>/cgroup.controllers.
	Controllers []string
	// Delegated reports whether <Root>/cgroup.subtree_control is non-empty,
	// i.e. whether the root already delegates any controller downwards.
	Delegated bool
	// HasFreezer reports whether cgroup.freeze exists (kernel >= 5.2).
	HasFreezer bool
	// HasKill reports whether cgroup.kill exists (kernel >= 5.14).
	HasKill bool
	// HasPSI reports whether <Root>/cpu.pressure exists (CONFIG_PSI, which is
	// unset on the WSL 5.15 kernel).
	HasPSI bool
	// HasCloneInto reports whether the kernel is >= 5.7 and clone3 works, so a
	// child can be spawned directly into a cgroup with CLONE_INTO_CGROUP.
	HasCloneInto bool
	// Warnings holds human-readable problems found while probing. A non-empty
	// Warnings does not necessarily mean cgroups are unusable, but an empty
	// Controllers list always does.
	Warnings []string
	// KernelVersion is the uname release string, e.g.
	// "5.15.167.4-microsoft-standard-WSL2".
	KernelVersion string
}

// HasController reports whether the named v2 controller is listed in
// <Root>/cgroup.controllers.
func (i Info) HasController(name string) bool {
	for _, c := range i.Controllers {
		if c == name {
			return true
		}
	}
	return false
}

// Usable reports whether hull can create and limit cgroups on this host.
func (i Info) Usable() bool {
	return i.Root != "" && len(i.Controllers) > 0 &&
		(i.Mode == ModeUnified || i.Mode == ModeHybrid)
}

// Stat is a point-in-time sample of one cgroup's counters. Values the kernel
// does not expose are left zero; MemoryLimit and PidsLimit are zero when the
// corresponding knob reads "max" (unlimited).
type Stat struct {
	CPUUsageUsec  uint64
	CPUUserUsec   uint64
	CPUSystemUsec uint64

	MemoryCurrent uint64
	MemoryPeak    uint64
	MemoryLimit   uint64
	MemoryAnon    uint64
	MemoryFile    uint64

	PidsCurrent uint64
	PidsLimit   uint64

	IORead  uint64
	IOWrite uint64

	OOMKills uint64

	CPUPressureSome10 float64
	MemPressureSome10 float64
	IOPressureSome10  float64
}

// hullControllers are the v2 controllers hull enables in cgroup.subtree_control
// on every ancestor of a container cgroup: "+cpu +memory +pids +io".
var hullControllers = []string{"cpu", "memory", "pids", "io"}

// optionalControllers are enabled additionally when the kernel lists them, so
// Apply can honour CpusetCpus/CpusetMems. Their absence is not an error.
var optionalControllers = []string{"cpuset"}

// CPUSharesToWeight converts a Docker/OCI CPU shares value (the v1 range
// [2, 262144]) to a cgroup v2 cpu.weight value in [1, 10000], using the
// conversion systemd and the OCI runtime-spec agreed on:
//
//	weight = 1 + ((shares - 2) * 9999) / 262142
//
// The result is clamped, so 2 maps to 1, 1024 maps to 39 and 262144 maps to
// 10000. Callers must not call this for an unset (zero) shares value.
func CPUSharesToWeight(shares int64) uint64 {
	if shares <= 2 {
		return 1
	}
	if shares >= 262144 {
		return 10000
	}
	w := 1 + ((shares-2)*9999)/262142
	if w < 1 {
		w = 1
	}
	if w > 10000 {
		w = 10000
	}
	return uint64(w)
}

// BlkioWeightToIOWeight rescales a Docker blkio weight from the v1 range
// [10, 1000] onto the cgroup v2 io.weight range [1, 10000]:
//
//	io.weight = 1 + (blkio - 10) * 9999 / 990
//
// Inputs outside the v1 range are clamped, so 10 maps to 1 and 1000 to 10000.
func BlkioWeightToIOWeight(w uint16) uint64 {
	v := int64(w)
	if v < 10 {
		v = 10
	}
	if v > 1000 {
		v = 1000
	}
	return uint64(1 + (v-10)*9999/990)
}

// CPUMax renders the cpu.max value for a quota/period/NanoCPUs triple.
//
// period defaults to DefaultCPUPeriod. NanoCPUs (Docker's --cpus, in units of
// 1e-9 CPU) wins over an explicit quota and yields quota = nanoCPUs*period/1e9.
// A negative quota means "max". ok is false when nothing should be written.
func CPUMax(quota, period, nanoCPUs int64) (value string, ok bool) {
	p := period
	if p <= 0 {
		p = DefaultCPUPeriod
	}
	switch {
	case nanoCPUs > 0:
		q := nanoCPUs * p / 1e9
		if q < 1 {
			q = 1
		}
		return fmt.Sprintf("%d %d", q, p), true
	case quota > 0:
		return fmt.Sprintf("%d %d", quota, p), true
	case quota < 0:
		return fmt.Sprintf("max %d", p), true
	case period > 0:
		// A period was requested without a quota: keep the group unlimited but
		// honour the period so a later quota write uses it.
		return fmt.Sprintf("max %d", p), true
	default:
		return "", false
	}
}

// MemoryMax renders the memory.max value for a Docker memory limit. A limit of
// 0 (unset) means nothing is written; -1 (explicitly unlimited) becomes "max".
func MemoryMax(memory int64) (value string, ok bool) {
	switch {
	case memory < 0:
		return "max", true
	case memory == 0:
		return "", false
	default:
		return strconv.FormatInt(memory, 10), true
	}
}

// SwapMax renders the memory.swap.max value from Docker's memory/memory-swap
// pair, where memorySwap is the combined memory+swap budget:
//
//	memorySwap == 0          -> unset, nothing is written
//	memorySwap == -1         -> "max" (unlimited swap)
//	memorySwap == memory     -> "0"   (swap disabled)
//	memorySwap  > memory > 0 -> memorySwap - memory
//
// ok is false for an unset value and for the invalid combinations (a swap
// budget smaller than the memory limit, or one given without a memory limit);
// Apply turns those into a descriptive error.
func SwapMax(memory, memorySwap int64) (value string, ok bool) {
	switch {
	case memorySwap == 0:
		return "", false
	case memorySwap < 0:
		if memorySwap == -1 {
			return "max", true
		}
		return "", false
	case memory <= 0:
		// Docker requires --memory when --memory-swap is set: without it the
		// swap-only budget cannot be derived.
		return "", false
	case memorySwap == memory:
		return "0", true
	case memorySwap < memory:
		return "", false
	default:
		return strconv.FormatInt(memorySwap-memory, 10), true
	}
}

// ---------- parsers (pure; fed golden text by the tests) ----------

// parseKeyedUint parses "key value" lines (cpu.stat, memory.stat,
// memory.events) into a map. Unparsable lines are skipped.
func parseKeyedUint(text string) map[string]uint64 {
	out := make(map[string]uint64)
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		out[f[0]] = v
	}
	return out
}

// parseUintFile parses a single-value cgroup file such as memory.current.
func parseUintFile(text string) (uint64, error) {
	s := strings.TrimSpace(text)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", s, err)
	}
	return v, nil
}

// parseLimitFile parses a limit file such as memory.max, pids.max or cpu.max,
// where the literal "max" means unlimited and is reported as 0. For two-field
// values (cpu.max) only the first field is considered.
func parseLimitFile(text string) (uint64, error) {
	s := strings.TrimSpace(text)
	if s == "" || s == "max" {
		return 0, nil
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
		if s == "max" {
			return 0, nil
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse limit %q: %w", s, err)
	}
	return v, nil
}

// parseIOStat sums the per-device rbytes=/wbytes= counters of io.stat.
func parseIOStat(text string) (read, write uint64) {
	for _, line := range strings.Split(text, "\n") {
		for _, f := range strings.Fields(line) {
			k, v, ok := strings.Cut(f, "=")
			if !ok {
				continue
			}
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				continue
			}
			switch k {
			case "rbytes":
				read += n
			case "wbytes":
				write += n
			}
		}
	}
	return read, write
}

// parsePressureSome10 extracts avg10 from the "some" line of a PSI pressure
// file. Kernels without CONFIG_PSI have no such file, so callers treat a
// missing file as zero.
func parsePressureSome10(text string) float64 {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "some" {
			continue
		}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k != "avg10" {
				continue
			}
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return 0
			}
			return n
		}
	}
	return 0
}

// parsePids parses a cgroup.procs / cgroup.threads listing.
func parsePids(text string) ([]int, error) {
	var out []int
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		if s == "" {
			continue
		}
		pid, err := strconv.Atoi(s)
		if err != nil {
			return out, fmt.Errorf("parse pid %q: %w", s, err)
		}
		out = append(out, pid)
	}
	return out, nil
}

// cleanRelPath validates a cgroup path relative to the v2 root and returns it
// without leading or trailing slashes. It rejects absolute escapes, "." and
// "..", empty segments, backslashes and NUL bytes, so a caller-supplied
// container ID can never walk out of hull's subtree.
func cleanRelPath(p string) (string, error) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", errors.New("cgroups: empty cgroup path")
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("cgroups: cgroup path contains NUL")
	}
	segs := strings.Split(p, "/")
	for _, s := range segs {
		switch s {
		case "", ".", "..":
			return "", fmt.Errorf("cgroups: invalid segment %q in cgroup path %q", s, p)
		}
		if strings.Contains(s, "\\") {
			return "", fmt.Errorf("cgroups: invalid segment %q in cgroup path %q", s, p)
		}
	}
	return strings.Join(segs, "/"), nil
}

// unescapeMountField decodes the octal escapes (\040, \011, \012, \134) that
// /proc/mounts uses for spaces, tabs, newlines and backslashes in paths.
func unescapeMountField(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// kernelAtLeast reports whether a uname release string such as
// "5.15.167.4-microsoft-standard-WSL2" is at least major.minor.
func kernelAtLeast(release string, major, minor int) bool {
	end := 0
	for end < len(release) && (release[end] == '.' || (release[end] >= '0' && release[end] <= '9')) {
		end++
	}
	parts := strings.Split(release[:end], ".")
	if len(parts) < 2 {
		return false
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	if ma != major {
		return ma > major
	}
	return mi >= minor
}

// countCPUList counts the CPUs in a kernel cpulist such as "0-3,7".
func countCPUList(s string) int {
	total := 0
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		if part == "" {
			continue
		}
		lo, hi, ok := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return 0
		}
		if !ok {
			total++
			continue
		}
		b, err := strconv.Atoi(strings.TrimSpace(hi))
		if err != nil || b < a {
			return 0
		}
		total += b - a + 1
	}
	return total
}
