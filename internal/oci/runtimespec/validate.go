package runtimespec

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// ErrNilSpec is returned by Validate when called on a nil *Spec.
var ErrNilSpec = errors.New("runtimespec: nil spec")

// Validate checks a Spec for the structural invariants the runtime-spec
// requires and that runc and crun enforce, so hull fails with a clear message
// before it hands a bundle to a runtime.
//
// It is deliberately strict about paths: every destination and every masked or
// read-only path must be absolute and lexically clean, because a relative or
// dot-segment path in a bundle is how container-controlled input escapes a
// rootfs.
func (s *Spec) Validate() error {
	if s == nil {
		return ErrNilSpec
	}
	if s.Version == "" {
		return errors.New("runtimespec: ociVersion is empty")
	}
	if !strings.HasPrefix(s.Version, "1.") {
		return fmt.Errorf("runtimespec: unsupported ociVersion %q, hull emits and understands 1.x", s.Version)
	}
	if s.Root == nil {
		return errors.New("runtimespec: root is required for a linux container")
	}
	if s.Root.Path == "" {
		return errors.New("runtimespec: root.path is empty")
	}
	if s.Process == nil {
		return errors.New("runtimespec: process is required")
	}
	if len(s.Process.Args) == 0 && s.Process.CommandLine == "" {
		return errors.New("runtimespec: process.args is empty and no commandLine is set")
	}
	if s.Process.Cwd == "" {
		return errors.New("runtimespec: process.cwd is empty")
	}
	if !isAbsClean(s.Process.Cwd) {
		return fmt.Errorf("runtimespec: process.cwd %q must be an absolute, clean path", s.Process.Cwd)
	}
	for i, e := range s.Process.Env {
		if !strings.Contains(e, "=") {
			return fmt.Errorf("runtimespec: process.env[%d] %q is not KEY=VALUE", i, e)
		}
		if strings.HasPrefix(e, "=") {
			return fmt.Errorf("runtimespec: process.env[%d] has an empty variable name", i)
		}
	}
	for i, rl := range s.Process.Rlimits {
		if !strings.HasPrefix(rl.Type, "RLIMIT_") {
			return fmt.Errorf("runtimespec: process.rlimits[%d].type %q must start with RLIMIT_", i, rl.Type)
		}
		if rl.Soft > rl.Hard {
			return fmt.Errorf("runtimespec: process.rlimits[%d] (%s) soft %d exceeds hard %d", i, rl.Type, rl.Soft, rl.Hard)
		}
	}
	if err := validateCaps(s.Process.Capabilities); err != nil {
		return err
	}

	seen := make(map[string]int, len(s.Mounts))
	for i, m := range s.Mounts {
		if m.Destination == "" {
			return fmt.Errorf("runtimespec: mounts[%d].destination is empty", i)
		}
		if !isAbsClean(m.Destination) {
			return fmt.Errorf("runtimespec: mounts[%d].destination %q must be an absolute, clean path", i, m.Destination)
		}
		if j, dup := seen[m.Destination]; dup {
			return fmt.Errorf("runtimespec: mounts[%d].destination %q duplicates mounts[%d]", i, m.Destination, j)
		}
		seen[m.Destination] = i
	}

	if s.Linux != nil {
		if err := validateLinux(s.Linux); err != nil {
			return err
		}
	}
	if s.Hooks != nil {
		for name, hooks := range map[string][]Hook{
			"prestart":        s.Hooks.Prestart,
			"createRuntime":   s.Hooks.CreateRuntime,
			"createContainer": s.Hooks.CreateContainer,
			"startContainer":  s.Hooks.StartContainer,
			"poststart":       s.Hooks.Poststart,
			"poststop":        s.Hooks.Poststop,
		} {
			for i, h := range hooks {
				if h.Path == "" {
					return fmt.Errorf("runtimespec: hooks.%s[%d].path is empty", name, i)
				}
				if !isAbsClean(h.Path) {
					return fmt.Errorf("runtimespec: hooks.%s[%d].path %q must be an absolute, clean path", name, i, h.Path)
				}
				if h.Timeout != nil && *h.Timeout <= 0 {
					return fmt.Errorf("runtimespec: hooks.%s[%d].timeout must be positive", name, i)
				}
			}
		}
	}
	return nil
}

func validateCaps(c *LinuxCapabilities) error {
	if c == nil {
		return nil
	}
	for name, set := range map[string][]string{
		"bounding":    c.Bounding,
		"effective":   c.Effective,
		"inheritable": c.Inheritable,
		"permitted":   c.Permitted,
		"ambient":     c.Ambient,
	} {
		for i, capName := range set {
			if !strings.HasPrefix(capName, "CAP_") {
				return fmt.Errorf("runtimespec: process.capabilities.%s[%d] %q must start with CAP_", name, i, capName)
			}
			if capName != strings.ToUpper(capName) {
				return fmt.Errorf("runtimespec: process.capabilities.%s[%d] %q must be upper case", name, i, capName)
			}
		}
	}
	return nil
}

func validateLinux(l *Linux) error {
	nsSeen := make(map[LinuxNamespaceType]bool, len(l.Namespaces))
	for i, ns := range l.Namespaces {
		if !validNamespaceTypes[ns.Type] {
			return fmt.Errorf("runtimespec: linux.namespaces[%d].type %q is not a known namespace type", i, ns.Type)
		}
		if nsSeen[ns.Type] {
			return fmt.Errorf("runtimespec: linux.namespaces has a duplicate %q entry", ns.Type)
		}
		nsSeen[ns.Type] = true
		if ns.Path != "" && !isAbsClean(ns.Path) {
			return fmt.Errorf("runtimespec: linux.namespaces[%d].path %q must be an absolute, clean path", i, ns.Path)
		}
	}
	if (len(l.UIDMappings) > 0 || len(l.GIDMappings) > 0) && !nsSeen[UserNamespace] {
		return errors.New("runtimespec: linux.uidMappings/gidMappings require a user namespace in linux.namespaces")
	}
	for i, m := range l.UIDMappings {
		if m.Size == 0 {
			return fmt.Errorf("runtimespec: linux.uidMappings[%d].size must be non-zero", i)
		}
	}
	for i, m := range l.GIDMappings {
		if m.Size == 0 {
			return fmt.Errorf("runtimespec: linux.gidMappings[%d].size must be non-zero", i)
		}
	}
	for i, p := range l.MaskedPaths {
		if !isAbsClean(p) {
			return fmt.Errorf("runtimespec: linux.maskedPaths[%d] %q must be an absolute, clean path", i, p)
		}
	}
	for i, p := range l.ReadonlyPaths {
		if !isAbsClean(p) {
			return fmt.Errorf("runtimespec: linux.readonlyPaths[%d] %q must be an absolute, clean path", i, p)
		}
	}
	for i, d := range l.Devices {
		if !isAbsClean(d.Path) {
			return fmt.Errorf("runtimespec: linux.devices[%d].path %q must be an absolute, clean path", i, d.Path)
		}
		switch d.Type {
		case "c", "b", "u", "p":
		default:
			return fmt.Errorf("runtimespec: linux.devices[%d].type %q must be one of c, b, u, p", i, d.Type)
		}
	}
	switch l.RootfsPropagation {
	case "", "private", "shared", "slave", "unbindable", "rprivate", "rshared", "rslave", "runbindable":
	default:
		return fmt.Errorf("runtimespec: linux.rootfsPropagation %q is not a valid propagation mode", l.RootfsPropagation)
	}
	if l.Resources != nil {
		if err := validateResources(l.Resources); err != nil {
			return err
		}
	}
	if l.Seccomp != nil {
		if err := validateSeccomp(l.Seccomp); err != nil {
			return err
		}
	}
	if l.Personality != nil {
		switch l.Personality.Domain {
		case PerLinux, PerLinux32:
		default:
			return fmt.Errorf("runtimespec: linux.personality.domain %q must be LINUX or LINUX32", l.Personality.Domain)
		}
	}
	return nil
}

func validateResources(r *LinuxResources) error {
	if r.CPU != nil {
		if r.CPU.Period != nil && *r.CPU.Period == 0 {
			return errors.New("runtimespec: linux.resources.cpu.period must be non-zero")
		}
		if r.CPU.Quota != nil && r.CPU.Period == nil && *r.CPU.Quota > 0 {
			return errors.New("runtimespec: linux.resources.cpu.quota set without cpu.period")
		}
	}
	if r.Memory != nil {
		lim, swap := r.Memory.Limit, r.Memory.Swap
		if lim != nil && swap != nil && *swap > 0 && *lim > 0 && *swap < *lim {
			return fmt.Errorf("runtimespec: linux.resources.memory.swap (%d) is less than memory.limit (%d); swap is the combined memory+swap total", *swap, *lim)
		}
		if r.Memory.Swappiness != nil && *r.Memory.Swappiness > 100 {
			return fmt.Errorf("runtimespec: linux.resources.memory.swappiness %d is out of range 0-100", *r.Memory.Swappiness)
		}
	}
	for i, d := range r.Devices {
		switch d.Type {
		case "", "a", "c", "b":
		default:
			return fmt.Errorf("runtimespec: linux.resources.devices[%d].type %q must be one of a, c, b", i, d.Type)
		}
		for _, ch := range d.Access {
			if ch != 'r' && ch != 'w' && ch != 'm' {
				return fmt.Errorf("runtimespec: linux.resources.devices[%d].access %q may only contain r, w, m", i, d.Access)
			}
		}
	}
	for i, h := range r.HugepageLimits {
		if h.Pagesize == "" {
			return fmt.Errorf("runtimespec: linux.resources.hugepageLimits[%d].pageSize is empty", i)
		}
	}
	return nil
}

func validateSeccomp(sc *LinuxSeccomp) error {
	if sc.DefaultAction == "" {
		return errors.New("runtimespec: linux.seccomp.defaultAction is empty")
	}
	if !validSeccompActions[sc.DefaultAction] {
		return fmt.Errorf("runtimespec: linux.seccomp.defaultAction %q is not a known SCMP_ACT_ value", sc.DefaultAction)
	}
	for i, a := range sc.Architectures {
		if !strings.HasPrefix(string(a), "SCMP_ARCH_") {
			return fmt.Errorf("runtimespec: linux.seccomp.architectures[%d] %q must start with SCMP_ARCH_", i, a)
		}
	}
	if sc.ListenerPath != "" && !isAbsClean(sc.ListenerPath) {
		return fmt.Errorf("runtimespec: linux.seccomp.listenerPath %q must be an absolute, clean path", sc.ListenerPath)
	}
	if sc.ListenerPath == "" {
		if sc.DefaultAction == ActNotify {
			return errors.New("runtimespec: linux.seccomp.defaultAction is SCMP_ACT_NOTIFY but no listenerPath is set")
		}
		for _, sys := range sc.Syscalls {
			if sys.Action == ActNotify {
				return fmt.Errorf("runtimespec: linux.seccomp syscall rule %v uses SCMP_ACT_NOTIFY but no listenerPath is set", sys.Names)
			}
		}
	}
	for i, sys := range sc.Syscalls {
		if len(sys.Names) == 0 {
			return fmt.Errorf("runtimespec: linux.seccomp.syscalls[%d].names is empty", i)
		}
		if !validSeccompActions[sys.Action] {
			return fmt.Errorf("runtimespec: linux.seccomp.syscalls[%d].action %q is not a known SCMP_ACT_ value", i, sys.Action)
		}
		for j, arg := range sys.Args {
			if arg.Index > 5 {
				return fmt.Errorf("runtimespec: linux.seccomp.syscalls[%d].args[%d].index %d is out of range 0-5", i, j, arg.Index)
			}
			if !validSeccompOps[arg.Op] {
				return fmt.Errorf("runtimespec: linux.seccomp.syscalls[%d].args[%d].op %q is not a known SCMP_CMP_ value", i, j, arg.Op)
			}
		}
	}
	return nil
}

var validNamespaceTypes = map[LinuxNamespaceType]bool{
	PIDNamespace:     true,
	NetworkNamespace: true,
	MountNamespace:   true,
	IPCNamespace:     true,
	UTSNamespace:     true,
	UserNamespace:    true,
	CgroupNamespace:  true,
	TimeNamespace:    true,
}

// isAbsClean reports whether p is an absolute slash path with no "." or ".."
// segments and no trailing or doubled slashes. It intentionally uses path, not
// filepath, so the result is identical when the hull CLI is built for Windows.
func isAbsClean(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") {
		return false
	}
	if strings.ContainsRune(p, '\x00') {
		return false
	}
	return path.Clean(p) == p
}
