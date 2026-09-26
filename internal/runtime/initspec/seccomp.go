package initspec

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/ChPuru/hull/internal/oci/runtimespec"
)

// ErrFilterTooLarge is returned when a seccomp profile compiles to more than
// BPFMaxInsns classic-BPF instructions. It is a hard kernel limit, so the only
// fix is a smaller profile.
var ErrFilterTooLarge = errors.New("initspec: seccomp filter exceeds BPF_MAXINSNS")

// ErrUnsupportedArch is returned when a profile names only architectures hull
// has no syscall table for.
var ErrUnsupportedArch = errors.New("initspec: unsupported seccomp architecture")

// AUDIT_ARCH_* tokens from linux/audit.h. seccomp_data.arch carries one of
// these and a filter that does not check it is trivially bypassable by a
// process that issues syscalls under a different personality.
const (
	auditArchX86_64  uint32 = 0xc000003e
	auditArchI386    uint32 = 0x40000003
	auditArchX32     uint32 = 0x4000003e
	auditArchAARCH64 uint32 = 0xc00000b7
	auditArchARM     uint32 = 0x40000028
	auditArchRISCV64 uint32 = 0xc00000f3
)

// x32Bit is __X32_SYSCALL_BIT: on x86-64 a syscall number with this bit set is
// an x32 call. x32 shares the AUDIT_ARCH_X86_64 token but has its own numbers,
// so a filter that ignores the bit can be walked straight past.
const x32Bit uint32 = 0x40000000

// ArchTarget is a compilation target for the seccomp assembler: an audit arch
// token plus the syscall-name table that goes with it.
type ArchTarget struct {
	// Spec is the runtime-spec token for this architecture.
	Spec runtimespec.Arch
	// AuditArch is the value seccomp_data.arch carries.
	AuditArch uint32
	// GOARCH is the Go architecture name, for diagnostics.
	GOARCH string

	table    map[string]int
	checkX32 bool
}

// Name returns the runtime-spec architecture token, e.g. SCMP_ARCH_X86_64.
func (t ArchTarget) Name() string { return string(t.Spec) }

// SyscallNumber resolves a syscall name on this target.
func (t ArchTarget) SyscallNumber(name string) (int, bool) {
	n, ok := t.table[name]
	return n, ok
}

var archTargets = []ArchTarget{
	{Spec: runtimespec.ArchX86_64, AuditArch: auditArchX86_64, GOARCH: "amd64", table: syscallsAMD64, checkX32: true},
	{Spec: runtimespec.ArchAARCH64, AuditArch: auditArchAARCH64, GOARCH: "arm64", table: syscallsARM64},
	{Spec: runtimespec.ArchRISCV64, AuditArch: auditArchRISCV64, GOARCH: "riscv64", table: syscallsARM64},
}

// TargetForArch returns the compilation target for a runtime-spec
// architecture token. Architectures hull has no syscall table for report
// false; a profile that names only those cannot be compiled.
func TargetForArch(a runtimespec.Arch) (ArchTarget, bool) {
	for _, t := range archTargets {
		if t.Spec == a {
			return t, true
		}
	}
	return ArchTarget{}, false
}

// TargetForGOARCH returns the compilation target for a Go architecture name.
func TargetForGOARCH(goarch string) (ArchTarget, bool) {
	for _, t := range archTargets {
		if t.GOARCH == goarch {
			return t, true
		}
	}
	return ArchTarget{}, false
}

// NativeTarget returns the compilation target for the architecture hull is
// running on. The second result is false on an architecture hull cannot build
// a seccomp filter for, which the caller must treat as an error rather than
// as "no filter".
func NativeTarget() (ArchTarget, bool) { return TargetForGOARCH(runtime.GOARCH) }

// Program is a compiled seccomp filter, ready to hand to seccomp(2).
type Program struct {
	// Insns is the classic-BPF instruction stream.
	Insns []Instruction
	// Target is the architecture the filter was compiled for.
	Target ArchTarget
	// Flags are the SECCOMP_FILTER_FLAG_* bits to load the filter with.
	Flags uint32
	// SkippedSyscalls lists rule syscall names that do not exist on the
	// target architecture. They are not an error - profiles are written
	// for many kernels at once - but the caller may want to log them.
	SkippedSyscalls []string
	// ForeignArchAction is the action taken for a syscall issued under any
	// other architecture token.
	ForeignArchAction uint32
}

// Len returns the instruction count.
func (p *Program) Len() int { return len(p.Insns) }

// SECCOMP_FILTER_FLAG_* bits from linux/seccomp.h.
const (
	// FilterFlagTSync applies the filter to every thread in the group.
	FilterFlagTSync uint32 = 1 << 0
	// FilterFlagLog logs every action other than ALLOW.
	FilterFlagLog uint32 = 1 << 1
	// FilterFlagSpecAllow opts out of the automatic Speculative Store
	// Bypass mitigation, which otherwise costs every container a large
	// slice of its syscall performance.
	FilterFlagSpecAllow uint32 = 1 << 2
	// FilterFlagNewListener returns a user-notification fd.
	FilterFlagNewListener uint32 = 1 << 3
	// FilterFlagWaitKillableRecv makes user-notification waits killable.
	FilterFlagWaitKillableRecv uint32 = 1 << 4
)

// actionValue maps a runtime-spec action plus its optional errno to the 32-bit
// value the filter returns.
func actionValue(a runtimespec.LinuxSeccompAction, errnoRet *uint) (uint32, error) {
	switch a {
	case runtimespec.ActKill, runtimespec.ActKillThread:
		return RetKillThread, nil
	case runtimespec.ActKillProcess:
		return RetKillProcess, nil
	case runtimespec.ActTrap:
		return RetTrap, nil
	case runtimespec.ActErrno:
		// EPERM is the default the OCI spec and Docker both assume.
		n := uint(1)
		if errnoRet != nil {
			n = *errnoRet
		}
		if n > 0xffff {
			return 0, fmt.Errorf("initspec: errnoRet %d does not fit in 16 bits", n)
		}
		return RetErrno | uint32(n)&retDataMask, nil
	case runtimespec.ActTrace:
		n := uint(0)
		if errnoRet != nil {
			n = *errnoRet
		}
		if n > 0xffff {
			return 0, fmt.Errorf("initspec: traceRet %d does not fit in 16 bits", n)
		}
		return RetTrace | uint32(n)&retDataMask, nil
	case runtimespec.ActAllow:
		return RetAllow, nil
	case runtimespec.ActLog:
		return RetLog, nil
	case runtimespec.ActNotify:
		return RetUserNotif, nil
	default:
		return 0, fmt.Errorf("initspec: unknown seccomp action %q", a)
	}
}

// permissive reports whether an action lets the syscall through. A filter
// whose default action is permissive must not fall back to that default for a
// foreign architecture, or the whole filter is bypassable by issuing syscalls
// under another personality.
func permissive(v uint32) bool {
	switch v & retActionMask {
	case RetAllow, RetLog, RetUserNotif, RetTrace:
		return true
	}
	return false
}

// SelectTarget picks the architecture to compile a profile for: the native one
// when the profile lists it (or lists none at all), otherwise the first listed
// architecture hull has a syscall table for.
func SelectTarget(sc *runtimespec.LinuxSeccomp) (ArchTarget, error) {
	native, haveNative := NativeTarget()
	if sc == nil || len(sc.Architectures) == 0 {
		if !haveNative {
			return ArchTarget{}, fmt.Errorf("initspec: no syscall table for GOARCH %s: %w",
				runtime.GOARCH, ErrUnsupportedArch)
		}
		return native, nil
	}
	if haveNative {
		for _, a := range sc.Architectures {
			if a == native.Spec {
				return native, nil
			}
		}
	}
	for _, a := range sc.Architectures {
		if t, ok := TargetForArch(a); ok {
			return t, nil
		}
	}
	return ArchTarget{}, fmt.Errorf("initspec: profile lists only architectures hull cannot compile (%v): %w",
		sc.Architectures, ErrUnsupportedArch)
}

// CompileSeccomp compiles an OCI seccomp profile into a classic-BPF program
// for the architecture hull is running on.
//
// The emitted program is:
//
//	ld  [4]                  ; seccomp_data.arch
//	jeq #AUDIT_ARCH, 1, 0    ; wrong architecture falls through
//	ret <foreign action>
//	ld  [0]                  ; seccomp_data.nr
//	jge #__X32_SYSCALL_BIT, 0, 1   ; x86-64 only
//	ret <foreign action>
//	<one compare per rule, each followed by its own ret>
//	ret <default action>
//
// Every conditional jump is either 0 or the length of one small rule block, so
// no offset can overflow the single-byte jt/jf fields no matter how large the
// profile is. Rules are emitted in profile order and a syscall may appear in
// several rules: when a rule with argument predicates does not match, control
// falls through to the next rule, and eventually to the default action, which
// is exactly the semantics libseccomp gives.
func CompileSeccomp(sc *runtimespec.LinuxSeccomp) (*Program, error) {
	t, err := SelectTarget(sc)
	if err != nil {
		return nil, err
	}
	return CompileSeccompFor(sc, t)
}

// CompileSeccompFor compiles a profile for an explicit architecture target.
// It is the form the tests use so golden instruction streams do not depend on
// the machine running them.
func CompileSeccompFor(sc *runtimespec.LinuxSeccomp, t ArchTarget) (*Program, error) {
	if sc == nil {
		return nil, fmt.Errorf("initspec: nil seccomp profile")
	}
	if t.table == nil {
		return nil, fmt.Errorf("initspec: architecture target has no syscall table: %w", ErrUnsupportedArch)
	}
	def, err := actionValue(sc.DefaultAction, sc.DefaultErrnoRet)
	if err != nil {
		return nil, err
	}

	// A permissive default must not be reused for a foreign architecture.
	foreign := def
	if permissive(def) {
		foreign = RetKillProcess
	}

	p := &Program{Target: t, ForeignArchAction: foreign}

	// Architecture guard.
	p.Insns = append(p.Insns,
		ld(offArch),
		jeq(t.AuditArch, 1, 0),
		ret(foreign),
		ld(offNR),
	)
	if t.checkX32 {
		// An x32 call carries __X32_SYSCALL_BIT in nr but the same
		// AUDIT_ARCH_X86_64 token, so it must be rejected explicitly.
		p.Insns = append(p.Insns, jge(x32Bit, 0, 1), ret(foreign))
	}

	for i := range sc.Syscalls {
		rule := &sc.Syscalls[i]
		if len(rule.Names) == 0 {
			return nil, fmt.Errorf("initspec: seccomp rule %d names no syscall", i)
		}
		act, err := actionValue(rule.Action, rule.ErrnoRet)
		if err != nil {
			return nil, fmt.Errorf("initspec: seccomp rule %d: %w", i, err)
		}
		body, err := ruleBody(rule, act)
		if err != nil {
			return nil, fmt.Errorf("initspec: seccomp rule %d: %w", i, err)
		}
		if len(body) > maxJump {
			return nil, fmt.Errorf("initspec: seccomp rule %d has too many argument predicates "+
				"(%d instructions, max %d)", i, len(body), maxJump)
		}
		for _, name := range rule.Names {
			nr, ok := t.SyscallNumber(name)
			if !ok {
				p.SkippedSyscalls = append(p.SkippedSyscalls, name)
				continue
			}
			if nr < 0 || int64(nr) > int64(^uint32(0)) {
				return nil, fmt.Errorf("initspec: syscall %q has out-of-range number %d", name, nr)
			}
			p.Insns = append(p.Insns, jeq(uint32(nr), 0, uint8(len(body))))
			p.Insns = append(p.Insns, body...)
		}
	}

	p.Insns = append(p.Insns, ret(def))

	if len(p.Insns) > BPFMaxInsns {
		return nil, fmt.Errorf("initspec: profile compiles to %d instructions, the kernel accepts at most %d "+
			"(drop argument predicates or split the profile): %w", len(p.Insns), BPFMaxInsns, ErrFilterTooLarge)
	}
	for _, f := range sc.Flags {
		switch f {
		case runtimespec.FlagLog:
			p.Flags |= FilterFlagLog
		case runtimespec.FlagSpecAllow:
			p.Flags |= FilterFlagSpecAllow
		case runtimespec.FlagWaitKillableRecv:
			p.Flags |= FilterFlagWaitKillableRecv
		default:
			return nil, fmt.Errorf("initspec: unknown seccomp flag %q", f)
		}
	}
	return p, nil
}

// ruleBody builds the instructions that follow a successful syscall-number
// compare: the argument predicates, then the rule action. Control reaching the
// instruction after the body means the rule did not match.
func ruleBody(rule *runtimespec.LinuxSyscall, act uint32) ([]Instruction, error) {
	if len(rule.Args) == 0 {
		return []Instruction{ret(act)}, nil
	}
	// Build the predicate instructions first so the distance from each
	// failure jump to the end of the body is known before patching.
	type stub struct {
		in    Instruction
		jtEnd bool
		jfEnd bool
	}
	var stubs []stub
	add := func(in Instruction, jtEnd, jfEnd bool) {
		stubs = append(stubs, stub{in: in, jtEnd: jtEnd, jfEnd: jfEnd})
	}
	for _, a := range rule.Args {
		if a.Index > 5 {
			return nil, fmt.Errorf("argument index %d is out of range (0-5)", a.Index)
		}
		lo, hi := argOffsets(a.Index)
		vLo := uint32(a.Value & 0xffffffff)
		vHi := uint32(a.Value >> 32)
		v2Lo := uint32(a.ValueTwo & 0xffffffff)
		v2Hi := uint32(a.ValueTwo >> 32)
		switch a.Op {
		case runtimespec.OpEqualTo:
			add(ld(hi), false, false)
			add(jeq(vHi, 0, 0), false, true)
			add(ld(lo), false, false)
			add(jeq(vLo, 0, 0), false, true)
		case runtimespec.OpNotEqual:
			// High words differing already proves inequality.
			add(ld(hi), false, false)
			add(jeq(vHi, 0, 2), false, false)
			add(ld(lo), false, false)
			add(jeq(vLo, 0, 0), true, false)
		case runtimespec.OpGreaterThan:
			add(ld(hi), false, false)
			add(jgt(vHi, 3, 0), false, false)
			add(jeq(vHi, 0, 0), false, true)
			add(ld(lo), false, false)
			add(jgt(vLo, 0, 0), false, true)
		case runtimespec.OpGreaterEqual:
			add(ld(hi), false, false)
			add(jgt(vHi, 3, 0), false, false)
			add(jeq(vHi, 0, 0), false, true)
			add(ld(lo), false, false)
			add(jge(vLo, 0, 0), false, true)
		case runtimespec.OpLessThan:
			add(ld(hi), false, false)
			add(jgt(vHi, 0, 0), true, false)
			add(jeq(vHi, 0, 2), false, false)
			add(ld(lo), false, false)
			add(jge(vLo, 0, 0), true, false)
		case runtimespec.OpLessEqual:
			add(ld(hi), false, false)
			add(jgt(vHi, 0, 0), true, false)
			add(jeq(vHi, 0, 2), false, false)
			add(ld(lo), false, false)
			add(jgt(vLo, 0, 0), true, false)
		case runtimespec.OpMaskedEqual:
			// (arg & value) == valueTwo
			add(ld(hi), false, false)
			add(and(vHi), false, false)
			add(jeq(v2Hi, 0, 0), false, true)
			add(ld(lo), false, false)
			add(and(vLo), false, false)
			add(jeq(v2Lo, 0, 0), false, true)
		default:
			return nil, fmt.Errorf("unknown argument operator %q", a.Op)
		}
	}
	out := make([]Instruction, 0, len(stubs)+1)
	for i, s := range stubs {
		// The body is stubs plus one ret; a failed predicate must land on
		// the instruction after the ret.
		off := len(stubs) - i
		if off > maxJump {
			return nil, fmt.Errorf("argument predicate jump offset %d overflows a byte", off)
		}
		in := s.in
		if s.jtEnd {
			in.JT = uint8(off)
		}
		if s.jfEnd {
			in.JF = uint8(off)
		}
		out = append(out, in)
	}
	return append(out, ret(act)), nil
}
