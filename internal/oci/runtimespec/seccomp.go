package runtimespec

// LinuxSeccomp is the seccomp-bpf program the runtime installs on the
// container process. hull always sets Process.NoNewPrivileges before the
// filter is loaded; a filter without no_new_privs is a privilege-escalation
// hazard, not a hardening measure.
type LinuxSeccomp struct {
	DefaultAction    LinuxSeccompAction `json:"defaultAction"`
	DefaultErrnoRet  *uint              `json:"defaultErrnoRet,omitempty"`
	Architectures    []Arch             `json:"architectures,omitempty"`
	Flags            []LinuxSeccompFlag `json:"flags,omitempty"`
	ListenerPath     string             `json:"listenerPath,omitempty"`
	ListenerMetadata string             `json:"listenerMetadata,omitempty"`
	Syscalls         []LinuxSyscall     `json:"syscalls,omitempty"`
}

// LinuxSyscall is one rule in a seccomp filter: a set of syscall names, the
// action to take, and optional argument predicates that must all match.
type LinuxSyscall struct {
	Names    []string           `json:"names"`
	Action   LinuxSeccompAction `json:"action"`
	ErrnoRet *uint              `json:"errnoRet,omitempty"`
	Args     []LinuxSeccompArg  `json:"args,omitempty"`
}

// LinuxSeccompArg is one argument predicate of a seccomp rule.
type LinuxSeccompArg struct {
	Index    uint                 `json:"index"`
	Value    uint64               `json:"value"`
	ValueTwo uint64               `json:"valueTwo,omitempty"`
	Op       LinuxSeccompOperator `json:"op"`
}

// LinuxSeccompAction is the action a seccomp rule takes.
type LinuxSeccompAction string

// Seccomp actions defined by the runtime spec.
const (
	ActKill        LinuxSeccompAction = "SCMP_ACT_KILL"
	ActKillProcess LinuxSeccompAction = "SCMP_ACT_KILL_PROCESS"
	ActKillThread  LinuxSeccompAction = "SCMP_ACT_KILL_THREAD"
	ActTrap        LinuxSeccompAction = "SCMP_ACT_TRAP"
	ActErrno       LinuxSeccompAction = "SCMP_ACT_ERRNO"
	ActTrace       LinuxSeccompAction = "SCMP_ACT_TRACE"
	ActAllow       LinuxSeccompAction = "SCMP_ACT_ALLOW"
	ActLog         LinuxSeccompAction = "SCMP_ACT_LOG"
	ActNotify      LinuxSeccompAction = "SCMP_ACT_NOTIFY"
)

// LinuxSeccompOperator is the comparison used by a LinuxSeccompArg.
type LinuxSeccompOperator string

// Seccomp argument comparison operators.
const (
	OpNotEqual     LinuxSeccompOperator = "SCMP_CMP_NE"
	OpLessThan     LinuxSeccompOperator = "SCMP_CMP_LT"
	OpLessEqual    LinuxSeccompOperator = "SCMP_CMP_LE"
	OpEqualTo      LinuxSeccompOperator = "SCMP_CMP_EQ"
	OpGreaterEqual LinuxSeccompOperator = "SCMP_CMP_GE"
	OpGreaterThan  LinuxSeccompOperator = "SCMP_CMP_GT"
	OpMaskedEqual  LinuxSeccompOperator = "SCMP_CMP_MASKED_EQ"
)

// LinuxSeccompFlag is a flag passed to seccomp(2) when the filter is loaded.
type LinuxSeccompFlag string

// Seccomp filter flags.
const (
	FlagLog              LinuxSeccompFlag = "SECCOMP_FILTER_FLAG_LOG"
	FlagSpecAllow        LinuxSeccompFlag = "SECCOMP_FILTER_FLAG_SPEC_ALLOW"
	FlagWaitKillableRecv LinuxSeccompFlag = "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV"
)

// Arch is a seccomp architecture token.
type Arch string

// Seccomp architectures defined by the runtime spec.
const (
	ArchX86         Arch = "SCMP_ARCH_X86"
	ArchX86_64      Arch = "SCMP_ARCH_X86_64"
	ArchX32         Arch = "SCMP_ARCH_X32"
	ArchARM         Arch = "SCMP_ARCH_ARM"
	ArchAARCH64     Arch = "SCMP_ARCH_AARCH64"
	ArchMIPS        Arch = "SCMP_ARCH_MIPS"
	ArchMIPS64      Arch = "SCMP_ARCH_MIPS64"
	ArchMIPS64N32   Arch = "SCMP_ARCH_MIPS64N32"
	ArchMIPSEL      Arch = "SCMP_ARCH_MIPSEL"
	ArchMIPSEL64    Arch = "SCMP_ARCH_MIPSEL64"
	ArchMIPSEL64N32 Arch = "SCMP_ARCH_MIPSEL64N32"
	ArchPPC         Arch = "SCMP_ARCH_PPC"
	ArchPPC64       Arch = "SCMP_ARCH_PPC64"
	ArchPPC64LE     Arch = "SCMP_ARCH_PPC64LE"
	ArchS390        Arch = "SCMP_ARCH_S390"
	ArchS390X       Arch = "SCMP_ARCH_S390X"
	ArchRISCV64     Arch = "SCMP_ARCH_RISCV64"
)

// validSeccompActions is the set Validate accepts.
var validSeccompActions = map[LinuxSeccompAction]bool{
	ActKill:        true,
	ActKillProcess: true,
	ActKillThread:  true,
	ActTrap:        true,
	ActErrno:       true,
	ActTrace:       true,
	ActAllow:       true,
	ActLog:         true,
	ActNotify:      true,
}

// validSeccompOps is the set Validate accepts.
var validSeccompOps = map[LinuxSeccompOperator]bool{
	OpNotEqual:     true,
	OpLessThan:     true,
	OpLessEqual:    true,
	OpEqualTo:      true,
	OpGreaterEqual: true,
	OpGreaterThan:  true,
	OpMaskedEqual:  true,
}
