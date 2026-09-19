package initspec

import (
	"fmt"
	"strings"
)

// Classic-BPF instruction classes and modifiers, from linux/bpf_common.h.
// They are spelled out here rather than imported so the assembler builds and
// is testable on every GOOS, including the Windows CLI host.
const (
	bpfLD   = 0x00
	bpfLDX  = 0x01
	bpfALU  = 0x04
	bpfJMP  = 0x05
	bpfRET  = 0x06
	bpfMISC = 0x07

	bpfW   = 0x00
	bpfABS = 0x20
	bpfIMM = 0x00

	bpfJA   = 0x00
	bpfJEQ  = 0x10
	bpfJGT  = 0x20
	bpfJGE  = 0x30
	bpfJSET = 0x40

	bpfAND = 0x50

	bpfK = 0x00
	bpfX = 0x08
)

// BPFMaxInsns is BPF_MAXINSNS from linux/bpf_common.h: the kernel refuses a
// classic-BPF program longer than this, and seccomp is no exception.
const BPFMaxInsns = 4096

// maxJump is the largest offset a classic-BPF conditional jump can encode; jt
// and jf are single bytes.
const maxJump = 255

// Instruction is one classic-BPF instruction, laid out exactly like the
// kernel struct sock_filter. It is an ordinary value type so a compiled
// program can be compared against a golden table in a unit test on any host.
type Instruction struct {
	// Code is the opcode (class, size/mode, and operation).
	Code uint16
	// JT is the offset taken when a conditional jump is true.
	JT uint8
	// JF is the offset taken when a conditional jump is false.
	JF uint8
	// K is the immediate operand.
	K uint32
}

// String renders the instruction the way a disassembler would, so a failing
// golden test prints something a human can read.
func (i Instruction) String() string {
	class := i.Code & 0x07
	switch class {
	case bpfLD:
		return fmt.Sprintf("ld   [%d]", i.K)
	case bpfLDX:
		return fmt.Sprintf("ldx  #%#x", i.K)
	case bpfALU:
		return fmt.Sprintf("and  #%#x", i.K)
	case bpfRET:
		return fmt.Sprintf("ret  %s", retName(i.K))
	case bpfJMP:
		op := i.Code & 0xf0
		name := map[uint16]string{bpfJA: "ja", bpfJEQ: "jeq", bpfJGT: "jgt", bpfJGE: "jge", bpfJSET: "jset"}[op]
		if op == bpfJA {
			return fmt.Sprintf("ja   +%d", i.K)
		}
		return fmt.Sprintf("%-4s #%#x, jt %d, jf %d", name, i.K, i.JT, i.JF)
	}
	return fmt.Sprintf("op %#x jt %d jf %d k %#x", i.Code, i.JT, i.JF, i.K)
}

func retName(k uint32) string {
	if n, ok := retNames[k&retActionMask]; ok {
		if data := k & retDataMask; data != 0 {
			return fmt.Sprintf("%s(%d)", n, data)
		}
		return n
	}
	return fmt.Sprintf("%#x", k)
}

var retNames = map[uint32]string{
	RetKillProcess: "KILL_PROCESS",
	RetKillThread:  "KILL_THREAD",
	RetTrap:        "TRAP",
	RetErrno:       "ERRNO",
	RetUserNotif:   "USER_NOTIF",
	RetTrace:       "TRACE",
	RetLog:         "LOG",
	RetAllow:       "ALLOW",
}

// seccomp(2) filter return values, from linux/seccomp.h.
const (
	// RetKillProcess terminates the whole thread group.
	RetKillProcess uint32 = 0x80000000
	// RetKillThread terminates the calling thread. It is the historical
	// SECCOMP_RET_KILL.
	RetKillThread uint32 = 0x00000000
	// RetTrap raises SIGSYS.
	RetTrap uint32 = 0x00030000
	// RetErrno fails the call with the errno in the low 16 bits.
	RetErrno uint32 = 0x00050000
	// RetUserNotif hands the call to a userspace supervisor.
	RetUserNotif uint32 = 0x7fc00000
	// RetTrace notifies an attached tracer.
	RetTrace uint32 = 0x7ff00000
	// RetLog allows the call and logs it.
	RetLog uint32 = 0x7ffc0000
	// RetAllow allows the call.
	RetAllow uint32 = 0x7fff0000

	retActionMask uint32 = 0xffff0000
	retDataMask   uint32 = 0x0000ffff
)

// Offsets into struct seccomp_data, from linux/seccomp.h. The struct is
// 64 bytes: int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6].
const (
	offNR   = 0
	offArch = 4
	offIP   = 8
	offArgs = 16
)

// argOffsets returns the absolute offsets of the low and high 32-bit words of
// seccomp_data.args[i] on a little-endian architecture.
func argOffsets(i uint) (lo, hi uint32) {
	base := uint32(offArgs + 8*i)
	return base, base + 4
}

// ld emits an absolute 32-bit load of seccomp_data at off into A.
func ld(off uint32) Instruction {
	return Instruction{Code: bpfLD | bpfW | bpfABS, K: off}
}

// and emits A &= k.
func and(k uint32) Instruction {
	return Instruction{Code: bpfALU | bpfAND | bpfK, K: k}
}

// jeq emits "if A == k jump jt else jump jf", offsets relative to the next
// instruction.
func jeq(k uint32, jt, jf uint8) Instruction {
	return Instruction{Code: bpfJMP | bpfJEQ | bpfK, K: k, JT: jt, JF: jf}
}

// jgt emits "if A > k jump jt else jump jf".
func jgt(k uint32, jt, jf uint8) Instruction {
	return Instruction{Code: bpfJMP | bpfJGT | bpfK, K: k, JT: jt, JF: jf}
}

// jge emits "if A >= k jump jt else jump jf".
func jge(k uint32, jt, jf uint8) Instruction {
	return Instruction{Code: bpfJMP | bpfJGE | bpfK, K: k, JT: jt, JF: jf}
}

// ret emits a terminating return of the seccomp action k.
func ret(k uint32) Instruction {
	return Instruction{Code: bpfRET | bpfK, K: k}
}

// Disassemble renders a whole program, one numbered instruction per line.
func Disassemble(insns []Instruction) string {
	var b strings.Builder
	for i, in := range insns {
		fmt.Fprintf(&b, "%03d: %s\n", i, in)
	}
	return b.String()
}
