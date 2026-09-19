package initspec

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

func amd64Target(t *testing.T) ArchTarget {
	t.Helper()
	tg, ok := TargetForArch(runtimespec.ArchX86_64)
	if !ok {
		t.Fatal("no x86-64 target")
	}
	return tg
}

func uptr(v uint) *uint { return &v }

// TestCompileSeccompGolden pins the exact instruction stream for a set of
// profiles. The stream is what the kernel executes on every syscall a
// container makes, so any change to it must be a deliberate, reviewed one.
func TestCompileSeccompGolden(t *testing.T) {
	tests := []struct {
		name    string
		profile *runtimespec.LinuxSeccomp
		want    []string
	}{
		{
			name: "default deny only",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActErrno,
				Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
			},
			want: []string{
				"ld   [4]",
				"jeq  #0xc000003e, jt 1, jf 0",
				"ret  ERRNO(1)",
				"ld   [0]",
				"jge  #0x40000000, jt 0, jf 1",
				"ret  ERRNO(1)",
				"ret  ERRNO(1)",
			},
		},
		{
			name: "allowlist of three syscalls",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActErrno,
				Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
				Syscalls: []runtimespec.LinuxSyscall{
					{Names: []string{"read", "write", "exit_group"}, Action: runtimespec.ActAllow},
				},
			},
			want: []string{
				"ld   [4]",
				"jeq  #0xc000003e, jt 1, jf 0",
				"ret  ERRNO(1)",
				"ld   [0]",
				"jge  #0x40000000, jt 0, jf 1",
				"ret  ERRNO(1)",
				"jeq  #0x0, jt 0, jf 1", // read
				"ret  ALLOW",
				"jeq  #0x1, jt 0, jf 1", // write
				"ret  ALLOW",
				"jeq  #0xe7, jt 0, jf 1", // exit_group
				"ret  ALLOW",
				"ret  ERRNO(1)",
			},
		},
		{
			name: "errnoRet override",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction:   runtimespec.ActErrno,
				DefaultErrnoRet: uptr(38), // ENOSYS
				Architectures:   []runtimespec.Arch{runtimespec.ArchX86_64},
				Syscalls: []runtimespec.LinuxSyscall{
					{Names: []string{"ptrace"}, Action: runtimespec.ActErrno, ErrnoRet: uptr(1)},
				},
			},
			want: []string{
				"ld   [4]",
				"jeq  #0xc000003e, jt 1, jf 0",
				"ret  ERRNO(38)",
				"ld   [0]",
				"jge  #0x40000000, jt 0, jf 1",
				"ret  ERRNO(38)",
				"jeq  #0x65, jt 0, jf 1", // ptrace
				"ret  ERRNO(1)",
				"ret  ERRNO(38)",
			},
		},
		{
			name: "masked-equal argument predicate (clone without CLONE_NEWUSER)",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActErrno,
				Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
				Syscalls: []runtimespec.LinuxSyscall{
					{
						Names:  []string{"clone"},
						Action: runtimespec.ActAllow,
						Args: []runtimespec.LinuxSeccompArg{
							{Index: 0, Value: 0x10000000, ValueTwo: 0, Op: runtimespec.OpMaskedEqual},
						},
					},
				},
			},
			want: []string{
				"ld   [4]",
				"jeq  #0xc000003e, jt 1, jf 0",
				"ret  ERRNO(1)",
				"ld   [0]",
				"jge  #0x40000000, jt 0, jf 1",
				"ret  ERRNO(1)",
				"jeq  #0x38, jt 0, jf 7", // clone, body is 7 instructions
				"ld   [20]",              // args[0] high word
				"and  #0x0",
				"jeq  #0x0, jt 0, jf 4",
				"ld   [16]", // args[0] low word
				"and  #0x10000000",
				"jeq  #0x0, jt 0, jf 1",
				"ret  ALLOW",
				"ret  ERRNO(1)",
			},
		},
		{
			name: "equality on a 64-bit argument",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActKillProcess,
				Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
				Syscalls: []runtimespec.LinuxSyscall{
					{
						Names:  []string{"personality"},
						Action: runtimespec.ActAllow,
						Args: []runtimespec.LinuxSeccompArg{
							{Index: 0, Value: 0x0000000100000008, Op: runtimespec.OpEqualTo},
						},
					},
				},
			},
			want: []string{
				"ld   [4]",
				"jeq  #0xc000003e, jt 1, jf 0",
				"ret  KILL_PROCESS",
				"ld   [0]",
				"jge  #0x40000000, jt 0, jf 1",
				"ret  KILL_PROCESS",
				"jeq  #0x87, jt 0, jf 5", // personality
				"ld   [20]",
				"jeq  #0x1, jt 0, jf 3",
				"ld   [16]",
				"jeq  #0x8, jt 0, jf 1",
				"ret  ALLOW",
				"ret  KILL_PROCESS",
			},
		},
		{
			name: "not-equal predicate",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActErrno,
				Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
				Syscalls: []runtimespec.LinuxSyscall{
					{
						Names:  []string{"setuid"},
						Action: runtimespec.ActAllow,
						Args: []runtimespec.LinuxSeccompArg{
							{Index: 0, Value: 0, Op: runtimespec.OpNotEqual},
						},
					},
				},
			},
			want: []string{
				"ld   [4]",
				"jeq  #0xc000003e, jt 1, jf 0",
				"ret  ERRNO(1)",
				"ld   [0]",
				"jge  #0x40000000, jt 0, jf 1",
				"ret  ERRNO(1)",
				"jeq  #0x69, jt 0, jf 5", // setuid
				"ld   [20]",
				"jeq  #0x0, jt 0, jf 2",
				"ld   [16]",
				"jeq  #0x0, jt 1, jf 0",
				"ret  ALLOW",
				"ret  ERRNO(1)",
			},
		},
		{
			name: "ordered comparisons",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActErrno,
				Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
				Syscalls: []runtimespec.LinuxSyscall{
					{
						Names:  []string{"ioprio_set"},
						Action: runtimespec.ActAllow,
						Args: []runtimespec.LinuxSeccompArg{
							{Index: 1, Value: 4, Op: runtimespec.OpLessThan},
							{Index: 2, Value: 7, Op: runtimespec.OpGreaterEqual},
						},
					},
				},
			},
			want: []string{
				"ld   [4]",
				"jeq  #0xc000003e, jt 1, jf 0",
				"ret  ERRNO(1)",
				"ld   [0]",
				"jge  #0x40000000, jt 0, jf 1",
				"ret  ERRNO(1)",
				"jeq  #0xfb, jt 0, jf 11", // ioprio_set, 10 predicate insns + ret
				// args[1] < 4
				"ld   [28]",
				"jgt  #0x0, jt 9, jf 0",
				"jeq  #0x0, jt 0, jf 2",
				"ld   [24]",
				"jge  #0x4, jt 6, jf 0",
				// args[2] >= 7
				"ld   [36]",
				"jgt  #0x0, jt 3, jf 0",
				"jeq  #0x0, jt 0, jf 3",
				"ld   [32]",
				"jge  #0x7, jt 0, jf 1",
				"ret  ALLOW",
				"ret  ERRNO(1)",
			},
		},
		{
			name: "permissive default still kills a foreign architecture",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActAllow,
				Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
				Syscalls: []runtimespec.LinuxSyscall{
					{Names: []string{"keyctl"}, Action: runtimespec.ActErrno},
				},
			},
			want: []string{
				"ld   [4]",
				"jeq  #0xc000003e, jt 1, jf 0",
				"ret  KILL_PROCESS",
				"ld   [0]",
				"jge  #0x40000000, jt 0, jf 1",
				"ret  KILL_PROCESS",
				"jeq  #0xfa, jt 0, jf 1", // keyctl
				"ret  ERRNO(1)",
				"ret  ALLOW",
			},
		},
		{
			name: "unknown syscall names are skipped, not fatal",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActErrno,
				Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
				Syscalls: []runtimespec.LinuxSyscall{
					{Names: []string{"definitely_not_a_syscall", "close"}, Action: runtimespec.ActAllow},
				},
			},
			want: []string{
				"ld   [4]",
				"jeq  #0xc000003e, jt 1, jf 0",
				"ret  ERRNO(1)",
				"ld   [0]",
				"jge  #0x40000000, jt 0, jf 1",
				"ret  ERRNO(1)",
				"jeq  #0x3, jt 0, jf 1", // close
				"ret  ALLOW",
				"ret  ERRNO(1)",
			},
		},
	}

	tg := amd64Target(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := CompileSeccompFor(tc.profile, tg)
			if err != nil {
				t.Fatalf("CompileSeccompFor: %v", err)
			}
			got := make([]string, len(p.Insns))
			for i, in := range p.Insns {
				got[i] = in.String()
			}
			if len(got) != len(tc.want) {
				t.Fatalf("instruction count = %d, want %d\ngot:\n%s", len(got), len(tc.want), Disassemble(p.Insns))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("insn %d = %q, want %q\nfull program:\n%s", i, got[i], tc.want[i], Disassemble(p.Insns))
				}
			}
		})
	}
}

// TestCompileSeccompAArch64 checks the arm64 target uses the asm-generic
// numbering and emits no x32 guard.
func TestCompileSeccompAArch64(t *testing.T) {
	tg, ok := TargetForArch(runtimespec.ArchAARCH64)
	if !ok {
		t.Fatal("no aarch64 target")
	}
	p, err := CompileSeccompFor(&runtimespec.LinuxSeccomp{
		DefaultAction: runtimespec.ActErrno,
		Architectures: []runtimespec.Arch{runtimespec.ArchAARCH64},
		Syscalls:      []runtimespec.LinuxSyscall{{Names: []string{"openat"}, Action: runtimespec.ActAllow}},
	}, tg)
	if err != nil {
		t.Fatalf("CompileSeccompFor: %v", err)
	}
	want := []string{
		"ld   [4]",
		"jeq  #0xc00000b7, jt 1, jf 0",
		"ret  ERRNO(1)",
		"ld   [0]",
		"jeq  #0x38, jt 0, jf 1", // openat is 56 in the asm-generic numbering
		"ret  ALLOW",
		"ret  ERRNO(1)",
	}
	got := Disassemble(p.Insns)
	for i, w := range want {
		if i >= len(p.Insns) || p.Insns[i].String() != w {
			t.Fatalf("insn %d mismatch, want %q\n%s", i, w, got)
		}
	}
	if len(p.Insns) != len(want) {
		t.Fatalf("instruction count = %d, want %d\n%s", len(p.Insns), len(want), got)
	}
}

// TestCompileSeccompJumpOffsets asserts the structural invariant that makes
// arbitrarily large profiles safe: no jump offset may exceed 255, and no jump
// may leave the program.
func TestCompileSeccompJumpOffsets(t *testing.T) {
	tg := amd64Target(t)
	var names []string
	for name := range tg.table {
		names = append(names, name)
	}
	profile := &runtimespec.LinuxSeccomp{
		DefaultAction: runtimespec.ActErrno,
		Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
		Syscalls:      []runtimespec.LinuxSyscall{{Names: names, Action: runtimespec.ActAllow}},
	}
	p, err := CompileSeccompFor(profile, tg)
	if err != nil {
		t.Fatalf("CompileSeccompFor with %d syscalls: %v", len(names), err)
	}
	if p.Len() < len(names) {
		t.Fatalf("program of %d instructions is too short for %d syscalls", p.Len(), len(names))
	}
	for i, in := range p.Insns {
		if in.Code&0x07 != bpfJMP {
			continue
		}
		for _, off := range []uint8{in.JT, in.JF} {
			if target := i + 1 + int(off); target >= len(p.Insns) {
				t.Fatalf("insn %d jumps to %d, past the end of a %d-instruction program", i, target, len(p.Insns))
			}
		}
	}
	// Every path must end on a return.
	if p.Insns[len(p.Insns)-1].Code&0x07 != bpfRET {
		t.Fatalf("program does not end with a return: %s", p.Insns[len(p.Insns)-1])
	}
}

// TestCompileSeccompTooLarge checks the BPF_MAXINSNS guard produces an
// actionable error rather than an EINVAL from the kernel at container start.
func TestCompileSeccompTooLarge(t *testing.T) {
	tg := amd64Target(t)
	var rules []runtimespec.LinuxSyscall
	// Each rule with six argument predicates costs ~31 instructions; 200 of
	// them comfortably clears 4096.
	args := make([]runtimespec.LinuxSeccompArg, 6)
	for i := range args {
		args[i] = runtimespec.LinuxSeccompArg{Index: uint(i), Value: 1, Op: runtimespec.OpEqualTo}
	}
	for i := 0; i < 400; i++ {
		rules = append(rules, runtimespec.LinuxSyscall{
			Names:  []string{"read", "write", "openat", "close"},
			Action: runtimespec.ActAllow,
			Args:   args,
		})
	}
	_, err := CompileSeccompFor(&runtimespec.LinuxSeccomp{
		DefaultAction: runtimespec.ActErrno,
		Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
		Syscalls:      rules,
	}, tg)
	if !errors.Is(err, ErrFilterTooLarge) {
		t.Fatalf("err = %v, want ErrFilterTooLarge", err)
	}
	if !strings.Contains(err.Error(), "4096") {
		t.Errorf("error should name the limit: %v", err)
	}
}

func TestCompileSeccompErrors(t *testing.T) {
	tg := amd64Target(t)
	tests := []struct {
		name    string
		profile *runtimespec.LinuxSeccomp
		want    string
	}{
		{
			name:    "unknown action",
			profile: &runtimespec.LinuxSeccomp{DefaultAction: "SCMP_ACT_NONSENSE"},
			want:    "unknown seccomp action",
		},
		{
			name: "unknown operator",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActErrno,
				Syscalls: []runtimespec.LinuxSyscall{{
					Names:  []string{"read"},
					Action: runtimespec.ActAllow,
					Args:   []runtimespec.LinuxSeccompArg{{Index: 0, Op: "SCMP_CMP_WAT"}},
				}},
			},
			want: "unknown argument operator",
		},
		{
			name: "argument index out of range",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActErrno,
				Syscalls: []runtimespec.LinuxSyscall{{
					Names:  []string{"read"},
					Action: runtimespec.ActAllow,
					Args:   []runtimespec.LinuxSeccompArg{{Index: 9, Op: runtimespec.OpEqualTo}},
				}},
			},
			want: "out of range",
		},
		{
			name: "rule with no names",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActErrno,
				Syscalls:      []runtimespec.LinuxSyscall{{Action: runtimespec.ActAllow}},
			},
			want: "names no syscall",
		},
		{
			name: "errno does not fit",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActErrno, DefaultErrnoRet: uptr(1 << 20),
			},
			want: "16 bits",
		},
		{
			name: "unknown flag",
			profile: &runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActErrno,
				Flags:         []runtimespec.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_MAGIC"},
			},
			want: "unknown seccomp flag",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileSeccompFor(tc.profile, tg)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestSelectTarget(t *testing.T) {
	tests := []struct {
		name    string
		arches  []runtimespec.Arch
		wantErr bool
	}{
		{name: "empty list picks native", arches: nil},
		{name: "native listed", arches: []runtimespec.Arch{runtimespec.ArchX86, runtimespec.ArchX86_64}},
		{name: "only unsupported", arches: []runtimespec.Arch{runtimespec.ArchS390X, runtimespec.ArchPPC64LE}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SelectTarget(&runtimespec.LinuxSeccomp{
				DefaultAction: runtimespec.ActErrno,
				Architectures: tc.arches,
			})
			if tc.wantErr {
				if !errors.Is(err, ErrUnsupportedArch) {
					t.Fatalf("err = %v, want ErrUnsupportedArch", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("SelectTarget: %v", err)
			}
		})
	}
}

func TestSeccompFlags(t *testing.T) {
	tg := amd64Target(t)
	p, err := CompileSeccompFor(&runtimespec.LinuxSeccomp{
		DefaultAction: runtimespec.ActErrno,
		Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
		Flags: []runtimespec.LinuxSeccompFlag{
			runtimespec.FlagSpecAllow, runtimespec.FlagLog,
		},
	}, tg)
	if err != nil {
		t.Fatalf("CompileSeccompFor: %v", err)
	}
	if want := FilterFlagSpecAllow | FilterFlagLog; p.Flags != want {
		t.Fatalf("flags = %#x, want %#x", p.Flags, want)
	}
}

// TestSyscallTablesAgree spot-checks the generated tables against numbers that
// are fixed for the lifetime of the ABI.
func TestSyscallTablesAgree(t *testing.T) {
	amd64 := map[string]int{
		"read": 0, "write": 1, "open": 2, "close": 3, "execve": 59,
		"ptrace": 101, "keyctl": 250, "seccomp": 317, "openat2": 437,
		"clone3": 435, "close_range": 436, "pidfd_send_signal": 424,
	}
	for name, want := range amd64 {
		if got, ok := syscallsAMD64[name]; !ok || got != want {
			t.Errorf("syscallsAMD64[%q] = %d (present %v), want %d", name, got, ok, want)
		}
	}
	arm64 := map[string]int{
		"openat": 56, "close": 57, "execve": 221, "clone3": 435, "openat2": 437,
	}
	for name, want := range arm64 {
		if got, ok := syscallsARM64[name]; !ok || got != want {
			t.Errorf("syscallsARM64[%q] = %d (present %v), want %d", name, got, ok, want)
		}
	}
	if _, ok := syscallsAMD64["open"]; !ok {
		t.Error("x86-64 must have open")
	}
	if _, ok := syscallsARM64["open"]; ok {
		t.Error("arm64 has no open(2); the table should not invent one")
	}
}

func TestDisassembleRoundTrip(t *testing.T) {
	insns := []Instruction{ld(offNR), jeq(59, 0, 1), ret(RetAllow), ret(RetErrno | 1)}
	got := Disassemble(insns)
	for _, want := range []string{"000: ld   [0]", "001: jeq  #0x3b, jt 0, jf 1", "002: ret  ALLOW", "003: ret  ERRNO(1)"} {
		if !strings.Contains(got, want) {
			t.Errorf("disassembly missing %q:\n%s", want, got)
		}
	}
}

func TestArgOffsets(t *testing.T) {
	for i := uint(0); i < 6; i++ {
		lo, hi := argOffsets(i)
		if wantLo := uint32(16 + 8*i); lo != wantLo {
			t.Errorf("arg %d lo = %d, want %d", i, lo, wantLo)
		}
		if hi != lo+4 {
			t.Errorf("arg %d hi = %d, want %d", i, hi, lo+4)
		}
	}
}

func ExampleCompileSeccompFor() {
	tg, _ := TargetForArch(runtimespec.ArchX86_64)
	p, err := CompileSeccompFor(&runtimespec.LinuxSeccomp{
		DefaultAction: runtimespec.ActErrno,
		Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
		Syscalls:      []runtimespec.LinuxSyscall{{Names: []string{"exit_group"}, Action: runtimespec.ActAllow}},
	}, tg)
	if err != nil {
		panic(err)
	}
	fmt.Print(Disassemble(p.Insns))
	// Output:
	// 000: ld   [4]
	// 001: jeq  #0xc000003e, jt 1, jf 0
	// 002: ret  ERRNO(1)
	// 003: ld   [0]
	// 004: jge  #0x40000000, jt 0, jf 1
	// 005: ret  ERRNO(1)
	// 006: jeq  #0xe7, jt 0, jf 1
	// 007: ret  ALLOW
	// 008: ret  ERRNO(1)
}
