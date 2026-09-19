package seccompprof

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

func TestDefaultShape(t *testing.T) {
	p := Default()
	if p == nil {
		t.Fatal("Default() returned nil")
	}
	if p.DefaultAction != runtimespec.ActErrno {
		t.Errorf("DefaultAction = %q, want SCMP_ACT_ERRNO", p.DefaultAction)
	}
	if p.DefaultErrnoRet == nil || *p.DefaultErrnoRet != 1 {
		t.Errorf("DefaultErrnoRet = %v, want EPERM (1)", p.DefaultErrnoRet)
	}
	if len(p.Architectures) == 0 {
		t.Fatal("Default() named no architectures; a filter that omits the compat ABIs is bypassable")
	}
	if len(p.Syscalls) == 0 {
		t.Fatal("Default() has no rules")
	}
}

func TestDefaultReturnsFreshProfile(t *testing.T) {
	a := Default()
	a.Syscalls[0].Names[0] = "poisoned"
	a.Architectures[0] = "SCMP_ARCH_S390X"
	b := Default()
	if b.Syscalls[0].Names[0] == "poisoned" {
		t.Fatal("Default() shares its syscall name slice between calls")
	}
	if b.Architectures[0] == "SCMP_ARCH_S390X" {
		t.Fatal("Default() shares its architecture slice between calls")
	}
}

func TestEveryNameIsARealSyscall(t *testing.T) {
	profiles := map[string]*runtimespec.LinuxSeccomp{
		"default":      Default(),
		"sys_admin":    ForCapabilities([]string{"CAP_SYS_ADMIN"}, false),
		"kitchen_sink": ForCapabilities(allGatedCaps(), false),
	}
	for name, p := range profiles {
		for i, rule := range p.Syscalls {
			for _, n := range rule.Names {
				if !knownSyscalls[n] {
					t.Errorf("%s: syscalls[%d] names %q, which is not a Linux syscall", name, i, n)
				}
				if n != strings.ToLower(n) {
					t.Errorf("%s: syscall name %q is not lower case", name, n)
				}
			}
		}
	}
}

func TestAllowlistIsCompleteAndDeduplicated(t *testing.T) {
	names := Default().Syscalls[0].Names
	if len(names) < 300 {
		t.Fatalf("the unconditional allowlist has only %d syscalls; a short list breaks real images", len(names))
	}
	seen := map[string]int{}
	for _, n := range names {
		seen[n]++
		if seen[n] > 1 {
			t.Errorf("duplicate syscall %q in the allowlist", n)
		}
	}

	// A workload-critical sample that must be present. These are the ones a
	// too-conservative list tends to miss, and each one breaks something real.
	for _, must := range []string{
		"io_uring_setup", "io_uring_enter", "io_uring_register", // modern async I/O
		"openat2",     // hull's own path resolution, and systemd's
		"faccessat2",  // glibc 2.33+
		"close_range", // glibc 2.34+, and CVE-2024-21626 hygiene
		"statx",       // coreutils, Go 1.21+
		"membarrier",  // Go and Java runtimes
		"rseq",        // glibc 2.35+ on every thread start
		"futex_waitv", // glibc 2.35+, wine, proton
		"getrandom",   // every TLS stack
		"landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self",
		"epoll_pwait2", "signalfd4", "timerfd_settime64", "inotify_init1",
		"pidfd_open", "pidfd_send_signal", "pidfd_getfd",
		"copy_file_range", "memfd_create", "prlimit64",
		"clock_gettime64", "utimensat_time64", "ppoll_time64", // 32-bit time64 ABI
	} {
		if seen[must] == 0 {
			t.Errorf("allowlist is missing %q", must)
		}
	}

	// And a sample that must NOT be unconditionally allowed.
	for _, mustNot := range []string{
		"mount", "umount2", "pivot_root", "setns", "unshare", "chroot",
		"init_module", "finit_module", "delete_module", "bpf", "reboot",
		"kexec_load", "iopl", "ioperm", "syslog", "acct", "add_key", "keyctl",
		"clone", "clone3", "socket", "personality", "swapon", "userfaultfd",
		"process_vm_readv", "process_vm_writev", "kcmp", "perf_event_open",
		"open_by_handle_at", "settimeofday", "clock_settime", "adjtimex",
	} {
		if seen[mustNot] > 0 {
			t.Errorf("%q must not be on the unconditional allowlist", mustNot)
		}
	}
}

func TestConditionalRules(t *testing.T) {
	p := Default()

	clone := findRule(p, "clone", true)
	if clone == nil {
		t.Fatal("no conditional clone rule")
	}
	if clone.Action != runtimespec.ActAllow {
		t.Errorf("clone action = %q, want allow", clone.Action)
	}
	if len(clone.Args) != 1 {
		t.Fatalf("clone has %d args, want 1", len(clone.Args))
	}
	a := clone.Args[0]
	if a.Index != 0 || a.Op != runtimespec.OpMaskedEqual || a.ValueTwo != 0 {
		t.Errorf("clone arg = %+v, want index 0, masked_eq, valueTwo 0", a)
	}
	const wantMask = 0x7e020000 // NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET
	if a.Value != wantMask {
		t.Errorf("clone mask = %#x, want %#x", a.Value, uint64(wantMask))
	}
	if CloneNamespaceFlags != wantMask {
		t.Errorf("CloneNamespaceFlags = %#x, want %#x", CloneNamespaceFlags, uint64(wantMask))
	}

	clone3 := findRule(p, "clone3", false)
	if clone3 == nil {
		t.Fatal("no clone3 rule")
	}
	if clone3.Action != runtimespec.ActErrno {
		t.Errorf("clone3 action = %q, want errno", clone3.Action)
	}
	if clone3.ErrnoRet == nil || *clone3.ErrnoRet != 38 {
		t.Errorf("clone3 errnoRet = %v, want ENOSYS (38) so glibc falls back to clone", clone3.ErrnoRet)
	}

	sock := findRule(p, "socket", true)
	if sock == nil {
		t.Fatal("no conditional socket rule")
	}
	if len(sock.Args) != 1 || sock.Args[0].Index != 0 ||
		sock.Args[0].Op != runtimespec.OpNotEqual || sock.Args[0].Value != 40 {
		t.Errorf("socket rule = %+v, want arg0 != 40 (AF_VSOCK)", sock.Args)
	}

	if r := findRule(p, "ptrace", false); r == nil || r.Action != runtimespec.ActAllow {
		t.Error("ptrace should be allowed unconditionally on kernels >= 4.8")
	}

	// personality: one rule per permitted value, all ANDed args are single.
	want := map[uint64]bool{0x0: true, 0x8: true, 0x20000: true, 0x20008: true, 0xffffffff: true}
	got := map[uint64]bool{}
	for _, r := range p.Syscalls {
		if len(r.Names) == 1 && r.Names[0] == "personality" {
			if len(r.Args) != 1 || r.Args[0].Op != runtimespec.OpEqualTo || r.Args[0].Index != 0 {
				t.Errorf("personality rule %+v is not a single arg0 equality", r.Args)
				continue
			}
			got[r.Args[0].Value] = true
		}
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("personality values = %v, want %v", got, want)
	}
}

func TestForCapabilities(t *testing.T) {
	tests := []struct {
		name       string
		caps       []string
		privileged bool
		wantNil    bool
		wantAllow  []string
		wantAbsent []string
	}{
		{
			name:       "privileged means no filter at all",
			caps:       []string{"CAP_SYS_ADMIN"},
			privileged: true,
			wantNil:    true,
		},
		{
			name:       "default caps unlock only chroot",
			caps:       []string{"CAP_CHOWN", "CAP_SYS_CHROOT"},
			wantAllow:  []string{"chroot"},
			wantAbsent: []string{"mount", "bpf", "reboot", "syslog", "acct"},
		},
		{
			name: "sys_admin unlocks the mount and namespace family",
			caps: []string{"sys_admin"},
			wantAllow: []string{
				"mount", "umount2", "pivot_root", "setns", "unshare",
				"open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick",
			},
			wantAbsent: []string{"init_module", "reboot", "iopl"},
		},
		{
			name:      "sys_module",
			caps:      []string{"CAP_SYS_MODULE"},
			wantAllow: []string{"init_module", "finit_module", "delete_module"},
		},
		{
			name:      "sys_time",
			caps:      []string{"cap_sys_time"},
			wantAllow: []string{"clock_settime", "adjtimex"},
		},
		{
			name:      "sys_ptrace",
			caps:      []string{"SYS_PTRACE"},
			wantAllow: []string{"process_vm_readv", "process_vm_writev", "kcmp"},
		},
		{
			name:      "sys_boot",
			caps:      []string{"CAP_SYS_BOOT"},
			wantAllow: []string{"reboot"},
		},
		{
			name:      "sys_rawio",
			caps:      []string{"CAP_SYS_RAWIO"},
			wantAllow: []string{"iopl", "ioperm"},
		},
		{
			name:      "syslog",
			caps:      []string{"CAP_SYSLOG"},
			wantAllow: []string{"syslog"},
		},
		{
			name:      "sys_pacct",
			caps:      []string{"CAP_SYS_PACCT"},
			wantAllow: []string{"acct"},
		},
		{
			name:      "sys_nice",
			caps:      []string{"CAP_SYS_NICE"},
			wantAllow: []string{"get_mempolicy", "set_mempolicy", "mbind", "migrate_pages", "move_pages"},
		},
		{
			name:       "net_admin alone does not unlock bpf",
			caps:       []string{"CAP_NET_ADMIN"},
			wantAbsent: []string{"bpf"},
		},
		{
			name:      "net_admin plus bpf unlocks bpf",
			caps:      []string{"CAP_NET_ADMIN", "CAP_BPF"},
			wantAllow: []string{"bpf"},
		},
		{
			name:       "no caps at all",
			caps:       nil,
			wantAbsent: []string{"mount", "chroot", "bpf", "reboot", "acct", "syslog"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := ForCapabilities(tc.caps, tc.privileged)
			if tc.wantNil {
				if p != nil {
					t.Fatal("privileged container must get a nil profile")
				}
				return
			}
			if p == nil {
				t.Fatal("ForCapabilities returned nil for an unprivileged container")
			}
			allowed := allowedNames(p)
			for _, n := range tc.wantAllow {
				if !allowed[n] {
					t.Errorf("%q should be allowed for caps %v", n, tc.caps)
				}
			}
			for _, n := range tc.wantAbsent {
				if allowed[n] {
					t.Errorf("%q must not be allowed for caps %v", n, tc.caps)
				}
			}
		})
	}
}

func TestSysAdminRelaxesCloneAndSocket(t *testing.T) {
	p := ForCapabilities([]string{"CAP_SYS_ADMIN"}, false)
	for _, name := range []string{"clone", "socket"} {
		if r := findRule(p, name, true); r != nil {
			t.Errorf("%s still carries an argument predicate under CAP_SYS_ADMIN: %+v", name, r.Args)
		}
		r := findRuleContaining(p, name)
		if r == nil || r.Action != runtimespec.ActAllow {
			t.Errorf("%s should be allowed unconditionally under CAP_SYS_ADMIN", name)
		}
	}
	// clone3 stays ENOSYS: glibc must keep falling back to clone.
	if r := findRule(p, "clone3", false); r == nil || r.Action != runtimespec.ActErrno {
		t.Error("clone3 must stay ENOSYS even with CAP_SYS_ADMIN")
	}
}

func TestDefaultRoundTripsThroughJSON(t *testing.T) {
	orig := Default()
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var back runtimespec.LinuxSeccomp
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(*orig, back) {
		t.Fatal("Default() does not survive a JSON round trip through the runtime spec")
	}

	// It must also round-trip through the Docker profile format hull reads,
	// which is what `hull inspect` and a user editing the profile would do.
	again, err := LoadProfile(data, nil)
	if err != nil {
		t.Fatalf("LoadProfile on our own default profile: %v", err)
	}
	if again.DefaultAction != orig.DefaultAction {
		t.Errorf("round trip changed defaultAction: %q vs %q", again.DefaultAction, orig.DefaultAction)
	}
	if again.DefaultErrnoRet == nil || *again.DefaultErrnoRet != *orig.DefaultErrnoRet {
		t.Errorf("round trip lost defaultErrnoRet")
	}
	if !reflect.DeepEqual(again.Architectures, orig.Architectures) {
		t.Errorf("round trip changed architectures: %v vs %v", again.Architectures, orig.Architectures)
	}
	if !reflect.DeepEqual(again.Syscalls, orig.Syscalls) {
		t.Errorf("round trip changed the rule set")
	}

	// The serialized form must use the spec's key names, not Go field names.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"defaultAction", "defaultErrnoRet", "architectures", "syscalls"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("serialized profile has no %q key", k)
		}
	}
}

func TestUnconfinedIsNil(t *testing.T) {
	if Unconfined() != nil {
		t.Fatal("Unconfined() must be nil; hull never installs an allow-everything filter")
	}
}

func TestArchitecturesCoverCompatABIs(t *testing.T) {
	got := Architectures()
	if len(got) == 0 {
		t.Fatal("no architectures")
	}
	seen := map[runtimespec.Arch]bool{}
	for _, a := range got {
		seen[a] = true
	}
	switch {
	case seen[runtimespec.ArchX86_64]:
		if !seen[runtimespec.ArchX86] || !seen[runtimespec.ArchX32] {
			t.Errorf("x86_64 profile must also name X86 and X32, got %v", got)
		}
	case seen[runtimespec.ArchAARCH64]:
		if !seen[runtimespec.ArchARM] {
			t.Errorf("aarch64 profile must also name ARM, got %v", got)
		}
	}
}

func TestGatedSyscalls(t *testing.T) {
	tests := []struct {
		in   string
		want string // one name that must be present; "" means expect nil
	}{
		{"CAP_SYS_MODULE", "init_module"},
		{"sys_module", "init_module"},
		{"CAP_SYS_BOOT", "reboot"},
		{"CAP_CHOWN", ""},
		{"not_a_cap", ""},
	}
	for _, tc := range tests {
		got := GatedSyscalls(tc.in)
		if tc.want == "" {
			if got != nil {
				t.Errorf("GatedSyscalls(%q) = %v, want nil", tc.in, got)
			}
			continue
		}
		found := false
		for _, n := range got {
			if n == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("GatedSyscalls(%q) = %v, want it to contain %q", tc.in, got, tc.want)
		}
	}
}

// ---------- helpers ----------

// findRule returns the first single-name rule for name, optionally requiring
// that it carries argument predicates.
func findRule(p *runtimespec.LinuxSeccomp, name string, withArgs bool) *runtimespec.LinuxSyscall {
	for i := range p.Syscalls {
		r := &p.Syscalls[i]
		if len(r.Names) == 1 && r.Names[0] == name && (len(r.Args) > 0) == withArgs {
			return r
		}
	}
	return nil
}

// findRuleContaining returns the first rule whose name list contains name.
func findRuleContaining(p *runtimespec.LinuxSeccomp, name string) *runtimespec.LinuxSyscall {
	for i := range p.Syscalls {
		for _, n := range p.Syscalls[i].Names {
			if n == name {
				return &p.Syscalls[i]
			}
		}
	}
	return nil
}

// allowedNames is the set of syscalls a profile allows without any argument
// predicate — the question "can the container call this at all".
func allowedNames(p *runtimespec.LinuxSeccomp) map[string]bool {
	m := map[string]bool{}
	for _, r := range p.Syscalls {
		if r.Action != runtimespec.ActAllow || len(r.Args) > 0 {
			continue
		}
		for _, n := range r.Names {
			m[n] = true
		}
	}
	return m
}

// allGatedCaps is every capability that unlocks something, for the
// kitchen-sink profile the syscall-name check runs over.
func allGatedCaps() []string {
	out := make([]string, 0, len(capGates)+1)
	for _, g := range capGates {
		out = append(out, g.cap)
		if g.alsoNeeds != "" {
			out = append(out, g.alsoNeeds)
		}
	}
	return out
}
