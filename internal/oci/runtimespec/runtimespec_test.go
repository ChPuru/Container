package runtimespec

import (
	"encoding/json"
	"strings"
	"testing"
)

func ptrI64(v int64) *int64   { return &v }
func ptrU64(v uint64) *uint64 { return &v }
func ptrInt(v int) *int       { return &v }

func TestDefaultSpecValidates(t *testing.T) {
	s := DefaultSpec()
	if err := s.Validate(); err != nil {
		t.Fatalf("DefaultSpec().Validate() = %v, want nil", err)
	}
	if s.Version != "1.2.0" {
		t.Errorf("Version = %q, want 1.2.0", s.Version)
	}
	if s.Process == nil || !s.Process.NoNewPrivileges {
		t.Error("DefaultSpec must set noNewPrivileges; seccomp without it is a privilege-escalation hazard")
	}
}

func TestDefaultSpecMounts(t *testing.T) {
	want := []string{"/proc", "/dev", "/dev/pts", "/dev/shm", "/dev/mqueue", "/sys", "/sys/fs/cgroup"}
	got := make(map[string]Mount)
	for _, m := range DefaultSpec().Mounts {
		got[m.Destination] = m
	}
	for _, dest := range want {
		m, ok := got[dest]
		if !ok {
			t.Fatalf("DefaultSpec is missing the %s mount", dest)
		}
		if m.Type == "" || m.Source == "" {
			t.Errorf("mount %s has an empty type or source: %+v", dest, m)
		}
	}
	if len(got) != len(want) {
		t.Errorf("DefaultSpec has %d mounts, want %d", len(got), len(want))
	}
}

func TestDefaultSpecPathLists(t *testing.T) {
	s := DefaultSpec()
	for _, p := range []string{"/proc/kcore", "/proc/keys", "/sys/firmware", "/proc/timer_list"} {
		if !contains(s.Linux.MaskedPaths, p) {
			t.Errorf("MaskedPaths is missing %s", p)
		}
	}
	for _, p := range []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"} {
		if !contains(s.Linux.ReadonlyPaths, p) {
			t.Errorf("ReadonlyPaths is missing %s", p)
		}
	}
	for _, ns := range []LinuxNamespaceType{PIDNamespace, NetworkNamespace, IPCNamespace, UTSNamespace, MountNamespace} {
		found := false
		for _, have := range s.Linux.Namespaces {
			if have.Type == ns {
				found = true
			}
		}
		if !found {
			t.Errorf("default namespaces are missing %q", ns)
		}
	}
}

func TestDefaultSpecIsFreshlyAllocated(t *testing.T) {
	a, b := DefaultSpec(), DefaultSpec()
	a.Mounts[0].Destination = "/mutated"
	a.Linux.MaskedPaths[0] = "/mutated"
	a.Process.Capabilities.Bounding[0] = "CAP_MUTATED"
	if b.Mounts[0].Destination == "/mutated" ||
		b.Linux.MaskedPaths[0] == "/mutated" ||
		b.Process.Capabilities.Bounding[0] == "CAP_MUTATED" {
		t.Error("DefaultSpec shares backing arrays between calls")
	}
}

func TestSpecJSONRoundTrip(t *testing.T) {
	s := DefaultSpec()
	s.Root.Path = "/var/lib/hull/containers/abc/merged"
	s.Linux.Resources.Memory = &LinuxMemory{Limit: ptrI64(1 << 30)}
	s.Linux.Resources.CPU = &LinuxCPU{Shares: ptrU64(512), Quota: ptrI64(100000), Period: ptrU64(100000)}
	s.Linux.Resources.Pids = &LinuxPids{Limit: 100}

	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Spec
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("round-tripped spec failed validation: %v", err)
	}
	if back.Root.Path != s.Root.Path {
		t.Errorf("root.path = %q, want %q", back.Root.Path, s.Root.Path)
	}
	if back.Linux.Resources.Memory.Limit == nil || *back.Linux.Resources.Memory.Limit != 1<<30 {
		t.Errorf("memory.limit lost in round trip: %+v", back.Linux.Resources.Memory)
	}
	if !strings.Contains(string(b), `"ociVersion"`) {
		t.Errorf("spec JSON does not use the ociVersion key: %s", b)
	}
}

func TestUnsetOptionalNumericsAreOmitted(t *testing.T) {
	s := &Spec{
		Version: Version,
		Root:    &Root{Path: "rootfs"},
		Process: &Process{Args: []string{"/bin/true"}, Cwd: "/"},
		Linux: &Linux{
			Resources: &LinuxResources{
				Memory: &LinuxMemory{},
				CPU:    &LinuxCPU{},
			},
		},
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"limit", "swap", "shares", "quota", "period", "oomScoreAdj", "consoleSize", "umask"} {
		if strings.Contains(string(b), `"`+key+`"`) {
			t.Errorf("unset optional field %q was emitted: %s", key, b)
		}
	}
	// A zero pids limit is required by the spec, so it must NOT be omitted.
	pb, err := json.Marshal(LinuxPids{})
	if err != nil {
		t.Fatal(err)
	}
	if string(pb) != `{"limit":0}` {
		t.Errorf("LinuxPids{} = %s, want {\"limit\":0}", pb)
	}
}

func TestValidate(t *testing.T) {
	valid := func(mut func(*Spec)) *Spec {
		s := DefaultSpec()
		s.Root.Path = "/rootfs"
		if mut != nil {
			mut(s)
		}
		return s
	}
	tests := []struct {
		name    string
		spec    *Spec
		wantErr string
	}{
		{name: "default is valid", spec: valid(nil)},
		{name: "nil spec", spec: nil, wantErr: "nil spec"},
		{
			name:    "empty version",
			spec:    valid(func(s *Spec) { s.Version = "" }),
			wantErr: "ociVersion is empty",
		},
		{
			name:    "unsupported version",
			spec:    valid(func(s *Spec) { s.Version = "2.0.0" }),
			wantErr: "unsupported ociVersion",
		},
		{
			name:    "no root",
			spec:    valid(func(s *Spec) { s.Root = nil }),
			wantErr: "root is required",
		},
		{
			name:    "empty root path",
			spec:    valid(func(s *Spec) { s.Root.Path = "" }),
			wantErr: "root.path is empty",
		},
		{
			name:    "no process",
			spec:    valid(func(s *Spec) { s.Process = nil }),
			wantErr: "process is required",
		},
		{
			name:    "no args",
			spec:    valid(func(s *Spec) { s.Process.Args = nil }),
			wantErr: "process.args is empty",
		},
		{
			name:    "commandLine substitutes for args",
			spec:    valid(func(s *Spec) { s.Process.Args = nil; s.Process.CommandLine = "cmd.exe" }),
			wantErr: "",
		},
		{
			name:    "relative cwd",
			spec:    valid(func(s *Spec) { s.Process.Cwd = "srv" }),
			wantErr: "must be an absolute, clean path",
		},
		{
			name:    "dot dot cwd",
			spec:    valid(func(s *Spec) { s.Process.Cwd = "/srv/../etc" }),
			wantErr: "must be an absolute, clean path",
		},
		{
			name:    "env without equals",
			spec:    valid(func(s *Spec) { s.Process.Env = []string{"BROKEN"} }),
			wantErr: "is not KEY=VALUE",
		},
		{
			name:    "env with empty name",
			spec:    valid(func(s *Spec) { s.Process.Env = []string{"=v"} }),
			wantErr: "empty variable name",
		},
		{
			name:    "rlimit bad type",
			spec:    valid(func(s *Spec) { s.Process.Rlimits = []POSIXRlimit{{Type: "NOFILE", Hard: 1, Soft: 1}} }),
			wantErr: "must start with RLIMIT_",
		},
		{
			name:    "rlimit soft over hard",
			spec:    valid(func(s *Spec) { s.Process.Rlimits = []POSIXRlimit{{Type: "RLIMIT_NOFILE", Hard: 1, Soft: 2}} }),
			wantErr: "exceeds hard",
		},
		{
			name:    "capability without prefix",
			spec:    valid(func(s *Spec) { s.Process.Capabilities.Bounding = []string{"CHOWN"} }),
			wantErr: "must start with CAP_",
		},
		{
			name:    "lowercase capability",
			spec:    valid(func(s *Spec) { s.Process.Capabilities.Ambient = []string{"CAP_chown"} }),
			wantErr: "must be upper case",
		},
		{
			name:    "relative mount destination",
			spec:    valid(func(s *Spec) { s.Mounts = append(s.Mounts, Mount{Destination: "etc"}) }),
			wantErr: "must be an absolute, clean path",
		},
		{
			name:    "traversal mount destination",
			spec:    valid(func(s *Spec) { s.Mounts = append(s.Mounts, Mount{Destination: "/a/../../etc"}) }),
			wantErr: "must be an absolute, clean path",
		},
		{
			name:    "duplicate mount destination",
			spec:    valid(func(s *Spec) { s.Mounts = append(s.Mounts, Mount{Destination: "/proc", Type: "proc"}) }),
			wantErr: "duplicates mounts",
		},
		{
			name:    "unknown namespace",
			spec:    valid(func(s *Spec) { s.Linux.Namespaces = append(s.Linux.Namespaces, LinuxNamespace{Type: "bogus"}) }),
			wantErr: "is not a known namespace type",
		},
		{
			name:    "duplicate namespace",
			spec:    valid(func(s *Spec) { s.Linux.Namespaces = append(s.Linux.Namespaces, LinuxNamespace{Type: PIDNamespace}) }),
			wantErr: "duplicate",
		},
		{
			name: "id mappings without userns",
			spec: valid(func(s *Spec) {
				s.Linux.UIDMappings = []LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}
			}),
			wantErr: "require a user namespace",
		},
		{
			name: "id mappings with userns",
			spec: valid(func(s *Spec) {
				s.Linux.Namespaces = append(s.Linux.Namespaces, LinuxNamespace{Type: UserNamespace})
				s.Linux.UIDMappings = []LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}
				s.Linux.GIDMappings = []LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}
			}),
			wantErr: "",
		},
		{
			name: "zero-size id mapping",
			spec: valid(func(s *Spec) {
				s.Linux.Namespaces = append(s.Linux.Namespaces, LinuxNamespace{Type: UserNamespace})
				s.Linux.UIDMappings = []LinuxIDMapping{{Size: 0}}
			}),
			wantErr: "size must be non-zero",
		},
		{
			name:    "relative masked path",
			spec:    valid(func(s *Spec) { s.Linux.MaskedPaths = []string{"proc/kcore"} }),
			wantErr: "must be an absolute, clean path",
		},
		{
			name:    "bad device type",
			spec:    valid(func(s *Spec) { s.Linux.Devices = []LinuxDevice{{Path: "/dev/x", Type: "z"}} }),
			wantErr: "must be one of c, b, u, p",
		},
		{
			name:    "bad propagation",
			spec:    valid(func(s *Spec) { s.Linux.RootfsPropagation = "sideways" }),
			wantErr: "not a valid propagation mode",
		},
		{
			name:    "zero cpu period",
			spec:    valid(func(s *Spec) { s.Linux.Resources.CPU = &LinuxCPU{Period: ptrU64(0)} }),
			wantErr: "cpu.period must be non-zero",
		},
		{
			name:    "quota without period",
			spec:    valid(func(s *Spec) { s.Linux.Resources.CPU = &LinuxCPU{Quota: ptrI64(50000)} }),
			wantErr: "quota set without cpu.period",
		},
		{
			name: "swap below limit",
			spec: valid(func(s *Spec) {
				s.Linux.Resources.Memory = &LinuxMemory{Limit: ptrI64(100), Swap: ptrI64(50)}
			}),
			wantErr: "is less than memory.limit",
		},
		{
			name: "swappiness out of range",
			spec: valid(func(s *Spec) {
				s.Linux.Resources.Memory = &LinuxMemory{Swappiness: ptrU64(101)}
			}),
			wantErr: "out of range 0-100",
		},
		{
			name: "bad device cgroup access",
			spec: valid(func(s *Spec) {
				s.Linux.Resources.Devices = []LinuxDeviceCgroup{{Allow: true, Type: "c", Access: "rwx"}}
			}),
			wantErr: "may only contain r, w, m",
		},
		{
			name:    "hook with relative path",
			spec:    valid(func(s *Spec) { s.Hooks = &Hooks{Poststop: []Hook{{Path: "cleanup.sh"}}} }),
			wantErr: "must be an absolute, clean path",
		},
		{
			name:    "hook with non-positive timeout",
			spec:    valid(func(s *Spec) { s.Hooks = &Hooks{Poststop: []Hook{{Path: "/c.sh", Timeout: ptrInt(0)}}} }),
			wantErr: "timeout must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSeccomp(t *testing.T) {
	base := func(sc *LinuxSeccomp) *Spec {
		s := DefaultSpec()
		s.Root.Path = "/rootfs"
		s.Linux.Seccomp = sc
		return s
	}
	tests := []struct {
		name    string
		sc      *LinuxSeccomp
		wantErr string
	}{
		{
			name: "valid allowlist",
			sc: &LinuxSeccomp{
				DefaultAction: ActErrno,
				Architectures: []Arch{ArchX86_64, ArchX86},
				Syscalls: []LinuxSyscall{
					{Names: []string{"read", "write"}, Action: ActAllow},
					{
						Names:  []string{"clone"},
						Action: ActAllow,
						Args:   []LinuxSeccompArg{{Index: 0, Value: 0x7e020000, ValueTwo: 0, Op: OpMaskedEqual}},
					},
				},
			},
		},
		{name: "empty default action", sc: &LinuxSeccomp{}, wantErr: "defaultAction is empty"},
		{
			name:    "unknown default action",
			sc:      &LinuxSeccomp{DefaultAction: "SCMP_ACT_NOPE"},
			wantErr: "is not a known SCMP_ACT_",
		},
		{
			name:    "bad arch",
			sc:      &LinuxSeccomp{DefaultAction: ActErrno, Architectures: []Arch{"X86_64"}},
			wantErr: "must start with SCMP_ARCH_",
		},
		{
			name:    "notify without listener",
			sc:      &LinuxSeccomp{DefaultAction: ActNotify},
			wantErr: "no listenerPath is set",
		},
		{
			name: "notify rule without listener",
			sc: &LinuxSeccomp{
				DefaultAction: ActErrno,
				Syscalls:      []LinuxSyscall{{Names: []string{"mount"}, Action: ActNotify}},
			},
			wantErr: "no listenerPath is set",
		},
		{
			name: "notify with listener",
			sc: &LinuxSeccomp{
				DefaultAction: ActErrno,
				ListenerPath:  "/var/lib/hull/seccomp.sock",
				Syscalls:      []LinuxSyscall{{Names: []string{"mount"}, Action: ActNotify}},
			},
		},
		{
			name: "empty names",
			sc: &LinuxSeccomp{
				DefaultAction: ActErrno,
				Syscalls:      []LinuxSyscall{{Action: ActAllow}},
			},
			wantErr: "names is empty",
		},
		{
			name: "arg index out of range",
			sc: &LinuxSeccomp{
				DefaultAction: ActErrno,
				Syscalls: []LinuxSyscall{
					{Names: []string{"x"}, Action: ActAllow, Args: []LinuxSeccompArg{{Index: 6, Op: OpEqualTo}}},
				},
			},
			wantErr: "out of range 0-5",
		},
		{
			name: "bad operator",
			sc: &LinuxSeccomp{
				DefaultAction: ActErrno,
				Syscalls: []LinuxSyscall{
					{Names: []string{"x"}, Action: ActAllow, Args: []LinuxSeccompArg{{Index: 0, Op: "SCMP_CMP_WAT"}}},
				},
			},
			wantErr: "is not a known SCMP_CMP_",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := base(tt.sc).Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSeccompJSONNames(t *testing.T) {
	sc := LinuxSeccomp{
		DefaultAction:   ActErrno,
		DefaultErrnoRet: func() *uint { v := uint(38); return &v }(),
		Architectures:   []Arch{ArchX86_64},
		Flags:           []LinuxSeccompFlag{FlagLog},
		Syscalls:        []LinuxSyscall{{Names: []string{"read"}, Action: ActAllow}},
	}
	b, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"defaultAction":"SCMP_ACT_ERRNO"`, `"defaultErrnoRet":38`, `"architectures":["SCMP_ARCH_X86_64"]`, `"flags":["SECCOMP_FILTER_FLAG_LOG"]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("seccomp JSON %s does not contain %s", b, want)
		}
	}
}

func TestIsAbsClean(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"/", true},
		{"/proc", true},
		{"/dev/pts", true},
		{"", false},
		{"proc", false},
		{"/proc/", false},
		{"//proc", false},
		{"/proc/./x", false},
		{"/proc/../etc", false},
		{"/a\x00b", false},
	}
	for _, tt := range tests {
		if got := isAbsClean(tt.in); got != tt.want {
			t.Errorf("isAbsClean(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
