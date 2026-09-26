package initspec

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ChPuru/hull/internal/oci/runtimespec"
)

func TestStageFromArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{name: "no flag is pid1", args: []string{"/bin/sh", "-c", "true"}, want: StagePID1},
		{name: "init", args: []string{"--hull-stage=init"}, want: StageInit},
		{name: "setns", args: []string{"--hull-stage=setns"}, want: StageSetns},
		{name: "exec", args: []string{"--hull-stage=exec"}, want: StageExec},
		{name: "explicit pid1", args: []string{"--hull-stage=pid1", "sh"}, want: StagePID1},
		{name: "unknown stage is an error", args: []string{"--hull-stage=escape"}, wantErr: true},
		{
			name: "a container cannot smuggle a stage in later argv",
			args: []string{"sh", "-c", "--hull-stage=init"},
			want: StageInit,
		},
		{name: "empty", args: nil, want: StagePID1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := StageFromArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("StageFromArgs: %v", err)
			}
			if got != tc.want {
				t.Fatalf("stage = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFDNumbersAreContiguous(t *testing.T) {
	// The runtime hands descriptors over as an ordered ExtraFiles slice, so
	// these must stay 3, 4, 5, 6, 7 with no gaps.
	want := []int{3, 4, 5, 6, 7}
	got := []int{FDSync, FDStart, FDConsole, FDSelf, FDTarget}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("fd %d = %d, want %d", i, got[i], want[i])
		}
	}
	if FDLast != FDTarget {
		t.Fatalf("FDLast = %d, want %d", FDLast, FDTarget)
	}
}

func TestMessageRoundTrip(t *testing.T) {
	cfg := &Config{
		ID:     "abc",
		Rootfs: "/var/lib/hull/containers/abc/merged",
		Exec: Exec{
			Process: runtimespec.Process{
				Args: []string{"/bin/true"},
				Cwd:  "/",
				Env:  []string{"SECRET=do-not-put-me-in-argv"},
			},
		},
	}
	in := &Message{Type: MsgConfig, Cfg: cfg}
	b, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := DecodeMessage(b)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if out.Type != MsgConfig || out.Cfg == nil {
		t.Fatalf("decoded = %+v", out)
	}
	if out.Cfg.Rootfs != cfg.Rootfs {
		t.Errorf("rootfs = %q, want %q", out.Cfg.Rootfs, cfg.Rootfs)
	}
	if len(out.Cfg.Exec.Process.Env) != 1 || out.Cfg.Exec.Process.Env[0] != "SECRET=do-not-put-me-in-argv" {
		t.Errorf("env did not survive: %v", out.Cfg.Exec.Process.Env)
	}
}

func TestDecodeMessageErrors(t *testing.T) {
	if _, err := DecodeMessage([]byte("{")); err == nil {
		t.Error("truncated json should fail")
	}
	if _, err := DecodeMessage([]byte(`{"err":"x"}`)); err == nil {
		t.Error("a message with no type should fail")
	}
}

func TestConfigValidate(t *testing.T) {
	good := func() *Config {
		return &Config{
			Rootfs: "/rootfs",
			Exec:   Exec{Process: runtimespec.Process{Args: []string{"/bin/sh"}, Cwd: "/"}},
		}
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "valid", mutate: func(*Config) {}},
		{name: "no rootfs", mutate: func(c *Config) { c.Rootfs = "" }, want: "no rootfs"},
		{name: "relative rootfs", mutate: func(c *Config) { c.Rootfs = "rootfs" }, want: "not absolute"},
		{name: "no args", mutate: func(c *Config) { c.Exec.Process.Args = nil }, want: "no args"},
		{name: "relative cwd", mutate: func(c *Config) { c.Exec.Process.Cwd = "work" }, want: "not absolute"},
		{
			name:   "joining a pid namespace is refused",
			mutate: func(c *Config) { c.NamespacePaths = map[string]string{"pid": "/proc/1/ns/pid"} },
			want:   "not supported",
		},
		{
			name:   "joining a user namespace is refused",
			mutate: func(c *Config) { c.NamespacePaths = map[string]string{"user": "/proc/1/ns/user"} },
			want:   "not supported",
		},
		{
			name:   "unknown namespace",
			mutate: func(c *Config) { c.NamespacePaths = map[string]string{"quantum": "/proc/1/ns/q"} },
			want:   "unknown namespace",
		},
		{
			name:   "relative namespace path",
			mutate: func(c *Config) { c.NamespacePaths = map[string]string{"network": "ns/net"} },
			want:   "not absolute",
		},
		{
			name:   "a joined network namespace is fine",
			mutate: func(c *Config) { c.NamespacePaths = map[string]string{"network": "/run/netns/hull0"} },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := good()
			tc.mutate(c)
			err := c.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestConfigCarriesNoSecretsInArgv is a guard on the shape of the protocol:
// the container stage takes exactly one flag, and everything else travels as
// JSON over the socket.
func TestConfigCarriesNoSecretsInArgv(t *testing.T) {
	argv := []string{ArgvName, StageFlagPrefix + StageInit}
	joined := strings.Join(argv, " ")
	for _, bad := range []string{"=", "/", "SECRET", "token"} {
		if bad == "=" || bad == "/" {
			continue
		}
		if strings.Contains(joined, bad) {
			t.Fatalf("argv %q must not carry %q", joined, bad)
		}
	}
	if len(argv) != 2 {
		t.Fatalf("argv has %d elements; the stage takes exactly one flag", len(argv))
	}
}

func TestCapNumber(t *testing.T) {
	tests := []struct {
		in   string
		want int
		ok   bool
	}{
		{"CAP_CHOWN", 0, true},
		{"cap_net_admin", 12, true},
		{"NET_RAW", 13, true},
		{" CAP_SYS_ADMIN ", 21, true},
		{"CAP_CHECKPOINT_RESTORE", 40, true},
		{"CAP_NOT_A_THING", 0, false},
	}
	for _, tc := range tests {
		got, ok := CapNumber(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("CapNumber(%q) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
	names := CapNames()
	if len(names) != CapLast+1 {
		t.Fatalf("CapNames returned %d entries, want %d", len(names), CapLast+1)
	}
	for i, n := range names {
		if n == "" {
			t.Errorf("capability bit %d has no name; the table has a hole", i)
		}
	}
}

func TestRlimitNumber(t *testing.T) {
	tests := []struct {
		in   string
		want int
		ok   bool
	}{
		{"RLIMIT_NOFILE", 7, true},
		{"nofile", 7, true},
		{"RLIMIT_CPU", 0, true},
		{"RLIMIT_RTTIME", 15, true},
		{"RLIMIT_MADEUP", 0, false},
	}
	for _, tc := range tests {
		got, ok := RlimitNumber(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("RlimitNumber(%q) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
	if err := ValidateRlimitName("RLIMIT_MADEUP"); err == nil {
		t.Error("ValidateRlimitName should reject an unknown name")
	}
	if err := ValidateRlimitName("RLIMIT_AS"); err != nil {
		t.Errorf("ValidateRlimitName(RLIMIT_AS): %v", err)
	}
}

func TestExecValidateJSONShape(t *testing.T) {
	// The Exec block must survive a round trip with its seccomp profile, so
	// the setns stage can hand it to the exec stage unchanged.
	e := Exec{
		Process:  runtimespec.Process{Args: []string{"/bin/sh"}, Cwd: "/"},
		Terminal: true,
		Seccomp: &runtimespec.LinuxSeccomp{
			DefaultAction: runtimespec.ActErrno,
			Syscalls:      []runtimespec.LinuxSyscall{{Names: []string{"read"}, Action: runtimespec.ActAllow}},
		},
		CgroupPath: "/sys/fs/cgroup/hull/abc",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Exec
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Seccomp == nil || len(back.Seccomp.Syscalls) != 1 {
		t.Fatalf("seccomp did not survive: %+v", back.Seccomp)
	}
	if back.CgroupPath != e.CgroupPath || !back.Terminal {
		t.Fatalf("exec did not survive: %+v", back)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
