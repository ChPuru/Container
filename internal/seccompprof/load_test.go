package seccompprof

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

const minimalProfile = `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 1,
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"}
  ]
}`

func TestLoadProfileTable(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		caps    []string
		wantErr string
		check   func(t *testing.T, p *runtimespec.LinuxSeccomp)
	}{
		{
			name: "minimal profile",
			json: minimalProfile,
			check: func(t *testing.T, p *runtimespec.LinuxSeccomp) {
				if p.DefaultAction != runtimespec.ActErrno {
					t.Errorf("action = %q", p.DefaultAction)
				}
				if p.DefaultErrnoRet == nil || *p.DefaultErrnoRet != 1 {
					t.Error("defaultErrnoRet lost")
				}
				if len(p.Syscalls) != 1 || len(p.Syscalls[0].Names) != 2 {
					t.Errorf("rules = %+v", p.Syscalls)
				}
			},
		},
		{
			name: "singular name key",
			json: `{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"name":"mount","action":"SCMP_ACT_ERRNO"}]}`,
			check: func(t *testing.T, p *runtimespec.LinuxSeccomp) {
				if len(p.Syscalls) != 1 || p.Syscalls[0].Names[0] != "mount" {
					t.Errorf("rules = %+v", p.Syscalls)
				}
			},
		},
		{
			name: "includes caps kept when held",
			json: `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[
			  {"names":["mount"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_ADMIN"]}}]}`,
			caps: []string{"CAP_SYS_ADMIN"},
			check: func(t *testing.T, p *runtimespec.LinuxSeccomp) {
				if len(p.Syscalls) != 1 {
					t.Errorf("rule should be kept, got %+v", p.Syscalls)
				}
			},
		},
		{
			name: "includes caps dropped when not held",
			json: `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[
			  {"names":["mount"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_ADMIN"]}}]}`,
			caps: []string{"CAP_CHOWN"},
			check: func(t *testing.T, p *runtimespec.LinuxSeccomp) {
				if len(p.Syscalls) != 0 {
					t.Errorf("rule should be dropped, got %+v", p.Syscalls)
				}
			},
		},
		{
			name: "includes caps is an AND",
			json: `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[
			  {"names":["bpf"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_NET_ADMIN","CAP_BPF"]}}]}`,
			caps: []string{"CAP_NET_ADMIN"},
			check: func(t *testing.T, p *runtimespec.LinuxSeccomp) {
				if len(p.Syscalls) != 0 {
					t.Errorf("rule needs both caps, got %+v", p.Syscalls)
				}
			},
		},
		{
			name: "excludes caps is an OR",
			json: `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[
			  {"names":["socket"],"action":"SCMP_ACT_ALLOW","excludes":{"caps":["CAP_SYS_ADMIN","CAP_NET_ADMIN"]}}]}`,
			caps: []string{"CAP_NET_ADMIN"},
			check: func(t *testing.T, p *runtimespec.LinuxSeccomp) {
				if len(p.Syscalls) != 0 {
					t.Errorf("rule should be excluded, got %+v", p.Syscalls)
				}
			},
		},
		{
			name: "arch condition dropping a foreign arch",
			json: `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[
			  {"names":["s390_pci_mmio_read"],"action":"SCMP_ACT_ALLOW","includes":{"arches":["s390x"]}},
			  {"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`,
			check: func(t *testing.T, p *runtimespec.LinuxSeccomp) {
				if runtime.GOARCH == "s390x" {
					t.Skip("running on s390x")
				}
				if len(p.Syscalls) != 1 || p.Syscalls[0].Names[0] != "read" {
					t.Errorf("s390x rule should be dropped, got %+v", p.Syscalls)
				}
			},
		},
		{
			name: "arch condition keeping the native arch",
			json: `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[
			  {"names":["arch_prctl"],"action":"SCMP_ACT_ALLOW","includes":{"arches":["amd64","arm64"]}}]}`,
			check: func(t *testing.T, p *runtimespec.LinuxSeccomp) {
				switch runtime.GOARCH {
				case "amd64", "arm64":
					if len(p.Syscalls) != 1 {
						t.Errorf("native rule should be kept, got %+v", p.Syscalls)
					}
				}
			},
		},
		{
			name: "archMap expands sub-architectures",
			json: `{"defaultAction":"SCMP_ACT_ERRNO",
			  "archMap":[
			    {"architecture":"SCMP_ARCH_X86_64","subArchitectures":["SCMP_ARCH_X86","SCMP_ARCH_X32"]},
			    {"architecture":"SCMP_ARCH_AARCH64","subArchitectures":["SCMP_ARCH_ARM"]},
			    {"architecture":"SCMP_ARCH_S390X","subArchitectures":["SCMP_ARCH_S390"]}],
			  "syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`,
			check: func(t *testing.T, p *runtimespec.LinuxSeccomp) {
				switch runtime.GOARCH {
				case "amd64":
					want := []runtimespec.Arch{runtimespec.ArchX86_64, runtimespec.ArchX86, runtimespec.ArchX32}
					if len(p.Architectures) != len(want) {
						t.Fatalf("architectures = %v, want %v", p.Architectures, want)
					}
					for i := range want {
						if p.Architectures[i] != want[i] {
							t.Fatalf("architectures = %v, want %v", p.Architectures, want)
						}
					}
				case "arm64":
					if len(p.Architectures) != 2 {
						t.Fatalf("architectures = %v, want aarch64+arm", p.Architectures)
					}
				}
			},
		},
		{
			name: "args are translated",
			json: `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[
			  {"names":["clone"],"action":"SCMP_ACT_ALLOW","args":[
			    {"index":0,"value":2114060288,"valueTwo":0,"op":"SCMP_CMP_MASKED_EQ"}]}]}`,
			check: func(t *testing.T, p *runtimespec.LinuxSeccomp) {
				a := p.Syscalls[0].Args[0]
				if a.Op != runtimespec.OpMaskedEqual || a.Value != 2114060288 {
					t.Errorf("arg = %+v", a)
				}
			},
		},
		{
			name: "errnoRet is carried",
			json: `{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[
			  {"names":["clone3"],"action":"SCMP_ACT_ERRNO","errnoRet":38}]}`,
			check: func(t *testing.T, p *runtimespec.LinuxSeccomp) {
				if p.Syscalls[0].ErrnoRet == nil || *p.Syscalls[0].ErrnoRet != 38 {
					t.Errorf("errnoRet = %v", p.Syscalls[0].ErrnoRet)
				}
			},
		},
		{
			name: "flags are validated",
			json: `{"defaultAction":"SCMP_ACT_ALLOW","flags":["SECCOMP_FILTER_FLAG_LOG"],"syscalls":[]}`,
			check: func(t *testing.T, p *runtimespec.LinuxSeccomp) {
				if len(p.Flags) != 1 || p.Flags[0] != runtimespec.FlagLog {
					t.Errorf("flags = %v", p.Flags)
				}
			},
		},
		{
			name:    "unknown defaultAction",
			json:    `{"defaultAction":"SCMP_ACT_NOPE","syscalls":[]}`,
			wantErr: "unknown defaultAction",
		},
		{
			name:    "unknown rule action",
			json:    `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_WAT"}]}`,
			wantErr: "unknown action",
		},
		{
			name:    "unknown op",
			json:    `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":1,"op":"SCMP_CMP_WHAT"}]}]}`,
			wantErr: "unknown op",
		},
		{
			name:    "arg index out of range",
			json:    `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW","args":[{"index":9,"value":1,"op":"SCMP_CMP_EQ"}]}]}`,
			wantErr: "out of range",
		},
		{
			name:    "rule with no name",
			json:    `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"action":"SCMP_ACT_ALLOW"}]}`,
			wantErr: "neither name nor names",
		},
		{
			name:    "unknown architecture",
			json:    `{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_VAX"],"syscalls":[]}`,
			wantErr: "unknown architecture",
		},
		{
			name:    "unknown flag",
			json:    `{"defaultAction":"SCMP_ACT_ERRNO","flags":["SECCOMP_FILTER_FLAG_NOPE"],"syscalls":[]}`,
			wantErr: "unknown seccomp flag",
		},
		{
			name:    "malformed json",
			json:    `{"defaultAction":`,
			wantErr: "parse seccomp profile",
		},
		{
			name:    "malformed minKernel",
			json:    `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW","includes":{"minKernel":"four"}}]}`,
			wantErr: "malformed minKernel",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := LoadProfile([]byte(tc.json), tc.caps)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got profile %+v", tc.wantErr, p)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadProfile: %v", err)
			}
			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}

func TestLoadProfileIgnoresUnknownKeys(t *testing.T) {
	// Real profiles carry "comment" on every rule and sometimes vendor keys.
	const j = `{
	  "defaultAction":"SCMP_ACT_ERRNO",
	  "someVendorKey": {"a": 1},
	  "syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW","comment":"basic io"}]
	}`
	p, err := LoadProfile([]byte(j), nil)
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	if len(p.Syscalls) != 1 {
		t.Fatalf("rules = %+v", p.Syscalls)
	}
}

func TestLoadFromDisk(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(good, []byte(minimalProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(good)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(p.Syscalls) != 1 {
		t.Fatalf("rules = %+v", p.Syscalls)
	}

	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("want an error for a missing profile")
	} else if !strings.Contains(err.Error(), "read profile") {
		t.Fatalf("unhelpful error: %v", err)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"defaultAction":"NOPE"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Fatal("want an error for an invalid profile")
	} else if !strings.Contains(err.Error(), bad) {
		t.Errorf("error %q should name the file", err)
	}
}

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		in       string
		maj, min int
		wantErr  bool
	}{
		{in: "4.8", maj: 4, min: 8},
		{in: "5.15", maj: 5, min: 15},
		{in: "6.6.87", maj: 6, min: 6},
		{in: "5.15.167.4-microsoft-standard-WSL2", maj: 5, min: 15},
		{in: "6.1.0-rc3", maj: 6, min: 1},
		{in: "5", wantErr: true},
		{in: "x.y", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tc := range tests {
		maj, min, err := parseKernelVersion(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseKernelVersion(%q) = %d.%d, want error", tc.in, maj, min)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseKernelVersion(%q): %v", tc.in, err)
			continue
		}
		if maj != tc.maj || min != tc.min {
			t.Errorf("parseKernelVersion(%q) = %d.%d, want %d.%d", tc.in, maj, min, tc.maj, tc.min)
		}
	}
}

func TestNormalizeArchToken(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"SCMP_ARCH_X86_64", "x86_64"},
		{"x86_64", "x86_64"},
		{"amd64", "amd64"},
		{" AARCH64 ", "aarch64"},
	} {
		if got := normalizeArchToken(tc.in); got != tc.want {
			t.Errorf("normalizeArchToken(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
