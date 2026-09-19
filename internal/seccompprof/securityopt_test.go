package seccompprof

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseSecurityOpt(t *testing.T) {
	dir := t.TempDir()
	profPath := filepath.Join(dir, "custom.json")
	if err := os.WriteFile(profPath, []byte(minimalProfile), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		opts    []string
		wantErr string
		want    func(t *testing.T, o SecurityOptions)
	}{
		{
			name: "no options at all",
			opts: nil,
			want: func(t *testing.T, o SecurityOptions) {
				if !o.NoNewPrivileges {
					t.Error("no-new-privileges must default to true")
				}
				if o.Seccomp != nil || o.SeccompUnconfined {
					t.Error("default is hull's own profile: nil Seccomp, not unconfined")
				}
			},
		},
		{
			name: "seccomp unconfined",
			opts: []string{"seccomp=unconfined"},
			want: func(t *testing.T, o SecurityOptions) {
				if !o.SeccompUnconfined || o.Seccomp != nil {
					t.Errorf("got %+v", o)
				}
			},
		},
		{
			name: "seccomp unconfined with the colon spelling",
			opts: []string{"seccomp:unconfined"},
			want: func(t *testing.T, o SecurityOptions) {
				if !o.SeccompUnconfined {
					t.Error("colon spelling should work")
				}
			},
		},
		{
			name: "seccomp unconfined is case-insensitive",
			opts: []string{"SECCOMP=Unconfined"},
			want: func(t *testing.T, o SecurityOptions) {
				if !o.SeccompUnconfined {
					t.Error("case should not matter")
				}
			},
		},
		{
			name: "seccomp from a path",
			opts: []string{"seccomp=" + profPath},
			want: func(t *testing.T, o SecurityOptions) {
				if o.Seccomp == nil {
					t.Fatal("profile not loaded")
				}
				if o.SeccompUnconfined {
					t.Error("a loaded profile is not unconfined")
				}
				if len(o.Seccomp.Syscalls) != 1 {
					t.Errorf("rules = %+v", o.Seccomp.Syscalls)
				}
			},
		},
		{
			name: "seccomp inline json",
			opts: []string{"seccomp=" + minimalProfile},
			want: func(t *testing.T, o SecurityOptions) {
				if o.Seccomp == nil || len(o.Seccomp.Syscalls) != 1 {
					t.Errorf("inline profile not parsed: %+v", o.Seccomp)
				}
			},
		},
		{
			name:    "seccomp with no value",
			opts:    []string{"seccomp"},
			wantErr: "seccomp needs a value",
		},
		{
			name:    "seccomp path that does not exist",
			opts:    []string{"seccomp=" + filepath.Join(dir, "nope.json")},
			wantErr: "read profile",
		},
		{
			name:    "seccomp inline json that is broken",
			opts:    []string{`seccomp={"defaultAction":`},
			wantErr: "inline seccomp profile",
		},
		{
			name: "bare no-new-privileges turns it on",
			opts: []string{"no-new-privileges"},
			want: func(t *testing.T, o SecurityOptions) {
				if !o.NoNewPrivileges {
					t.Error("bare no-new-privileges means true")
				}
			},
		},
		{
			name: "no-new-privileges=true",
			opts: []string{"no-new-privileges=true"},
			want: func(t *testing.T, o SecurityOptions) {
				if !o.NoNewPrivileges {
					t.Error("want true")
				}
			},
		},
		{
			name: "no-new-privileges=false",
			opts: []string{"no-new-privileges=false"},
			want: func(t *testing.T, o SecurityOptions) {
				if o.NoNewPrivileges {
					t.Error("want false")
				}
			},
		},
		{
			name: "no-new-privileges=0",
			opts: []string{"no-new-privileges=0"},
			want: func(t *testing.T, o SecurityOptions) {
				if o.NoNewPrivileges {
					t.Error("want false")
				}
			},
		},
		{
			name:    "no-new-privileges with a junk value",
			opts:    []string{"no-new-privileges=maybe"},
			wantErr: "wants true or false",
		},
		{
			name: "apparmor",
			opts: []string{"apparmor=docker-default"},
			want: func(t *testing.T, o SecurityOptions) {
				if o.AppArmor != "docker-default" {
					t.Errorf("AppArmor = %q", o.AppArmor)
				}
			},
		},
		{
			name:    "apparmor with no value",
			opts:    []string{"apparmor"},
			wantErr: "apparmor needs a profile name",
		},
		{
			name: "label keeps everything after the first separator",
			opts: []string{"label=user:USER", "label=type:svirt_apache_t"},
			want: func(t *testing.T, o SecurityOptions) {
				want := []string{"user:USER", "type:svirt_apache_t"}
				if !reflect.DeepEqual(o.SELinuxLabels, want) {
					t.Errorf("SELinuxLabels = %v, want %v", o.SELinuxLabels, want)
				}
			},
		},
		{
			name: "label with the colon spelling",
			opts: []string{"label:level:s0:c100,c200"},
			want: func(t *testing.T, o SecurityOptions) {
				want := []string{"level:s0:c100,c200"}
				if !reflect.DeepEqual(o.SELinuxLabels, want) {
					t.Errorf("SELinuxLabels = %v, want %v", o.SELinuxLabels, want)
				}
			},
		},
		{
			name: "systempaths unconfined",
			opts: []string{"systempaths=unconfined"},
			want: func(t *testing.T, o SecurityOptions) {
				if !o.MaskedPathsUnconfined {
					t.Error("want MaskedPathsUnconfined")
				}
			},
		},
		{
			name:    "systempaths with any other value",
			opts:    []string{"systempaths=confined"},
			wantErr: "systempaths only accepts",
		},
		{
			name: "several options together",
			opts: []string{"seccomp=unconfined", "no-new-privileges=false", "apparmor=unconfined", "systempaths=unconfined"},
			want: func(t *testing.T, o SecurityOptions) {
				if !o.SeccompUnconfined || o.NoNewPrivileges || o.AppArmor != "unconfined" || !o.MaskedPathsUnconfined {
					t.Errorf("got %+v", o)
				}
			},
		},
		{
			name: "blank entries are skipped",
			opts: []string{"", "   "},
			want: func(t *testing.T, o SecurityOptions) {
				if !o.NoNewPrivileges {
					t.Error("blank entries should change nothing")
				}
			},
		},
		{
			name:    "an unknown option is an error, never ignored",
			opts:    []string{"selinux=on"},
			wantErr: "unknown security-opt",
		},
		{
			name:    "a typo in a known option is an error",
			opts:    []string{"no_new_privileges=false"},
			wantErr: "unknown security-opt",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSecurityOpt(tc.opts)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got %+v", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSecurityOpt(%v): %v", tc.opts, err)
			}
			if tc.want != nil {
				tc.want(t, got)
			}
		})
	}
}

func TestSecurityOptionsResolve(t *testing.T) {
	tests := []struct {
		name       string
		opts       SecurityOptions
		caps       []string
		privileged bool
		wantNil    bool
		wantAllow  string
	}{
		{
			name:    "unconfined",
			opts:    SecurityOptions{SeccompUnconfined: true},
			wantNil: true,
		},
		{
			name:       "privileged beats everything",
			opts:       DefaultSecurityOptions(),
			privileged: true,
			wantNil:    true,
		},
		{
			name:      "default profile is capability aware",
			opts:      DefaultSecurityOptions(),
			caps:      []string{"CAP_SYS_CHROOT"},
			wantAllow: "chroot",
		},
		{
			name:      "a user profile wins over the default",
			opts:      mustParse(t, []string{"seccomp=" + inlineOnly("mount")}),
			caps:      []string{"CAP_SYS_ADMIN"},
			wantAllow: "mount",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.opts.Resolve(tc.caps, tc.privileged)
			if tc.wantNil {
				if p != nil {
					t.Fatalf("want nil, got %+v", p)
				}
				return
			}
			if p == nil {
				t.Fatal("want a profile, got nil")
			}
			if tc.wantAllow != "" && !allowedNames(p)[tc.wantAllow] {
				t.Errorf("%q should be allowed", tc.wantAllow)
			}
		})
	}
}

// inlineOnly builds a one-rule inline profile allowing a single syscall.
func inlineOnly(name string) string {
	return `{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"syscalls":[{"names":["` + name + `"],"action":"SCMP_ACT_ALLOW"}]}`
}

func mustParse(t *testing.T, opts []string) SecurityOptions {
	t.Helper()
	o, err := ParseSecurityOpt(opts)
	if err != nil {
		t.Fatalf("ParseSecurityOpt(%v): %v", opts, err)
	}
	return o
}
