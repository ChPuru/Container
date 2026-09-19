//go:build linux

package capabilities

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBoundingSetParsesFixtures(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		want     []Cap
		wantErr  bool
		contains string
	}{
		{
			name:   "full 5.15 bounding set",
			status: "Name:\tbash\nCapBnd:\t000001ffffffffff\nCapEff:\t0000000000000000\n",
			want:   All(),
		},
		{
			name:   "docker default-ish subset",
			status: "CapBnd:\t00000000a80425fb\n",
			// 0xa80425fb decodes to the fourteen Docker default caps.
			want: []Cap{
				CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID, CAP_KILL,
				CAP_SETGID, CAP_SETUID, CAP_SETPCAP, CAP_NET_BIND_SERVICE,
				CAP_NET_RAW, CAP_SYS_CHROOT, CAP_MKNOD, CAP_AUDIT_WRITE,
				CAP_SETFCAP,
			},
		},
		{
			name:   "empty bounding set",
			status: "CapBnd:\t0000000000000000\n",
			want:   []Cap{},
		},
		{
			name:   "bits above LastCap are ignored",
			status: "CapBnd:\tffffffffffffffff\n",
			want:   All(),
		},
		{
			name:     "no CapBnd line",
			status:   "Name:\tbash\nPid:\t1\n",
			wantErr:  true,
			contains: "no CapBnd line",
		},
		{
			name:     "unparseable CapBnd",
			status:   "CapBnd:\tnot-hex\n",
			wantErr:  true,
			contains: "parse CapBnd",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "status")
			if err := os.WriteFile(p, []byte(tc.status), 0o600); err != nil {
				t.Fatal(err)
			}
			old := statusPath
			statusPath = p
			defer func() { statusPath = old }()

			got, err := BoundingSet()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("BoundingSet() = %v, want error", got)
				}
				if tc.contains != "" && !containsSubstr(err.Error(), tc.contains) {
					t.Fatalf("error %q does not mention %q", err, tc.contains)
				}
				return
			}
			if err != nil {
				t.Fatalf("BoundingSet(): %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("BoundingSet() = %v (%d), want %d entries", got, len(got), len(tc.want))
			}
			set := make(map[Cap]bool, len(got))
			for _, c := range got {
				set[c] = true
			}
			for _, c := range tc.want {
				if !set[c] {
					t.Errorf("missing %s", c)
				}
			}
		})
	}
}

func TestBoundingSetOnThisHost(t *testing.T) {
	got, err := BoundingSet()
	if err != nil {
		t.Fatalf("BoundingSet() on a real /proc: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("this host reports an empty capability bounding set")
	}
	for _, c := range got {
		if !c.Valid() {
			t.Errorf("BoundingSet returned unknown cap %d", int(c))
		}
	}
}

func TestBoundingSetMissingFile(t *testing.T) {
	old := statusPath
	statusPath = filepath.Join(t.TempDir(), "does-not-exist")
	defer func() { statusPath = old }()
	if _, err := BoundingSet(); err == nil {
		t.Fatal("want error for a missing status file")
	}
}

func containsSubstr(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
