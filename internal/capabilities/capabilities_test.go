package capabilities

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Cap
		wantErr bool
	}{
		{"canonical", "CAP_NET_ADMIN", CAP_NET_ADMIN, false},
		{"lower with prefix", "cap_net_admin", CAP_NET_ADMIN, false},
		{"lower without prefix", "net_admin", CAP_NET_ADMIN, false},
		{"upper without prefix", "NET_ADMIN", CAP_NET_ADMIN, false},
		{"mixed case", "Cap_Sys_Admin", CAP_SYS_ADMIN, false},
		{"whitespace", "  chown  ", CAP_CHOWN, false},
		{"first cap", "CAP_CHOWN", CAP_CHOWN, false},
		{"last cap", "checkpoint_restore", CAP_CHECKPOINT_RESTORE, false},
		{"perfmon", "PERFMON", CAP_PERFMON, false},
		{"bpf", "bpf", CAP_BPF, false},
		{"unknown", "CAP_NOT_A_THING", 0, true},
		{"empty", "", 0, true},
		{"whitespace only", "   ", 0, true},
		{"bare ALL is not a cap", "ALL", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) = %v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("Parse(%q) = %d (%s), want %d (%s)", tc.in, got, got, tc.want, tc.want)
			}
		})
	}
}

func TestTableIsContiguousAndRoundTrips(t *testing.T) {
	all := All()
	if len(all) != 41 {
		t.Fatalf("All() has %d caps, want 41 (CAP_CHOWN..CAP_CHECKPOINT_RESTORE)", len(all))
	}
	if all[0] != CAP_CHOWN || all[len(all)-1] != CAP_CHECKPOINT_RESTORE {
		t.Fatalf("All() endpoints wrong: %s..%s", all[0], all[len(all)-1])
	}
	for i, c := range all {
		if int(c) != i {
			t.Fatalf("All()[%d] = %d, want contiguous bit order", i, int(c))
		}
		name := c.String()
		if !strings.HasPrefix(name, "CAP_") {
			t.Fatalf("cap %d name %q lacks CAP_ prefix", i, name)
		}
		back, err := Parse(name)
		if err != nil {
			t.Fatalf("Parse(%q): %v", name, err)
		}
		if back != c {
			t.Fatalf("round trip %s: got %d want %d", name, back, c)
		}
	}
	// Spot-check the bit numbers that matter to the rest of the engine.
	for _, tc := range []struct {
		c    Cap
		bit  int
		name string
	}{
		{CAP_SYS_ADMIN, 21, "CAP_SYS_ADMIN"},
		{CAP_NET_RAW, 13, "CAP_NET_RAW"},
		{CAP_SETFCAP, 31, "CAP_SETFCAP"},
		{CAP_SYSLOG, 34, "CAP_SYSLOG"},
		{CAP_PERFMON, 38, "CAP_PERFMON"},
		{CAP_BPF, 39, "CAP_BPF"},
		{CAP_CHECKPOINT_RESTORE, 40, "CAP_CHECKPOINT_RESTORE"},
	} {
		if int(tc.c) != tc.bit || tc.c.String() != tc.name {
			t.Errorf("%s = bit %d/%q, want bit %d/%q", tc.name, int(tc.c), tc.c.String(), tc.bit, tc.name)
		}
	}
}

func TestUnknownCapString(t *testing.T) {
	if got := Cap(99).String(); got != "CAP_UNKNOWN(99)" {
		t.Fatalf("Cap(99).String() = %q", got)
	}
	if Cap(99).Valid() {
		t.Fatal("Cap(99) should not be Valid")
	}
}

func TestKnownIsSortedAndComplete(t *testing.T) {
	k := Known()
	if len(k) != len(All()) {
		t.Fatalf("Known() has %d entries, All() has %d", len(k), len(All()))
	}
	if !sort.StringsAreSorted(k) {
		t.Fatal("Known() is not sorted")
	}
}

func TestDefaultSet(t *testing.T) {
	want := []string{
		"CAP_AUDIT_WRITE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER",
		"CAP_FSETID", "CAP_KILL", "CAP_MKNOD", "CAP_NET_BIND_SERVICE",
		"CAP_NET_RAW", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP",
		"CAP_SETUID", "CAP_SYS_CHROOT",
	}
	got := Default()
	if len(got) != 14 {
		t.Fatalf("Default() has %d caps, want exactly 14", len(got))
	}
	sorted := append([]string(nil), got...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(sorted, want) {
		t.Fatalf("Default() = %v, want (sorted) %v", sorted, want)
	}
	for _, n := range got {
		if _, err := Parse(n); err != nil {
			t.Errorf("default set contains invalid name %q", n)
		}
	}
	// Default must never hand out the big ones.
	for _, forbidden := range []string{"CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_NET_ADMIN", "CAP_DAC_READ_SEARCH", "CAP_SYS_RAWIO", "CAP_BPF"} {
		for _, n := range got {
			if n == forbidden {
				t.Errorf("default set must not contain %s", forbidden)
			}
		}
	}
	// Default returns a copy: mutating it must not poison the package.
	got[0] = "CAP_SYS_ADMIN"
	if Default()[0] == "CAP_SYS_ADMIN" {
		t.Fatal("Default() returned a shared slice")
	}
}

func TestResolve(t *testing.T) {
	def := Default()
	sortedDefault := append([]string(nil), def...)
	sort.Strings(sortedDefault)

	tests := []struct {
		name    string
		add     []string
		drop    []string
		want    []string
		wantErr bool
	}{
		{
			name: "no flags gives the default set",
			want: sortedDefault,
		},
		{
			name: "add one, case insensitive and unprefixed",
			add:  []string{"net_admin"},
			want: sortedPlus(sortedDefault, "CAP_NET_ADMIN"),
		},
		{
			name: "drop one",
			drop: []string{"CAP_NET_RAW"},
			want: sortedMinus(sortedDefault, "CAP_NET_RAW"),
		},
		{
			name: "drop ALL",
			drop: []string{"ALL"},
			want: []string{},
		},
		{
			name: "drop ALL then add back two",
			drop: []string{"all"},
			add:  []string{"CHOWN", "cap_setuid"},
			want: []string{"CAP_CHOWN", "CAP_SETUID"},
		},
		{
			name: "add ALL",
			add:  []string{"ALL"},
			want: Known(),
		},
		{
			name: "add ALL then drop one",
			add:  []string{"ALL"},
			drop: []string{"sys_admin"},
			want: sortedMinus(Known(), "CAP_SYS_ADMIN"),
		},
		{
			name: "add ALL beats drop ALL",
			add:  []string{"ALL"},
			drop: []string{"ALL"},
			want: Known(),
		},
		{
			name: "add is idempotent",
			add:  []string{"CAP_CHOWN", "chown", "CHOWN"},
			want: sortedDefault,
		},
		{
			name: "empty entries are ignored",
			add:  []string{"", "   "},
			want: sortedDefault,
		},
		{
			name:    "unknown add",
			add:     []string{"CAP_NOPE"},
			wantErr: true,
		},
		{
			name:    "unknown drop",
			drop:    []string{"not_a_cap"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.add, tc.drop, false)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Resolve(%v,%v) = %v, want error", tc.add, tc.drop, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%v,%v): %v", tc.add, tc.drop, err)
			}
			if !sort.StringsAreSorted(got) {
				t.Fatalf("Resolve returned unsorted %v", got)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("Resolve = %v (%d), want %v (%d)", got, len(got), tc.want, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("Resolve = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestResolvePrivileged(t *testing.T) {
	got, err := Resolve([]string{"net_admin"}, []string{"ALL"}, true)
	if err != nil {
		t.Skipf("bounding set unavailable here: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("privileged resolve returned no capabilities")
	}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("privileged resolve unsorted: %v", got)
	}
	// add/drop are ignored entirely under --privileged.
	if !contains(got, "CAP_CHOWN") {
		t.Errorf("privileged set lacks CAP_CHOWN even though --cap-drop ALL must be ignored: %v", got)
	}
	for _, n := range got {
		if _, err := Parse(n); err != nil {
			t.Errorf("privileged set contains %q: %v", n, err)
		}
	}
}

func TestToSpec(t *testing.T) {
	caps := []string{"cap_chown", "CAP_SETUID", "kill"}
	want := []string{"CAP_CHOWN", "CAP_KILL", "CAP_SETUID"}

	tests := []struct {
		name        string
		uid         int
		wantAmbient bool
	}{
		{"root gets no ambient", 0, false},
		{"non-root gets ambient", 1000, true},
		{"nobody gets ambient", 65534, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lc := ToSpecForUID(caps, tc.uid)
			if !reflect.DeepEqual(lc.Bounding, want) {
				t.Errorf("Bounding = %v, want %v", lc.Bounding, want)
			}
			if !reflect.DeepEqual(lc.Effective, want) {
				t.Errorf("Effective = %v, want %v", lc.Effective, want)
			}
			if !reflect.DeepEqual(lc.Permitted, want) {
				t.Errorf("Permitted = %v, want %v", lc.Permitted, want)
			}
			if len(lc.Inheritable) != 0 {
				t.Errorf("Inheritable = %v, want empty (runc dropped it in 1.0.0-rc94)", lc.Inheritable)
			}
			if tc.wantAmbient {
				if !reflect.DeepEqual(lc.Ambient, want) {
					t.Errorf("Ambient = %v, want %v", lc.Ambient, want)
				}
			} else if len(lc.Ambient) != 0 {
				t.Errorf("Ambient = %v, want empty for uid 0", lc.Ambient)
			}
		})
	}

	// The sets must not alias each other: mutating one must not touch another.
	lc := ToSpecForUID(caps, 1000)
	lc.Effective[0] = "CAP_SYS_ADMIN"
	if lc.Bounding[0] == "CAP_SYS_ADMIN" || lc.Ambient[0] == "CAP_SYS_ADMIN" {
		t.Fatal("ToSpecForUID aliased the capability slices")
	}

	// ToSpec must agree with ToSpecForUID at the current uid.
	if !reflect.DeepEqual(ToSpec(caps), ToSpecForUID(caps, geteuid())) {
		t.Fatal("ToSpec disagrees with ToSpecForUID(geteuid())")
	}
}

func TestToSpecDeduplicates(t *testing.T) {
	lc := ToSpecForUID([]string{"chown", "CAP_CHOWN", "CHOWN", ""}, 0)
	if !reflect.DeepEqual(lc.Bounding, []string{"CAP_CHOWN"}) {
		t.Fatalf("Bounding = %v, want [CAP_CHOWN]", lc.Bounding)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func sortedPlus(base []string, extra ...string) []string {
	out := append(append([]string(nil), base...), extra...)
	sort.Strings(out)
	return out
}

func sortedMinus(base []string, drop ...string) []string {
	out := make([]string, 0, len(base))
	for _, n := range base {
		if !contains(drop, n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
