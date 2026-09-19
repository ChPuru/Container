package idle

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigWithDefaults(t *testing.T) {
	cases := []struct {
		name string
		in   Config
		want func(t *testing.T, c Config)
	}{
		{
			name: "zero config is inert but usable",
			in:   Config{},
			want: func(t *testing.T, c Config) {
				if c.SampleInterval != DefaultSampleInterval {
					t.Errorf("SampleInterval = %v, want %v", c.SampleInterval, DefaultSampleInterval)
				}
				if c.FreezeAfter != 0 || c.ExitAfter != 0 {
					t.Errorf("a zero config must not freeze or exit: %v / %v", c.FreezeAfter, c.ExitAfter)
				}
				if c.ThawTimeout != DefaultThawTimeout {
					t.Errorf("ThawTimeout = %v, want %v", c.ThawTimeout, DefaultThawTimeout)
				}
				if c.CPUFloorUsec != DefaultCPUFloorUsec {
					t.Errorf("CPUFloorUsec = %d, want %d", c.CPUFloorUsec, DefaultCPUFloorUsec)
				}
				if c.Now == nil || c.CPUUsage == nil || c.Logger == nil {
					t.Error("a zero config left a required function nil")
				}
			},
		},
		{
			name: "cooldown defaults to the freeze window",
			in:   Config{FreezeAfter: 5 * time.Minute},
			want: func(t *testing.T, c Config) {
				if c.Cooldown != 5*time.Minute {
					t.Errorf("Cooldown = %v, want the freeze window", c.Cooldown)
				}
			},
		},
		{
			name: "an explicit cooldown is kept",
			in:   Config{FreezeAfter: time.Minute, Cooldown: time.Hour},
			want: func(t *testing.T, c Config) {
				if c.Cooldown != time.Hour {
					t.Errorf("Cooldown = %v, want an hour", c.Cooldown)
				}
			},
		},
		{
			name: "a negative window is off, not backwards",
			in:   Config{FreezeAfter: -time.Minute, ExitAfter: -time.Minute},
			want: func(t *testing.T, c Config) {
				if c.FreezeAfter != 0 || c.ExitAfter != 0 {
					t.Errorf("negative windows survived: %v / %v", c.FreezeAfter, c.ExitAfter)
				}
			},
		},
		{
			name: "a sub-millisecond sample interval is clamped",
			in:   Config{SampleInterval: time.Nanosecond},
			want: func(t *testing.T, c Config) {
				if c.SampleInterval != minSampleInterval {
					t.Errorf("SampleInterval = %v, want %v", c.SampleInterval, minSampleInterval)
				}
			},
		},
		{
			name: "a floor of one means any cpu movement counts",
			in:   Config{CPUFloorUsec: 1},
			want: func(t *testing.T, c Config) {
				if c.CPUFloorUsec != 1 {
					t.Errorf("CPUFloorUsec = %d, want 1", c.CPUFloorUsec)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.want(t, tc.in.withDefaults())
		})
	}
}

func TestParseCPUUsageUsec(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want uint64
		ok   bool
	}{
		{
			name: "a real cgroup v2 cpu.stat",
			in: "usage_usec 1234567\nuser_usec 1000000\nsystem_usec 234567\n" +
				"nr_periods 0\nnr_throttled 0\nthrottled_usec 0\n",
			want: 1234567,
			ok:   true,
		},
		{name: "usage is not the first line", in: "user_usec 5\nusage_usec 42\n", want: 42, ok: true},
		{name: "no trailing newline", in: "usage_usec 7", want: 7, ok: true},
		{name: "zero is a real reading", in: "usage_usec 0\n", want: 0, ok: true},
		{name: "empty file", in: "", ok: false},
		{name: "no cpu controller, so no usage line", in: "nr_periods 0\n", ok: false},
		{name: "a prefix is not a match", in: "usage_usec_total 9\n", ok: false},
		{name: "unparsable value", in: "usage_usec max\n", ok: false},
		{name: "negative value", in: "usage_usec -1\n", ok: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseCPUUsageUsec(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("usage = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestReadCPUUsageUsec(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cpuStatFile), []byte("usage_usec 99\n"), 0o644); err != nil {
		t.Fatalf("write cpu.stat: %v", err)
	}

	cases := []struct {
		name string
		path string
		want uint64
		ok   bool
	}{
		{name: "a readable cgroup", path: dir, want: 99, ok: true},
		{name: "no cgroup path at all", path: "", ok: false},
		{name: "a cgroup with no cpu.stat", path: filepath.Join(dir, "missing"), ok: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ReadCPUUsageUsec(tc.path)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("usage = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestReadCPUUsageUsecOnThisHost reads the real root cgroup when the host has
// one. It needs no privileges; on a hybrid-cgroup WSL kernel, or on Windows,
// there is nothing to read and the test skips, which is exactly the degraded
// mode the watcher is written to survive.
func TestReadCPUUsageUsecOnThisHost(t *testing.T) {
	const root = "/sys/fs/cgroup"
	if _, err := os.Stat(filepath.Join(root, cpuStatFile)); err != nil {
		t.Skipf("no %s/%s on this host: %v", root, cpuStatFile, err)
	}
	if _, ok := ReadCPUUsageUsec(root); !ok {
		t.Fatalf("could not read usage_usec from the root cgroup")
	}
}

func TestTopReasonPicksTheStrongestSignal(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{name: "nothing", in: []string{"", "", ""}, want: ""},
		{name: "a stream beats everything", in: []string{ReasonAttach, ReasonPort, ReasonCPU, ReasonTouch}, want: ReasonAttach},
		{name: "port traffic beats cpu", in: []string{"", ReasonPort, ReasonCPU, ReasonTouch}, want: ReasonPort},
		{name: "cpu beats a bare touch", in: []string{"", "", ReasonCPU, ReasonTouch}, want: ReasonCPU},
		{name: "a touch on its own", in: []string{"", "", "", ReasonTouch}, want: ReasonTouch},
		{name: "an unknown reason ranks below every real one", in: []string{"weather", ReasonTouch}, want: ReasonTouch},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := topReason(tc.in...); got != tc.want {
				t.Fatalf("topReason(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEventAttributes(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
		want map[string]string
	}{
		{
			name: "a pause carries the reason and how long it was idle",
			ev:   Event{Action: ActionPause, ID: "c1", Reason: ReasonIdle, IdleFor: 5 * time.Minute, PublishedPorts: 2},
			want: map[string]string{"reason": "idle", "source": "hull-idle", "idleFor": "5m0s", "publishedPorts": "2"},
		},
		{
			name: "an unpause carries the waking signal",
			ev:   Event{Action: ActionUnpause, ID: "c1", Reason: ReasonPort},
			want: map[string]string{"reason": "port", "source": "hull-idle"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.ev.Attributes()
			if len(got) != len(tc.want) {
				t.Fatalf("attributes = %v, want %v", got, tc.want)
			}
			for k, want := range tc.want {
				if got[k] != want {
					t.Errorf("attribute %q = %q, want %q", k, got[k], want)
				}
			}
		})
	}
}

func TestShortID(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "abc", want: "abc"},
		{in: "0123456789abcdef0123", want: "0123456789ab"},
	}
	for _, tc := range cases {
		if got := short(tc.in); got != tc.want {
			t.Errorf("short(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
