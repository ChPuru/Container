package tui

import (
	"testing"
	"time"

	"github.com/ChPuru/hull/internal/types"
)

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{0, "0B"},
		{512, "512B"},
		{1024, "1.00K"},
		{1536, "1.50K"},
		{10 * 1024, "10.0K"},
		{100 * 1024, "100K"},
		{5 << 20, "5.00M"},
		{12 << 30, "12.0G"},
		{3 << 40, "3.00T"},
	}
	for _, tc := range tests {
		if got := HumanBytes(tc.in); got != tc.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{-time.Second, "0s"},
		{500 * time.Millisecond, "0s"},
		{45 * time.Second, "45s"},
		{4*time.Minute + 12*time.Second, "4m12s"},
		{2*time.Hour + 5*time.Minute, "2h05m"},
		{50 * time.Hour, "2d2h"},
		{20 * 24 * time.Hour, "2w"},
	}
	for _, tc := range tests {
		if got := HumanDuration(tc.in); got != tc.want {
			t.Errorf("HumanDuration(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHumanPercent(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{0, "0.0%"},
		{12.34, "12.3%"},
		{99.99, "100.0%"},
		{150, "150%"},
		{-1, "-"},
	}
	for _, tc := range tests {
		if got := HumanPercent(tc.in); got != tc.want {
			t.Errorf("HumanPercent(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCPUPercent(t *testing.T) {
	tests := []struct {
		name string
		in   types.Stats
		want float64
	}{
		{
			name: "half of one cpu",
			in: types.Stats{
				CPUUsage: 500, PreCPUUsage: 0,
				SystemUsage: 1000, PreSystemUsage: 0,
				OnlineCPUs: 1,
			},
			want: 50,
		},
		{
			name: "all of four cpus",
			in: types.Stats{
				CPUUsage: 1000, PreCPUUsage: 0,
				SystemUsage: 1000, PreSystemUsage: 0,
				OnlineCPUs: 4,
			},
			want: 400,
		},
		{
			name: "the first sample has nothing to difference against",
			in:   types.Stats{CPUUsage: 1000, OnlineCPUs: 4},
			want: 0,
		},
		{
			name: "a host with no cpu accounting reports nothing",
			in:   types.Stats{},
			want: 0,
		},
		{
			name: "no online cpu count still gives an answer",
			in: types.Stats{
				CPUUsage: 250, PreCPUUsage: 0,
				SystemUsage: 1000, PreSystemUsage: 0,
			},
			want: 25,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CPUPercent(tc.in); got != tc.want {
				t.Errorf("CPUPercent() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMemoryUsageSubtractsCache(t *testing.T) {
	tests := []struct {
		name string
		in   types.Stats
		want uint64
	}{
		{"cache is not usage", types.Stats{MemoryUsage: 1000, MemoryCache: 400}, 600},
		{"cache larger than usage cannot go negative", types.Stats{MemoryUsage: 100, MemoryCache: 400}, 0},
		{"no cache reported", types.Stats{MemoryUsage: 1000}, 1000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MemoryUsage(tc.in); got != tc.want {
				t.Errorf("MemoryUsage() = %d, want %d", got, tc.want)
			}
		})
	}
	if got := MemoryPercent(types.Stats{MemoryUsage: 600, MemoryLimit: 1200}); got != 50 {
		t.Errorf("MemoryPercent() = %v, want 50", got)
	}
	if got := MemoryPercent(types.Stats{MemoryUsage: 600}); got != 0 {
		t.Errorf("MemoryPercent() with no limit = %v, want 0", got)
	}
}

func TestShortID(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"0123456789abcdef0123", "0123456789ab"},
		{"sha256:0123456789abcdef", "0123456789ab"},
		{"short", "short"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := ShortID(tc.in); got != tc.want {
			t.Errorf("ShortID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUptime(t *testing.T) {
	now := time.Date(2026, 9, 19, 17, 30, 0, 0, time.UTC)
	tests := []struct {
		name string
		in   types.Container
		want time.Duration
	}{
		{
			name: "running counts from the start",
			in:   types.Container{State: types.StateRunning, StartedAt: now.Add(-time.Hour)},
			want: time.Hour,
		},
		{
			name: "exited counts from the finish",
			in:   types.Container{State: types.StateExited, FinishedAt: now.Add(-time.Minute)},
			want: time.Minute,
		},
		{
			name: "created counts from creation",
			in:   types.Container{State: types.StateCreated, Created: now.Add(-time.Second)},
			want: time.Second,
		},
		{
			name: "a missing timestamp is zero, not an epoch",
			in:   types.Container{State: types.StateRunning},
			want: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Uptime(tc.in, now); got != tc.want {
				t.Errorf("Uptime() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStateSummary(t *testing.T) {
	tests := []struct {
		name string
		in   types.Container
		want string
	}{
		{"running", types.Container{State: types.StateRunning}, "running"},
		{
			name: "running with health",
			in:   types.Container{State: types.StateRunning, Health: &types.HealthState{Status: "healthy"}},
			want: "running (healthy)",
		},
		{"exited carries the code", types.Container{State: types.StateExited, ExitCode: 137}, "exited (137)"},
		{"paused", types.Container{State: types.StatePaused}, "paused"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := StateSummary(tc.in); got != tc.want {
				t.Errorf("StateSummary() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPortStrings(t *testing.T) {
	tests := []struct {
		name string
		in   types.Container
		want []string
	}{
		{
			name: "published ports are sorted and formatted",
			in: types.Container{NetworkSettings: types.NetworkSettings{
				Ports: map[string][]types.PortBinding{
					"443/tcp": {{HostIP: "127.0.0.1", HostPort: "8443"}},
					"80/tcp":  {{HostPort: "8080"}},
				},
			}},
			want: []string{"0.0.0.0:8080->80/tcp", "127.0.0.1:8443->443/tcp"},
		},
		{
			name: "an unpublished mapping shows the container port alone",
			in: types.Container{NetworkSettings: types.NetworkSettings{
				Ports: map[string][]types.PortBinding{"9000/tcp": nil},
			}},
			want: []string{"9000/tcp"},
		},
		{
			name: "with nothing published the exposed ports are shown",
			in: types.Container{Config: types.ContainerConfig{
				ExposedPorts: map[string]struct{}{"5432/tcp": {}},
			}},
			want: []string{"5432/tcp"},
		},
		{name: "nothing at all", in: types.Container{}, want: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := PortStrings(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("PortStrings() = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("PortStrings() = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestEventLine(t *testing.T) {
	e := types.Event{
		Type:   "container",
		Action: "die",
		Actor: types.EventActor{
			ID:         "abcdef0123456789",
			Attributes: map[string]string{"name": "web", "exitCode": "1"},
		},
		Time: time.Date(2026, 9, 19, 17, 30, 15, 0, time.UTC).Unix(),
	}
	got := EventLine(e, time.UTC)
	if want := "17:30:15 container die web"; got != want {
		t.Errorf("EventLine() = %q, want %q", got, want)
	}

	e.Actor.Attributes = nil
	got = EventLine(e, time.UTC)
	if want := "17:30:15 container die abcdef012345"; got != want {
		t.Errorf("EventLine() without a name = %q, want %q", got, want)
	}
}

func TestWrapLines(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		width int
		want  []string
	}{
		{"short enough", "one two", 10, []string{"one two"}},
		{"wraps on a space", "one two three", 7, []string{"one two", "three"}},
		{"a word longer than the width is split", "abcdefghij", 4, []string{"abcd", "efgh", "ij"}},
		{"empty", "", 10, []string{""}},
		{"no width", "anything", 0, []string{""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := wrapLines(tc.in, tc.width)
			if len(got) != len(tc.want) {
				t.Fatalf("wrapLines(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("wrapLines(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
				}
			}
		})
	}
}

func TestImageName(t *testing.T) {
	if got := ImageName(types.Container{ImageRef: "alpine:3.20"}); got != "alpine:3.20" {
		t.Errorf("ImageName() = %q", got)
	}
	if got := ImageName(types.Container{Image: "sha256:0123456789abcdef"}); got != "0123456789ab" {
		t.Errorf("ImageName() fallback = %q", got)
	}
}
