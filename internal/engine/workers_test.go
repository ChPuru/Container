package engine

import (
	"testing"
	"time"

	"github.com/ChPuru/hull/internal/types"
)

func TestShouldRestart(t *testing.T) {
	tests := []struct {
		name       string
		policy     types.RestartPolicy
		code       int
		manualStop bool
		attempts   int
		want       bool
	}{
		{name: "no policy", policy: types.RestartPolicy{}, code: 1},
		{name: "explicit no", policy: types.RestartPolicy{Name: "no"}, code: 1},
		{name: "always after a clean exit", policy: types.RestartPolicy{Name: "always"}, code: 0, want: true},
		{name: "always after a failure", policy: types.RestartPolicy{Name: "always"}, code: 1, want: true},
		{
			name:       "always is still beaten by an explicit stop",
			policy:     types.RestartPolicy{Name: "always"},
			code:       0,
			manualStop: true,
		},
		{
			name:   "unless-stopped restarts a container nobody stopped",
			policy: types.RestartPolicy{Name: "unless-stopped"},
			code:   1,
			want:   true,
		},
		{
			name:       "unless-stopped honours the marker that survives a daemon restart",
			policy:     types.RestartPolicy{Name: "unless-stopped"},
			code:       1,
			manualStop: true,
		},
		{name: "on-failure ignores a clean exit", policy: types.RestartPolicy{Name: "on-failure"}, code: 0},
		{name: "on-failure restarts a failure", policy: types.RestartPolicy{Name: "on-failure"}, code: 1, want: true},
		{
			name:     "on-failure stops at the retry limit",
			policy:   types.RestartPolicy{Name: "on-failure", MaximumRetryCount: 3},
			code:     1,
			attempts: 3,
		},
		{
			name:     "on-failure keeps going below the retry limit",
			policy:   types.RestartPolicy{Name: "on-failure", MaximumRetryCount: 3},
			code:     1,
			attempts: 2,
			want:     true,
		},
		{
			name:     "a retry limit also bounds always",
			policy:   types.RestartPolicy{Name: "always", MaximumRetryCount: 2},
			code:     1,
			attempts: 2,
		},
		{name: "an unknown policy never restarts", policy: types.RestartPolicy{Name: "sometimes"}, code: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldRestart(tt.policy, tt.code, tt.manualStop, tt.attempts)
			if got != tt.want {
				t.Errorf("ShouldRestart(%+v, code=%d, manual=%v, attempts=%d) = %v, want %v",
					tt.policy, tt.code, tt.manualStop, tt.attempts, got, tt.want)
			}
		})
	}
}

func TestNextBackoffDoublesAndCaps(t *testing.T) {
	want := []time.Duration{
		RestartBackoffInitial,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
		1600 * time.Millisecond,
	}
	got := time.Duration(0)
	for i, w := range want {
		got = NextBackoff(got)
		if got != w {
			t.Fatalf("backoff %d = %s, want %s", i, got, w)
		}
	}
	// Doubling from anywhere below the cap lands exactly on the cap and stays.
	got = RestartBackoffMax
	for i := 0; i < 5; i++ {
		got = NextBackoff(got)
		if got != RestartBackoffMax {
			t.Fatalf("backoff exceeded the cap: %s", got)
		}
	}
	if NextBackoff(40*time.Second) != RestartBackoffMax {
		t.Errorf("a doubling that would overshoot should land on the cap, got %s", NextBackoff(40*time.Second))
	}
	if NextBackoff(-time.Second) != RestartBackoffInitial {
		t.Errorf("a negative backoff should reset to the initial value")
	}
}

func TestTruncateOutputCapsProbeOutput(t *testing.T) {
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'x'
	}
	got := truncateOutput(string(long))
	if len(got) >= len(long) {
		t.Errorf("probe output was not truncated: %d bytes", len(got))
	}
	if short := truncateOutput("fine"); short != "fine" {
		t.Errorf("short output was altered: %q", short)
	}
}

func TestRecordHealthTransitions(t *testing.T) {
	te := newTestEngine(t)
	c := putContainer(t, te, &types.Container{
		Name:  "probed",
		State: types.StateRunning,
		Config: types.ContainerConfig{
			Healthcheck: &types.Healthcheck{Test: []string{"CMD", "true"}, Retries: 2},
		},
	})

	// A failure inside the start period must not count.
	te.recordHealth(c.ID, types.HealthLog{ExitCode: 1}, 2, true)
	got, err := te.lookup(c.ID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.Health.Status != HealthStarting || got.Health.FailingStreak != 0 {
		t.Errorf("inside the start period: status=%q streak=%d", got.Health.Status, got.Health.FailingStreak)
	}

	// One failure outside it is not enough for Retries=2.
	te.recordHealth(c.ID, types.HealthLog{ExitCode: 1}, 2, false)
	got, _ = te.lookup(c.ID)
	if got.Health.Status != HealthStarting || got.Health.FailingStreak != 1 {
		t.Errorf("after one failure: status=%q streak=%d", got.Health.Status, got.Health.FailingStreak)
	}

	// The second crosses the threshold.
	te.recordHealth(c.ID, types.HealthLog{ExitCode: 1}, 2, false)
	got, _ = te.lookup(c.ID)
	if got.Health.Status != HealthUnhealthy {
		t.Errorf("after two failures: status=%q, want %q", got.Health.Status, HealthUnhealthy)
	}

	// A success resets everything.
	te.recordHealth(c.ID, types.HealthLog{ExitCode: 0}, 2, false)
	got, _ = te.lookup(c.ID)
	if got.Health.Status != HealthHealthy || got.Health.FailingStreak != 0 {
		t.Errorf("after a success: status=%q streak=%d", got.Health.Status, got.Health.FailingStreak)
	}

	// The probe log is a bounded ring.
	for i := 0; i < maxHealthLog*2; i++ {
		te.recordHealth(c.ID, types.HealthLog{ExitCode: 0}, 2, false)
	}
	got, _ = te.lookup(c.ID)
	if len(got.Health.Log) != maxHealthLog {
		t.Errorf("health log holds %d entries, want %d", len(got.Health.Log), maxHealthLog)
	}
}
