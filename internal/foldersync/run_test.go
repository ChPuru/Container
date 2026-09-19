package foldersync

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeWatcher stands in for inotify so the overflow recovery and the Run loop
// can be exercised on any platform, including the windows/amd64 build of the
// CLI.
type fakeWatcher struct {
	mu       sync.Mutex
	results  []watchResult
	rearmed  int
	closed   bool
	released chan struct{}
}

// newFakeWatcher returns a watcher that hands out the given results, one per
// wait, and then blocks until its context ends.
func newFakeWatcher(results ...watchResult) *fakeWatcher {
	return &fakeWatcher{results: results, released: make(chan struct{})}
}

func (f *fakeWatcher) wait(ctx context.Context) (watchResult, error) {
	f.mu.Lock()
	if len(f.results) > 0 {
		r := f.results[0]
		f.results = f.results[1:]
		f.mu.Unlock()
		return r, nil
	}
	f.mu.Unlock()
	<-ctx.Done()
	return watchResult{}, ctx.Err()
}

func (f *fakeWatcher) rearm() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rearmed++
	return nil
}

func (f *fakeWatcher) watchCount() int { return 1 }

func (f *fakeWatcher) close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeWatcher) rearmCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rearmed
}

func TestOnOverflowFallsBackToAFullScan(t *testing.T) {
	// IN_Q_OVERFLOW means the kernel threw the event queue away. Nothing can
	// be replayed, so the only recovery that cannot be wrong is to scan both
	// trees - and to re-arm the watches, because directories created during
	// the gap never produced the IN_CREATE that would have added theirs.
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	var events []Event
	s := newSyncer(t, host, volume, func(c *Config) {
		c.OnEvent = func(e Event) { events = append(events, e) }
	})
	syncOnce(t, s)

	fake := newFakeWatcher()
	s.watchMu.Lock()
	s.watcher = fake
	s.watchMu.Unlock()

	// Changes the watcher never reported, exactly as after a dropped queue.
	write(t, volume, "created/while-overflowed.txt", "missed", 0o644, base)
	write(t, host, "also-missed.txt", "missed", 0o644, base)

	res, err := s.onOverflow(context.Background())
	if err != nil {
		t.Fatalf("onOverflow() error = %v", err)
	}
	if !res.Changed() {
		t.Fatalf("onOverflow() changed nothing: %+v", res)
	}
	if !present(host, "created/while-overflowed.txt") {
		t.Errorf("the missed volume-side file never reached the host")
	}
	if !present(volume, "also-missed.txt") {
		t.Errorf("the missed host-side file never reached the volume")
	}
	if fake.rearmCount() != 1 {
		t.Errorf("rearm called %d times, want 1", fake.rearmCount())
	}
	if got := s.Status().Watches; got != 1 {
		t.Errorf("Status().Watches = %d, want the watcher's own count of 1", got)
	}
	if got := s.Status().Overflows; got != 1 {
		t.Errorf("Status().Overflows = %d, want 1", got)
	}
	found := false
	for _, e := range events {
		if e.Kind == EventOverflow {
			found = true
		}
	}
	if !found {
		t.Errorf("no EventOverflow was emitted")
	}
}

func TestRunPropagatesEditsFromBothSides(t *testing.T) {
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	write(t, host, "app.js", "v1", 0o644, base)

	s := newSyncer(t, host, volume, func(c *Config) {
		c.PollInterval = 20 * time.Millisecond
		c.MaxPollInterval = 80 * time.Millisecond
		c.Debounce = 10 * time.Millisecond
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitFor(t, "initial copy to the volume", func() bool { return present(volume, "app.js") })

	// A Windows-side edit: no inotify event will ever be raised for this, so
	// only the poller can catch it.
	write(t, host, "src/new-on-host.js", "H", 0o644, base.Add(time.Minute))
	waitFor(t, "host edit reaching the volume", func() bool { return present(volume, "src/new-on-host.js") })

	// A volume-side edit, which inotify should catch where it exists and the
	// fallback poller where it does not.
	write(t, volume, "out/new-on-volume.txt", "V", 0o644, base.Add(2*time.Minute))
	waitFor(t, "volume edit reaching the host", func() bool { return present(host, "out/new-on-volume.txt") })

	// A deletion, propagated from the baseline.
	if err := os.Remove(filepath.Join(host, "app.js")); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	waitFor(t, "host deletion reaching the volume", func() bool { return !present(volume, "app.js") })

	if st := s.Status(); !st.Running {
		t.Errorf("Status().Running = false while Run is going")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil on cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("Run() did not return after cancellation")
	}
	if st := s.Status(); st.Running {
		t.Errorf("Status().Running = true after Run returned")
	}
}

func TestRunReturnsNilOnAnAlreadyCancelledContext(t *testing.T) {
	host, volume := pair(t)
	s := newSyncer(t, host, volume, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Run(ctx); err != nil {
		t.Fatalf("Run(cancelled) = %v, want nil", err)
	}
}

func TestRunPollsTheVolumeWhenItCannotBeWatched(t *testing.T) {
	// The Run loop must degrade rather than fail when no watcher can be
	// opened, which is exactly what the windows build of the CLI does.
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	s := newSyncer(t, host, volume, func(c *Config) {
		c.PollInterval = 20 * time.Millisecond
		c.MaxPollInterval = 60 * time.Millisecond
		c.Debounce = 10 * time.Millisecond
	})
	// Pre-install the volume poller that Run sets up for itself when no
	// watcher can be opened - which is what the windows build always does, and
	// what a Linux host out of watch descriptors does too. On Linux a real
	// watcher is opened as well; the poller still has to carry the change on
	// its own schedule, which is what this exercises.
	s.volPoll = newPoller(volume, s.ig, 20*time.Millisecond, 60*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	write(t, volume, "built.txt", "V", 0o644, base)
	waitFor(t, "polled volume edit reaching the host", func() bool { return present(host, "built.txt") })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("Run() did not return after cancellation")
	}
}

func TestIsDone(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"canceled", context.Canceled, true},
		{"deadline", context.DeadlineExceeded, true},
		{"wrapped", errors.New("x: " + context.Canceled.Error()), false},
		{"other", os.ErrPermission, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDone(tt.err); got != tt.want {
				t.Fatalf("isDone(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// waitFor polls a condition until it holds or the test gives up. Everything
// Run does is asynchronous, and a fixed sleep would either be flaky or slow.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
