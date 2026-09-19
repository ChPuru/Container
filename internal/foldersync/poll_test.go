package foldersync

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// equalPaths compares a change list against what a step expected.
func equalPaths(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestPollerDetectsEveryKindOfChange(t *testing.T) {
	// The Windows side of a WSL sync raises no inotify events at all, so
	// everything below is what the syncer would otherwise never be told: a
	// create, an in-place modification, a delete, and a rename - which from
	// outside is exactly a delete plus a create.
	root := t.TempDir()
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	ig, err := NewIgnorer(DefaultIgnores()...)
	if err != nil {
		t.Fatalf("NewIgnorer() error = %v", err)
	}
	p := newPoller(root, ig, 10*time.Millisecond, 100*time.Millisecond)

	write(t, root, "app.js", "v1", 0o644, base)
	write(t, root, "pkg/lib.js", "lib", 0o644, base)

	// The first poll primes the baseline: what is already there is not news.
	c, err := p.poll(context.Background())
	if err != nil {
		t.Fatalf("priming poll() error = %v", err)
	}
	if !c.empty() {
		t.Fatalf("priming poll reported %+v, want nothing", c)
	}

	steps := []struct {
		name         string
		mutate       func(t *testing.T)
		wantCreated  []string
		wantModified []string
		wantDeleted  []string
	}{
		{
			name:        "create",
			mutate:      func(t *testing.T) { write(t, root, "pkg/new.js", "new", 0o644, base) },
			wantCreated: []string{"pkg/new.js"},
		},
		{
			name:         "modify in place",
			mutate:       func(t *testing.T) { write(t, root, "app.js", "v2", 0o644, base.Add(time.Second)) },
			wantModified: []string{"app.js"},
		},
		{
			name: "modify without changing the size",
			// Same length, different bytes: only the timestamp gives it away,
			// which is why (size, mtime) and not size alone is the key.
			mutate:       func(t *testing.T) { write(t, root, "app.js", "v3", 0o644, base.Add(2*time.Second)) },
			wantModified: []string{"app.js"},
		},
		{
			name: "delete",
			mutate: func(t *testing.T) {
				if err := os.Remove(filepath.Join(root, "pkg", "new.js")); err != nil {
					t.Fatalf("Remove() error = %v", err)
				}
			},
			wantDeleted: []string{"pkg/new.js"},
		},
		{
			name: "rename",
			mutate: func(t *testing.T) {
				from := filepath.Join(root, "pkg", "lib.js")
				to := filepath.Join(root, "pkg", "renamed.js")
				if err := os.Rename(from, to); err != nil {
					t.Fatalf("Rename() error = %v", err)
				}
			},
			wantCreated: []string{"pkg/renamed.js"},
			wantDeleted: []string{"pkg/lib.js"},
		},
		{
			name:        "ignored directory is invisible",
			mutate:      func(t *testing.T) { write(t, root, "node_modules/react/index.js", "huge", 0o644, base) },
			wantCreated: nil,
		},
		{
			name:   "nothing at all",
			mutate: func(t *testing.T) {},
		},
	}

	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			st.mutate(t)
			c, err := p.poll(context.Background())
			if err != nil {
				t.Fatalf("poll() error = %v", err)
			}
			if !equalPaths(c.created, st.wantCreated) {
				t.Errorf("created = %q, want %q", c.created, st.wantCreated)
			}
			if !equalPaths(c.modified, st.wantModified) {
				t.Errorf("modified = %q, want %q", c.modified, st.wantModified)
			}
			if !equalPaths(c.deleted, st.wantDeleted) {
				t.Errorf("deleted = %q, want %q", c.deleted, st.wantDeleted)
			}
			wantCount := len(st.wantCreated) + len(st.wantModified) + len(st.wantDeleted)
			if c.count() != wantCount {
				t.Errorf("count() = %d, want %d", c.count(), wantCount)
			}
		})
	}
}

func TestPollerBacksOffWhenIdleAndSnapsBack(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	ig, err := NewIgnorer()
	if err != nil {
		t.Fatalf("NewIgnorer() error = %v", err)
	}

	const (
		floor   = 50 * time.Millisecond
		ceiling = 400 * time.Millisecond
	)
	p := newPoller(root, ig, floor, ceiling)

	if got := p.currentInterval(); got != floor {
		t.Fatalf("initial interval = %v, want %v", got, floor)
	}

	// Priming plus four idle polls: 50 -> 100 -> 200 -> 400 -> 400 (capped).
	want := []time.Duration{floor, 2 * floor, 4 * floor, ceiling, ceiling}
	for i, w := range want {
		if _, err := p.poll(context.Background()); err != nil {
			t.Fatalf("poll(%d) error = %v", i, err)
		}
		if got := p.currentInterval(); got != w {
			t.Fatalf("interval after idle poll %d = %v, want %v", i, got, w)
		}
	}

	// One change and the syncer is responsive again immediately.
	write(t, root, "app.js", "v1", 0o644, base)
	c, err := p.poll(context.Background())
	if err != nil {
		t.Fatalf("poll() error = %v", err)
	}
	if c.empty() {
		t.Fatalf("poll() saw no change")
	}
	if got := p.currentInterval(); got != floor {
		t.Fatalf("interval after a change = %v, want %v", got, floor)
	}
}

func TestPollerSetBaselineSuppressesTheSyncersOwnWrites(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	ig, err := NewIgnorer()
	if err != nil {
		t.Fatalf("NewIgnorer() error = %v", err)
	}
	p := newPoller(root, ig, 10*time.Millisecond, 100*time.Millisecond)

	write(t, root, "written-by-the-syncer.txt", "x", 0o644, base)
	observed, _, err := scanTree(context.Background(), root, ig)
	if err != nil {
		t.Fatalf("scanTree() error = %v", err)
	}
	p.setBaseline(observed)

	c, err := p.poll(context.Background())
	if err != nil {
		t.Fatalf("poll() error = %v", err)
	}
	if !c.empty() {
		t.Fatalf("poll() reported %+v after setBaseline, want nothing", c)
	}

	p.reset()
	if got := p.currentInterval(); got != 10*time.Millisecond {
		t.Fatalf("interval after reset = %v, want the floor", got)
	}
}

func TestPollerHonoursContextCancellation(t *testing.T) {
	root := t.TempDir()
	ig, err := NewIgnorer()
	if err != nil {
		t.Fatalf("NewIgnorer() error = %v", err)
	}
	p := newPoller(root, ig, 10*time.Millisecond, 100*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.poll(ctx); err == nil {
		t.Fatalf("poll(cancelled) error = nil, want a context error")
	}
}
