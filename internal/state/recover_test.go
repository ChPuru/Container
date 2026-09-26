package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChPuru/hull/internal/types"
)

// TestRecoverFlipsStaleRunningContainers is the core crash-recovery case: the
// daemon was SIGKILLed while containers were running, their processes are gone,
// and the store must be told the truth on the next start.
func TestRecoverFlipsStaleRunningContainers(t *testing.T) {
	started := time.Unix(1700000000, 0).UTC()

	tests := []struct {
		name      string
		state     types.State
		pid       int
		alive     bool
		wantState types.State
		wantFlip  bool
	}{
		{"running and gone", types.StateRunning, 4242, false, types.StateExited, true},
		{"restarting and gone", types.StateRestarting, 4243, false, types.StateExited, true},
		{"running and alive", types.StateRunning, 4244, true, types.StateRunning, false},
		{"already exited", types.StateExited, 0, false, types.StateExited, false},
		{"created", types.StateCreated, 0, false, types.StateCreated, false},
		{"paused", types.StatePaused, 4245, false, types.StatePaused, false},
		{"dead", types.StateDead, 0, false, types.StateDead, false},
	}

	s := newTestStore(t)
	ids := make([]string, len(tests))
	for i, tc := range tests {
		id := NewID()
		ids[i] = id
		c := sampleContainer(id, "")
		c.State = tc.state
		c.Pid = tc.pid
		c.StartedAt = started
		c.ExitCode = 0
		if err := s.PutContainer(c); err != nil {
			t.Fatal(err)
		}
	}

	alivePids := map[int]bool{}
	for _, tc := range tests {
		if tc.alive {
			alivePids[tc.pid] = true
		}
	}
	seen := map[int]time.Time{}
	actions, err := s.Recover(t.Context(), func(pid int, startedAt time.Time) bool {
		seen[pid] = startedAt
		return alivePids[pid]
	})
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}

	byID := map[string]RecoveryAction{}
	for _, a := range actions {
		byID[a.ID] = a
	}
	wantFlips := 0
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.GetContainer(ids[i])
			if err != nil {
				t.Fatalf("GetContainer: %v", err)
			}
			if got.State != tc.wantState {
				t.Fatalf("State = %q, want %q", got.State, tc.wantState)
			}
			action, flipped := byID[ids[i]]
			if flipped != tc.wantFlip {
				t.Fatalf("recovery action present = %v, want %v", flipped, tc.wantFlip)
			}
			if !tc.wantFlip {
				return
			}
			if got.ExitCode != DisappearedExitCode {
				t.Errorf("ExitCode = %d, want %d", got.ExitCode, DisappearedExitCode)
			}
			if got.Error != DisappearedProcessError {
				t.Errorf("Error = %q, want %q", got.Error, DisappearedProcessError)
			}
			if got.Pid != 0 {
				t.Errorf("Pid = %d, want 0", got.Pid)
			}
			if got.FinishedAt.IsZero() {
				t.Error("FinishedAt was not set")
			}
			if action.From != tc.state || action.To != types.StateExited {
				t.Errorf("action = %+v, want %q -> exited", action, tc.state)
			}
			if action.Reason != DisappearedProcessError {
				t.Errorf("action.Reason = %q", action.Reason)
			}
			if !strings.Contains(action.String(), string(tc.state)) {
				t.Errorf("action.String() = %q", action.String())
			}
		})
		if tc.wantFlip {
			wantFlips++
		}
	}
	if len(actions) != wantFlips {
		t.Fatalf("got %d actions, want %d", len(actions), wantFlips)
	}

	// The alive callback must be handed the recorded start time so it can
	// detect a recycled pid.
	if ts, ok := seen[4242]; !ok || !ts.Equal(started) {
		t.Errorf("alive() got startedAt %v for pid 4242, want %v", ts, started)
	}

	// Recovery is idempotent: a second pass changes nothing.
	again, err := s.Recover(t.Context(), func(pid int, _ time.Time) bool { return alivePids[pid] })
	if err != nil {
		t.Fatalf("second Recover: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second Recover produced %d actions, want 0", len(again))
	}
}

// TestRecoverSweepsDebris covers the leftovers a SIGKILLed daemon leaves:
// staging files, unfinished content-store ingests and dangling name links.
func TestRecoverSweepsDebris(t *testing.T) {
	s := newTestStore(t)

	id := NewID()
	if err := s.PutContainer(sampleContainer(id, "survivor")); err != nil {
		t.Fatal(err)
	}
	if err := s.ReserveName("survivor", id); err != nil {
		t.Fatal(err)
	}

	stray := filepath.Join(s.ContainerDir(id), "config.json"+tmpSuffix)
	if err := os.WriteFile(stray, []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}

	ingest := filepath.Join(s.Root(), "content", "ingest")
	blob := filepath.Join(ingest, "abcdef123")
	if err := os.WriteFile(blob, []byte("partial blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	ingestDir := filepath.Join(ingest, "subdir")
	if err := os.MkdirAll(ingestDir, 0o700); err != nil {
		t.Fatal(err)
	}

	ghostID := NewID()
	ghostLink := filepath.Join(s.namesDir(), "ghost")
	if err := os.Symlink(nameTarget(ghostID), ghostLink); err != nil {
		t.Fatal(err)
	}
	bogusLink := filepath.Join(s.namesDir(), "bogus")
	if err := os.Symlink("/etc/passwd", bogusLink); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Recover(t.Context(), func(int, time.Time) bool { return true }); err != nil {
		t.Fatalf("Recover: %v", err)
	}

	for _, p := range []string{stray, blob, ingestDir, ghostLink, bogusLink} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived Recover: %v", p, err)
		}
	}
	if got, err := s.lookupName("survivor"); err != nil || got != id {
		t.Errorf("live reservation was swept: %q, %v", got, err)
	}
	if _, err := s.GetContainer(id); err != nil {
		t.Errorf("container record was damaged: %v", err)
	}
}

func TestRecoverSkipsUnreadableRecords(t *testing.T) {
	s := newTestStore(t)
	good := NewID()
	c := sampleContainer(good, "")
	c.State = types.StateRunning
	c.Pid = 99
	if err := s.PutContainer(c); err != nil {
		t.Fatal(err)
	}
	bad := NewID()
	if err := os.MkdirAll(s.ContainerDir(bad), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.ContainerDir(bad), stateFile), []byte("}{"), 0o600); err != nil {
		t.Fatal(err)
	}

	actions, err := s.Recover(t.Context(), func(int, time.Time) bool { return false })
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(actions) != 1 || actions[0].ID != good {
		t.Fatalf("actions = %+v, want only %s", actions, good)
	}
}

func TestRecoverHonoursContextCancellation(t *testing.T) {
	s := newTestStore(t)
	for range 5 {
		c := sampleContainer(NewID(), "")
		c.State = types.StateRunning
		c.Pid = 1234
		if err := s.PutContainer(c); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.Recover(ctx, func(int, time.Time) bool { return false }); !errors.Is(err, context.Canceled) {
		t.Fatalf("Recover with a cancelled context = %v, want context.Canceled", err)
	}
}

func TestRecoverOnEmptyStore(t *testing.T) {
	s := newTestStore(t)
	actions, err := s.Recover(t.Context(), nil)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(actions) != 0 {
		t.Fatalf("actions = %+v, want none", actions)
	}
}
