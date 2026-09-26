//go:build linux

package state

import (
	"os"
	"testing"
	"time"

	"github.com/ChPuru/hull/internal/types"
)

func TestRecoverUsesProcessAliveByDefault(t *testing.T) {
	s := newTestStore(t)

	// A container whose recorded pid does not exist at all.
	goneID := NewID()
	gone := sampleContainer(goneID, "")
	gone.State = types.StateRunning
	gone.Pid = 0x7FFFFFFE // far above any live pid
	gone.StartedAt = time.Now().Add(-time.Minute)
	if err := s.PutContainer(gone); err != nil {
		t.Fatal(err)
	}

	// A container "running" as this very test process, with a StartedAt close
	// enough to the process's real start time to pass the recycle check.
	selfID := NewID()
	self := sampleContainer(selfID, "")
	self.State = types.StateRunning
	self.Pid = os.Getpid()
	start, _, err := procStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("procStartTime: %v", err)
	}
	self.StartedAt = start
	if err := s.PutContainer(self); err != nil {
		t.Fatal(err)
	}

	actions, err := s.Recover(t.Context(), nil)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(actions) != 1 || actions[0].ID != goneID {
		t.Fatalf("actions = %+v, want only %s", actions, goneID)
	}
	if c, _ := s.GetContainer(selfID); c.State != types.StateRunning {
		t.Errorf("live container was reaped: %q", c.State)
	}
}

func TestProcessAlive(t *testing.T) {
	if ProcessAlive(0, time.Time{}) {
		t.Error("ProcessAlive(0) = true, want false")
	}
	if ProcessAlive(-1, time.Time{}) {
		t.Error("ProcessAlive(-1) = true, want false")
	}
	if !ProcessAlive(os.Getpid(), time.Time{}) {
		t.Error("ProcessAlive(self, zero time) = false, want true")
	}
	start, _, err := procStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("procStartTime: %v", err)
	}
	if !ProcessAlive(os.Getpid(), start) {
		t.Error("ProcessAlive(self, real start time) = false, want true")
	}
	// A pid recycled long after the container started must read as dead.
	if ProcessAlive(os.Getpid(), start.Add(-24*time.Hour)) {
		t.Error("ProcessAlive did not detect a recycled pid")
	}
	if ProcessAlive(0x7FFFFFFE, time.Time{}) {
		t.Error("ProcessAlive on a nonexistent pid = true, want false")
	}
}
