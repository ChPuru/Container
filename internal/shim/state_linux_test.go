package shim

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestProcessStartTime(t *testing.T) {
	t.Parallel()
	self, err := ProcessStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("ProcessStartTime(self): %v", err)
	}
	if self == 0 {
		t.Fatal("our own start time is 0, which cannot be right")
	}
	again, err := ProcessStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("ProcessStartTime(self) twice: %v", err)
	}
	if again != self {
		t.Fatalf("start time changed between reads: %d then %d", self, again)
	}

	// PID 1 exists in every namespace and started before us.
	init, err := ProcessStartTime(1)
	if err != nil {
		t.Fatalf("ProcessStartTime(1): %v", err)
	}
	if init > self {
		t.Errorf("pid 1 start time %d is after ours %d", init, self)
	}

	if _, err := ProcessStartTime(0); err == nil {
		t.Error("ProcessStartTime(0) should fail")
	}
	if _, err := ProcessStartTime(-1); err == nil {
		t.Error("ProcessStartTime(-1) should fail")
	}
	// A pid that is almost certainly not in use.
	if _, err := ProcessStartTime(4_000_000); err == nil {
		t.Error("ProcessStartTime of a dead pid should fail")
	}
}

// TestProcessStartTimeHandlesSpacesInComm covers the parse trap: the comm
// field is parenthesised and may contain spaces and parentheses of its own, so
// the parse has to start after the LAST ')'.
func TestProcessStartTimeHandlesSpacesInComm(t *testing.T) {
	t.Parallel()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on this host")
	}
	// argv[0] with spaces and parentheses becomes the comm.
	cmd := exec.Command(sh, "-c", "exec -a 'we ird) name' sleep 5")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		st, err := ProcessStartTime(cmd.Process.Pid)
		if err == nil && st > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ProcessStartTime of a process with an odd comm: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestShimStateValidate(t *testing.T) {
	t.Parallel()
	start, err := ProcessStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("ProcessStartTime: %v", err)
	}
	tests := []struct {
		name  string
		state ShimState
		want  bool
	}{
		{"this process", ShimState{Pid: os.Getpid(), StartTime: start}, true},
		{"right pid, wrong start time", ShimState{Pid: os.Getpid(), StartTime: start + 1}, false},
		{"no start time recorded falls back to pid liveness", ShimState{Pid: os.Getpid()}, true},
		{"dead pid", ShimState{Pid: 4_000_000, StartTime: start}, false},
		{"zero pid", ShimState{}, false},
		{"negative pid", ShimState{Pid: -5}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.Validate(); got != tt.want {
				t.Fatalf("Validate = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestShimStateValidateCatchesARecycledPid is the point of recording the start
// time at all: a pid that has been handed to a different process must not be
// mistaken for the shim.
func TestShimStateValidateCatchesARecycledPid(t *testing.T) {
	t.Parallel()
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	start, err := ProcessStartTime(pid)
	if err != nil {
		// It may already be gone; that is fine for this test's purpose.
		start = 1
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	// The pid is now free. Whether it has been reused or not, a record whose
	// start time does not match must not validate.
	bogus := ShimState{Pid: pid, StartTime: start + 1_000_000}
	if bogus.Validate() {
		t.Fatal("a record with a mismatched start time validated")
	}
}

func TestCleanStale(t *testing.T) {
	t.Parallel()

	t.Run("nothing there", func(t *testing.T) {
		t.Parallel()
		removed, err := CleanStale(t.TempDir())
		if err != nil {
			t.Fatalf("CleanStale: %v", err)
		}
		if removed {
			t.Error("CleanStale reported a removal in an empty directory")
		}
	})

	t.Run("dead shim is cleaned", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := WriteShimState(StatePath(dir), ShimState{
			Pid: 4_000_000, StartTime: 1, Socket: SocketPath(dir), ContainerID: "x",
		}); err != nil {
			t.Fatalf("WriteShimState: %v", err)
		}
		if err := os.WriteFile(SocketPath(dir), nil, 0o600); err != nil {
			t.Fatalf("write fake socket: %v", err)
		}
		removed, err := CleanStale(dir)
		if err != nil {
			t.Fatalf("CleanStale: %v", err)
		}
		if !removed {
			t.Fatal("CleanStale did not report removing the dead shim's state")
		}
		if _, err := os.Stat(StatePath(dir)); !errors.Is(err, os.ErrNotExist) {
			t.Error("shim.json survived CleanStale")
		}
		if _, err := os.Stat(SocketPath(dir)); !errors.Is(err, os.ErrNotExist) {
			t.Error("the stale socket survived CleanStale")
		}
	})

	t.Run("live shim is left alone", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		start, err := ProcessStartTime(os.Getpid())
		if err != nil {
			t.Fatalf("ProcessStartTime: %v", err)
		}
		if err := WriteShimState(StatePath(dir), ShimState{
			Pid: os.Getpid(), StartTime: start, Socket: SocketPath(dir), ContainerID: "x",
		}); err != nil {
			t.Fatalf("WriteShimState: %v", err)
		}
		removed, err := CleanStale(dir)
		if err != nil {
			t.Fatalf("CleanStale: %v", err)
		}
		if removed {
			t.Fatal("CleanStale removed a live shim's state")
		}
		if _, err := os.Stat(StatePath(dir)); err != nil {
			t.Errorf("shim.json was removed: %v", err)
		}
	})
}

func TestReconnectReportsAMissingShim(t *testing.T) {
	t.Parallel()

	t.Run("no shim.json", func(t *testing.T) {
		t.Parallel()
		_, err := Reconnect(t.TempDir())
		if !errors.Is(err, ErrShimGone) {
			t.Fatalf("err = %v, want ErrShimGone", err)
		}
	})

	t.Run("dead pid", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := WriteShimState(StatePath(dir), ShimState{
			Pid: 4_000_000, StartTime: 12345, Socket: SocketPath(dir), ContainerID: "x",
		}); err != nil {
			t.Fatalf("WriteShimState: %v", err)
		}
		_, err := Reconnect(dir)
		if !errors.Is(err, ErrShimGone) {
			t.Fatalf("err = %v, want ErrShimGone", err)
		}
	})

	t.Run("live pid but no socket", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		start, err := ProcessStartTime(os.Getpid())
		if err != nil {
			t.Fatalf("ProcessStartTime: %v", err)
		}
		if err := WriteShimState(StatePath(dir), ShimState{
			Pid: os.Getpid(), StartTime: start, Socket: SocketPath(dir), ContainerID: "x",
		}); err != nil {
			t.Fatalf("WriteShimState: %v", err)
		}
		_, err = Reconnect(dir)
		if !errors.Is(err, ErrShimGone) {
			t.Fatalf("err = %v, want ErrShimGone", err)
		}
	})
}
