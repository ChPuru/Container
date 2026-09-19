package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/logbuf"
	"github.com/rahuldhali/hull/internal/types"
)

// collectEvents subscribes to the bus and returns a function that drains what
// has arrived so far.
func collectEvents(t *testing.T, te *testEngine) func() []types.Event {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch, stop := te.bus.Subscribe(ctx, events.Filter{}, time.Time{}, time.Time{})
	t.Cleanup(stop)

	var mu sync.Mutex
	var seen []types.Event
	go func() {
		for ev := range ch {
			mu.Lock()
			seen = append(seen, ev)
			mu.Unlock()
		}
	}()
	return func() []types.Event {
		// Give the bus a moment to deliver.
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		return append([]types.Event(nil), seen...)
	}
}

// hasAction reports whether any collected event carries the action.
func hasAction(evs []types.Event, action string) bool {
	for _, ev := range evs {
		if ev.Action == action || strings.HasPrefix(ev.Action, action+":") {
			return true
		}
	}
	return false
}

func TestStartAttachesTheNetworkAndPublishesPorts(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	drain := collectEvents(t, te)

	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	c, err := te.Create(ctx, "svc", types.ContainerConfig{
		ExposedPorts: map[string]struct{}{"80/tcp": {}},
	}, types.HostConfig{
		PortBindings: map[string][]types.PortBinding{"80/tcp": {{HostPort: "8080"}}},
	}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	sup := te.spawner.supervisor(t, c.ID)

	got, err := te.Inspect(ctx, c.ID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.State != types.StateRunning {
		t.Errorf("state = %q, want running", got.State)
	}
	if got.Pid != sup.pid {
		t.Errorf("pid = %d, want %d", got.Pid, sup.pid)
	}
	if got.StartedAt.IsZero() {
		t.Error("startedAt was not recorded")
	}
	ep, ok := got.NetworkSettings.Networks["bridge"]
	if !ok || ep.IPAddress == "" {
		t.Errorf("no address was allocated at start: %+v", got.NetworkSettings.Networks)
	}
	if len(got.NetworkSettings.Ports["80/tcp"]) == 0 {
		t.Errorf("the published port was not recorded: %v", got.NetworkSettings.Ports)
	}
	if len(te.nets.published[c.ID]) == 0 {
		t.Error("the network manager was never asked to publish the port")
	}
	if !hasAction(drain(), events.ActionStart) {
		t.Error("no start event was published")
	}

	// Starting an already-running container is a no-op, not an error.
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Errorf("starting a running container = %v, want nil", err)
	}
	if te.spawner.spawned != 1 {
		t.Errorf("%d shims were spawned, want 1", te.spawner.spawned)
	}
}

func TestStopSendsTheStopSignalThenGivesUpAndKills(t *testing.T) {
	zero := 0
	tests := []struct {
		name       string
		ignoreTerm bool
		stopSignal string
		timeout    *int
		wantFirst  int
		wantKill   bool
	}{
		{name: "SIGTERM is enough", wantFirst: 15},
		{name: "the image stop signal is honoured", stopSignal: "SIGQUIT", wantFirst: 3},
		{name: "an ignored signal escalates to SIGKILL", ignoreTerm: true, timeout: &zero, wantFirst: 15, wantKill: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			te := newTestEngine(t)
			ctx := context.Background()
			te.seedImage(t, "test:latest", types.ImageConfig{
				Cmd:        []string{"/bin/sh"},
				StopSignal: tt.stopSignal,
			})
			c, err := te.Create(ctx, "stoppable", types.ContainerConfig{}, types.HostConfig{}, "test:latest")
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if err := te.Start(ctx, c.ID, nil); err != nil {
				t.Fatalf("Start: %v", err)
			}
			sup := te.spawner.supervisor(t, c.ID)
			sup.mu.Lock()
			sup.ignoreTerm = tt.ignoreTerm
			sup.mu.Unlock()

			if err := te.Stop(ctx, c.ID, tt.timeout); err != nil {
				t.Fatalf("Stop: %v", err)
			}

			sup.mu.Lock()
			if len(sup.signals) == 0 {
				sup.mu.Unlock()
				t.Fatal("no signal reached the container")
			}
			first := int(sup.signals[0])
			all := append([]syscall.Signal(nil), sup.signals...)
			sup.mu.Unlock()

			if first != tt.wantFirst {
				t.Errorf("first signal = %d, want %d", first, tt.wantFirst)
			}
			if tt.wantKill {
				if len(all) < 2 || int(all[len(all)-1]) != 9 {
					t.Errorf("signals = %v, want an eventual SIGKILL", all)
				}
			}

			got := te.waitForState(t, c.ID, types.StateExited)
			if got.FinishedAt.IsZero() {
				t.Error("finishedAt was not recorded")
			}
			if got.Pid != 0 {
				t.Errorf("pid = %d after exit, want 0", got.Pid)
			}

			// Stopping again is a no-op.
			if err := te.Stop(ctx, c.ID, nil); err != nil {
				t.Errorf("stopping an already-stopped container = %v, want nil", err)
			}
		})
	}
}

func TestStopReleasesPortsAndEndpoints(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	c, err := te.Create(ctx, "netty", types.ContainerConfig{}, types.HostConfig{
		PortBindings: map[string][]types.PortBinding{"80/tcp": {{HostPort: "8081"}}},
	}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := te.Stop(ctx, c.ID, nil); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	te.waitForState(t, c.ID, types.StateExited)

	deadline := time.Now().Add(2 * time.Second)
	for {
		te.nets.mu.Lock()
		unpublished := len(te.nets.unpublished)
		disconnected := len(te.nets.disconnected)
		te.nets.mu.Unlock()
		if unpublished > 0 && disconnected > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ports/endpoints were not released on exit (unpublish=%d disconnect=%d)",
				unpublished, disconnected)
		}
		time.Sleep(10 * time.Millisecond)
	}

	sup := te.spawner.supervisor(t, c.ID)
	sup.mu.Lock()
	acked := sup.acked
	sup.mu.Unlock()
	if !acked {
		t.Error("the shim was never told the exit had been recorded, so it will sit out its grace period")
	}
}

func TestKillSendsAnExplicitSignal(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	c := te.createTestContainer(t, "killable")
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := te.Kill(ctx, c.ID, "SIGUSR1"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	sup := te.spawner.supervisor(t, c.ID)
	sup.mu.Lock()
	first := int(sup.signals[0])
	sup.mu.Unlock()
	if first != 10 {
		t.Errorf("signal = %d, want 10 (SIGUSR1)", first)
	}

	// The fake exits on any signal, so the container is gone now.
	te.waitForState(t, c.ID, types.StateExited)
	if err := te.Kill(ctx, c.ID, "SIGTERM"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("killing a stopped container = %v, want ErrNotRunning", err)
	}
}

func TestWaitConditions(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()

	t.Run("not-running returns immediately for a created container", func(t *testing.T) {
		c := te.createTestContainer(t, "waiter1")
		code, err := te.Wait(ctx, c.ID, WaitNotRunning)
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	})

	t.Run("not-running blocks until the container exits", func(t *testing.T) {
		c := te.createTestContainer(t, "waiter2")
		if err := te.Start(ctx, c.ID, nil); err != nil {
			t.Fatalf("Start: %v", err)
		}
		sup := te.spawner.supervisor(t, c.ID)

		done := make(chan int, 1)
		go func() {
			code, werr := te.Wait(ctx, c.ID, WaitNotRunning)
			if werr != nil {
				t.Errorf("Wait: %v", werr)
			}
			done <- code
		}()
		time.Sleep(50 * time.Millisecond)
		sup.exit(42, false)

		select {
		case code := <-done:
			if code != 42 {
				t.Errorf("exit code = %d, want 42", code)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Wait never returned")
		}
	})

	t.Run("removed waits for the record to disappear", func(t *testing.T) {
		c := te.createTestContainer(t, "waiter3")
		done := make(chan int, 1)
		go func() {
			code, werr := te.Wait(ctx, c.ID, WaitRemoved)
			if werr != nil {
				t.Errorf("Wait: %v", werr)
			}
			done <- code
		}()
		time.Sleep(50 * time.Millisecond)
		if err := te.Remove(ctx, c.ID, true, false); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Wait(removed) never returned")
		}
	})

	t.Run("an unknown condition is rejected", func(t *testing.T) {
		c := te.createTestContainer(t, "waiter4")
		if _, err := te.Wait(ctx, c.ID, "eventually"); !errors.Is(err, ErrInvalid) {
			t.Errorf("Wait with a bad condition = %v, want ErrInvalid", err)
		}
	})

	t.Run("a cancelled context stops waiting", func(t *testing.T) {
		c := te.createTestContainer(t, "waiter5")
		if err := te.Start(ctx, c.ID, nil); err != nil {
			t.Fatalf("Start: %v", err)
		}
		cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		if _, err := te.Wait(cctx, c.ID, WaitNextExit); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Wait = %v, want a deadline error", err)
		}
	})
}

func TestRemoveRefusesARunningContainerWithoutForce(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	c := te.createTestContainer(t, "busy")
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := te.Remove(ctx, c.ID, false, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("Remove without force = %v, want ErrConflict", err)
	}
	if err := te.Remove(ctx, c.ID, true, true); err != nil {
		t.Fatalf("Remove with force: %v", err)
	}
	if _, err := te.lookup(c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the container record survived removal: %v", err)
	}
	if len(te.snaps.removed) == 0 {
		t.Error("the rootfs was not removed")
	}
	if len(te.vols.released) == 0 {
		t.Error("volume references were not released")
	}
}

func TestAutoRemoveTakesTheContainerAwayOnExit(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	c, err := te.Create(ctx, "ephemeral", types.ContainerConfig{},
		types.HostConfig{AutoRemove: true}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	te.spawner.supervisor(t, c.ID).exit(0, false)

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := te.lookup(c.ID); errors.Is(err, ErrNotFound) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("an --rm container was not removed after it exited")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRestartPolicyStartsTheContainerAgain(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	c, err := te.Create(ctx, "resilient", types.ContainerConfig{}, types.HostConfig{
		RestartPolicy: types.RestartPolicy{Name: "on-failure", MaximumRetryCount: 1},
	}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	te.spawner.supervisor(t, c.ID).exit(1, false)

	// The first backoff is 100ms, so this should not take long.
	deadline := time.Now().Add(5 * time.Second)
	for {
		te.spawner.mu.Lock()
		spawned := te.spawner.spawned
		te.spawner.mu.Unlock()
		if spawned >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the restart policy never restarted the container (%d shims spawned)", spawned)
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := te.waitForState(t, c.ID, types.StateRunning)
	if got.RestartCount != 1 {
		t.Errorf("restartCount = %d, want 1", got.RestartCount)
	}
}

func TestAnExplicitStopSuppressesTheRestartPolicy(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	c, err := te.Create(ctx, "obedient", types.ContainerConfig{}, types.HostConfig{
		RestartPolicy: types.RestartPolicy{Name: "always"},
	}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := te.Stop(ctx, c.ID, nil); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	te.waitForState(t, c.ID, types.StateExited)

	// Give any stray restart a generous chance to happen.
	time.Sleep(500 * time.Millisecond)
	te.spawner.mu.Lock()
	spawned := te.spawner.spawned
	te.spawner.mu.Unlock()
	if spawned != 1 {
		t.Errorf("%d shims were spawned; an explicit stop must suppress the restart policy", spawned)
	}
	if !te.manuallyStopped(c.ID) {
		t.Error("the manual-stop marker was not recorded, so unless-stopped would not survive a restart")
	}
	// Starting it again clears the marker.
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start after Stop: %v", err)
	}
	if te.manuallyStopped(c.ID) {
		t.Error("an explicit start did not clear the manual-stop marker")
	}
}

func TestPauseReportsTheMissingFreezerHonestly(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	c := te.createTestContainer(t, "frozen")
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// This host has no usable cgroup v2 hierarchy, so a pause cannot work and
	// must say so rather than pretending the container is frozen.
	err := te.Pause(ctx, c.ID)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Pause = %v, want ErrUnsupported", err)
	}
	got, err := te.Inspect(ctx, c.ID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.State != types.StateRunning {
		t.Errorf("state = %q after a failed pause, want running", got.State)
	}
}

func TestExecRunsAndRecordsItsExitCode(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	c := te.createTestContainer(t, "execable")
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	sup := te.spawner.supervisor(t, c.ID)
	sup.execCode = 3

	execID, err := te.Exec(ctx, c.ID, ExecConfig{Cmd: []string{"/bin/true"}})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	insp, err := te.ExecInspect(ctx, execID)
	if err != nil {
		t.Fatalf("ExecInspect: %v", err)
	}
	if insp.Started || insp.Running {
		t.Error("an exec should not be running before ExecStart")
	}

	var out strings.Builder
	if err := te.ExecStart(ctx, execID, AttachConfig{Stdout: &out, UseStdout: true}); err != nil {
		t.Fatalf("ExecStart: %v", err)
	}
	insp, err = te.ExecInspect(ctx, execID)
	if err != nil {
		t.Fatalf("ExecInspect after start: %v", err)
	}
	if !insp.Started || insp.Running {
		t.Errorf("exec state after completion: started=%v running=%v", insp.Started, insp.Running)
	}
	if insp.ExitCode != 3 {
		t.Errorf("exit code = %d, want 3", insp.ExitCode)
	}
	if _, err := te.ExecInspect(ctx, "nosuchexec"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ExecInspect on an unknown id = %v, want ErrNotFound", err)
	}
}

func TestExecRefusesAStoppedContainer(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	c := te.createTestContainer(t, "stopped")
	if _, err := te.Exec(ctx, c.ID, ExecConfig{Cmd: []string{"/bin/true"}}); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Exec on a created container = %v, want ErrNotRunning", err)
	}
}

func TestExecNeedsACommand(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	c := te.createTestContainer(t, "nocmd")
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := te.Exec(ctx, c.ID, ExecConfig{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Exec with no command = %v, want ErrInvalid", err)
	}
}

func TestHealthTransitionsAndEvents(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	drain := collectEvents(t, te)

	te.seedImage(t, "test:latest", types.ImageConfig{
		Cmd: []string{"/bin/sh"},
		Healthcheck: &types.Healthcheck{
			Test:     []string{"CMD", "/bin/true"},
			Interval: 20 * time.Millisecond,
			Timeout:  time.Second,
			Retries:  1,
		},
	})
	c, err := te.Create(ctx, "healthy", types.ContainerConfig{}, types.HostConfig{}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.Config.Healthcheck == nil {
		t.Fatal("the image healthcheck was not merged into the container")
	}
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	sup := te.spawner.supervisor(t, c.ID)

	waitHealth := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			got, err := te.Inspect(ctx, c.ID)
			if err == nil && got.Health != nil && got.Health.Status == want {
				return
			}
			if time.Now().After(deadline) {
				status := "<none>"
				if got, err := te.Inspect(ctx, c.ID); err == nil && got.Health != nil {
					status = got.Health.Status
				}
				t.Fatalf("health never became %q (it is %q)", want, status)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	waitHealth(HealthHealthy)

	// Break the probe: one failure is enough, because Retries is 1.
	sup.mu.Lock()
	sup.execCode = 1
	sup.mu.Unlock()
	waitHealth(HealthUnhealthy)

	got, err := te.Inspect(ctx, c.ID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(got.Health.Log) == 0 {
		t.Error("no probe results were recorded")
	}
	if len(got.Health.Log) > maxHealthLog {
		t.Errorf("the health log grew to %d entries, want at most %d", len(got.Health.Log), maxHealthLog)
	}
	if !hasAction(drain(), events.ActionHealthStatus) {
		t.Error("no health_status event was published on the transition")
	}
}

func TestHealthStartPeriodDoesNotFailTheContainer(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{
		Cmd: []string{"/bin/sh"},
		Healthcheck: &types.Healthcheck{
			Test:        []string{"CMD", "/bin/false"},
			Interval:    10 * time.Millisecond,
			Timeout:     time.Second,
			Retries:     1,
			StartPeriod: 2 * time.Second,
		},
	})
	c, err := te.Create(ctx, "slowboot", types.ContainerConfig{}, types.HostConfig{}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	te.spawner.supervisor(t, c.ID).execCode = 1

	// Several probes will have failed by now; inside the start period none of
	// them may make the container unhealthy.
	time.Sleep(200 * time.Millisecond)
	got, err := te.Inspect(ctx, c.ID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.Health == nil {
		t.Fatal("no health state was recorded")
	}
	if got.Health.Status != HealthStarting {
		t.Errorf("health = %q during the start period, want %q", got.Health.Status, HealthStarting)
	}
	if got.Health.FailingStreak != 0 {
		t.Errorf("failing streak = %d during the start period, want 0", got.Health.FailingStreak)
	}
}

func TestStatsReturnsOneSampleWithoutStreaming(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	c := te.createTestContainer(t, "measured")
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	sup := te.spawner.supervisor(t, c.ID)
	sup.mu.Lock()
	sup.stats = types.Stats{CPUUsage: 1234, MemoryUsage: 5678}
	sup.mu.Unlock()

	var samples []types.Stats
	if err := te.Stats(ctx, c.ID, false, func(s types.Stats) error {
		samples = append(samples, s)
		return nil
	}); err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(samples) != 1 {
		t.Fatalf("%d samples were delivered, want 1", len(samples))
	}
	if samples[0].CPUUsage != 1234 || samples[0].MemoryUsage != 5678 {
		t.Errorf("sample = %+v, want the shim's numbers", samples[0])
	}
	if samples[0].Read.IsZero() {
		t.Error("the sample has no timestamp")
	}

	// A second call reuses the first as its "pre" half, so a CPU percentage
	// can be computed without a second's latency.
	var second types.Stats
	if err := te.Stats(ctx, c.ID, false, func(s types.Stats) error {
		second = s
		return nil
	}); err != nil {
		t.Fatalf("Stats again: %v", err)
	}
	if second.PreCPUUsage != 1234 {
		t.Errorf("preCpuUsage = %d, want 1234 from the cached sample", second.PreCPUUsage)
	}
}

func TestLogsRefuseTheNoneDriver(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	c, err := te.Create(ctx, "quiet", types.ContainerConfig{}, types.HostConfig{
		LogConfig: types.LogConfig{Type: "none"},
	}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	var sink strings.Builder
	if err := te.Logs(ctx, c.ID, logbuf.ReadOptions{Tail: -1, Stdout: true, Stderr: true}, &sink, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("Logs on a none-driver container = %v, want ErrConflict", err)
	}
}

func TestOperationsOnAClosedEngineAreRefused(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.createTestContainer(t, "doomed")
	if err := te.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := te.Create(ctx, "later", types.ContainerConfig{}, types.HostConfig{}, "test:latest"); !errors.Is(err, ErrClosed) {
		t.Errorf("Create after Close = %v, want ErrClosed", err)
	}
	if err := te.Start(ctx, "doomed", nil); !errors.Is(err, ErrClosed) {
		t.Errorf("Start after Close = %v, want ErrClosed", err)
	}
}

func TestConcurrentOperationsOnDifferentContainers(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})

	const n = 8
	var wg sync.WaitGroup
	ids := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := te.Create(ctx, "", types.ContainerConfig{}, types.HostConfig{}, "test:latest")
			if err != nil {
				errs[i] = err
				return
			}
			ids[i] = c.ID
			errs[i] = te.Start(ctx, c.ID, nil)
		}(i)
	}
	// Listing must never be blocked by the creates.
	listed := make(chan int, 1)
	go func() {
		count := 0
		for i := 0; i < 20; i++ {
			out, err := te.List(ctx, ListOptions{All: true})
			if err != nil {
				t.Errorf("List during concurrent creates: %v", err)
				break
			}
			count = len(out)
			time.Sleep(time.Millisecond)
		}
		listed <- count
	}()
	wg.Wait()
	<-listed

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	out, err := te.List(ctx, ListOptions{All: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != n {
		t.Errorf("%d containers listed, want %d", len(out), n)
	}
}
