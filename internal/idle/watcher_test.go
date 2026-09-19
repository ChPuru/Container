package idle

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWatcherFreezesAnIdleContainerAndEmitsAPauseEvent(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	h.src.edit("c1", func(c *fakeCtr) { c.ports = 2 })
	ctx := context.Background()

	h.w.Sample(ctx)
	if h.src.frozen("c1") {
		t.Fatal("froze a container the watcher had only just met")
	}
	h.clk.add(30 * time.Second)
	h.w.Sample(ctx)
	if h.src.frozen("c1") {
		t.Fatal("froze a container before FreezeAfter had elapsed")
	}

	h.clk.add(31 * time.Second)
	h.w.Sample(ctx)
	h.settle("c1", true)

	if got := h.freezeCallbacks(); len(got) != 1 || got[0] != "c1" {
		t.Fatalf("OnFreeze calls = %v, want [c1]", got)
	}
	evs := h.eventsFor("c1")
	if len(evs) != 1 {
		t.Fatalf("events = %v, want exactly one", evs)
	}
	ev := evs[0]
	if ev.Action != ActionPause || ev.Reason != ReasonIdle {
		t.Errorf("event = %s/%s, want %s/%s", ev.Action, ev.Reason, ActionPause, ReasonIdle)
	}
	if ev.IdleFor != 61*time.Second {
		t.Errorf("event IdleFor = %v, want 61s", ev.IdleFor)
	}
	if ev.PublishedPorts != 2 {
		t.Errorf("event PublishedPorts = %d, want 2", ev.PublishedPorts)
	}
	if attrs := ev.Attributes(); attrs["reason"] != ReasonIdle || attrs["publishedPorts"] != "2" {
		t.Errorf("event attributes = %v", attrs)
	}
}

// TestActivityKeepsAContainerAwake walks each activity signal in turn: an open
// stream, a byte through the port proxy, CPU movement above the floor and a
// bare Touch must each hold the freeze off indefinitely, and a CPU heartbeat
// below the floor must not.
func TestActivityKeepsAContainerAwake(t *testing.T) {
	cases := []struct {
		name      string
		busy      func(h *harness)
		wantFroze bool
	}{
		{
			name: "attach stream open",
			busy: func(h *harness) { h.src.edit("c1", func(c *fakeCtr) { c.attached = 1 }) },
		},
		{
			name: "exec stream open",
			busy: func(h *harness) { h.src.edit("c1", func(c *fakeCtr) { c.attached = 3 }) },
		},
		{
			name: "bytes through the port proxy",
			busy: func(h *harness) { h.w.TouchWith("c1", ReasonPort) },
		},
		{
			name: "explicit touch from the api",
			busy: func(h *harness) { h.w.Touch("c1") },
		},
		{
			name: "cpu usage above the floor",
			busy: func(h *harness) { h.src.edit("c1", func(c *fakeCtr) { c.cpu += 50_000 }) },
		},
		{
			name:      "cpu heartbeat below the floor",
			busy:      func(h *harness) { h.src.edit("c1", func(c *fakeCtr) { c.cpu += 100 }) },
			wantFroze: true,
		},
		{
			name:      "nothing at all",
			busy:      func(h *harness) {},
			wantFroze: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Config{FreezeAfter: time.Minute, CPUFloorUsec: 10_000})
			h.src.add("c1")
			ctx := context.Background()
			h.w.Sample(ctx)

			// Ten windows' worth of time, in twenty steps.
			for i := 0; i < 20; i++ {
				tc.busy(h)
				h.clk.add(30 * time.Second)
				h.w.Sample(ctx)
			}
			if got := h.src.frozen("c1"); got != tc.wantFroze {
				t.Fatalf("frozen = %v, want %v", got, tc.wantFroze)
			}
			if !tc.wantFroze && len(h.freezeCallbacks()) != 0 {
				t.Fatalf("OnFreeze fired for a busy container: %v", h.freezeCallbacks())
			}
		})
	}
}

// TestNoFreezeWhileAnAttachStreamIsOpen pins the invariant down on its own:
// the stream, not the elapsed time, is what decides.
func TestNoFreezeWhileAnAttachStreamIsOpen(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: 10 * time.Second})
	h.src.add("c1")
	h.src.edit("c1", func(c *fakeCtr) { c.attached = 1 })
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(time.Hour)
	h.w.Sample(ctx)
	if h.src.frozen("c1") {
		t.Fatal("froze a container with an attach stream open")
	}

	// The stream closes. The container is only frozen a full window later.
	h.src.edit("c1", func(c *fakeCtr) { c.attached = 0 })
	h.clk.add(9 * time.Second)
	h.w.Sample(ctx)
	if h.src.frozen("c1") {
		t.Fatal("froze before a full idle window had passed since the detach")
	}
	h.clk.add(2 * time.Second)
	h.w.Sample(ctx)
	h.settle("c1", true)
}

func TestWatcherThawsAFrozenContainerOnActivity(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	h.settle("c1", true)

	h.w.Touch("c1")
	h.w.Sample(ctx)
	h.settle("c1", false)

	if got := h.thawCallbacks(); len(got) != 1 || got[0] != "c1" {
		t.Fatalf("OnThaw calls = %v, want [c1]", got)
	}
	evs := h.eventsFor("c1")
	if len(evs) != 2 {
		t.Fatalf("events = %v, want a pause and an unpause", evs)
	}
	if evs[1].Action != ActionUnpause {
		t.Errorf("second event = %s, want %s", evs[1].Action, ActionUnpause)
	}
	if _, thaws := h.src.calls("c1"); thaws != 1 {
		t.Errorf("Source.Thaw calls = %d, want 1", thaws)
	}
}

// TestHysteresisAfterAThaw checks that a container which becomes busy again is
// not re-frozen the moment its next idle window elapses: the cooldown has to
// pass too, or a service touched once a minute would spend its life on the
// freeze/thaw treadmill.
func TestHysteresisAfterAThaw(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute, Cooldown: 5 * time.Minute})
	h.src.add("c1")
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	h.settle("c1", true)

	h.w.Touch("c1")
	h.w.Sample(ctx)
	h.settle("c1", false)

	// A full idle window passes, but not the cooldown.
	h.clk.add(90 * time.Second)
	h.w.Sample(ctx)
	if h.src.frozen("c1") {
		t.Fatal("re-froze inside the cooldown")
	}
	if freezes, _ := h.src.calls("c1"); freezes != 1 {
		t.Fatalf("Source.Freeze calls = %d, want 1", freezes)
	}

	// Once the cooldown is spent it may freeze again.
	h.clk.add(4 * time.Minute)
	h.w.Sample(ctx)
	h.settle("c1", true)
	if freezes, _ := h.src.calls("c1"); freezes != 2 {
		t.Fatalf("Source.Freeze calls = %d, want 2", freezes)
	}
}

func TestWatcherLeavesAUserPausedContainerAlone(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	h.src.edit("c1", func(c *fakeCtr) { c.frozen = true })
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(time.Hour)
	h.w.Sample(ctx)

	freezes, thaws := h.src.calls("c1")
	if freezes != 0 || thaws != 0 {
		t.Fatalf("touched a user-paused container: %d freezes, %d thaws", freezes, thaws)
	}
	if h.w.Frozen("c1") {
		t.Fatal("claimed ownership of a freeze it did not perform")
	}
	if err := h.w.ThawFor(ctx, "c1"); !errors.Is(err, ErrPausedExternally) {
		t.Fatalf("ThawFor on a user-paused container = %v, want ErrPausedExternally", err)
	}
	if _, thaws := h.src.calls("c1"); thaws != 0 {
		t.Fatal("ThawFor unpaused a container the user had paused")
	}
}

func TestWatcherNeverFreezesAContainerThatIsNotRunning(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	h.src.edit("c1", func(c *fakeCtr) { c.running = false })
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(time.Hour)
	h.w.Sample(ctx)

	if freezes, _ := h.src.calls("c1"); freezes != 0 {
		t.Fatalf("froze a container that was not running (%d calls)", freezes)
	}
}

// TestAFrozenContainerIsReportedFrozenNotExited guards the second failure mode:
// the watcher changes no lifecycle state, and says plainly which containers it
// has frozen so the API layer can report them as paused.
func TestAFrozenContainerIsReportedFrozenNotExited(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1").add("c2")
	ctx := context.Background()

	h.w.Sample(ctx)
	h.src.edit("c2", func(c *fakeCtr) { c.attached = 1 })
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	h.settle("c1", true)

	if !h.w.Frozen("c1") || h.w.Frozen("c2") {
		t.Fatalf("Frozen: c1=%v c2=%v, want true/false", h.w.Frozen("c1"), h.w.Frozen("c2"))
	}
	if got := h.w.FrozenIDs(); len(got) != 1 || got[0] != "c1" {
		t.Fatalf("FrozenIDs = %v, want [c1]", got)
	}

	st := h.w.Stats()
	if st.Tracked != 2 || st.Running != 2 || st.Frozen != 1 {
		t.Fatalf("stats tracked=%d running=%d frozen=%d, want 2/2/1", st.Tracked, st.Running, st.Frozen)
	}
	if st.Freezes != 1 || st.FreezeErrors != 0 {
		t.Fatalf("stats freezes=%d errors=%d, want 1/0", st.Freezes, st.FreezeErrors)
	}
	if len(st.Containers) != 2 || st.Containers[0].ID != "c1" {
		t.Fatalf("per-container stats = %+v", st.Containers)
	}
	c1 := st.Containers[0]
	if !c1.Running || !c1.Frozen || !c1.FrozenByHull {
		t.Errorf("c1 stats running=%v frozen=%v byHull=%v, want all true", c1.Running, c1.Frozen, c1.FrozenByHull)
	}
	if st.Containers[1].LastReason != ReasonAttach {
		t.Errorf("c2 last reason = %q, want %q", st.Containers[1].LastReason, ReasonAttach)
	}
}

func TestFreezeFailureIsRecordedAndRetriedNextWindow(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	h.src.freezeErr["c1"] = errFake("cgroup.freeze: permission denied")
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)

	if h.w.Frozen("c1") {
		t.Fatal("reported a container as frozen after the freeze failed")
	}
	st := h.w.Stats()
	if st.FreezeErrors != 1 || st.Freezes != 0 {
		t.Fatalf("stats freezes=%d errors=%d, want 0/1", st.Freezes, st.FreezeErrors)
	}
	if st.Containers[0].LastError == "" {
		t.Error("the failure was not recorded on the container")
	}

	// Not retried on the very next sample: the idle window restarts.
	h.clk.add(time.Second)
	h.w.Sample(ctx)
	if freezes, _ := h.src.calls("c1"); freezes != 1 {
		t.Fatalf("Source.Freeze calls = %d, want 1 (no hammering)", freezes)
	}
	// Retried once a full window has passed again.
	delete(h.src.freezeErr, "c1")
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	h.settle("c1", true)
}

func TestOnIdleFires(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(h *harness)
		advance time.Duration
		want    int
	}{
		{
			name:    "no containers at all",
			setup:   func(h *harness) {},
			advance: 2 * time.Minute,
			want:    1,
		},
		{
			name:    "one container, idle",
			setup:   func(h *harness) { h.src.add("c1") },
			advance: 2 * time.Minute,
			want:    1,
		},
		{
			name:    "several containers, all idle",
			setup:   func(h *harness) { h.src.add("c1").add("c2").add("c3") },
			advance: 2 * time.Minute,
			want:    1,
		},
		{
			name:    "not idle for long enough yet",
			setup:   func(h *harness) { h.src.add("c1") },
			advance: 30 * time.Second,
			want:    0,
		},
		{
			name: "a client holds an api connection",
			setup: func(h *harness) {
				h.src.add("c1")
				h.w.ClientConnected()
			},
			advance: 2 * time.Minute,
			want:    0,
		},
		{
			name: "a client counted by the daemon instead",
			setup: func(h *harness) {
				h.src.add("c1")
			},
			advance: 2 * time.Minute,
			want:    0,
		},
		{
			name: "one container still has a stream open",
			setup: func(h *harness) {
				h.src.add("c1").add("c2")
				h.src.edit("c2", func(c *fakeCtr) { c.attached = 1 })
			},
			advance: 2 * time.Minute,
			want:    0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{ExitAfter: time.Minute}
			if tc.name == "a client counted by the daemon instead" {
				cfg.ActiveClients = func() int { return 1 }
			}
			h := newHarness(t, cfg)
			tc.setup(h)
			ctx := context.Background()

			h.w.Sample(ctx)
			h.clk.add(tc.advance)
			h.w.Sample(ctx)

			if got := h.idleCalls(); got != tc.want {
				t.Fatalf("OnIdle calls = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestOnIdleFiresOncePerIdleSpell(t *testing.T) {
	h := newHarness(t, Config{ExitAfter: time.Minute})
	h.src.add("c1")
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	if got := h.idleCalls(); got != 1 {
		t.Fatalf("OnIdle calls = %d, want 1", got)
	}

	// Activity resumes, then stops again: it arms once more.
	h.w.Touch("c1")
	h.w.Sample(ctx)
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	if got := h.idleCalls(); got != 2 {
		t.Fatalf("OnIdle calls after a new idle spell = %d, want 2", got)
	}
}

func TestClientDisconnectRestartsTheExitClock(t *testing.T) {
	h := newHarness(t, Config{ExitAfter: time.Minute})
	h.src.add("c1")
	ctx := context.Background()
	h.w.ClientConnected()
	h.w.Sample(ctx)

	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	if got := h.idleCalls(); got != 0 {
		t.Fatalf("OnIdle fired with a client connected (%d calls)", got)
	}

	h.w.ClientDisconnected()
	h.clk.add(30 * time.Second)
	h.w.Sample(ctx)
	if got := h.idleCalls(); got != 0 {
		t.Fatalf("OnIdle fired %d times only 30s after the disconnect", got)
	}
	h.clk.add(31 * time.Second)
	h.w.Sample(ctx)
	if got := h.idleCalls(); got != 1 {
		t.Fatalf("OnIdle calls = %d, want 1", got)
	}
}

func TestSetFreezeAfterOverridesTheWindowPerContainer(t *testing.T) {
	cases := []struct {
		name      string
		override  time.Duration
		advance   time.Duration
		wantFroze bool
	}{
		{name: "default window", override: 0, advance: 90 * time.Second, wantFroze: true},
		{name: "longer window not yet reached", override: 10 * time.Minute, advance: 90 * time.Second},
		{name: "longer window reached", override: 10 * time.Minute, advance: 11 * time.Minute, wantFroze: true},
		{name: "shorter window", override: 5 * time.Second, advance: 6 * time.Second, wantFroze: true},
		{name: "never freeze this one", override: -1, advance: 10 * time.Hour},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Config{FreezeAfter: time.Minute})
			h.src.add("c1")
			h.w.SetFreezeAfter("c1", tc.override)
			ctx := context.Background()

			h.w.Sample(ctx)
			h.clk.add(tc.advance)
			h.w.Sample(ctx)

			if got := h.src.frozen("c1"); got != tc.wantFroze {
				t.Fatalf("frozen = %v, want %v", got, tc.wantFroze)
			}
		})
	}
}

func TestReclaimTakesOverAPreviousDaemonsFreeze(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	h.src.edit("c1", func(c *fakeCtr) { c.frozen = true })
	ctx := context.Background()

	h.w.Reclaim("c1")
	if !h.w.Frozen("c1") {
		t.Fatal("Reclaim did not take ownership of the freeze")
	}
	if err := h.w.ThawFor(ctx, "c1"); err != nil {
		t.Fatalf("ThawFor after Reclaim: %v", err)
	}
	if h.src.frozen("c1") {
		t.Fatal("still frozen after ThawFor")
	}
}

func TestThawAllUnfreezesEverythingTheWatcherFroze(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1").add("c2").add("c3")
	h.src.edit("c3", func(c *fakeCtr) { c.frozen = true }) // paused by a person
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	h.settle("c1", true)
	h.settle("c2", true)

	if err := h.w.ThawAll(ctx); err != nil {
		t.Fatalf("ThawAll: %v", err)
	}
	if h.src.frozen("c1") || h.src.frozen("c2") {
		t.Fatal("ThawAll left a container frozen")
	}
	if !h.src.frozen("c3") {
		t.Fatal("ThawAll unpaused a container the user had paused")
	}
}

func TestRunSamplesOnItsOwnClockUntilCancelled(t *testing.T) {
	h := newHarness(t, Config{
		FreezeAfter:    20 * time.Millisecond,
		SampleInterval: 2 * time.Millisecond,
		Now:            time.Now,
	})
	h.src.add("c1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- h.w.Run(ctx) }()

	h.settle("c1", true)

	// A second Run is refused rather than racing the first.
	if err := h.w.Run(ctx); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Run = %v, want ErrAlreadyRunning", err)
	}

	// A touch wakes it without waiting for the next tick.
	h.w.SetFreezeAfter("c1", -1)
	h.w.Touch("c1")
	h.settle("c1", false)

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Run returned %v, want nil after a clean cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

func TestRunWithoutASourceIsAnError(t *testing.T) {
	w := NewWatcher(Config{}, nil)
	if err := w.Run(context.Background()); !errors.Is(err, ErrNoSource) {
		t.Fatalf("Run without a source = %v, want ErrNoSource", err)
	}
	if err := w.ThawFor(context.Background(), "c1"); !errors.Is(err, ErrNoSource) {
		t.Fatalf("ThawFor without a source = %v, want ErrNoSource", err)
	}
}

func TestRunThawsOnStopWhenAsked(t *testing.T) {
	h := newHarness(t, Config{
		FreezeAfter:    10 * time.Millisecond,
		SampleInterval: time.Millisecond,
		ThawOnStop:     true,
		Now:            time.Now,
	})
	h.src.add("c1")

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- h.w.Run(ctx) }()
	h.settle("c1", true)
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if h.src.frozen("c1") {
		t.Fatal("ThawOnStop left the container frozen")
	}
}

func TestForgottenContainersAreDropped(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	ctx := context.Background()
	h.w.Sample(ctx)
	if st := h.w.Stats(); st.Tracked != 1 {
		t.Fatalf("tracked = %d, want 1", st.Tracked)
	}

	h.src.remove("c1")
	h.w.Sample(ctx)
	if st := h.w.Stats(); st.Tracked != 0 {
		t.Fatalf("tracked = %d after the container was removed, want 0", st.Tracked)
	}
}

func TestCPUCounterResetIsNotReadAsActivity(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	ctx := context.Background()
	h.src.edit("c1", func(c *fakeCtr) { c.cpu = 5_000_000 })
	h.w.Sample(ctx)

	// The cgroup is recreated under the same ID and the counter restarts.
	h.src.edit("c1", func(c *fakeCtr) { c.cpu = 0 })
	h.clk.add(30 * time.Second)
	h.w.Sample(ctx)
	h.clk.add(31 * time.Second)
	h.w.Sample(ctx)

	h.settle("c1", true)
}

func TestMissingCPUCounterIsReportedNotGuessed(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	h.src.edit("c1", func(c *fakeCtr) { c.cpuOK = false; c.cgroup = "" })
	ctx := context.Background()

	h.w.Sample(ctx)
	if st := h.w.Stats(); st.CPUSampling {
		t.Fatal("claimed a CPU signal on a host that has none")
	}
	// The other signals still hold the freeze off.
	for i := 0; i < 10; i++ {
		h.w.Touch("c1")
		h.clk.add(30 * time.Second)
		h.w.Sample(ctx)
	}
	if h.src.frozen("c1") {
		t.Fatal("froze a touched container on a host with no CPU counter")
	}
}
