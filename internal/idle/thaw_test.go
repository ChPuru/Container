package idle

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestThawForIsAFastPathWhenTheContainerIsAwake(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	ctx := context.Background()
	h.w.Sample(ctx)

	if err := h.w.ThawFor(ctx, "c1"); err != nil {
		t.Fatalf("ThawFor on a running container: %v", err)
	}
	if _, thaws := h.src.calls("c1"); thaws != 0 {
		t.Fatalf("Source.Thaw calls = %d, want 0 for a container that was never frozen", thaws)
	}
	// It counts as port activity all the same, so the container cannot be
	// frozen out from under the connection that just arrived.
	h.clk.add(59 * time.Second)
	h.w.Sample(ctx)
	if h.src.frozen("c1") {
		t.Fatal("froze a container inside the window ThawFor had just refreshed")
	}
}

// TestThawForWaitsForTheThawToTakeEffect is the invariant the port proxy rests
// on: when ThawFor returns, the container really is running again, so the
// freeze is invisible to the client whose connection triggered it.
func TestThawForWaitsForTheThawToTakeEffect(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	h.src.edit("c1", func(c *fakeCtr) { c.ports = 1; c.thawLag = 3 })
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	h.settle("c1", true)

	if err := h.w.ThawFor(ctx, "c1"); err != nil {
		t.Fatalf("ThawFor: %v", err)
	}
	if h.src.frozen("c1") {
		t.Fatal("ThawFor returned while the container was still frozen")
	}
	if h.w.Frozen("c1") {
		t.Fatal("the watcher still reports the container as frozen")
	}
	if _, thaws := h.src.calls("c1"); thaws != 1 {
		t.Fatalf("Source.Thaw calls = %d, want 1", thaws)
	}
	evs := h.eventsFor("c1")
	if len(evs) != 2 || evs[1].Action != ActionUnpause || evs[1].Reason != ReasonPort {
		t.Fatalf("events = %+v, want a pause then an unpause tagged %q", evs, ReasonPort)
	}
}

func TestThawForIsSingleFlight(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	h.src.edit("c1", func(c *fakeCtr) { c.thawLag = 4 })
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	h.settle("c1", true)

	const callers = 8
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = h.w.ThawFor(ctx, "c1")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if _, thaws := h.src.calls("c1"); thaws != 1 {
		t.Fatalf("Source.Thaw calls = %d, want 1 for %d concurrent connections", thaws, callers)
	}
	if h.src.frozen("c1") {
		t.Fatal("still frozen after every caller returned")
	}
}

func TestThawForTimesOutWhenTheThawNeverLands(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute, ThawTimeout: 30 * time.Millisecond})
	h.src.add("c1")
	h.src.edit("c1", func(c *fakeCtr) { c.thawLag = 1 << 30 })
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	h.settle("c1", true)

	err := h.w.ThawFor(ctx, "c1")
	if !errors.Is(err, ErrThawTimeout) {
		t.Fatalf("ThawFor = %v, want ErrThawTimeout", err)
	}
	if !h.w.Frozen("c1") {
		t.Fatal("the watcher forgot it still has the container frozen")
	}
	if st := h.w.Stats(); st.ThawErrors != 1 {
		t.Fatalf("stats thaw errors = %d, want 1", st.ThawErrors)
	}
}

func TestThawForPropagatesAThawFailure(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	h.src.thawErr["c1"] = errFake("cgroup.freeze: write: no such file")
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	h.settle("c1", true)

	err := h.w.ThawFor(ctx, "c1")
	if err == nil {
		t.Fatal("ThawFor swallowed a failed thaw")
	}
	if !h.w.Frozen("c1") {
		t.Fatal("the container stopped being reported as frozen even though the thaw failed")
	}
}

func TestThawForRespectsItsContext(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute, ThawTimeout: 50 * time.Millisecond})
	h.src.add("c1")
	h.src.edit("c1", func(c *fakeCtr) { c.thawLag = 1 << 30 })
	ctx := context.Background()

	h.w.Sample(ctx)
	h.clk.add(2 * time.Minute)
	h.w.Sample(ctx)
	h.settle("c1", true)

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancel()
	err := h.w.ThawFor(callCtx, "c1")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ThawFor = %v, want a context deadline", err)
	}
}

func TestThawForOnAnUnknownContainer(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	ctx := context.Background()
	h.w.Sample(ctx)

	if err := h.w.ThawFor(ctx, "nope"); !errors.Is(err, ErrUnknownContainer) {
		t.Fatalf("ThawFor on an unknown container = %v, want ErrUnknownContainer", err)
	}
	if err := h.w.ThawFor(ctx, ""); !errors.Is(err, ErrUnknownContainer) {
		t.Fatalf("ThawFor on an empty id = %v, want ErrUnknownContainer", err)
	}
}

func TestThawForAdoptsAContainerTheWatcherHasNotSampledYet(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	ctx := context.Background()

	// No Sample has run: the proxy may still be the first to hear about a
	// container, because it is wired up before the loop starts.
	if err := h.w.ThawFor(ctx, "c1"); err != nil {
		t.Fatalf("ThawFor before the first sample: %v", err)
	}
	st := h.w.Stats()
	if st.Tracked != 1 {
		t.Fatalf("tracked = %d, want 1", st.Tracked)
	}
	if st.Containers[0].LastReason != ReasonPort {
		t.Fatalf("last reason = %q, want %q", st.Containers[0].LastReason, ReasonPort)
	}
}

// TestThawForBeatsAFreezeThatIsAlreadyInFlight is the nastiest ordering in the
// package: the connection arrives in the microseconds between the decision to
// freeze and the cgroup write. The connection must still win.
func TestThawForBeatsAFreezeThatIsAlreadyInFlight(t *testing.T) {
	h := newHarness(t, Config{FreezeAfter: time.Minute})
	h.src.add("c1")
	ctx := context.Background()
	h.w.Sample(ctx)

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	h.src.freezeHook = func(string) {
		once.Do(func() { close(entered) })
		<-release
	}

	h.clk.add(2 * time.Minute)
	sampled := make(chan struct{})
	go func() { defer close(sampled); h.w.Sample(ctx) }()
	<-entered

	thawed := make(chan error, 1)
	go func() { thawed <- h.w.ThawFor(ctx, "c1") }()
	// Only to shape the interleaving: the assertions below hold either way.
	time.Sleep(20 * time.Millisecond)
	close(release)

	if err := <-thawed; err != nil {
		t.Fatalf("ThawFor: %v", err)
	}
	<-sampled
	if h.src.frozen("c1") {
		t.Fatal("the connection was forwarded to a frozen container")
	}
	if h.w.Frozen("c1") {
		t.Fatal("the watcher still reports the container as frozen")
	}
	freezes, thaws := h.src.calls("c1")
	if freezes != 1 || thaws != 1 {
		t.Fatalf("Source calls: %d freezes, %d thaws; want 1 and 1", freezes, thaws)
	}
}

// checkerSource is a Source that also implements FrozenChecker, which is the
// cheap path ThawFor prefers while it waits.
type checkerSource struct {
	*fakeSource
	mu    sync.Mutex
	count int
}

func (c *checkerSource) FrozenState(id string) (bool, bool) {
	c.mu.Lock()
	c.count++
	c.mu.Unlock()
	c.fakeSource.mu.Lock()
	defer c.fakeSource.mu.Unlock()
	ctr := c.fakeSource.ctrs[id]
	if ctr == nil {
		return false, false
	}
	return ctr.frozen, true
}

func (c *checkerSource) checks() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

func TestThawForUsesFrozenCheckerWhenTheSourceOffersOne(t *testing.T) {
	src := newSource()
	src.add("c1")
	src.edit("c1", func(c *fakeCtr) { c.frozen = true })
	cs := &checkerSource{fakeSource: src}

	w := NewWatcher(Config{
		FreezeAfter: time.Minute,
		CPUUsage:    src.cpuUsage,
		Logger:      quietLogger(),
	}, cs)
	w.Reclaim("c1")

	if err := w.ThawFor(context.Background(), "c1"); err != nil {
		t.Fatalf("ThawFor: %v", err)
	}
	if cs.checks() == 0 {
		t.Fatal("FrozenState was never consulted, so Containers was polled instead")
	}
	if src.frozen("c1") {
		t.Fatal("still frozen")
	}
}
