package idle

import (
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// quietLogger keeps the watcher's diagnostics out of the test output.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ---------- a fake clock ----------

// fakeClock is a manually advanced clock, so the state machine can be driven
// through hours of idle time in microseconds and without a sleep in sight.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ---------- a fake Source ----------

// fakeCtr is one container inside the fake engine.
type fakeCtr struct {
	running  bool
	frozen   bool
	cgroup   string
	attached int
	ports    int

	cpu   uint64
	cpuOK bool

	// thawLag is how many further polls of the source must happen after Thaw
	// returns before the container actually reports itself unfrozen. It is
	// how the tests reproduce a kernel that takes a moment to leave the
	// FREEZING state.
	thawLag int
	// thawPending counts the polls still owed.
	thawPending int
}

// fakeSource is an in-memory stand-in for the engine.
type fakeSource struct {
	mu    sync.Mutex
	order []string
	ctrs  map[string]*fakeCtr

	freezeErr   map[string]error
	thawErr     map[string]error
	freezeCalls map[string]int
	thawCalls   map[string]int
	polls       int

	// freezeHook runs inside Freeze, before the state changes, so a test can
	// interleave something with a freeze that is in flight.
	freezeHook func(id string)
}

func newSource() *fakeSource {
	return &fakeSource{
		ctrs:        make(map[string]*fakeCtr),
		freezeErr:   make(map[string]error),
		thawErr:     make(map[string]error),
		freezeCalls: make(map[string]int),
		thawCalls:   make(map[string]int),
	}
}

// add registers a running container with a cgroup and a readable CPU counter.
func (s *fakeSource) add(id string) *fakeSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ctrs[id]; !ok {
		s.order = append(s.order, id)
	}
	s.ctrs[id] = &fakeCtr{running: true, cgroup: "/sys/fs/cgroup/hull/" + id, cpuOK: true}
	return s
}

// edit mutates one container under the source's lock.
func (s *fakeSource) edit(id string, fn func(c *fakeCtr)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.ctrs[id]; c != nil {
		fn(c)
	}
}

// remove drops a container from the source entirely.
func (s *fakeSource) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ctrs, id)
	kept := s.order[:0]
	for _, o := range s.order {
		if o != id {
			kept = append(kept, o)
		}
	}
	s.order = kept
}

func (s *fakeSource) frozen(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.ctrs[id]
	return c != nil && c.frozen
}

func (s *fakeSource) calls(id string) (freezes, thaws int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.freezeCalls[id], s.thawCalls[id]
}

// Containers implements Source. Every call is a poll, which is what retires a
// pending thaw lag.
func (s *fakeSource) Containers() []Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.polls++
	out := make([]Snapshot, 0, len(s.ctrs))
	for _, id := range s.order {
		c := s.ctrs[id]
		if c == nil {
			continue
		}
		if c.thawPending > 0 {
			c.thawPending--
			if c.thawPending == 0 {
				c.frozen = false
			}
		}
		out = append(out, Snapshot{
			ID:             id,
			Running:        c.running,
			Frozen:         c.frozen,
			CGroupPath:     c.cgroup,
			Attached:       c.attached,
			PublishedPorts: c.ports,
		})
	}
	return out
}

// Freeze implements Source.
func (s *fakeSource) Freeze(id string) error {
	if s.freezeHook != nil {
		s.freezeHook(id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.freezeCalls[id]++
	if err := s.freezeErr[id]; err != nil {
		return err
	}
	c := s.ctrs[id]
	if c == nil {
		return errNoSuchFakeContainer
	}
	c.frozen = true
	return nil
}

// Thaw implements Source.
func (s *fakeSource) Thaw(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.thawCalls[id]++
	if err := s.thawErr[id]; err != nil {
		return err
	}
	c := s.ctrs[id]
	if c == nil {
		return errNoSuchFakeContainer
	}
	if c.thawLag > 0 {
		c.thawPending = c.thawLag
		return nil
	}
	c.frozen = false
	return nil
}

// cpuUsage is the Config.CPUUsage stand-in: it resolves a cgroup path back to
// the fake container that owns it.
func (s *fakeSource) cpuUsage(path string) (uint64, bool) {
	if path == "" {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.ctrs {
		if c.cgroup == path {
			if !c.cpuOK {
				return 0, false
			}
			return c.cpu, true
		}
	}
	return 0, false
}

// errNoSuchFakeContainer is what the fake engine returns for an unknown ID.
var errNoSuchFakeContainer = errFake("no such container")

// errFake is a tiny error type so the fakes need no extra imports.
type errFake string

func (e errFake) Error() string { return string(e) }

// ---------- the harness ----------

// harness wires a watcher to a fake source and a fake clock and records every
// callback it fires.
type harness struct {
	t   *testing.T
	w   *Watcher
	src *fakeSource
	clk *fakeClock

	mu     sync.Mutex
	events []Event
	frozen []string
	thawed []string
	idle   int
}

// newHarness builds a watcher over cfg, filling in the clock, the CPU reader
// and the recording callbacks. A caller that sets one of those itself keeps it.
func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	h := &harness{t: t, src: newSource(), clk: newClock()}
	if cfg.Now == nil {
		cfg.Now = h.clk.now
	}
	if cfg.CPUUsage == nil {
		cfg.CPUUsage = h.src.cpuUsage
	}
	if cfg.Logger == nil {
		cfg.Logger = quietLogger()
	}
	cfg.OnFreeze = func(id string) {
		h.mu.Lock()
		h.frozen = append(h.frozen, id)
		h.mu.Unlock()
	}
	cfg.OnThaw = func(id string) {
		h.mu.Lock()
		h.thawed = append(h.thawed, id)
		h.mu.Unlock()
	}
	cfg.OnIdle = func() {
		h.mu.Lock()
		h.idle++
		h.mu.Unlock()
	}
	cfg.OnEvent = func(ev Event) {
		h.mu.Lock()
		h.events = append(h.events, ev)
		h.mu.Unlock()
	}
	h.w = NewWatcher(cfg, h.src)
	return h
}

// eventsFor returns the recorded events for one container.
func (h *harness) eventsFor(id string) []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []Event
	for _, ev := range h.events {
		if ev.ID == id {
			out = append(out, ev)
		}
	}
	return out
}

func (h *harness) freezeCallbacks() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.frozen...)
}

func (h *harness) thawCallbacks() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.thawed...)
}

func (h *harness) idleCalls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.idle
}

// settle waits until the container's freeze state in the fake source matches
// want, or fails. Thaws run in their own goroutine, so a Sample that decides
// to thaw does not finish the thaw itself.
func (h *harness) settle(id string, wantFrozen bool) {
	h.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.src.frozen(id) == wantFrozen && h.w.Frozen(id) == wantFrozen {
			return
		}
		time.Sleep(time.Millisecond)
	}
	h.t.Fatalf("container %s: frozen in source = %v, watcher = %v, want %v",
		id, h.src.frozen(id), h.w.Frozen(id), wantFrozen)
}
