package idle

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// record is the watcher's bookkeeping for one container. Everything in it is
// guarded by Watcher.mu.
type record struct {
	id string

	// The last snapshot, as the source reported it.
	running    bool
	attached   int
	published  int
	cgroupPath string

	// firstSeen and lastSeen bound the record's life.
	firstSeen time.Time
	lastSeen  time.Time

	// lastActive is the activity clock every freeze decision is measured
	// against, and lastReason names the signal that last set it.
	lastActive time.Time
	lastReason string

	// dirty latches activity reported between two samples — a Touch, a byte
	// through the port proxy, a ThawFor — and dirtyReason keeps the strongest
	// signal among them. A latch rather than a timestamp comparison, because
	// two events inside one clock tick must not be able to hide each other.
	dirty       bool
	dirtyReason string

	// cpuUsec is the previous cpu.stat usage_usec reading; haveCPU says
	// whether it is a usable baseline for a delta.
	cpuUsec uint64
	haveCPU bool

	// frozenByHull records a freeze this watcher performed, which is the only
	// kind it will undo. externallyFrozen records a freeze somebody else
	// performed — a user's `hull pause` — which it never touches.
	frozenByHull     bool
	externallyFrozen bool
	frozenAt         time.Time
	lastThaw         time.Time

	// freezeDone is non-nil while a freeze is in flight. A connection that
	// arrives in that window waits on it and then thaws, so the freeze stays
	// invisible to the client.
	freezeDone chan struct{}

	// holds counts ThawFor calls in flight. A container with a hold is never
	// frozen.
	holds int

	freezes    int
	thaws      int
	freezeErrs int
	thawErrs   int
	lastErr    string
}

// thawOp is one in-flight thaw, shared by every caller that asked for it.
type thawOp struct {
	done chan struct{}
	err  error
}

// decision is one freeze or thaw the sample pass resolved on, carried out of
// the lock so no callback and no cgroup write happens while it is held.
type decision struct {
	id      string
	reason  string
	idleFor time.Duration
	at      time.Time
}

// Watcher freezes idle containers and tells the daemon when the whole engine
// has gone quiet. It is safe for concurrent use.
//
// The watcher holds no engine state: it reads Snapshots from a Source, keeps
// an activity clock per container, and calls Source.Freeze and Source.Thaw.
// It never changes a container's lifecycle state, so a frozen container is
// still a running container as far as the rest of hull is concerned — Frozen
// and FrozenIDs are what the API layer uses to report it as paused.
type Watcher struct {
	cfg Config
	src Source

	running atomic.Bool
	wake    chan struct{}

	mu         sync.Mutex
	recs       map[string]*record
	overrides  map[string]time.Duration
	inflight   map[string]*thawOp
	clients    int
	started    time.Time
	lastSample time.Time
	lastBusy   time.Time
	idleFired  bool
	cpuSeen    bool
	cpuWarned  bool

	samples    uint64
	freezes    uint64
	thaws      uint64
	touches    uint64
	freezeErrs uint64
	thawErrs   uint64
}

// NewWatcher builds a watcher over src. Every zero field in cfg takes its
// documented default, so the only decisions a caller has to make are
// FreezeAfter, ExitAfter and what to do in the callbacks.
//
// The watcher does nothing until Run is called, except record activity: Touch
// and ThawFor are safe from the moment it exists, which lets the daemon wire
// the API layer and the port proxies up before it starts the loop.
func NewWatcher(cfg Config, src Source) *Watcher {
	cfg = cfg.withDefaults()
	now := cfg.Now()
	return &Watcher{
		cfg:       cfg,
		src:       src,
		wake:      make(chan struct{}, 1),
		recs:      make(map[string]*record),
		overrides: make(map[string]time.Duration),
		inflight:  make(map[string]*thawOp),
		started:   now,
		lastBusy:  now,
	}
}

// now reads the watcher's clock.
func (w *Watcher) now() time.Time { return w.cfg.Now() }

// Run evaluates every container once immediately and then on every
// SampleInterval tick, until ctx is cancelled. A clean cancellation is not an
// error, so Run returns nil; it returns ErrNoSource when there is nothing to
// watch and ErrAlreadyRunning if a second Run is started on the same watcher.
//
// Containers frozen by the watcher stay frozen when Run returns, because the
// point of scale-to-zero is that the daemon exits and the freeze outlives it.
// Set Config.ThawOnStop to thaw them on the way out instead.
func (w *Watcher) Run(ctx context.Context) error {
	if w.src == nil {
		return fmt.Errorf("idle: run: %w", ErrNoSource)
	}
	if !w.running.CompareAndSwap(false, true) {
		return fmt.Errorf("idle: run: %w", ErrAlreadyRunning)
	}
	defer w.running.Store(false)

	w.mu.Lock()
	w.lastBusy = w.now()
	w.idleFired = false
	w.mu.Unlock()

	ticker := time.NewTicker(w.cfg.SampleInterval)
	defer ticker.Stop()

	w.Sample(ctx)
	for {
		select {
		case <-ctx.Done():
			if w.cfg.ThawOnStop {
				// Deliberately detached from ctx: the thaw has to outlive the
				// cancellation that triggered it.
				stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), w.cfg.ThawTimeout)
				if err := w.ThawAll(stop); err != nil {
					w.cfg.Logger.Warn("hull: could not thaw every frozen container on shutdown", "err", err)
				}
				cancel()
			}
			return nil
		case <-ticker.C:
			w.Sample(ctx)
		case <-w.wake:
			w.Sample(ctx)
		}
	}
}

// kick asks the run loop for an out-of-band sample. It never blocks: a wake
// already pending is a wake.
func (w *Watcher) kick() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Sample runs exactly one evaluation pass: it reads the source, updates every
// container's activity clock, freezes what has gone quiet, thaws what has not,
// and fires OnIdle when the engine as a whole has been idle for ExitAfter.
//
// Run calls it on every tick. It is exported so a caller with its own clock —
// the tests, or a daemon that wants a pass right now — can drive the watcher
// directly. Callbacks are invoked after the watcher's lock is released, so
// they may call back into Touch, Stats or ThawFor.
func (w *Watcher) Sample(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	if w.src == nil || ctx.Err() != nil {
		return
	}

	snaps := w.src.Containers()
	external := w.externalClients()
	now := w.now()

	// Read every cgroup counter before taking the lock: the default reader
	// touches the filesystem, and Touch is on the port proxy's hot path.
	cpu := make(map[string]uint64, len(snaps))
	for _, s := range snaps {
		if !s.Running {
			continue
		}
		if usec, ok := w.cfg.CPUUsage(s.CGroupPath); ok {
			cpu[s.ID] = usec
		}
	}

	var (
		freezes  []decision
		thaws    []decision
		fireIdle bool
		warnCPU  bool
	)

	w.mu.Lock()
	w.samples++
	w.lastSample = now

	busy := w.clients+external > 0
	allIdle := true
	cpuMissing, anyRunning := false, false
	seen := make(map[string]struct{}, len(snaps))

	for _, s := range snaps {
		if s.ID == "" {
			continue
		}
		seen[s.ID] = struct{}{}

		r, fresh := w.recordLocked(s.ID, now)
		wasRunning := r.running
		r.lastSeen = now
		r.running = s.Running
		r.attached = s.Attached
		r.published = s.PublishedPorts
		r.cgroupPath = s.CGroupPath

		if !s.Running {
			// A container that is not running holds nothing open, cannot be
			// frozen by us and never keeps the daemon awake. Drop the freeze
			// bookkeeping so a restart starts from a clean slate.
			r.frozenByHull = false
			r.externallyFrozen = s.Frozen
			r.haveCPU = false
			continue
		}
		anyRunning = true

		if fresh || !wasRunning {
			// Appearing, or starting, is activity in its own right: a
			// container must not inherit an idle window it was never awake
			// for.
			r.lastActive = now
			r.lastReason = ReasonStart
			r.haveCPU = false
			busy = true
		}

		// Reconcile with whoever else may have moved the freeze state.
		if s.Frozen {
			if !r.frozenByHull {
				r.externallyFrozen = true
			}
		} else {
			r.externallyFrozen = false
			if r.frozenByHull {
				// Something outside the watcher thawed it — `hull unpause`,
				// or a restart of the container. Give up ownership and start
				// the idle window again.
				r.frozenByHull = false
				r.lastThaw = now
				r.lastActive = now
				r.lastReason = ReasonTouch
			}
		}

		// The CPU signal. A frozen cgroup's counter cannot move, so this only
		// ever keeps a live container awake.
		cpuReason := ""
		if usec, ok := cpu[s.ID]; ok {
			w.cpuSeen = true
			switch {
			case !r.haveCPU:
				// No baseline yet.
			case usec < r.cpuUsec:
				// The cgroup was recreated under the same ID; re-baseline
				// rather than read the wrap as a burst of work.
			case usec-r.cpuUsec > w.cfg.CPUFloorUsec:
				cpuReason = ReasonCPU
			}
			r.cpuUsec, r.haveCPU = usec, true
		} else {
			r.haveCPU = false
			cpuMissing = true
		}

		// Everything else: whatever was latched since the previous pass.
		touched := ""
		if r.dirty {
			touched = r.dirtyReason
			if touched == "" {
				touched = ReasonTouch
			}
			r.dirty, r.dirtyReason = false, ""
		}
		held := ""
		if r.holds > 0 {
			held = ReasonPort
		}
		attach := ""
		if s.Attached > 0 {
			attach = ReasonAttach
		}

		reason := topReason(attach, held, cpuReason, touched)
		if reason != "" {
			r.lastActive = now
			r.lastReason = reason
			busy = true
		}

		idleFor := now.Sub(r.lastActive)
		if idleFor < 0 {
			idleFor = 0
		}
		if w.cfg.ExitAfter > 0 && idleFor < w.cfg.ExitAfter {
			allIdle = false
		}

		freezeAfter := w.freezeAfterLocked(s.ID)
		switch {
		case r.frozenByHull:
			// Anything at all that counted as activity since we froze it is a
			// wake-up: an attach, a hold taken by ThawFor, a Touch.
			if reason != "" || r.holds > 0 || s.Attached > 0 || !r.lastActive.Before(r.frozenAt) {
				thaws = append(thaws, decision{
					id:     s.ID,
					reason: topReason(attach, held, r.lastReason, ReasonTouch),
					at:     now,
				})
			}
		case r.externallyFrozen || r.freezeDone != nil:
			// Paused by a person, or already being frozen. Not ours to act on.
		case freezeAfter > 0 && s.Attached == 0 && r.holds == 0 &&
			idleFor >= freezeAfter && w.cooledDownLocked(r, now):
			freezes = append(freezes, decision{
				id:      s.ID,
				reason:  ReasonIdle,
				idleFor: idleFor,
				at:      now,
			})
		}
	}

	// Forget containers the source no longer reports, unless a ThawFor is
	// still holding one or a freeze is in flight against it.
	for id, r := range w.recs {
		if _, ok := seen[id]; ok || r.holds > 0 || r.freezeDone != nil {
			continue
		}
		delete(w.recs, id)
		delete(w.overrides, id)
	}

	if busy {
		w.lastBusy = now
		w.idleFired = false
	}
	if w.cfg.ExitAfter > 0 && !busy && allIdle && !w.idleFired &&
		w.clients+external == 0 && now.Sub(w.lastBusy) >= w.cfg.ExitAfter {
		w.idleFired = true
		fireIdle = true
	}
	if cpuMissing && anyRunning && !w.cpuSeen && !w.cpuWarned {
		w.cpuWarned = true
		warnCPU = true
	}
	w.mu.Unlock()

	if warnCPU {
		w.cfg.Logger.Warn("hull: no cgroup cpu.stat on this host, so idle detection has no CPU signal",
			"remedy", "run 'wsl --update', or set kernelCommandLine = cgroup_no_v1=all in .wslconfig",
			"fallback", "attach streams, published-port traffic and API activity")
	}
	// Waking first: a container that should be awake must never wait behind a
	// container that is going to sleep.
	for _, d := range thaws {
		w.startThaw(d.id, d.reason)
	}
	for _, d := range freezes {
		w.freeze(d)
	}
	if fireIdle && w.cfg.OnIdle != nil {
		w.cfg.OnIdle()
	}
}

// recordLocked returns the record for id, creating it if this is the first
// sighting. It reports whether the record is new.
func (w *Watcher) recordLocked(id string, now time.Time) (*record, bool) {
	if r := w.recs[id]; r != nil {
		return r, false
	}
	r := &record{id: id, firstSeen: now, lastSeen: now, lastActive: now, lastReason: ReasonStart}
	w.recs[id] = r
	return r, true
}

// freezeAfterLocked is the idle window for one container: its own override
// from SetFreezeAfter, or the global FreezeAfter. Zero means never freeze.
func (w *Watcher) freezeAfterLocked(id string) time.Duration {
	if d, ok := w.overrides[id]; ok {
		if d < 0 {
			return 0
		}
		return d
	}
	return w.cfg.FreezeAfter
}

// cooledDownLocked is the hysteresis check: a container that has just been
// woken gets a full Cooldown before it can be frozen again, so a burst of
// traffic every few minutes does not turn into a freeze/thaw treadmill.
func (w *Watcher) cooledDownLocked(r *record, now time.Time) bool {
	if w.cfg.Cooldown <= 0 || r.lastThaw.IsZero() {
		return true
	}
	return now.Sub(r.lastThaw) >= w.cfg.Cooldown
}

// externalClients reads Config.ActiveClients, outside the lock: it belongs to
// the daemon and may take the daemon's own lock.
func (w *Watcher) externalClients() int {
	if w.cfg.ActiveClients == nil {
		return 0
	}
	if n := w.cfg.ActiveClients(); n > 0 {
		return n
	}
	return 0
}

// freeze applies one freeze decision.
//
// The decision is re-checked under the lock immediately before the cgroup
// write, against the activity clock as it was when the decision was taken, so
// a connection, an attach or a Touch that arrived in between cancels the
// freeze instead of racing it.
func (w *Watcher) freeze(d decision) {
	w.mu.Lock()
	r := w.recs[d.id]
	if r == nil || !r.running || r.frozenByHull || r.externallyFrozen ||
		r.holds > 0 || r.attached > 0 || r.freezeDone != nil || !r.lastActive.Before(d.at) {
		w.mu.Unlock()
		return
	}
	done := make(chan struct{})
	r.freezeDone = done
	w.mu.Unlock()

	err := w.src.Freeze(d.id)

	now := w.now()
	w.mu.Lock()
	r.freezeDone = nil
	if err != nil {
		r.freezeErrs++
		r.lastErr = err.Error()
		w.freezeErrs++
		// Restart the idle window so a cgroup that cannot be frozen is
		// retried once per window rather than on every sample.
		r.lastActive = now
		r.lastReason = ReasonTouch
		w.mu.Unlock()
		close(done)
		w.cfg.Logger.Warn("hull: could not freeze an idle container", "container", short(d.id), "err", err)
		return
	}
	r.frozenByHull = true
	r.frozenAt = now
	r.freezes++
	w.freezes++
	ports := r.published
	// A ThawFor that arrived while the write was in flight is waiting on
	// freezeDone; it thaws as soon as it sees the freeze land.
	w.mu.Unlock()
	close(done)

	w.emit(Event{
		Action:         ActionPause,
		ID:             d.id,
		Reason:         ReasonIdle,
		IdleFor:        d.idleFor,
		PublishedPorts: ports,
		Time:           now,
	})
	if w.cfg.OnFreeze != nil {
		w.cfg.OnFreeze(d.id)
	}
}

// startThaw begins a thaw, or joins the one already in flight, and returns the
// operation so a caller can wait for it. It never blocks.
func (w *Watcher) startThaw(id, reason string) *thawOp {
	w.mu.Lock()
	op := w.inflight[id]
	if op == nil {
		op = &thawOp{done: make(chan struct{})}
		w.inflight[id] = op
		go w.performThaw(id, reason, op)
	}
	w.mu.Unlock()
	return op
}

// performThaw does the cgroup write and then waits for the source to agree
// that the container really is running again.
func (w *Watcher) performThaw(id, reason string, op *thawOp) {
	defer func() {
		w.mu.Lock()
		if w.inflight[id] == op {
			delete(w.inflight, id)
		}
		w.mu.Unlock()
		close(op.done)
	}()

	if reason == "" {
		reason = ReasonTouch
	}
	if err := w.src.Thaw(id); err != nil {
		w.noteThawError(id, err)
		op.err = fmt.Errorf("idle: thaw %s: %w", short(id), err)
		return
	}
	if err := w.waitThawed(id); err != nil {
		w.noteThawError(id, err)
		op.err = err
		return
	}

	now := w.now()
	w.mu.Lock()
	ports := 0
	if r := w.recs[id]; r != nil {
		r.frozenByHull = false
		r.externallyFrozen = false
		r.lastThaw = now
		r.lastActive = now
		r.lastReason = reason
		r.thaws++
		ports = r.published
	}
	w.thaws++
	w.lastBusy = now
	w.idleFired = false
	w.mu.Unlock()

	w.emit(Event{
		Action:         ActionUnpause,
		ID:             id,
		Reason:         reason,
		PublishedPorts: ports,
		Time:           now,
	})
	if w.cfg.OnThaw != nil {
		w.cfg.OnThaw(id)
	}
}

// noteThawError records a failed thaw. The container keeps its frozenByHull
// flag, so the next sample tries again: a container hull froze and cannot
// thaw is the one state this package must never settle into quietly.
func (w *Watcher) noteThawError(id string, err error) {
	w.mu.Lock()
	if r := w.recs[id]; r != nil {
		r.thawErrs++
		r.lastErr = err.Error()
	}
	w.thawErrs++
	w.mu.Unlock()
	w.cfg.Logger.Warn("hull: could not thaw a frozen container", "container", short(id), "err", err)
}

// waitThawed polls the source until the container is no longer frozen, or
// ThawTimeout expires. The deadline is real time, not Config.Now, because it
// bounds a real wait on the kernel.
func (w *Watcher) waitThawed(id string) error {
	deadline := time.Now().Add(w.cfg.ThawTimeout)
	delay := thawPollMin
	for {
		frozen, found := w.frozenInSource(id)
		if !found {
			return fmt.Errorf("idle: thaw %s: %w", short(id), ErrUnknownContainer)
		}
		if !frozen {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("idle: thaw %s: %w", short(id), ErrThawTimeout)
		}
		time.Sleep(delay)
		if delay < thawPollMax {
			delay *= 2
		}
	}
}

// frozenInSource asks the source for one container's freeze state, using the
// cheap FrozenChecker path when the source offers it.
func (w *Watcher) frozenInSource(id string) (frozen, found bool) {
	if fc, ok := w.src.(FrozenChecker); ok {
		return fc.FrozenState(id)
	}
	for _, s := range w.src.Containers() {
		if s.ID == id {
			return s.Frozen, true
		}
	}
	return false, false
}

// ThawFor makes sure a container is awake before its caller forwards anything
// to it, and is what keeps the freeze invisible: the port proxy calls it on
// every incoming connection, before the first byte is relayed.
//
// It records port activity either way, so the container cannot be frozen
// underneath the connection that just arrived. When the container is not
// frozen — the overwhelmingly common case — it returns immediately without
// touching the source. When it is frozen, it thaws it and waits, bounded by
// Config.ThawTimeout and by ctx, until the source agrees the container is
// running again; concurrent callers share one thaw.
//
// A freeze that was already in flight when the connection arrived is waited
// out first, then undone. A container a person paused with `hull pause` is
// never unpaused: ThawFor returns an error wrapping ErrPausedExternally, and
// the caller should fail the connection rather than resurrect a container its
// owner deliberately stopped.
func (w *Watcher) ThawFor(ctx context.Context, id string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if w.src == nil {
		return fmt.Errorf("idle: thaw: %w", ErrNoSource)
	}
	if id == "" {
		return fmt.Errorf("idle: thaw: %w", ErrUnknownContainer)
	}

	r, ok := w.hold(id)
	if !ok {
		return fmt.Errorf("idle: thaw %s: %w", short(id), ErrUnknownContainer)
	}
	defer w.release(id)

	// Wait out a freeze that was already being applied when this connection
	// arrived, so the thaw below cannot be overtaken by it.
	w.mu.Lock()
	freezing := r.freezeDone
	w.mu.Unlock()
	if freezing != nil {
		select {
		case <-freezing:
		case <-ctx.Done():
			return fmt.Errorf("idle: thaw %s: %w", short(id), ctx.Err())
		}
	}

	w.mu.Lock()
	frozen := r.frozenByHull
	external := r.externallyFrozen
	w.mu.Unlock()
	if external && !frozen {
		return fmt.Errorf("idle: thaw %s: %w", short(id), ErrPausedExternally)
	}
	if !frozen {
		return nil
	}

	op := w.startThaw(id, ReasonPort)
	select {
	case <-op.done:
		return op.err
	case <-ctx.Done():
		return fmt.Errorf("idle: thaw %s: %w", short(id), ctx.Err())
	}
}

// hold marks a container busy and takes a reference that forbids freezing it
// until the matching release. It adopts the container from the source when the
// watcher has not sampled it yet, which is what makes ThawFor safe to call
// before Run has started.
func (w *Watcher) hold(id string) (*record, bool) {
	now := w.now()

	w.mu.Lock()
	r := w.recs[id]
	w.mu.Unlock()
	if r == nil {
		w.adopt(id)
		w.mu.Lock()
		r = w.recs[id]
		w.mu.Unlock()
		if r == nil {
			return nil, false
		}
	}

	w.mu.Lock()
	r.holds++
	r.lastActive = now
	r.lastReason = ReasonPort
	r.dirty = true
	r.dirtyReason = topReason(r.dirtyReason, ReasonPort)
	w.lastBusy = now
	w.idleFired = false
	w.mu.Unlock()
	return r, true
}

// release drops a hold taken by hold and restamps the activity clock, so the
// container gets a full idle window after the connection rather than being
// frozen the instant it closes.
func (w *Watcher) release(id string) {
	now := w.now()
	w.mu.Lock()
	if r := w.recs[id]; r != nil {
		if r.holds > 0 {
			r.holds--
		}
		r.lastActive = now
		r.lastReason = ReasonPort
		r.dirty = true
		r.dirtyReason = topReason(r.dirtyReason, ReasonPort)
	}
	w.mu.Unlock()
}

// adopt learns about one container the watcher has not sampled yet. A
// container that is already frozen when it is first seen is recorded as
// paused by someone else: the watcher only ever undoes its own freezes. Use
// Reclaim to take ownership of a freeze made by a previous daemon.
func (w *Watcher) adopt(id string) {
	snaps := w.src.Containers()
	now := w.now()

	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range snaps {
		if s.ID != id {
			continue
		}
		r, _ := w.recordLocked(s.ID, now)
		r.lastSeen = now
		r.running = s.Running
		r.attached = s.Attached
		r.published = s.PublishedPorts
		r.cgroupPath = s.CGroupPath
		if s.Frozen && !r.frozenByHull {
			r.externallyFrozen = true
		}
		return
	}
}

// Reclaim takes ownership of containers that are frozen because a previous
// daemon froze them, so this watcher will thaw them again on the next
// connection. The daemon calls it during recovery for the containers its
// persisted state records as idle-frozen; without it a freeze that outlived
// the daemon is indistinguishable from a user's `hull pause`, and the watcher
// would refuse to undo it.
func (w *Watcher) Reclaim(ids ...string) {
	now := w.now()
	for _, id := range ids {
		if id == "" {
			continue
		}
		w.mu.Lock()
		r, _ := w.recordLocked(id, now)
		r.frozenByHull = true
		r.externallyFrozen = false
		if r.frozenAt.IsZero() {
			r.frozenAt = now
		}
		r.lastActive = r.frozenAt
		r.lastReason = ReasonIdle
		w.mu.Unlock()
	}
}

// Touch records activity for a container. The API layer calls it on any
// request that concerns one — an exec, a log read, a stats scrape, a copy —
// and the port proxy calls it as bytes move. It is cheap enough for the hot
// path: one lock and a timestamp.
func (w *Watcher) Touch(id string) { w.TouchWith(id, ReasonTouch) }

// TouchWith records activity and names the signal, so events and Stats can say
// what kept a container awake. The port proxy uses ReasonPort; an unknown
// reason is treated as a bare Touch.
func (w *Watcher) TouchWith(id, reason string) {
	if id == "" {
		return
	}
	if reasonRank(reason) == 0 {
		reason = ReasonTouch
	}
	now := w.now()

	w.mu.Lock()
	w.touches++
	w.lastBusy = now
	w.idleFired = false
	r, _ := w.recordLocked(id, now)
	r.lastActive = now
	r.lastReason = reason
	r.dirty = true
	r.dirtyReason = topReason(r.dirtyReason, reason)
	wake := r.frozenByHull
	w.mu.Unlock()

	// A frozen container needs waking now, not at the next tick.
	if wake {
		w.kick()
	}
}

// ClientConnected records that an API client has connected. While any client
// is connected the engine is never idle, so OnIdle cannot fire underneath a
// `docker events` or `hull ui` session.
func (w *Watcher) ClientConnected() {
	now := w.now()
	w.mu.Lock()
	w.clients++
	w.lastBusy = now
	w.idleFired = false
	w.mu.Unlock()
}

// ClientDisconnected records that an API client has gone away. The idle clock
// starts from the moment the last one leaves.
func (w *Watcher) ClientDisconnected() {
	now := w.now()
	w.mu.Lock()
	if w.clients > 0 {
		w.clients--
	}
	w.lastBusy = now
	w.idleFired = false
	w.mu.Unlock()
}

// SetFreezeAfter overrides the idle window for one container, which is what
// `hull run --idle-freeze=5m` sets. A negative duration means never freeze
// this container; zero removes the override and restores Config.FreezeAfter.
// It may be called before the container has ever been sampled.
func (w *Watcher) SetFreezeAfter(id string, d time.Duration) {
	if id == "" {
		return
	}
	w.mu.Lock()
	if d == 0 {
		delete(w.overrides, id)
	} else {
		w.overrides[id] = d
	}
	w.mu.Unlock()
}

// Frozen reports whether the watcher has this container frozen. The API layer
// uses it to report the container as paused: a frozen container is still
// running, and must never be shown as exited.
func (w *Watcher) Frozen(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	r := w.recs[id]
	return r != nil && r.frozenByHull
}

// FrozenIDs lists every container the watcher currently has frozen, sorted.
func (w *Watcher) FrozenIDs() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	ids := make([]string, 0, len(w.recs))
	for id, r := range w.recs {
		if r.frozenByHull {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// ThawAll thaws every container the watcher froze and waits for each thaw to
// take effect, returning the errors joined. It is what the daemon calls before
// switching scale-to-zero off, and what Run does on the way out when
// Config.ThawOnStop is set. Containers paused by a person are left alone.
func (w *Watcher) ThawAll(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ids := w.FrozenIDs()
	ops := make([]*thawOp, 0, len(ids))
	for _, id := range ids {
		ops = append(ops, w.startThaw(id, ReasonTouch))
	}
	var errs []error
	for i, op := range ops {
		select {
		case <-op.done:
			if op.err != nil {
				errs = append(errs, op.err)
			}
		case <-ctx.Done():
			errs = append(errs, fmt.Errorf("idle: thaw %s: %w", short(ids[i]), ctx.Err()))
		}
	}
	return errors.Join(errs...)
}

// emit hands one event to Config.OnEvent, if there is one.
func (w *Watcher) emit(ev Event) {
	if w.cfg.OnEvent != nil {
		w.cfg.OnEvent(ev)
	}
}

// Stats reports what the watcher is doing, as a copy that the caller owns.
func (w *Watcher) Stats() Stats {
	external := w.externalClients()
	now := w.now()

	w.mu.Lock()
	defer w.mu.Unlock()

	st := Stats{
		Since:        w.started,
		LastSample:   w.lastSample,
		Samples:      w.samples,
		Tracked:      len(w.recs),
		Freezes:      w.freezes,
		Thaws:        w.thaws,
		Touches:      w.touches,
		FreezeErrors: w.freezeErrs,
		ThawErrors:   w.thawErrs,
		Clients:      w.clients + external,
		CPUSampling:  w.cpuSeen,
		LastActivity: w.lastBusy,
		IdleFor:      now.Sub(w.lastBusy),
		IdleFired:    w.idleFired,
		Containers:   make([]ContainerStats, 0, len(w.recs)),
	}
	if st.IdleFor < 0 {
		st.IdleFor = 0
	}
	for _, r := range w.recs {
		if r.running {
			st.Running++
		}
		if r.frozenByHull || r.externallyFrozen {
			st.Frozen++
		}
		idleFor := now.Sub(r.lastActive)
		if idleFor < 0 {
			idleFor = 0
		}
		st.Containers = append(st.Containers, ContainerStats{
			ID:             r.id,
			Running:        r.running,
			Frozen:         r.frozenByHull || r.externallyFrozen,
			FrozenByHull:   r.frozenByHull,
			FrozenAt:       r.frozenAt,
			LastActive:     r.lastActive,
			IdleFor:        idleFor,
			LastReason:     r.lastReason,
			Attached:       r.attached,
			PublishedPorts: r.published,
			Holds:          r.holds,
			Freezes:        r.freezes,
			Thaws:          r.thaws,
			CPUUsec:        r.cpuUsec,
			LastError:      r.lastErr,
		})
	}
	sort.Slice(st.Containers, func(i, j int) bool { return st.Containers[i].ID < st.Containers[j].ID })
	return st
}
