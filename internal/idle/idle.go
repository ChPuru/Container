// Package idle implements hull's scale-to-zero supervisor: the answer to the
// fact that Docker Desktop's Resource Saver never gives memory back.
//
// Resource Saver parks Docker's VM CPU, but the WSL utility VM keeps every
// page it has ever claimed until the VM itself is shut down, so an idle Docker
// Desktop still costs gigabytes of Windows RAM. hull attacks the problem from
// both ends. A container nobody is using is frozen with cgroup.freeze, which
// stops it consuming CPU and lets the kernel reclaim its pages under pressure;
// and when every container has been idle for ExitAfter with no client holding
// an API connection, the daemon is told to exit, which releases the engine
// distro so WSL tears the VM down and hands the memory back to Windows.
//
// # Activity
//
// A container counts as active when any of these holds, highest priority
// first:
//
//  1. a client holds an attach or exec stream open (Snapshot.Attached > 0);
//  2. a byte moved through a published port proxy — the proxy calls ThawFor
//     before it forwards a new connection and TouchWith(id, ReasonPort) as
//     bytes flow;
//  3. the container's cgroup cpu.stat usage_usec advanced by more than
//     Config.CPUFloorUsec since the previous sample;
//  4. an explicit Touch from the API layer.
//
// # The two failure modes this package is shaped around
//
// A container serving traffic must never be frozen. Every signal above latches
// into the container's activity clock the moment it is observed, a freeze is
// re-checked against that clock immediately before it is applied, and a
// connection that arrives while a freeze is in flight waits for it and thaws
// again before the client sees anything. The one honest gap is CPU: on the
// hybrid-cgroup WSL kernels hull targets, cpu.stat may not exist at all. The
// watcher then has no CPU signal, says so once through the logger and in
// Stats.CPUSampling, and relies on streams, port traffic and Touch.
//
// A frozen container must never be reported as exited. This package never
// changes lifecycle state: it calls only Source.Freeze and Source.Thaw, and
// Frozen and FrozenIDs tell the API layer which containers it must report as
// paused. A container the *user* paused is never touched at all — the watcher
// only ever thaws what it froze itself.
//
// # Using it
//
//	w := idle.NewWatcher(idle.Config{
//	        FreezeAfter: 5 * time.Minute,
//	        ExitAfter:   30 * time.Minute,
//	        OnFreeze:    func(id string) { ... },
//	        OnIdle:      func() { daemon.Shutdown() },
//	}, engine)
//	go w.Run(ctx)
//
// Every method is safe for concurrent use. The package imports nothing but the
// standard library, so it builds on every GOOS hull ships for; on a host with
// no cgroup filesystem the CPU signal is simply absent.
package idle

import (
	"errors"
	"log/slog"
	"strconv"
	"time"
)

// Defaults for the tunables a caller leaves zero.
const (
	// DefaultSampleInterval is how often Run evaluates every container when
	// Config.SampleInterval is zero.
	DefaultSampleInterval = 10 * time.Second
	// DefaultThawTimeout bounds how long ThawFor waits for a thaw to actually
	// take effect when Config.ThawTimeout is zero.
	DefaultThawTimeout = 5 * time.Second
	// DefaultCPUFloorUsec is the cpu.stat usage_usec delta, in microseconds of
	// CPU time per sample, at or below which a container counts as idle. It is
	// deliberately small: 10 ms of CPU inside a 10 s sample is 0.1% of one
	// core, which is a heartbeat, not work.
	DefaultCPUFloorUsec uint64 = 10_000
)

// Bounds the watcher enforces on itself.
const (
	// minSampleInterval keeps a misconfigured interval from becoming a busy
	// loop.
	minSampleInterval = time.Millisecond
	// thawPollMin and thawPollMax bound the backoff ThawFor uses while it
	// waits for a thaw to become visible in the source.
	thawPollMin = time.Millisecond
	thawPollMax = 25 * time.Millisecond
	// shortIDLen is how much of a container ID appears in logs and errors.
	shortIDLen = 12
)

// Event actions, spelled the way the Docker event stream spells them so the
// daemon can publish them unchanged.
const (
	// ActionPause is emitted when the watcher freezes a container.
	ActionPause = "pause"
	// ActionUnpause is emitted when the watcher thaws one.
	ActionUnpause = "unpause"
)

// Reasons an event carries. A pause is always ReasonIdle; an unpause names the
// signal that woke the container.
const (
	// ReasonIdle means no activity signal fired for FreezeAfter.
	ReasonIdle = "idle"
	// ReasonAttach means a client holds an attach or exec stream open.
	ReasonAttach = "attach"
	// ReasonPort means traffic arrived on a published port.
	ReasonPort = "port"
	// ReasonCPU means the cgroup's cpu.stat usage_usec moved past the floor.
	ReasonCPU = "cpu"
	// ReasonTouch means the API layer reported activity explicitly.
	ReasonTouch = "touch"
	// ReasonStart means the container has only just appeared or started.
	ReasonStart = "start"
)

// Errors returned by this package. Callers should test them with errors.Is:
// every error is wrapped with the container ID for context.
var (
	// ErrNoSource means the watcher was built without a Source.
	ErrNoSource = errors.New("idle: no container source")
	// ErrAlreadyRunning means Run was called on a watcher that is already
	// running.
	ErrAlreadyRunning = errors.New("idle: watcher is already running")
	// ErrUnknownContainer means the source does not know the container, so
	// there is nothing to thaw.
	ErrUnknownContainer = errors.New("idle: unknown container")
	// ErrPausedExternally means the container was paused by the user rather
	// than by the watcher. Scale-to-zero never second-guesses an explicit
	// pause, so the caller — normally the port proxy — must fail the
	// connection instead.
	ErrPausedExternally = errors.New("idle: container was paused explicitly, not by the idle watcher")
	// ErrThawTimeout means Source.Thaw returned but the container was still
	// frozen when ThawTimeout expired.
	ErrThawTimeout = errors.New("idle: timed out waiting for the container to thaw")
)

// Snapshot is the engine's view of one container, reduced to what the idle
// decision needs. The watcher never holds a reference to engine state; it asks
// for a fresh slice of these on every pass.
type Snapshot struct {
	// ID is the container ID. An empty ID is ignored.
	ID string
	// Running reports whether the container's init process is alive. A
	// container that is not running is never frozen and never keeps the
	// daemon awake.
	Running bool
	// Frozen reports whether the container's cgroup is frozen right now,
	// whoever froze it. The watcher compares it against its own bookkeeping
	// so it can tell its own freezes from a user's `hull pause`.
	Frozen bool
	// CGroupPath is the absolute cgroup v2 directory for the container, or ""
	// when the host has no usable unified hierarchy. An empty path simply
	// means no CPU signal.
	CGroupPath string
	// Attached is the number of live attach and exec streams. Any open stream
	// pins the container awake.
	Attached int
	// PublishedPorts is how many host ports are published for the container.
	// It does not affect the freeze decision — a published server is exactly
	// what scale-to-zero is for — but it is what makes a frozen container
	// wakeable from outside, and it is reported on the pause event.
	PublishedPorts int
}

// Source is the engine, seen through the narrowest hole that works. The
// watcher owns no engine state and takes no engine lock; it reads snapshots
// and asks for a freeze or a thaw.
//
// Containers is called on every sample, and repeatedly with a
// millisecond-scale backoff while ThawFor waits for a thaw to land, so it must
// be cheap and must not block on container I/O. A Source that can answer for
// one container more cheaply than it can list them all should also implement
// FrozenChecker.
//
// Freeze and Thaw must be idempotent: the watcher may ask for a state the
// container is already in.
type Source interface {
	// Containers returns the current snapshot of every container the engine
	// knows about.
	Containers() []Snapshot
	// Freeze freezes the container's cgroup (cgroup.freeze = 1).
	Freeze(id string) error
	// Thaw unfreezes it (cgroup.freeze = 0).
	Thaw(id string) error
}

// FrozenChecker is an optional extension to Source. When a Source implements
// it, ThawFor polls FrozenState instead of scanning Containers while it waits
// for a thaw to take effect.
type FrozenChecker interface {
	// FrozenState reports whether the container is frozen, and whether the
	// source knows it at all.
	FrozenState(id string) (frozen, found bool)
}

// Event is one freeze or thaw, ready to be published on the engine's event
// bus. The daemon maps it onto a types.Event; this package deliberately does
// not import hull's domain model.
type Event struct {
	// Action is ActionPause or ActionUnpause.
	Action string
	// ID is the container ID.
	ID string
	// Reason is why: ReasonIdle for a pause, and the waking signal for an
	// unpause.
	Reason string
	// IdleFor is how long the container had been idle when the event fired.
	IdleFor time.Duration
	// PublishedPorts is how many host ports the container publishes, which is
	// what decides whether traffic can wake it again.
	PublishedPorts int
	// Time is when the event happened, on the watcher's clock.
	Time time.Time
}

// Attributes renders the event as Docker event actor attributes, so the daemon
// can publish it with the reason attached:
//
//	bus.Publish(events.Container(ev.Action, ctr, ev.Attributes()))
func (e Event) Attributes() map[string]string {
	attrs := map[string]string{
		"reason": e.Reason,
		"source": "hull-idle",
	}
	if e.IdleFor > 0 {
		attrs["idleFor"] = e.IdleFor.Truncate(time.Millisecond).String()
	}
	if e.PublishedPorts > 0 {
		attrs["publishedPorts"] = strconv.Itoa(e.PublishedPorts)
	}
	return attrs
}

// Config tunes the watcher. Every duration is measured on Config.Now, and
// every zero field takes a working default, so the zero Config is a watcher
// that only tracks activity and never freezes or exits.
type Config struct {
	// FreezeAfter is how long a container must show no activity before it is
	// frozen. Zero disables freezing entirely.
	FreezeAfter time.Duration
	// ExitAfter is how long every container must have been idle, with no API
	// client connected, before OnIdle fires. Zero disables the idle exit.
	ExitAfter time.Duration
	// SampleInterval is how often Run evaluates the world. It defaults to
	// DefaultSampleInterval and is clamped up to one millisecond.
	SampleInterval time.Duration

	// OnFreeze is called after a container has been frozen.
	OnFreeze func(id string)
	// OnThaw is called after a container has been thawed by the watcher.
	OnThaw func(id string)
	// OnIdle is called once when the whole engine has been idle for
	// ExitAfter, so the daemon can shut down and let WSL reclaim the VM's
	// memory. It fires again only after activity resumes.
	OnIdle func()
	// OnEvent receives the "pause" and "unpause" events, tagged with the
	// reason, for the engine's event bus. Optional.
	OnEvent func(ev Event)

	// Cooldown is the hysteresis: the minimum time between thawing a
	// container and being allowed to freeze it again. Zero means FreezeAfter,
	// so a container that becomes busy again always gets a full fresh idle
	// window before it is reconsidered.
	Cooldown time.Duration
	// ThawTimeout bounds how long ThawFor waits for a thaw to become visible
	// in the source. It is measured on the real clock, because it bounds a
	// real wait. Zero means DefaultThawTimeout.
	ThawTimeout time.Duration
	// CPUFloorUsec is the cpu.stat usage_usec delta per sample at or below
	// which a container counts as idle. Zero means DefaultCPUFloorUsec; one
	// means any CPU movement at all is activity.
	CPUFloorUsec uint64

	// ActiveClients reports how many API clients are connected right now, in
	// addition to the ones counted through ClientConnected. Optional: a
	// daemon that already counts its clients can hand the counter over
	// instead of calling the methods.
	ActiveClients func() int

	// ThawOnStop makes Run thaw everything it had frozen before it returns.
	// Leave it false for scale-to-zero — the daemon exits because the
	// containers are frozen, and the freeze has to survive it — and set it
	// when the watcher is switched off while the daemon keeps running.
	ThawOnStop bool

	// CPUUsage reads a cgroup's cumulative CPU time in microseconds, and
	// reports false when there is no such counter. Nil reads usage_usec from
	// <cgroupPath>/cpu.stat, which is what the engine wants; tests and hosts
	// with an exotic hierarchy can replace it.
	CPUUsage func(cgroupPath string) (usec uint64, ok bool)

	// Now is the clock. Nil means time.Now.
	Now func() time.Time

	// Logger receives the watcher's diagnostics: a cgroup that cannot be
	// frozen, and the one-time warning that this host exposes no CPU counter.
	// Nil means slog.Default.
	Logger *slog.Logger
}

// withDefaults returns cfg with every zero field filled in.
func (c Config) withDefaults() Config {
	if c.SampleInterval <= 0 {
		c.SampleInterval = DefaultSampleInterval
	}
	if c.SampleInterval < minSampleInterval {
		c.SampleInterval = minSampleInterval
	}
	if c.FreezeAfter < 0 {
		c.FreezeAfter = 0
	}
	if c.ExitAfter < 0 {
		c.ExitAfter = 0
	}
	if c.Cooldown <= 0 {
		c.Cooldown = c.FreezeAfter
	}
	if c.ThawTimeout <= 0 {
		c.ThawTimeout = DefaultThawTimeout
	}
	if c.CPUFloorUsec == 0 {
		c.CPUFloorUsec = DefaultCPUFloorUsec
	}
	if c.CPUUsage == nil {
		c.CPUUsage = ReadCPUUsageUsec
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// Stats is a point-in-time report of what the watcher is doing, for
// `hull engine status` and the TUI.
type Stats struct {
	// Since is when the watcher was created.
	Since time.Time
	// LastSample is when the last evaluation pass ran.
	LastSample time.Time
	// Samples counts evaluation passes.
	Samples uint64
	// Tracked is how many containers the watcher knows about.
	Tracked int
	// Running is how many of them are running.
	Running int
	// Frozen is how many are frozen, including ones the user paused.
	Frozen int
	// Freezes counts freezes the watcher performed.
	Freezes uint64
	// Thaws counts thaws the watcher performed.
	Thaws uint64
	// Touches counts activity reports.
	Touches uint64
	// FreezeErrors counts failed freezes.
	FreezeErrors uint64
	// ThawErrors counts failed thaws.
	ThawErrors uint64
	// Clients is how many API clients are connected.
	Clients int
	// CPUSampling reports whether the CPU activity signal is available on
	// this host. It is false on a hybrid-cgroup WSL kernel, where freeze
	// decisions rest on streams, port traffic and Touch alone.
	CPUSampling bool
	// LastActivity is when the engine as a whole last saw activity.
	LastActivity time.Time
	// IdleFor is how long ago that was.
	IdleFor time.Duration
	// IdleFired reports whether OnIdle has already fired for this idle spell.
	IdleFired bool
	// Containers is the per-container detail, sorted by ID.
	Containers []ContainerStats
}

// ContainerStats is one container's row in Stats.
type ContainerStats struct {
	// ID is the container ID.
	ID string
	// Running mirrors the last snapshot.
	Running bool
	// Frozen mirrors the last snapshot.
	Frozen bool
	// FrozenByHull distinguishes the watcher's freeze from a user's pause.
	// Only a container with this set is ever thawed automatically.
	FrozenByHull bool
	// FrozenAt is when the watcher froze it.
	FrozenAt time.Time
	// LastActive is when an activity signal last fired.
	LastActive time.Time
	// IdleFor is how long ago that was.
	IdleFor time.Duration
	// LastReason is the signal that last counted as activity.
	LastReason string
	// Attached mirrors the last snapshot.
	Attached int
	// PublishedPorts mirrors the last snapshot.
	PublishedPorts int
	// Holds is how many ThawFor calls are in flight for this container. A
	// container with a hold is never frozen.
	Holds int
	// Freezes counts this container's freezes.
	Freezes int
	// Thaws counts this container's thaws.
	Thaws int
	// CPUUsec is the last cpu.stat usage_usec reading, zero when unavailable.
	CPUUsec uint64
	// LastError is the last freeze or thaw failure, if any.
	LastError string
}

// reasonRank orders the activity signals so the strongest one names the event:
// an open stream beats port traffic, which beats CPU movement, which beats a
// bare Touch.
func reasonRank(reason string) int {
	switch reason {
	case ReasonAttach:
		return 4
	case ReasonPort:
		return 3
	case ReasonCPU:
		return 2
	case ReasonTouch, ReasonStart:
		return 1
	default:
		return 0
	}
}

// topReason returns the highest-priority reason given, or "" when there is
// none.
func topReason(reasons ...string) string {
	best := ""
	for _, r := range reasons {
		if r == "" {
			continue
		}
		if reasonRank(r) > reasonRank(best) {
			best = r
		}
	}
	return best
}

// short trims a container ID for logs and errors the way the rest of hull
// does.
func short(id string) string {
	if len(id) > shortIDLen {
		return id[:shortIDLen]
	}
	return id
}
