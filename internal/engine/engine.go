package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rahuldhali/hull/internal/bundle"
	"github.com/rahuldhali/hull/internal/cgroups"
	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/fsutil"
	"github.com/rahuldhali/hull/internal/hostinfo"
	"github.com/rahuldhali/hull/internal/network"
	"github.com/rahuldhali/hull/internal/oci/registry"
	"github.com/rahuldhali/hull/internal/oci/runtimespec"
	hullruntime "github.com/rahuldhali/hull/internal/runtime"
	"github.com/rahuldhali/hull/internal/snapshot"
	"github.com/rahuldhali/hull/internal/state"
	"github.com/rahuldhali/hull/internal/types"
	"github.com/rahuldhali/hull/internal/version"
	"github.com/rahuldhali/hull/internal/volume"
)

// Defaults the engine falls back on when Config leaves a field zero.
const (
	// DefaultDataRoot is where hull keeps everything.
	DefaultDataRoot = state.DefaultRoot
	// DefaultSubnetPool is the CIDR container networks are carved from. It
	// deliberately avoids both the WSL NAT subnet and Docker's default pools.
	DefaultSubnetPool = "10.66.0.0/16"
	// DefaultMaxConcurrentPulls bounds simultaneous image pulls.
	DefaultMaxConcurrentPulls = 3
	// DefaultEventHistory is how many past events a new subscriber can replay.
	DefaultEventHistory = 256
	// DefaultGCInterval is how often the background collector sweeps dangling
	// snapshots and unreferenced blobs.
	DefaultGCInterval = 30 * time.Minute
	// DefaultIdlePoll is how often the scale-to-zero watcher samples.
	DefaultIdlePoll = 15 * time.Second
)

// Config is everything hulld tells the engine at startup. The zero value is
// usable: every field falls back to a documented default.
type Config struct {
	// DataRoot is hull's state directory, normally /var/lib/hull.
	DataRoot string
	// RuntimeName selects the container driver: "hull" for the native one,
	// "crun" (or "runc") for an external OCI runtime binary. Empty prefers
	// the native driver and falls back with a logged explanation.
	RuntimeName string
	// RuntimeBinary is an explicit path to the OCI runtime executable. Empty
	// means look for crun and then runc on PATH.
	RuntimeBinary string
	// ShimBinary is the absolute path of hull-shim. Without it no container
	// can be started, because the shim is what outlives the daemon.
	ShimBinary string
	// InitBinary is the absolute path of hull-init, bind-mounted into a
	// container started with --init so orphaned children are reaped.
	InitBinary string
	// DefaultPool is the subnet pool for container networks.
	DefaultPool string
	// RegistryMirrors are tried before the canonical registry host.
	RegistryMirrors []string
	// InsecureRegistries are hosts hull will talk plain HTTP to.
	InsecureRegistries []string
	// IdleFreeze is how long a container may sit with no CPU movement and no
	// attached client before it is frozen. Zero disables scale-to-zero.
	IdleFreeze time.Duration
	// IdleExit is how long every container must have been idle, with no
	// client connected, before the daemon emits its "idle" event so the
	// supervisor can shut the distro down. Zero disables it.
	IdleExit time.Duration
	// MaxConcurrentPulls bounds simultaneous image pulls.
	MaxConcurrentPulls int
	// LogConfig is the default log driver for new containers.
	LogConfig types.LogConfig
	// Logger receives the engine's own diagnostics. Nil means slog.Default.
	Logger *slog.Logger
}

// withDefaults returns cfg with every zero field filled in.
func (c Config) withDefaults() Config {
	if c.DataRoot == "" {
		c.DataRoot = DefaultDataRoot
	}
	if c.DefaultPool == "" {
		c.DefaultPool = DefaultSubnetPool
	}
	if c.MaxConcurrentPulls <= 0 {
		c.MaxConcurrentPulls = DefaultMaxConcurrentPulls
	}
	if c.LogConfig.Type == "" {
		c.LogConfig.Type = "json-file"
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// ctrState is the engine's in-memory view of one container: its shim, the
// goroutines watching it, and the bookkeeping the restart, health and idle
// workers need.
type ctrState struct {
	// sup is the live supervisor, or nil when the container is not running.
	sup Supervisor
	// reaperStop cancels the goroutine waiting on the container's exit.
	reaperStop context.CancelFunc
	// healthStop cancels the healthcheck loop.
	healthStop context.CancelFunc
	// restartBackoff is the delay the next automatic restart will wait.
	restartBackoff time.Duration
	// restartAttempts counts automatic restarts since the last manual start.
	restartAttempts int
	// manualStop records an explicit Stop, Kill or Remove, which suppresses
	// the restart policy. It is mirrored to disk so "unless-stopped" survives
	// a daemon restart.
	manualStop bool
	// attachments counts live attach streams, which is what makes a container
	// "in use" for the idle watcher.
	attachments int
	// lastCPU and lastBusy drive idle detection.
	lastCPU  uint64
	lastBusy time.Time
	// lastSample is the most recent stats reading, used as the "pre" half of
	// a one-shot stats call so a CPU percentage can be computed without
	// sampling twice.
	lastSample types.Stats
	// frozen records that the idle watcher, rather than the user, froze it.
	frozen bool
}

// Engine is hull's orchestration core. It is safe for concurrent use.
type Engine struct {
	cfg Config
	log *slog.Logger

	state   *state.Store
	content *content.Store
	snaps   Snapshotter
	vols    Volumes
	nets    Networker
	images  *imageStore
	bus     *events.Bus

	driver        hullruntime.Runtime
	runtimeName   string
	runtimeBinary string
	runtimeVer    string
	specVersion   string
	bundleFeat    bundle.Features
	cgroupInfo    cgroups.Info
	host          *hostinfo.Report
	hostWarnings  []string

	spawner Spawner

	// newRegistry builds a registry client bound to one call's progress sink.
	newRegistry func(progress func(registry.ProgressEvent)) Registry

	locks   *keyedLock
	pullSem chan struct{}
	notify  *notifier

	mu     sync.RWMutex
	rt     map[string]*ctrState
	execs  map[string]*execRecord
	closed bool

	// clients counts live API clients, which the idle watcher consults before
	// it declares the daemon idle.
	clientMu sync.Mutex
	clients  int

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	now func() time.Time
}

// New builds an engine over cfg.DataRoot and reconciles it with reality.
//
// It probes the host, opens the state, content, snapshot, volume and network
// subsystems, selects a container runtime, then recovers: every persisted
// container is checked against the process table and the shim that claims it,
// live shims are re-adopted, vanished containers are marked exited, restart
// policies are re-applied and published ports and network endpoints are
// re-created. A daemon "start" event is emitted last.
func New(ctx context.Context, cfg Config) (*Engine, error) {
	cfg = cfg.withDefaults()
	root, err := filepath.Abs(cfg.DataRoot)
	if err != nil {
		return nil, fmt.Errorf("engine: resolve data root %q: %w", cfg.DataRoot, err)
	}
	cfg.DataRoot = root

	e := &Engine{
		cfg:     cfg,
		log:     cfg.Logger,
		locks:   newKeyedLock(),
		pullSem: make(chan struct{}, cfg.MaxConcurrentPulls),
		notify:  newNotifier(),
		rt:      make(map[string]*ctrState),
		execs:   make(map[string]*execRecord),
		now:     func() time.Time { return time.Now().UTC() },
	}
	e.ctx, e.cancel = context.WithCancel(context.WithoutCancel(ctx))
	e.bus = events.NewBus(DefaultEventHistory)

	// The host probe is advisory: a daemon that cannot probe is still a
	// daemon, and every subsystem below feature-probes what it actually uses.
	if rep, perr := hostinfo.Probe(ctx); perr == nil {
		e.host = rep
		for _, c := range rep.Checks {
			if c.Status == hostinfo.StatusFail || c.Status == hostinfo.StatusWarn {
				e.hostWarnings = append(e.hostWarnings, checkWarning(c))
			}
		}
	} else if !errors.Is(perr, hostinfo.ErrUnsupported) {
		e.hostWarnings = append(e.hostWarnings, "host probe failed: "+perr.Error())
	}

	if e.state, err = state.Open(root); err != nil {
		return nil, fmt.Errorf("engine: open state store: %w", err)
	}
	e.state.SetLogger(e.log)
	fail := func(err error) (*Engine, error) {
		_ = e.state.Close()
		e.cancel()
		return nil, err
	}

	if e.content, err = content.NewStore(filepath.Join(root, "content")); err != nil {
		return fail(fmt.Errorf("engine: open content store: %w", err))
	}

	feat, derr := snapshot.Detect(ctx, root)
	if derr != nil && !errors.Is(derr, snapshot.ErrUnsupportedPlatform) {
		return fail(fmt.Errorf("engine: probe overlayfs: %w", derr))
	}
	snaps, serr := snapshot.New(root, feat)
	if serr != nil {
		return fail(fmt.Errorf("engine: open snapshotter: %w", serr))
	}
	e.snaps = snaps
	if ferr := feat.Err(); ferr != nil {
		e.hostWarnings = append(e.hostWarnings, ferr.Error())
	}

	vm, verr := volume.New(filepath.Join(root, "volumes"), e.state)
	if verr != nil {
		return fail(fmt.Errorf("engine: open volume manager: %w", verr))
	}
	vm.SetLogger(e.log)
	e.vols = vm

	nopts := network.DefaultManagerOptions()
	nopts.DefaultPool = cfg.DefaultPool
	nm, nerr := network.New(root, nopts)
	if nerr != nil {
		return fail(fmt.Errorf("engine: open network manager: %w", nerr))
	}
	e.nets = nm

	if e.images, err = openImageStore(root); err != nil {
		return fail(err)
	}

	if cerr := e.selectRuntime(ctx); cerr != nil {
		return fail(cerr)
	}
	e.spawner = newShimSpawner(cfg.ShimBinary)
	e.newRegistry = e.defaultRegistryFactory

	if err := e.recover(ctx); err != nil {
		return fail(err)
	}

	e.startWorkers()
	e.bus.Publish(events.Daemon(events.ActionStart, map[string]string{
		"dataRoot": root,
		"runtime":  e.runtimeName,
		"version":  version.Version,
	}))
	return e, nil
}

// checkWarning renders a failed or warned host check as one actionable line.
func checkWarning(c hostinfo.Check) string {
	s := c.Name + ": " + c.Detail
	if c.Remedy != "" {
		s += " — " + c.Remedy
	}
	return s
}

// selectRuntime picks the container driver and works out which runtime-spec
// version to write into bundles on this host.
//
// The native driver is preferred when the kernel satisfies it. When it does
// not, the reason is logged rather than swallowed, because "hull silently used
// crun" is exactly the kind of thing that makes a container engine feel
// haunted.
func (e *Engine) selectRuntime(ctx context.Context) error {
	root := filepath.Join(e.cfg.DataRoot, "runtime")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("engine: create runtime state root %s: %w", root, err)
	}

	want := strings.ToLower(strings.TrimSpace(e.cfg.RuntimeName))
	if want == "" || want == hullruntime.NativeName {
		probe, perr := hullruntime.ProbeFeatures(ctx)
		native, nerr := hullruntime.NewNative(root, probe)
		switch {
		case perr != nil:
			e.log.Info("hull: native runtime unavailable, using an external OCI runtime",
				"reason", perr.Error())
		case nerr != nil:
			e.log.Info("hull: native runtime unavailable, using an external OCI runtime",
				"reason", nerr.Error())
		default:
			e.driver = native
			e.runtimeName = native.Name()
			if e.cfg.InitBinary != "" {
				if b, rerr := os.ReadFile(e.cfg.InitBinary); rerr == nil {
					if serr := native.SetInitBinary(b); serr != nil {
						e.log.Warn("hull: could not seal the init binary into a memfd", "err", serr)
					}
				}
			}
		}
	}

	// The shim drives an external runtime binary whatever the engine's own
	// driver is, so resolve one regardless and say so plainly if there is
	// none.
	crun, cerr := hullruntime.NewCrun(e.cfg.RuntimeBinary, root)
	if cerr == nil {
		e.runtimeBinary = crun.Binary()
		if e.driver == nil {
			e.driver = crun
			e.runtimeName = crun.Name()
		}
	} else if e.driver == nil {
		return fmt.Errorf("engine: no container runtime is usable: %w", cerr)
	} else {
		e.hostWarnings = append(e.hostWarnings, "no external OCI runtime binary was found, so the "+
			"per-container shim has nothing to drive; install crun or runc, or pass --runtime with a path")
	}

	feats, ferr := e.driver.Features(ctx)
	if ferr != nil {
		e.log.Warn("hull: could not read the runtime's feature report", "runtime", e.runtimeName, "err", ferr)
	}
	e.runtimeVer = feats.Version
	e.specVersion = NegotiateSpecVersion(runtimespec.Version, feats.OCIVersions)
	e.hostWarnings = append(e.hostWarnings, feats.Warnings...)

	info, derr := cgroups.Detect()
	if derr != nil && !errors.Is(derr, cgroups.ErrUnsupported) {
		e.log.Warn("hull: cgroup probe failed", "err", derr)
	}
	e.cgroupInfo = info
	e.hostWarnings = append(e.hostWarnings, info.Warnings...)

	e.bundleFeat = bundle.Features{
		IdmappedMounts: feats.Probe.IDMappedMounts,
		CgroupV2:       info.Usable(),
		Seccomp:        feats.Probe.Seccomp,
	}
	if e.host != nil {
		e.bundleFeat.KernelMajor = e.host.Kernel.Major
		e.bundleFeat.KernelMinor = e.host.Kernel.Minor
		e.bundleFeat.Landlock = e.host.Security.Landlock > 0
	}
	return nil
}

// defaultRegistryFactory builds a registry client for one call, wiring its
// progress sink and hull's insecure-registry policy.
func (e *Engine) defaultRegistryFactory(progress func(registry.ProgressEvent)) Registry {
	return registry.NewClient(registry.Options{
		Auth:        registry.NewKeychain(registry.DefaultHullConfigPath(), registry.DefaultDockerConfigPath()),
		Insecure:    len(e.cfg.InsecureRegistries) > 0,
		Concurrency: e.cfg.MaxConcurrentPulls,
		Progress:    progress,
	})
}

// Events returns the engine's event bus. Subscribers filter and replay through
// it; the engine never hands out the raw channel.
func (e *Engine) Events() *events.Bus { return e.bus }

// DataRoot is hull's state directory.
func (e *Engine) DataRoot() string { return e.cfg.DataRoot }

// Doctor re-probes the host and returns the full report behind "hull doctor".
// It is deliberately a fresh probe: the answer changes when the operator runs
// `wsl --update` or starts Docker Desktop, and a cached report would lie.
func (e *Engine) Doctor(ctx context.Context) (*hostinfo.Report, error) {
	rep, err := hostinfo.Probe(ctx)
	if err != nil {
		return nil, fmt.Errorf("engine: probe host: %w", err)
	}
	e.mu.Lock()
	e.host = rep
	e.mu.Unlock()
	return rep, nil
}

// Info returns the /info payload: counts, driver names, the kernel, whether
// cgroup v2 is actually delegated, and the host warnings the operator should
// act on.
func (e *Engine) Info(ctx context.Context) (Info, error) {
	if err := e.checkOpen(); err != nil {
		return Info{}, err
	}
	ctrs, err := e.state.ListContainers()
	if err != nil {
		return Info{}, fmt.Errorf("engine: list containers: %w", err)
	}
	info := Info{
		ID:                daemonID(e.cfg.DataRoot),
		ServerVersion:     version.Version,
		Images:            e.images.Len(),
		Driver:            "overlay2",
		LoggingDriver:     e.cfg.LogConfig.Type,
		CgroupDriver:      "cgroupfs",
		CgroupVersion:     cgroupVersionString(e.cgroupInfo),
		CgroupV2Delegated: e.cgroupInfo.Usable(),
		OSType:            "linux",
		Architecture:      runtime.GOARCH,
		NCPU:              cgroups.OnlineCPUs(),
		DataRoot:          e.cfg.DataRoot,
		DockerRootDir:     e.cfg.DataRoot,
		DefaultRuntime:    e.runtimeName,
		RuntimeVersion:    e.runtimeVer,
		OCIVersion:        e.specVersion,
		Runtimes:          []string{hullruntime.NativeName, "crun", "runc"},
		Plugins: InfoPlugins{
			Volume:  []string{volume.DriverLocal},
			Network: []string{"bridge", "host", "none"},
			Log:     []string{"json-file", "none"},
		},
	}
	if host, herr := os.Hostname(); herr == nil {
		info.Name = host
	}
	for _, c := range ctrs {
		info.Containers++
		switch c.State {
		case types.StateRunning, types.StateRestarting:
			info.ContainersRunning++
		case types.StatePaused:
			info.ContainersPaused++
		default:
			info.ContainersStopped++
		}
	}

	e.mu.RLock()
	host := e.host
	e.mu.RUnlock()
	if host != nil {
		info.KernelVersion = host.Kernel.Release
		info.OperatingSystem = host.WSL.Distro
		info.MemTotal = int64(host.Storage.TotalBytes)
		if host.WSL.IsWSL && info.OperatingSystem == "" {
			info.OperatingSystem = "WSL2"
		}
		if host.Namespaces.User {
			info.SecurityOptions = append(info.SecurityOptions, "name=userns")
		}
		if host.Security.Seccomp {
			info.SecurityOptions = append(info.SecurityOptions, "name=seccomp,profile=builtin")
		}
	}
	info.DriverStatus = [][2]string{
		{"Backing Filesystem", "overlayfs"},
		{"Snapshot root", filepath.Join(e.cfg.DataRoot, snapshot.DirSnapshots)},
	}
	info.Warnings = append(info.Warnings, e.hostWarnings...)
	if !e.cgroupInfo.Usable() {
		info.Warnings = append(info.Warnings, cgroups.HybridRemedy)
	}
	info.Warnings = dedupeStrings(info.Warnings)
	return info, nil
}

// cgroupVersionString renders the cgroup mode as the "1"/"2" the Docker API
// expects, while the hybrid case is spelled out honestly.
func cgroupVersionString(i cgroups.Info) string {
	switch i.Mode {
	case cgroups.ModeUnified:
		return "2"
	case cgroups.ModeHybrid:
		if i.Usable() {
			return "2"
		}
		return "1"
	case cgroups.ModeLegacy:
		return "1"
	default:
		return "0"
	}
}

// daemonID derives a stable identity for this daemon from its data root, so
// two engines on one host are distinguishable without persisting yet another
// file.
func daemonID(root string) string {
	d := content.DigestBytes([]byte("hull:" + root))
	return strings.TrimPrefix(d, content.Algorithm+":")[:32]
}

// Close stops accepting work, shuts the background workers down, detaches from
// every shim without killing anything, flushes the state store and releases the
// daemon lock.
//
// Containers deliberately survive: each one is supervised by a shim reparented
// to PID 1, and the next daemon start re-adopts them.
func (e *Engine) Close(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	sups := make([]Supervisor, 0, len(e.rt))
	for _, st := range e.rt {
		if st.reaperStop != nil {
			st.reaperStop()
		}
		if st.healthStop != nil {
			st.healthStop()
		}
		if st.sup != nil {
			sups = append(sups, st.sup)
		}
	}
	e.rt = make(map[string]*ctrState)
	e.mu.Unlock()

	e.cancel()
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		e.log.Warn("hull: background workers did not stop in time", "err", ctx.Err())
	}

	var errs []error
	for _, s := range sups {
		// Close detaches the control connection. It does not signal the
		// container, and it must not: the shim keeps supervising.
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if e.nets != nil {
		if err := e.nets.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("engine: shut the network manager down: %w", err))
		}
	}
	e.bus.Publish(events.Daemon("shutdown", map[string]string{"dataRoot": e.cfg.DataRoot}))
	e.bus.Close()
	if e.state != nil {
		if err := e.state.Close(); err != nil {
			errs = append(errs, fmt.Errorf("engine: close the state store: %w", err))
		}
	}
	return errors.Join(errs...)
}

// checkOpen refuses work once Close has started.
func (e *Engine) checkOpen() error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return ErrClosed
	}
	return nil
}

// ClientConnected and ClientDisconnected bracket an API client's lifetime. The
// idle watcher will not declare the daemon idle while any client is connected,
// which is what stops `hull logs -f` from being cut off by scale-to-zero.
func (e *Engine) ClientConnected() {
	e.clientMu.Lock()
	e.clients++
	e.clientMu.Unlock()
}

// ClientDisconnected records that an API client has gone away.
func (e *Engine) ClientDisconnected() {
	e.clientMu.Lock()
	if e.clients > 0 {
		e.clients--
	}
	e.clientMu.Unlock()
}

// clientCount reports how many API clients are connected.
func (e *Engine) clientCount() int {
	e.clientMu.Lock()
	defer e.clientMu.Unlock()
	return e.clients
}

// ---------- per-container bookkeeping ----------

// runtimeState returns the in-memory record for id, creating it if needed.
func (e *Engine) runtimeState(id string) *ctrState {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, ok := e.rt[id]
	if !ok {
		st = &ctrState{}
		e.rt[id] = st
	}
	return st
}

// lookupRuntimeState returns the in-memory record for id without creating one.
func (e *Engine) lookupRuntimeState(id string) *ctrState {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rt[id]
}

// supervisorFor returns the live supervisor for id, or an error saying the
// container is not running.
func (e *Engine) supervisorFor(id string) (Supervisor, error) {
	e.mu.RLock()
	st := e.rt[id]
	e.mu.RUnlock()
	if st == nil || st.sup == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotRunning, idShort(id))
	}
	return st.sup, nil
}

// setSupervisor attaches a supervisor to a container's record.
func (e *Engine) setSupervisor(id string, sup Supervisor) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, ok := e.rt[id]
	if !ok {
		st = &ctrState{}
		e.rt[id] = st
	}
	st.sup = sup
}

// clearSupervisor detaches and returns the supervisor for id, if any.
func (e *Engine) clearSupervisor(id string) Supervisor {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.rt[id]
	if st == nil {
		return nil
	}
	sup := st.sup
	st.sup = nil
	return sup
}

// forgetContainer drops every in-memory trace of a removed container.
func (e *Engine) forgetContainer(id string) {
	e.mu.Lock()
	st := e.rt[id]
	delete(e.rt, id)
	for eid, rec := range e.execs {
		if rec.containerID == id {
			delete(e.execs, eid)
		}
	}
	e.mu.Unlock()
	if st != nil {
		if st.reaperStop != nil {
			st.reaperStop()
		}
		if st.healthStop != nil {
			st.healthStop()
		}
	}
}

// ---------- container records ----------

// lookup resolves an id, id prefix or name to the full container record.
func (e *Engine) lookup(idOrName string) (*types.Container, error) {
	c, err := e.state.GetContainer(idOrName)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return nil, fmt.Errorf("%w: no such container: %s", ErrNotFound, idOrName)
		}
		return nil, fmt.Errorf("engine: look up container %q: %w", idOrName, err)
	}
	return c, nil
}

// resolveID turns an id, id prefix or name into a full container id.
func (e *Engine) resolveID(idOrName string) (string, error) {
	id, err := e.state.Resolve(idOrName)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return "", fmt.Errorf("%w: no such container: %s", ErrNotFound, idOrName)
		}
		return "", fmt.Errorf("engine: resolve container %q: %w", idOrName, err)
	}
	return id, nil
}

// update applies fn to a container record under the store's per-container lock
// and persists the result.
func (e *Engine) update(id string, fn func(*types.Container) error) error {
	if err := e.state.UpdateContainer(id, fn); err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return fmt.Errorf("%w: no such container: %s", ErrNotFound, idShort(id))
		}
		return fmt.Errorf("engine: update container %s: %w", idShort(id), err)
	}
	return nil
}

// containerDir is where a container's bundle, logs, shim socket and overlay
// directories live.
func (e *Engine) containerDir(id string) string { return e.state.ContainerDir(id) }

// logPath is the json-file log for a container.
func (e *Engine) logPath(id string) string {
	return filepath.Join(e.containerDir(id), id+"-json.log")
}

// cgroupPath is the absolute cgroup v2 directory for a container, or "" when
// the host has no usable unified hierarchy. An empty path tells the shim to
// skip stats and OOM detection rather than to guess.
func (e *Engine) cgroupPath(id string) string {
	if e.cgroupInfo.Root == "" || !e.cgroupInfo.Usable() {
		return ""
	}
	return filepath.Join(e.cgroupInfo.Root, "hull", id)
}

// cgroupRel is the cgroup path relative to the hierarchy root, which is what
// the runtime-spec wants.
func cgroupRel(id string) string { return "hull/" + id }

// manualStopPath records an explicit stop so "unless-stopped" survives a
// daemon restart. Its presence means "the user stopped this on purpose".
func (e *Engine) manualStopPath(id string) string {
	return filepath.Join(e.containerDir(id), "manual-stop")
}

// setManualStop records or clears the explicit-stop marker, in memory and on
// disk.
func (e *Engine) setManualStop(id string, stopped bool) {
	st := e.runtimeState(id)
	e.mu.Lock()
	st.manualStop = stopped
	e.mu.Unlock()

	p := e.manualStopPath(id)
	if stopped {
		if err := fsutil.WriteFileAtomic(p, []byte("1\n"), 0o600); err != nil {
			e.log.Warn("hull: could not record the manual stop marker", "container", idShort(id), "err", err)
		}
		return
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		e.log.Warn("hull: could not clear the manual stop marker", "container", idShort(id), "err", err)
	}
}

// manuallyStopped reports whether the container carries the explicit-stop
// marker, consulting the on-disk one so the answer survives a restart.
func (e *Engine) manuallyStopped(id string) bool {
	e.mu.RLock()
	st := e.rt[id]
	e.mu.RUnlock()
	if st != nil && st.manualStop {
		return true
	}
	return fsutil.Exists(e.manualStopPath(id))
}

// warningsPath is where the bundle warnings for a container are kept, so they
// survive a daemon restart and can still be shown by `hull inspect`.
func (e *Engine) warningsPath(id string) string {
	return filepath.Join(e.containerDir(id), "warnings.json")
}

// setWarnings persists the warnings a bundle generation produced.
//
// These are the messages that say a resource limit could not be enforced on
// this host's hybrid cgroups. They must reach the API response and the CLI, or
// the user silently gets an unlimited container, so they are stored rather
// than logged and forgotten.
func (e *Engine) setWarnings(id string, warnings []string) {
	if len(warnings) == 0 {
		_ = os.Remove(e.warningsPath(id))
		return
	}
	if err := fsutil.WriteJSONAtomic(e.warningsPath(id), warnings, 0o600); err != nil {
		e.log.Warn("hull: could not record container warnings", "container", idShort(id), "err", err)
	}
}

// Warnings returns the warnings recorded when the container's bundle was
// generated: resource limits this host cannot enforce, ownership caveats under
// a user namespace, security options that were ignored.
func (e *Engine) Warnings(ctx context.Context, idOrName string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return nil, err
	}
	var out []string
	if rerr := fsutil.ReadJSON(e.warningsPath(id), &out); rerr != nil {
		if errors.Is(rerr, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("engine: read warnings for %s: %w", idShort(id), rerr)
	}
	return out, nil
}

// emit publishes a container event with the given extra attributes.
func (e *Engine) emit(action string, c *types.Container, extra map[string]string) {
	e.bus.Publish(events.Container(action, c, extra))
}

// idShort trims an id to the 12 characters the CLI shows.
func idShort(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// dedupeStrings removes duplicates and empty entries, keeping first-seen order.
func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// NegotiateSpecVersion picks the runtime-spec version to write into a bundle.
//
// A runtime refuses a spec version it does not know, and says so badly: crun
// 1.14.1 rejects 1.2.0 with a bare "unknown version specified" even though it
// reads every field hull emits. accepted is the driver's own answer
// (RuntimeFeatures.OCIVersions), which for crun is [min, max] and may carry a
// "+dev" suffix. The result is the highest version both sides understand, and
// falls back to hull's own when the driver said nothing useful.
func NegotiateSpecVersion(hullVersion string, accepted []string) string {
	best := ""
	for _, raw := range accepted {
		v := strings.TrimSpace(raw)
		if i := strings.IndexAny(v, "+-"); i > 0 {
			v = v[:i]
		}
		if v == "" || !looksLikeVersion(v) {
			continue
		}
		if compareVersions(v, hullVersion) > 0 {
			continue // the driver accepts more than hull models
		}
		if best == "" || compareVersions(v, best) > 0 {
			best = v
		}
	}
	if best == "" {
		return hullVersion
	}
	return best
}

// looksLikeVersion reports whether s is a dotted numeric version.
func looksLikeVersion(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// compareVersions orders two dotted numeric versions.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = atoiSafe(as[i])
		}
		if i < len(bs) {
			bv = atoiSafe(bs[i])
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// atoiSafe parses a non-negative decimal, returning 0 for anything else.
func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// sortedKeys returns a map's keys in sorted order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
