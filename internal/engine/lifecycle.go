package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/network"
	"github.com/rahuldhali/hull/internal/shim"
	"github.com/rahuldhali/hull/internal/types"
)

// hardKillGrace bounds how long Stop waits after SIGKILL before giving up and
// reporting the container as dead. A cgroup kill cannot be ignored, so this
// only ever expires when the shim itself is wedged.
const hardKillGrace = 30 * time.Second

// Start spawns the container's shim, attaches it to the network, publishes its
// ports and releases its init process into the entrypoint.
//
// attach may be nil. When it is not, the stream is opened before the container
// is started, so no output can be missed between start and attach.
func (e *Engine) Start(ctx context.Context, idOrName string, attach *AttachConfig) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	return e.startLocked(ctx, id, attach)
}

// startLocked is Start with the container's lock already held.
func (e *Engine) startLocked(ctx context.Context, id string, attach *AttachConfig) error {
	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	switch c.State {
	case types.StateRunning:
		// Docker answers 304 here and the CLI treats it as success; making it
		// an error would break every "start it if it is not running" script.
		return nil
	case types.StatePaused:
		return fmt.Errorf("%w: %s is paused; unpause it before starting it", ErrConflict, idShort(id))
	case types.StateRemoving:
		return fmt.Errorf("%w: %s is being removed", ErrConflict, idShort(id))
	}
	if e.cfg.ShimBinary == "" {
		return fmt.Errorf("%w: no hull-shim binary is configured, so containers cannot be supervised", ErrInvalid)
	}
	if e.runtimeBinary == "" {
		return fmt.Errorf("%w: install crun or runc, or pass --runtime with a path", ErrNoRuntimeBinary)
	}

	img, err := e.images.Get(c.Image)
	if err != nil {
		return fmt.Errorf("engine: the image %s for %s is gone: %w", idShort(c.Image), idShort(id), err)
	}

	// The overlay may have been torn down by a crash or by a daemon restart.
	if mounted, merr := e.snaps.IsMounted(id); merr != nil || !mounted {
		rootfs, rerr := e.snaps.Mount(ctx, id, c.SnapshotID, c.HostConfig.ReadonlyRootfs)
		if rerr != nil {
			return fmt.Errorf("engine: mount the rootfs for %s: %w", idShort(id), rerr)
		}
		c.RootFS = rootfs
	}
	if _, serr := os.Stat(filepath.Join(e.containerDir(id), "config.json")); serr != nil {
		if _, gerr := e.generateBundle(c, img); gerr != nil {
			return gerr
		}
	}

	if warn := e.ensureCgroup(c); warn != "" {
		e.log.Warn("hull: container warning", "container", idShort(id), "warning", warn)
		e.setWarnings(id, dedupeStrings(append(mustWarnings(e, ctx, id), warn)))
	}

	// An explicit start clears the manual-stop marker, which is what makes
	// "unless-stopped" start this container again after a daemon restart.
	e.setManualStop(id, false)

	sup, err := e.spawner.Spawn(ctx, e.shimConfig(c))
	if err != nil {
		return fmt.Errorf("engine: start the shim for %s: %w", idShort(id), err)
	}
	started := false
	defer func() {
		if !started {
			// The shim created the container; tell it to tear it down rather
			// than leaving an orphan in "created" forever.
			sdctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			if serr := sup.Shutdown(sdctx); serr != nil {
				e.log.Warn("hull: could not shut a half-started shim down", "container", idShort(id), "err", serr)
			}
			cancel()
			_ = sup.Close()
		}
	}()

	st, err := sup.State(ctx)
	if err != nil {
		return fmt.Errorf("engine: read the state of %s from its shim: %w", idShort(id), err)
	}
	c.Pid = st.Pid

	// The network needs a live namespace, which is why the veth is created
	// here and not at create time.
	if err := e.attachNetworks(ctx, c); err != nil {
		return err
	}
	if err := e.nets.ConfigureSandbox(ctx, c.Pid, c); err != nil {
		return fmt.Errorf("engine: configure the sandbox of %s: %w", idShort(id), err)
	}
	if err := e.syncSandboxFiles(id); err != nil {
		return err
	}
	if err := e.publishPorts(ctx, c); err != nil {
		return err
	}

	var stream Stream
	if attach != nil && attach.wantsAnyStream() {
		stream, err = sup.Attach(ctx, shim.AttachOptions{
			Stdin:      attach.UseStdin && attach.Stdin != nil,
			Stdout:     attach.UseStdout && attach.Stdout != nil,
			Stderr:     attach.UseStderr && attach.Stderr != nil,
			DetachKeys: attach.DetachKeys,
		})
		if err != nil {
			return fmt.Errorf("engine: attach to %s: %w", idShort(id), err)
		}
	}

	if err := sup.Start(ctx); err != nil {
		if stream != nil {
			_ = stream.Close()
		}
		return fmt.Errorf("engine: start %s: %w", idShort(id), err)
	}
	started = true

	now := e.now()
	if err := e.update(id, func(cur *types.Container) error {
		cur.State = types.StateRunning
		cur.Pid = c.Pid
		cur.StartedAt = now
		cur.FinishedAt = time.Time{}
		cur.ExitCode = 0
		cur.Error = ""
		cur.OOMKilled = false
		cur.RootFS = c.RootFS
		cur.BundleDir = c.BundleDir
		cur.NetworkSettings = c.NetworkSettings
		if cur.Config.Healthcheck != nil {
			cur.Health = &types.HealthState{Status: HealthStarting}
		}
		return nil
	}); err != nil {
		return err
	}
	c.State = types.StateRunning
	c.StartedAt = now

	e.setSupervisor(id, sup)
	e.startReaper(id, sup)
	e.startHealth(id)
	e.emit(events.ActionStart, c, nil)

	if stream != nil {
		e.runAttachment(ctx, id, stream, *attach, c.Config.Tty)
	}
	return nil
}

// shimConfig builds the supervision request for one container.
func (e *Engine) shimConfig(c *types.Container) shim.Config {
	dir := e.containerDir(c.ID)
	cfg := shim.Config{
		ID:            c.ID,
		BundleDir:     dir,
		ContainerDir:  dir,
		RuntimeName:   e.runtimeName,
		RuntimeBinary: e.runtimeBinary,
		RuntimeRoot:   filepath.Join(e.cfg.DataRoot, "runtime"),
		Terminal:      c.Config.Tty,
		OpenStdin:     c.Config.OpenStdin,
		CgroupPath:    e.cgroupPath(c.ID),
		StopSignal:    c.Config.StopSignal,
		StopTimeout:   stopTimeoutFor(c, nil),
	}
	if c.HostConfig.LogConfig.Type != "none" {
		cfg.LogPath = e.logPath(c.ID)
		cfg.LogMaxSize, cfg.LogMaxFiles = logRotation(c.HostConfig.LogConfig)
	}
	return cfg
}

// logRotation reads Docker's max-size and max-file log options.
func logRotation(lc types.LogConfig) (maxSize int64, maxFiles int) {
	maxFiles = 1
	if v, ok := lc.Config["max-file"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			maxFiles = n
		}
	}
	if v, ok := lc.Config["max-size"]; ok {
		if n, err := parseSize(v); err == nil {
			maxSize = n
		}
	}
	return maxSize, maxFiles
}

// parseSize reads a Docker size string such as "10m" or "512k".
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("%w: empty size", ErrInvalid)
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "g"), strings.HasSuffix(s, "gb"):
		mult = 1 << 30
	case strings.HasSuffix(s, "m"), strings.HasSuffix(s, "mb"):
		mult = 1 << 20
	case strings.HasSuffix(s, "k"), strings.HasSuffix(s, "kb"):
		mult = 1 << 10
	}
	digits := strings.TrimRight(s, "gmkb")
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q is not a size", ErrInvalid, s)
	}
	return n * mult, nil
}

// attachNetworks creates the veth pairs recorded at create time and records
// the addresses the IPAM allocated.
func (e *Engine) attachNetworks(ctx context.Context, c *types.Container) error {
	planned, err := e.planEndpoints(c)
	if err != nil {
		return err
	}
	if c.NetworkSettings.Networks == nil {
		c.NetworkSettings.Networks = map[string]types.EndpointSettings{}
	}
	for _, p := range planned {
		cfg := p.cfg
		if existing, ok := c.NetworkSettings.Networks[p.name]; ok && existing.IPAddress != "" {
			// A daemon restart finds the endpoint already there.
			continue
		}
		ep, cerr := e.nets.Connect(ctx, p.id, c, cfg)
		if cerr != nil {
			if errors.Is(cerr, network.ErrExists) {
				continue
			}
			return fmt.Errorf("engine: attach %s to network %s: %w", idShort(c.ID), p.name, cerr)
		}
		c.NetworkSettings.Networks[p.name] = *ep
		e.bus.Publish(events.Network(events.ActionConnect, &types.Network{ID: p.id, Name: p.name}, c.ID))
	}
	return nil
}

// publishPorts opens the userland proxies and DNAT rules for a container and
// records what was actually bound.
func (e *Engine) publishPorts(ctx context.Context, c *types.Container) error {
	bindings := c.HostConfig.PortBindings
	if c.HostConfig.PublishAll {
		bindings = publishAllBindings(c.Config, bindings)
	}
	if len(bindings) == 0 {
		return nil
	}
	published, err := e.nets.PublishPorts(ctx, c, bindings)
	if err != nil {
		return fmt.Errorf("engine: publish the ports of %s: %w", idShort(c.ID), err)
	}
	ports := make(map[string][]types.PortBinding, len(published))
	for _, p := range published {
		spec := network.PortSpec(p.ContainerPort, p.Proto)
		ports[spec] = append(ports[spec], types.PortBinding{
			HostIP:   p.HostIP,
			HostPort: strconv.Itoa(p.HostPort),
		})
	}
	c.NetworkSettings.Ports = ports
	return nil
}

// Stop sends the container's stop signal, waits up to the timeout and then
// kills the whole cgroup.
//
// It is idempotent: stopping an already-stopped container succeeds and changes
// nothing. An explicit Stop also suppresses the restart policy, and records
// that fact on disk so "unless-stopped" still knows about it after a daemon
// restart.
func (e *Engine) Stop(ctx context.Context, idOrName string, timeout *int) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	return e.stopLocked(ctx, id, timeout, true)
}

// stopLocked is Stop with the container's lock held. manual says whether this
// is a user-requested stop, which is what suppresses the restart policy.
func (e *Engine) stopLocked(ctx context.Context, id string, timeout *int, manual bool) error {
	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	if manual {
		e.setManualStop(id, true)
	}
	if c.State != types.StateRunning && c.State != types.StatePaused && c.State != types.StateRestarting {
		return nil
	}
	sup, err := e.supervisorFor(id)
	if err != nil {
		// The record says running but no shim is attached: reconcile rather
		// than leave a phantom.
		return e.markExited(id, 0, "the container's shim is gone", false)
	}

	sub, unsub := e.notify.subscribe(id)
	defer unsub()

	// A paused container cannot react to a signal, so thaw it first.
	if c.State == types.StatePaused {
		if terr := e.thaw(id); terr != nil {
			e.log.Warn("hull: could not thaw a paused container before stopping it",
				"container", idShort(id), "err", terr)
		}
	}

	sig, err := stopSignalFor(c.Config.StopSignal)
	if err != nil {
		return err
	}
	if err := sup.Kill(ctx, sig, false); err != nil && !errors.Is(err, shim.ErrNotRunning) {
		return fmt.Errorf("engine: signal %s with %s: %w", idShort(id), SignalName(sig), err)
	}
	e.emit(events.ActionKill, c, map[string]string{"signal": SignalName(sig)})

	wait := stopTimeoutFor(c, timeout)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case ev := <-sub:
		if ev.kind == notifyExit {
			e.emit(events.ActionStop, c, nil)
			return nil
		}
	case <-timer.C:
	case <-ctx.Done():
		return ctx.Err()
	}

	// The stop signal was not enough. Kill every process in the cgroup, not
	// just init, so a fork bomb or a shell that ignores SIGTERM cannot keep
	// the container alive.
	if err := sup.Kill(ctx, sigKill, true); err != nil && !errors.Is(err, shim.ErrNotRunning) {
		return fmt.Errorf("engine: kill %s: %w", idShort(id), err)
	}
	hard := time.NewTimer(hardKillGrace)
	defer hard.Stop()
	select {
	case <-sub:
		e.emit(events.ActionStop, c, nil)
		return nil
	case <-hard.C:
		return fmt.Errorf("engine: %s did not exit within %s of SIGKILL; its shim may be wedged",
			idShort(id), hardKillGrace)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Kill sends one signal to a running container. An empty signal means SIGKILL,
// matching Docker.
func (e *Engine) Kill(ctx context.Context, idOrName, signal string) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()

	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	if c.State != types.StateRunning && c.State != types.StatePaused {
		return fmt.Errorf("%w: %s is %s", ErrNotRunning, idShort(id), c.State)
	}
	sig := sigKill
	if strings.TrimSpace(signal) != "" {
		if sig, err = ParseSignal(signal); err != nil {
			return err
		}
	}
	if sig == sigKill {
		// A kill is as deliberate as a stop, so it must suppress the restart
		// policy the same way.
		e.setManualStop(id, true)
	}
	sup, err := e.supervisorFor(id)
	if err != nil {
		return err
	}
	if err := sup.Kill(ctx, sig, sig == sigKill); err != nil {
		if errors.Is(err, shim.ErrNotRunning) {
			return fmt.Errorf("%w: %s", ErrNotRunning, idShort(id))
		}
		return fmt.Errorf("engine: signal %s with %s: %w", idShort(id), SignalName(sig), err)
	}
	e.emit(events.ActionKill, c, map[string]string{"signal": SignalName(sig)})
	return nil
}

// Restart stops a container and starts it again, keeping its name, its
// addresses and its writable layer.
func (e *Engine) Restart(ctx context.Context, idOrName string, timeout *int) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()

	if err := e.stopLocked(ctx, id, timeout, true); err != nil {
		return err
	}
	if err := e.startLocked(ctx, id, nil); err != nil {
		return err
	}
	c, err := e.lookup(id)
	if err == nil {
		e.emit(events.ActionRestart, c, nil)
	}
	return nil
}

// Pause freezes every process in a container with cgroup.freeze.
func (e *Engine) Pause(ctx context.Context, idOrName string) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()

	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	if c.State == types.StatePaused {
		return fmt.Errorf("%w: %s is already paused", ErrConflict, idShort(id))
	}
	if c.State != types.StateRunning {
		return fmt.Errorf("%w: %s is %s", ErrNotRunning, idShort(id), c.State)
	}
	if err := e.freeze(id); err != nil {
		return err
	}
	if err := e.update(id, func(cur *types.Container) error {
		cur.State = types.StatePaused
		return nil
	}); err != nil {
		return err
	}
	c.State = types.StatePaused
	e.emit(events.ActionPause, c, nil)
	return nil
}

// Unpause thaws a frozen container.
func (e *Engine) Unpause(ctx context.Context, idOrName string) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()

	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	if c.State != types.StatePaused {
		return fmt.Errorf("%w: %s is not paused", ErrConflict, idShort(id))
	}
	if err := e.thaw(id); err != nil {
		return err
	}
	if err := e.update(id, func(cur *types.Container) error {
		cur.State = types.StateRunning
		return nil
	}); err != nil {
		return err
	}
	c.State = types.StateRunning
	if st := e.lookupRuntimeState(id); st != nil {
		e.mu.Lock()
		st.frozen = false
		e.mu.Unlock()
	}
	e.emit(events.ActionUnpause, c, nil)
	return nil
}

// Remove deletes a container and everything hull created for it.
//
// force stops a running container first. removeVolumes deletes the anonymous
// volumes nothing else references, which is what "hull rm -v" means; a named
// volume is never deleted, because the user named it and it outlives the
// container.
func (e *Engine) Remove(ctx context.Context, idOrName string, force, removeVolumes bool) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	return e.removeLocked(ctx, id, force, removeVolumes)
}

// removeLocked is Remove with the container's lock held.
func (e *Engine) removeLocked(ctx context.Context, id string, force, removeVolumes bool) error {
	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	running := c.State == types.StateRunning || c.State == types.StatePaused || c.State == types.StateRestarting
	if running && !force {
		return fmt.Errorf("%w: %s is running; stop it first or use force", ErrConflict, idShort(id))
	}
	if running {
		if err := e.stopLocked(ctx, id, nil, true); err != nil {
			return err
		}
	}

	if err := e.update(id, func(cur *types.Container) error {
		cur.State = types.StateRemoving
		return nil
	}); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	// Cancel the watchers before tearing anything down, so a late exit
	// notification cannot resurrect the container through its restart policy.
	e.forgetContainer(id)

	var errs []error
	if sup := e.clearSupervisor(id); sup != nil {
		ackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = sup.Ack(ackCtx)
		cancel()
		_ = sup.Close()
	}
	if err := e.nets.UnpublishPorts(ctx, id); err != nil {
		errs = append(errs, err)
	}
	for name, ep := range c.NetworkSettings.Networks {
		netID := ep.NetworkID
		if netID == "" {
			netID = name
		}
		if err := e.nets.Disconnect(ctx, netID, id, true); err != nil {
			errs = append(errs, err)
		}
	}
	if err := e.snaps.Remove(ctx, id); err != nil {
		errs = append(errs, fmt.Errorf("engine: remove the rootfs of %s: %w", idShort(id), err))
	}
	if err := e.vols.Release(ctx, c, removeVolumes); err != nil {
		errs = append(errs, err)
	}
	e.removeCgroup(id)
	if err := e.state.DeleteContainer(id); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("engine: delete the record of %s: %w", idShort(id), err))
	}
	if c.Name != "" {
		if err := e.state.ReleaseName(c.Name); err != nil {
			e.log.Debug("hull: could not release a name on remove", "name", c.Name, "err", err)
		}
	}

	e.emit(events.ActionDestroy, c, nil)
	e.notify.publish(id, lifecycleEvent{kind: notifyRemoved, exitCode: c.ExitCode})
	return errors.Join(errs...)
}

// Wait conditions, as the Docker API spells them.
const (
	// WaitNotRunning returns as soon as the container is not running, which
	// includes a container that had already stopped.
	WaitNotRunning = "not-running"
	// WaitNextExit waits for the next exit, ignoring one that already
	// happened.
	WaitNextExit = "next-exit"
	// WaitRemoved waits until the container record is gone.
	WaitRemoved = "removed"
)

// Wait blocks until the container satisfies condition and returns its exit
// code. An empty condition means WaitNotRunning.
func (e *Engine) Wait(ctx context.Context, idOrName, condition string) (int, error) {
	id, err := e.resolveID(idOrName)
	if err != nil {
		return 0, err
	}
	switch condition {
	case "", WaitNotRunning, WaitNextExit, WaitRemoved:
	default:
		return 0, fmt.Errorf("%w: wait condition %q; use %s, %s or %s",
			ErrInvalid, condition, WaitNotRunning, WaitNextExit, WaitRemoved)
	}

	// Subscribing first closes the race where the container exits between the
	// state check and the subscription.
	sub, unsub := e.notify.subscribe(id)
	defer unsub()

	c, err := e.lookup(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) && condition == WaitRemoved {
			return 0, nil
		}
		return 0, err
	}
	if condition == "" || condition == WaitNotRunning {
		switch c.State {
		case types.StateExited, types.StateCreated, types.StateDead:
			return c.ExitCode, nil
		}
	}

	last := c.ExitCode
	for {
		select {
		case ev := <-sub:
			switch ev.kind {
			case notifyExit:
				last = ev.exitCode
				if condition != WaitRemoved {
					return ev.exitCode, nil
				}
			case notifyRemoved:
				return ev.exitCode, nil
			}
		case <-ctx.Done():
			return last, ctx.Err()
		case <-e.ctx.Done():
			return last, ErrClosed
		}
	}
}

// markExited reconciles a container whose supervision was lost, so the record
// never claims something is running when nothing is.
func (e *Engine) markExited(id string, code int, reason string, oomKilled bool) error {
	now := e.now()
	if err := e.update(id, func(cur *types.Container) error {
		cur.State = types.StateExited
		cur.Pid = 0
		cur.ExitCode = code
		cur.OOMKilled = oomKilled
		cur.FinishedAt = now
		if reason != "" {
			cur.Error = reason
		}
		if cur.Health != nil {
			cur.Health.Status = HealthUnhealthy
		}
		return nil
	}); err != nil {
		return err
	}
	e.notify.publish(id, lifecycleEvent{kind: notifyExit, exitCode: code})
	return nil
}

// Resize sets a running container's pty window size.
func (e *Engine) Resize(ctx context.Context, idOrName string, h, w uint16) error {
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	sup, err := e.supervisorFor(id)
	if err != nil {
		return err
	}
	if err := sup.Resize(ctx, h, w); err != nil {
		if errors.Is(err, shim.ErrNoTerminal) {
			return fmt.Errorf("%w: %s was created without a terminal", ErrConflict, idShort(id))
		}
		return fmt.Errorf("engine: resize %s: %w", idShort(id), err)
	}
	if c, lerr := e.lookup(id); lerr == nil {
		e.emit(events.ActionResize, c, map[string]string{
			"height": strconv.Itoa(int(h)),
			"width":  strconv.Itoa(int(w)),
		})
	}
	return nil
}

// signalOf is a small helper so callers can log a signal without importing
// syscall.
func signalOf(sig syscall.Signal) string { return SignalName(sig) }
