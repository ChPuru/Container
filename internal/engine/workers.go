package engine

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/shim"
	"github.com/rahuldhali/hull/internal/types"
)

// Health status values, matching Docker's vocabulary.
const (
	// HealthStarting means the container is inside its start period, or has
	// not been probed yet.
	HealthStarting = "starting"
	// HealthHealthy means the last probe succeeded.
	HealthHealthy = "healthy"
	// HealthUnhealthy means the probe has failed Retries times in a row.
	HealthUnhealthy = "unhealthy"
)

// Restart backoff bounds. The first automatic restart waits 100ms and each
// subsequent one doubles, up to a minute, so a container that cannot start
// stops hammering the machine without ever being given up on.
const (
	// RestartBackoffInitial is the first delay.
	RestartBackoffInitial = 100 * time.Millisecond
	// RestartBackoffMax is the ceiling the delay doubles up to.
	RestartBackoffMax = 60 * time.Second
)

// maxHealthLog is how many probe results are kept on a container, matching
// Docker's ring of five.
const maxHealthLog = 5

// startWorkers launches the background goroutines that outlive any single
// request: the garbage collector and, when configured, the idle watcher.
func (e *Engine) startWorkers() {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.gcLoop(e.ctx)
	}()
	if e.cfg.IdleFreeze > 0 || e.cfg.IdleExit > 0 {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.IdleWatcher(e.ctx)
		}()
	}
}

// ---------- reaper ----------

// startReaper watches one container's exit.
//
// It does its bookkeeping without taking the container's keyed lock: a Stop is
// holding that lock while it waits for exactly this notification, and taking
// it here would deadlock. Anything that does need the lock — the restart
// policy, an auto-remove — is handed to a separate goroutine that takes it
// properly.
func (e *Engine) startReaper(id string, sup Supervisor) {
	ctx, cancel := context.WithCancel(e.ctx)
	e.mu.Lock()
	st, ok := e.rt[id]
	if !ok {
		st = &ctrState{}
		e.rt[id] = st
	}
	if st.reaperStop != nil {
		st.reaperStop()
	}
	st.reaperStop = cancel
	e.mu.Unlock()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer cancel()
		code, err := sup.Wait(ctx)
		oom := false
		reason := ""
		if err != nil {
			if ctx.Err() != nil {
				// The daemon is shutting down or the container was removed.
				// Either way the container is not ours to reap any more.
				return
			}
			if st, rerr := e.spawner.ReadExit(e.containerDir(id)); rerr == nil {
				code, oom, reason = st.ExitCode, st.OOMKilled, st.Error
			} else {
				e.log.Warn("hull: lost the shim of a running container",
					"container", idShort(id), "err", err)
				code, reason = 255, err.Error()
			}
		} else if state, serr := sup.State(context.WithoutCancel(ctx)); serr == nil {
			oom = state.OOMKilled
			reason = state.Error
		}
		e.handleExit(ctx, id, code, oom, reason)
	}()
}

// handleExit records a container's exit and releases the resources that only
// a running container needs.
func (e *Engine) handleExit(ctx context.Context, id string, code int, oomKilled bool, reason string) {
	bg := context.WithoutCancel(ctx)
	c, err := e.lookup(id)
	if err != nil {
		return
	}
	now := e.now()
	if uerr := e.update(id, func(cur *types.Container) error {
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
		cur.NetworkSettings.Ports = nil
		for name, ep := range cur.NetworkSettings.Networks {
			cur.NetworkSettings.Networks[name] = types.EndpointSettings{
				NetworkID: ep.NetworkID,
				Aliases:   ep.Aliases,
			}
		}
		return nil
	}); uerr != nil {
		e.log.Warn("hull: could not record a container exit", "container", idShort(id), "err", uerr)
	}
	c.State = types.StateExited
	c.ExitCode = code
	c.OOMKilled = oomKilled

	if oomKilled {
		e.emit(events.ActionOOM, c, nil)
	}
	e.emit(events.ActionDie, c, map[string]string{"exitCode": strconv.Itoa(code)})

	// The cgroup, the ports and the veth belong to a running container.
	if err := e.nets.UnpublishPorts(bg, id); err != nil {
		e.log.Debug("hull: could not unpublish ports on exit", "container", idShort(id), "err", err)
	}
	for name, ep := range c.NetworkSettings.Networks {
		netID := ep.NetworkID
		if netID == "" {
			netID = name
		}
		if err := e.nets.Disconnect(bg, netID, id, true); err != nil {
			e.log.Debug("hull: could not release an endpoint on exit", "container", idShort(id), "err", err)
		}
	}

	// Release the shim: it has done its job, and acknowledging the exit lets
	// it leave at once instead of sitting out its grace period.
	if sup := e.clearSupervisor(id); sup != nil {
		ackCtx, cancel := context.WithTimeout(bg, 5*time.Second)
		if err := sup.Ack(ackCtx); err != nil && !errors.Is(err, shim.ErrShimGone) {
			e.log.Debug("hull: could not acknowledge an exit to the shim", "container", idShort(id), "err", err)
		}
		cancel()
		_ = sup.Close()
	}
	e.stopHealth(id)
	e.notify.publish(id, lifecycleEvent{kind: notifyExit, exitCode: code})

	if c.HostConfig.AutoRemove {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.autoRemove(bg, id)
		}()
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.maybeRestart(bg, id, code)
	}()
}

// autoRemove performs the full removal an --rm container asked for.
func (e *Engine) autoRemove(ctx context.Context, id string) {
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return
	}
	defer unlock()
	if err := e.removeLocked(ctx, id, true, true); err != nil && !errors.Is(err, ErrNotFound) {
		e.log.Warn("hull: could not auto-remove a container", "container", idShort(id), "err", err)
	}
}

// ---------- restart policy ----------

// ShouldRestart decides whether a container that exited with code should be
// started again.
//
// manualStop is the decisive input: a container the user stopped is never
// restarted, whatever its policy says, and that fact is persisted so
// "unless-stopped" still honours it after a daemon restart.
func ShouldRestart(policy types.RestartPolicy, code int, manualStop bool, attempts int) bool {
	if manualStop {
		return false
	}
	switch policy.Name {
	case "", "no":
		return false
	case "always", "unless-stopped":
		if policy.MaximumRetryCount > 0 && attempts >= policy.MaximumRetryCount {
			return false
		}
		return true
	case "on-failure":
		if code == 0 {
			return false
		}
		if policy.MaximumRetryCount > 0 && attempts >= policy.MaximumRetryCount {
			return false
		}
		return true
	default:
		return false
	}
}

// NextBackoff doubles a restart delay, starting at RestartBackoffInitial and
// stopping at RestartBackoffMax.
func NextBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return RestartBackoffInitial
	}
	next := current * 2
	if next > RestartBackoffMax {
		return RestartBackoffMax
	}
	return next
}

// maybeRestart applies the container's restart policy after an exit.
func (e *Engine) maybeRestart(ctx context.Context, id string, code int) {
	c, err := e.lookup(id)
	if err != nil {
		return
	}
	st := e.runtimeState(id)
	e.mu.Lock()
	attempts := st.restartAttempts
	e.mu.Unlock()

	if !ShouldRestart(c.HostConfig.RestartPolicy, code, e.manuallyStopped(id), attempts) {
		e.mu.Lock()
		st.restartBackoff = 0
		st.restartAttempts = 0
		e.mu.Unlock()
		return
	}

	e.mu.Lock()
	st.restartBackoff = NextBackoff(st.restartBackoff)
	st.restartAttempts++
	delay := st.restartBackoff
	attempts = st.restartAttempts
	e.mu.Unlock()

	if uerr := e.update(id, func(cur *types.Container) error {
		cur.State = types.StateRestarting
		cur.RestartCount = attempts
		return nil
	}); uerr != nil {
		return
	}
	c.State = types.StateRestarting
	e.emit(events.ActionRestart, c, map[string]string{"attempt": strconv.Itoa(attempts)})

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return
	case <-e.ctx.Done():
		return
	}

	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return
	}
	defer unlock()

	// The world may have moved on while the backoff ran.
	cur, err := e.lookup(id)
	if err != nil || cur.State == types.StateRunning || e.manuallyStopped(id) {
		return
	}
	if err := e.startLocked(ctx, id, nil); err != nil {
		e.log.Warn("hull: automatic restart failed", "container", idShort(id),
			"attempt", attempts, "backoff", delay, "err", err)
		// A failed restart is itself an exit as far as the policy is
		// concerned, so try again with the next backoff.
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.maybeRestart(ctx, id, code)
		}()
		return
	}
	e.mu.Lock()
	st.restartBackoff = 0
	e.mu.Unlock()
}

// ---------- healthcheck ----------

// startHealth launches the healthcheck loop for a container that has one.
func (e *Engine) startHealth(id string) {
	c, err := e.lookup(id)
	if err != nil || c.Config.Healthcheck == nil {
		return
	}
	ctx, cancel := context.WithCancel(e.ctx)
	e.mu.Lock()
	st, ok := e.rt[id]
	if !ok {
		st = &ctrState{}
		e.rt[id] = st
	}
	if st.healthStop != nil {
		st.healthStop()
	}
	st.healthStop = cancel
	e.mu.Unlock()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer cancel()
		e.healthLoop(ctx, id, *c.Config.Healthcheck)
	}()
}

// stopHealth cancels a container's healthcheck loop.
func (e *Engine) stopHealth(id string) {
	e.mu.Lock()
	st := e.rt[id]
	var cancel context.CancelFunc
	if st != nil {
		cancel = st.healthStop
		st.healthStop = nil
	}
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// healthLoop probes a container on its interval and maintains its health
// state.
//
// Failures inside the start period do not count towards Retries and do not
// make the container unhealthy: that is what a start period is for, and
// getting it wrong makes every slow-booting database look broken.
func (e *Engine) healthLoop(ctx context.Context, id string, hc types.Healthcheck) {
	start := e.now()
	ticker := time.NewTicker(hc.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		c, err := e.lookup(id)
		if err != nil || c.State != types.StateRunning {
			return
		}
		inStartPeriod := hc.StartPeriod > 0 && e.now().Sub(start) < hc.StartPeriod
		res := e.probeHealth(ctx, c, hc)
		if ctx.Err() != nil {
			return
		}
		e.recordHealth(id, res, hc.Retries, inStartPeriod)
	}
}

// probeHealth runs one healthcheck probe and returns its result.
func (e *Engine) probeHealth(ctx context.Context, c *types.Container, hc types.Healthcheck) types.HealthLog {
	entry := types.HealthLog{Start: e.now()}
	cmd, err := HealthcheckCommand(&hc, nil)
	if err != nil {
		entry.End = e.now()
		entry.ExitCode = -1
		entry.Output = err.Error()
		return entry
	}
	probeCtx, cancel := context.WithTimeout(ctx, hc.Timeout)
	defer cancel()

	code, out, err := e.execProbe(probeCtx, c, cmd)
	entry.End = e.now()
	entry.Output = truncateOutput(out)
	switch {
	case err != nil && errors.Is(err, context.DeadlineExceeded):
		entry.ExitCode = -1
		entry.Output = "healthcheck timed out after " + hc.Timeout.String()
	case err != nil:
		entry.ExitCode = -1
		if entry.Output == "" {
			entry.Output = err.Error()
		}
	default:
		entry.ExitCode = code
	}
	return entry
}

// truncateOutput caps a probe's captured output, as Docker does, so a chatty
// healthcheck cannot grow the container record without bound.
func truncateOutput(s string) string {
	const max = 4096
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// recordHealth folds one probe result into the container's health state and
// emits an event when the status changes.
func (e *Engine) recordHealth(id string, entry types.HealthLog, retries int, inStartPeriod bool) {
	var before, after string
	if err := e.update(id, func(cur *types.Container) error {
		if cur.Health == nil {
			cur.Health = &types.HealthState{Status: HealthStarting}
		}
		before = cur.Health.Status
		cur.Health.Log = append(cur.Health.Log, entry)
		if len(cur.Health.Log) > maxHealthLog {
			cur.Health.Log = cur.Health.Log[len(cur.Health.Log)-maxHealthLog:]
		}
		switch {
		case entry.ExitCode == 0:
			cur.Health.FailingStreak = 0
			cur.Health.Status = HealthHealthy
		case inStartPeriod:
			// Still booting: a failure here is expected and must not count.
			cur.Health.Status = HealthStarting
		default:
			cur.Health.FailingStreak++
			if cur.Health.FailingStreak >= retries {
				cur.Health.Status = HealthUnhealthy
			}
		}
		after = cur.Health.Status
		return nil
	}); err != nil {
		e.log.Debug("hull: could not record a healthcheck result", "container", idShort(id), "err", err)
		return
	}
	if before == after {
		return
	}
	if c, err := e.lookup(id); err == nil {
		e.emit(events.ActionHealthStatus+": "+after, c, map[string]string{
			"health_status": after,
			"exitCode":      strconv.Itoa(entry.ExitCode),
		})
	}
}

// ---------- garbage collection ----------

// gcLoop periodically drops dangling snapshots and unreferenced blobs.
func (e *Engine) gcLoop(ctx context.Context) {
	ticker := time.NewTicker(DefaultGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if _, err := e.collectGarbage(ctx); err != nil && ctx.Err() == nil {
			e.log.Warn("hull: background garbage collection failed", "err", err)
		}
	}
}

// ---------- scale to zero ----------

// IdleWatcher runs hull's scale-to-zero loop until ctx is cancelled.
//
// A container whose cgroup CPU usage has not moved for IdleFreeze, and which
// has no attached client, is frozen and reported with a "pause" event: a
// frozen container holds no CPU and its pages become reclaimable, which is the
// whole point on WSL, where Docker Desktop's resource saver does not actually
// give memory back.
//
// When every container has been idle for IdleExit and no API client is
// connected, a daemon "idle" event is emitted so the supervisor can stop the
// distro and let WSL reclaim the VM.
func (e *Engine) IdleWatcher(ctx context.Context) {
	if e.cfg.IdleFreeze <= 0 && e.cfg.IdleExit <= 0 {
		return
	}
	ticker := time.NewTicker(DefaultIdlePoll)
	defer ticker.Stop()

	idleSince := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		allIdle, any := e.sweepIdle(ctx)
		switch {
		case !allIdle || e.clientCount() > 0:
			idleSince = time.Time{}
		case idleSince.IsZero():
			idleSince = e.now()
		case e.cfg.IdleExit > 0 && e.now().Sub(idleSince) >= e.cfg.IdleExit:
			e.bus.Publish(events.Daemon("idle", map[string]string{
				"idleFor":    e.now().Sub(idleSince).String(),
				"containers": strconv.Itoa(any),
			}))
			idleSince = e.now()
		}
	}
}

// sweepIdle samples every running container, freezing the ones that have gone
// quiet. It reports whether all of them are idle and how many there are.
func (e *Engine) sweepIdle(ctx context.Context) (allIdle bool, count int) {
	ctrs, err := e.state.ListContainers()
	if err != nil {
		return false, 0
	}
	allIdle = true
	now := e.now()
	for _, c := range ctrs {
		if c.State != types.StateRunning {
			continue
		}
		count++
		st := e.runtimeState(c.ID)
		stat, serr := e.cgroupStat(c.ID)
		if serr != nil {
			// Without a cgroup there is no honest idleness signal, so the
			// container counts as busy rather than being frozen on a guess.
			allIdle = false
			continue
		}
		e.mu.Lock()
		busy := stat.CPUUsageUsec != st.lastCPU || st.attachments > 0
		if busy {
			st.lastCPU = stat.CPUUsageUsec
			st.lastBusy = now
		}
		if st.lastBusy.IsZero() {
			st.lastBusy = now
		}
		idleFor := now.Sub(st.lastBusy)
		frozen := st.frozen
		e.mu.Unlock()

		if busy || idleFor < e.cfg.IdleFreeze {
			allIdle = false
			continue
		}
		if e.cfg.IdleFreeze > 0 && !frozen {
			if err := e.freezeIdle(ctx, c); err != nil {
				e.log.Debug("hull: could not freeze an idle container", "container", idShort(c.ID), "err", err)
				allIdle = false
			}
		}
	}
	return allIdle, count
}

// freezeIdle freezes one idle container and records it as paused.
func (e *Engine) freezeIdle(ctx context.Context, c *types.Container) error {
	unlock, ok := e.locks.TryLock(c.ID)
	if !ok {
		// Something else is working on it; it is not idle after all.
		return nil
	}
	defer unlock()
	if err := e.freeze(c.ID); err != nil {
		return err
	}
	if err := e.update(c.ID, func(cur *types.Container) error {
		cur.State = types.StatePaused
		return nil
	}); err != nil {
		return err
	}
	st := e.runtimeState(c.ID)
	e.mu.Lock()
	st.frozen = true
	e.mu.Unlock()
	c.State = types.StatePaused
	e.emit(events.ActionPause, c, map[string]string{"reason": "idle"})
	_ = ctx
	return nil
}

// trackAttachment adjusts the live-attachment count that keeps a container out
// of the idle watcher's reach.
func (e *Engine) trackAttachment(id string, delta int) {
	st := e.runtimeState(id)
	e.mu.Lock()
	st.attachments += delta
	if st.attachments < 0 {
		st.attachments = 0
	}
	st.lastBusy = e.now()
	e.mu.Unlock()
}

// describeRestartPolicy renders a restart policy the way the CLI prints it.
func describeRestartPolicy(p types.RestartPolicy) string {
	if p.Name == "" {
		return "no"
	}
	if p.MaximumRetryCount > 0 {
		return fmt.Sprintf("%s:%d", p.Name, p.MaximumRetryCount)
	}
	return strings.ToLower(p.Name)
}
