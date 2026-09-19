package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/shim"
	"github.com/rahuldhali/hull/internal/snapshot"
	"github.com/rahuldhali/hull/internal/state"
	"github.com/rahuldhali/hull/internal/types"
)

// recover reconciles the persisted state with reality.
//
// A hull daemon does not own its containers' lifetimes: each one is supervised
// by a shim that is reparented to PID 1, so a container outlives the daemon
// that started it. Startup therefore has to ask, for every persisted
// container, what is actually true right now — and fix the record when it is
// not what the record claims.
//
// The order matters. Overlay mounts are reconciled first, because a daemon
// that was killed leaves them mounted and every later step touches a container
// directory. Then the network is brought up, because re-publishing a port and
// re-creating an endpoint both need the bridges back. Only then is each
// container examined.
func (e *Engine) recover(ctx context.Context) error {
	if err := e.snaps.Cleanup(ctx); err != nil && !errors.Is(err, snapshot.ErrUnsupportedPlatform) {
		e.log.Warn("hull: reconciling overlay mounts at startup reported problems", "err", err)
	}

	if err := e.nets.Init(ctx); err != nil {
		// Without networking hull can still inspect, list and remove
		// containers, so this is reported rather than fatal.
		e.log.Error("hull: could not bring the container network up", "err", err)
		e.hostWarnings = append(e.hostWarnings,
			"container networking is not available: "+err.Error())
	}

	actions, err := e.state.Recover(ctx, e.processAlive)
	if err != nil {
		return fmt.Errorf("engine: recover the state store: %w", err)
	}
	for _, a := range actions {
		e.log.Info("hull: recovered a container", "action", a.String())
	}

	ctrs, err := e.state.ListContainers()
	if err != nil {
		return fmt.Errorf("engine: list containers during recovery: %w", err)
	}
	for _, c := range ctrs {
		if err := ctx.Err(); err != nil {
			return err
		}
		e.recoverContainer(ctx, c)
	}
	return nil
}

// processAlive is the liveness test state.Recover uses. It asks the process
// table, not the record, and compares the process start time so a recycled pid
// cannot be mistaken for the container's own.
func (e *Engine) processAlive(pid int, startedAt time.Time) bool {
	return state.ProcessAlive(pid, startedAt)
}

// recoverContainer reconciles one container.
func (e *Engine) recoverContainer(ctx context.Context, c *types.Container) {
	dir := e.containerDir(c.ID)
	// Read the on-disk marker before taking the lock: manuallyStopped takes
	// the same RWMutex for reading, and a Go RWMutex is not re-entrant.
	stopped := e.manuallyStopped(c.ID)
	st := e.runtimeState(c.ID)
	e.mu.Lock()
	st.manualStop = stopped
	e.mu.Unlock()

	sup, err := e.spawner.Reconnect(ctx, dir)
	if err == nil {
		e.adoptContainer(ctx, c, sup)
		return
	}
	if !errors.Is(err, shim.ErrShimGone) && !errors.Is(err, fs.ErrNotExist) {
		e.log.Warn("hull: could not reconnect to a container's shim",
			"container", idShort(c.ID), "err", err)
	}

	// No live shim. Whatever the record said, this container is not running.
	if c.State == types.StateRunning || c.State == types.StatePaused || c.State == types.StateRestarting {
		code, oom, reason := e.exitStatusFor(dir)
		if err := e.markExited(c.ID, code, reason, oom); err != nil {
			e.log.Warn("hull: could not record a vanished container's exit",
				"container", idShort(c.ID), "err", err)
		}
		fresh, lerr := e.lookup(c.ID)
		if lerr == nil {
			e.emit(events.ActionDie, fresh, map[string]string{"exitCode": itoa(code)})
			c = fresh
		}
		// The ports and endpoints of a container that is no longer running
		// belong to nobody.
		if uerr := e.nets.UnpublishPorts(ctx, c.ID); uerr != nil {
			e.log.Debug("hull: could not unpublish the ports of a vanished container",
				"container", idShort(c.ID), "err", uerr)
		}
	}

	// A container the user never stopped, whose policy says it should be
	// running, is started again. This is what makes "unless-stopped" survive a
	// daemon restart, and it is why the manual-stop marker is on disk.
	if ShouldRestart(c.HostConfig.RestartPolicy, c.ExitCode, e.manuallyStopped(c.ID), 0) {
		e.wg.Add(1)
		go func(id string) {
			defer e.wg.Done()
			unlock, lerr := e.locks.Lock(e.ctx, id)
			if lerr != nil {
				return
			}
			defer unlock()
			if _, serr := e.startLocked(e.ctx, id, nil); serr != nil {
				e.log.Warn("hull: could not restart a container after a daemon restart",
					"container", idShort(id), "err", serr)
			}
		}(c.ID)
	}
}

// adoptContainer re-takes ownership of a container whose shim is still alive.
func (e *Engine) adoptContainer(ctx context.Context, c *types.Container, sup Supervisor) {
	live, err := sup.State(ctx)
	if err != nil {
		e.log.Warn("hull: a reconnected shim would not report its state",
			"container", idShort(c.ID), "err", err)
		_ = sup.Close()
		return
	}
	if live.Exited {
		// The shim held the exit status open for exactly this case.
		reason := live.Error
		if uerr := e.markExited(c.ID, live.ExitCode, reason, live.OOMKilled); uerr != nil {
			e.log.Warn("hull: could not record an exit collected from a shim",
				"container", idShort(c.ID), "err", uerr)
		}
		ackCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = sup.Ack(ackCtx)
		cancel()
		_ = sup.Close()
		if fresh, lerr := e.lookup(c.ID); lerr == nil {
			e.emit(events.ActionDie, fresh, map[string]string{"exitCode": itoa(live.ExitCode)})
		}
		return
	}

	e.log.Info("hull: re-adopted a running container",
		"container", idShort(c.ID), "pid", live.Pid)
	e.setSupervisor(c.ID, sup)

	if err := e.update(c.ID, func(cur *types.Container) error {
		cur.State = types.StateRunning
		cur.Pid = live.Pid
		if cur.StartedAt.IsZero() && !live.StartedAt.IsZero() {
			cur.StartedAt = live.StartedAt
		}
		return nil
	}); err != nil {
		e.log.Warn("hull: could not update a re-adopted container", "container", idShort(c.ID), "err", err)
	}
	c.Pid = live.Pid
	c.State = types.StateRunning

	// Endpoints and published ports live in the daemon's memory as well as on
	// disk, so both are re-created here.
	if err := e.attachNetworks(ctx, c); err != nil {
		e.log.Warn("hull: could not re-create a container's network endpoints",
			"container", idShort(c.ID), "err", err)
	}
	if err := e.nets.ConfigureSandbox(ctx, c.Pid, c); err == nil {
		if serr := e.syncSandboxFiles(c.ID); serr != nil {
			e.log.Debug("hull: could not refresh the sandbox files", "container", idShort(c.ID), "err", serr)
		}
	}
	if err := e.publishPorts(ctx, c); err != nil {
		e.log.Warn("hull: could not re-publish a container's ports",
			"container", idShort(c.ID), "err", err)
	}
	if err := e.update(c.ID, func(cur *types.Container) error {
		cur.NetworkSettings = c.NetworkSettings
		return nil
	}); err != nil {
		e.log.Debug("hull: could not persist re-created network settings",
			"container", idShort(c.ID), "err", err)
	}

	e.startReaper(c.ID, sup)
	e.startHealth(c.ID)
}

// exitStatusFor reads the exit record a departed shim left behind.
func (e *Engine) exitStatusFor(dir string) (code int, oomKilled bool, reason string) {
	st, err := e.spawner.ReadExit(dir)
	if err != nil {
		return state.DisappearedExitCode, false, state.DisappearedProcessError
	}
	return st.ExitCode, st.OOMKilled, st.Error
}

// itoa is strconv.Itoa under a shorter name, used only for event attributes.
func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
