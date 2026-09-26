package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ChPuru/hull/internal/bundle"
	"github.com/ChPuru/hull/internal/events"
	"github.com/ChPuru/hull/internal/idutil"
	"github.com/ChPuru/hull/internal/shim"
	"github.com/ChPuru/hull/internal/types"
)

// execRecord is one created exec, alive from Exec until the daemon forgets the
// container.
type execRecord struct {
	id          string
	containerID string
	cfg         ExecConfig
	created     time.Time

	mu       sync.Mutex
	started  bool
	running  bool
	exitCode int
	pid      int
	// handle is the live process while the exec runs. It is kept so a resize
	// can reach the exec's pty: the shim addresses an exec by id, but the
	// only client-side route to that call is through the handle the starter
	// holds.
	handle ExecHandle
}

// snapshot renders the record as an ExecInspect.
func (r *execRecord) snapshot() *ExecInspect {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &ExecInspect{
		ID:           r.id,
		ContainerID:  r.containerID,
		Running:      r.running,
		Started:      r.started,
		ExitCode:     r.exitCode,
		Pid:          r.pid,
		Cmd:          append([]string(nil), r.cfg.Cmd...),
		Env:          append([]string(nil), r.cfg.Env...),
		User:         r.cfg.User,
		WorkingDir:   r.cfg.WorkingDir,
		Tty:          r.cfg.Tty,
		Privileged:   r.cfg.Privileged,
		AttachStdin:  r.cfg.AttachStdin,
		AttachStdout: r.cfg.AttachStdout,
		AttachStderr: r.cfg.AttachStderr,
		Created:      r.created,
	}
}

// Exec registers a command to run inside a running container and returns its
// exec id. Nothing runs until ExecStart is called, which is what lets a client
// set its streams up first.
func (e *Engine) Exec(ctx context.Context, idOrName string, cfg ExecConfig) (string, error) {
	if err := e.checkOpen(); err != nil {
		return "", err
	}
	if len(cfg.Cmd) == 0 {
		return "", fmt.Errorf("%w: exec needs a command to run", ErrInvalid)
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return "", err
	}
	c, err := e.lookup(id)
	if err != nil {
		return "", err
	}
	switch c.State {
	case types.StateRunning:
	case types.StatePaused:
		return "", fmt.Errorf("%w: %s is paused", ErrPaused, idShort(id))
	default:
		return "", fmt.Errorf("%w: %s is %s", ErrNotRunning, idShort(id), c.State)
	}

	rec := &execRecord{
		id:          idutil.NewID(),
		containerID: id,
		cfg:         cfg,
		created:     e.now(),
	}
	e.mu.Lock()
	e.execs[rec.id] = rec
	e.mu.Unlock()

	e.emit(events.ActionExecCreate+": "+strings.Join(cfg.Cmd, " "), c, map[string]string{"execID": rec.id})
	return rec.id, nil
}

// execRecordFor looks an exec up by id.
func (e *Engine) execRecordFor(execID string) (*execRecord, error) {
	e.mu.RLock()
	rec := e.execs[execID]
	e.mu.RUnlock()
	if rec == nil {
		return nil, fmt.Errorf("%w: no such exec: %s", ErrNotFound, execID)
	}
	return rec, nil
}

// ExecStart runs a previously created exec and streams its output until it
// exits or the client detaches.
func (e *Engine) ExecStart(ctx context.Context, execID string, opts AttachConfig) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	rec, err := e.execRecordFor(execID)
	if err != nil {
		return err
	}
	rec.mu.Lock()
	if rec.running {
		rec.mu.Unlock()
		return fmt.Errorf("%w: exec %s is already running", ErrConflict, execID)
	}
	rec.mu.Unlock()

	c, err := e.lookup(rec.containerID)
	if err != nil {
		return err
	}
	if c.State != types.StateRunning {
		return fmt.Errorf("%w: %s is %s", ErrNotRunning, idShort(c.ID), c.State)
	}
	sup, err := e.supervisorFor(rec.containerID)
	if err != nil {
		return err
	}
	spec, err := e.execSpec(c, rec.cfg.Cmd, bundle.ExecOptions{
		User:       rec.cfg.User,
		WorkingDir: rec.cfg.WorkingDir,
		Env:        rec.cfg.Env,
		Tty:        rec.cfg.Tty,
		Privileged: rec.cfg.Privileged,
	})
	if err != nil {
		return err
	}

	detach := opts.DetachKeys
	if detach == "" {
		detach = rec.cfg.DetachKeys
	}
	handle, err := sup.Exec(ctx, execID, spec, shim.AttachOptions{
		Stdin:      opts.UseStdin && opts.Stdin != nil,
		Stdout:     opts.UseStdout && opts.Stdout != nil,
		Stderr:     opts.UseStderr && opts.Stderr != nil,
		DetachKeys: detach,
	})
	if err != nil {
		return fmt.Errorf("engine: start exec %s in %s: %w", execID, idShort(c.ID), err)
	}
	defer handle.Close()

	rec.mu.Lock()
	rec.started, rec.running, rec.pid, rec.handle = true, true, handle.Pid(), handle
	rec.mu.Unlock()
	e.emit(events.ActionExecStart+": "+strings.Join(rec.cfg.Cmd, " "), c, map[string]string{"execID": execID})

	if opts.Started != nil {
		close(opts.Started)
		opts.Started = nil
	}
	e.trackAttachment(rec.containerID, 1)
	defer e.trackAttachment(rec.containerID, -1)

	pumpErr := pumpStream(ctx, handle, opts, rec.cfg.Tty)

	code, werr := handle.Wait(context.WithoutCancel(ctx))
	rec.mu.Lock()
	rec.running = false
	rec.handle = nil
	if werr == nil {
		rec.exitCode = code
	}
	rec.mu.Unlock()
	if werr == nil {
		e.emit(events.ActionExecDie, c, map[string]string{
			"execID":   execID,
			"exitCode": strconv.Itoa(code),
		})
	}
	if pumpErr != nil && !errors.Is(pumpErr, shim.ErrDetached) {
		return pumpErr
	}
	return nil
}

// ExecInspect reports an exec's state.
func (e *Engine) ExecInspect(ctx context.Context, execID string) (*ExecInspect, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec, err := e.execRecordFor(execID)
	if err != nil {
		return nil, err
	}
	return rec.snapshot(), nil
}

// ExecResize sets a running exec's pty window size.
func (e *Engine) ExecResize(ctx context.Context, execID string, h, w uint16) error {
	rec, err := e.execRecordFor(execID)
	if err != nil {
		return err
	}
	rec.mu.Lock()
	handle := rec.handle
	rec.mu.Unlock()
	if handle == nil {
		return fmt.Errorf("%w: exec %s is not running", ErrNotRunning, execID)
	}
	if err := handle.Resize(ctx, h, w); err != nil {
		if errors.Is(err, shim.ErrNoTerminal) {
			return fmt.Errorf("%w: exec %s was created without a terminal", ErrConflict, execID)
		}
		return fmt.Errorf("engine: resize exec %s: %w", execID, err)
	}
	return nil
}

// execSpec builds the OCI process block for one exec, inheriting from the
// container's own spec so "hull exec <ctr> env" shows the container's
// environment and not the daemon's.
func (e *Engine) execSpec(c *types.Container, cmd []string, opts bundle.ExecOptions) ([]byte, error) {
	spec, err := bundle.Read(e.containerDir(c.ID))
	if err != nil {
		return nil, fmt.Errorf("engine: read the bundle of %s: %w", idShort(c.ID), err)
	}
	proc, err := bundle.GenerateExec(c, spec, cmd, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	body, err := json.Marshal(proc)
	if err != nil {
		return nil, fmt.Errorf("engine: encode the exec process spec: %w", err)
	}
	return body, nil
}

// execProbe runs a short-lived command inside a container and returns its exit
// code and combined output. It is what the healthcheck worker uses.
func (e *Engine) execProbe(ctx context.Context, c *types.Container, cmd []string) (int, string, error) {
	sup, err := e.supervisorFor(c.ID)
	if err != nil {
		return -1, "", err
	}
	spec, err := e.execSpec(c, cmd, bundle.ExecOptions{})
	if err != nil {
		return -1, "", err
	}
	handle, err := sup.Exec(ctx, "health-"+idutil.NewShortID(), spec, shim.AttachOptions{
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		return -1, "", err
	}
	defer handle.Close()

	var buf bytes.Buffer
	var mu sync.Mutex
	var wg sync.WaitGroup
	collect := func(r io.Reader) {
		defer wg.Done()
		if r == nil {
			return
		}
		chunk := make([]byte, 4096)
		for {
			n, rerr := r.Read(chunk)
			if n > 0 {
				mu.Lock()
				buf.Write(chunk[:n])
				mu.Unlock()
			}
			if rerr != nil {
				return
			}
		}
	}
	wg.Add(2)
	go collect(handle.Stdout())
	go collect(handle.Stderr())

	code, werr := handle.Wait(ctx)
	// Give the output a moment to drain before the stream is torn down, so a
	// healthcheck's diagnosis is not truncated by its own exit.
	drain := time.NewTimer(2 * time.Second)
	select {
	case <-handle.Done():
	case <-drain.C:
	}
	drain.Stop()
	_ = handle.Close()
	wg.Wait()
	mu.Lock()
	out := buf.String()
	mu.Unlock()
	if werr != nil {
		return -1, out, werr
	}
	return code, out, nil
}
