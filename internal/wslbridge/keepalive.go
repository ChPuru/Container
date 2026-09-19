package wslbridge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
	"time"
)

// Why this exists at all: WSL terminates a distro roughly fifteen seconds after
// its last Windows-side client exits, and it does not care what is running
// inside. A resident hulld does not keep its own distro alive -- containers,
// shims and the daemon all go down with it. The only thing that holds a distro
// open is a live Windows-side process attached to it, so hull keeps one.

// Keep-alive defaults.
const (
	// DefaultKeepAliveMinBackoff is the first pause after the holder dies.
	DefaultKeepAliveMinBackoff = 250 * time.Millisecond

	// DefaultKeepAliveMaxBackoff caps the pause between restarts. A distro that
	// refuses to start should not be retried in a tight loop, but the bridge
	// must recover promptly once the user fixes it.
	DefaultKeepAliveMaxBackoff = 30 * time.Second

	// DefaultKeepAliveResetAfter is how long a holder must survive before the
	// backoff is considered recovered and reset to the minimum.
	DefaultKeepAliveResetAfter = 30 * time.Second
)

// KeepAliveProcess is one running keep-alive holder.
type KeepAliveProcess interface {
	// Wait blocks until the holder exits.
	Wait() error
	// Stop terminates the holder. It must be safe to call more than once, and
	// safe to call concurrently with Wait.
	Stop() error
}

// KeepAliveSpawner starts a keep-alive holder. Tests substitute their own so
// the supervisor's backoff can be exercised without a WSL installation.
type KeepAliveSpawner interface {
	Spawn(ctx context.Context, cfg Config) (KeepAliveProcess, error)
}

// WSLKeepAliveSpawner is the real spawner: a
// `wsl.exe -d <distro> -u root --exec /bin/sh -c "while :; do sleep 3600; done"`
// child that does nothing but exist.
//
// The sleep loop rather than a bare `sleep infinity` is deliberate: busybox's
// sleep on some builds caps its argument, and a loop is immune to that.
type WSLKeepAliveSpawner struct{}

// keepAliveScript is the shell the holder runs.
const keepAliveScript = "while :; do sleep 3600; done"

// keepAliveArgs is the wsl.exe argument list for the holder.
func (c Config) keepAliveArgs() []string {
	return c.wslArgs("/bin/sh", "-c", keepAliveScript)
}

// Spawn implements KeepAliveSpawner.
func (WSLKeepAliveSpawner) Spawn(ctx context.Context, cfg Config) (KeepAliveProcess, error) {
	cfg = cfg.WithDefaults()
	cmd := exec.CommandContext(ctx, cfg.WSLPath, cfg.keepAliveArgs()...)
	cmd.Env = wslEnv(nil)
	hideWindow(cmd)
	errs := &ringBuffer{max: 2048}
	cmd.Stderr = errs
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("wslbridge: start keep-alive for %q: %w", cfg.Distro, err)
	}
	return &execProcess{cmd: cmd, errs: errs}, nil
}

// execProcess adapts an exec.Cmd to KeepAliveProcess.
type execProcess struct {
	cmd  *exec.Cmd
	errs *ringBuffer
	once sync.Once
}

// Wait implements KeepAliveProcess.
func (p *execProcess) Wait() error {
	err := p.cmd.Wait()
	if err != nil {
		if msg := p.errs.String(); msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
	}
	return err
}

// Stop implements KeepAliveProcess.
func (p *execProcess) Stop() error {
	p.once.Do(func() {
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
	})
	return nil
}

// KeepAliveOptions configures the keep-alive agent.
type KeepAliveOptions struct {
	// Config names the distro and the wsl.exe to run.
	Config Config

	// Spawner starts each holder. Zero means WSLKeepAliveSpawner.
	Spawner KeepAliveSpawner

	// MinBackoff, MaxBackoff and ResetAfter tune the restart supervisor. Zero
	// values mean the DefaultKeepAlive* constants.
	MinBackoff time.Duration
	MaxBackoff time.Duration
	ResetAfter time.Duration

	// Sleep waits for d or until ctx is done, returning ctx.Err() if it was.
	// Zero means a real timer; tests substitute a recorder so the backoff
	// sequence can be asserted without spending it.
	Sleep func(ctx context.Context, d time.Duration) error

	// Logger receives restart diagnostics. Zero means Config.Logger.
	Logger *slog.Logger
}

// withDefaults fills in the zero values.
func (o KeepAliveOptions) withDefaults() KeepAliveOptions {
	o.Config = o.Config.WithDefaults()
	if o.Spawner == nil {
		o.Spawner = WSLKeepAliveSpawner{}
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = DefaultKeepAliveMinBackoff
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = DefaultKeepAliveMaxBackoff
	}
	if o.MaxBackoff < o.MinBackoff {
		o.MaxBackoff = o.MinBackoff
	}
	if o.ResetAfter <= 0 {
		o.ResetAfter = DefaultKeepAliveResetAfter
	}
	if o.Sleep == nil {
		o.Sleep = sleepContext
	}
	if o.Logger == nil {
		o.Logger = o.Config.Logger
	}
	return o
}

// sleepContext waits for d or until ctx is done.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// KeepAlive holds a WSL distro open by keeping a Windows-side child attached to
// it, restarting that child with exponential backoff whenever it dies.
//
// It is safe for concurrent use.
type KeepAlive struct {
	opts   KeepAliveOptions
	cancel context.CancelFunc
	done   chan struct{}

	mu          sync.Mutex
	proc        KeepAliveProcess
	alive       bool
	released    bool
	closed      bool
	restarts    int
	lastRestart time.Time
	lastErr     error
	resume      chan struct{}
}

// StartKeepAlive holds the named distro open until the returned KeepAlive is
// released or closed.
func StartKeepAlive(ctx context.Context, distro string) (*KeepAlive, error) {
	return StartKeepAliveWith(ctx, KeepAliveOptions{Config: Config{Distro: distro}})
}

// StartKeepAliveWith is StartKeepAlive with a full set of options.
//
// It returns as soon as the supervisor is running, without waiting for the first
// holder to start: a distro that is slow to boot must not block the bridge from
// serving its pipe, and Alive reports the real state.
func StartKeepAliveWith(ctx context.Context, opts KeepAliveOptions) (*KeepAlive, error) {
	opts = opts.withDefaults()
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	k := &KeepAlive{
		opts:   opts,
		cancel: cancel,
		done:   make(chan struct{}),
		resume: make(chan struct{}, 1),
	}
	// The caller's context still governs: cancelling it closes the agent, but
	// the supervisor's own context outlives a request-scoped one so a keep-alive
	// started during a dial is not torn down when that dial completes.
	go func() {
		select {
		case <-ctx.Done():
			_ = k.Close()
		case <-k.done:
		}
	}()
	go k.supervise(runCtx)
	return k, nil
}

// supervise runs one holder at a time, restarting it with backoff.
func (k *KeepAlive) supervise(ctx context.Context) {
	defer close(k.done)
	backoff := k.opts.MinBackoff

	for {
		if ctx.Err() != nil {
			return
		}
		if k.isReleased() {
			// The hold was dropped. Park until Hold or Close.
			select {
			case <-ctx.Done():
				return
			case <-k.resume:
				backoff = k.opts.MinBackoff
				continue
			}
		}

		proc, err := k.opts.Spawner.Spawn(ctx, k.opts.Config)
		if err != nil {
			k.recordFailure(err)
			k.opts.Logger.Warn("wslbridge: keep-alive failed to start",
				"distro", k.opts.Config.Distro, "error", err, "retry_in", backoff)
			if serr := k.opts.Sleep(ctx, backoff); serr != nil {
				return
			}
			backoff = nextBackoff(backoff, k.opts.MaxBackoff)
			continue
		}

		started := time.Now()
		k.mu.Lock()
		stale := k.closed || k.released
		if !stale {
			k.proc = proc
			k.alive = true
			k.restarts++
			k.lastRestart = started
			k.lastErr = nil
		}
		k.mu.Unlock()
		if stale {
			_ = proc.Stop()
			_ = proc.Wait()
			continue
		}

		waitErr := proc.Wait()

		k.mu.Lock()
		k.alive = false
		k.proc = nil
		k.lastErr = waitErr
		closed, released := k.closed, k.released
		k.mu.Unlock()

		if ctx.Err() != nil || closed {
			return
		}
		if released {
			continue
		}
		if time.Since(started) >= k.opts.ResetAfter {
			backoff = k.opts.MinBackoff
		}
		k.opts.Logger.Warn("wslbridge: keep-alive holder exited, restarting",
			"distro", k.opts.Config.Distro, "lived", time.Since(started).Round(time.Millisecond),
			"error", waitErr, "retry_in", backoff)
		if err := k.opts.Sleep(ctx, backoff); err != nil {
			return
		}
		backoff = nextBackoff(backoff, k.opts.MaxBackoff)
	}
}

// nextBackoff doubles d, capped at max.
func nextBackoff(d, max time.Duration) time.Duration {
	d *= 2
	if d > max {
		d = max
	}
	return d
}

// recordFailure notes a spawn failure.
func (k *KeepAlive) recordFailure(err error) {
	k.mu.Lock()
	k.alive = false
	k.lastErr = err
	k.mu.Unlock()
}

// isReleased reports whether the hold is currently dropped.
func (k *KeepAlive) isReleased() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.released && !k.closed
}

// Alive reports whether a holder is running right now.
func (k *KeepAlive) Alive() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.alive
}

// LastRestart reports when the current holder started. It is the zero time until
// the first one does, and it moves on every restart, so a caller can tell a
// stable distro from one that is flapping.
func (k *KeepAlive) LastRestart() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.lastRestart
}

// Restarts reports how many holders have been started, including the first.
func (k *KeepAlive) Restarts() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.restarts
}

// Err reports why the last holder ended, or why it could not be started.
func (k *KeepAlive) Err() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.lastErr
}

// Released reports whether the hold is currently dropped.
func (k *KeepAlive) Released() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.released
}

// Release drops the hold so WSL can reclaim the VM, without shutting the agent
// down. This is what the engine's idle-exit signal triggers: the distro goes
// away, its memory comes back to Windows, and the next Hold brings it back.
//
// Release is idempotent.
func (k *KeepAlive) Release() {
	k.mu.Lock()
	if k.released || k.closed {
		k.mu.Unlock()
		return
	}
	k.released = true
	proc := k.proc
	k.proc = nil
	k.mu.Unlock()

	k.opts.Logger.Info("wslbridge: keep-alive released", "distro", k.opts.Config.Distro)
	if proc != nil {
		_ = proc.Stop()
	}
}

// Hold re-acquires a hold that Release dropped. It is idempotent, and an error
// only when the agent has been closed.
func (k *KeepAlive) Hold(ctx context.Context) error {
	k.mu.Lock()
	if k.closed {
		k.mu.Unlock()
		return errors.New("wslbridge: keep-alive is closed")
	}
	if !k.released {
		k.mu.Unlock()
		return nil
	}
	k.released = false
	k.mu.Unlock()

	k.opts.Logger.Info("wslbridge: keep-alive re-acquired", "distro", k.opts.Config.Distro)
	select {
	case k.resume <- struct{}{}:
	default:
	}
	return nil
}

// Close stops the agent permanently and waits for its holder to exit.
func (k *KeepAlive) Close() error {
	k.mu.Lock()
	if k.closed {
		k.mu.Unlock()
		<-k.done
		return nil
	}
	k.closed = true
	proc := k.proc
	k.proc = nil
	k.mu.Unlock()

	if proc != nil {
		_ = proc.Stop()
	}
	k.cancel()
	select {
	case k.resume <- struct{}{}:
	default:
	}
	<-k.done
	return nil
}
