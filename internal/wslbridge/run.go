package wslbridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// Control is a handle on a running bridge, handed to Config.OnStart. It exists
// for hull's scale-to-zero differentiator: when the engine reports that it has
// been idle long enough to exit, something on the Windows side has to let go of
// the distro, and the bridge is the only thing still holding it.
type Control struct {
	cfg       Config
	keep      *KeepAlive
	transport Transport

	// wake serialises Hold, so a burst of clients arriving at a released
	// bridge wakes the distro once and then queues behind it rather than
	// racing several hull-boot invocations into the same distro.
	wake sync.Mutex
}

// KeepAlive returns the bridge's keep-alive agent, or nil when the bridge was
// configured without one.
func (c *Control) KeepAlive() *KeepAlive { return c.keep }

// Transport returns the transport the bridge selected.
func (c *Control) Transport() Transport { return c.transport }

// Release drops every hold the bridge has on the distro, so WSL can reclaim the
// VM and give its memory back to Windows. The pipes stay served: the next
// client to connect brings everything back through Hold.
//
// Both holds have to go. The keep-alive holder is the obvious one; the stdio
// transport's relay child is the one that is easy to forget, and leaving it
// running means the VM is never reclaimed no matter what the keep-alive does.
func (c *Control) Release() {
	if c.keep != nil {
		c.keep.Release()
	}
	releaseTransport(c.transport)
	c.cfg.Logger.Info("wslbridge: released the engine distro", "distro", c.cfg.Distro)
}

// Hold re-acquires the distro and waits for the engine to answer again. It is
// cheap and idempotent when nothing was released.
func (c *Control) Hold(ctx context.Context) error {
	if c.keep == nil {
		return nil
	}
	if !c.keep.Released() {
		return nil
	}
	c.wake.Lock()
	defer c.wake.Unlock()
	if !c.keep.Released() {
		// Somebody else woke it while this caller waited for the lock.
		return nil
	}
	if err := c.keep.Hold(ctx); err != nil {
		return err
	}
	// The distro was torn down, so hulld went with it. Starting the engine
	// here rather than letting the first dial fail is what turns a wake-up
	// into a slow request instead of an error.
	if err := StartEngineWith(ctx, c.cfg); err != nil {
		return fmt.Errorf("wslbridge: wake the engine: %w", err)
	}
	return nil
}

// Released reports whether the distro is currently let go of.
func (c *Control) Released() bool {
	return c.keep != nil && c.keep.Released()
}

// Run is the `hull __bridge` entrypoint: it holds the engine distro open, picks
// a transport into it, serves the named pipes on Windows, and relays bytes both
// ways for the life of the context.
//
// The order matters. The keep-alive goes up first, because every later step runs
// wsl.exe and each of those would otherwise start and stop the distro on its
// own. The engine is started next, so the transport probe has something to
// answer it. The pipes come last, because a pipe that exists before the engine
// does turns "the engine is starting" into "connection refused" for whatever
// connects in between.
func Run(ctx context.Context, cfg Config) error {
	cfg = cfg.WithDefaults()

	if err := EnsureDistroWith(ctx, cfg); err != nil {
		return err
	}

	var keep *KeepAlive
	if cfg.KeepAlive {
		k, err := StartKeepAliveWith(ctx, KeepAliveOptions{Config: cfg})
		if err != nil {
			return err
		}
		keep = k
		defer func() { _ = keep.Close() }()
	}

	if err := StartEngineWith(ctx, cfg); err != nil {
		// Not fatal on its own: the engine may be reachable even though this
		// particular start attempt failed, and the transport probe is the real
		// test. A bridge that refuses to start here would be unfixable from the
		// CLI, since the CLI is what talks to it.
		cfg.Logger.Warn("wslbridge: could not start the engine", "distro", cfg.Distro, "error", err)
	}

	transport, err := SelectTransport(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeTransport(transport)

	control := &Control{cfg: cfg, keep: keep, transport: transport}

	listeners, err := listenPipes(cfg)
	if err != nil {
		return err
	}
	if cfg.OnStart != nil {
		cfg.OnStart(control)
	}
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg      sync.WaitGroup
		failure atomic.Pointer[error]
	)
	for _, l := range listeners {
		wg.Add(1)
		go func(l net.Listener) {
			defer wg.Done()
			defer cancel()
			if err := serve(ctx, cfg, l, control); err != nil {
				failure.CompareAndSwap(nil, &err)
			}
		}(l)
	}

	// Closing the listeners is what unblocks their Accept calls.
	<-ctx.Done()
	for _, l := range listeners {
		_ = l.Close()
	}
	wg.Wait()

	if p := failure.Load(); p != nil {
		return *p
	}
	return nil
}

// listenPipes opens hull's own pipe and, when configured and free, the
// docker_engine compatibility pipe.
func listenPipes(cfg Config) ([]net.Listener, error) {
	primary, err := ListenPipe(PipeConfig{
		Name:                 cfg.PipeName,
		RequireFirstInstance: true,
		Logger:               cfg.Logger,
	})
	if err != nil {
		if errors.Is(err, ErrPipeInUse) {
			return nil, fmt.Errorf("%w -- another hull bridge is already running", err)
		}
		return nil, err
	}
	listeners := []net.Listener{primary}
	cfg.Logger.Info("wslbridge: listening", "pipe", cfg.PipeName)

	if !cfg.ServeDockerPipe {
		return listeners, nil
	}
	docker, err := ListenPipe(PipeConfig{
		Name:                 cfg.DockerPipeName,
		RequireFirstInstance: true,
		Logger:               cfg.Logger,
	})
	switch {
	case err == nil:
		listeners = append(listeners, docker)
		cfg.Logger.Info("wslbridge: listening", "pipe", cfg.DockerPipeName,
			"note", "the stock docker CLI needs no DOCKER_HOST")
	case errors.Is(err, ErrPipeInUse):
		// Docker Desktop, or another engine, owns the name. That is not a
		// failure: hull's own pipe still works, and taking the name away from a
		// running Docker Desktop would be hostile.
		cfg.Logger.Info("wslbridge: docker compatibility pipe is owned by another process, skipping",
			"pipe", cfg.DockerPipeName,
			"use", "$env:DOCKER_HOST = 'npipe:////./pipe/hull_engine'")
	default:
		cfg.Logger.Warn("wslbridge: could not serve the docker compatibility pipe",
			"pipe", cfg.DockerPipeName, "error", err)
	}
	return listeners, nil
}

// serve accepts connections on one listener and relays each to the engine.
func serve(ctx context.Context, cfg Config, l net.Listener, control *Control) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("wslbridge: accept on %s: %w", l.Addr(), err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			bridgeConn(ctx, cfg, conn, control)
		}()
	}
}

// bridgeConn relays one client connection to the engine.
func bridgeConn(ctx context.Context, cfg Config, client net.Conn, control *Control) {
	// A client arriving after an idle release is the wake-up signal: bring the
	// distro and the engine back before dialling, so the request is merely slow
	// rather than refused.
	if control.Released() {
		if err := control.Hold(ctx); err != nil {
			cfg.Logger.Warn("wslbridge: could not wake the engine", "error", err)
		}
	}
	engine, err := dialWithRetry(ctx, control.transport, cfg)
	if err != nil {
		cfg.Logger.Warn("wslbridge: could not reach the engine", "error", err)
		_ = client.Close()
		return
	}
	if err := proxy(ctx, client, engine); err != nil {
		cfg.Logger.Debug("wslbridge: connection ended", "error", err)
	}
}
