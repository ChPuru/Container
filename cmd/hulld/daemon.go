package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/ChPuru/hull/internal/api"
	"github.com/ChPuru/hull/internal/engine"
	"github.com/ChPuru/hull/internal/events"
	"github.com/ChPuru/hull/internal/types"
)

// daemon is one hulld process: an engine, an API server and the listeners it
// is served on.
type daemon struct {
	// opts is the resolved command line.
	opts *options
	// log receives the daemon's own diagnostics.
	log *slog.Logger
}

// listenerResult is one listener goroutine's outcome.
type listenerResult struct {
	// name identifies the listener in a log line.
	name string
	// err is nil for a clean drain.
	err error
}

// run builds the engine, serves the API on every configured listener and
// blocks until a signal, an idle timeout or a listener failure ends it.
//
// The shutdown path is deliberately narrow: drain the API, close the engine,
// remove the pid file. It never stops a container. Containers are supervised
// by shims reparented to PID 1 and are expected to outlive this process; a
// daemon that killed them on SIGTERM would make every hulld upgrade an outage.
func (d *daemon) run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stopSignals := d.watchSignals(cancel)
	defer stopSignals()

	switch {
	case d.opts.shim == "":
		d.log.Warn("hulld: no hull-shim binary found; containers cannot be started until --shim names one")
	case !fileExists(d.opts.shim):
		d.log.Warn("hulld: the named hull-shim binary does not exist", "path", d.opts.shim)
	}

	// The pid file goes down before the engine comes up and is removed after
	// it closes, so a supervisor reading it always sees a pid that owns the
	// data root for the whole window in which it does.
	removePID := d.writePIDFile()
	defer removePID()

	eng, err := engine.New(ctx, engine.Config{
		DataRoot:      d.opts.dataRoot,
		RuntimeName:   d.opts.runtimeName,
		RuntimeBinary: d.opts.runtimeBinary,
		ShimBinary:    d.opts.shim,
		InitBinary:    d.opts.initBinary,
		DefaultPool:   d.opts.defaultPool,
		IdleFreeze:    d.opts.idleFreeze,
		IdleExit:      d.opts.idleExit,
		Logger:        d.log,
	})
	if err != nil {
		return fmt.Errorf("start the engine: %w", err)
	}
	defer d.closeEngine(eng)

	if info, ierr := eng.Info(ctx); ierr == nil {
		d.log.Info("hulld: engine ready",
			"version", info.ServerVersion, "runtime", info.DefaultRuntime,
			"runtimeVersion", info.RuntimeVersion, "ociVersion", info.OCIVersion,
			"storage", info.Driver, "cgroups", info.CgroupVersion,
			"delegated", info.CgroupV2Delegated, "kernel", info.KernelVersion,
			"dataRoot", info.DataRoot)
		// The host warnings are the difference between "resource limits are
		// off" and "resource limits are silently off", so they go out at
		// startup as well as on /info and on every container create.
		for _, w := range info.Warnings {
			d.log.Warn("hulld: " + w)
		}
	} else {
		d.log.Warn("hulld: could not read the host report", "err", ierr)
	}

	// Version and MinVersion are left at their defaults on purpose: the api
	// package owns the range it serves, and a daemon flag that could disagree
	// with it would only ever be a way to break the client handshake.
	srv, err := api.New(eng, api.Options{
		CORS:         d.opts.cors,
		AccessLog:    d.opts.accessLog,
		Debug:        d.opts.debug,
		Logger:       d.log,
		BuildKitAddr: d.opts.buildKitAddr,
		DataRoot:     eng.DataRoot(),
	})
	if err != nil {
		return fmt.Errorf("build the API server: %w", err)
	}

	if d.opts.idleFreeze > 0 || d.opts.idleExit > 0 {
		go eng.IdleWatcher(ctx)
	}
	if d.opts.idleExit > 0 {
		go d.watchIdle(ctx, eng, cancel)
	}

	results := make(chan listenerResult, 3)
	var started int
	launch := func(name string, fn func() error) {
		started++
		go func() { results <- listenerResult{name: name, err: fn()} }()
	}

	mode := os.FileMode(d.opts.socketMode)
	if d.opts.socket != "" {
		path := d.opts.socket
		launch("unix:"+path, func() error { return srv.ServeUnix(ctx, path, mode) })
	}
	if d.opts.sharedSocket != "" {
		path := d.opts.sharedSocket
		launch("shared:"+path, func() error { return srv.ServeUnix(ctx, path, mode) })
	}
	if d.opts.tcp != "" {
		addr, token := d.opts.tcp, d.opts.tcpToken
		launch("tcp:"+addr, func() error { return srv.ServeTCP(ctx, addr, token) })
	}

	// The first listener that fails takes the daemon down: half a daemon —
	// reachable from Windows but not from the shared socket, say — is a worse
	// outcome than a clean failure the supervisor can restart.
	var fatal error
	select {
	case res := <-results:
		started--
		if res.err != nil {
			fatal = fmt.Errorf("listener %s: %w", res.name, res.err)
			d.log.Error("hulld: a listener failed", "listener", res.name, "err", res.err)
		}
		cancel()
	case <-ctx.Done():
		d.log.Info("hulld: draining")
	}

	drainDeadline := time.After(closeTimeout)
	for started > 0 {
		select {
		case res := <-results:
			started--
			if res.err != nil && fatal == nil {
				fatal = fmt.Errorf("listener %s: %w", res.name, res.err)
			}
		case <-drainDeadline:
			d.log.Warn("hulld: a listener did not drain in time; leaving it behind",
				"remaining", started)
			started = 0
		}
	}
	return fatal
}

// watchSignals cancels the daemon on the first shutdown signal and exits hard
// on the second.
//
// The second signal matters: a drain waits on in-flight API requests, and an
// operator who has decided the daemon must go now should not have to find its
// pid. Exiting without running the deferred cleanup is safe here for the same
// reason the whole design is safe — containers belong to their shims, and the
// state store is crash-consistent by construction.
func (d *daemon) watchSignals(cancel context.CancelFunc) func() {
	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, shutdownSignals()...)
	done := make(chan struct{})
	go func() {
		for first := true; ; {
			select {
			case sig := <-sigc:
				if first {
					first = false
					d.log.Info("hulld: shutting down; running containers are left alone",
						"signal", sig.String())
					cancel()
					continue
				}
				d.log.Warn("hulld: second signal, exiting immediately", "signal", sig.String())
				os.Exit(exitFailure)
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(sigc)
		close(done)
	}
}

// watchIdle ends the daemon when the engine reports that everything has been
// idle for --idle-exit.
//
// This is hull's scale-to-zero: with no daemon and no client, WSL tears the
// engine distro down and the VM gives its memory back to Windows, which is
// something Docker Desktop's resource saver does not actually do. The
// containers that were running are frozen, not killed, and the next API call
// through the Windows relay starts the distro and this daemon again.
func (d *daemon) watchIdle(ctx context.Context, eng *engine.Engine, cancel context.CancelFunc) {
	ch, unsubscribe := eng.Events().Subscribe(ctx, events.Filter{
		Types:   []string{events.TypeDaemon},
		Actions: []string{"idle"},
	}, time.Time{}, time.Time{})
	defer unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			d.log.Info("hulld: idle, shutting down so WSL can reclaim the VM",
				"after", d.opts.idleExit.String(), "containers", eventAttr(ev, "containers"))
			cancel()
			return
		}
	}
}

// eventAttr reads one attribute off an event, returning "" when it is absent.
func eventAttr(ev types.Event, key string) string { return ev.Actor.Attributes[key] }

// closeEngine shuts the engine down on a context of its own.
//
// It cannot reuse the daemon's context: that one is already cancelled by the
// time this runs, and Close has real work to do — detaching from every shim,
// stopping the network manager's proxies and DNS, flushing and unlocking the
// state store.
func (d *daemon) closeEngine(eng *engine.Engine) {
	ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
	defer cancel()
	if err := eng.Close(ctx); err != nil && !errors.Is(err, context.Canceled) {
		d.log.Error("hulld: the engine did not shut down cleanly", "err", err)
		return
	}
	d.log.Info("hulld: engine closed; containers keep running under their shims")
}

// writePIDFile records this process's pid next to the socket and returns the
// function that removes it.
//
// It is advisory only. The authority on "is another daemon running" is the
// exclusive lock the state store takes on the data root, which is held by the
// kernel and therefore cannot go stale after a crash the way a pid file can.
func (d *daemon) writePIDFile() func() {
	path := filepath.Join(d.opts.dataRoot, filepath.FromSlash(defaultPIDName))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		d.log.Warn("hulld: could not create the run directory", "path", filepath.Dir(path), "err", err)
		return func() {}
	}
	pid := strconv.Itoa(os.Getpid()) + "\n"
	if err := os.WriteFile(path, []byte(pid), 0o644); err != nil {
		d.log.Warn("hulld: could not write the pid file", "path", path, "err", err)
		return func() {}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			// Only remove the file if it is still ours: a supervisor that
			// restarted hulld quickly may already have replaced it.
			if data, err := os.ReadFile(path); err == nil && string(data) != pid {
				return
			}
			_ = os.Remove(path)
		})
	}
}
