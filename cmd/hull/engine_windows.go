//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/ChPuru/hull/internal/cli"
	"github.com/ChPuru/hull/internal/wslbridge"
)

// installEngineController gives "hull engine start|stop|restart" something to
// drive on Windows.
//
// The CLI package cannot do this itself: starting the engine means registering
// intent with WSL, booting hulld inside the distro and putting a bridge on the
// named pipe, and none of that belongs in a package that also has to compile
// for a Linux client.
func installEngineController() {
	cli.SetEngineController(&windowsEngine{cfg: wslbridge.DefaultConfig()})
}

// windowsEngine starts and stops the engine distro and the bridge in front of
// it.
type windowsEngine struct{ cfg wslbridge.Config }

// Describe names what this controller drives.
func (e *windowsEngine) Describe() string {
	return "WSL distro " + e.cfg.Distro + " via " + e.cfg.PipeName
}

// Start brings the engine up and leaves a bridge serving the named pipe.
//
// The order is the same one the bridge itself uses and for the same reason:
// the distro has to exist before anything can run in it, hulld has to be up
// before a pipe that promises to reach it is offered, and the bridge is what
// holds the distro open once this process exits.
func (e *windowsEngine) Start(ctx context.Context) error {
	if err := wslbridge.EnsureDistroWith(ctx, e.cfg); err != nil {
		return err
	}
	if err := wslbridge.StartEngineWith(ctx, e.cfg); err != nil {
		return err
	}
	if bridgeIsServing(ctx, e.cfg) {
		return nil
	}
	if err := spawnBridge(e.cfg); err != nil {
		return err
	}
	// The bridge creates its pipe after it has picked a transport, so a
	// caller that returns immediately would hand back an address nothing is
	// listening on yet.
	return waitForBridge(ctx, e.cfg, 30*time.Second)
}

// Stop shuts the engine down by terminating its distro.
//
// Terminating the distro rather than signalling hulld is deliberate: WSL will
// reclaim the VM anyway once the last Windows-side client goes, and a
// half-stopped engine whose distro is still resident is the state that
// produces the confusing bug reports.
func (e *windowsEngine) Stop(ctx context.Context) error {
	cfg := e.cfg.WithDefaults()
	if _, err := cfg.Runner.Run(ctx, cfg.WSLPath, "--terminate", cfg.Distro); err != nil {
		return fmt.Errorf("stopping the engine distro %q: %w", cfg.Distro, err)
	}
	return nil
}

// bridgeIsServing reports whether something already answers on hull's pipe.
func bridgeIsServing(ctx context.Context, cfg wslbridge.Config) bool {
	cfg = cfg.WithDefaults()
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := wslbridge.DialPipe(dialCtx, cfg.PipeName)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// waitForBridge polls the pipe until it answers or the deadline passes.
func waitForBridge(ctx context.Context, cfg wslbridge.Config, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if bridgeIsServing(ctx, cfg) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the bridge did not start serving %s within %s; run 'hull __bridge --log-level debug' to see why",
				cfg.WithDefaults().PipeName, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// spawnBridge starts "hull __bridge" as a detached child.
//
// It has to outlive this process — the whole point is a resident agent — so it
// is put in its own process group with no console of its own, and its streams
// are detached rather than inherited so the terminal that started it can close.
func spawnBridge(cfg wslbridge.Config) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating the hull binary: %w", err)
	}
	cfg = cfg.WithDefaults()
	cmd := exec.Command(self, wslbridge.BridgeSubcommand,
		"--distro", cfg.Distro,
		"--socket", cfg.SocketPath,
		"--pipe", cfg.PipeName,
	)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow | detachedProcess,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting the bridge: %w", err)
	}
	// Releasing the child stops this process from being its reaper, which it
	// will not be around long enough to do.
	return cmd.Process.Release()
}

// The Windows creation flags that make a child survive its parent without a
// console. They are spelled out rather than imported because x/sys/windows is
// not on hull's dependency list.
const (
	// createNoWindow gives the child no console window of its own.
	createNoWindow = 0x08000000
	// detachedProcess stops the child inheriting this process's console, so
	// closing the terminal does not take the bridge with it.
	detachedProcess = 0x00000008
)
