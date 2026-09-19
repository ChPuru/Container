//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/rahuldhali/hull/internal/cli"
)

// installEngineController gives "hull engine start|stop|restart" something to
// drive off Windows.
//
// On Linux the engine is an ordinary daemon rather than something behind a WSL
// boundary, so the controller drives whatever init is present instead of
// reimplementing process supervision. When there is no systemd — an engine
// distro started by hull-boot, a container, a bare chroot — it says so and
// names the command that does work, because a start that silently did nothing
// would be worse than an honest refusal.
func installEngineController() {
	cli.SetEngineController(&systemdEngine{unit: "hulld"})
}

// systemdEngine drives hulld through systemctl.
type systemdEngine struct{ unit string }

// Describe names what this controller drives.
func (e *systemdEngine) Describe() string { return "systemd unit " + e.unit }

// Start brings hulld up.
func (e *systemdEngine) Start(ctx context.Context) error { return e.run(ctx, "start") }

// Stop shuts hulld down.
func (e *systemdEngine) Stop(ctx context.Context) error { return e.run(ctx, "stop") }

// run invokes systemctl, translating a missing systemd into an explanation.
func (e *systemdEngine) run(ctx context.Context, verb string) error {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return fmt.Errorf("cannot %s the engine here: no systemctl on PATH.\n"+
			"       Inside hull's own engine distro the daemon is started by\n"+
			"       /usr/local/bin/hull-boot; elsewhere run hulld directly", verb)
	}
	cmd := exec.CommandContext(ctx, path, verb, e.unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("systemctl %s %s: %s", verb, e.unit, msg)
		}
		return fmt.Errorf("systemctl %s %s: %w", verb, e.unit, err)
	}
	return nil
}
