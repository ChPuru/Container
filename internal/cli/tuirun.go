package cli

import (
	"context"
	"errors"
	"strings"

	"github.com/ChPuru/hull/internal/client"
	"github.com/ChPuru/hull/internal/tui"
)

// runDashboard opens the terminal dashboard against one engine.
//
// The dashboard owns the terminal for its lifetime, so the CLI checks first
// that there is one: piping the dashboard somewhere is a mistake worth naming
// rather than a screen full of escape codes.
func runDashboard(ctx context.Context, env *Env, cli *client.Client, filter, tab string, noColor bool) error {
	if !env.StdinIsTerminal() || !env.StdoutIsTerminal() {
		return Errorf("the dashboard needs a terminal; use 'hull ps', 'hull logs' or 'hull events' in a pipe")
	}
	detail, err := parseDetailTab(tab)
	if err != nil {
		return err
	}
	opts := tui.Options{
		In:      env.In,
		Out:     env.Out,
		NoColor: noColor,
		Filter:  filter,
		Tab:     detail,
	}
	if err := tui.Run(ctx, cli, opts); err != nil {
		if errors.Is(err, tui.ErrNotTerminal) {
			return Errorf("the dashboard needs a terminal; use 'hull ps', 'hull logs' or 'hull events' in a pipe")
		}
		return err
	}
	return nil
}

// parseDetailTab maps the --tab value onto the dashboard's tab constants.
func parseDetailTab(name string) (tui.DetailTab, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "logs":
		return tui.TabLogs, nil
	case "stats":
		return tui.TabStats, nil
	case "inspect":
		return tui.TabInspect, nil
	case "ports":
		return tui.TabPorts, nil
	default:
		return tui.TabLogs, Errorf(`invalid --tab %q: want "logs", "stats", "inspect" or "ports"`, name)
	}
}
