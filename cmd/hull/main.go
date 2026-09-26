// Command hull is hull's command-line interface.
//
// It builds for both Linux and Windows. On Windows it also carries the two
// hidden subcommands the relay needs — "hull __bridge", which serves the named
// pipe and holds the engine distro open, and "hull __keepalive", which holds
// the distro alone — and on Linux it carries "hull __relay", the process
// wsl.exe runs inside the engine distro to bridge stdio onto hulld's socket.
//
// Those three are spelled with a leading double underscore so they can never
// collide with a real verb, and they are absent from help for the same reason
// a user never types them.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ChPuru/hull/internal/cli"
)

func main() {
	args := os.Args[1:]

	// The hidden subcommands are dispatched before the command tree, because
	// they are not commands: they are long-lived plumbing processes with their
	// own flag sets, and one of them is started by hull's own client.
	if len(args) > 0 && strings.HasPrefix(args[0], "__") {
		os.Exit(runHidden(context.Background(), args[0], args[1:]))
	}

	// The global options are parsed here as well as inside the CLI so that
	// logging is configured before the first line any command can log. A bad
	// flag is left for the CLI to report, with the command's own context.
	if g, _, err := cli.ParseGlobal(args); err == nil {
		configureLogging(g.LogLevel, g.Debug)
	}

	installEngineController()

	env := cli.NewEnv(os.Stdin, os.Stdout, os.Stderr)
	os.Exit(env.ReportError(cli.Run(context.Background(), env, args)))
}

// configureLogging points the default slog logger at stderr at the requested
// level. hull's own diagnostics go through the CLI's Debugf and Warnf, so this
// only governs what the packages beneath it log.
func configureLogging(level string, debug bool) {
	lvl := slog.LevelWarn
	if debug {
		lvl = slog.LevelDebug
	}
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	case "":
	default:
		fmt.Fprintf(os.Stderr, "hull: unknown --log-level %q, using warn\n", level)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
}

// logger builds a logger for the hidden plumbing subcommands, which log to
// stderr because they have no other output.
func logger(level string) *slog.Logger {
	configureLogging(level, false)
	return slog.Default()
}
