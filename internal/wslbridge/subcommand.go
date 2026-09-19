package wslbridge

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// The two hidden subcommands live here rather than in cmd/hull for one reason:
// Config.relayArgs builds the exact command line that RelayMain has to parse,
// and the two would drift the moment they lived in different packages. A drift
// there is invisible until a user's first docker command, because the relay is
// spawned inside WSL where nothing is watching its stderr.
//
// Both build everywhere. RelayMain runs inside the engine distro, on Linux;
// BridgeMain runs on Windows and returns ErrUnsupportedPlatform elsewhere, from
// ListenPipe, which is exactly what a Linux developer running it should see.

// RelayMain is the `hull __relay` entrypoint, run inside the engine distro by
// the stdio transport's wsl.exe child. It reads multiplexed frames from stdin,
// writes them to stdout, and connects each stream to hulld's API socket.
//
// args is the argument list after the subcommand itself.
func RelayMain(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet(RelaySubcommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", DefaultSocketPath, "hulld API socket to connect each stream to")
	window := fs.Int("window", DefaultWindow, "per-stream receive window in bytes")
	verbose := fs.Bool("verbose", false, "log every stream to stderr")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("wslbridge: %s: %w", RelaySubcommand, err)
	}
	if rest := fs.Args(); len(rest) > 0 {
		return fmt.Errorf("wslbridge: %s: unexpected argument %q", RelaySubcommand, rest[0])
	}

	cfg := Config{SocketPath: *socket, Window: *window}
	if *verbose {
		cfg.Logger = stderrLogger()
	}
	return RunRelay(ctx, RelayOptions{Config: cfg})
}

// BridgeConfigFromArgs parses the `hull __bridge` flag set into a Config. It is
// separate from BridgeMain so the flag surface can be tested without serving a
// named pipe.
func BridgeConfigFromArgs(args []string) (Config, error) {
	fs := flag.NewFlagSet(BridgeSubcommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	distro := fs.String("distro", "", "WSL distro holding the engine (default $"+EnvDistro+", then "+DefaultDistro+")")
	socket := fs.String("socket", DefaultSocketPath, "hulld API socket inside the distro")
	pipe := fs.String("pipe", DefaultPipeName, "named pipe to serve")
	dockerPipe := fs.Bool("docker-pipe", true, "also serve "+DockerPipeName+" when it is free")
	keepAlive := fs.Bool("keep-alive", true, "hold the distro open with a long-lived wsl.exe child")
	enableVsock := fs.Bool("vsock", false, "also probe the opportunistic AF_HYPERV transport")
	enableTCP := fs.Bool("tcp", false, "also probe the loopback TCP transport (needs a shared secret)")
	verbose := fs.Bool("verbose", false, "log transport selection and every connection to stderr")
	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("wslbridge: %s: %w", BridgeSubcommand, err)
	}
	if rest := fs.Args(); len(rest) > 0 {
		return Config{}, fmt.Errorf("wslbridge: %s: unexpected argument %q", BridgeSubcommand, rest[0])
	}

	cfg := Config{
		Distro:          *distro,
		SocketPath:      *socket,
		PipeName:        *pipe,
		ServeDockerPipe: *dockerPipe,
		KeepAlive:       *keepAlive,
		EnableVsock:     *enableVsock,
		EnableTCP:       *enableTCP,
	}
	if *verbose {
		cfg.Logger = stderrLogger()
	}
	return cfg.WithDefaults(), nil
}

// BridgeMain is the `hull __bridge` entrypoint: it parses the bridge's flags and
// runs the bridge until the context is cancelled.
func BridgeMain(ctx context.Context, args []string) error {
	cfg, err := BridgeConfigFromArgs(args)
	if err != nil {
		return err
	}
	return Run(ctx, cfg)
}

// stderrLogger is the logger the hidden subcommands use with -verbose. It writes
// to standard error deliberately: the relay's standard output carries the frame
// stream, and a single log line written there would desynchronise the wire.
func stderrLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(stderrWriter(), &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// DescribeConfig renders the settings that decide how hull reaches the engine,
// for `hull doctor` and for the bridge's own startup line.
func DescribeConfig(cfg Config) string {
	cfg = cfg.WithDefaults()
	var b strings.Builder
	fmt.Fprintf(&b, "distro=%s socket=%s pipe=%s", cfg.Distro, cfg.SocketPath, cfg.PipeName)
	if cfg.ServeDockerPipe {
		fmt.Fprintf(&b, " docker-pipe=%s", cfg.DockerPipeName)
	}
	fmt.Fprintf(&b, " keep-alive=%t transports=%s", cfg.KeepAlive, strings.Join(enabledTransports(cfg), ","))
	return b.String()
}

// enabledTransports names the transports a configuration would probe, in order.
func enabledTransports(cfg Config) []string {
	var names []string
	for _, name := range TransportOrder {
		switch name {
		case "vsock":
			if !cfg.EnableVsock {
				continue
			}
		case "tcp":
			if !cfg.EnableTCP {
				continue
			}
		}
		names = append(names, name)
	}
	return names
}
