package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/ChPuru/hull/internal/cli"
	"github.com/ChPuru/hull/internal/wslbridge"
)

// runHidden dispatches one of the plumbing subcommands and returns the process
// exit status.
//
// They are not part of the command tree on purpose: each is a long-lived
// process started by something other than a person — hull's own client starts
// the relay, and the Windows CLI starts the bridge — and giving them a place
// in help would invite someone to run one by hand and wonder why it never
// returns.
func runHidden(ctx context.Context, name string, args []string) int {
	ctx, stop := signal.NotifyContext(ctx, interruptSignals()...)
	defer stop()

	var err error
	switch name {
	case "__relay":
		err = runRelay(ctx, args)
	case "__bridge":
		err = runBridge(ctx, args)
	case "__keepalive":
		err = runKeepAlive(ctx, args)
	default:
		fmt.Fprintf(os.Stderr, "hull: unknown internal subcommand %q\n", name)
		return cli.ExitFailure
	}
	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "hull: %s: %v\n", name, err)
		return cli.ExitFailure
	}
	return cli.ExitOK
}

// runRelay is "hull __relay", the Linux end of the stdio transport.
//
// wsl.exe runs it inside the engine distro with the API socket's path; it
// reads multiplexed frames from stdin, connects each stream the Windows side
// opens to hulld, and copies bytes both ways. It exits when its stdin closes,
// which is what happens the moment hull.exe on Windows goes away.
func runRelay(ctx context.Context, args []string) error {
	fs := cli.NewFlagSet("hull __relay")
	fs.SetOutput(os.Stderr)
	socket := fs.String("socket", "", wslbridge.DefaultSocketPath, "hulld API socket to relay to")
	level := fs.String("log-level", "", "error", "Logging level")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return wslbridge.RunRelay(ctx, wslbridge.RelayOptions{
		Config: wslbridge.Config{
			SocketPath: *socket,
			Logger:     logger(*level),
		},
		In:  os.Stdin,
		Out: os.Stdout,
	})
}

// runBridge is "hull __bridge", the Windows end of the transport: it holds the
// engine distro open, picks a transport into it, serves hull's named pipe (and
// the docker_engine compatibility pipe when it is free) and relays bytes both
// ways until it is stopped.
func runBridge(ctx context.Context, args []string) error {
	fs := cli.NewFlagSet("hull __bridge")
	fs.SetOutput(os.Stderr)
	distro := fs.String("distro", "", "", "WSL distro holding the engine")
	socket := fs.String("socket", "", "", "hulld API socket inside the distro")
	pipe := fs.String("pipe", "", "", "Named pipe to serve")
	level := fs.String("log-level", "", "info", "Logging level")
	dockerPipe := fs.Bool("docker-pipe", "", true, "Also serve the docker_engine compatibility pipe when free")
	keepAlive := fs.Bool("keep-alive", "", true, "Hold the distro open for the life of the bridge")
	tcp := fs.Bool("tcp", "", false, "Allow the loopback TCP transport, guarded by a shared secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := wslbridge.Config{
		Distro:          *distro,
		SocketPath:      *socket,
		PipeName:        *pipe,
		ServeDockerPipe: *dockerPipe,
		KeepAlive:       *keepAlive,
		EnableTCP:       *tcp,
		Logger:          logger(*level),
	}
	return wslbridge.Run(ctx, cfg.WithDefaults())
}

// runKeepAlive is "hull __keepalive", the agent that stops WSL from tearing
// the engine distro down.
//
// WSL reclaims a distro about fifteen seconds after its last Windows-side
// client exits, so something on Windows has to stay attached. This is that
// something, split out from the bridge for the case where the engine is
// reached over TCP or from a sibling distro and no pipe is being served.
func runKeepAlive(ctx context.Context, args []string) error {
	fs := cli.NewFlagSet("hull __keepalive")
	fs.SetOutput(os.Stderr)
	distro := fs.String("distro", "", "", "WSL distro to hold open")
	level := fs.String("log-level", "", "info", "Logging level")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keep, err := wslbridge.StartKeepAliveWith(ctx, wslbridge.KeepAliveOptions{
		Config: wslbridge.Config{Distro: *distro, Logger: logger(*level)},
	})
	if err != nil {
		return err
	}
	defer func() { _ = keep.Close() }()
	<-ctx.Done()
	return nil
}
