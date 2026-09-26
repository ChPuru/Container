package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ChPuru/hull/internal/client"
)

// newRunCommand builds "hull run".
func newRunCommand() *Command {
	o := &runOptions{}
	return &Command{
		Name:  "run",
		Usage: "run [OPTIONS] IMAGE [COMMAND] [ARG...]",
		Short: "Create and run a new container from an image",
		Long: "Create and run a new container from an image.\n\n" +
			"The image is pulled when it is not present locally, unless --pull=never.\n" +
			"With -it the local terminal is put into raw mode and restored on every\n" +
			"exit path, including a panic, and window resizes are forwarded to the\n" +
			"container as they happen.",
		Example: "  hull run --rm alpine echo hello\n" +
			"  hull run -d --name web -p 8080:80 nginx\n" +
			"  hull run -it --rm -v .:/src -w /src golang:1.26 sh",
		StopAtOperand: true,
		MinArgs:       1,
		MaxArgs:       -1,
		Flags:         func(fs *FlagSet) { registerRunFlags(fs, o, true) },
		Run: func(ctx context.Context, env *Env, fs *FlagSet, args []string) error {
			return runRun(ctx, env, fs, o, args)
		},
	}
}

// newCreateCommand builds "hull create".
func newCreateCommand() *Command {
	o := &runOptions{}
	return &Command{
		Name:          "create",
		Usage:         "create [OPTIONS] IMAGE [COMMAND] [ARG...]",
		Short:         "Create a new container without starting it",
		StopAtOperand: true,
		MinArgs:       1,
		MaxArgs:       -1,
		Flags:         func(fs *FlagSet) { registerRunFlags(fs, o, false) },
		Run: func(ctx context.Context, env *Env, fs *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			id, err := createContainer(ctx, env, cli, o, args[0], args[1:])
			if err != nil {
				return err
			}
			env.Println(id)
			return nil
		},
	}
}

// runRun is "hull run": create, optionally attach, start, and then either
// print the id or follow the container to its exit code.
func runRun(ctx context.Context, env *Env, _ *FlagSet, o *runOptions, args []string) error {
	if o.detach && (o.interactive || o.tty) && len(o.attach) > 0 {
		return Errorf("conflicting options: --detach cannot be combined with --attach")
	}
	cli, err := env.Client(ctx)
	if err != nil {
		return err
	}
	id, err := createContainer(ctx, env, cli, o, args[0], args[1:])
	if err != nil {
		return err
	}

	if o.detach {
		if err := cli.ContainerStart(ctx, id, o.detachKeys); err != nil {
			return StartFailure(err)
		}
		env.Println(id)
		return nil
	}

	code, err := attachRunAndWait(ctx, env, cli, id, o)
	if err != nil {
		return err
	}
	if o.autoRemove {
		// The engine removes the container itself; this only waits for it to
		// be gone so a follow-up command does not race the removal.
		_, _ = cli.ContainerWait(ctx, id, client.WaitConditionRemoved)
	}
	if code != 0 {
		return &ExitError{Code: code}
	}
	return nil
}

// createContainer creates the container, pulling the image first when the
// policy asks for it or when the engine says it does not have it.
func createContainer(ctx context.Context, env *Env, cli *client.Client, o *runOptions, image string, cmd []string) (string, error) {
	policy, err := pullPolicy(o.pull)
	if err != nil {
		return "", err
	}
	req, err := o.buildCreateRequest(env, image, cmd)
	if err != nil {
		return "", err
	}
	if policy == "always" {
		if err := pullImage(ctx, env, cli, image, o.platform, false); err != nil {
			return "", err
		}
	}
	resp, err := cli.ContainerCreate(ctx, o.name, o.platform, req)
	if err != nil && client.IsNotFound(err) && policy != "never" {
		env.Printf("Unable to find image '%s' locally\n", image)
		if perr := pullImage(ctx, env, cli, image, o.platform, false); perr != nil {
			return "", perr
		}
		resp, err = cli.ContainerCreate(ctx, o.name, o.platform, req)
	}
	if err != nil {
		return "", err
	}
	// The engine reports here that a limit it was asked for cannot be
	// enforced on this host. Dropping these would leave the user with a
	// silently unlimited container.
	env.ShowWarnings(resp.Warnings)
	if o.idleFreeze != 0 {
		if err := cli.SetIdleFreeze(ctx, resp.ID, o.idleFreeze); err != nil && !client.IsNotImplemented(err) {
			env.Warnf("could not set --idle-freeze: %v", err)
		}
	}
	return resp.ID, nil
}

// attachRunAndWait attaches to the container, starts it, streams until the
// stream ends, and reports the exit code.
//
// The order matters: the attach has to be in place before the container is
// started, or the first lines of output are lost.
func attachRunAndWait(ctx context.Context, env *Env, cli *client.Client, id string, o *runOptions) (int, error) {
	wantStdin := o.interactive
	attachOpts := client.ContainerAttachOptions{
		Stream:     true,
		Stdin:      wantStdin,
		Stdout:     true,
		Stderr:     !o.tty,
		DetachKeys: o.detachKeys,
		TTY:        o.tty,
	}
	stream, err := cli.ContainerAttach(ctx, id, attachOpts)
	if err != nil {
		return 0, err
	}
	defer func() { _ = stream.Close() }()

	if err := cli.ContainerStart(ctx, id, o.detachKeys); err != nil {
		// A command the image does not have, or cannot run, is the shell's
		// 127 or 126 rather than hull's 125 — the distinction a script
		// branches on.
		return 0, StartFailure(err)
	}

	// Without a TTY the local terminal stays cooked, so Ctrl-C raises SIGINT
	// in the CLI instead of reaching the container. Forwarding it is what
	// makes "hull run alpine sleep 100" stoppable; without it the CLI dies
	// and the container keeps running.
	if o.sigProxy && !o.tty {
		stopProxy := proxySignals(ctx, env, cli, id)
		defer stopProxy()
	}

	if err := pumpStream(ctx, env, cli, id, "", stream, wantStdin, o.tty); err != nil {
		return 0, err
	}
	res, err := cli.ContainerWait(ctx, id, client.WaitConditionNotRunning)
	if err != nil {
		// A container removed by --rm before the wait landed is not a
		// failure; there is simply nothing left to ask about.
		if client.IsNotFound(err) {
			return 0, nil
		}
		return 0, err
	}
	if res.Error != nil && res.Error.Message != "" {
		return int(res.StatusCode), Errorf("%s", res.Error.Message)
	}
	return int(res.StatusCode), nil
}

// pumpStream wires the local terminal to a hijacked stream and blocks until
// the stream ends.
//
// With a TTY the terminal goes into raw mode for the duration and is restored
// on every exit path — a normal end, an error, a signal, or a panic — and
// window changes are forwarded to the container or the exec as they happen.
func pumpStream(ctx context.Context, env *Env, cli *client.Client, container, execID string, stream *client.HijackedResponse, wantStdin, tty bool) error {
	var stdin io.Reader
	if wantStdin {
		stdin = env.In
	}
	term := NewTerminal(env.In, env.Out)
	run := func() error {
		if tty {
			resize := func(height, width int) {
				if height <= 0 || width <= 0 {
					return
				}
				var err error
				if execID != "" {
					err = cli.ExecResize(ctx, execID, height, width)
				} else {
					err = cli.ContainerResize(ctx, container, height, width)
				}
				if err != nil {
					env.Debugf("resize to %dx%d failed: %v", height, width, err)
				}
			}
			if w, h, err := term.Size(); err == nil {
				resize(h, w)
			}
			resizeCtx, stop := context.WithCancel(ctx)
			defer stop()
			term.WatchResize(resizeCtx, resize)
		}
		return stream.Stream(ctx, stdin, env.Out, env.Err)
	}
	if tty && term.IsTerminal() {
		return term.RawGuard(run)
	}
	return run()
}

// pullImage fetches an image, rendering progress unless output is not a
// terminal, in which case the status lines are printed plainly.
func pullImage(ctx context.Context, env *Env, cli *client.Client, ref, platform string, quiet bool) error {
	p := NewProgress(env, quiet)
	defer func() { _ = p.Close() }()
	opts := client.ImagePullOptions{Platform: platform}
	if auth, ok := registryAuthFor(ref); ok {
		opts.Auth = auth
	}
	if err := cli.ImagePull(ctx, ref, opts, p.Handle); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	return nil
}

// registryAuthFor returns a credential for a reference when the environment
// carries one.
//
// hull keeps credentials in the engine, where the pull actually happens, so
// the CLI only ever forwards what a user has put in the environment for a
// one-off pull. $HULL_REGISTRY_AUTH is "user:password".
func registryAuthFor(ref string) (*client.AuthConfig, bool) {
	raw := strings.TrimSpace(os.Getenv("HULL_REGISTRY_AUTH"))
	if raw == "" {
		return nil, false
	}
	user, pass, ok := strings.Cut(raw, ":")
	if !ok {
		return nil, false
	}
	host := ref
	if i := strings.Index(ref, "/"); i > 0 && strings.ContainsAny(ref[:i], ".:") {
		host = ref[:i]
	}
	return &client.AuthConfig{Username: user, Password: pass, ServerAddress: host}, true
}

// newStartCommand builds "hull start".
func newStartCommand() *Command {
	var attach, interactive bool
	var detachKeys string
	return &Command{
		Name:    "start",
		Usage:   "start [OPTIONS] CONTAINER [CONTAINER...]",
		Short:   "Start one or more stopped containers",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&attach, "attach", "a", false, "Attach STDOUT/STDERR and forward signals")
			fs.BoolVar(&interactive, "interactive", "i", false, "Attach container's STDIN")
			fs.StringVar(&detachKeys, "detach-keys", "", "", "Override the key sequence for detaching a container")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			if attach || interactive {
				if len(args) != 1 {
					return Errorf("you cannot start and attach multiple containers at once")
				}
				return startAndAttach(ctx, env, cli, args[0], interactive, detachKeys)
			}
			var failed error
			for _, name := range args {
				if err := cli.ContainerStart(ctx, name, detachKeys); err != nil {
					env.ReportError(err)
					failed = Exit(ExitFailure)
					continue
				}
				env.Println(name)
			}
			return failed
		},
	}
}

// startAndAttach implements "hull start -a", which follows the container to
// its exit code the way run does.
func startAndAttach(ctx context.Context, env *Env, cli *client.Client, name string, interactive bool, detachKeys string) error {
	insp, err := cli.ContainerInspect(ctx, name, false)
	if err != nil {
		return err
	}
	tty := insp.Config != nil && insp.Config.Tty
	stream, err := cli.ContainerAttach(ctx, name, client.ContainerAttachOptions{
		Stream:     true,
		Stdin:      interactive,
		Stdout:     true,
		Stderr:     !tty,
		DetachKeys: detachKeys,
		TTY:        tty,
	})
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()
	if err := cli.ContainerStart(ctx, name, detachKeys); err != nil {
		return StartFailure(err)
	}
	if err := pumpStream(ctx, env, cli, insp.ID, "", stream, interactive, tty); err != nil {
		return err
	}
	res, err := cli.ContainerWait(ctx, insp.ID, client.WaitConditionNotRunning)
	if err != nil {
		if client.IsNotFound(err) {
			return nil
		}
		return err
	}
	if res.StatusCode != 0 {
		return &ExitError{Code: int(res.StatusCode)}
	}
	return nil
}

// newAttachCommand builds "hull attach".
func newAttachCommand() *Command {
	var noStdin, sigProxy bool
	var detachKeys string
	return &Command{
		Name:    "attach",
		Usage:   "attach [OPTIONS] CONTAINER",
		Short:   "Attach local standard input, output and error streams to a running container",
		MinArgs: 1,
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&noStdin, "no-stdin", "", false, "Do not attach STDIN")
			fs.BoolVar(&sigProxy, "sig-proxy", "", true, "Proxy all received signals to the process")
			fs.StringVar(&detachKeys, "detach-keys", "", "", "Override the key sequence for detaching a container")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			insp, err := cli.ContainerInspect(ctx, args[0], false)
			if err != nil {
				return err
			}
			if insp.State == nil || !insp.State.Running {
				return Errorf("You cannot attach to a stopped container, start it first")
			}
			tty := insp.Config != nil && insp.Config.Tty
			wantStdin := !noStdin && insp.Config != nil && insp.Config.OpenStdin
			stream, err := cli.ContainerAttach(ctx, args[0], client.ContainerAttachOptions{
				Stream:     true,
				Stdin:      wantStdin,
				Stdout:     true,
				Stderr:     !tty,
				DetachKeys: detachKeys,
				TTY:        tty,
			})
			if err != nil {
				return err
			}
			defer func() { _ = stream.Close() }()
			if err := pumpStream(ctx, env, cli, insp.ID, "", stream, wantStdin, tty); err != nil {
				return err
			}
			res, err := cli.ContainerWait(ctx, insp.ID, client.WaitConditionNotRunning)
			if err != nil {
				if client.IsNotFound(err) || errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
			if res.StatusCode != 0 {
				return &ExitError{Code: int(res.StatusCode)}
			}
			return nil
		},
	}
}
