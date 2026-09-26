package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/ChPuru/hull/internal/client"
	"github.com/ChPuru/hull/internal/version"
)

// Global holds the options hull accepts before the subcommand name. They are
// parsed separately from a command's own flags because they have to be known
// before the command is chosen: --host decides which engine every later call
// talks to.
type Global struct {
	// Host is the engine address, from --host or -H.
	Host string
	// LogLevel is hull's own diagnostic verbosity: debug, info, warn, error.
	LogLevel string
	// Version asks for the version banner instead of a command.
	Version bool
	// Help asks for help instead of a command.
	Help bool
	// Debug is shorthand for --log-level debug.
	Debug bool
}

// EnvAPIVersion pins the Docker Engine API version the client asks for, which
// is what a user needs when talking to a daemon hull cannot negotiate with
// automatically.
const EnvAPIVersion = "HULL_API_VERSION"

// registerGlobalFlags declares the pre-command options. They are never parsed
// through a FlagSet — [ParseGlobal] does that — but registering them keeps
// "hull --help" honest about what it accepts.
func registerGlobalFlags(fs *FlagSet) {
	fs.String("host", "H", "", "Engine address (unix://, npipe://, tcp:// or wsl://)")
	fs.String("log-level", "l", "info", `Logging level ("debug", "info", "warn", "error")`)
	fs.Bool("debug", "D", false, "Shorthand for --log-level debug")
	fs.Bool("version", "v", false, "Print the version and exit")
}

// ParseGlobal consumes the options that may appear before the subcommand and
// returns the rest of the command line unchanged.
//
// Parsing stops at the first operand, at "--", or at a flag it does not know:
// an unrecognised flag belongs to the command, and letting it through produces
// a much better error than claiming hull has no such option.
func ParseGlobal(args []string) (Global, []string, error) {
	var g Global
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			return g, args[i+1:], nil
		case arg == "-" || !strings.HasPrefix(arg, "-"):
			return g, args[i:], nil
		case strings.HasPrefix(arg, "--"):
			name, value, hasValue := strings.Cut(arg[2:], "=")
			switch name {
			case "host":
				v, next, err := globalValue(args, i, "--host", value, hasValue)
				if err != nil {
					return g, nil, err
				}
				g.Host, i = v, next
			case "log-level":
				v, next, err := globalValue(args, i, "--log-level", value, hasValue)
				if err != nil {
					return g, nil, err
				}
				g.LogLevel, i = v, next
			case "debug":
				g.Debug = true
			case "version":
				g.Version = true
			case "help":
				g.Help = true
			default:
				return g, args[i:], nil
			}
		default:
			next, stop, err := parseGlobalCluster(&g, args, i)
			if err != nil {
				return g, nil, err
			}
			if stop {
				return g, args[i:], nil
			}
			i = next
		}
	}
	return g, nil, nil
}

// parseGlobalCluster handles one "-abc" token of global short flags. It
// reports the index of the last argument it consumed, and whether the caller
// should stop parsing because the cluster held something unknown.
func parseGlobalCluster(g *Global, args []string, i int) (next int, stop bool, err error) {
	token := args[i][1:]
	next = i
	for j := 0; j < len(token); j++ {
		switch token[j] {
		case 'H', 'l':
			name := "-" + string(token[j])
			attached := strings.TrimPrefix(token[j+1:], "=")
			v, after, verr := globalValue(args, next, name, attached, attached != "")
			if verr != nil {
				return next, false, verr
			}
			if token[j] == 'H' {
				g.Host = v
			} else {
				g.LogLevel = v
			}
			return after, false, nil
		case 'D':
			g.Debug = true
		case 'v':
			g.Version = true
		case 'h':
			g.Help = true
		default:
			return next, true, nil
		}
	}
	return next, false, nil
}

// globalValue resolves one global flag's argument, whether it was attached
// with "=" or given as the following word.
func globalValue(args []string, i int, name, attached string, hasAttached bool) (string, int, error) {
	if hasAttached {
		return attached, i, nil
	}
	if i+1 >= len(args) {
		return "", i, Errorf("flag needs an argument: %s", name)
	}
	return args[i+1], i + 1, nil
}

// Apply copies the global options onto the environment every command reads.
func (e *Env) Apply(g Global) {
	if g.Host != "" {
		e.Host = g.Host
	}
	level := g.LogLevel
	if g.Debug {
		level = "debug"
	}
	if level != "" {
		e.LogLevel = level
	}
	if strings.EqualFold(e.LogLevel, "debug") {
		e.Debug = true
	}
	if v := strings.TrimSpace(os.Getenv(EnvAPIVersion)); v != "" {
		e.APIVersion = v
	}
}

// Run parses the global options and dispatches to a command.
func Run(ctx context.Context, env *Env, args []string) error {
	g, rest, err := ParseGlobal(args)
	if err != nil {
		return &ExitError{Code: ExitFailure, Err: err}
	}
	env.Apply(g)
	root := NewRootCommand()
	if g.Version {
		return writeVersionBanner(ctx, env)
	}
	if g.Help {
		if len(rest) == 0 {
			return writeRootHelp(env, root)
		}
		rest = append(rest, "--help")
	}
	if len(rest) == 0 {
		return writeRootHelp(env, root)
	}
	return Execute(ctx, env, root, rest)
}

// Main is the whole CLI: it builds an environment around the process streams,
// runs the command line and returns the process exit status.
//
// Errors are reported here rather than inside commands so every one of them
// carries the same "hull: " prefix on stderr and the same exit-code mapping.
func Main(ctx context.Context, args []string) int {
	env := NewEnv(os.Stdin, os.Stdout, os.Stderr)
	return env.ReportError(Run(ctx, env, args))
}

// writeRootHelp renders the top-level help, including the global options.
func writeRootHelp(env *Env, root *Command) error {
	fs := NewFlagSet(root.Name)
	registerGlobalFlags(fs)
	return WriteHelp(env.Out, root, fs)
}

// writeVersionBanner prints hull's own build identity and, when an engine is
// reachable, the engine's too. An unreachable engine is not an error here:
// "hull --version" has to work before anything is running.
func writeVersionBanner(ctx context.Context, env *Env) error {
	env.Printf("hull version %s, build %s\n", version.Version, version.Commit)
	env.Printf(" API version:  %s (minimum %s)\n", version.APIVersion, version.MinAPIVersion)
	env.Printf(" Go version:   %s\n", runtime.Version())
	env.Printf(" Built:        %s\n", version.BuildDate)
	env.Printf(" OS/Arch:      %s/%s\n", runtime.GOOS, runtime.GOARCH)

	cli, err := env.Client(ctx)
	if err != nil {
		return nil
	}
	v, err := cli.Version(ctx)
	if err != nil {
		env.Printf("\nEngine: not reachable at %s\n", cli.Host().String())
		return nil
	}
	env.Printf("\nEngine:\n")
	env.Printf(" Version:      %s\n", v.Version)
	env.Printf(" API version:  %s (minimum %s)\n", v.APIVersion, v.MinAPIVersion)
	env.Printf(" OS/Arch:      %s/%s\n", v.Os, v.Arch)
	if v.KernelVersion != "" {
		env.Printf(" Kernel:       %s\n", v.KernelVersion)
	}
	for _, c := range v.Components {
		env.Printf(" %-13s %s\n", c.Name+":", c.Version)
	}
	return nil
}

// rootLong is the top-level description, and is where the Docker compatibility
// story is told: a user whose muscle memory is "docker" needs to know in the
// first screen of help that the stock tooling works, and exactly how.
const rootLong = "hull is a container engine for Windows 11 and WSL2.\n" +
	"\n" +
	"It speaks the Docker Engine API, so the stock docker CLI, docker compose,\n" +
	"Dev Containers and Testcontainers work against it unchanged. Run\n" +
	"'hull docker-compat' for the exact DOCKER_HOST value to use on this machine."

// NewRootCommand builds the whole command tree.
func NewRootCommand() *Command {
	return &Command{
		Name:  "hull",
		Usage: "[OPTIONS] COMMAND [ARG...]",
		Short: "A container engine for Windows 11 and WSL2",
		Long:  rootLong,
		Flags: registerGlobalFlags,
		Subcommands: []*Command{
			// containers
			newRunCommand(),
			newCreateCommand(),
			newStartCommand(),
			newStopCommand(),
			newRestartCommand(),
			newKillCommand(),
			newPauseCommand(),
			newUnpauseCommand(),
			newRemoveCommand(),
			newPsCommand(),
			newInspectCommand(),
			newLogsCommand(),
			newExecCommand(),
			newAttachCommand(),
			newTopCommand(),
			newStatsCommand(),
			newPortCommand(),
			newRenameCommand(),
			newUpdateCommand(),
			newWaitCommand(),
			newCopyCommand(),
			newDiffCommand(),
			newCommitCommand(),
			newExportCommand(),
			newPruneCommand(),

			// images
			newPullCommand(),
			newPushCommand(),
			newImagesCommand(),
			newImageCommand(),
			newRemoveImageCommand(),
			newTagCommand(),
			newSaveCommand(),
			newLoadCommand(),
			newLoginCommand(),
			newLogoutCommand(),
			newHistoryCommand(),
			newBuildCommand(),

			// networks and volumes
			newNetworkCommand(),
			newVolumeCommand(),

			// hull's own verbs
			newDoctorCommand(),
			newUICommand(),
			newEventsCommand(),
			newSnapshotCommand(),
			newRevertCommand(),
			newBranchCommand(),
			newLockCommand(),
			newSyncCommand(),
			newDebugCommand(),
			newEngineCommand(),

			// system
			newVersionCommand(),
			newInfoCommand(),
			newDockerCompatCommand(),
		},
	}
}

// newVersionCommand builds "hull version".
func newVersionCommand() *Command {
	var format string
	return &Command{
		Name:    "version",
		Usage:   "version [OPTIONS]",
		Short:   "Show hull and engine version information",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&format, "format", "", "", "Format output using a Go template or 'json'")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			if format == "" {
				return writeVersionBanner(ctx, env)
			}
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			v, err := cli.Version(ctx)
			if err != nil {
				return err
			}
			return renderOne(env, format, v)
		},
	}
}

// newInfoCommand builds "hull info".
func newInfoCommand() *Command {
	var format string
	return &Command{
		Name:    "info",
		Usage:   "info [OPTIONS]",
		Short:   "Display system-wide information",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&format, "format", "", "", "Format output using a Go template or 'json'")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			info, err := cli.Info(ctx)
			if err != nil {
				return err
			}
			if format != "" {
				return renderOne(env, format, info)
			}
			writeInfo(env, info)
			return nil
		},
	}
}

// writeInfo renders "hull info" in Docker's layout.
func writeInfo(env *Env, info client.Info) {
	env.Printf("Server:\n")
	env.Printf(" Name:              %s\n", info.Name)
	env.Printf(" Server Version:    %s\n", info.ServerVersion)
	env.Printf(" Containers:        %d (running %d, paused %d, stopped %d)\n",
		info.Containers, info.ContainersRunning, info.ContainersPaused, info.ContainersStopped)
	env.Printf(" Images:            %d\n", info.Images)
	env.Printf(" Storage Driver:    %s\n", info.Driver)
	env.Printf(" Logging Driver:    %s\n", info.LoggingDriver)
	env.Printf(" Cgroup Driver:     %s\n", info.CgroupDriver)
	env.Printf(" Cgroup Version:    %s (delegated: %t)\n", info.CgroupVersion, info.CgroupV2Delegated)
	env.Printf(" Default Runtime:   %s\n", info.DefaultRuntime)
	if info.OCIVersion != "" {
		env.Printf(" OCI Version:       %s\n", info.OCIVersion)
	}
	env.Printf(" Kernel Version:    %s\n", info.KernelVersion)
	env.Printf(" Operating System:  %s\n", info.OperatingSystem)
	env.Printf(" OSType/Arch:       %s/%s\n", info.OSType, info.Architecture)
	env.Printf(" CPUs:              %d\n", info.NCPU)
	env.Printf(" Total Memory:      %s\n", HumanSize(info.MemTotal))
	env.Printf(" Data Root:         %s\n", JoinNonEmpty(" ", info.DataRoot, info.DockerRootDir))
	if len(info.SecurityOptions) > 0 {
		env.Printf(" Security Options:  %s\n", strings.Join(info.SecurityOptions, ", "))
	}
	// The host warnings are the whole point of this command on a WSL host: an
	// undelegated cgroup v2 hierarchy means every resource limit is silently
	// ignored, and the user has to be told.
	env.ShowWarnings(info.Warnings)
}

// newDockerCompatCommand builds "hull docker-compat", which prints the exact
// environment a Docker-speaking tool needs on this machine.
func newDockerCompatCommand() *Command {
	return &Command{
		Name:  "docker-compat",
		Usage: "docker-compat",
		Short: "How to point docker, compose and Testcontainers at hull",
		Long: "Print the DOCKER_HOST setting that makes the stock Docker tooling\n" +
			"talk to hull: the docker CLI, docker compose, VS Code Dev Containers\n" +
			"and Testcontainers all work unchanged against hull's Engine API.",
		MaxArgs: 0,
		Run: func(_ context.Context, env *Env, _ *FlagSet, _ []string) error {
			addr := env.Host
			if addr == "" {
				addr = client.DefaultHost()
			}
			env.Println("hull serves the Docker Engine API, so the stock tooling works unchanged.")
			env.Println("")
			env.Printf("This machine's engine address: %s\n", addr)
			env.Println("")
			if runtime.GOOS == "windows" {
				env.Println("PowerShell:")
				env.Printf("  $env:DOCKER_HOST = '%s'\n", addr)
				env.Println("")
				env.Println("cmd.exe:")
				env.Printf("  set DOCKER_HOST=%s\n", addr)
				env.Println("")
				env.Println("Permanently, for your user:")
				env.Printf("  setx DOCKER_HOST %s\n", addr)
			} else {
				env.Println("sh, bash, zsh:")
				env.Printf("  export DOCKER_HOST=%s\n", addr)
			}
			env.Println("")
			env.Println("From another WSL distro the engine socket is also bound into the")
			env.Println("shared /mnt/wsl tmpfs, which needs no Windows relay:")
			env.Printf("  export DOCKER_HOST=unix://%s\n", client.SharedUnixSocket)
			env.Println("")
			env.Println("hull reads $HULL_HOST first and $DOCKER_HOST second, so setting")
			env.Println("DOCKER_HOST points both CLIs at the same engine.")
			return nil
		},
	}
}

// renderOne prints a single object through --format, which accepts "json" or
// a Go template just as the listing commands do.
func renderOne(env *Env, format string, v any) error {
	if format == FormatJSON {
		return WriteJSON(env.Out, v)
	}
	t, err := NewTemplate(format)
	if err != nil {
		return err
	}
	return RenderTemplate(env.Out, t, []any{v})
}

// forEachTarget runs fn once per operand, printing the operand on success and
// the failure on stderr, and reports a hull-level failure when any of them
// failed. This is Docker's behaviour for the multi-target verbs: one bad name
// must not stop the others.
func forEachTarget(env *Env, args []string, fn func(string) error) error {
	failed := false
	for _, name := range args {
		if err := fn(name); err != nil {
			env.ReportError(err)
			failed = true
			continue
		}
		env.Println(name)
	}
	if failed {
		return Exit(ExitFailure)
	}
	return nil
}

// printPruneReport prints what a prune removed, in Docker's layout.
func printPruneReport(env *Env, r client.PruneReport) {
	printed := false
	section := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		env.Printf("%s:\n", title)
		for _, it := range items {
			env.Printf("%s\n", it)
		}
		printed = true
	}
	section("Deleted Containers", r.ContainersDeleted)
	section("Deleted Volumes", r.VolumesDeleted)
	section("Deleted Networks", r.NetworksDeleted)
	if len(r.ImagesDeleted) > 0 {
		env.Printf("Deleted Images:\n")
		for _, d := range r.ImagesDeleted {
			switch {
			case d.Untagged != "":
				env.Printf("untagged: %s\n", d.Untagged)
			case d.Deleted != "":
				env.Printf("deleted: %s\n", d.Deleted)
			}
		}
		printed = true
	}
	if printed {
		env.Println("")
	}
	env.Printf("Total reclaimed space: %s\n", HumanSize(r.SpaceReclaimed))
}

// confirm asks a yes/no question before a destructive sweep. Off a terminal it
// refuses rather than assuming yes, because a prune in a script that forgot
// --force must not silently delete anything.
func confirm(env *Env, prompt string) (bool, error) {
	if !env.StdinIsTerminal() || !env.StdoutIsTerminal() {
		return false, Errorf("%s\n       Refusing to continue without a terminal; pass --force", prompt)
	}
	env.Printf("%s [y/N] ", prompt)
	var answer string
	if _, err := fmt.Fscanln(env.In, &answer); err != nil {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
