package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/client"
	"github.com/rahuldhali/hull/internal/hostinfo"
)

// newDoctorCommand builds "hull doctor": what this machine supports, and the
// exact fix for what it does not.
//
// The report is produced by the engine, because the engine is the thing that
// has to run containers and it lives inside the WSL distro. When no engine is
// reachable the Linux build falls back to probing locally, so "hull doctor" is
// still useful before anything has been started — which is exactly when a user
// reaches for it.
func newDoctorCommand() *Command {
	var asJSON, kconfig, noColor bool
	return &Command{
		Name:  "doctor",
		Usage: "doctor [OPTIONS]",
		Short: "Report what this machine supports, and the fix for what it does not",
		Long: "Report what this machine supports, and the exact fix for what it does not.\n\n" +
			"The exit status is 1 when any check failed, so a setup script can gate\n" +
			"on it. The full kernel configuration is omitted unless --kconfig is\n" +
			"given: it is thousands of lines and buries everything else.",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&asJSON, "json", "", false, "Print the report as JSON")
			fs.BoolVar(&kconfig, "kconfig", "", false, "Include the full kernel configuration")
			fs.BoolVar(&noColor, "no-color", "", false, "Never colourise the report")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			report, source, err := doctorReport(ctx, env, kconfig)
			if err != nil {
				return err
			}
			if asJSON {
				if err := report.JSON(env.Out); err != nil {
					return err
				}
			} else {
				color := env.Color() && !noColor
				if err := report.Text(env.Out, color); err != nil {
					return err
				}
				if source != "" {
					env.Printf("\nreported by %s\n", source)
				}
			}
			if report.Failed() {
				// Exit 1 rather than hull's usual 125: doctor's status is the
				// answer to a question, not a command failure, and a setup
				// script wants the conventional non-zero.
				return &ExitError{Code: 1}
			}
			return nil
		},
	}
}

// doctorReport fetches the host report from the engine, falling back to a
// local probe when the engine cannot be reached.
func doctorReport(ctx context.Context, env *Env, kconfig bool) (*hostinfo.Report, string, error) {
	cli, err := env.Client(ctx)
	if err == nil {
		report, derr := cli.Doctor(ctx, kconfig)
		if derr == nil {
			return report, "the hull engine at " + cli.Host().String(), nil
		}
		env.Debugf("engine doctor failed: %v", derr)
		if !client.IsConnectionFailed(derr) && !client.IsNotFound(derr) && !client.IsNotImplemented(derr) {
			return nil, "", derr
		}
	}
	local, lerr := hostinfo.Probe(ctx)
	if lerr != nil {
		if runtime.GOOS != "linux" {
			return nil, "", Errorf(
				"the hull engine is not reachable, and this host cannot be probed from %s.\n"+
					"       Start the engine with 'hull engine start', then run 'hull doctor' again.", runtime.GOOS)
		}
		return nil, "", fmt.Errorf("probing this host: %w", lerr)
	}
	if !kconfig {
		local.Kernel.Config = nil
	}
	return local, "a local probe (the engine was not reachable)", nil
}

// newUICommand builds "hull ui", the terminal dashboard.
func newUICommand() *Command {
	var filter, tab string
	var noColor bool
	return &Command{
		Name:    "ui",
		Aliases: []string{"dashboard", "tui"},
		Usage:   "ui [OPTIONS]",
		Short:   "Open the terminal dashboard: containers, logs, stats and events",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&filter, "filter", "f", "", "Initial container name filter")
			fs.StringVar(&tab, "tab", "", "", `Detail tab to open on ("logs", "stats", "inspect", "events")`)
			fs.BoolVar(&noColor, "no-color", "", false, "Use the monochrome theme")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			return runDashboard(ctx, env, cli, filter, tab, noColor || !env.Color())
		},
	}
}

// newSnapshotCommand builds "hull snapshot", which is both a verb and a group:
// "hull snapshot CTR NAME" takes a checkpoint, and "hull snapshot ls CTR"
// lists them.
func newSnapshotCommand() *Command {
	return &Command{
		Name:  "snapshot",
		Usage: "snapshot CONTAINER NAME",
		Short: "Checkpoint a running container's writable layer",
		Long: "Checkpoint a running container's writable layer under a name.\n\n" +
			"'hull revert' rolls the layer back to a checkpoint and 'hull branch'\n" +
			"starts a new container from one.",
		MinArgs: 2,
		MaxArgs: 2,
		Subcommands: []*Command{
			newSnapshotListCommand(),
			newSnapshotDiffCommand(),
			newSnapshotRemoveCommand(),
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			cp, err := cli.CheckpointCreate(ctx, args[0], args[1])
			if err != nil {
				return err
			}
			env.Println(cp.Name)
			return nil
		},
	}
}

// newSnapshotListCommand builds "hull snapshot ls".
func newSnapshotListCommand() *Command {
	var quietFlag bool
	var format string
	return &Command{
		Name:    "ls",
		Aliases: []string{"list"},
		Usage:   "ls [OPTIONS] CONTAINER",
		Short:   "List a container's checkpoints",
		MinArgs: 1,
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&quietFlag, "quiet", "q", false, "Only display checkpoint names")
			fs.StringVar(&format, "format", "", "", "Format output using a Go template or 'json'")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			list, err := cli.CheckpointList(ctx, args[0])
			if err != nil {
				return err
			}
			table := env.newTable("NAME", "CREATED", "SIZE", "PARENT")
			names := make([]string, 0, len(list))
			items := make([]any, 0, len(list))
			for _, cp := range list {
				table.Row(cp.Name, HumanSince(cp.Created), HumanSize(cp.Size), cp.Parent)
				names = append(names, cp.Name)
				items = append(items, cp)
			}
			return env.renderList(quietFlag, format, names, items, table)
		},
	}
}

// newSnapshotDiffCommand builds "hull snapshot diff".
func newSnapshotDiffCommand() *Command {
	return &Command{
		Name:    "diff",
		Usage:   "diff CONTAINER A [B]",
		Short:   "Show what changed between two checkpoints",
		MinArgs: 2,
		MaxArgs: 3,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			b := ""
			if len(args) == 3 {
				b = args[2]
			}
			changes, err := cli.CheckpointDiff(ctx, args[0], args[1], b)
			if err != nil {
				return err
			}
			for _, c := range changes {
				env.Printf("%s %s\n", client.FilesystemChange{Kind: c.Kind}.Letter(), c.Path)
			}
			return nil
		},
	}
}

// newSnapshotRemoveCommand builds "hull snapshot rm".
func newSnapshotRemoveCommand() *Command {
	return &Command{
		Name:    "rm",
		Aliases: []string{"remove"},
		Usage:   "rm CONTAINER NAME [NAME...]",
		Short:   "Remove one or more checkpoints",
		MinArgs: 2,
		MaxArgs: -1,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			return forEachTarget(env, args[1:], func(name string) error {
				return cli.CheckpointRemove(ctx, args[0], name)
			})
		},
	}
}

// newRevertCommand builds "hull revert".
func newRevertCommand() *Command {
	return &Command{
		Name:    "revert",
		Usage:   "revert CONTAINER NAME",
		Short:   "Roll a container's writable layer back to a checkpoint",
		MinArgs: 2,
		MaxArgs: 2,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			if err := cli.CheckpointRevert(ctx, args[0], args[1]); err != nil {
				return err
			}
			env.Println(args[0])
			return nil
		},
	}
}

// newBranchCommand builds "hull branch".
func newBranchCommand() *Command {
	return &Command{
		Name:    "branch",
		Usage:   "branch CONTAINER NAME NEW_CONTAINER",
		Short:   "Start a new container from a checkpoint",
		MinArgs: 3,
		MaxArgs: 3,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			res, err := cli.CheckpointBranch(ctx, args[0], args[1], args[2])
			if err != nil {
				return err
			}
			env.ShowWarnings(res.Warnings)
			env.Println(res.ID)
			return nil
		},
	}
}

// defaultLockfile is the file "hull lock" writes.
const defaultLockfile = "hull.lock"

// newLockCommand builds "hull lock", which pins every image a project uses to
// the digest it resolves to today.
func newLockCommand() *Command {
	var update bool
	var out string
	return &Command{
		Name:  "lock",
		Usage: "lock [OPTIONS] [IMAGE...]",
		Short: "Write hull.lock, pinning every image to a digest",
		Long: "Resolve every image reference to the exact manifest digest it points at\n" +
			"today and write them to hull.lock, so the project rebuilds byte-identically.\n\n" +
			"With no arguments the references already in hull.lock are re-resolved.",
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&update, "update", "", false, "Re-resolve every reference to its current digest")
			fs.StringVar(&out, "output", "o", defaultLockfile, "Lockfile to write")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			refs := args
			if len(refs) == 0 {
				existing, err := readLockfile(out)
				if err != nil {
					return err
				}
				if len(existing) == 0 {
					return Errorf("no references given and %s is empty or missing", out)
				}
				for _, e := range existing {
					refs = append(refs, e.Ref)
				}
			}
			_ = update
			entries, err := cli.Lockfile(ctx, refs)
			if err != nil {
				return err
			}
			if err := writeLockfile(out, entries); err != nil {
				return err
			}
			for _, e := range entries {
				env.Printf("%s -> %s\n", e.Ref, e.Digest)
			}
			env.Printf("wrote %s (%d references)\n", out, len(entries))
			return nil
		},
	}
}

// readLockfile loads an existing lockfile, returning nothing when there is no
// file yet.
func readLockfile(path string) ([]client.LockEntry, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var doc struct {
		Images []client.LockEntry `json:"images"`
	}
	if err := json.Unmarshal(buf, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return doc.Images, nil
}

// writeLockfile writes the lockfile atomically, so an interrupted run never
// leaves a half-written pin behind.
func writeLockfile(path string, entries []client.LockEntry) error {
	doc := struct {
		Version   int                `json:"version"`
		Generated time.Time          `json:"generated"`
		Images    []client.LockEntry `json:"images"`
	}{Version: 1, Generated: time.Now().UTC(), Images: entries}
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	buf = append(buf, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	return nil
}

// newSyncCommand builds "hull sync".
func newSyncCommand() *Command {
	var volume, direction string
	var once bool
	var exclude []string
	return &Command{
		Name:  "sync",
		Usage: "sync [OPTIONS] PATH [VOLUME]",
		Short: "Two-way sync a host folder into a volume, with real inotify",
		Long: "Keep a host folder and a named volume in step.\n\n" +
			"The sync runs inside the engine, where inotify actually works: a\n" +
			"bind mount of a Windows drive does not deliver file events to a\n" +
			"container, which is why a watcher in a container never rebuilds.",
		MinArgs: 1,
		MaxArgs: 2,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&volume, "volume", "v", "", "Volume to keep in step with the folder")
			fs.StringVar(&direction, "direction", "", "both", `Sync direction ("both", "to-volume", "to-host")`)
			fs.BoolVar(&once, "once", "", false, "Reconcile once and exit instead of watching")
			fs.StringSliceVar(&exclude, "exclude", "", "Path patterns to skip")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			target := volume
			if len(args) == 2 {
				target = args[1]
			}
			if target == "" {
				target = filepath.Base(filepath.Clean(TranslateLocalPath(args[0])))
			}
			switch direction {
			case "both", "to-volume", "to-host":
			default:
				return Errorf(`invalid --direction %q: want "both", "to-volume" or "to-host"`, direction)
			}
			opts := client.SyncOptions{
				HostPath:  TranslateHostPath(args[0]),
				Volume:    target,
				Direction: direction,
				Once:      once,
				Exclude:   exclude,
			}
			streamCtx, stop := interruptible(ctx)
			defer stop()
			env.Printf("syncing %s <-> volume %s\n", opts.HostPath, opts.Volume)
			err = cli.Sync(streamCtx, opts, func(ev client.SyncEvent) error {
				switch ev.Kind {
				case "error", "conflict":
					env.Warnf("%s %s: %s", ev.Kind, ev.Path, ev.Message)
				default:
					env.Printf("%-8s %-6s %s\n", ev.Kind, ev.Side, ev.Path)
				}
				return nil
			})
			if err != nil && !quiet(err) {
				return err
			}
			return nil
		},
	}
}

// newDebugCommand builds "hull debug", which attaches a toolbox shell to a
// container that has no shell of its own.
func newDebugCommand() *Command {
	var image string
	var namespaces []string
	var noTTY bool
	return &Command{
		Name:  "debug",
		Usage: "debug [OPTIONS] CONTAINER [COMMAND [ARG...]]",
		Short: "Attach a busybox toolbox to a distroless container's namespaces",
		Long: "Attach a toolbox to a running container's namespaces.\n\n" +
			"This is the only way into a distroless container: it has no shell, so\n" +
			"'hull exec' has nothing to run. The toolbox joins the container's\n" +
			"namespaces rather than its filesystem, so its own binaries are used.",
		StopAtOperand: true,
		MinArgs:       1,
		MaxArgs:       -1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&image, "image", "", "", "Toolbox image to use instead of the built-in busybox")
			fs.StringSliceVar(&namespaces, "namespace", "", "Namespaces to join (default: all of them)")
			fs.BoolVar(&noTTY, "no-tty", "", false, "Do not allocate a pseudo-TTY")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			tty := !noTTY && env.StdinIsTerminal()
			opts := client.DebugOptions{
				Image:      image,
				Cmd:        args[1:],
				Tty:        tty,
				Namespaces: namespaces,
			}
			streamCtx, stop := interruptible(ctx)
			defer stop()
			stream, err := cli.Debug(streamCtx, args[0], opts)
			if err != nil {
				return err
			}
			defer func() { _ = stream.Close() }()
			if err := pumpStream(streamCtx, env, cli, args[0], "", stream, true, tty); err != nil && !quiet(err) {
				return err
			}
			return nil
		},
	}
}

// EngineController starts and stops the engine on this machine.
//
// It is a hook rather than a direct dependency because starting the engine is
// a Windows-side job — registering a WSL distro, spawning the bridge and the
// keep-alive agent — and the CLI package must not reach into the bridge. The
// hull binary installs one at startup; a build without it still reports
// engine status, and says what to run instead of failing silently.
type EngineController interface {
	// Start brings the engine up and waits for it to answer.
	Start(ctx context.Context) error
	// Stop shuts the engine down and releases the distro.
	Stop(ctx context.Context) error
	// Describe names what this controller drives, for diagnostics.
	Describe() string
}

// engineController is the process-wide hook, installed by cmd/hull.
var engineController EngineController

// SetEngineController installs the engine lifecycle hook. It is called once,
// before any command runs.
func SetEngineController(c EngineController) { engineController = c }

// newEngineCommand builds the "hull engine" group.
func newEngineCommand() *Command {
	return &Command{
		Name:  "engine",
		Usage: "engine COMMAND",
		Short: "Control the hull engine",
		Subcommands: []*Command{
			newEngineStatusCommand(),
			newEngineStartCommand(),
			newEngineStopCommand(),
			newEngineRestartCommand(),
			newEngineLogsCommand(),
			newEngineGCCommand(),
		},
	}
}

// newEngineStatusCommand builds "hull engine status".
func newEngineStatusCommand() *Command {
	var format string
	return &Command{
		Name:    "status",
		Usage:   "status [OPTIONS]",
		Short:   "Report whether the engine is running, and what it is holding",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&format, "format", "", "", "Format output using a Go template or 'json'")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			status, err := cli.EngineStatus(ctx)
			if err != nil {
				if !client.IsConnectionFailed(err) && !client.IsNotFound(err) {
					return err
				}
				// Fall back to a ping: an engine that does not serve the hull
				// namespace is still an engine, and a dead one must be
				// reported as "stopped" rather than as an error.
				if _, perr := cli.Ping(ctx); perr != nil {
					if format != "" {
						return renderOne(env, format, client.EngineStatus{})
					}
					env.Printf("engine: stopped (%s)\n", cli.Host().String())
					return &ExitError{Code: 1}
				}
				status = client.EngineStatus{Running: true}
			}
			status.Running = true
			if format != "" {
				return renderOne(env, format, status)
			}
			env.Printf("engine:     running at %s\n", cli.Host().String())
			if status.Version != "" {
				env.Printf("version:    %s\n", status.Version)
			}
			if status.Distro != "" {
				env.Printf("distro:     %s\n", status.Distro)
			}
			if status.PID != 0 {
				env.Printf("pid:        %d\n", status.PID)
			}
			if status.Uptime != 0 {
				env.Printf("uptime:     %s\n", HumanDuration(status.Uptime))
			}
			if status.DataRoot != "" {
				env.Printf("data root:  %s\n", status.DataRoot)
			}
			env.Printf("containers: %d\n", status.Containers)
			env.Printf("images:     %d\n", status.Images)
			if status.IdleFrozen > 0 {
				env.Printf("frozen:     %d (idle)\n", status.IdleFrozen)
			}
			return nil
		},
	}
}

// newEngineStartCommand builds "hull engine start".
func newEngineStartCommand() *Command {
	return &Command{
		Name:    "start",
		Usage:   "start",
		Short:   "Start the engine",
		MaxArgs: 0,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			if engineController == nil {
				return noControllerError("start")
			}
			if err := engineController.Start(ctx); err != nil {
				return err
			}
			env.Printf("engine started (%s)\n", engineController.Describe())
			return nil
		},
	}
}

// newEngineStopCommand builds "hull engine stop".
func newEngineStopCommand() *Command {
	return &Command{
		Name:    "stop",
		Usage:   "stop",
		Short:   "Stop the engine and release the WSL distro",
		MaxArgs: 0,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			if engineController != nil {
				if err := engineController.Stop(ctx); err != nil {
					return err
				}
				env.Println("engine stopped")
				return nil
			}
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			if err := cli.EngineStop(ctx); err != nil {
				if client.IsNotFound(err) || client.IsNotImplemented(err) {
					return noControllerError("stop")
				}
				return err
			}
			env.Println("engine stopped")
			return nil
		},
	}
}

// newEngineRestartCommand builds "hull engine restart".
func newEngineRestartCommand() *Command {
	return &Command{
		Name:    "restart",
		Usage:   "restart",
		Short:   "Restart the engine",
		MaxArgs: 0,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			if engineController == nil {
				return noControllerError("restart")
			}
			if err := engineController.Stop(ctx); err != nil {
				env.Debugf("stopping the engine: %v", err)
			}
			if err := engineController.Start(ctx); err != nil {
				return err
			}
			env.Printf("engine restarted (%s)\n", engineController.Describe())
			return nil
		},
	}
}

// noControllerError explains what to do when this build cannot drive the
// engine's lifecycle itself.
func noControllerError(verb string) error {
	if runtime.GOOS == "windows" {
		return Errorf("cannot %s the engine: no engine controller is installed in this build", verb)
	}
	return Errorf("cannot %s the engine from inside the distro.\n"+
		"       Run 'hull engine %s' from the Windows hull.exe, or manage hulld directly\n"+
		"       (for example 'hulld --data-root %s').", verb, verb, hostinfo.DefaultDataRoot)
}

// newEngineLogsCommand builds "hull engine logs".
func newEngineLogsCommand() *Command {
	var follow bool
	var tail int
	var since string
	return &Command{
		Name:    "logs",
		Usage:   "logs [OPTIONS]",
		Short:   "Show the engine's own log",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&follow, "follow", "f", false, "Follow the log output")
			fs.IntVar(&tail, "tail", "n", 0, "Number of lines to show from the end of the log")
			fs.StringVar(&since, "since", "", "", "Show entries since a timestamp or relative time")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			streamCtx, stop := interruptible(ctx)
			defer stop()
			body, err := cli.EngineLogs(streamCtx, client.EngineLogsOptions{Follow: follow, Tail: tail, Since: since})
			if err != nil {
				return err
			}
			defer func() { _ = body.Close() }()
			if _, err := io.Copy(env.Out, body); err != nil && !quiet(err) {
				return fmt.Errorf("reading the engine log: %w", err)
			}
			return nil
		},
	}
}

// newEngineGCCommand builds "hull engine gc".
func newEngineGCCommand() *Command {
	var dryRun bool
	return &Command{
		Name:    "gc",
		Usage:   "gc [OPTIONS]",
		Short:   "Reclaim unreferenced blobs and snapshots",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&dryRun, "dry-run", "", false, "Report what would be removed without removing it")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			report, err := cli.EngineGC(ctx, dryRun)
			if err != nil {
				return err
			}
			if dryRun {
				env.Println("dry run: nothing was removed")
			}
			printPruneReport(env, report)
			return nil
		},
	}
}

// describeHost renders an engine address for a diagnostic line.
func describeHost(h client.Host) string {
	s := h.String()
	if s == "" {
		return "(unset)"
	}
	return strings.TrimSpace(s)
}
