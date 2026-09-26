package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/ChPuru/hull/internal/client"
)

// newStopCommand builds "hull stop".
func newStopCommand() *Command {
	var timeout int
	var signal string
	return &Command{
		Name:    "stop",
		Usage:   "stop [OPTIONS] CONTAINER [CONTAINER...]",
		Short:   "Stop one or more running containers",
		Long:    "Send the stop signal, then SIGKILL after the timeout expires.",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.IntVar(&timeout, "time", "t", 10, "Seconds to wait before killing the container")
			fs.StringVar(&signal, "signal", "s", "", "Signal to send instead of the container's stop signal")
		},
		Run: func(ctx context.Context, env *Env, fs *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			var t *int
			if fs.Changed("time") {
				t = &timeout
			}
			return forEachTarget(env, args, func(name string) error {
				return cli.ContainerStop(ctx, name, t, signal)
			})
		},
	}
}

// newRestartCommand builds "hull restart".
func newRestartCommand() *Command {
	var timeout int
	return &Command{
		Name:    "restart",
		Usage:   "restart [OPTIONS] CONTAINER [CONTAINER...]",
		Short:   "Restart one or more containers",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.IntVar(&timeout, "time", "t", 10, "Seconds to wait before killing the container")
		},
		Run: func(ctx context.Context, env *Env, fs *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			var t *int
			if fs.Changed("time") {
				t = &timeout
			}
			return forEachTarget(env, args, func(name string) error {
				return cli.ContainerRestart(ctx, name, t)
			})
		},
	}
}

// newKillCommand builds "hull kill".
func newKillCommand() *Command {
	var signal string
	return &Command{
		Name:    "kill",
		Usage:   "kill [OPTIONS] CONTAINER [CONTAINER...]",
		Short:   "Kill one or more running containers",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&signal, "signal", "s", "KILL", "Signal to send to the container")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			return forEachTarget(env, args, func(name string) error {
				return cli.ContainerKill(ctx, name, signal)
			})
		},
	}
}

// newPauseCommand builds "hull pause".
func newPauseCommand() *Command {
	return &Command{
		Name:    "pause",
		Usage:   "pause CONTAINER [CONTAINER...]",
		Short:   "Pause all processes within one or more containers",
		MinArgs: 1,
		MaxArgs: -1,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			return forEachTarget(env, args, func(name string) error {
				return cli.ContainerPause(ctx, name)
			})
		},
	}
}

// newUnpauseCommand builds "hull unpause".
func newUnpauseCommand() *Command {
	return &Command{
		Name:    "unpause",
		Usage:   "unpause CONTAINER [CONTAINER...]",
		Short:   "Unpause all processes within one or more containers",
		MinArgs: 1,
		MaxArgs: -1,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			return forEachTarget(env, args, func(name string) error {
				return cli.ContainerUnpause(ctx, name)
			})
		},
	}
}

// newRemoveCommand builds "hull rm".
func newRemoveCommand() *Command {
	var force, volumes, links bool
	return &Command{
		Name:    "rm",
		Aliases: []string{"remove"},
		Usage:   "rm [OPTIONS] CONTAINER [CONTAINER...]",
		Short:   "Remove one or more containers",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&force, "force", "f", false, "Force the removal of a running container (uses SIGKILL)")
			fs.BoolVar(&volumes, "volumes", "v", false, "Remove anonymous volumes created with the container")
			fs.BoolVar(&links, "link", "l", false, "Remove the specified link")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			opts := client.ContainerRemoveOptions{Force: force, RemoveVolumes: volumes, RemoveLinks: links}
			return forEachTarget(env, args, func(name string) error {
				return cli.ContainerRemove(ctx, name, opts)
			})
		},
	}
}

// newWaitCommand builds "hull wait".
func newWaitCommand() *Command {
	var condition string
	return &Command{
		Name:    "wait",
		Usage:   "wait [OPTIONS] CONTAINER [CONTAINER...]",
		Short:   "Block until one or more containers stop, then print their exit codes",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&condition, "condition", "", client.WaitConditionNotRunning,
				`Wait until a condition is met ("not-running", "next-exit", "removed")`)
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			failed := false
			for _, name := range args {
				res, err := cli.ContainerWait(ctx, name, condition)
				if err != nil {
					env.ReportError(err)
					failed = true
					continue
				}
				if res.Error != nil && res.Error.Message != "" {
					env.ReportError(Errorf("%s", res.Error.Message))
					failed = true
					continue
				}
				env.Printf("%d\n", res.StatusCode)
			}
			if failed {
				return Exit(ExitFailure)
			}
			return nil
		},
	}
}

// newRenameCommand builds "hull rename".
func newRenameCommand() *Command {
	return &Command{
		Name:    "rename",
		Usage:   "rename CONTAINER NEW_NAME",
		Short:   "Rename a container",
		MinArgs: 2,
		MaxArgs: 2,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			return cli.ContainerRename(ctx, args[0], args[1])
		},
	}
}

// newUpdateCommand builds "hull update", which changes a container's resource
// limits in place.
//
// Its warnings are as load-bearing as create's: a limit this host cannot
// enforce is reported rather than refused, so a user who never sees the line
// believes a cap is in force when it is not.
func newUpdateCommand() *Command {
	var memory, memorySwap, memoryReservation, cpusetCpus, cpusetMems, restart string
	var cpus float64
	var cpuShares, cpuPeriod, cpuQuota, pidsLimit int64
	var blkioWeight int
	return &Command{
		Name:    "update",
		Usage:   "update [OPTIONS] CONTAINER [CONTAINER...]",
		Short:   "Update configuration of one or more containers",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&memory, "memory", "m", "", "Memory limit")
			fs.StringVar(&memorySwap, "memory-swap", "", "", "Swap limit equal to memory plus swap: -1 for unlimited")
			fs.StringVar(&memoryReservation, "memory-reservation", "", "", "Memory soft limit")
			fs.Float64Var(&cpus, "cpus", "", 0, "Number of CPUs")
			fs.Int64Var(&cpuShares, "cpu-shares", "c", 0, "CPU shares (relative weight)")
			fs.Int64Var(&cpuPeriod, "cpu-period", "", 0, "Limit CPU CFS period")
			fs.Int64Var(&cpuQuota, "cpu-quota", "", 0, "Limit CPU CFS quota")
			fs.StringVar(&cpusetCpus, "cpuset-cpus", "", "", "CPUs in which to allow execution (0-3, 0,1)")
			fs.StringVar(&cpusetMems, "cpuset-mems", "", "", "MEMs in which to allow execution (0-3, 0,1)")
			fs.IntVar(&blkioWeight, "blkio-weight", "", 0, "Block IO (relative weight), between 10 and 1000")
			fs.Int64Var(&pidsLimit, "pids-limit", "", 0, "Tune container pids limit (-1 for unlimited)")
			fs.StringVar(&restart, "restart", "", "", "Restart policy to apply when a container exits")
		},
		Run: func(ctx context.Context, env *Env, fs *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			var req client.ContainerUpdateRequest
			if memory != "" {
				n, err := ParseSize(memory)
				if err != nil {
					return Errorf("invalid --memory %q: %v", memory, err)
				}
				req.Memory = n
			}
			if memoryReservation != "" {
				n, err := ParseSize(memoryReservation)
				if err != nil {
					return Errorf("invalid --memory-reservation %q: %v", memoryReservation, err)
				}
				req.MemoryReservation = n
			}
			if memorySwap != "" {
				if strings.TrimSpace(memorySwap) == "-1" {
					req.MemorySwap = -1
				} else {
					n, err := ParseSize(memorySwap)
					if err != nil {
						return Errorf("invalid --memory-swap %q: %v", memorySwap, err)
					}
					req.MemorySwap = n
				}
			}
			if cpus > 0 {
				req.NanoCPUs = int64(cpus * 1e9)
			}
			req.CPUShares = cpuShares
			req.CPUPeriod = cpuPeriod
			req.CPUQuota = cpuQuota
			req.CpusetCpus = cpusetCpus
			req.CpusetMems = cpusetMems
			req.BlkioWeight = uint16(blkioWeight)
			if fs.Changed("pids-limit") {
				limit := pidsLimit
				req.PidsLimit = &limit
			}
			if restart != "" {
				rp, err := ParseRestartPolicy(restart)
				if err != nil {
					return err
				}
				req.RestartPolicy = &rp
			}
			failed := false
			for _, name := range args {
				warnings, err := cli.ContainerUpdate(ctx, name, req)
				if err != nil {
					env.ReportError(err)
					failed = true
					continue
				}
				env.ShowWarnings(warnings)
				env.Println(name)
			}
			if failed {
				return Exit(ExitFailure)
			}
			return nil
		},
	}
}

// newPortCommand builds "hull port".
func newPortCommand() *Command {
	return &Command{
		Name:    "port",
		Usage:   "port CONTAINER [PRIVATE_PORT[/PROTO]]",
		Short:   "List port mappings, or a specific mapping, for the container",
		MinArgs: 1,
		MaxArgs: 2,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			ports, err := cli.ContainerPorts(ctx, args[0])
			if err != nil {
				return err
			}
			if len(args) == 2 {
				port, proto := client.ParsePort(args[1])
				key := port + "/" + proto
				binds, ok := ports[key]
				if !ok || len(binds) == 0 {
					return &ExitError{Code: ExitFailure, Err: Errorf("no public port %q published for %s", key, args[0])}
				}
				for _, b := range binds {
					env.Printf("%s\n", bindString(b))
				}
				return nil
			}
			keys := sortedKeys(ports)
			for _, key := range keys {
				for _, b := range ports[key] {
					env.Printf("%s -> %s\n", key, bindString(b))
				}
			}
			return nil
		},
	}
}

// bindString renders one host binding as "ip:port".
func bindString(b client.PortBinding) string {
	host := b.HostIP
	if host == "" {
		host = "0.0.0.0"
	}
	return host + ":" + b.HostPort
}

// newTopCommand builds "hull top".
func newTopCommand() *Command {
	return &Command{
		Name:          "top",
		Usage:         "top CONTAINER [ps OPTIONS]",
		Short:         "Display the running processes of a container",
		StopAtOperand: true,
		MinArgs:       1,
		MaxArgs:       -1,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			res, err := cli.ContainerTop(ctx, args[0], strings.Join(args[1:], " "))
			if err != nil {
				return err
			}
			table := env.newTable(res.Titles...)
			for _, row := range res.Processes {
				table.Row(row...)
			}
			return table.Render(env.Out)
		},
	}
}

// newDiffCommand builds "hull diff".
func newDiffCommand() *Command {
	var format string
	return &Command{
		Name:    "diff",
		Usage:   "diff CONTAINER",
		Short:   "Inspect changes to files or directories on a container's filesystem",
		MinArgs: 1,
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&format, "format", "", "", "Format output using a Go template or 'json'")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			changes, err := cli.ContainerChanges(ctx, args[0])
			if err != nil {
				return err
			}
			if format != "" {
				items := make([]any, 0, len(changes))
				for _, c := range changes {
					items = append(items, changeRow{Kind: c.Letter(), Path: c.Path})
				}
				return renderItems(env, format, items)
			}
			for _, c := range changes {
				env.Printf("%s %s\n", c.Letter(), c.Path)
			}
			return nil
		},
	}
}

// changeRow is what a --format template sees for one filesystem change.
type changeRow struct {
	// Kind is "A", "C" or "D".
	Kind string `json:"Kind"`
	// Path is the container-absolute path.
	Path string `json:"Path"`
}

// newExportCommand builds "hull export".
func newExportCommand() *Command {
	var output string
	return &Command{
		Name:    "export",
		Usage:   "export [OPTIONS] CONTAINER",
		Short:   "Export a container's filesystem as a tar archive",
		MinArgs: 1,
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&output, "output", "o", "", "Write to a file instead of STDOUT")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			body, err := cli.ContainerExport(ctx, args[0])
			if err != nil {
				return err
			}
			defer func() { _ = body.Close() }()
			return writeArchive(env, output, body, "export")
		},
	}
}

// writeArchive sends a tar stream to a file or to stdout, refusing to dump
// binary onto a terminal the way every tar-producing command does.
func writeArchive(env *Env, output string, body io.Reader, what string) error {
	if output == "" {
		if env.StdoutIsTerminal() {
			return Errorf("cowardly refusing to save %s to a terminal, use -o or redirect", what)
		}
		if _, err := io.Copy(env.Out, body); err != nil {
			return fmt.Errorf("writing %s: %w", what, err)
		}
		return nil
	}
	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("creating %s: %w", output, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(f, body); err != nil {
		return fmt.Errorf("writing %s: %w", output, err)
	}
	return f.Close()
}

// newCommitCommand builds "hull commit".
func newCommitCommand() *Command {
	var message, author, pauseFlag string
	var changes []string
	var noPause bool
	return &Command{
		Name:    "commit",
		Usage:   "commit [OPTIONS] CONTAINER [REPOSITORY[:TAG]]",
		Short:   "Create a new image from a container's changes",
		MinArgs: 1,
		MaxArgs: 2,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&message, "message", "m", "", "Commit message")
			fs.StringVar(&author, "author", "a", "", `Author (e.g. "Ada <ada@example.com>")`)
			fs.StringSliceVar(&changes, "change", "c", "Apply Dockerfile instruction to the created image")
			fs.BoolVar(&noPause, "no-pause", "", false, "Do not pause the container while committing")
			fs.StringVar(&pauseFlag, "pause", "p", "true", "Pause the container during commit")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			opts := client.CommitOptions{
				Container: args[0],
				Comment:   message,
				Author:    author,
				Changes:   changes,
				Pause:     !noPause && isTrue(pauseFlag),
			}
			if len(args) == 2 {
				repo, tag := splitReference(args[1])
				opts.Repo, opts.Tag = repo, tag
			}
			res, err := cli.ContainerCommit(ctx, opts)
			if err != nil {
				return err
			}
			env.Println(res.ID)
			return nil
		},
	}
}

// splitReference separates a "repo:tag" into its halves, leaving a registry
// host's port alone.
func splitReference(ref string) (repo, tag string) {
	i := strings.LastIndex(ref, ":")
	if i < 0 || strings.Contains(ref[i+1:], "/") {
		return ref, ""
	}
	return ref[:i], ref[i+1:]
}

// newPruneCommand builds "hull prune", the one-shot sweep across every object
// kind.
func newPruneCommand() *Command {
	var all, volumes, force bool
	var filters []string
	return &Command{
		Name:    "prune",
		Usage:   "prune [OPTIONS]",
		Short:   "Remove unused containers, images, networks and optionally volumes",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&all, "all", "a", false, "Remove all unused images, not just dangling ones")
			fs.BoolVar(&volumes, "volumes", "", false, "Prune anonymous volumes too")
			fs.BoolVar(&force, "force", "f", false, "Do not prompt for confirmation")
			fs.StringSliceVar(&filters, "filter", "", "Provide filter values (e.g. until=24h)")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			f, err := buildFilters(filters)
			if err != nil {
				return err
			}
			if !force {
				ok, err := confirm(env, "This will remove all stopped containers, unused networks and dangling images.")
				if err != nil {
					return err
				}
				if !ok {
					return nil
				}
			}
			var total client.PruneReport
			if r, err := cli.ContainersPrune(ctx, f); err == nil {
				total.Add(r)
			} else {
				env.ReportError(err)
			}
			if r, err := cli.NetworksPrune(ctx, f); err == nil {
				total.Add(r)
			} else {
				env.ReportError(err)
			}
			imageFilters := client.Filters{}
			for k, vs := range f {
				imageFilters[k] = append(imageFilters[k], vs...)
			}
			if all {
				imageFilters.Add("dangling", "false")
			}
			if r, err := cli.ImagesPrune(ctx, imageFilters); err == nil {
				total.Add(r)
			} else {
				env.ReportError(err)
			}
			if volumes {
				if r, err := cli.VolumesPrune(ctx, f); err == nil {
					total.Add(r)
				} else {
					env.ReportError(err)
				}
			}
			printPruneReport(env, total)
			return nil
		},
	}
}

// renderItems prints a list through --format, sharing the listing commands'
// contract: "json" gives one array, anything else is a Go template.
func renderItems(env *Env, format string, items []any) error {
	if format == FormatJSON {
		if items == nil {
			items = []any{}
		}
		return WriteJSON(env.Out, items)
	}
	t, err := NewTemplate(format)
	if err != nil {
		return err
	}
	return RenderTemplate(env.Out, t, items)
}

// sortedKeys returns a map's keys in a stable order, so a listing never
// reshuffles between runs.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys
}

// sortStrings sorts in place. It is a tiny insertion sort rather than a sort
// package import, because these lists are a handful of ports or networks.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && portLess(s[j], s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// portLess orders "80/tcp" before "443/tcp" numerically, and falls back to
// lexical order for anything that is not a port key.
func portLess(a, b string) bool {
	an, aok := leadingNumber(a)
	bn, bok := leadingNumber(b)
	if aok && bok && an != bn {
		return an < bn
	}
	return a < b
}

// leadingNumber reads the integer a string starts with.
func leadingNumber(s string) (int, bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, false
	}
	return n, true
}
