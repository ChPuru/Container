package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rahuldhali/hull/internal/client"
	"github.com/rahuldhali/hull/internal/logbuf"
)

// interruptible returns a context that is cancelled on the first Ctrl-C, so a
// streaming command unwinds cleanly — closing the response body, restoring the
// terminal and returning zero — instead of being killed mid-write.
//
// The second interrupt is deliberately left to the runtime's default handler:
// a user pressing Ctrl-C twice wants out now, not a tidier shutdown.
func interruptible(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, interruptSignals()...)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			signal.Stop(ch)
			cancel()
		})
	}
	go func() {
		select {
		case <-ch:
			signal.Stop(ch)
			signal.Reset(interruptSignals()...)
			cancel()
		case <-ctx.Done():
			signal.Stop(ch)
		}
	}()
	return ctx, stop
}

// quiet reports whether an error is only the stream ending or the user
// pressing Ctrl-C, neither of which is a failure worth printing.
func quiet(err error) bool {
	return err == nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe)
}

// newLogsCommand builds "hull logs".
func newLogsCommand() *Command {
	var follow, timestamps, details bool
	var tail, since, until string
	return &Command{
		Name:  "logs",
		Usage: "logs [OPTIONS] CONTAINER",
		Short: "Fetch the logs of a container",
		Long: "Fetch the logs of a container.\n\n" +
			"With -f the stream stays open until the container exits or Ctrl-C is\n" +
			"pressed, which ends the stream cleanly rather than killing the CLI.",
		MinArgs: 1,
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&follow, "follow", "f", false, "Follow log output")
			fs.StringVar(&tail, "tail", "n", "all", "Number of lines to show from the end of the logs")
			fs.StringVar(&since, "since", "", "", "Show logs since a timestamp or relative time (e.g. 10m)")
			fs.StringVar(&until, "until", "", "", "Show logs before a timestamp or relative time")
			fs.BoolVar(&timestamps, "timestamps", "t", false, "Show timestamps")
			fs.BoolVar(&details, "details", "", false, "Show extra details provided to logs")
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
			streamCtx, stop := interruptible(ctx)
			defer stop()
			body, err := cli.ContainerLogs(streamCtx, args[0], client.ContainerLogsOptions{
				ShowStdout: true,
				ShowStderr: true,
				Follow:     follow,
				Tail:       tail,
				Since:      since,
				Until:      until,
				Timestamps: timestamps,
			})
			if err != nil {
				return err
			}
			defer func() { _ = body.Close() }()
			_ = details
			if insp.Tty() {
				if _, err := io.Copy(env.Out, body); err != nil && !quiet(err) {
					return fmt.Errorf("reading logs: %w", err)
				}
				return nil
			}
			if err := logbuf.DemuxFramed(body, env.Out, env.Err); err != nil && !quiet(err) {
				return fmt.Errorf("reading logs: %w", err)
			}
			return nil
		},
	}
}

// newExecCommand builds "hull exec".
func newExecCommand() *Command {
	var interactive, tty, detach, privileged bool
	var user, workdir, detachKeys string
	var envVars, envFiles []string
	return &Command{
		Name:          "exec",
		Usage:         "exec [OPTIONS] CONTAINER COMMAND [ARG...]",
		Short:         "Execute a command in a running container",
		StopAtOperand: true,
		MinArgs:       2,
		MaxArgs:       -1,
		Example: "  hull exec -it web sh\n" +
			"  hull exec -u root -w /srv web ls -la",
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&interactive, "interactive", "i", false, "Keep STDIN open even if not attached")
			fs.BoolVar(&tty, "tty", "t", false, "Allocate a pseudo-TTY")
			fs.BoolVar(&detach, "detach", "d", false, "Detached mode: run the command in the background")
			fs.StringVar(&user, "user", "u", "", "Username or UID (format: <name|uid>[:<group|gid>])")
			fs.StringVar(&workdir, "workdir", "w", "", "Working directory inside the container")
			fs.StringSliceVar(&envVars, "env", "e", "Set environment variables")
			fs.StringSliceVar(&envFiles, "env-file", "", "Read in a file of environment variables")
			fs.BoolVar(&privileged, "privileged", "", false, "Give extended privileges to the command")
			fs.StringVar(&detachKeys, "detach-keys", "", "", "Override the key sequence for detaching")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			var envList []string
			for _, path := range envFiles {
				vars, err := ReadEnvFile(path)
				if err != nil {
					return err
				}
				envList = append(envList, vars...)
			}
			envList = append(envList, expandEnvFromHost(envVars)...)

			req := client.ExecCreateRequest{
				AttachStdin:  interactive && !detach,
				AttachStdout: !detach,
				AttachStderr: !detach,
				DetachKeys:   detachKeys,
				Tty:          tty,
				Env:          envList,
				Cmd:          args[1:],
				Privileged:   privileged,
				User:         user,
				WorkingDir:   workdir,
			}
			created, err := cli.ExecCreate(ctx, args[0], req)
			if err != nil {
				return err
			}
			if detach {
				return cli.ExecStart(ctx, created.ID, tty)
			}
			streamCtx, stop := interruptible(ctx)
			defer stop()
			stream, err := cli.ExecAttach(streamCtx, created.ID, tty)
			if err != nil {
				// A command the container does not have, or cannot run, is
				// the shell's 127 or 126 rather than hull's 125.
				return StartFailure(err)
			}
			defer func() { _ = stream.Close() }()
			if err := pumpStream(streamCtx, env, cli, args[0], created.ID, stream, interactive, tty); err != nil && !quiet(err) {
				return err
			}
			insp, err := cli.ExecInspect(ctx, created.ID)
			if err != nil {
				// The exec ran; only its exit status is unknown. Reporting a
				// hull-level failure here would mask the command's own result.
				env.Debugf("exec inspect failed: %v", err)
				return nil
			}
			return execExit(insp.ExitCode)
		},
	}
}

// execExit maps an exec's exit status onto hull's own, keeping Docker's
// convention that 126 means "could not invoke" and 127 means "not found".
func execExit(code int) error {
	if code == 0 {
		return nil
	}
	return &ExitError{Code: code}
}

// newStatsCommand builds "hull stats".
func newStatsCommand() *Command {
	var noStream, all, noTrunc bool
	var format string
	return &Command{
		Name:  "stats",
		Usage: "stats [OPTIONS] [CONTAINER...]",
		Short: "Display a live stream of container resource usage statistics",
		Long: "Display a live stream of container resource usage statistics.\n\n" +
			"Off a terminal the display does not repaint in place: each sample is\n" +
			"printed as its own block of rows, so a redirected log stays readable.",
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&all, "all", "a", false, "Show all containers (default shows just running)")
			fs.BoolVar(&noStream, "no-stream", "", false, "Disable streaming stats and only pull the first result")
			fs.BoolVar(&noTrunc, "no-trunc", "", false, "Do not truncate output")
			fs.StringVar(&format, "format", "", "", "Format output using a Go template or 'json'")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			targets := args
			if len(targets) == 0 {
				list, err := cli.ContainerList(ctx, client.ContainerListOptions{All: all})
				if err != nil {
					return err
				}
				for _, c := range list {
					targets = append(targets, c.ID)
				}
			}
			if len(targets) == 0 {
				return nil
			}
			streamCtx, stop := interruptible(ctx)
			defer stop()
			return streamStats(streamCtx, env, cli, targets, noStream, noTrunc, format)
		},
	}
}

// statsRow is one rendered line of "hull stats", and the value a --format
// template sees.
type statsRow struct {
	ID       string `json:"ID"`
	Name     string `json:"Name"`
	CPUPerc  string `json:"CPUPerc"`
	MemUsage string `json:"MemUsage"`
	MemPerc  string `json:"MemPerc"`
	NetIO    string `json:"NetIO"`
	BlockIO  string `json:"BlockIO"`
	PIDs     string `json:"PIDs"`
}

// streamStats samples every target concurrently and repaints one block per
// interval until the context ends.
func streamStats(ctx context.Context, env *Env, cli *client.Client, targets []string, noStream, noTrunc bool, format string) error {
	var mu sync.Mutex
	latest := make(map[string]statsRow, len(targets))
	order := append([]string(nil), targets...)

	var wg sync.WaitGroup
	for _, id := range targets {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			err := cli.ContainerStatsStream(ctx, id, !noStream, func(s client.StatsResponse) error {
				mu.Lock()
				latest[id] = statsRowFrom(id, s, noTrunc)
				mu.Unlock()
				return nil
			})
			if err != nil && !quiet(err) {
				env.Debugf("stats for %s ended: %v", id, err)
			}
		}(id)
	}

	render := func() error {
		mu.Lock()
		rows := make([]statsRow, 0, len(order))
		for _, id := range order {
			if r, ok := latest[id]; ok {
				rows = append(rows, r)
			}
		}
		mu.Unlock()
		if format != "" {
			items := make([]any, 0, len(rows))
			for _, r := range rows {
				items = append(items, r)
			}
			return renderItems(env, format, items)
		}
		table := env.newTable("CONTAINER ID", "NAME", "CPU %", "MEM USAGE / LIMIT", "MEM %", "NET I/O", "BLOCK I/O", "PIDS")
		for _, r := range rows {
			table.Row(r.ID, r.Name, r.CPUPerc, r.MemUsage, r.MemPerc, r.NetIO, r.BlockIO, r.PIDs)
		}
		return table.Render(env.Out)
	}

	if noStream {
		wg.Wait()
		return render()
	}

	repaint := env.StdoutIsTerminal()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	drawn := 0
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-ticker.C:
			if repaint && drawn > 0 {
				fmt.Fprintf(env.Out, "\x1b[%dA\x1b[J", drawn)
			}
			if err := render(); err != nil {
				return err
			}
			mu.Lock()
			drawn = len(latest) + 1
			mu.Unlock()
		}
	}
}

// statsRowFrom renders one sample.
func statsRowFrom(id string, s client.StatsResponse, noTrunc bool) statsRow {
	shown := id
	if !noTrunc {
		shown = TruncateID(id)
	}
	rx, tx := s.NetworkIO()
	read, write := s.BlockIO()
	pids := strconv.FormatUint(s.PidsStats.Current, 10)
	return statsRow{
		ID:       shown,
		Name:     strings.TrimPrefix(s.Name, "/"),
		CPUPerc:  fmt.Sprintf("%.2f%%", s.CPUPercent()),
		MemUsage: HumanSizeUnsigned(s.MemoryUsage()) + " / " + HumanSizeUnsigned(s.MemoryStats.Limit),
		MemPerc:  fmt.Sprintf("%.2f%%", s.MemoryPercent()),
		NetIO:    HumanSizeUnsigned(rx) + " / " + HumanSizeUnsigned(tx),
		BlockIO:  HumanSizeUnsigned(read) + " / " + HumanSizeUnsigned(write),
		PIDs:     pids,
	}
}

// newEventsCommand builds "hull events".
func newEventsCommand() *Command {
	var format, since, until string
	var filters []string
	return &Command{
		Name:    "events",
		Usage:   "events [OPTIONS]",
		Short:   "Get real-time events from the engine",
		MaxArgs: 0,
		Example: "  hull events\n" +
			"  hull events --filter type=container --filter event=die\n" +
			"  hull events --format json | jq .",
		Flags: func(fs *FlagSet) {
			fs.StringSliceVar(&filters, "filter", "f", "Filter output on conditions provided")
			fs.StringVar(&format, "format", "", "", "Format output using a Go template or 'json'")
			fs.StringVar(&since, "since", "", "", "Show all events created since a timestamp")
			fs.StringVar(&until, "until", "", "", "Stream events until this timestamp")
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
			streamCtx, stop := interruptible(ctx)
			defer stop()
			events, errs := cli.Events(streamCtx, client.EventsOptions{Since: since, Until: until, Filters: f})

			var tmpl = format
			for {
				select {
				case ev, ok := <-events:
					if !ok {
						select {
						case err := <-errs:
							if err != nil && !quiet(err) {
								return err
							}
						default:
						}
						return nil
					}
					if err := printEvent(env, tmpl, ev); err != nil {
						return err
					}
				case err := <-errs:
					if err != nil && !quiet(err) {
						return err
					}
					return nil
				case <-streamCtx.Done():
					return nil
				}
			}
		},
	}
}

// printEvent renders one engine event.
func printEvent(env *Env, format string, ev client.Event) error {
	switch format {
	case "":
		env.Printf("%s %s %s %s%s\n",
			ev.At().Format(time.RFC3339Nano), ev.Type, ev.Action, ev.Actor.ID, eventAttributes(ev))
		return nil
	case FormatJSON:
		buf, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("encoding event: %w", err)
		}
		env.Println(string(buf))
		return nil
	default:
		t, err := NewTemplate(format)
		if err != nil {
			return err
		}
		return RenderTemplate(env.Out, t, []any{ev})
	}
}

// eventAttributes renders an event's actor attributes in Docker's bracketed
// form, with a stable key order.
func eventAttributes(ev client.Event) string {
	if len(ev.Actor.Attributes) == 0 {
		return ""
	}
	keys := sortedKeys(ev.Actor.Attributes)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+ev.Actor.Attributes[k])
	}
	return " (" + strings.Join(parts, ", ") + ")"
}
