package cli

import (
	"context"
	"strings"

	"github.com/ChPuru/hull/internal/client"
)

// newPsCommand builds "hull ps".
func newPsCommand() *Command {
	var all, quiet, noTrunc, size, latest bool
	var last int
	var format string
	var filters []string
	return &Command{
		Name:    "ps",
		Aliases: []string{"list"},
		Usage:   "ps [OPTIONS]",
		Short:   "List containers",
		Long: "List containers.\n\n" +
			"Columns are sized to the terminal. Without a terminal nothing is\n" +
			"truncated and colour is dropped, so piping into a script is lossless.",
		Example: "  hull ps -a\n" +
			"  hull ps --filter status=running --format '{{.Names}}\\t{{.Status}}'\n" +
			"  hull ps -q | xargs hull stop",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&all, "all", "a", false, "Show all containers (default shows just running)")
			fs.BoolVar(&quiet, "quiet", "q", false, "Only display container IDs")
			fs.BoolVar(&noTrunc, "no-trunc", "", false, "Don't truncate output")
			fs.BoolVar(&size, "size", "s", false, "Display total file sizes")
			fs.BoolVar(&latest, "latest", "l", false, "Show the latest created container")
			fs.IntVar(&last, "last", "n", 0, "Show n last created containers (includes all states)")
			fs.StringVar(&format, "format", "", "", "Format output using a Go template or 'json'")
			fs.StringSliceVar(&filters, "filter", "f", "Filter output on conditions provided")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			opts := client.ContainerListOptions{All: all, Size: size, Limit: last}
			if latest {
				opts.Limit, opts.All = 1, true
			}
			if opts.Limit > 0 {
				opts.All = true
			}
			opts.Filters, err = buildFilters(filters)
			if err != nil {
				return err
			}
			list, err := cli.ContainerList(ctx, opts)
			if err != nil {
				return err
			}
			headers := []string{"CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "PORTS", "NAMES"}
			if size {
				headers = append(headers, "SIZE")
			}
			table := env.newTable(headers...)
			ids := make([]string, 0, len(list))
			items := make([]any, 0, len(list))
			for _, c := range list {
				id := c.ID
				if !noTrunc {
					id = TruncateID(id)
				}
				command := c.Command
				if !noTrunc {
					command = Ellipsis(command, 20)
				}
				row := []string{
					id,
					c.Image,
					quoteCommand(command),
					HumanSince(c.CreatedAt()),
					c.Status,
					c.PortString(),
					strings.Join(trimNames(c.Names), ","),
				}
				if size {
					row = append(row, containerSize(c))
				}
				table.Row(row...)
				ids = append(ids, id)
				items = append(items, psItem(c, noTrunc))
			}
			return env.renderList(quiet, format, ids, items, table)
		},
	}
}

// psItem is the value a --format template or a JSON listing sees. It carries
// the rendered columns as well as the raw fields, so both
// "{{.Status}}" and "{{.State}}" do what a reader expects.
type psRow struct {
	ID         string            `json:"ID"`
	Image      string            `json:"Image"`
	Command    string            `json:"Command"`
	CreatedAt  string            `json:"CreatedAt"`
	RunningFor string            `json:"RunningFor"`
	Status     string            `json:"Status"`
	State      string            `json:"State"`
	Ports      string            `json:"Ports"`
	Names      string            `json:"Names"`
	Labels     map[string]string `json:"Labels,omitempty"`
	Size       string            `json:"Size,omitempty"`
	Mounts     string            `json:"Mounts,omitempty"`
	Networks   string            `json:"Networks,omitempty"`
}

// psItem builds one template row from a listing entry.
func psItem(c client.ContainerSummary, noTrunc bool) psRow {
	id := c.ID
	if !noTrunc {
		id = TruncateID(id)
	}
	mounts := make([]string, 0, len(c.Mounts))
	for _, m := range c.Mounts {
		if m.Name != "" {
			mounts = append(mounts, m.Name)
			continue
		}
		mounts = append(mounts, m.Source)
	}
	return psRow{
		ID:         id,
		Image:      c.Image,
		Command:    quoteCommand(c.Command),
		CreatedAt:  c.CreatedAt().Format("2006-01-02 15:04:05 -0700 MST"),
		RunningFor: HumanSince(c.CreatedAt()),
		Status:     c.Status,
		State:      c.State,
		Ports:      c.PortString(),
		Names:      strings.Join(trimNames(c.Names), ","),
		Labels:     c.Labels,
		Size:       containerSize(c),
		Mounts:     strings.Join(mounts, ","),
		Networks:   strings.Join(c.NetworkNames(), ","),
	}
}

// containerSize renders the writable-layer size, with the image size in
// brackets, as "docker ps -s" does.
func containerSize(c client.ContainerSummary) string {
	if c.SizeRw == 0 && c.SizeRootFs == 0 {
		return ""
	}
	if c.SizeRootFs == 0 {
		return HumanSize(c.SizeRw)
	}
	return HumanSize(c.SizeRw) + " (virtual " + HumanSize(c.SizeRootFs) + ")"
}

// trimNames strips the leading slash the API puts on every container name.
// The slash is right on the wire — compose matches on it — and wrong in a
// listing.
func trimNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, strings.TrimPrefix(n, "/"))
	}
	return out
}

// quoteCommand renders a container's command the way every Docker listing
// does, in double quotes.
func quoteCommand(cmd string) string {
	if cmd == "" {
		return ""
	}
	return `"` + cmd + `"`
}

// buildFilters turns repeated --filter key=value flags into the API's filter
// map. A term with no "=" is rejected here rather than by the engine, because
// the engine's message cannot name the flag.
func buildFilters(terms []string) (client.Filters, error) {
	if len(terms) == 0 {
		return nil, nil
	}
	f := client.Filters{}
	for _, t := range terms {
		key, value, ok := strings.Cut(t, "=")
		if !ok || key == "" {
			return nil, Errorf("bad --filter %q: want key=value", t)
		}
		f.Add(key, value)
	}
	return f, nil
}
