package cli

import (
	"context"
	"strconv"

	"github.com/rahuldhali/hull/internal/client"
)

// newVolumeCommand builds the "hull volume" group.
func newVolumeCommand() *Command {
	return &Command{
		Name:  "volume",
		Usage: "volume COMMAND",
		Short: "Manage volumes",
		Subcommands: []*Command{
			newVolumeCreateCommand(),
			newVolumeListCommand(),
			newVolumeInspectCommand(),
			newVolumeRemoveCommand(),
			newVolumePruneCommand(),
		},
	}
}

// newVolumeCreateCommand builds "hull volume create".
func newVolumeCreateCommand() *Command {
	var driver string
	var labels, options []string
	return &Command{
		Name:    "create",
		Usage:   "create [OPTIONS] [VOLUME]",
		Short:   "Create a volume",
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&driver, "driver", "d", "local", "Specify the volume driver name")
			fs.StringSliceVar(&labels, "label", "", "Set metadata for a volume")
			fs.StringSliceVar(&options, "opt", "o", "Set driver-specific options")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			req := client.VolumeCreateRequest{
				Driver:     driver,
				Labels:     ParseLabels(labels),
				DriverOpts: ParseLabels(options),
			}
			if len(args) == 1 {
				req.Name = args[0]
			}
			v, err := cli.VolumeCreate(ctx, req)
			if err != nil {
				return err
			}
			env.Println(v.Name)
			return nil
		},
	}
}

// volumeRow is one line of "hull volume ls", and what a --format template
// sees.
type volumeRow struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Mountpoint string            `json:"Mountpoint"`
	Scope      string            `json:"Scope,omitempty"`
	Size       string            `json:"Size,omitempty"`
	Links      string            `json:"Links,omitempty"`
	CreatedAt  string            `json:"CreatedAt,omitempty"`
	Labels     map[string]string `json:"Labels,omitempty"`
}

// newVolumeListCommand builds "hull volume ls".
func newVolumeListCommand() *Command {
	var quietFlag bool
	var format string
	var filters []string
	return &Command{
		Name:    "ls",
		Aliases: []string{"list"},
		Usage:   "ls [OPTIONS]",
		Short:   "List volumes",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&quietFlag, "quiet", "q", false, "Only display volume names")
			fs.StringVar(&format, "format", "", "", "Format output using a Go template or 'json'")
			fs.StringSliceVar(&filters, "filter", "f", "Provide filter values (e.g. dangling=true)")
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
			res, err := cli.VolumeList(ctx, f)
			if err != nil {
				return err
			}
			table := env.newTable("DRIVER", "VOLUME NAME", "MOUNTPOINT", "SIZE")
			names := make([]string, 0, len(res.Volumes))
			items := make([]any, 0, len(res.Volumes))
			for _, v := range res.Volumes {
				if v == nil {
					continue
				}
				row := volumeRow{
					Name:       v.Name,
					Driver:     v.Driver,
					Mountpoint: v.Mountpoint,
					Scope:      v.Scope,
					CreatedAt:  v.CreatedAt,
					Labels:     v.Labels,
				}
				if v.UsageData != nil && v.UsageData.Size >= 0 {
					row.Size = HumanSize(v.UsageData.Size)
				}
				if v.UsageData != nil && v.UsageData.RefCount >= 0 {
					row.Links = strconv.FormatInt(v.UsageData.RefCount, 10)
				}
				table.Row(row.Driver, row.Name, row.Mountpoint, row.Size)
				names = append(names, v.Name)
				items = append(items, row)
			}
			if err := env.renderList(quietFlag, format, names, items, table); err != nil {
				return err
			}
			env.ShowWarnings(res.Warnings)
			return nil
		},
	}
}

// newVolumeInspectCommand builds "hull volume inspect".
func newVolumeInspectCommand() *Command {
	var format string
	return &Command{
		Name:    "inspect",
		Usage:   "inspect [OPTIONS] VOLUME [VOLUME...]",
		Short:   "Display detailed information on one or more volumes",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&format, "format", "f", "", "Format output using a Go template or 'json'")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			items := make([]any, 0, len(args))
			failed := false
			for _, name := range args {
				v, err := cli.VolumeInspect(ctx, name)
				if err != nil {
					env.ReportError(err)
					failed = true
					continue
				}
				items = append(items, v)
			}
			if err := renderItems(env, orJSON(format), items); err != nil {
				return err
			}
			if failed {
				return Exit(ExitFailure)
			}
			return nil
		},
	}
}

// orJSON defaults an empty --format to the JSON array every inspect prints.
func orJSON(format string) string {
	if format == "" {
		return FormatJSON
	}
	return format
}

// newVolumeRemoveCommand builds "hull volume rm".
func newVolumeRemoveCommand() *Command {
	var force bool
	return &Command{
		Name:    "rm",
		Aliases: []string{"remove"},
		Usage:   "rm [OPTIONS] VOLUME [VOLUME...]",
		Short:   "Remove one or more volumes",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&force, "force", "f", false, "Force the removal of one or more volumes")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			return forEachTarget(env, args, func(name string) error {
				return cli.VolumeRemove(ctx, name, force)
			})
		},
	}
}

// newVolumePruneCommand builds "hull volume prune".
func newVolumePruneCommand() *Command {
	var force, all bool
	var filters []string
	return &Command{
		Name:    "prune",
		Usage:   "prune [OPTIONS]",
		Short:   "Remove unused local volumes",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&force, "force", "f", false, "Do not prompt for confirmation")
			fs.BoolVar(&all, "all", "a", false, "Remove all unused volumes, not just anonymous ones")
			fs.StringSliceVar(&filters, "filter", "", "Provide filter values (e.g. label=<label>)")
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
			if all {
				if f == nil {
					f = client.Filters{}
				}
				f.Add("all", "true")
			}
			if !force {
				ok, err := confirm(env, "This will remove all volumes not used by at least one container.")
				if err != nil {
					return err
				}
				if !ok {
					return nil
				}
			}
			report, err := cli.VolumesPrune(ctx, f)
			if err != nil {
				return err
			}
			printPruneReport(env, report)
			return nil
		},
	}
}
