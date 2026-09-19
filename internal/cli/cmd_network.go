package cli

import (
	"context"
	"strings"

	"github.com/rahuldhali/hull/internal/client"
)

// newNetworkCommand builds the "hull network" group.
func newNetworkCommand() *Command {
	return &Command{
		Name:  "network",
		Usage: "network COMMAND",
		Short: "Manage networks",
		Subcommands: []*Command{
			newNetworkCreateCommand(),
			newNetworkListCommand(),
			newNetworkInspectCommand(),
			newNetworkRemoveCommand(),
			newNetworkConnectCommand(),
			newNetworkDisconnectCommand(),
			newNetworkPruneCommand(),
		},
	}
}

// newNetworkCreateCommand builds "hull network create".
func newNetworkCreateCommand() *Command {
	var driver, gateway, ipRange string
	var subnets, options, labels []string
	var internal, attachable, ipv6 bool
	return &Command{
		Name:    "create",
		Usage:   "create [OPTIONS] NETWORK",
		Short:   "Create a network",
		MinArgs: 1,
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&driver, "driver", "d", "bridge", "Driver to manage the network")
			fs.StringSliceVar(&subnets, "subnet", "", "Subnet in CIDR format that represents a network segment")
			fs.StringVar(&gateway, "gateway", "", "", "IPv4 or IPv6 gateway for the master subnet")
			fs.StringVar(&ipRange, "ip-range", "", "", "Allocate container IP from a sub-range")
			fs.BoolVar(&internal, "internal", "", false, "Restrict external access to the network")
			fs.BoolVar(&attachable, "attachable", "", false, "Enable manual container attachment")
			fs.BoolVar(&ipv6, "ipv6", "", false, "Enable IPv6 networking")
			fs.StringSliceVar(&options, "opt", "o", "Set driver-specific options")
			fs.StringSliceVar(&labels, "label", "", "Set metadata on a network")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			req := client.NetworkCreateRequest{
				Name:           args[0],
				Driver:         driver,
				Internal:       internal,
				Attachable:     attachable,
				EnableIPv6:     ipv6,
				Options:        ParseLabels(options),
				Labels:         ParseLabels(labels),
				CheckDuplicate: true,
			}
			if len(subnets) > 0 || gateway != "" || ipRange != "" {
				ipam := &client.IPAM{Driver: "default"}
				if len(subnets) == 0 {
					// A gateway with no subnet is meaningless to the engine,
					// and the error it would raise names neither flag.
					return Errorf("--gateway and --ip-range need a --subnet")
				}
				for i, s := range subnets {
					entry := client.IPAMConfigEntry{Subnet: s}
					if i == 0 {
						entry.Gateway, entry.IPRange = gateway, ipRange
					}
					ipam.Config = append(ipam.Config, entry)
				}
				req.IPAM = ipam
			}
			res, err := cli.NetworkCreate(ctx, req)
			if err != nil {
				return err
			}
			if res.Warning != "" {
				env.Warnf("%s", res.Warning)
			}
			env.Println(res.ID)
			return nil
		},
	}
}

// newNetworkListCommand builds "hull network ls".
func newNetworkListCommand() *Command {
	var quietFlag, noTrunc bool
	var format string
	var filters []string
	return &Command{
		Name:    "ls",
		Aliases: []string{"list"},
		Usage:   "ls [OPTIONS]",
		Short:   "List networks",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&quietFlag, "quiet", "q", false, "Only display network IDs")
			fs.BoolVar(&noTrunc, "no-trunc", "", false, "Do not truncate the output")
			fs.StringVar(&format, "format", "", "", "Format output using a Go template or 'json'")
			fs.StringSliceVar(&filters, "filter", "f", "Provide filter values (e.g. driver=bridge)")
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
			list, err := cli.NetworkList(ctx, client.NetworkListOptions{Filters: f})
			if err != nil {
				return err
			}
			table := env.newTable("NETWORK ID", "NAME", "DRIVER", "SCOPE", "SUBNET")
			ids := make([]string, 0, len(list))
			items := make([]any, 0, len(list))
			for _, n := range list {
				id := n.ID
				if !noTrunc {
					id = TruncateID(id)
				}
				row := networkRow{
					ID:        id,
					Name:      n.Name,
					Driver:    n.Driver,
					Scope:     n.Scope,
					Subnet:    n.Subnet(),
					Gateway:   n.Gateway(),
					Internal:  n.Internal,
					IPv6:      n.EnableIPv6,
					CreatedAt: n.Created,
					Labels:    n.Labels,
				}
				table.Row(row.ID, row.Name, row.Driver, row.Scope, row.Subnet)
				ids = append(ids, row.ID)
				items = append(items, row)
			}
			return env.renderList(quietFlag, format, ids, items, table)
		},
	}
}

// networkRow is one line of "hull network ls", and what a --format template
// sees.
type networkRow struct {
	ID        string            `json:"ID"`
	Name      string            `json:"Name"`
	Driver    string            `json:"Driver"`
	Scope     string            `json:"Scope"`
	Subnet    string            `json:"Subnet,omitempty"`
	Gateway   string            `json:"Gateway,omitempty"`
	Internal  bool              `json:"Internal"`
	IPv6      bool              `json:"IPv6"`
	CreatedAt string            `json:"CreatedAt,omitempty"`
	Labels    map[string]string `json:"Labels,omitempty"`
}

// newNetworkInspectCommand builds "hull network inspect".
func newNetworkInspectCommand() *Command {
	var format string
	var verbose bool
	return &Command{
		Name:    "inspect",
		Usage:   "inspect [OPTIONS] NETWORK [NETWORK...]",
		Short:   "Display detailed information on one or more networks",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&format, "format", "f", "", "Format output using a Go template or 'json'")
			fs.BoolVar(&verbose, "verbose", "v", false, "Show detailed service information")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			items := make([]any, 0, len(args))
			for _, name := range args {
				n, err := cli.NetworkInspect(ctx, name, verbose)
				if err != nil {
					return err
				}
				items = append(items, n)
			}
			return renderItems(env, format, items)
		},
	}
}

// newNetworkRemoveCommand builds "hull network rm".
func newNetworkRemoveCommand() *Command {
	return &Command{
		Name:    "rm",
		Aliases: []string{"remove"},
		Usage:   "rm NETWORK [NETWORK...]",
		Short:   "Remove one or more networks",
		MinArgs: 1,
		MaxArgs: -1,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			return forEachTarget(env, args, func(name string) error {
				return cli.NetworkRemove(ctx, name)
			})
		},
	}
}

// newNetworkConnectCommand builds "hull network connect".
func newNetworkConnectCommand() *Command {
	var ip, ipv6 string
	var aliases []string
	return &Command{
		Name:    "connect",
		Usage:   "connect [OPTIONS] NETWORK CONTAINER",
		Short:   "Connect a container to a network",
		MinArgs: 2,
		MaxArgs: 2,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&ip, "ip", "", "", "IPv4 address to assign")
			fs.StringVar(&ipv6, "ip6", "", "", "IPv6 address to assign")
			fs.StringSliceVar(&aliases, "alias", "", "Add network-scoped alias for the container")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			var cfg *client.EndpointSettings
			if ip != "" || ipv6 != "" || len(aliases) > 0 {
				cfg = &client.EndpointSettings{Aliases: aliases}
				if ip != "" || ipv6 != "" {
					cfg.IPAMConfig = &client.EndpointIPAMConfig{IPv4Address: ip, IPv6Address: ipv6}
				}
			}
			return cli.NetworkConnect(ctx, args[0], args[1], cfg)
		},
	}
}

// newNetworkDisconnectCommand builds "hull network disconnect".
func newNetworkDisconnectCommand() *Command {
	var force bool
	return &Command{
		Name:    "disconnect",
		Usage:   "disconnect [OPTIONS] NETWORK CONTAINER",
		Short:   "Disconnect a container from a network",
		MinArgs: 2,
		MaxArgs: 2,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&force, "force", "f", false, "Force the container to disconnect")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			return cli.NetworkDisconnect(ctx, args[0], args[1], force)
		},
	}
}

// newNetworkPruneCommand builds "hull network prune".
func newNetworkPruneCommand() *Command {
	var force bool
	var filters []string
	return &Command{
		Name:    "prune",
		Usage:   "prune [OPTIONS]",
		Short:   "Remove all unused networks",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
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
				ok, err := confirm(env, "This will remove all networks not used by at least one container.")
				if err != nil || !ok {
					return err
				}
			}
			report, err := cli.NetworksPrune(ctx, f)
			if err != nil {
				return err
			}
			printPruneReport(env, report)
			return nil
		},
	}
}

// networkNames renders a container's attachment list for a listing column.
func networkNames(n map[string]*client.EndpointSettings) string {
	names := make([]string, 0, len(n))
	for name := range n {
		names = append(names, name)
	}
	sortStrings(names)
	return strings.Join(names, ",")
}
