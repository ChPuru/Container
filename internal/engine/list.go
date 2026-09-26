package engine

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/ChPuru/hull/internal/types"
)

// List returns the containers matching opts, newest first.
//
// Filter semantics are Docker's: values of one key are ORed, different keys
// are ANDed, and label filters are ANDed with each other because "give me the
// containers carrying these labels" only means anything that way.
func (e *Engine) List(ctx context.Context, opts ListOptions) ([]*types.Container, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	all, err := e.state.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("engine: list containers: %w", err)
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].Created.Equal(all[j].Created) {
			return all[i].Created.After(all[j].Created)
		}
		return all[i].ID < all[j].ID
	})

	f, err := e.compileListFilters(opts, all)
	if err != nil {
		return nil, err
	}

	out := make([]*types.Container, 0, len(all))
	for _, c := range all {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !f.match(c) {
			continue
		}
		e.refreshHealthView(c)
		out = append(out, copyContainer(c))
		if opts.Limit > 0 && len(out) >= opts.Limit {
			break
		}
	}
	return out, nil
}

// listFilter is a compiled ListOptions: everything that needs resolving
// against the store has already been resolved, so matching is a pure
// predicate.
type listFilter struct {
	all      bool
	status   []string
	names    []string
	ids      []string
	labels   []labelTerm
	ancestor map[string]bool
	networks map[string]bool
	volumes  map[string]bool
	exited   []int
	health   []string
	before   *time.Time
	since    *time.Time
}

// compileListFilters resolves the parts of a filter that need the store: image
// references, network names and the before/since anchors.
func (e *Engine) compileListFilters(opts ListOptions, all []*types.Container) (*listFilter, error) {
	f := &listFilter{
		all:    opts.All,
		status: opts.Status,
		names:  opts.Name,
		ids:    opts.ID,
		exited: opts.Exited,
		health: opts.Health,
	}
	for _, s := range opts.Status {
		switch types.State(s) {
		case types.StateCreated, types.StateRunning, types.StatePaused, types.StateRestarting,
			types.StateRemoving, types.StateExited, types.StateDead:
		default:
			return nil, fmt.Errorf("%w: unknown status filter %q", ErrInvalid, s)
		}
	}
	labels, err := parseLabelFilters(opts.Label)
	if err != nil {
		return nil, err
	}
	f.labels = labels
	if len(opts.Ancestor) > 0 {
		f.ancestor = make(map[string]bool, len(opts.Ancestor))
		for _, a := range opts.Ancestor {
			f.ancestor[a] = true
			if img, err := e.images.Get(a); err == nil {
				f.ancestor[img.ID] = true
			}
		}
	}
	if len(opts.Network) > 0 {
		f.networks = make(map[string]bool, len(opts.Network))
		for _, n := range opts.Network {
			f.networks[n] = true
			if net, err := e.nets.Get(n); err == nil {
				f.networks[net.ID] = true
				f.networks[net.Name] = true
			}
		}
	}
	if len(opts.Volume) > 0 {
		f.volumes = make(map[string]bool, len(opts.Volume))
		for _, v := range opts.Volume {
			f.volumes[v] = true
			if strings.HasPrefix(v, "/") {
				f.volumes[path.Clean(v)] = true
			}
			if vol, err := e.vols.Get(v); err == nil {
				f.volumes[vol.Mountpoint] = true
				if data, derr := e.vols.DataDir(vol.Name); derr == nil {
					f.volumes[data] = true
				}
			}
		}
	}
	anchor := func(names []string) (*time.Time, error) {
		if len(names) == 0 {
			return nil, nil
		}
		for _, n := range names {
			for _, c := range all {
				if c.ID == n || c.Name == n || strings.HasPrefix(c.ID, n) {
					t := c.Created
					return &t, nil
				}
			}
		}
		return nil, fmt.Errorf("%w: no such container: %s", ErrNotFound, names[0])
	}
	if f.before, err = anchor(opts.Before); err != nil {
		return nil, err
	}
	if f.since, err = anchor(opts.Since); err != nil {
		return nil, err
	}
	return f, nil
}

// match reports whether one container satisfies every filter.
func (f *listFilter) match(c *types.Container) bool {
	if !f.all && len(f.status) == 0 && len(f.exited) == 0 {
		if c.State != types.StateRunning && c.State != types.StateRestarting && c.State != types.StatePaused {
			return false
		}
	}
	if len(f.status) > 0 && !containsString(f.status, string(c.State)) {
		return false
	}
	if len(f.names) > 0 && !anySubstring(f.names, c.Name) {
		return false
	}
	if len(f.ids) > 0 && !anyPrefix(f.ids, c.ID) {
		return false
	}
	if !matchLabels(f.labels, c.Config.Labels) {
		return false
	}
	if f.ancestor != nil && !f.ancestor[c.Image] && !f.ancestor[c.ImageRef] {
		return false
	}
	if f.networks != nil {
		hit := false
		for name, ep := range c.NetworkSettings.Networks {
			if f.networks[name] || f.networks[ep.NetworkID] {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if f.volumes != nil {
		hit := false
		for _, m := range c.HostConfig.Mounts {
			if f.volumes[m.Source] || f.volumes[path.Clean(m.Target)] {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(f.exited) > 0 {
		hit := false
		for _, code := range f.exited {
			if c.State == types.StateExited && c.ExitCode == code {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(f.health) > 0 {
		status := ""
		if c.Health != nil {
			status = c.Health.Status
		}
		if !containsString(f.health, status) {
			return false
		}
	}
	if f.before != nil && !c.Created.Before(*f.before) {
		return false
	}
	if f.since != nil && !c.Created.After(*f.since) {
		return false
	}
	return true
}

// containsString reports whether list holds want.
func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// anySubstring reports whether got contains any of the patterns, which is how
// Docker's name filter behaves.
func anySubstring(patterns []string, got string) bool {
	for _, p := range patterns {
		if p != "" && strings.Contains(got, p) {
			return true
		}
	}
	return false
}

// anyPrefix reports whether got starts with any of the prefixes.
func anyPrefix(prefixes []string, got string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(got, p) {
			return true
		}
	}
	return false
}
