package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rahuldhali/hull/internal/client"
	"github.com/rahuldhali/hull/internal/types"
)

// EngineClient adapts hull's HTTP client to the narrow [Client] the dashboard
// consumes.
//
// The two speak different dialects on purpose. The engine serves the Docker
// Engine API, whose shapes are capitalised, timestamped in strings and split
// between a cheap listing and an expensive inspect; the dashboard works in
// hull's own [types] vocabulary. This type is where that translation lives, so
// neither side has to know about the other and the dashboard stays testable
// against a fake.
//
// It keeps one small cache: the full inspect of every listed container, keyed
// by the state the listing last reported. A listing alone cannot say when a
// container started - it carries only Docker's "Up 3 minutes" prose - so the
// uptime column would read zero without it. Re-inspecting every container on
// every poll would instead cost one round trip per container per second down a
// WSL relay, so the cache is refreshed only when a container's state changes,
// which is exactly when the answer can have moved.
//
// An EngineClient is safe for concurrent use: the dashboard runs one goroutine
// per data source and they all share one of these.
type EngineClient struct {
	c *client.Client

	mu    sync.Mutex
	cache map[string]cachedContainer

	diskAt time.Time
	disk   DiskUsage
}

// cachedContainer is one container's inspect, with the listing key it was
// taken at.
type cachedContainer struct {
	key string
	rec types.Container
}

// diskInterval is how long a free-space answer is reused. The figure comes
// from the engine's host probe, which is not free, and free space does not
// move fast enough to be worth a round trip every poll.
const diskInterval = time.Minute

// NewEngineClient wraps a hull client for the dashboard. It never returns an
// error: everything it needs is on c already.
func NewEngineClient(c *client.Client) *EngineClient {
	return &EngineClient{c: c, cache: map[string]cachedContainer{}}
}

// Info reports engine identity, container counts and host warnings.
func (e *EngineClient) Info(ctx context.Context) (Info, error) {
	in, err := e.c.Info(ctx)
	if err != nil {
		return Info{}, fmt.Errorf("tui: engine info: %w", err)
	}
	out := Info{
		Version:           in.ServerVersion,
		APIVersion:        e.c.ClientVersion(),
		Name:              in.Name,
		DataRoot:          in.DataRoot,
		Containers:        in.Containers,
		ContainersRunning: in.ContainersRunning,
		ContainersPaused:  in.ContainersPaused,
		ContainersStopped: in.ContainersStopped,
		Images:            in.Images,
		Runtime:           in.DefaultRuntime,
		OCIVersion:        in.OCIVersion,
		CgroupVersion:     in.CgroupVersion,
		CgroupV2Delegated: in.CgroupV2Delegated,
		KernelVersion:     in.KernelVersion,
		OperatingSystem:   in.OperatingSystem,
		Warnings:          in.Warnings,
	}
	if out.DataRoot == "" {
		out.DataRoot = in.DockerRootDir
	}
	if in.RuntimeVersion != "" && out.Runtime != "" {
		out.Runtime += " " + in.RuntimeVersion
	}
	return out, nil
}

// Containers lists every container, running or not.
//
// Each entry is the container's full record where one is cached or can be
// fetched, and the listing's own cut-down view otherwise, so a slow or failing
// inspect degrades the uptime column rather than the whole dashboard.
func (e *EngineClient) Containers(ctx context.Context) ([]types.Container, error) {
	sums, err := e.c.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("tui: list containers: %w", err)
	}
	out := make([]types.Container, 0, len(sums))
	live := make(map[string]struct{}, len(sums))
	for _, s := range sums {
		live[s.ID] = struct{}{}
		key := summaryKey(s)
		if rec, ok := e.cached(s.ID, key); ok {
			out = append(out, rec)
			continue
		}
		rec := containerFromSummary(s)
		if full, err := e.c.ContainerInspect(ctx, s.ID, false); err == nil && full != nil {
			rec = containerFromInspect(full)
			e.store(s.ID, key, rec)
		}
		out = append(out, rec)
	}
	e.evict(live)
	return out, nil
}

// cached returns the cached record for id when it was taken at the same
// listing key.
func (e *EngineClient) cached(id, key string) (types.Container, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	got, ok := e.cache[id]
	if !ok || got.key != key {
		return types.Container{}, false
	}
	return got.rec, true
}

// store records one container's inspect against the listing key it matches.
func (e *EngineClient) store(id, key string, rec types.Container) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cache[id] = cachedContainer{key: key, rec: rec}
}

// evict drops cache entries for containers the engine no longer lists, so a
// dashboard left open all day does not accumulate the dead.
func (e *EngineClient) evict(live map[string]struct{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id := range e.cache {
		if _, ok := live[id]; !ok {
			delete(e.cache, id)
		}
	}
}

// summaryKey is the value that decides whether a cached inspect is still
// current: the state, plus the first parenthesised part of Docker's status
// prose, which is where the health result and the exit code live.
func summaryKey(s client.ContainerSummary) string {
	return s.State + "|" + firstParen(s.Status)
}

// firstParen returns the first "(...)" group in s, or "".
func firstParen(s string) string {
	open := strings.Index(s, "(")
	if open < 0 {
		return ""
	}
	closeIdx := strings.Index(s[open:], ")")
	if closeIdx < 0 {
		return ""
	}
	return s[open : open+closeIdx+1]
}

// Inspect returns the full record for one container.
func (e *EngineClient) Inspect(ctx context.Context, idOrName string) (types.Container, error) {
	in, err := e.c.ContainerInspect(ctx, idOrName, false)
	if err != nil {
		return types.Container{}, fmt.Errorf("tui: inspect %s: %w", idOrName, err)
	}
	return containerFromInspect(in), nil
}

// Warnings returns the warnings the engine recorded when it built a
// container's bundle.
//
// These are the ones bundle.Generate produces instead of failing when a
// resource limit cannot be enforced on this host's hybrid cgroups: a container
// created with --memory may be running with no memory limit at all.
//
// Three sources are tried, because the engine has answered in three shapes as
// it has been built out: hull's own per-container endpoint, the HullWarnings
// field of the inspect payload, and the label the API layer writes onto the
// container so the warnings outlive the create response that first carried
// them. Whichever the engine offers, the user sees them.
func (e *EngineClient) Warnings(ctx context.Context, idOrName string) ([]string, error) {
	warns, err := e.c.ContainerWarnings(ctx, idOrName)
	if err == nil && len(warns) > 0 {
		return warns, nil
	}
	in, ierr := e.c.ContainerInspect(ctx, idOrName, false)
	if ierr != nil {
		if err != nil {
			return nil, fmt.Errorf("tui: warnings for %s: %w", idOrName, err)
		}
		return warns, nil
	}
	if len(in.HullWarnings) > 0 {
		return in.HullWarnings, nil
	}
	return ContainerWarnings(containerFromInspect(in)), nil
}

// DiskUsage reports free and total bytes on the engine's data root.
//
// The figure has to come from the engine rather than from a local statfs: on
// Windows the data root lives inside the WSL distro and the client process
// cannot see it at all. The answer is reused for [diskInterval], and a failed
// attempt counts, so a daemon that cannot answer is asked once a minute rather
// than on every poll.
func (e *EngineClient) DiskUsage(ctx context.Context) (DiskUsage, error) {
	e.mu.Lock()
	if !e.diskAt.IsZero() && time.Since(e.diskAt) < diskInterval {
		d := e.disk
		e.mu.Unlock()
		if !d.Known() {
			return DiskUsage{}, fmt.Errorf("tui: engine disk usage: not available")
		}
		return d, nil
	}
	e.mu.Unlock()

	rep, err := e.c.Doctor(ctx, false)
	e.mu.Lock()
	e.diskAt = time.Now()
	if err != nil {
		e.disk = DiskUsage{}
		e.mu.Unlock()
		return DiskUsage{}, fmt.Errorf("tui: engine disk usage: %w", err)
	}
	path := rep.Storage.Probed
	if path == "" {
		path = rep.Storage.DataRoot
	}
	d := DiskUsage{Path: path, Free: rep.Storage.FreeBytes, Total: rep.Storage.TotalBytes}
	e.disk = d
	e.mu.Unlock()
	if !d.Known() {
		return DiskUsage{}, fmt.Errorf("tui: engine disk usage: not available")
	}
	return d, nil
}

// Stats streams resource samples for one container until ctx is cancelled.
func (e *EngineClient) Stats(ctx context.Context, idOrName string, fn func(types.Stats) error) error {
	err := e.c.ContainerStatsStream(ctx, idOrName, true, func(s client.StatsResponse) error {
		return fn(statsFromResponse(s))
	})
	if err != nil && ctx.Err() == nil {
		return fmt.Errorf("tui: stats for %s: %w", idOrName, err)
	}
	return nil
}

// Events streams the engine event bus until ctx is cancelled.
func (e *EngineClient) Events(ctx context.Context, fn func(types.Event) error) error {
	evs, errs := e.c.Events(ctx, client.EventsOptions{})
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			if err != nil && ctx.Err() == nil {
				return fmt.Errorf("tui: events: %w", err)
			}
			return nil
		case ev, ok := <-evs:
			if !ok {
				// The stream ended; a failure may still be sitting
				// in the buffered error channel.
				select {
				case err := <-errs:
					if err != nil && ctx.Err() == nil {
						return fmt.Errorf("tui: events: %w", err)
					}
				default:
				}
				return nil
			}
			if err := fn(eventFromClient(ev)); err != nil {
				return err
			}
		}
	}
}

// Start starts a created or exited container.
func (e *EngineClient) Start(ctx context.Context, idOrName string) error {
	if err := e.c.ContainerStart(ctx, idOrName, ""); err != nil {
		return fmt.Errorf("tui: start %s: %w", idOrName, err)
	}
	return nil
}

// Stop sends the container's stop signal and kills it after its own timeout.
func (e *EngineClient) Stop(ctx context.Context, idOrName string) error {
	if err := e.c.ContainerStop(ctx, idOrName, nil, ""); err != nil {
		return fmt.Errorf("tui: stop %s: %w", idOrName, err)
	}
	return nil
}

// Restart stops and starts a container.
func (e *EngineClient) Restart(ctx context.Context, idOrName string) error {
	if err := e.c.ContainerRestart(ctx, idOrName, nil); err != nil {
		return fmt.Errorf("tui: restart %s: %w", idOrName, err)
	}
	return nil
}

// Pause freezes a running container.
func (e *EngineClient) Pause(ctx context.Context, idOrName string) error {
	if err := e.c.ContainerPause(ctx, idOrName); err != nil {
		return fmt.Errorf("tui: pause %s: %w", idOrName, err)
	}
	return nil
}

// Unpause thaws a paused container.
func (e *EngineClient) Unpause(ctx context.Context, idOrName string) error {
	if err := e.c.ContainerUnpause(ctx, idOrName); err != nil {
		return fmt.Errorf("tui: unpause %s: %w", idOrName, err)
	}
	return nil
}

// Remove deletes a container, killing it first when force is set.
func (e *EngineClient) Remove(ctx context.Context, idOrName string, force bool) error {
	opts := client.ContainerRemoveOptions{Force: force}
	if err := e.c.ContainerRemove(ctx, idOrName, opts); err != nil {
		return fmt.Errorf("tui: remove %s: %w", idOrName, err)
	}
	return nil
}

// ---------- conversions ----------

// parseAPITime parses one of the API's RFC3339 timestamps. Docker writes
// "0001-01-01T00:00:00Z" for a time that has not happened, and an unparseable
// value is treated the same way, because a wrong timestamp on the uptime
// column is worse than a blank one.
func parseAPITime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// stateFromAPI maps the API's state vocabulary onto hull's.
func stateFromAPI(s *client.ContainerState) types.State {
	if s == nil {
		return types.StateCreated
	}
	switch types.State(strings.ToLower(s.Status)) {
	case types.StateCreated, types.StateRunning, types.StatePaused,
		types.StateRestarting, types.StateRemoving, types.StateExited,
		types.StateDead:
		return types.State(strings.ToLower(s.Status))
	}
	// An engine that only set the booleans, or an unknown word: fall back
	// to what the flags say rather than showing a state nothing matches.
	switch {
	case s.Paused:
		return types.StatePaused
	case s.Restarting:
		return types.StateRestarting
	case s.Running:
		return types.StateRunning
	case s.Dead:
		return types.StateDead
	default:
		return types.StateExited
	}
}

// containerFromSummary converts one listing row. It is the degraded path: a
// listing carries no start time, so uptime reads from the creation time until
// an inspect lands.
func containerFromSummary(s client.ContainerSummary) types.Container {
	c := types.Container{
		ID:       s.ID,
		Name:     s.Name(),
		Created:  time.Unix(s.Created, 0),
		Image:    s.ImageID,
		ImageRef: s.Image,
		State:    types.State(s.State),
	}
	c.Config.Labels = s.Labels
	c.HostConfig.NetworkMode = s.HostConfig.NetworkMode
	c.NetworkSettings.Ports = summaryPortMap(s.Ports)
	c.NetworkSettings.Networks = map[string]types.EndpointSettings{}
	if s.NetworkSettings != nil {
		for name, ep := range s.NetworkSettings.Networks {
			c.NetworkSettings.Networks[name] = endpointFromAPI(ep)
		}
	}
	return c
}

// summaryPortMap turns a listing's flat port array into the inspect-shaped
// map the dashboard's port column and tab both read.
func summaryPortMap(ports []client.Port) map[string][]types.PortBinding {
	if len(ports) == 0 {
		return nil
	}
	out := map[string][]types.PortBinding{}
	for _, p := range ports {
		proto := p.Type
		if proto == "" {
			proto = "tcp"
		}
		key := strconv.Itoa(int(p.PrivatePort)) + "/" + proto
		if p.PublicPort == 0 {
			if _, ok := out[key]; !ok {
				out[key] = nil
			}
			continue
		}
		out[key] = append(out[key], types.PortBinding{
			HostIP:   p.IP,
			HostPort: strconv.Itoa(int(p.PublicPort)),
		})
	}
	return out
}

// endpointFromAPI converts one network attachment.
func endpointFromAPI(ep *client.EndpointSettings) types.EndpointSettings {
	if ep == nil {
		return types.EndpointSettings{}
	}
	return types.EndpointSettings{
		NetworkID:   ep.NetworkID,
		EndpointID:  ep.EndpointID,
		Gateway:     ep.Gateway,
		IPAddress:   ep.IPAddress,
		IPPrefixLen: ep.IPPrefixLen,
		MacAddress:  ep.MacAddress,
		Aliases:     ep.Aliases,
		DNSNames:    ep.DNSNames,
	}
}

// containerFromInspect converts a full inspect into hull's own record. This is
// what the list, the detail panes and the inspect tab all read, so it maps
// every field the dashboard can show rather than only the ones one pane wants.
func containerFromInspect(in *client.ContainerInspect) types.Container {
	if in == nil {
		return types.Container{}
	}
	c := types.Container{
		ID:           in.ID,
		Name:         in.ShortName(),
		Created:      parseAPITime(in.Created),
		Image:        in.Image,
		RestartCount: in.RestartCount,
		State:        stateFromAPI(in.State),
	}
	if in.State != nil {
		c.Pid = in.State.Pid
		c.ExitCode = in.State.ExitCode
		c.Error = in.State.Error
		c.OOMKilled = in.State.OOMKilled
		c.StartedAt = parseAPITime(in.State.StartedAt)
		c.FinishedAt = parseAPITime(in.State.FinishedAt)
		if h := in.State.Health; h != nil {
			c.Health = &types.HealthState{
				Status:        h.Status,
				FailingStreak: h.FailingStreak,
			}
			for _, l := range h.Log {
				c.Health.Log = append(c.Health.Log, types.HealthLog{
					Start:    l.Start,
					End:      l.End,
					ExitCode: l.ExitCode,
					Output:   l.Output,
				})
			}
		}
	}
	if cfg := in.Config; cfg != nil {
		c.ImageRef = cfg.Image
		c.Config = types.ContainerConfig{
			Hostname:     cfg.Hostname,
			Domainname:   cfg.Domainname,
			User:         cfg.User,
			AttachStdin:  cfg.AttachStdin,
			AttachStdout: cfg.AttachStdout,
			AttachStderr: cfg.AttachStderr,
			Tty:          cfg.Tty,
			OpenStdin:    cfg.OpenStdin,
			StdinOnce:    cfg.StdinOnce,
			Env:          cfg.Env,
			Cmd:          cfg.Cmd,
			Entrypoint:   cfg.Entrypoint,
			WorkingDir:   cfg.WorkingDir,
			Labels:       cfg.Labels,
			ExposedPorts: cfg.ExposedPorts,
			StopSignal:   cfg.StopSignal,
			StopTimeout:  cfg.StopTimeout,
			Volumes:      cfg.Volumes,
			Healthcheck:  healthcheckFromAPI(cfg.Healthcheck),
		}
	}
	if hc := in.HostConfig; hc != nil {
		c.HostConfig = hostConfigFromAPI(hc)
	}
	if ns := in.NetworkSettings; ns != nil {
		c.NetworkSettings.SandboxKey = ns.SandboxKey
		c.NetworkSettings.Ports = portsFromAPI(ns.Ports)
		c.NetworkSettings.Networks = map[string]types.EndpointSettings{}
		for name, ep := range ns.Networks {
			c.NetworkSettings.Networks[name] = endpointFromAPI(ep)
		}
	}
	return c
}

// healthcheckFromAPI converts an image or container healthcheck.
func healthcheckFromAPI(h *client.HealthConfig) *types.Healthcheck {
	if h == nil {
		return nil
	}
	return &types.Healthcheck{
		Test:        h.Test,
		Interval:    h.Interval,
		Timeout:     h.Timeout,
		StartPeriod: h.StartPeriod,
		Retries:     h.Retries,
	}
}

// portsFromAPI converts the inspect-shaped port map.
func portsFromAPI(in map[string][]client.PortBinding) map[string][]types.PortBinding {
	if in == nil {
		return nil
	}
	out := make(map[string][]types.PortBinding, len(in))
	for key, bindings := range in {
		if len(bindings) == 0 {
			out[key] = nil
			continue
		}
		conv := make([]types.PortBinding, 0, len(bindings))
		for _, b := range bindings {
			conv = append(conv, types.PortBinding{HostIP: b.HostIP, HostPort: b.HostPort})
		}
		out[key] = conv
	}
	return out
}

// hostConfigFromAPI converts the host half of an inspect. It is only ever
// displayed - the dashboard never sends one back - so the fields that carry no
// meaning on screen are left at their zero values rather than invented.
func hostConfigFromAPI(hc *client.HostConfig) types.HostConfig {
	out := types.HostConfig{
		Binds:          hc.Binds,
		PortBindings:   portsFromAPI(hc.PortBindings),
		PublishAll:     hc.PublishAllPorts,
		NetworkMode:    hc.NetworkMode,
		DNS:            hc.DNS,
		DNSSearch:      hc.DNSSearch,
		ExtraHosts:     hc.ExtraHosts,
		AutoRemove:     hc.AutoRemove,
		Privileged:     hc.Privileged,
		ReadonlyRootfs: hc.ReadonlyRootfs,
		CapAdd:         hc.CapAdd,
		CapDrop:        hc.CapDrop,
		SecurityOpt:    hc.SecurityOpt,
		Sysctls:        hc.Sysctls,
		Tmpfs:          hc.Tmpfs,
		Runtime:        hc.Runtime,
		ShmSize:        hc.ShmSize,
		Isolation:      hc.Isolation,
		GroupAdd:       hc.GroupAdd,
		UsernsMode:     hc.UsernsMode,
		OomScoreAdj:    hc.OomScoreAdj,
		PidsLimit:      hc.PidsLimit,
		RestartPolicy: types.RestartPolicy{
			Name:              hc.RestartPolicy.Name,
			MaximumRetryCount: hc.RestartPolicy.MaximumRetryCount,
		},
		LogConfig: types.LogConfig{Type: hc.LogConfig.Type, Config: hc.LogConfig.Config},
		Resources: types.Resources{
			Memory:            hc.Memory,
			MemoryReservation: hc.MemoryReservation,
			MemorySwap:        hc.MemorySwap,
			CPUShares:         hc.CPUShares,
			CPUQuota:          hc.CPUQuota,
			CPUPeriod:         hc.CPUPeriod,
			CpusetCpus:        hc.CpusetCpus,
			CpusetMems:        hc.CpusetMems,
			BlkioWeight:       hc.BlkioWeight,
			NanoCPUs:          hc.NanoCPUs,
		},
	}
	if hc.Init != nil {
		out.Init = *hc.Init
	}
	for _, u := range hc.Ulimits {
		out.Ulimits = append(out.Ulimits, types.Ulimit{Name: u.Name, Soft: u.Soft, Hard: u.Hard})
	}
	for _, d := range hc.Devices {
		out.Devices = append(out.Devices, types.DeviceMapping{
			PathOnHost:        d.PathOnHost,
			PathInContainer:   d.PathInContainer,
			CgroupPermissions: d.CgroupPermissions,
		})
	}
	for _, m := range hc.Mounts {
		conv := types.Mount{
			Type:     m.Type,
			Source:   m.Source,
			Target:   m.Target,
			ReadOnly: m.ReadOnly,
		}
		if m.BindOptions != nil {
			conv.BindOptions = &types.BindOptions{
				Propagation:      m.BindOptions.Propagation,
				CreateMountpoint: m.BindOptions.CreateMountpoint,
			}
		}
		if m.TmpfsOptions != nil {
			conv.TmpfsOptions = &types.TmpfsOptions{
				SizeBytes: m.TmpfsOptions.SizeBytes,
				Mode:      m.TmpfsOptions.Mode,
			}
		}
		out.Mounts = append(out.Mounts, conv)
	}
	return out
}

// statsFromResponse converts one Docker-shaped stats sample into hull's flat
// one. The cache figure is what makes [MemoryUsage] meaningful: the dashboard
// subtracts it, and without it every container that has read a file looks as
// though it is at its limit.
func statsFromResponse(s client.StatsResponse) types.Stats {
	out := types.Stats{
		Read:           s.Read,
		PreRead:        s.PreRead,
		CPUUsage:       s.CPUStats.CPUUsage.TotalUsage,
		PreCPUUsage:    s.PreCPUStats.CPUUsage.TotalUsage,
		SystemUsage:    s.CPUStats.SystemUsage,
		PreSystemUsage: s.PreCPUStats.SystemUsage,
		OnlineCPUs:     int(s.CPUStats.OnlineCPUs),
		MemoryUsage:    s.MemoryStats.Usage,
		MemoryLimit:    s.MemoryStats.Limit,
		PidsCurrent:    s.PidsStats.Current,
		PidsLimit:      s.PidsStats.Limit,
	}
	if out.OnlineCPUs == 0 {
		out.OnlineCPUs = len(s.CPUStats.CPUUsage.PercpuUsage)
	}
	if v, ok := s.MemoryStats.Stats["inactive_file"]; ok {
		out.MemoryCache = v
	} else if v, ok := s.MemoryStats.Stats["cache"]; ok {
		out.MemoryCache = v
	}
	for _, n := range s.Networks {
		out.RxBytes += n.RxBytes
		out.TxBytes += n.TxBytes
		out.RxPackets += n.RxPackets
		out.TxPackets += n.TxPackets
	}
	out.BlkRead, out.BlkWrite = s.BlockIO()
	return out
}

// eventFromClient converts one engine event.
func eventFromClient(e client.Event) types.Event {
	return types.Event{
		Type:     e.Type,
		Action:   e.Action,
		Actor:    types.EventActor{ID: e.Actor.ID, Attributes: e.Actor.Attributes},
		Scope:    e.Scope,
		Time:     e.Time,
		TimeNano: e.TimeNano,
	}
}
