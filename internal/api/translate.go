package api

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ChPuru/hull/internal/engine"
	"github.com/ChPuru/hull/internal/types"
)

// This file is the translation layer between hull's domain model and Docker's
// wire format. It exists so internal/types never has to carry a Docker json
// tag: the domain model stays about containers, and the compatibility burden
// stays here where it is visible.

// timeString renders an instant the way Docker's inspect documents do. The
// zero time becomes Docker's own "0001-01-01T00:00:00Z" rather than an empty
// string, because clients parse the field unconditionally.
func timeString(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// containerJSON renders one container as the full Docker inspect document.
func (s *Server) containerJSON(c *types.Container, warnings []string, execIDs []string) *ContainerJSON {
	dir := filepath.Join(s.dataRoot, "containers", c.ID)
	path, args := splitCommand(c.Config.Entrypoint, c.Config.Cmd)

	doc := &ContainerJSON{
		ID:              c.ID,
		Created:         timeString(c.Created),
		Path:            path,
		Args:            stringsOrEmpty(args),
		State:           containerState(c),
		Image:           c.Image,
		ResolvConfPath:  filepath.Join(dir, "resolv.conf"),
		HostnamePath:    filepath.Join(dir, "hostname"),
		HostsPath:       filepath.Join(dir, "hosts"),
		LogPath:         filepath.Join(dir, c.ID+"-json.log"),
		Name:            "/" + c.Name,
		RestartCount:    c.RestartCount,
		Driver:          "overlay2",
		Platform:        "linux",
		MountLabel:      "",
		ProcessLabel:    "",
		AppArmorProfile: "",
		ExecIDs:         stringsOrNil(execIDs),
		HostConfig:      hostConfigToAPI(c.HostConfig),
		GraphDriver: GraphDriverData{
			Name: "overlay2",
			Data: map[string]string{
				"MergedDir": filepath.Join(dir, "merged"),
				"UpperDir":  filepath.Join(dir, "upper"),
				"WorkDir":   filepath.Join(dir, "work"),
			},
		},
		Mounts:          mountPoints(c),
		Config:          containerConfigToAPI(c),
		NetworkSettings: networkSettingsToAPI(c),
	}
	if c.HostConfig.LogConfig.Type == "none" {
		doc.LogPath = ""
	}
	// A limit this host could not enforce is recorded as a label rather than
	// dropped: the create response carries the warnings, and inspect is where
	// a user looks afterwards to find out why their memory cap did nothing.
	if len(warnings) > 0 {
		if doc.Config.Labels == nil {
			doc.Config.Labels = map[string]string{}
		}
		doc.Config.Labels[WarningsLabel] = strings.Join(warnings, "; ")
	}
	return doc
}

// WarningsLabel is where a container's unenforceable-limit warnings surface in
// its inspect document. The create response returns them directly, but a
// container created by compose is inspected long after that response was
// discarded, so they are also durable here.
const WarningsLabel = "com.hull.warnings"

// splitCommand splits the effective entrypoint into Docker's Path and Args.
func splitCommand(entrypoint, cmd []string) (string, []string) {
	all := make([]string, 0, len(entrypoint)+len(cmd))
	all = append(all, entrypoint...)
	all = append(all, cmd...)
	if len(all) == 0 {
		return "", nil
	}
	return all[0], all[1:]
}

// containerState renders the State block.
//
// A frozen container reports as paused and never as exited: the scale-to-zero
// watcher freezes idle containers behind the user's back, and a compose
// reconciliation loop that saw "exited" would recreate a container that is
// merely asleep.
func containerState(c *types.Container) *ContainerState {
	st := &ContainerState{
		Status:     string(c.State),
		Running:    c.State == types.StateRunning || c.State == types.StatePaused,
		Paused:     c.State == types.StatePaused,
		Restarting: c.State == types.StateRestarting,
		OOMKilled:  c.OOMKilled,
		Dead:       c.State == types.StateDead,
		Pid:        c.Pid,
		ExitCode:   c.ExitCode,
		Error:      c.Error,
		StartedAt:  timeString(c.StartedAt),
		FinishedAt: timeString(c.FinishedAt),
	}
	if c.Health != nil {
		h := &Health{
			Status:        c.Health.Status,
			FailingStreak: c.Health.FailingStreak,
			Log:           make([]*HealthLog, 0, len(c.Health.Log)),
		}
		for _, l := range c.Health.Log {
			h.Log = append(h.Log, &HealthLog{
				Start:    timeString(l.Start),
				End:      timeString(l.End),
				ExitCode: l.ExitCode,
				Output:   l.Output,
			})
		}
		st.Health = h
	}
	return st
}

// containerConfigToAPI renders the Config block.
func containerConfigToAPI(c *types.Container) *ContainerConfig {
	cfg := &ContainerConfig{
		Hostname:     c.Config.Hostname,
		Domainname:   c.Config.Domainname,
		User:         c.Config.User,
		AttachStdin:  c.Config.AttachStdin,
		AttachStdout: c.Config.AttachStdout,
		AttachStderr: c.Config.AttachStderr,
		ExposedPorts: c.Config.ExposedPorts,
		Tty:          c.Config.Tty,
		OpenStdin:    c.Config.OpenStdin,
		StdinOnce:    c.Config.StdinOnce,
		Env:          stringsOrEmpty(c.Config.Env),
		Cmd:          stringsOrNil(c.Config.Cmd),
		Image:        c.ImageRef,
		Volumes:      c.Config.Volumes,
		WorkingDir:   c.Config.WorkingDir,
		Entrypoint:   stringsOrNil(c.Config.Entrypoint),
		OnBuild:      nil,
		Labels:       mapOrEmpty(c.Config.Labels),
		StopSignal:   c.Config.StopSignal,
		StopTimeout:  c.Config.StopTimeout,
	}
	if c.Config.Healthcheck != nil {
		cfg.Healthcheck = healthcheckToAPI(c.Config.Healthcheck)
	}
	if cfg.Volumes == nil {
		cfg.Volumes = map[string]struct{}{}
	}
	return cfg
}

// healthcheckToAPI converts hull's healthcheck into Docker's nanosecond form.
func healthcheckToAPI(h *types.Healthcheck) *HealthConfig {
	if h == nil {
		return nil
	}
	return &HealthConfig{
		Test:        stringsOrNil(h.Test),
		Interval:    int64(h.Interval),
		Timeout:     int64(h.Timeout),
		StartPeriod: int64(h.StartPeriod),
		Retries:     h.Retries,
	}
}

// healthcheckFromAPI converts Docker's nanosecond form back into hull's.
func healthcheckFromAPI(h *HealthConfig) *types.Healthcheck {
	if h == nil {
		return nil
	}
	return &types.Healthcheck{
		Test:        stringsOrNil(h.Test),
		Interval:    time.Duration(h.Interval),
		Timeout:     time.Duration(h.Timeout),
		StartPeriod: time.Duration(h.StartPeriod),
		Retries:     h.Retries,
	}
}

// hostConfigToAPI renders the HostConfig block.
func hostConfigToAPI(h types.HostConfig) *HostConfig {
	out := &HostConfig{
		Binds:           stringsOrNil(h.Binds),
		ContainerIDFile: "",
		LogConfig:       LogConfig{Type: h.LogConfig.Type, Config: mapOrEmpty(h.LogConfig.Config)},
		NetworkMode:     h.NetworkMode,
		PortBindings:    portBindingsToAPI(h.PortBindings),
		RestartPolicy: RestartPolicy{
			Name:              h.RestartPolicy.Name,
			MaximumRetryCount: h.RestartPolicy.MaximumRetryCount,
		},
		AutoRemove:        h.AutoRemove,
		VolumesFrom:       nil,
		CapAdd:            stringsOrNil(h.CapAdd),
		CapDrop:           stringsOrNil(h.CapDrop),
		CgroupnsMode:      "private",
		DNS:               stringsOrEmpty(h.DNS),
		DNSOptions:        []string{},
		DNSSearch:         stringsOrEmpty(h.DNSSearch),
		ExtraHosts:        stringsOrNil(h.ExtraHosts),
		GroupAdd:          stringsOrNil(h.GroupAdd),
		IpcMode:           "private",
		PidMode:           "",
		UTSMode:           "",
		OomScoreAdj:       h.OomScoreAdj,
		Privileged:        h.Privileged,
		PublishAllPorts:   h.PublishAll,
		ReadonlyRootfs:    h.ReadonlyRootfs,
		SecurityOpt:       stringsOrNil(h.SecurityOpt),
		Tmpfs:             h.Tmpfs,
		UsernsMode:        h.UsernsMode,
		ShmSize:           h.ShmSize,
		Sysctls:           h.Sysctls,
		Runtime:           h.Runtime,
		Isolation:         h.Isolation,
		CPUShares:         h.Resources.CPUShares,
		Memory:            h.Resources.Memory,
		NanoCPUs:          h.Resources.NanoCPUs,
		BlkioWeight:       h.Resources.BlkioWeight,
		CPUPeriod:         h.Resources.CPUPeriod,
		CPUQuota:          h.Resources.CPUQuota,
		CpusetCpus:        h.Resources.CpusetCpus,
		CpusetMems:        h.Resources.CpusetMems,
		MemoryReservation: h.Resources.MemoryReservation,
		MemorySwap:        h.Resources.MemorySwap,
		PidsLimit:         h.PidsLimit,
		Ulimits:           ulimitsToAPI(h.Ulimits),
		Mounts:            mountsToAPI(h.Mounts),
		Devices:           devicesToAPI(h.Devices),
	}
	init := h.Init
	out.Init = &init
	return out
}

// ulimitsToAPI converts rlimit overrides.
func ulimitsToAPI(in []types.Ulimit) []Ulimit {
	if len(in) == 0 {
		return nil
	}
	out := make([]Ulimit, 0, len(in))
	for _, u := range in {
		out = append(out, Ulimit{Name: u.Name, Soft: u.Soft, Hard: u.Hard})
	}
	return out
}

// devicesToAPI converts device mappings.
func devicesToAPI(in []types.DeviceMapping) []DeviceMapping {
	if len(in) == 0 {
		return nil
	}
	out := make([]DeviceMapping, 0, len(in))
	for _, d := range in {
		out = append(out, DeviceMapping{
			PathOnHost:        d.PathOnHost,
			PathInContainer:   d.PathInContainer,
			CgroupPermissions: d.CgroupPermissions,
		})
	}
	return out
}

// mountsToAPI converts long-form mount requests.
func mountsToAPI(in []types.Mount) []Mount {
	if len(in) == 0 {
		return nil
	}
	out := make([]Mount, 0, len(in))
	for _, m := range in {
		am := Mount{
			Type:        m.Type,
			Source:      m.Source,
			Target:      m.Target,
			ReadOnly:    m.ReadOnly,
			Consistency: m.Consistency,
		}
		if m.BindOptions != nil {
			am.BindOptions = &MountBindOptions{
				Propagation:      m.BindOptions.Propagation,
				CreateMountpoint: m.BindOptions.CreateMountpoint,
			}
		}
		if m.TmpfsOptions != nil {
			am.TmpfsOptions = &MountTmpfsOptions{
				SizeBytes: m.TmpfsOptions.SizeBytes,
				Mode:      m.TmpfsOptions.Mode,
			}
		}
		out = append(out, am)
	}
	return out
}

// mountPoints renders the resolved Mounts array of an inspect document.
func mountPoints(c *types.Container) []MountPoint {
	out := make([]MountPoint, 0, len(c.HostConfig.Mounts))
	for _, m := range c.HostConfig.Mounts {
		mp := MountPoint{
			Type:        m.Type,
			Source:      m.Source,
			Destination: m.Target,
			Mode:        "",
			RW:          !m.ReadOnly,
			Propagation: "rprivate",
		}
		if m.Type == "volume" {
			mp.Name = m.Source
			mp.Driver = "local"
		}
		if m.BindOptions != nil && m.BindOptions.Propagation != "" {
			mp.Propagation = m.BindOptions.Propagation
		}
		out = append(out, mp)
	}
	return out
}

// portBindingsToAPI converts hull's port bindings into Docker's PortMap.
func portBindingsToAPI(in map[string][]types.PortBinding) PortMap {
	out := PortMap{}
	for port, bindings := range in {
		if len(bindings) == 0 {
			out[port] = nil
			continue
		}
		converted := make([]PortBinding, 0, len(bindings))
		for _, b := range bindings {
			converted = append(converted, PortBinding{HostIP: b.HostIP, HostPort: b.HostPort})
		}
		out[port] = converted
	}
	return out
}

// portBindingsFromAPI converts Docker's PortMap into hull's bindings.
func portBindingsFromAPI(in PortMap) map[string][]types.PortBinding {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]types.PortBinding, len(in))
	for port, bindings := range in {
		converted := make([]types.PortBinding, 0, len(bindings))
		for _, b := range bindings {
			converted = append(converted, types.PortBinding{HostIP: b.HostIP, HostPort: b.HostPort})
		}
		out[port] = converted
	}
	return out
}

// networkSettingsToAPI renders the NetworkSettings block of an inspect
// document, including the flattened default-network fields old clients read.
func networkSettingsToAPI(c *types.Container) *NetworkSettings {
	ns := &NetworkSettings{
		SandboxID:              c.NetworkSettings.SandboxKey,
		SandboxKey:             c.NetworkSettings.SandboxKey,
		Ports:                  inspectPorts(c),
		SecondaryIPAddresses:   []string{},
		SecondaryIPv6Addresses: []string{},
		Networks:               map[string]*EndpointSettings{},
	}
	names := make([]string, 0, len(c.NetworkSettings.Networks))
	for name := range c.NetworkSettings.Networks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ep := c.NetworkSettings.Networks[name]
		ns.Networks[name] = &EndpointSettings{
			IPAMConfig:  nil,
			Links:       nil,
			Aliases:     stringsOrNil(ep.Aliases),
			MacAddress:  ep.MacAddress,
			DriverOpts:  nil,
			NetworkID:   ep.NetworkID,
			EndpointID:  ep.EndpointID,
			Gateway:     ep.Gateway,
			IPAddress:   ep.IPAddress,
			IPPrefixLen: ep.IPPrefixLen,
			DNSNames:    stringsOrNil(ep.DNSNames),
		}
	}
	// The flattened fields describe whichever network sorts first, which is
	// what Docker does for the default bridge.
	if len(names) > 0 {
		first := ns.Networks[names[0]]
		ns.Bridge = names[0]
		ns.EndpointID = first.EndpointID
		ns.Gateway = first.Gateway
		ns.IPAddress = first.IPAddress
		ns.IPPrefixLen = first.IPPrefixLen
		ns.MacAddress = first.MacAddress
	}
	return ns
}

// inspectPorts merges the container's exposed ports with its published ones,
// so an exposed-but-unpublished port appears with a null binding the way
// Docker reports it.
func inspectPorts(c *types.Container) PortMap {
	out := PortMap{}
	for port := range c.Config.ExposedPorts {
		out[port] = nil
	}
	for port, bindings := range c.NetworkSettings.Ports {
		if len(bindings) == 0 {
			if _, ok := out[port]; !ok {
				out[port] = nil
			}
			continue
		}
		converted := make([]PortBinding, 0, len(bindings))
		for _, b := range bindings {
			converted = append(converted, PortBinding{HostIP: b.HostIP, HostPort: b.HostPort})
		}
		out[port] = converted
	}
	return out
}

// summaryPorts renders the flat Ports array of a container listing. It is a
// different shape from the inspect document's map and both are load-bearing.
func summaryPorts(c *types.Container) []Port {
	seen := map[string]bool{}
	out := make([]Port, 0, len(c.NetworkSettings.Ports))
	for spec, bindings := range c.NetworkSettings.Ports {
		priv, proto, err := splitPortSpec(spec)
		if err != nil {
			continue
		}
		seen[spec] = true
		if len(bindings) == 0 {
			out = append(out, Port{PrivatePort: priv, Type: proto})
			continue
		}
		for _, b := range bindings {
			pub, _ := strconv.ParseUint(b.HostPort, 10, 16)
			ip := b.HostIP
			if ip == "" {
				ip = "0.0.0.0"
			}
			out = append(out, Port{IP: ip, PrivatePort: priv, PublicPort: uint16(pub), Type: proto})
		}
	}
	for spec := range c.Config.ExposedPorts {
		if seen[spec] {
			continue
		}
		priv, proto, err := splitPortSpec(spec)
		if err != nil {
			continue
		}
		out = append(out, Port{PrivatePort: priv, Type: proto})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PrivatePort != out[j].PrivatePort {
			return out[i].PrivatePort < out[j].PrivatePort
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].PublicPort < out[j].PublicPort
	})
	return out
}

// splitPortSpec parses "80/tcp" into its port and protocol.
func splitPortSpec(spec string) (uint16, string, error) {
	portStr, proto, ok := strings.Cut(spec, "/")
	if !ok {
		proto = "tcp"
	}
	n, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, "", fmt.Errorf("api: %q is not a port specification: %w", spec, err)
	}
	return uint16(n), proto, nil
}

// containerSummary renders one container as a listing entry.
func containerSummary(c *types.Container, now time.Time) *ContainerSummary {
	cmd := append(append([]string{}, c.Config.Entrypoint...), c.Config.Cmd...)
	sum := &ContainerSummary{
		ID:         c.ID,
		Names:      []string{"/" + c.Name},
		Image:      c.ImageRef,
		ImageID:    c.Image,
		Command:    strings.Join(cmd, " "),
		Created:    c.Created.Unix(),
		Ports:      summaryPorts(c),
		Labels:     mapOrEmpty(c.Config.Labels),
		State:      string(c.State),
		Status:     humanStatus(c, now),
		HostConfig: ContainerSummaryHostConfig{NetworkMode: c.HostConfig.NetworkMode},
		Mounts:     mountPoints(c),
	}
	ns := &SummaryNetworkSettings{Networks: map[string]*EndpointSettings{}}
	for name, ep := range c.NetworkSettings.Networks {
		ns.Networks[name] = &EndpointSettings{
			Aliases:     stringsOrNil(ep.Aliases),
			MacAddress:  ep.MacAddress,
			NetworkID:   ep.NetworkID,
			EndpointID:  ep.EndpointID,
			Gateway:     ep.Gateway,
			IPAddress:   ep.IPAddress,
			IPPrefixLen: ep.IPPrefixLen,
			DNSNames:    stringsOrNil(ep.DNSNames),
		}
	}
	sum.NetworkSettings = ns
	return sum
}

// humanStatus renders the Status column exactly as `docker ps` prints it.
// Clients display it verbatim, and at least one test framework parses the
// "(healthy)" suffix out of it.
func humanStatus(c *types.Container, now time.Time) string {
	switch c.State {
	case types.StateCreated:
		return "Created"
	case types.StateRunning:
		s := "Up " + formatDuration(now.Sub(c.StartedAt))
		if c.Health != nil && c.Health.Status != "" {
			s += " (" + c.Health.Status + ")"
		}
		return s
	case types.StatePaused:
		return "Up " + formatDuration(now.Sub(c.StartedAt)) + " (Paused)"
	case types.StateRestarting:
		return fmt.Sprintf("Restarting (%d) %s ago", c.ExitCode, formatDuration(now.Sub(c.FinishedAt)))
	case types.StateRemoving:
		return "Removal In Progress"
	case types.StateDead:
		return "Dead"
	default:
		if c.FinishedAt.IsZero() {
			return fmt.Sprintf("Exited (%d)", c.ExitCode)
		}
		return fmt.Sprintf("Exited (%d) %s ago", c.ExitCode, formatDuration(now.Sub(c.FinishedAt)))
	}
}

// imageSummary renders one image as a listing entry.
func imageSummary(img *types.Image) *ImageSummary {
	return &ImageSummary{
		ID:          img.ID,
		ParentID:    "",
		RepoTags:    repoTags(img),
		RepoDigests: stringsOrEmpty(img.RepoDigests),
		Created:     img.Created.Unix(),
		Size:        img.Size,
		SharedSize:  -1,
		VirtualSize: img.Size,
		Labels:      mapOrEmpty(img.Labels),
		Containers:  -1,
	}
}

// repoTags returns an image's tags, substituting Docker's "<none>:<none>"
// placeholder for a dangling image, which is what the CLI prints.
func repoTags(img *types.Image) []string {
	if len(img.RepoTags) == 0 {
		return []string{"<none>:<none>"}
	}
	return img.RepoTags
}

// imageInspect renders one image as the inspect document.
func imageInspect(img *types.Image) *ImageInspect {
	cfg := &ContainerConfig{
		User:         img.Config.User,
		ExposedPorts: img.Config.ExposedPorts,
		Env:          stringsOrEmpty(img.Config.Env),
		Cmd:          stringsOrNil(img.Config.Cmd),
		Entrypoint:   stringsOrNil(img.Config.Entrypoint),
		Volumes:      img.Config.Volumes,
		WorkingDir:   img.Config.WorkingDir,
		Labels:       mapOrEmpty(img.Config.Labels),
		StopSignal:   img.Config.StopSignal,
		Shell:        stringsOrNil(img.Config.Shell),
		Healthcheck:  healthcheckToAPI(img.Config.Healthcheck),
	}
	if cfg.Volumes == nil {
		cfg.Volumes = map[string]struct{}{}
	}
	return &ImageInspect{
		ID:            img.ID,
		RepoTags:      stringsOrEmpty(img.RepoTags),
		RepoDigests:   stringsOrEmpty(img.RepoDigests),
		Parent:        "",
		Comment:       "",
		Created:       timeString(img.Created),
		DockerVersion: "",
		Author:        "",
		Config:        cfg,
		Architecture:  img.Architecture,
		Os:            img.OS,
		Size:          img.Size,
		VirtualSize:   img.Size,
		GraphDriver:   GraphDriverData{Name: "overlay2", Data: map[string]string{}},
		RootFS:        ImageRootFS{Type: "layers", Layers: stringsOrEmpty(img.DiffIDs)},
		Metadata:      ImageMetadata{LastTagTime: timeString(time.Time{})},
	}
}

// networkResource renders one network as the API reports it.
func networkResource(n *types.Network, containers map[string]NetworkContainer) *NetworkResource {
	res := &NetworkResource{
		Name:       n.Name,
		ID:         n.ID,
		Created:    timeString(n.Created),
		Scope:      orDefault(n.Scope, "local"),
		Driver:     n.Driver,
		EnableIPv6: n.EnableIPv6,
		IPAM: IPAM{
			Driver:  orDefault(n.IPAM.Driver, "default"),
			Config:  []IPAMConfigEntry{},
			Options: nil,
		},
		Internal:   n.Internal,
		Attachable: n.Attachable,
		Containers: containers,
		Options:    mapOrEmpty(n.Options),
		Labels:     mapOrEmpty(n.Labels),
	}
	if n.IPAM.Subnet != "" || n.IPAM.Gateway != "" {
		res.IPAM.Config = append(res.IPAM.Config, IPAMConfigEntry{
			Subnet:             n.IPAM.Subnet,
			IPRange:            n.IPAM.IPRange,
			Gateway:            n.IPAM.Gateway,
			AuxiliaryAddresses: n.IPAM.AuxAddresses,
		})
	}
	if res.Containers == nil {
		res.Containers = map[string]NetworkContainer{}
	}
	return res
}

// networkContainers renders a network's attached containers.
func networkContainers(n *types.Network) map[string]NetworkContainer {
	out := make(map[string]NetworkContainer, len(n.Containers))
	for id, ep := range n.Containers {
		addr := ep.IPAddress
		if addr != "" && ep.IPPrefixLen > 0 {
			addr = addr + "/" + strconv.Itoa(ep.IPPrefixLen)
		}
		name := ""
		if len(ep.DNSNames) > 0 {
			name = ep.DNSNames[0]
		}
		out[id] = NetworkContainer{
			Name:        name,
			EndpointID:  ep.EndpointID,
			MacAddress:  ep.MacAddress,
			IPv4Address: addr,
		}
	}
	return out
}

// volumeToAPI renders one volume as the API reports it.
func volumeToAPI(v *types.Volume) *Volume {
	return &Volume{
		Name:       v.Name,
		Driver:     orDefault(v.Driver, "local"),
		Mountpoint: v.Mountpoint,
		CreatedAt:  v.Created.UTC().Format(time.RFC3339),
		Labels:     mapOrEmpty(v.Labels),
		Options:    mapOrEmpty(v.Options),
		Scope:      orDefault(v.Scope, "local"),
	}
}

// orDefault returns s, or def when s is empty.
func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// configFromCreate converts a create request into hull's domain model.
func configFromCreate(req *ContainerCreateRequest) (types.ContainerConfig, types.HostConfig) {
	cfg := types.ContainerConfig{
		Hostname:     req.Hostname,
		Domainname:   req.Domainname,
		User:         req.User,
		AttachStdin:  req.AttachStdin,
		AttachStdout: req.AttachStdout,
		AttachStderr: req.AttachStderr,
		Tty:          req.Tty,
		OpenStdin:    req.OpenStdin,
		StdinOnce:    req.StdinOnce,
		Env:          req.Env,
		Cmd:          req.Cmd,
		Entrypoint:   req.Entrypoint,
		WorkingDir:   req.WorkingDir,
		Labels:       req.Labels,
		ExposedPorts: req.ExposedPorts,
		StopSignal:   req.StopSignal,
		StopTimeout:  req.StopTimeout,
		Healthcheck:  healthcheckFromAPI(req.Healthcheck),
		Volumes:      req.Volumes,
	}
	var host types.HostConfig
	if req.HostConfig != nil {
		host = hostConfigFromAPI(req.HostConfig)
	}
	return cfg, host
}

// hostConfigFromAPI converts Docker's HostConfig into hull's.
func hostConfigFromAPI(h *HostConfig) types.HostConfig {
	out := types.HostConfig{
		Binds:        stringsOrNil(h.Binds),
		Mounts:       mountsFromAPI(h.Mounts),
		PortBindings: portBindingsFromAPI(h.PortBindings),
		PublishAll:   h.PublishAllPorts,
		NetworkMode:  h.NetworkMode,
		DNS:          stringsOrNil(h.DNS),
		DNSSearch:    stringsOrNil(h.DNSSearch),
		ExtraHosts:   stringsOrNil(h.ExtraHosts),
		RestartPolicy: types.RestartPolicy{
			Name:              h.RestartPolicy.Name,
			MaximumRetryCount: h.RestartPolicy.MaximumRetryCount,
		},
		AutoRemove:     h.AutoRemove,
		Privileged:     h.Privileged,
		ReadonlyRootfs: h.ReadonlyRootfs,
		CapAdd:         stringsOrNil(h.CapAdd),
		CapDrop:        stringsOrNil(h.CapDrop),
		SecurityOpt:    stringsOrNil(h.SecurityOpt),
		Sysctls:        h.Sysctls,
		Tmpfs:          h.Tmpfs,
		Runtime:        h.Runtime,
		ShmSize:        h.ShmSize,
		Isolation:      h.Isolation,
		LogConfig:      types.LogConfig{Type: h.LogConfig.Type, Config: h.LogConfig.Config},
		GroupAdd:       stringsOrNil(h.GroupAdd),
		OomScoreAdj:    h.OomScoreAdj,
		PidsLimit:      h.PidsLimit,
		UsernsMode:     h.UsernsMode,
		Resources:      resourcesFromAPI(h),
	}
	if h.Init != nil {
		out.Init = *h.Init
	}
	for _, u := range h.Ulimits {
		out.Ulimits = append(out.Ulimits, types.Ulimit{Name: u.Name, Soft: u.Soft, Hard: u.Hard})
	}
	for _, d := range h.Devices {
		out.Devices = append(out.Devices, types.DeviceMapping{
			PathOnHost:        d.PathOnHost,
			PathInContainer:   d.PathInContainer,
			CgroupPermissions: d.CgroupPermissions,
		})
	}
	return out
}

// resourcesFromAPI extracts the cgroup knobs from a Docker HostConfig.
func resourcesFromAPI(h *HostConfig) types.Resources {
	return types.Resources{
		Memory:            h.Memory,
		MemoryReservation: h.MemoryReservation,
		MemorySwap:        h.MemorySwap,
		CPUShares:         h.CPUShares,
		CPUQuota:          h.CPUQuota,
		CPUPeriod:         h.CPUPeriod,
		CpusetCpus:        h.CpusetCpus,
		CpusetMems:        h.CpusetMems,
		BlkioWeight:       h.BlkioWeight,
		NanoCPUs:          h.NanoCPUs,
	}
}

// mountsFromAPI converts Docker's long-form mounts into hull's.
func mountsFromAPI(in []Mount) []types.Mount {
	if len(in) == 0 {
		return nil
	}
	out := make([]types.Mount, 0, len(in))
	for _, m := range in {
		tm := types.Mount{
			Type:        m.Type,
			Source:      m.Source,
			Target:      m.Target,
			ReadOnly:    m.ReadOnly,
			Consistency: m.Consistency,
		}
		if m.BindOptions != nil {
			tm.BindOptions = &types.BindOptions{
				Propagation:      m.BindOptions.Propagation,
				CreateMountpoint: m.BindOptions.CreateMountpoint,
			}
		}
		if m.TmpfsOptions != nil {
			tm.TmpfsOptions = &types.TmpfsOptions{
				SizeBytes: m.TmpfsOptions.SizeBytes,
				Mode:      m.TmpfsOptions.Mode,
			}
		}
		out = append(out, tm)
	}
	return out
}

// historyItems converts the engine's history entries into Docker's shape.
func historyItems(in []engine.HistoryEntry) []HistoryResponseItem {
	out := make([]HistoryResponseItem, 0, len(in))
	for _, h := range in {
		out = append(out, HistoryResponseItem{
			ID:        h.ID,
			Created:   h.Created.Unix(),
			CreatedBy: h.CreatedBy,
			Tags:      stringsOrNil(h.Tags),
			Size:      h.Size,
			Comment:   h.Comment,
		})
	}
	return out
}

// imageDeleteItems converts the engine's removal report into Docker's shape.
func imageDeleteItems(in []engine.ImageDelete) []ImageDeleteResponseItem {
	out := make([]ImageDeleteResponseItem, 0, len(in))
	for _, d := range in {
		out = append(out, ImageDeleteResponseItem{Untagged: d.Untagged, Deleted: d.Deleted})
	}
	return out
}
