package client

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// The wire types in this file are the Docker Engine API's own JSON shapes, not
// hull's internal model. They are deliberately separate from internal/types:
// the engine speaks Docker's spelling on the wire — capitalised fields, a
// leading slash on container names, unix timestamps — so that the stock docker
// CLI, compose and Testcontainers work against hulld unchanged, and this
// client therefore works against a real dockerd too.

// Port is one published port as a container listing reports it. A listing and
// an inspect describe the same data in different shapes: this one, and
// NetworkSettings.Ports. Both have to be right.
type Port struct {
	// IP is the host address the port is bound on, empty for all addresses.
	IP string `json:"IP,omitempty"`
	// PrivatePort is the port inside the container.
	PrivatePort uint16 `json:"PrivatePort"`
	// PublicPort is the host port, zero when the port is only exposed.
	PublicPort uint16 `json:"PublicPort,omitempty"`
	// Type is "tcp" or "udp".
	Type string `json:"Type"`
}

// PortBinding is one host side of a published port, as inspect reports it.
type PortBinding struct {
	// HostIP is the host address, empty for all addresses.
	HostIP string `json:"HostIp"`
	// HostPort is the host port as a string, because Docker allows a range.
	HostPort string `json:"HostPort"`
}

// HealthConfig is the image or container healthcheck. Docker encodes the
// durations as nanosecond integers, which time.Duration marshals to natively.
type HealthConfig struct {
	// Test is the probe, starting with "CMD", "CMD-SHELL" or "NONE".
	Test []string `json:"Test,omitempty"`
	// Interval is the gap between probes.
	Interval time.Duration `json:"Interval,omitempty"`
	// Timeout bounds one probe.
	Timeout time.Duration `json:"Timeout,omitempty"`
	// StartPeriod is the grace period before failures count.
	StartPeriod time.Duration `json:"StartPeriod,omitempty"`
	// Retries is how many consecutive failures mean unhealthy.
	Retries int `json:"Retries,omitempty"`
}

// Config is the container's process configuration, in Docker's spelling.
type Config struct {
	// Hostname and Domainname name the container inside its UTS namespace.
	Hostname   string `json:"Hostname,omitempty"`
	Domainname string `json:"Domainname,omitempty"`
	// User is a "user", "uid", "user:group" or "uid:gid" string.
	User string `json:"User,omitempty"`
	// AttachStdin, AttachStdout and AttachStderr record which streams the
	// creating client intends to consume.
	AttachStdin  bool `json:"AttachStdin"`
	AttachStdout bool `json:"AttachStdout"`
	AttachStderr bool `json:"AttachStderr"`
	// ExposedPorts is the set of "port/proto" keys declared by the image or
	// the user.
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	// Tty allocates a pseudo-terminal.
	Tty bool `json:"Tty"`
	// OpenStdin keeps stdin open; StdinOnce closes it after the first
	// attached client detaches.
	OpenStdin bool `json:"OpenStdin"`
	StdinOnce bool `json:"StdinOnce"`
	// Env is the environment as "K=V" strings.
	Env []string `json:"Env,omitempty"`
	// Cmd overrides the image's command.
	Cmd []string `json:"Cmd,omitempty"`
	// Healthcheck overrides the image's healthcheck.
	Healthcheck *HealthConfig `json:"Healthcheck,omitempty"`
	// Image is the reference the container was created from.
	Image string `json:"Image,omitempty"`
	// Volumes is the set of anonymous volume mountpoints.
	Volumes map[string]struct{} `json:"Volumes,omitempty"`
	// WorkingDir is the process's initial directory.
	WorkingDir string `json:"WorkingDir,omitempty"`
	// Entrypoint overrides the image's entrypoint.
	Entrypoint []string `json:"Entrypoint,omitempty"`
	// Labels are user metadata.
	Labels map[string]string `json:"Labels,omitempty"`
	// StopSignal is the signal a stop sends first, e.g. "SIGTERM".
	StopSignal string `json:"StopSignal,omitempty"`
	// StopTimeout is the seconds to wait before SIGKILL.
	StopTimeout *int `json:"StopTimeout,omitempty"`
	// Shell is the shell used by CMD-SHELL healthchecks.
	Shell []string `json:"Shell,omitempty"`
}

// RestartPolicy mirrors Docker's restart policy.
type RestartPolicy struct {
	// Name is "", "no", "always", "unless-stopped" or "on-failure".
	Name string `json:"Name,omitempty"`
	// MaximumRetryCount bounds "on-failure".
	MaximumRetryCount int `json:"MaximumRetryCount,omitempty"`
}

// LogConfig selects the log driver. hull ships "json-file" and "none".
type LogConfig struct {
	// Type is the driver name.
	Type string `json:"Type,omitempty"`
	// Config is the driver's options.
	Config map[string]string `json:"Config,omitempty"`
}

// Ulimit is one rlimit override.
type Ulimit struct {
	// Name is the rlimit name without its RLIMIT_ prefix, e.g. "nofile".
	Name string `json:"Name"`
	// Soft and Hard are the two halves of the limit.
	Soft int64 `json:"Soft"`
	Hard int64 `json:"Hard"`
}

// DeviceMapping exposes a host device inside the container.
type DeviceMapping struct {
	// PathOnHost is the device node on the host.
	PathOnHost string `json:"PathOnHost"`
	// PathInContainer is where it appears inside.
	PathInContainer string `json:"PathInContainer"`
	// CgroupPermissions is the rwm string.
	CgroupPermissions string `json:"CgroupPermissions"`
}

// BindOptions carries bind-mount specifics.
type BindOptions struct {
	// Propagation is the mount propagation mode.
	Propagation string `json:"Propagation,omitempty"`
	// CreateMountpoint creates a missing target.
	CreateMountpoint bool `json:"CreateMountpoint,omitempty"`
}

// TmpfsOptions carries tmpfs specifics.
type TmpfsOptions struct {
	// SizeBytes caps the filesystem.
	SizeBytes int64 `json:"SizeBytes,omitempty"`
	// Mode is the root directory's permission bits.
	Mode uint32 `json:"Mode,omitempty"`
}

// VolumeOptions carries named-volume specifics.
type VolumeOptions struct {
	// NoCopy skips seeding the volume from the image.
	NoCopy bool `json:"NoCopy,omitempty"`
	// Labels are applied to a volume created on demand.
	Labels map[string]string `json:"Labels,omitempty"`
}

// Mount is a long-form --mount request.
type Mount struct {
	// Type is "bind", "volume" or "tmpfs".
	Type string `json:"Type"`
	// Source is the host path or volume name.
	Source string `json:"Source,omitempty"`
	// Target is the path inside the container.
	Target string `json:"Target"`
	// ReadOnly mounts without write access.
	ReadOnly bool `json:"ReadOnly,omitempty"`
	// BindOptions, VolumeOptions and TmpfsOptions are type-specific.
	BindOptions   *BindOptions   `json:"BindOptions,omitempty"`
	VolumeOptions *VolumeOptions `json:"VolumeOptions,omitempty"`
	TmpfsOptions  *TmpfsOptions  `json:"TmpfsOptions,omitempty"`
}

// MountPoint is one resolved mount, as inspect and the listing report it.
type MountPoint struct {
	// Type is "bind", "volume" or "tmpfs".
	Type string `json:"Type,omitempty"`
	// Name is the volume name, empty for a bind.
	Name string `json:"Name,omitempty"`
	// Source is the host path backing the mount.
	Source string `json:"Source"`
	// Destination is the path inside the container.
	Destination string `json:"Destination"`
	// Driver is the volume driver.
	Driver string `json:"Driver,omitempty"`
	// Mode is the raw mode string from a -v spec.
	Mode string `json:"Mode"`
	// RW reports write access.
	RW bool `json:"RW"`
	// Propagation is the mount propagation mode.
	Propagation string `json:"Propagation"`
}

// Resources are the cgroup knobs the API carries. Docker inlines them into
// HostConfig and repeats them in the update request, so they live in their own
// struct and are embedded in both.
type Resources struct {
	// Memory, MemoryReservation and MemorySwap are byte limits.
	Memory            int64 `json:"Memory,omitempty"`
	MemoryReservation int64 `json:"MemoryReservation,omitempty"`
	MemorySwap        int64 `json:"MemorySwap,omitempty"`
	// CPUShares maps to cpu.weight; CPUQuota over CPUPeriod is cpu.max.
	CPUShares int64 `json:"CpuShares,omitempty"`
	CPUQuota  int64 `json:"CpuQuota,omitempty"`
	CPUPeriod int64 `json:"CpuPeriod,omitempty"`
	// NanoCPUs is --cpus expressed in billionths of a CPU.
	NanoCPUs int64 `json:"NanoCpus,omitempty"`
	// CpusetCpus and CpusetMems pin the container to cores and nodes.
	CpusetCpus string `json:"CpusetCpus,omitempty"`
	CpusetMems string `json:"CpusetMems,omitempty"`
	// BlkioWeight maps to io.weight.
	BlkioWeight uint16 `json:"BlkioWeight,omitempty"`
	// PidsLimit caps the pids controller.
	PidsLimit *int64 `json:"PidsLimit,omitempty"`
	// Devices exposes host devices.
	Devices []DeviceMapping `json:"Devices,omitempty"`
	// Ulimits are rlimit overrides.
	Ulimits []Ulimit `json:"Ulimits,omitempty"`
	// OomScoreAdj biases the OOM killer.
	OomScoreAdj int `json:"OomScoreAdj,omitempty"`
}

// HostConfig is everything the host decides about a container.
type HostConfig struct {
	// Resources are the cgroup limits. They are embedded so the JSON stays
	// flat, which is the shape Docker's API defines, while a caller can still
	// set them as one group in a composite literal.
	Resources

	// Binds are short-form "-v" specs.
	Binds []string `json:"Binds,omitempty"`
	// Mounts are long-form "--mount" specs.
	Mounts []Mount `json:"Mounts,omitempty"`
	// PortBindings maps "port/proto" to its host bindings.
	PortBindings map[string][]PortBinding `json:"PortBindings,omitempty"`
	// PublishAllPorts publishes every exposed port on a random host port.
	PublishAllPorts bool `json:"PublishAllPorts,omitempty"`
	// NetworkMode is "bridge", "host", "none", "container:<id>" or a network
	// name.
	NetworkMode string `json:"NetworkMode,omitempty"`
	// DNS, DNSSearch and DNSOptions configure the resolver.
	DNS        []string `json:"Dns,omitempty"`
	DNSSearch  []string `json:"DnsSearch,omitempty"`
	DNSOptions []string `json:"DnsOptions,omitempty"`
	// ExtraHosts are "name:ip" entries written into /etc/hosts.
	ExtraHosts []string `json:"ExtraHosts,omitempty"`
	// RestartPolicy governs automatic restarts.
	RestartPolicy RestartPolicy `json:"RestartPolicy,omitzero"`
	// AutoRemove deletes the container when it exits.
	AutoRemove bool `json:"AutoRemove,omitempty"`
	// Privileged disables every confinement.
	Privileged bool `json:"Privileged,omitempty"`
	// ReadonlyRootfs mounts the container's root read-only.
	ReadonlyRootfs bool `json:"ReadonlyRootfs,omitempty"`
	// CapAdd and CapDrop adjust the capability set.
	CapAdd  []string `json:"CapAdd,omitempty"`
	CapDrop []string `json:"CapDrop,omitempty"`
	// SecurityOpt carries seccomp, apparmor and no-new-privileges options.
	SecurityOpt []string `json:"SecurityOpt,omitempty"`
	// Sysctls are kernel parameters set inside the container's namespaces.
	Sysctls map[string]string `json:"Sysctls,omitempty"`
	// Tmpfs maps a path to its tmpfs mount options.
	Tmpfs map[string]string `json:"Tmpfs,omitempty"`
	// Init runs a minimal pid 1 that reaps zombies.
	Init *bool `json:"Init,omitempty"`
	// Runtime selects "hull" (native) or "crun".
	Runtime string `json:"Runtime,omitempty"`
	// ShmSize is the size of /dev/shm in bytes.
	ShmSize int64 `json:"ShmSize,omitempty"`
	// Isolation is hull's per-container isolation tier: "", "userns", "host"
	// or "gvisor".
	Isolation string `json:"Isolation,omitempty"`
	// LogConfig selects the log driver.
	LogConfig LogConfig `json:"LogConfig,omitzero"`
	// GroupAdd lists supplementary groups.
	GroupAdd []string `json:"GroupAdd,omitempty"`
	// UsernsMode is "" or "host".
	UsernsMode string `json:"UsernsMode,omitempty"`
	// StorageOpt carries driver options. hull also parks out-of-band hints
	// here — "hull.platform" is where the CLI puts --platform so the create
	// body stays exactly Docker's shape.
	StorageOpt map[string]string `json:"StorageOpt,omitempty"`

	// HullIdleFreeze is hull's per-container idle freeze delay, as a Go
	// duration string. A Docker daemon ignores it.
	HullIdleFreeze string `json:"HullIdleFreeze,omitempty"`
	// HullExplain asks the engine to narrate every kernel step it takes.
	HullExplain bool `json:"HullExplain,omitempty"`
	// HullBudget is a soft resource budget, e.g. "mem=2G,cpu=2".
	HullBudget string `json:"HullBudget,omitempty"`
}

// EndpointIPAMConfig requests a fixed address on one network.
type EndpointIPAMConfig struct {
	// IPv4Address is the address to assign.
	IPv4Address string `json:"IPv4Address,omitempty"`
	// IPv6Address is recorded but not allocated by hull.
	IPv6Address string `json:"IPv6Address,omitempty"`
}

// EndpointSettings is one container's attachment to one network.
type EndpointSettings struct {
	// IPAMConfig requests a fixed address.
	IPAMConfig *EndpointIPAMConfig `json:"IPAMConfig,omitempty"`
	// Aliases are extra names the container answers to on this network.
	Aliases []string `json:"Aliases,omitempty"`
	// DNSNames are additional resolvable names.
	DNSNames []string `json:"DNSNames,omitempty"`
	// NetworkID and EndpointID identify the attachment.
	NetworkID  string `json:"NetworkID,omitempty"`
	EndpointID string `json:"EndpointID,omitempty"`
	// Gateway, IPAddress and IPPrefixLen are the assigned addressing.
	Gateway     string `json:"Gateway,omitempty"`
	IPAddress   string `json:"IPAddress,omitempty"`
	IPPrefixLen int    `json:"IPPrefixLen,omitempty"`
	// MacAddress is the container-side interface address.
	MacAddress string `json:"MacAddress,omitempty"`
}

// NetworkingConfig carries per-network settings at create time.
type NetworkingConfig struct {
	// EndpointsConfig maps a network name to its endpoint settings.
	EndpointsConfig map[string]*EndpointSettings `json:"EndpointsConfig,omitempty"`
}

// NetworkSettings is the container-side view of its attachments.
type NetworkSettings struct {
	// Bridge, SandboxID and SandboxKey describe the network sandbox.
	Bridge     string `json:"Bridge,omitempty"`
	SandboxID  string `json:"SandboxID,omitempty"`
	SandboxKey string `json:"SandboxKey,omitempty"`
	// Ports maps "port/proto" to its host bindings — the inspect shape.
	Ports map[string][]PortBinding `json:"Ports,omitempty"`
	// IPAddress and friends describe the default network, kept for old
	// clients that never learned to read Networks.
	IPAddress   string `json:"IPAddress,omitempty"`
	IPPrefixLen int    `json:"IPPrefixLen,omitempty"`
	Gateway     string `json:"Gateway,omitempty"`
	MacAddress  string `json:"MacAddress,omitempty"`
	// Networks is the real attachment table.
	Networks map[string]*EndpointSettings `json:"Networks,omitempty"`
}

// SummaryNetworkSettings is the cut-down network view in a listing.
type SummaryNetworkSettings struct {
	// Networks maps a network name to its endpoint settings.
	Networks map[string]*EndpointSettings `json:"Networks,omitempty"`
}

// ContainerSummary is one row of GET /containers/json.
type ContainerSummary struct {
	// ID is the full container id.
	ID string `json:"Id"`
	// Names are the container's names, each with a leading slash. Compose
	// matches on that slash, so it is never stripped on the wire.
	Names []string `json:"Names"`
	// Image is the reference the container was created from.
	Image string `json:"Image"`
	// ImageID is the resolved image id.
	ImageID string `json:"ImageID"`
	// Command is the container's command rendered as one string.
	Command string `json:"Command"`
	// Created is a unix timestamp in seconds.
	Created int64 `json:"Created"`
	// Ports are the exposed and published ports.
	Ports []Port `json:"Ports,omitempty"`
	// SizeRw and SizeRootFs are only present when size was requested.
	SizeRw     int64 `json:"SizeRw,omitempty"`
	SizeRootFs int64 `json:"SizeRootFs,omitempty"`
	// Labels are user metadata.
	Labels map[string]string `json:"Labels,omitempty"`
	// State is created, running, paused, restarting, removing, exited or
	// dead.
	State string `json:"State"`
	// Status is the human form, e.g. "Up 3 minutes".
	Status string `json:"Status"`
	// HostConfig carries just the network mode in a listing.
	HostConfig struct {
		// NetworkMode is the container's network mode.
		NetworkMode string `json:"NetworkMode,omitempty"`
	} `json:"HostConfig"`
	// NetworkSettings is the cut-down attachment table.
	NetworkSettings *SummaryNetworkSettings `json:"NetworkSettings,omitempty"`
	// Mounts are the container's mounts.
	Mounts []MountPoint `json:"Mounts,omitempty"`
}

// Name returns the container's primary name without the leading slash, which
// is what a listing prints.
func (c ContainerSummary) Name() string {
	if len(c.Names) == 0 {
		return ""
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

// CreatedAt returns the creation time.
func (c ContainerSummary) CreatedAt() time.Time { return time.Unix(c.Created, 0) }

// PortString renders the ports the way a listing does, e.g.
// "0.0.0.0:8080->80/tcp, 443/tcp".
func (c ContainerSummary) PortString() string {
	if len(c.Ports) == 0 {
		return ""
	}
	out := make([]string, 0, len(c.Ports))
	for _, p := range c.Ports {
		if p.PublicPort == 0 {
			out = append(out, strconv.Itoa(int(p.PrivatePort))+"/"+p.Type)
			continue
		}
		host := p.IP
		if host == "" {
			host = "0.0.0.0"
		}
		out = append(out, host+":"+strconv.Itoa(int(p.PublicPort))+"->"+
			strconv.Itoa(int(p.PrivatePort))+"/"+p.Type)
	}
	return strings.Join(out, ", ")
}

// NetworkNames returns the networks the container is attached to, for a
// listing's NETWORKS column.
func (c ContainerSummary) NetworkNames() []string {
	if c.NetworkSettings == nil {
		return nil
	}
	names := make([]string, 0, len(c.NetworkSettings.Networks))
	for name := range c.NetworkSettings.Networks {
		names = append(names, name)
	}
	return names
}

// Health is a container's healthcheck state.
type Health struct {
	// Status is "starting", "healthy" or "unhealthy".
	Status string `json:"Status"`
	// FailingStreak counts consecutive failures.
	FailingStreak int `json:"FailingStreak"`
	// Log holds the most recent probe results.
	Log []HealthLog `json:"Log,omitempty"`
}

// HealthLog is one probe result.
type HealthLog struct {
	// Start and End bound the probe.
	Start time.Time `json:"Start"`
	End   time.Time `json:"End"`
	// ExitCode is the probe's exit status.
	ExitCode int `json:"ExitCode"`
	// Output is the probe's combined output.
	Output string `json:"Output"`
}

// ContainerState is the runtime half of an inspect.
type ContainerState struct {
	// Status is the lifecycle state.
	Status string `json:"Status"`
	// Running, Paused, Restarting, OOMKilled and Dead are the boolean views
	// clients still read.
	Running    bool `json:"Running"`
	Paused     bool `json:"Paused"`
	Restarting bool `json:"Restarting"`
	OOMKilled  bool `json:"OOMKilled"`
	Dead       bool `json:"Dead"`
	// Pid is the container's init process on the host.
	Pid int `json:"Pid"`
	// ExitCode is meaningful once the container has exited.
	ExitCode int `json:"ExitCode"`
	// Error is the failure that stopped it, if any.
	Error string `json:"Error,omitempty"`
	// StartedAt and FinishedAt are RFC3339 timestamps.
	StartedAt  string `json:"StartedAt"`
	FinishedAt string `json:"FinishedAt"`
	// Health is the healthcheck state when one is configured.
	Health *Health `json:"Health,omitempty"`
}

// ContainerInspect is GET /containers/{id}/json.
type ContainerInspect struct {
	// ID is the full container id.
	ID string `json:"Id"`
	// Created is an RFC3339 timestamp.
	Created string `json:"Created"`
	// Path and Args are the resolved entrypoint and its arguments.
	Path string   `json:"Path"`
	Args []string `json:"Args"`
	// State is the runtime state.
	State *ContainerState `json:"State"`
	// Image is the image id.
	Image string `json:"Image"`
	// ResolvConfPath, HostnamePath and HostsPath are the sandbox files.
	ResolvConfPath string `json:"ResolvConfPath,omitempty"`
	HostnamePath   string `json:"HostnamePath,omitempty"`
	HostsPath      string `json:"HostsPath,omitempty"`
	// LogPath is the json-file driver's log.
	LogPath string `json:"LogPath,omitempty"`
	// Name carries a leading slash, which compose matches on.
	Name string `json:"Name"`
	// RestartCount counts automatic restarts.
	RestartCount int `json:"RestartCount"`
	// Driver is the storage driver.
	Driver string `json:"Driver,omitempty"`
	// Platform is the container's OS.
	Platform string `json:"Platform,omitempty"`
	// SizeRw and SizeRootFs are present when size was requested.
	SizeRw     *int64 `json:"SizeRw,omitempty"`
	SizeRootFs *int64 `json:"SizeRootFs,omitempty"`
	// Mounts are the resolved mounts.
	Mounts []MountPoint `json:"Mounts,omitempty"`
	// Config and HostConfig echo the creation request, merged with the image.
	Config     *Config     `json:"Config"`
	HostConfig *HostConfig `json:"HostConfig"`
	// NetworkSettings is the attachment table.
	NetworkSettings *NetworkSettings `json:"NetworkSettings"`
	// HullWarnings carries the warnings the engine produced while generating
	// this container's bundle — most importantly, that a resource limit could
	// not be enforced on a host with no delegated cgroup v2 controllers. It
	// is hull's own field; a Docker daemon never sets it.
	HullWarnings []string `json:"HullWarnings,omitempty"`
}

// ShortName returns the container name without its leading slash.
func (c ContainerInspect) ShortName() string { return strings.TrimPrefix(c.Name, "/") }

// Tty reports whether the container was created with a pseudo-terminal, which
// decides whether its streams are framed.
func (c ContainerInspect) Tty() bool { return c.Config != nil && c.Config.Tty }

// ContainerCreateRequest is the body of POST /containers/create.
//
// Docker flattens Config into the top level and nests the rest, so Config is
// embedded by value: the JSON stays exactly Docker's shape, req.Config still
// names the process configuration, and the whole request can be written as a
// single composite literal — which a promoted pointer field would forbid.
type ContainerCreateRequest struct {
	Config
	// HostConfig is the host half of the request.
	HostConfig *HostConfig `json:"HostConfig,omitempty"`
	// NetworkingConfig carries per-network endpoint settings.
	NetworkingConfig *NetworkingConfig `json:"NetworkingConfig,omitempty"`
}

// ContainerCreateResponse is what the engine returns from a create.
//
// Warnings is load-bearing: bundle generation returns warnings rather than
// failing when a requested resource limit cannot be enforced on this host's
// hybrid cgroups, and those warnings must reach the user or the container
// silently runs unlimited.
type ContainerCreateResponse struct {
	// ID is the new container's id.
	ID string `json:"Id"`
	// Warnings are the engine's non-fatal complaints about the request.
	Warnings []string `json:"Warnings,omitempty"`
}

// WaitResponse is what /wait returns.
type WaitResponse struct {
	// StatusCode is the container's exit status.
	StatusCode int `json:"StatusCode"`
	// Error carries a failure that prevented waiting.
	Error *WaitError `json:"Error,omitempty"`
}

// WaitError is the error half of a wait response.
type WaitError struct {
	// Message is the failure text.
	Message string `json:"Message"`
}

// TopResponse is the process table of one container.
type TopResponse struct {
	// Titles are the column headers.
	Titles []string `json:"Titles"`
	// Processes is one row per process, in the same column order.
	Processes [][]string `json:"Processes"`
}

// FilesystemChange is one entry of /changes.
type FilesystemChange struct {
	// Path is the container-absolute path that changed.
	Path string `json:"Path"`
	// Kind is 0 for modified, 1 for added and 2 for deleted.
	Kind int `json:"Kind"`
}

// Letter renders the change kind the way "hull diff" prints it.
func (c FilesystemChange) Letter() string {
	switch c.Kind {
	case 1:
		return "A"
	case 2:
		return "D"
	default:
		return "C"
	}
}

// ---------- images ----------

// ImageSummary is one row of GET /images/json.
type ImageSummary struct {
	// ID is the image id, the digest of its config blob.
	ID string `json:"Id"`
	// ParentID is the parent image id, when one was recorded.
	ParentID string `json:"ParentId,omitempty"`
	// RepoTags and RepoDigests are the references pointing at this image.
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests,omitempty"`
	// Created is a unix timestamp in seconds.
	Created int64 `json:"Created"`
	// Size is the sum of the uncompressed layer sizes.
	Size int64 `json:"Size"`
	// SharedSize and VirtualSize are reported for Docker compatibility.
	SharedSize  int64 `json:"SharedSize,omitempty"`
	VirtualSize int64 `json:"VirtualSize,omitempty"`
	// Labels are the image's labels.
	Labels map[string]string `json:"Labels,omitempty"`
	// Containers counts containers created from this image, -1 when unknown.
	Containers int64 `json:"Containers,omitempty"`
}

// CreatedAt returns the image's creation time.
func (i ImageSummary) CreatedAt() time.Time { return time.Unix(i.Created, 0) }

// HistoryEntry is one row of GET /images/{name}/history.
type HistoryEntry struct {
	// ID is the image id, or "<missing>" for an intermediate step.
	ID string `json:"Id"`
	// Created is a unix timestamp in seconds.
	Created int64 `json:"Created"`
	// CreatedBy is the build instruction.
	CreatedBy string `json:"CreatedBy"`
	// Tags point at this entry, only ever the topmost one.
	Tags []string `json:"Tags,omitempty"`
	// Size is the layer's uncompressed size.
	Size int64 `json:"Size"`
	// Comment is the step's comment.
	Comment string `json:"Comment,omitempty"`
}

// ImageDeleteResponse is one entry of the report a removal returns.
type ImageDeleteResponse struct {
	// Untagged is a reference that was removed from an image.
	Untagged string `json:"Untagged,omitempty"`
	// Deleted is an image id that was removed entirely.
	Deleted string `json:"Deleted,omitempty"`
}

// DistributionDescriptor is the manifest descriptor /distribution returns.
type DistributionDescriptor struct {
	// MediaType, Digest and Size describe the manifest.
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// DistributionPlatform is one platform a reference resolves to.
type DistributionPlatform struct {
	// Architecture, OS and Variant name the platform.
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

// DistributionInspect is GET /distribution/{name}/json, which is how "hull
// lock" resolves a reference to a digest without pulling it.
type DistributionInspect struct {
	// Descriptor is the manifest descriptor.
	Descriptor DistributionDescriptor `json:"Descriptor"`
	// Platforms lists what the reference offers.
	Platforms []DistributionPlatform `json:"Platforms,omitempty"`
}

// AuthConfig is a registry credential, as POST /auth takes it and as the
// X-Registry-Auth header carries it base64url-encoded.
type AuthConfig struct {
	// Username and Password are basic credentials.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Auth is a pre-encoded "user:pass".
	Auth string `json:"auth,omitempty"`
	// Email is legacy and ignored.
	Email string `json:"email,omitempty"`
	// ServerAddress is the registry host.
	ServerAddress string `json:"serveraddress,omitempty"`
	// IdentityToken and RegistryToken are the OAuth flows.
	IdentityToken string `json:"identitytoken,omitempty"`
	RegistryToken string `json:"registrytoken,omitempty"`
}

// AuthResponse is what POST /auth returns.
type AuthResponse struct {
	// Status is the human result, e.g. "Login Succeeded".
	Status string `json:"Status"`
	// IdentityToken is returned when the registry issued one.
	IdentityToken string `json:"IdentityToken,omitempty"`
}

// ---------- networks and volumes ----------

// IPAMConfigEntry is one subnet of a network's address plan.
type IPAMConfigEntry struct {
	// Subnet is the CIDR.
	Subnet string `json:"Subnet,omitempty"`
	// IPRange narrows the allocatable part of Subnet.
	IPRange string `json:"IPRange,omitempty"`
	// Gateway is the bridge address.
	Gateway string `json:"Gateway,omitempty"`
	// AuxAddress reserves named addresses.
	AuxAddress map[string]string `json:"AuxiliaryAddresses,omitempty"`
}

// IPAM is a network's address plan.
type IPAM struct {
	// Driver is the IPAM driver name.
	Driver string `json:"Driver,omitempty"`
	// Config is the list of subnets.
	Config []IPAMConfigEntry `json:"Config,omitempty"`
	// Options are driver options.
	Options map[string]string `json:"Options,omitempty"`
}

// NetworkEndpoint is one container's presence on a network.
type NetworkEndpoint struct {
	// Name is the container name.
	Name string `json:"Name"`
	// EndpointID identifies the attachment.
	EndpointID string `json:"EndpointID"`
	// MacAddress is the container-side interface address.
	MacAddress string `json:"MacAddress"`
	// IPv4Address and IPv6Address are the assigned addresses, in CIDR form.
	IPv4Address string `json:"IPv4Address"`
	IPv6Address string `json:"IPv6Address,omitempty"`
}

// NetworkResource is one network, as list and inspect report it.
type NetworkResource struct {
	// Name and ID identify the network.
	Name string `json:"Name"`
	ID   string `json:"Id"`
	// Created is an RFC3339 timestamp.
	Created string `json:"Created,omitempty"`
	// Scope is "local" for every hull network.
	Scope string `json:"Scope,omitempty"`
	// Driver is "bridge", "host" or "none".
	Driver string `json:"Driver,omitempty"`
	// EnableIPv6 reports the IPv6 setting.
	EnableIPv6 bool `json:"EnableIPv6,omitempty"`
	// IPAM is the address plan.
	IPAM IPAM `json:"IPAM,omitzero"`
	// Internal removes the masquerade rule.
	Internal bool `json:"Internal,omitempty"`
	// Attachable is recorded for compatibility.
	Attachable bool `json:"Attachable,omitempty"`
	// Containers is the attachment table.
	Containers map[string]NetworkEndpoint `json:"Containers,omitempty"`
	// Options and Labels are driver options and user metadata.
	Options map[string]string `json:"Options,omitempty"`
	Labels  map[string]string `json:"Labels,omitempty"`
}

// Subnet returns the network's first configured subnet, which is what a
// listing shows.
func (n NetworkResource) Subnet() string {
	if len(n.IPAM.Config) == 0 {
		return ""
	}
	return n.IPAM.Config[0].Subnet
}

// Gateway returns the network's first configured gateway.
func (n NetworkResource) Gateway() string {
	if len(n.IPAM.Config) == 0 {
		return ""
	}
	return n.IPAM.Config[0].Gateway
}

// NetworkCreateRequest is the body of POST /networks/create.
type NetworkCreateRequest struct {
	// Name is the new network's name.
	Name string `json:"Name"`
	// Driver is "bridge"; hull has no other real driver.
	Driver string `json:"Driver,omitempty"`
	// Internal, Attachable and EnableIPv6 are the network's flags.
	Internal   bool `json:"Internal,omitempty"`
	Attachable bool `json:"Attachable,omitempty"`
	EnableIPv6 bool `json:"EnableIPv6,omitempty"`
	// IPAM is the requested address plan.
	IPAM *IPAM `json:"IPAM,omitempty"`
	// Options and Labels are driver options and user metadata.
	Options map[string]string `json:"Options,omitempty"`
	Labels  map[string]string `json:"Labels,omitempty"`
	// CheckDuplicate asks the engine to reject a name already in use.
	CheckDuplicate bool `json:"CheckDuplicate,omitempty"`
}

// NetworkCreateResponse is what a network create returns.
type NetworkCreateResponse struct {
	// ID is the new network's id.
	ID string `json:"Id"`
	// Warning is a non-fatal complaint about the request.
	Warning string `json:"Warning,omitempty"`
}

// Volume is one named volume.
type Volume struct {
	// Name is the volume's name.
	Name string `json:"Name"`
	// Driver is the volume driver, "local" for hull.
	Driver string `json:"Driver"`
	// Mountpoint is the host path holding the data.
	Mountpoint string `json:"Mountpoint"`
	// CreatedAt is an RFC3339 timestamp.
	CreatedAt string `json:"CreatedAt,omitempty"`
	// Labels and Options are user metadata and driver options.
	Labels  map[string]string `json:"Labels,omitempty"`
	Options map[string]string `json:"Options,omitempty"`
	// Scope is "local".
	Scope string `json:"Scope,omitempty"`
	// UsageData is present when the engine computed sizes.
	UsageData *VolumeUsageData `json:"UsageData,omitempty"`
}

// VolumeUsageData is a volume's size and reference count.
type VolumeUsageData struct {
	// Size is the bytes the volume holds, -1 when not computed.
	Size int64 `json:"Size"`
	// RefCount is how many containers reference it, -1 when not computed.
	RefCount int64 `json:"RefCount"`
}

// VolumeCreateRequest is the body of POST /volumes/create.
type VolumeCreateRequest struct {
	// Name is the volume's name; empty asks the engine to generate one.
	Name string `json:"Name,omitempty"`
	// Driver is the volume driver.
	Driver string `json:"Driver,omitempty"`
	// DriverOpts are driver options.
	DriverOpts map[string]string `json:"DriverOpts,omitempty"`
	// Labels are user metadata.
	Labels map[string]string `json:"Labels,omitempty"`
}

// VolumeListResponse is what GET /volumes returns.
type VolumeListResponse struct {
	// Volumes is the listing.
	Volumes []*Volume `json:"Volumes"`
	// Warnings are non-fatal complaints.
	Warnings []string `json:"Warnings,omitempty"`
}

// PruneReport is what the /prune endpoints return. Different endpoints fill
// different fields, so one shape covers them all.
type PruneReport struct {
	// ContainersDeleted, ImagesDeleted, VolumesDeleted and NetworksDeleted
	// name what was removed.
	ContainersDeleted []string              `json:"ContainersDeleted,omitempty"`
	ImagesDeleted     []ImageDeleteResponse `json:"ImagesDeleted,omitempty"`
	VolumesDeleted    []string              `json:"VolumesDeleted,omitempty"`
	NetworksDeleted   []string              `json:"NetworksDeleted,omitempty"`
	// SpaceReclaimed is the total bytes freed.
	SpaceReclaimed int64 `json:"SpaceReclaimed"`
}

// Add folds another report into this one, which is what a top-level prune does
// as it sweeps each object kind in turn.
func (p *PruneReport) Add(other PruneReport) {
	p.ContainersDeleted = append(p.ContainersDeleted, other.ContainersDeleted...)
	p.ImagesDeleted = append(p.ImagesDeleted, other.ImagesDeleted...)
	p.VolumesDeleted = append(p.VolumesDeleted, other.VolumesDeleted...)
	p.NetworksDeleted = append(p.NetworksDeleted, other.NetworksDeleted...)
	p.SpaceReclaimed += other.SpaceReclaimed
}

// DiskUsage is what GET /system/df returns.
type DiskUsage struct {
	// LayersSize is the total size of the image layers.
	LayersSize int64 `json:"LayersSize"`
	// Images, Containers and Volumes are the populations.
	Images     []*ImageSummary     `json:"Images,omitempty"`
	Containers []*ContainerSummary `json:"Containers,omitempty"`
	Volumes    []*Volume           `json:"Volumes,omitempty"`
	// BuilderSize is the build cache size.
	BuilderSize int64 `json:"BuilderSize,omitempty"`
}

// VersionComponent is one entry of a version response's component list.
type VersionComponent struct {
	// Name is the component's name, e.g. "Engine" or "crun".
	Name string `json:"Name"`
	// Version is its version string.
	Version string `json:"Version"`
	// Details is free-form metadata.
	Details map[string]string `json:"Details,omitempty"`
}

// VersionResponse is what GET /version returns.
type VersionResponse struct {
	// Platform names the product.
	Platform struct {
		// Name is the product name.
		Name string `json:"Name"`
	} `json:"Platform,omitzero"`
	// Version is the daemon version.
	Version string `json:"Version"`
	// APIVersion and MinAPIVersion bound what the daemon serves.
	APIVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion,omitempty"`
	// GitCommit, GoVersion, Os, Arch and KernelVersion describe the build.
	GitCommit     string `json:"GitCommit,omitempty"`
	GoVersion     string `json:"GoVersion,omitempty"`
	Os            string `json:"Os,omitempty"`
	Arch          string `json:"Arch,omitempty"`
	KernelVersion string `json:"KernelVersion,omitempty"`
	// BuildTime is when the daemon was built.
	BuildTime string `json:"BuildTime,omitempty"`
	// Components lists the sub-versions the daemon reports.
	Components []VersionComponent `json:"Components,omitempty"`
}

// Info is what GET /info returns. hull adds a handful of fields of its own; a
// Docker daemon omits them and the CLI copes.
type Info struct {
	// ID is the daemon's stable identity.
	ID string `json:"ID"`
	// Name is the host name.
	Name string `json:"Name"`
	// ServerVersion is the daemon's version.
	ServerVersion string `json:"ServerVersion"`
	// Containers and the per-state counters describe the population.
	Containers        int `json:"Containers"`
	ContainersRunning int `json:"ContainersRunning"`
	ContainersPaused  int `json:"ContainersPaused"`
	ContainersStopped int `json:"ContainersStopped"`
	// Images is how many images the store holds.
	Images int `json:"Images"`
	// Driver and DriverStatus describe the storage driver.
	Driver       string      `json:"Driver"`
	DriverStatus [][2]string `json:"DriverStatus,omitempty"`
	// LoggingDriver, CgroupDriver and CgroupVersion describe the subsystems.
	LoggingDriver string `json:"LoggingDriver,omitempty"`
	CgroupDriver  string `json:"CgroupDriver,omitempty"`
	CgroupVersion string `json:"CgroupVersion,omitempty"`
	// KernelVersion, OperatingSystem, OSType and Architecture describe the
	// host.
	KernelVersion   string `json:"KernelVersion,omitempty"`
	OperatingSystem string `json:"OperatingSystem,omitempty"`
	OSType          string `json:"OSType,omitempty"`
	Architecture    string `json:"Architecture,omitempty"`
	// NCPU and MemTotal are the host's capacity.
	NCPU     int   `json:"NCPU,omitempty"`
	MemTotal int64 `json:"MemTotal,omitempty"`
	// DockerRootDir is the data directory under the name Docker clients look
	// for.
	DockerRootDir string `json:"DockerRootDir,omitempty"`
	// DefaultRuntime and Runtimes describe the runtime drivers.
	DefaultRuntime string         `json:"DefaultRuntime,omitempty"`
	Runtimes       map[string]any `json:"Runtimes,omitempty"`
	// SecurityOptions lists the isolation features in effect.
	SecurityOptions []string `json:"SecurityOptions,omitempty"`
	// Warnings are the host problems "hull doctor" would report, phrased as
	// something the operator can act on.
	Warnings []string `json:"Warnings,omitempty"`
	// Plugins names the built-in drivers.
	Plugins struct {
		// Volume, Network and Log are the built-in driver names.
		Volume  []string `json:"Volume,omitempty"`
		Network []string `json:"Network,omitempty"`
		Log     []string `json:"Log,omitempty"`
	} `json:"Plugins,omitzero"`

	// CgroupV2Delegated reports whether the unified hierarchy actually offers
	// the controllers hull needs. It is false on a stock WSL 2.4 host, and it
	// is the single most important thing this payload says.
	CgroupV2Delegated bool `json:"CgroupV2Delegated,omitempty"`
	// OCIVersion is the runtime-spec version hull writes into bundles on this
	// host, after negotiating with the runtime that will read them.
	OCIVersion string `json:"OCIVersion,omitempty"`
	// RuntimeVersion is the selected runtime driver's own version string.
	RuntimeVersion string `json:"RuntimeVersion,omitempty"`
	// DataRoot is hull's data directory under its own name.
	DataRoot string `json:"DataRoot,omitempty"`
}

// ---------- events ----------

// Event is one entry of the /events stream.
//
// Docker capitalises Type, Action and Actor but not scope, time or timeNano,
// while hull's internal model spells them all lower case. The unmarshaller
// accepts either, so the client keeps working whichever model the engine
// serialises.
type Event struct {
	// Type is "container", "image", "network", "volume" or "daemon".
	Type string `json:"Type"`
	// Action is the verb, e.g. "create", "start" or "die".
	Action string `json:"Action"`
	// Actor names the object the event is about.
	Actor EventActor `json:"Actor"`
	// Scope is "local".
	Scope string `json:"scope,omitempty"`
	// Time and TimeNano are the event's timestamp.
	Time     int64 `json:"time"`
	TimeNano int64 `json:"timeNano"`
}

// EventActor names the object an event is about.
type EventActor struct {
	// ID is the object's id.
	ID string `json:"ID"`
	// Attributes carries the object's name, image and labels.
	Attributes map[string]string `json:"Attributes,omitempty"`
}

// At returns the event's timestamp.
func (e Event) At() time.Time {
	if e.TimeNano != 0 {
		return time.Unix(0, e.TimeNano)
	}
	return time.Unix(e.Time, 0)
}

// Name returns the actor's name attribute, falling back to a short id.
func (e Event) Name() string {
	if n := e.Actor.Attributes["name"]; n != "" {
		return n
	}
	if len(e.Actor.ID) > 12 {
		return e.Actor.ID[:12]
	}
	return e.Actor.ID
}

// eventWire is the tolerant decoding target for [Event.UnmarshalJSON].
type eventWire struct {
	Type    string `json:"Type"`
	TypeAlt string `json:"type"`

	Action    string `json:"Action"`
	ActionAlt string `json:"action"`

	Actor struct {
		ID            string            `json:"ID"`
		IDAlt         string            `json:"id"`
		Attributes    map[string]string `json:"Attributes"`
		AttributesAlt map[string]string `json:"attributes"`
	} `json:"Actor"`
	ActorAlt struct {
		ID         string            `json:"id"`
		Attributes map[string]string `json:"attributes"`
	} `json:"actor"`

	Scope    string `json:"scope"`
	ScopeAlt string `json:"Scope"`

	Time     int64 `json:"time"`
	TimeNano int64 `json:"timeNano"`
}

// UnmarshalJSON accepts both Docker's capitalised spelling and hull's internal
// lower-case one.
func (e *Event) UnmarshalJSON(data []byte) error {
	var raw eventWire
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	e.Type = firstNonEmpty(raw.Type, raw.TypeAlt)
	e.Action = firstNonEmpty(raw.Action, raw.ActionAlt)
	e.Actor.ID = firstNonEmpty(raw.Actor.ID, raw.Actor.IDAlt, raw.ActorAlt.ID)
	switch {
	case raw.Actor.Attributes != nil:
		e.Actor.Attributes = raw.Actor.Attributes
	case raw.Actor.AttributesAlt != nil:
		e.Actor.Attributes = raw.Actor.AttributesAlt
	default:
		e.Actor.Attributes = raw.ActorAlt.Attributes
	}
	e.Scope = firstNonEmpty(raw.Scope, raw.ScopeAlt)
	e.Time = raw.Time
	e.TimeNano = raw.TimeNano
	return nil
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------- compatibility aliases ----------
//
// Both spellings are in use across this package's call sites: the Docker API
// reference names the payloads ContainerJSON and ContainerWaitResponse, while
// hull's own method set reads better with ContainerInspect and WaitResponse.
// They are aliases, not conversions, so either name may be used freely.

// ContainerJSON is the Docker API's name for [ContainerInspect].
type ContainerJSON = ContainerInspect

// ContainerWaitResponse is the Docker API's name for [WaitResponse].
type ContainerWaitResponse = WaitResponse

// ContainerTopResponse is the Docker API's name for [TopResponse].
type ContainerTopResponse = TopResponse

// ContainerChange is the Docker API's name for [FilesystemChange].
type ContainerChange = FilesystemChange

// ContainerUpdateRequest is the body of POST /containers/{id}/update: the
// resource limits to change, plus an optional new restart policy.
type ContainerUpdateRequest struct {
	Resources
	// RestartPolicy replaces the container's restart policy when set.
	RestartPolicy *RestartPolicy `json:"RestartPolicy,omitempty"`
}

// ContainerUpdateConfig is the name hull's own call sites use for
// [ContainerUpdateRequest].
type ContainerUpdateConfig = ContainerUpdateRequest

// ContainerUpdateResponse carries the warnings an update produced, in the same
// spirit as the create response: a limit the host cannot enforce is reported
// here rather than silently dropped.
type ContainerUpdateResponse struct {
	// Warnings are the engine's non-fatal complaints.
	Warnings []string `json:"Warnings,omitempty"`
}
