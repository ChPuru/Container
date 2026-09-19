// Package api implements hull's Docker Engine API v1.43 server.
//
// Fidelity is the point of this package. The stock docker CLI, docker compose,
// VS Code Dev Containers and Testcontainers all parse these payloads by shape,
// and several of them match on the exact message text of an error, so the
// types here mirror Docker's wire format field for field rather than being a
// tidy projection of hull's own domain model. The translation between the two
// lives in translate.go; nothing in internal/types carries a Docker json tag.
//
// # Layering
//
// The server drives a [Backend], which is the subset of *engine.Engine the
// HTTP surface needs. Keeping it an interface is what makes the routing,
// version gating, filter parsing, error shapes, chunked progress encoder and
// hijack handshake testable with httptest and no kernel at all.
package api

import "encoding/json"

// ErrorResponse is the body of every error this API returns. Docker's clients
// read exactly one field, and compose matches on its text.
type ErrorResponse struct {
	// Message is the human-readable failure, phrased the way Docker phrases
	// it so string-matching clients keep working.
	Message string `json:"message"`
}

// IDResponse is the {"Id": "..."} body returned by exec create.
type IDResponse struct {
	// ID is the created object's identifier.
	ID string `json:"Id"`
}

// ContainerCreateResponse is the body of POST /containers/create.
type ContainerCreateResponse struct {
	// ID is the new container's full 64-character id.
	ID string `json:"Id"`
	// Warnings are the host problems that did not stop the create, such as a
	// resource limit this kernel cannot enforce. They must be surfaced: a
	// silently unlimited container is worse than a refused one.
	Warnings []string `json:"Warnings"`
}

// ContainerUpdateResponse is the body of POST /containers/{id}/update.
type ContainerUpdateResponse struct {
	// Warnings are limits that could not be applied.
	Warnings []string `json:"Warnings"`
}

// ContainerWaitResponse is the body of POST /containers/{id}/wait.
type ContainerWaitResponse struct {
	// StatusCode is the container's exit status.
	StatusCode int `json:"StatusCode"`
	// Error carries a wait failure without changing the HTTP status, because
	// the header may already have been sent.
	Error *ContainerWaitError `json:"Error,omitempty"`
}

// ContainerWaitError is the error half of a wait response.
type ContainerWaitError struct {
	// Message explains why the wait could not complete.
	Message string `json:"Message"`
}

// ContainerTopResponse is the body of GET /containers/{id}/top.
type ContainerTopResponse struct {
	// Titles are the ps column headers.
	Titles []string `json:"Titles"`
	// Processes is one row per process, in Titles order.
	Processes [][]string `json:"Processes"`
}

// ContainerChange is one entry of GET /containers/{id}/changes.
type ContainerChange struct {
	// Path is the container-absolute path that changed.
	Path string `json:"Path"`
	// Kind is 0 modified, 1 added, 2 deleted.
	Kind int `json:"Kind"`
}

// Docker's numeric change kinds, which are positional and not named on the
// wire.
const (
	// ChangeModify marks a path present in both the image and the writable
	// layer, with different contents.
	ChangeModify = 0
	// ChangeAdd marks a path created in the writable layer.
	ChangeAdd = 1
	// ChangeDelete marks a path removed from the image by a whiteout.
	ChangeDelete = 2
)

// AuthResponse is the body of POST /auth.
type AuthResponse struct {
	// Status is "Login Succeeded" on success.
	Status string `json:"Status"`
	// IdentityToken is always empty: hull does not mint tokens, the client's
	// credential store owns them.
	IdentityToken string `json:"IdentityToken,omitempty"`
}

// AuthConfig is the credential blob clients post to /auth and send
// base64-encoded in the X-Registry-Auth header.
type AuthConfig struct {
	// Username and Password are the registry credentials.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Auth is the legacy base64 "user:pass" form.
	Auth string `json:"auth,omitempty"`
	// Email is accepted and ignored; registries stopped using it long ago.
	Email string `json:"email,omitempty"`
	// ServerAddress names the registry. Empty means Docker Hub.
	ServerAddress string `json:"serveraddress,omitempty"`
	// IdentityToken and RegistryToken are accepted for compatibility.
	IdentityToken string `json:"identitytoken,omitempty"`
	RegistryToken string `json:"registrytoken,omitempty"`
}

// Port is one published port as the container list reports it. Note that the
// list and the inspect document describe the same data in two different
// shapes, and clients depend on both being right.
type Port struct {
	// IP is the host address the port is published on, absent when it is not
	// published at all.
	IP string `json:"IP,omitempty"`
	// PrivatePort is the port inside the container.
	PrivatePort uint16 `json:"PrivatePort"`
	// PublicPort is the host port, zero when unpublished.
	PublicPort uint16 `json:"PublicPort,omitempty"`
	// Type is "tcp" or "udp".
	Type string `json:"Type"`
}

// PortBinding is one host side of a published port in the inspect document.
type PortBinding struct {
	// HostIP is the host address, "0.0.0.0" for all interfaces.
	HostIP string `json:"HostIp"`
	// HostPort is the host port as a decimal string, as Docker sends it.
	HostPort string `json:"HostPort"`
}

// PortMap maps "80/tcp" to its host bindings. An exposed but unpublished port
// maps to a JSON null, which is what Docker emits and what clients expect.
type PortMap map[string][]PortBinding

// MountPoint is one resolved mount in the inspect document and the list.
type MountPoint struct {
	// Type is bind, volume or tmpfs.
	Type string `json:"Type"`
	// Name is the volume name, empty for a bind or tmpfs mount.
	Name string `json:"Name,omitempty"`
	// Source is the host path.
	Source string `json:"Source"`
	// Destination is the path inside the container.
	Destination string `json:"Destination"`
	// Driver is the volume driver, empty for binds.
	Driver string `json:"Driver,omitempty"`
	// Mode is the raw mode string from the bind spec.
	Mode string `json:"Mode"`
	// RW reports that the mount is writable.
	RW bool `json:"RW"`
	// Propagation is the bind propagation mode.
	Propagation string `json:"Propagation"`
}

// HealthConfig is the image- and container-level healthcheck, with durations
// in nanoseconds the way Docker serialises them.
type HealthConfig struct {
	// Test is the probe, e.g. ["CMD-SHELL", "curl -f localhost"].
	Test []string `json:"Test,omitempty"`
	// Interval, Timeout and StartPeriod are nanosecond durations.
	Interval    int64 `json:"Interval,omitempty"`
	Timeout     int64 `json:"Timeout,omitempty"`
	StartPeriod int64 `json:"StartPeriod,omitempty"`
	// Retries is how many consecutive failures mean unhealthy.
	Retries int `json:"Retries,omitempty"`
}

// ContainerConfig is the Docker-shaped process configuration, used both in
// container inspect and as the image's Config.
type ContainerConfig struct {
	// Hostname and Domainname name the container on its networks.
	Hostname   string `json:"Hostname"`
	Domainname string `json:"Domainname"`
	// User is the user spec the process runs as.
	User string `json:"User"`
	// AttachStdin, AttachStdout and AttachStderr record what the creating
	// client asked to be connected to.
	AttachStdin  bool `json:"AttachStdin"`
	AttachStdout bool `json:"AttachStdout"`
	AttachStderr bool `json:"AttachStderr"`
	// ExposedPorts is the set of "80/tcp" keys the image or the request
	// declared.
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	// Tty allocates a pseudo-terminal.
	Tty bool `json:"Tty"`
	// OpenStdin keeps stdin open, StdinOnce closes it after the first client
	// detaches.
	OpenStdin bool `json:"OpenStdin"`
	StdinOnce bool `json:"StdinOnce"`
	// Env is the environment, "KEY=value".
	Env []string `json:"Env"`
	// Cmd is the command, after the image's own default has been merged.
	Cmd []string `json:"Cmd"`
	// Healthcheck is the effective healthcheck.
	Healthcheck *HealthConfig `json:"Healthcheck,omitempty"`
	// ArgsEscaped is a Windows-image concept hull never sets.
	ArgsEscaped bool `json:"ArgsEscaped,omitempty"`
	// Image is the reference the container was created from.
	Image string `json:"Image"`
	// Volumes is the set of anonymous volume targets.
	Volumes map[string]struct{} `json:"Volumes"`
	// WorkingDir is the process's initial directory.
	WorkingDir string `json:"WorkingDir"`
	// Entrypoint is the effective entrypoint.
	Entrypoint []string `json:"Entrypoint"`
	// NetworkDisabled and MacAddress are legacy fields kept for clients that
	// read them.
	NetworkDisabled bool   `json:"NetworkDisabled,omitempty"`
	MacAddress      string `json:"MacAddress,omitempty"`
	// OnBuild is the image's ONBUILD triggers.
	OnBuild []string `json:"OnBuild"`
	// Labels are the container's labels.
	Labels map[string]string `json:"Labels"`
	// StopSignal and StopTimeout govern a graceful stop.
	StopSignal  string `json:"StopSignal,omitempty"`
	StopTimeout *int   `json:"StopTimeout,omitempty"`
	// Shell is the image's default shell for shell-form instructions.
	Shell []string `json:"Shell,omitempty"`
}

// RestartPolicy is the Docker-shaped restart policy.
type RestartPolicy struct {
	// Name is "", "no", "always", "unless-stopped" or "on-failure".
	Name string `json:"Name"`
	// MaximumRetryCount bounds "on-failure".
	MaximumRetryCount int `json:"MaximumRetryCount"`
}

// LogConfig selects a log driver.
type LogConfig struct {
	// Type is "json-file" or "none".
	Type string `json:"Type"`
	// Config is the driver's options.
	Config map[string]string `json:"Config"`
}

// Ulimit is one rlimit override.
type Ulimit struct {
	// Name is the rlimit name without the RLIMIT_ prefix, e.g. "nofile".
	Name string `json:"Name"`
	// Soft and Hard are the limits.
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

// Mount is the long-form mount request Docker's clients send and read back.
type Mount struct {
	// Type is bind, volume or tmpfs.
	Type string `json:"Type,omitempty"`
	// Source is the host path or volume name.
	Source string `json:"Source,omitempty"`
	// Target is the path inside the container.
	Target string `json:"Target,omitempty"`
	// ReadOnly makes the mount read-only.
	ReadOnly bool `json:"ReadOnly,omitempty"`
	// Consistency is a macOS concept hull records and ignores.
	Consistency string `json:"Consistency,omitempty"`
	// BindOptions, VolumeOptions and TmpfsOptions carry per-type settings.
	BindOptions   *MountBindOptions   `json:"BindOptions,omitempty"`
	VolumeOptions *MountVolumeOptions `json:"VolumeOptions,omitempty"`
	TmpfsOptions  *MountTmpfsOptions  `json:"TmpfsOptions,omitempty"`
}

// MountBindOptions carries bind-specific settings.
type MountBindOptions struct {
	// Propagation is the bind propagation mode.
	Propagation string `json:"Propagation,omitempty"`
	// NonRecursive and CreateMountpoint mirror Docker's flags.
	NonRecursive     bool `json:"NonRecursive,omitempty"`
	CreateMountpoint bool `json:"CreateMountpoint,omitempty"`
}

// MountVolumeOptions carries volume-specific settings.
type MountVolumeOptions struct {
	// NoCopy suppresses seeding the volume from the image.
	NoCopy bool `json:"NoCopy,omitempty"`
	// Labels are applied to a volume created on demand.
	Labels map[string]string `json:"Labels,omitempty"`
	// DriverConfig selects the volume driver.
	DriverConfig *MountDriverConfig `json:"DriverConfig,omitempty"`
}

// MountDriverConfig names a volume driver and its options.
type MountDriverConfig struct {
	// Name is the driver name.
	Name string `json:"Name,omitempty"`
	// Options are the driver's options.
	Options map[string]string `json:"Options,omitempty"`
}

// MountTmpfsOptions carries tmpfs-specific settings.
type MountTmpfsOptions struct {
	// SizeBytes bounds the tmpfs.
	SizeBytes int64 `json:"SizeBytes,omitempty"`
	// Mode is the mountpoint's permission bits.
	Mode uint32 `json:"Mode,omitempty"`
}

// HostConfig is the Docker-shaped host half of a container definition: what
// the host decides rather than what the image declares.
type HostConfig struct {
	// Binds are short-form "src:dst[:opts]" mounts.
	Binds []string `json:"Binds"`
	// ContainerIDFile is accepted and ignored.
	ContainerIDFile string `json:"ContainerIDFile"`
	// LogConfig selects the log driver.
	LogConfig LogConfig `json:"LogConfig"`
	// NetworkMode is bridge, host, none, container:<id> or a network name.
	NetworkMode string `json:"NetworkMode"`
	// PortBindings maps "80/tcp" to host bindings.
	PortBindings PortMap `json:"PortBindings"`
	// RestartPolicy governs automatic restarts.
	RestartPolicy RestartPolicy `json:"RestartPolicy"`
	// AutoRemove deletes the container when it exits.
	AutoRemove bool `json:"AutoRemove"`
	// VolumeDriver and VolumesFrom are accepted for compatibility.
	VolumeDriver string   `json:"VolumeDriver"`
	VolumesFrom  []string `json:"VolumesFrom"`
	// ConsoleSize is the initial tty size, [height, width].
	ConsoleSize [2]uint `json:"ConsoleSize"`
	// CapAdd and CapDrop adjust the capability set.
	CapAdd  []string `json:"CapAdd"`
	CapDrop []string `json:"CapDrop"`
	// CgroupnsMode is "private" or "host".
	CgroupnsMode string `json:"CgroupnsMode"`
	// DNS, DNSOptions and DNSSearch configure the resolver.
	DNS        []string `json:"Dns"`
	DNSOptions []string `json:"DnsOptions"`
	DNSSearch  []string `json:"DnsSearch"`
	// ExtraHosts are "name:ip" entries written into /etc/hosts.
	ExtraHosts []string `json:"ExtraHosts"`
	// GroupAdd lists supplementary groups.
	GroupAdd []string `json:"GroupAdd"`
	// IpcMode, Cgroup, Links, PidMode and UTSMode mirror Docker's namespace
	// controls.
	IpcMode string   `json:"IpcMode"`
	Cgroup  string   `json:"Cgroup"`
	Links   []string `json:"Links"`
	PidMode string   `json:"PidMode"`
	UTSMode string   `json:"UTSMode"`
	// OomScoreAdj biases the OOM killer.
	OomScoreAdj int `json:"OomScoreAdj"`
	// Privileged disables nearly every isolation feature.
	Privileged bool `json:"Privileged"`
	// PublishAllPorts publishes every exposed port on a random host port.
	PublishAllPorts bool `json:"PublishAllPorts"`
	// ReadonlyRootfs mounts the container's root read-only.
	ReadonlyRootfs bool `json:"ReadonlyRootfs"`
	// SecurityOpt carries seccomp, apparmor and no-new-privileges settings.
	SecurityOpt []string `json:"SecurityOpt"`
	// StorageOpt is accepted and ignored.
	StorageOpt map[string]string `json:"StorageOpt,omitempty"`
	// Tmpfs maps a path to its tmpfs mount options.
	Tmpfs map[string]string `json:"Tmpfs,omitempty"`
	// UsernsMode is "" or "host".
	UsernsMode string `json:"UsernsMode"`
	// ShmSize is the size of /dev/shm in bytes.
	ShmSize int64 `json:"ShmSize"`
	// Sysctls are kernel parameters set in the container's namespaces.
	Sysctls map[string]string `json:"Sysctls,omitempty"`
	// Runtime selects the container runtime.
	Runtime string `json:"Runtime"`
	// Isolation is a Windows concept hull records for compatibility.
	Isolation string `json:"Isolation"`
	// CPUShares through CpusetMems are the cgroup knobs.
	CPUShares          int64  `json:"CpuShares"`
	Memory             int64  `json:"Memory"`
	NanoCPUs           int64  `json:"NanoCpus"`
	CgroupParent       string `json:"CgroupParent"`
	BlkioWeight        uint16 `json:"BlkioWeight"`
	CPUPeriod          int64  `json:"CpuPeriod"`
	CPUQuota           int64  `json:"CpuQuota"`
	CPURealtimePeriod  int64  `json:"CpuRealtimePeriod"`
	CPURealtimeRuntime int64  `json:"CpuRealtimeRuntime"`
	CpusetCpus         string `json:"CpusetCpus"`
	CpusetMems         string `json:"CpusetMems"`
	// Devices exposes host device nodes.
	Devices []DeviceMapping `json:"Devices"`
	// DeviceCgroupRules and DeviceRequests are accepted for compatibility.
	DeviceCgroupRules []string          `json:"DeviceCgroupRules,omitempty"`
	DeviceRequests    []json.RawMessage `json:"DeviceRequests,omitempty"`
	// KernelMemory is a removed cgroup v1 knob clients still send.
	KernelMemory int64 `json:"KernelMemory,omitempty"`
	// MemoryReservation, MemorySwap and MemorySwappiness bound memory.
	MemoryReservation int64  `json:"MemoryReservation"`
	MemorySwap        int64  `json:"MemorySwap"`
	MemorySwappiness  *int64 `json:"MemorySwappiness,omitempty"`
	// OomKillDisable is accepted; cgroup v2 has no equivalent.
	OomKillDisable *bool `json:"OomKillDisable,omitempty"`
	// PidsLimit bounds the pid cgroup.
	PidsLimit *int64 `json:"PidsLimit,omitempty"`
	// Ulimits are rlimit overrides.
	Ulimits []Ulimit `json:"Ulimits"`
	// Mounts are long-form mount requests.
	Mounts []Mount `json:"Mounts,omitempty"`
	// MaskedPaths and ReadonlyPaths override the default procfs hardening.
	MaskedPaths   []string `json:"MaskedPaths,omitempty"`
	ReadonlyPaths []string `json:"ReadonlyPaths,omitempty"`
	// Init runs hull-init as pid 1.
	Init *bool `json:"Init,omitempty"`
}

// EndpointIPAMConfig is the requested addressing for one endpoint.
type EndpointIPAMConfig struct {
	// IPv4Address and IPv6Address request specific addresses.
	IPv4Address string `json:"IPv4Address,omitempty"`
	IPv6Address string `json:"IPv6Address,omitempty"`
	// LinkLocalIPs is accepted for compatibility.
	LinkLocalIPs []string `json:"LinkLocalIPs,omitempty"`
}

// EndpointSettings is one container's attachment to one network.
type EndpointSettings struct {
	// IPAMConfig is the requested addressing.
	IPAMConfig *EndpointIPAMConfig `json:"IPAMConfig"`
	// Links and Aliases are compose's service-discovery hooks.
	Links   []string `json:"Links"`
	Aliases []string `json:"Aliases"`
	// MacAddress is the endpoint's hardware address.
	MacAddress string `json:"MacAddress"`
	// DriverOpts are per-endpoint driver options.
	DriverOpts map[string]string `json:"DriverOpts"`
	// NetworkID and EndpointID identify the attachment.
	NetworkID  string `json:"NetworkID"`
	EndpointID string `json:"EndpointID"`
	// Gateway, IPAddress and IPPrefixLen are the assigned IPv4 addressing.
	Gateway     string `json:"Gateway"`
	IPAddress   string `json:"IPAddress"`
	IPPrefixLen int    `json:"IPPrefixLen"`
	// The IPv6 fields are always empty; hull does not allocate IPv6 yet.
	IPv6Gateway         string `json:"IPv6Gateway"`
	GlobalIPv6Address   string `json:"GlobalIPv6Address"`
	GlobalIPv6PrefixLen int    `json:"GlobalIPv6PrefixLen"`
	// DNSNames are the names this container answers to on the network.
	DNSNames []string `json:"DNSNames,omitempty"`
}

// NetworkSettings is the container-side network view in the inspect document.
type NetworkSettings struct {
	// Bridge is the legacy default-bridge name.
	Bridge string `json:"Bridge"`
	// SandboxID and SandboxKey identify the network namespace.
	SandboxID  string `json:"SandboxID"`
	SandboxKey string `json:"SandboxKey"`
	// HairpinMode and the link-local fields are legacy libnetwork state.
	HairpinMode            bool   `json:"HairpinMode"`
	LinkLocalIPv6Address   string `json:"LinkLocalIPv6Address"`
	LinkLocalIPv6PrefixLen int    `json:"LinkLocalIPv6PrefixLen"`
	// Ports maps "80/tcp" to its host bindings.
	Ports PortMap `json:"Ports"`
	// SecondaryIPAddresses and SecondaryIPv6Addresses are always empty.
	SecondaryIPAddresses   []string `json:"SecondaryIPAddresses"`
	SecondaryIPv6Addresses []string `json:"SecondaryIPv6Addresses"`
	// The flattened default-network fields below are what old clients read.
	EndpointID          string `json:"EndpointID"`
	Gateway             string `json:"Gateway"`
	GlobalIPv6Address   string `json:"GlobalIPv6Address"`
	GlobalIPv6PrefixLen int    `json:"GlobalIPv6PrefixLen"`
	IPAddress           string `json:"IPAddress"`
	IPPrefixLen         int    `json:"IPPrefixLen"`
	IPv6Gateway         string `json:"IPv6Gateway"`
	MacAddress          string `json:"MacAddress"`
	// Networks is the real, per-network view every modern client uses.
	Networks map[string]*EndpointSettings `json:"Networks"`
}

// SummaryNetworkSettings is the cut-down network view in the container list.
type SummaryNetworkSettings struct {
	// Networks is the per-network view.
	Networks map[string]*EndpointSettings `json:"Networks"`
}

// Health is the health block of a container's state.
type Health struct {
	// Status is starting, healthy or unhealthy.
	Status string `json:"Status"`
	// FailingStreak counts consecutive failures.
	FailingStreak int `json:"FailingStreak"`
	// Log holds the most recent probe results.
	Log []*HealthLog `json:"Log"`
}

// HealthLog is one healthcheck probe result.
type HealthLog struct {
	// Start and End bound the probe.
	Start string `json:"Start"`
	End   string `json:"End"`
	// ExitCode is the probe's exit status.
	ExitCode int `json:"ExitCode"`
	// Output is what the probe printed.
	Output string `json:"Output"`
}

// ContainerState is the State block of a container's inspect document.
type ContainerState struct {
	// Status is created, running, paused, restarting, removing, exited or
	// dead.
	Status string `json:"Status"`
	// Running, Paused, Restarting, OOMKilled and Dead are the booleans older
	// clients branch on.
	Running    bool `json:"Running"`
	Paused     bool `json:"Paused"`
	Restarting bool `json:"Restarting"`
	OOMKilled  bool `json:"OOMKilled"`
	Dead       bool `json:"Dead"`
	// Pid is the init process's host pid, zero when not running.
	Pid int `json:"Pid"`
	// ExitCode and Error describe the last exit.
	ExitCode int    `json:"ExitCode"`
	Error    string `json:"Error"`
	// StartedAt and FinishedAt are RFC3339Nano instants.
	StartedAt  string `json:"StartedAt"`
	FinishedAt string `json:"FinishedAt"`
	// Health is present only when the container has a healthcheck.
	Health *Health `json:"Health,omitempty"`
}

// GraphDriverData names the storage driver and its per-container paths.
type GraphDriverData struct {
	// Name is the storage driver, always "overlay2" here.
	Name string `json:"Name"`
	// Data holds the overlay directories.
	Data map[string]string `json:"Data"`
}

// ContainerJSON is the full inspect document. Every field compose, Dev
// Containers or Testcontainers reads is present and correctly typed.
type ContainerJSON struct {
	// ID is the full 64-character container id.
	ID string `json:"Id"`
	// Created is an RFC3339Nano instant.
	Created string `json:"Created"`
	// Path and Args are the entrypoint split into program and arguments.
	Path string   `json:"Path"`
	Args []string `json:"Args"`
	// State is the lifecycle block.
	State *ContainerState `json:"State"`
	// Image is the image id the container was created from.
	Image string `json:"Image"`
	// ResolvConfPath, HostnamePath and HostsPath are the host files bound
	// into the container.
	ResolvConfPath string `json:"ResolvConfPath"`
	HostnamePath   string `json:"HostnamePath"`
	HostsPath      string `json:"HostsPath"`
	// LogPath is the json-file log.
	LogPath string `json:"LogPath"`
	// Name carries a leading slash, which compose matches on.
	Name string `json:"Name"`
	// RestartCount counts automatic restarts.
	RestartCount int `json:"RestartCount"`
	// Driver is the storage driver.
	Driver string `json:"Driver"`
	// Platform is "linux".
	Platform string `json:"Platform"`
	// MountLabel, ProcessLabel and AppArmorProfile are LSM labels; hull runs
	// on a kernel with no AppArmor, so they are empty.
	MountLabel      string `json:"MountLabel"`
	ProcessLabel    string `json:"ProcessLabel"`
	AppArmorProfile string `json:"AppArmorProfile"`
	// ExecIDs lists live execs, null when there are none.
	ExecIDs []string `json:"ExecIDs"`
	// HostConfig is the host half of the definition.
	HostConfig *HostConfig `json:"HostConfig"`
	// GraphDriver names the storage driver and its directories.
	GraphDriver GraphDriverData `json:"GraphDriver"`
	// SizeRw and SizeRootFs are only present when the client asked for sizes.
	SizeRw     *int64 `json:"SizeRw,omitempty"`
	SizeRootFs *int64 `json:"SizeRootFs,omitempty"`
	// Mounts are the resolved mounts.
	Mounts []MountPoint `json:"Mounts"`
	// Config is the process configuration.
	Config *ContainerConfig `json:"Config"`
	// NetworkSettings is the network view.
	NetworkSettings *NetworkSettings `json:"NetworkSettings"`
}

// ContainerSummary is one entry of GET /containers/json.
type ContainerSummary struct {
	// ID is the full container id.
	ID string `json:"Id"`
	// Names carry a leading slash.
	Names []string `json:"Names"`
	// Image is the reference the container was created from, ImageID its
	// resolved digest.
	Image   string `json:"Image"`
	ImageID string `json:"ImageID"`
	// Command is the entrypoint rendered as one line.
	Command string `json:"Command"`
	// Created is unix seconds, not a string: the list and the inspect
	// document disagree on this and both are load-bearing.
	Created int64 `json:"Created"`
	// Ports is the flat published-port view.
	Ports []Port `json:"Ports"`
	// SizeRw and SizeRootFs appear only with ?size=1.
	SizeRw     int64 `json:"SizeRw,omitempty"`
	SizeRootFs int64 `json:"SizeRootFs,omitempty"`
	// Labels are the container's labels.
	Labels map[string]string `json:"Labels"`
	// State is the lifecycle word, Status the human sentence.
	State  string `json:"State"`
	Status string `json:"Status"`
	// HostConfig carries only the network mode in a listing.
	HostConfig ContainerSummaryHostConfig `json:"HostConfig"`
	// NetworkSettings is the cut-down network view.
	NetworkSettings *SummaryNetworkSettings `json:"NetworkSettings"`
	// Mounts are the resolved mounts.
	Mounts []MountPoint `json:"Mounts"`
}

// ContainerSummaryHostConfig is the sliver of host config a listing carries.
type ContainerSummaryHostConfig struct {
	// NetworkMode is the container's network mode.
	NetworkMode string `json:"NetworkMode,omitempty"`
	// Annotations is accepted for compatibility.
	Annotations map[string]string `json:"Annotations,omitempty"`
}

// ContainerCreateRequest is the body of POST /containers/create: the image's
// Config fields, plus HostConfig and NetworkingConfig.
type ContainerCreateRequest struct {
	ContainerConfig
	// HostConfig is the host half of the definition.
	HostConfig *HostConfig `json:"HostConfig,omitempty"`
	// NetworkingConfig names the networks to attach at create time.
	NetworkingConfig *NetworkingConfig `json:"NetworkingConfig,omitempty"`
}

// NetworkingConfig is the create-time network attachment request.
type NetworkingConfig struct {
	// EndpointsConfig maps a network name to its endpoint settings.
	EndpointsConfig map[string]*EndpointSettings `json:"EndpointsConfig,omitempty"`
}

// ImageSummary is one entry of GET /images/json.
type ImageSummary struct {
	// ID is the image config digest.
	ID string `json:"Id"`
	// ParentID is empty: hull does not keep intermediate configs.
	ParentID string `json:"ParentId"`
	// RepoTags and RepoDigests are the references pointing at the image.
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
	// Created is unix seconds.
	Created int64 `json:"Created"`
	// Size is the sum of the uncompressed layers; VirtualSize repeats it for
	// clients that still read the old field.
	Size        int64 `json:"Size"`
	SharedSize  int64 `json:"SharedSize"`
	VirtualSize int64 `json:"VirtualSize"`
	// Labels are the image's labels.
	Labels map[string]string `json:"Labels"`
	// Containers is how many containers use the image, -1 when not computed.
	Containers int64 `json:"Containers"`
}

// ImageRootFS lists an image's layer diff ids.
type ImageRootFS struct {
	// Type is always "layers".
	Type string `json:"Type"`
	// Layers are the uncompressed layer digests, base first.
	Layers []string `json:"Layers"`
}

// ImageMetadata carries the tagging timestamp clients display.
type ImageMetadata struct {
	// LastTagTime is an RFC3339Nano instant, or the zero time.
	LastTagTime string `json:"LastTagTime"`
}

// ImageInspect is the body of GET /images/{name}/json.
type ImageInspect struct {
	// ID is the image config digest.
	ID string `json:"Id"`
	// RepoTags and RepoDigests are the references pointing at the image.
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
	// Parent and Comment are build-history fields.
	Parent  string `json:"Parent"`
	Comment string `json:"Comment"`
	// Created is an RFC3339Nano instant.
	Created string `json:"Created"`
	// Container and ContainerConfig are legacy build fields.
	Container       string           `json:"Container,omitempty"`
	ContainerConfig *ContainerConfig `json:"ContainerConfig,omitempty"`
	// DockerVersion and Author are build provenance.
	DockerVersion string `json:"DockerVersion"`
	Author        string `json:"Author"`
	// Config is the image's process configuration.
	Config *ContainerConfig `json:"Config"`
	// Architecture, Variant and Os describe the platform.
	Architecture string `json:"Architecture"`
	Variant      string `json:"Variant,omitempty"`
	Os           string `json:"Os"`
	OsVersion    string `json:"OsVersion,omitempty"`
	// Size and VirtualSize are the uncompressed layer total.
	Size        int64 `json:"Size"`
	VirtualSize int64 `json:"VirtualSize"`
	// GraphDriver names the storage driver.
	GraphDriver GraphDriverData `json:"GraphDriver"`
	// RootFS lists the layers.
	RootFS ImageRootFS `json:"RootFS"`
	// Metadata carries the tagging timestamp.
	Metadata ImageMetadata `json:"Metadata"`
}

// HistoryResponseItem is one entry of GET /images/{name}/history.
type HistoryResponseItem struct {
	// ID is the image id for the top entry and "<missing>" below it.
	ID string `json:"Id"`
	// Created is unix seconds.
	Created int64 `json:"Created"`
	// CreatedBy is the build instruction.
	CreatedBy string `json:"CreatedBy"`
	// Tags point at this entry, only ever on the top one.
	Tags []string `json:"Tags"`
	// Size is the layer's uncompressed size.
	Size int64 `json:"Size"`
	// Comment is the step's comment.
	Comment string `json:"Comment"`
}

// ImageDeleteResponseItem is one entry of the image-removal report.
type ImageDeleteResponseItem struct {
	// Untagged names a reference that was removed.
	Untagged string `json:"Untagged,omitempty"`
	// Deleted names an image id that was removed entirely.
	Deleted string `json:"Deleted,omitempty"`
}

// IPAMConfigEntry is one subnet plan in a network's IPAM block.
type IPAMConfigEntry struct {
	// Subnet is the CIDR.
	Subnet string `json:"Subnet,omitempty"`
	// IPRange narrows the allocatable part of Subnet.
	IPRange string `json:"IPRange,omitempty"`
	// Gateway is the bridge address.
	Gateway string `json:"Gateway,omitempty"`
	// AuxiliaryAddresses are reserved names.
	AuxiliaryAddresses map[string]string `json:"AuxiliaryAddresses,omitempty"`
}

// IPAM is a network's address plan.
type IPAM struct {
	// Driver is the IPAM driver, always "default".
	Driver string `json:"Driver"`
	// Options are driver options.
	Options map[string]string `json:"Options,omitempty"`
	// Config is the list of subnet plans.
	Config []IPAMConfigEntry `json:"Config"`
}

// NetworkContainer is one container attached to a network, as inspect reports.
type NetworkContainer struct {
	// Name is the container name without a leading slash, which is how
	// Docker reports it here and nowhere else.
	Name string `json:"Name"`
	// EndpointID identifies the attachment.
	EndpointID string `json:"EndpointID"`
	// MacAddress is the endpoint's hardware address.
	MacAddress string `json:"MacAddress"`
	// IPv4Address and IPv6Address are CIDR-formatted.
	IPv4Address string `json:"IPv4Address"`
	IPv6Address string `json:"IPv6Address"`
}

// NetworkResource is a network as GET /networks and /networks/{id} report it.
type NetworkResource struct {
	// Name and ID identify the network.
	Name string `json:"Name"`
	ID   string `json:"Id"`
	// Created is an RFC3339Nano instant.
	Created string `json:"Created"`
	// Scope is always "local".
	Scope string `json:"Scope"`
	// Driver is bridge, host or none.
	Driver string `json:"Driver"`
	// EnableIPv6 reports IPv6 addressing, always false here.
	EnableIPv6 bool `json:"EnableIPv6"`
	// IPAM is the address plan.
	IPAM IPAM `json:"IPAM"`
	// Internal removes the masquerade rule.
	Internal bool `json:"Internal"`
	// Attachable, Ingress, ConfigOnly and ConfigFrom are swarm fields kept
	// so clients that read them do not panic.
	Attachable bool                   `json:"Attachable"`
	Ingress    bool                   `json:"Ingress"`
	ConfigFrom NetworkConfigReference `json:"ConfigFrom"`
	ConfigOnly bool                   `json:"ConfigOnly"`
	// Containers maps container id to its attachment.
	Containers map[string]NetworkContainer `json:"Containers"`
	// Options and Labels are driver options and user labels.
	Options map[string]string `json:"Options"`
	Labels  map[string]string `json:"Labels"`
}

// NetworkConfigReference is the swarm config-only pointer, always empty here.
type NetworkConfigReference struct {
	// Network is the name of the config-only network.
	Network string `json:"Network"`
}

// NetworkCreateRequest is the body of POST /networks/create.
type NetworkCreateRequest struct {
	// Name is the network name.
	Name string `json:"Name"`
	// CheckDuplicate is a removed flag clients still send.
	CheckDuplicate bool `json:"CheckDuplicate,omitempty"`
	// Driver must be "bridge".
	Driver string `json:"Driver"`
	// Internal, Attachable, Ingress and EnableIPv6 are network flags.
	Internal   bool `json:"Internal"`
	Attachable bool `json:"Attachable"`
	Ingress    bool `json:"Ingress"`
	EnableIPv6 bool `json:"EnableIPv6"`
	// IPAM is the requested address plan.
	IPAM *IPAM `json:"IPAM,omitempty"`
	// Options and Labels are driver options and user labels.
	Options map[string]string `json:"Options"`
	Labels  map[string]string `json:"Labels"`
}

// NetworkCreateResponse is the body of POST /networks/create.
type NetworkCreateResponse struct {
	// ID is the new network's id.
	ID string `json:"Id"`
	// Warning is non-empty when the network was created with a caveat.
	Warning string `json:"Warning"`
}

// NetworkConnectRequest is the body of POST /networks/{id}/connect.
type NetworkConnectRequest struct {
	// Container is the container id or name.
	Container string `json:"Container"`
	// EndpointConfig is the requested endpoint settings.
	EndpointConfig *EndpointSettings `json:"EndpointConfig,omitempty"`
}

// NetworkDisconnectRequest is the body of POST /networks/{id}/disconnect.
type NetworkDisconnectRequest struct {
	// Container is the container id or name.
	Container string `json:"Container"`
	// Force detaches even when the container is running.
	Force bool `json:"Force"`
}

// VolumeUsageData reports a volume's size and reference count.
type VolumeUsageData struct {
	// Size is the on-disk size, -1 when not computed.
	Size int64 `json:"Size"`
	// RefCount is how many containers reference it, -1 when not computed.
	RefCount int64 `json:"RefCount"`
}

// Volume is a named volume as the API reports it.
type Volume struct {
	// Name and Driver identify the volume.
	Name   string `json:"Name"`
	Driver string `json:"Driver"`
	// Mountpoint is the host directory.
	Mountpoint string `json:"Mountpoint"`
	// CreatedAt is an RFC3339 instant.
	CreatedAt string `json:"CreatedAt"`
	// Status is driver-specific state.
	Status map[string]any `json:"Status,omitempty"`
	// Labels and Options are user labels and driver options.
	Labels  map[string]string `json:"Labels"`
	Options map[string]string `json:"Options"`
	// Scope is always "local".
	Scope string `json:"Scope"`
	// UsageData is present in /system/df.
	UsageData *VolumeUsageData `json:"UsageData,omitempty"`
}

// VolumeCreateRequest is the body of POST /volumes/create.
type VolumeCreateRequest struct {
	// Name is the volume name; empty means generate one.
	Name string `json:"Name"`
	// Driver must be "local".
	Driver string `json:"Driver"`
	// DriverOpts are driver options.
	DriverOpts map[string]string `json:"DriverOpts"`
	// Labels are user labels.
	Labels map[string]string `json:"Labels"`
}

// VolumeListResponse is the body of GET /volumes.
type VolumeListResponse struct {
	// Volumes is the matching set.
	Volumes []*Volume `json:"Volumes"`
	// Warnings is always empty; hull has no remote volume drivers to warn
	// about.
	Warnings []string `json:"Warnings"`
}

// ContainerPruneResponse is the body of POST /containers/prune.
type ContainerPruneResponse struct {
	// ContainersDeleted lists the removed container ids.
	ContainersDeleted []string `json:"ContainersDeleted"`
	// SpaceReclaimed is the number of bytes freed.
	SpaceReclaimed int64 `json:"SpaceReclaimed"`
}

// ImagePruneResponse is the body of POST /images/prune.
type ImagePruneResponse struct {
	// ImagesDeleted lists what was untagged and deleted.
	ImagesDeleted []ImageDeleteResponseItem `json:"ImagesDeleted"`
	// SpaceReclaimed is the number of bytes freed.
	SpaceReclaimed int64 `json:"SpaceReclaimed"`
}

// NetworkPruneResponse is the body of POST /networks/prune.
type NetworkPruneResponse struct {
	// NetworksDeleted lists the removed network names.
	NetworksDeleted []string `json:"NetworksDeleted"`
}

// VolumePruneResponse is the body of POST /volumes/prune.
type VolumePruneResponse struct {
	// VolumesDeleted lists the removed volume names.
	VolumesDeleted []string `json:"VolumesDeleted"`
	// SpaceReclaimed is the number of bytes freed.
	SpaceReclaimed int64 `json:"SpaceReclaimed"`
}

// BuildCache is one build-cache record in /system/df. hull has no native
// builder yet, so the list is empty.
type BuildCache struct {
	// ID identifies the cache record.
	ID string `json:"ID"`
	// Type is the cache record's kind.
	Type string `json:"Type"`
	// Size is its on-disk size.
	Size int64 `json:"Size"`
	// InUse and Shared describe its reachability.
	InUse  bool `json:"InUse"`
	Shared bool `json:"Shared"`
}

// DiskUsage is the body of GET /system/df.
type DiskUsage struct {
	// LayersSize is the total size of all image layers.
	LayersSize int64 `json:"LayersSize"`
	// Images, Containers and Volumes are the per-object breakdowns.
	Images     []*ImageSummary     `json:"Images"`
	Containers []*ContainerSummary `json:"Containers"`
	Volumes    []*Volume           `json:"Volumes"`
	// BuildCache and BuilderSize describe the builder's storage.
	BuildCache  []*BuildCache `json:"BuildCache"`
	BuilderSize int64         `json:"BuilderSize"`
}

// ExecCreateRequest is the body of POST /containers/{id}/exec.
type ExecCreateRequest struct {
	// AttachStdin, AttachStdout and AttachStderr select the streams.
	AttachStdin  bool `json:"AttachStdin"`
	AttachStdout bool `json:"AttachStdout"`
	AttachStderr bool `json:"AttachStderr"`
	// ConsoleSize is the initial tty size.
	ConsoleSize *[2]uint `json:"ConsoleSize,omitempty"`
	// DetachKeys is the detach sequence.
	DetachKeys string `json:"DetachKeys"`
	// Tty allocates a pseudo-terminal.
	Tty bool `json:"Tty"`
	// Env entries are merged over the container's environment.
	Env []string `json:"Env"`
	// Cmd is the command to run.
	Cmd []string `json:"Cmd"`
	// Privileged gives the exec every capability.
	Privileged bool `json:"Privileged"`
	// User is the user spec to run as.
	User string `json:"User"`
	// WorkingDir overrides the container's working directory.
	WorkingDir string `json:"WorkingDir"`
}

// ExecStartRequest is the body of POST /exec/{id}/start.
type ExecStartRequest struct {
	// Detach runs the exec without streaming its output.
	Detach bool `json:"Detach"`
	// Tty says the client has a terminal, so the stream is not framed.
	Tty bool `json:"Tty"`
	// ConsoleSize is the initial tty size.
	ConsoleSize *[2]uint `json:"ConsoleSize,omitempty"`
}

// ExecProcessConfig is the ProcessConfig block of an exec inspect.
type ExecProcessConfig struct {
	// Tty reports a pseudo-terminal.
	Tty bool `json:"tty"`
	// Entrypoint and Arguments are the command, split.
	Entrypoint string   `json:"entrypoint"`
	Arguments  []string `json:"arguments"`
	// Privileged reports an unconfined exec.
	Privileged bool `json:"privileged"`
	// User is the user spec.
	User string `json:"user,omitempty"`
}

// ExecInspect is the body of GET /exec/{id}/json.
type ExecInspect struct {
	// ID is the exec id.
	ID string `json:"ID"`
	// Running reports a live exec process.
	Running bool `json:"Running"`
	// ExitCode is meaningful once Running is false.
	ExitCode int `json:"ExitCode"`
	// ProcessConfig describes the command.
	ProcessConfig *ExecProcessConfig `json:"ProcessConfig"`
	// OpenStdin, OpenStderr and OpenStdout echo the request.
	OpenStdin  bool `json:"OpenStdin"`
	OpenStderr bool `json:"OpenStderr"`
	OpenStdout bool `json:"OpenStdout"`
	// CanRemove is always false; hull garbage-collects execs with their
	// container.
	CanRemove bool `json:"CanRemove"`
	// ContainerID is the container the exec belongs to.
	ContainerID string `json:"ContainerID"`
	// DetachKeys is the detach sequence.
	DetachKeys string `json:"DetachKeys"`
	// Pid is the exec process's pid.
	Pid int `json:"Pid"`
}

// CommitResponse is the body of POST /commit.
type CommitResponse struct {
	// ID is the new image's id.
	ID string `json:"Id"`
}

// DistributionInspect is the body of GET /distribution/{name}/json.
type DistributionInspect struct {
	// Descriptor is the manifest descriptor the reference resolves to.
	Descriptor DistributionDescriptor `json:"Descriptor"`
	// Platforms lists the platforms the reference can be pulled for.
	Platforms []DistributionPlatform `json:"Platforms"`
}

// DistributionDescriptor is an OCI descriptor as /distribution reports it.
type DistributionDescriptor struct {
	// MediaType is the manifest's media type.
	MediaType string `json:"mediaType"`
	// Digest is the manifest digest.
	Digest string `json:"digest"`
	// Size is the manifest size in bytes.
	Size int64 `json:"size"`
}

// DistributionPlatform is one platform a reference resolves for.
type DistributionPlatform struct {
	// Architecture, OS and Variant identify the platform.
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	OSVersion    string `json:"os.version,omitempty"`
	Variant      string `json:"variant,omitempty"`
}
