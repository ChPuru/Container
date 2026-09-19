// Package types holds the domain model shared by every hull subsystem.
// Nothing here may import another hull package, so it stays the common
// vocabulary for the engine, the API layer, the CLI and the TUI.
package types

import "time"

// ---------- images ----------

// Descriptor is an OCI content descriptor (image-spec v1.1.1).
type Descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	URLs         []string          `json:"urls,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Platform     *Platform         `json:"platform,omitempty"`
	ArtifactType string            `json:"artifactType,omitempty"`
}

// Platform identifies an OS/arch/variant triple.
type Platform struct {
	Architecture string   `json:"architecture"`
	OS           string   `json:"os"`
	OSVersion    string   `json:"os.version,omitempty"`
	OSFeatures   []string `json:"os.features,omitempty"`
	Variant      string   `json:"variant,omitempty"`
}

// Image is a pulled image as hull records it locally.
type Image struct {
	ID           string            `json:"id"`     // sha256:... of the config blob
	Digest       string            `json:"digest"` // sha256:... of the manifest
	RepoTags     []string          `json:"repoTags"`
	RepoDigests  []string          `json:"repoDigests"`
	Created      time.Time         `json:"created"`
	Size         int64             `json:"size"` // sum of uncompressed layer sizes
	Architecture string            `json:"architecture"`
	OS           string            `json:"os"`
	DiffIDs      []string          `json:"diffIDs"` // uncompressed layer digests, base first
	ChainID      string            `json:"chainID"` // ChainID of the topmost layer
	Config       ImageConfig       `json:"config"`
	Labels       map[string]string `json:"labels,omitempty"`
	ManifestType string            `json:"manifestType"`
}

// ImageConfig is the runtime-relevant half of an OCI image config.
type ImageConfig struct {
	User         string              `json:"User,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	Env          []string            `json:"Env,omitempty"`
	Entrypoint   []string            `json:"Entrypoint,omitempty"`
	Cmd          []string            `json:"Cmd,omitempty"`
	Volumes      map[string]struct{} `json:"Volumes,omitempty"`
	WorkingDir   string              `json:"WorkingDir,omitempty"`
	Labels       map[string]string   `json:"Labels,omitempty"`
	StopSignal   string              `json:"StopSignal,omitempty"`
	Healthcheck  *Healthcheck        `json:"Healthcheck,omitempty"`
	Shell        []string            `json:"Shell,omitempty"`
}

// Healthcheck mirrors Docker's image-level healthcheck block.
type Healthcheck struct {
	Test        []string      `json:"Test,omitempty"`
	Interval    time.Duration `json:"Interval,omitempty"`
	Timeout     time.Duration `json:"Timeout,omitempty"`
	StartPeriod time.Duration `json:"StartPeriod,omitempty"`
	Retries     int           `json:"Retries,omitempty"`
}

// ---------- containers ----------

// State is the lifecycle state of a container.
type State string

// Container lifecycle states, matching Docker's vocabulary.
const (
	StateCreated    State = "created"
	StateRunning    State = "running"
	StatePaused     State = "paused"
	StateRestarting State = "restarting"
	StateRemoving   State = "removing"
	StateExited     State = "exited"
	StateDead       State = "dead"
)

// Container is hull's persistent record of one container.
type Container struct {
	ID       string    `json:"id"`   // 64 hex chars
	Name     string    `json:"name"` // without leading slash
	Created  time.Time `json:"created"`
	Image    string    `json:"image"`    // image ID (sha256:...)
	ImageRef string    `json:"imageRef"` // what the user asked for, e.g. alpine:3.20

	Config     ContainerConfig `json:"config"`
	HostConfig HostConfig      `json:"hostConfig"`

	// Runtime state.
	State        State     `json:"state"`
	Pid          int       `json:"pid"`
	ExitCode     int       `json:"exitCode"`
	Error        string    `json:"error,omitempty"`
	StartedAt    time.Time `json:"startedAt"`
	FinishedAt   time.Time `json:"finishedAt"`
	OOMKilled    bool      `json:"oomKilled"`
	RestartCount int       `json:"restartCount"`

	// Filesystem.
	SnapshotID string `json:"snapshotID"`
	RootFS     string `json:"rootfs"` // mounted merged dir
	BundleDir  string `json:"bundle"` // where config.json lives

	// Networking.
	NetworkSettings NetworkSettings `json:"networkSettings"`

	// Health.
	Health *HealthState `json:"health,omitempty"`
}

// ContainerConfig is the image-derived plus user-supplied process configuration.
type ContainerConfig struct {
	Hostname     string              `json:"hostname"`
	Domainname   string              `json:"domainname,omitempty"`
	User         string              `json:"user,omitempty"`
	AttachStdin  bool                `json:"attachStdin"`
	AttachStdout bool                `json:"attachStdout"`
	AttachStderr bool                `json:"attachStderr"`
	Tty          bool                `json:"tty"`
	OpenStdin    bool                `json:"openStdin"`
	StdinOnce    bool                `json:"stdinOnce"`
	Env          []string            `json:"env,omitempty"`
	Cmd          []string            `json:"cmd,omitempty"`
	Entrypoint   []string            `json:"entrypoint,omitempty"`
	WorkingDir   string              `json:"workingDir,omitempty"`
	Labels       map[string]string   `json:"labels,omitempty"`
	ExposedPorts map[string]struct{} `json:"exposedPorts,omitempty"`
	StopSignal   string              `json:"stopSignal,omitempty"`
	StopTimeout  *int                `json:"stopTimeout,omitempty"`
	Healthcheck  *Healthcheck        `json:"healthcheck,omitempty"`
	Volumes      map[string]struct{} `json:"volumes,omitempty"`
}

// HostConfig is everything the host decides: resources, mounts, isolation, net.
type HostConfig struct {
	Binds          []string                 `json:"binds,omitempty"`
	Mounts         []Mount                  `json:"mounts,omitempty"`
	PortBindings   map[string][]PortBinding `json:"portBindings,omitempty"`
	PublishAll     bool                     `json:"publishAllPorts"`
	NetworkMode    string                   `json:"networkMode"` // bridge|host|none|container:<id>|<name>
	DNS            []string                 `json:"dns,omitempty"`
	DNSSearch      []string                 `json:"dnsSearch,omitempty"`
	ExtraHosts     []string                 `json:"extraHosts,omitempty"`
	RestartPolicy  RestartPolicy            `json:"restartPolicy"`
	AutoRemove     bool                     `json:"autoRemove"`
	Privileged     bool                     `json:"privileged"`
	ReadonlyRootfs bool                     `json:"readonlyRootfs"`
	CapAdd         []string                 `json:"capAdd,omitempty"`
	CapDrop        []string                 `json:"capDrop,omitempty"`
	SecurityOpt    []string                 `json:"securityOpt,omitempty"`
	Sysctls        map[string]string        `json:"sysctls,omitempty"`
	Tmpfs          map[string]string        `json:"tmpfs,omitempty"`
	Init           bool                     `json:"init"`
	Runtime        string                   `json:"runtime,omitempty"` // "hull" (native) or "crun"
	ShmSize        int64                    `json:"shmSize,omitempty"`
	Resources      Resources                `json:"resources"`
	Isolation      string                   `json:"isolation,omitempty"` // ""|userns|gvisor
	LogConfig      LogConfig                `json:"logConfig"`
	GroupAdd       []string                 `json:"groupAdd,omitempty"`
	Ulimits        []Ulimit                 `json:"ulimits,omitempty"`
	OomScoreAdj    int                      `json:"oomScoreAdj,omitempty"`
	PidsLimit      *int64                   `json:"pidsLimit,omitempty"`
	Devices        []DeviceMapping          `json:"devices,omitempty"`
	UsernsMode     string                   `json:"usernsMode,omitempty"` // ""|host|private
}

// Resources are the cgroup v2 knobs hull supports.
type Resources struct {
	Memory            int64  `json:"memory,omitempty"`            // bytes, memory.max
	MemoryReservation int64  `json:"memoryReservation,omitempty"` // bytes, memory.low
	MemorySwap        int64  `json:"memorySwap,omitempty"`        // bytes, total mem+swap
	CPUShares         int64  `json:"cpuShares,omitempty"`         // maps to cpu.weight
	CPUQuota          int64  `json:"cpuQuota,omitempty"`          // us per period
	CPUPeriod         int64  `json:"cpuPeriod,omitempty"`         // us
	CpusetCpus        string `json:"cpusetCpus,omitempty"`
	CpusetMems        string `json:"cpusetMems,omitempty"`
	BlkioWeight       uint16 `json:"blkioWeight,omitempty"` // maps to io.weight
	NanoCPUs          int64  `json:"nanoCpus,omitempty"`
}

// Ulimit is a single rlimit override.
type Ulimit struct {
	Name string `json:"name"`
	Soft int64  `json:"soft"`
	Hard int64  `json:"hard"`
}

// DeviceMapping exposes a host device inside the container.
type DeviceMapping struct {
	PathOnHost        string `json:"pathOnHost"`
	PathInContainer   string `json:"pathInContainer"`
	CgroupPermissions string `json:"cgroupPermissions"`
}

// LogConfig selects the log driver. hull only ships "json-file" and "none".
type LogConfig struct {
	Type   string            `json:"type"`
	Config map[string]string `json:"config,omitempty"`
}

// RestartPolicy mirrors Docker's.
type RestartPolicy struct {
	Name              string `json:"name"` // ""|no|always|unless-stopped|on-failure
	MaximumRetryCount int    `json:"maximumRetryCount,omitempty"`
}

// Mount is a long-form mount request.
type Mount struct {
	Type         string        `json:"type"` // bind|volume|tmpfs
	Source       string        `json:"source,omitempty"`
	Target       string        `json:"target"`
	ReadOnly     bool          `json:"readOnly,omitempty"`
	Consistency  string        `json:"consistency,omitempty"`
	BindOptions  *BindOptions  `json:"bindOptions,omitempty"`
	TmpfsOptions *TmpfsOptions `json:"tmpfsOptions,omitempty"`
}

// BindOptions carries bind-specific flags.
type BindOptions struct {
	Propagation      string `json:"propagation,omitempty"`
	CreateMountpoint bool   `json:"createMountpoint,omitempty"`
}

// TmpfsOptions carries tmpfs-specific flags.
type TmpfsOptions struct {
	SizeBytes int64  `json:"sizeBytes,omitempty"`
	Mode      uint32 `json:"mode,omitempty"`
}

// PortBinding is one host side of a published port.
type PortBinding struct {
	HostIP   string `json:"hostIp,omitempty"`
	HostPort string `json:"hostPort,omitempty"`
}

// ---------- networking ----------

// Network is a user-defined or built-in hull network.
type Network struct {
	ID         string                      `json:"id"`
	Name       string                      `json:"name"`
	Driver     string                      `json:"driver"` // bridge|host|none
	Scope      string                      `json:"scope"`
	Created    time.Time                   `json:"created"`
	Internal   bool                        `json:"internal"`
	Attachable bool                        `json:"attachable"`
	EnableIPv6 bool                        `json:"enableIPv6"`
	IPAM       IPAMConfig                  `json:"ipam"`
	Options    map[string]string           `json:"options,omitempty"`
	Labels     map[string]string           `json:"labels,omitempty"`
	BridgeName string                      `json:"bridgeName"`
	Containers map[string]EndpointSettings `json:"containers,omitempty"`
}

// IPAMConfig describes a network's address plan.
type IPAMConfig struct {
	Driver       string            `json:"driver"`
	Subnet       string            `json:"subnet"`
	Gateway      string            `json:"gateway"`
	IPRange      string            `json:"ipRange,omitempty"`
	AuxAddresses map[string]string `json:"auxAddresses,omitempty"`
}

// EndpointSettings is one container's attachment to one network.
type EndpointSettings struct {
	NetworkID   string   `json:"networkId"`
	EndpointID  string   `json:"endpointId"`
	Gateway     string   `json:"gateway"`
	IPAddress   string   `json:"ipAddress"`
	IPPrefixLen int      `json:"ipPrefixLen"`
	MacAddress  string   `json:"macAddress"`
	Aliases     []string `json:"aliases,omitempty"`
	DNSNames    []string `json:"dnsNames,omitempty"`
	HostIfname  string   `json:"hostIfname"` // veth peer name on the host side
}

// NetworkSettings is the container-side view of all its attachments.
type NetworkSettings struct {
	SandboxKey string                      `json:"sandboxKey"`
	Networks   map[string]EndpointSettings `json:"networks"`
	Ports      map[string][]PortBinding    `json:"ports,omitempty"`
}

// ---------- volumes ----------

// Volume is a named volume.
type Volume struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	Created    time.Time         `json:"created"`
	Labels     map[string]string `json:"labels,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
	Scope      string            `json:"scope"`
}

// ---------- health and events ----------

// HealthState tracks healthcheck results.
type HealthState struct {
	Status        string      `json:"status"` // starting|healthy|unhealthy
	FailingStreak int         `json:"failingStreak"`
	Log           []HealthLog `json:"log,omitempty"`
}

// HealthLog is one healthcheck probe result.
type HealthLog struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	ExitCode int       `json:"exitCode"`
	Output   string    `json:"output"`
}

// Event is one entry on the engine event bus.
type Event struct {
	Type     string     `json:"type"`   // container|image|network|volume|daemon
	Action   string     `json:"action"` // create|start|die|...
	Actor    EventActor `json:"actor"`
	Scope    string     `json:"scope"`
	Time     int64      `json:"time"`
	TimeNano int64      `json:"timeNano"`
}

// EventActor names the object an event is about.
type EventActor struct {
	ID         string            `json:"id"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// ---------- stats ----------

// Stats is a point-in-time resource sample for one container.
type Stats struct {
	Read           time.Time `json:"read"`
	PreRead        time.Time `json:"preread"`
	CPUUsage       uint64    `json:"cpuUsageUsec"`
	PreCPUUsage    uint64    `json:"preCpuUsageUsec"`
	SystemUsage    uint64    `json:"systemUsageUsec"`
	PreSystemUsage uint64    `json:"preSystemUsageUsec"`
	OnlineCPUs     int       `json:"onlineCpus"`
	MemoryUsage    uint64    `json:"memoryUsage"`
	MemoryLimit    uint64    `json:"memoryLimit"`
	MemoryCache    uint64    `json:"memoryCache"`
	PidsCurrent    uint64    `json:"pidsCurrent"`
	PidsLimit      uint64    `json:"pidsLimit"`
	RxBytes        uint64    `json:"rxBytes"`
	TxBytes        uint64    `json:"txBytes"`
	RxPackets      uint64    `json:"rxPackets"`
	TxPackets      uint64    `json:"txPackets"`
	BlkRead        uint64    `json:"blkRead"`
	BlkWrite       uint64    `json:"blkWrite"`

	// PSI fields are only populated on kernels with CONFIG_PSI (6.x WSL kernels).
	MemPressureSome10 float64 `json:"memPressureSome10,omitempty"`
	CPUPressureSome10 float64 `json:"cpuPressureSome10,omitempty"`
	IOPressureSome10  float64 `json:"ioPressureSome10,omitempty"`
}
