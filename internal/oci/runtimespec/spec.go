// Package runtimespec holds the OCI runtime-spec v1.2 config.json types that
// hull writes into a container bundle. The structs are wire types: every
// optional numeric field is a pointer so encoding/json omits it exactly the
// way runc and crun expect, and every field name matches the spec's JSON name.
//
// The package is pure data plus validation; it performs no I/O and is safe to
// build on every GOOS, including the Windows CLI.
package runtimespec

// Version is the runtime-spec version hull emits.
const Version = "1.2.0"

// Spec is the top-level config.json of an OCI bundle.
type Spec struct {
	Version     string            `json:"ociVersion"`
	Process     *Process          `json:"process,omitempty"`
	Root        *Root             `json:"root,omitempty"`
	Hostname    string            `json:"hostname,omitempty"`
	Domainname  string            `json:"domainname,omitempty"`
	Mounts      []Mount           `json:"mounts,omitempty"`
	Hooks       *Hooks            `json:"hooks,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Linux       *Linux            `json:"linux,omitempty"`
}

// Process describes the container's initial process.
type Process struct {
	Terminal        bool               `json:"terminal,omitempty"`
	ConsoleSize     *Box               `json:"consoleSize,omitempty"`
	User            User               `json:"user"`
	Args            []string           `json:"args,omitempty"`
	CommandLine     string             `json:"commandLine,omitempty"`
	Env             []string           `json:"env,omitempty"`
	Cwd             string             `json:"cwd"`
	Capabilities    *LinuxCapabilities `json:"capabilities,omitempty"`
	Rlimits         []POSIXRlimit      `json:"rlimits,omitempty"`
	NoNewPrivileges bool               `json:"noNewPrivileges,omitempty"`
	ApparmorProfile string             `json:"apparmorProfile,omitempty"`
	OOMScoreAdj     *int               `json:"oomScoreAdj,omitempty"`
	SelinuxLabel    string             `json:"selinuxLabel,omitempty"`
	Scheduler       *Scheduler         `json:"scheduler,omitempty"`
	IOPriority      *LinuxIOPriority   `json:"ioPriority,omitempty"`
	ExecCPUAffinity *CPUAffinity       `json:"execCPUAffinity,omitempty"`
}

// Box is a terminal size in character cells.
type Box struct {
	Height uint `json:"height"`
	Width  uint `json:"width"`
}

// User is the uid/gid the container process runs as.
type User struct {
	UID            uint32   `json:"uid"`
	GID            uint32   `json:"gid"`
	Umask          *uint32  `json:"umask,omitempty"`
	AdditionalGids []uint32 `json:"additionalGids,omitempty"`
	Username       string   `json:"username,omitempty"`
}

// LinuxCapabilities is the five capability sets of the container process.
type LinuxCapabilities struct {
	Bounding    []string `json:"bounding,omitempty"`
	Effective   []string `json:"effective,omitempty"`
	Inheritable []string `json:"inheritable,omitempty"`
	Permitted   []string `json:"permitted,omitempty"`
	Ambient     []string `json:"ambient,omitempty"`
}

// POSIXRlimit is one setrlimit(2) value applied to the container process.
type POSIXRlimit struct {
	Type string `json:"type"`
	Hard uint64 `json:"hard"`
	Soft uint64 `json:"soft"`
}

// Scheduler selects the process scheduling policy (runtime-spec v1.2).
type Scheduler struct {
	Policy   string   `json:"policy"`
	Nice     int32    `json:"nice,omitempty"`
	Priority int32    `json:"priority,omitempty"`
	Flags    []string `json:"flags,omitempty"`
	Runtime  uint64   `json:"runtime,omitempty"`
	Deadline uint64   `json:"deadline,omitempty"`
	Period   uint64   `json:"period,omitempty"`
}

// Scheduler policy values accepted in Scheduler.Policy.
const (
	SchedOther    = "SCHED_OTHER"
	SchedFIFO     = "SCHED_FIFO"
	SchedRR       = "SCHED_RR"
	SchedBatch    = "SCHED_BATCH"
	SchedISO      = "SCHED_ISO"
	SchedIdle     = "SCHED_IDLE"
	SchedDeadline = "SCHED_DEADLINE"
)

// LinuxIOPriority sets the container process's I/O scheduling class.
type LinuxIOPriority struct {
	Class    string `json:"class"`
	Priority int    `json:"priority"`
}

// I/O priority classes accepted in LinuxIOPriority.Class.
const (
	IOPrioClassRT   = "IOPRIO_CLASS_RT"
	IOPrioClassBE   = "IOPRIO_CLASS_BE"
	IOPrioClassIdle = "IOPRIO_CLASS_IDLE"
)

// CPUAffinity pins the exec'd process to a cpu set (runtime-spec v1.2).
type CPUAffinity struct {
	Initial string `json:"initial,omitempty"`
	Final   string `json:"final,omitempty"`
}

// Root is the container root filesystem.
type Root struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly,omitempty"`
}

// Mount is one filesystem mounted into the container.
type Mount struct {
	Destination string           `json:"destination"`
	Type        string           `json:"type,omitempty"`
	Source      string           `json:"source,omitempty"`
	Options     []string         `json:"options,omitempty"`
	UIDMappings []LinuxIDMapping `json:"uidMappings,omitempty"`
	GIDMappings []LinuxIDMapping `json:"gidMappings,omitempty"`
}

// Hooks are the lifecycle hooks the runtime invokes.
type Hooks struct {
	Prestart        []Hook `json:"prestart,omitempty"`
	CreateRuntime   []Hook `json:"createRuntime,omitempty"`
	CreateContainer []Hook `json:"createContainer,omitempty"`
	StartContainer  []Hook `json:"startContainer,omitempty"`
	Poststart       []Hook `json:"poststart,omitempty"`
	Poststop        []Hook `json:"poststop,omitempty"`
}

// Hook is one executable the runtime runs at a lifecycle point.
type Hook struct {
	Path    string   `json:"path"`
	Args    []string `json:"args,omitempty"`
	Env     []string `json:"env,omitempty"`
	Timeout *int     `json:"timeout,omitempty"`
}

// Linux is the Linux-specific half of the spec.
type Linux struct {
	UIDMappings       []LinuxIDMapping           `json:"uidMappings,omitempty"`
	GIDMappings       []LinuxIDMapping           `json:"gidMappings,omitempty"`
	Sysctl            map[string]string          `json:"sysctl,omitempty"`
	Resources         *LinuxResources            `json:"resources,omitempty"`
	CgroupsPath       string                     `json:"cgroupsPath,omitempty"`
	Namespaces        []LinuxNamespace           `json:"namespaces,omitempty"`
	Devices           []LinuxDevice              `json:"devices,omitempty"`
	Seccomp           *LinuxSeccomp              `json:"seccomp,omitempty"`
	RootfsPropagation string                     `json:"rootfsPropagation,omitempty"`
	MaskedPaths       []string                   `json:"maskedPaths,omitempty"`
	ReadonlyPaths     []string                   `json:"readonlyPaths,omitempty"`
	MountLabel        string                     `json:"mountLabel,omitempty"`
	IntelRdt          *LinuxIntelRdt             `json:"intelRdt,omitempty"`
	Personality       *LinuxPersonality          `json:"personality,omitempty"`
	TimeOffsets       map[string]LinuxTimeOffset `json:"timeOffsets,omitempty"`
}

// LinuxNamespace is one namespace the container joins or creates.
type LinuxNamespace struct {
	Type LinuxNamespaceType `json:"type"`
	Path string             `json:"path,omitempty"`
}

// LinuxNamespaceType names a Linux namespace kind.
type LinuxNamespaceType string

// Namespace types defined by the runtime spec.
const (
	PIDNamespace     LinuxNamespaceType = "pid"
	NetworkNamespace LinuxNamespaceType = "network"
	MountNamespace   LinuxNamespaceType = "mount"
	IPCNamespace     LinuxNamespaceType = "ipc"
	UTSNamespace     LinuxNamespaceType = "uts"
	UserNamespace    LinuxNamespaceType = "user"
	CgroupNamespace  LinuxNamespaceType = "cgroup"
	TimeNamespace    LinuxNamespaceType = "time"
)

// LinuxIDMapping is one line of /proc/<pid>/uid_map or gid_map.
type LinuxIDMapping struct {
	ContainerID uint32 `json:"containerID"`
	HostID      uint32 `json:"hostID"`
	Size        uint32 `json:"size"`
}

// LinuxTimeOffset is a time-namespace clock offset.
type LinuxTimeOffset struct {
	Secs     int64  `json:"secs,omitempty"`
	Nanosecs uint32 `json:"nanosecs,omitempty"`
}

// LinuxResources are the cgroup limits applied to the container.
type LinuxResources struct {
	Devices        []LinuxDeviceCgroup  `json:"devices,omitempty"`
	Memory         *LinuxMemory         `json:"memory,omitempty"`
	CPU            *LinuxCPU            `json:"cpu,omitempty"`
	Pids           *LinuxPids           `json:"pids,omitempty"`
	BlockIO        *LinuxBlockIO        `json:"blockIO,omitempty"`
	HugepageLimits []LinuxHugepageLimit `json:"hugepageLimits,omitempty"`
	Network        *LinuxNetwork        `json:"network,omitempty"`
	Rdma           map[string]LinuxRdma `json:"rdma,omitempty"`
	Unified        map[string]string    `json:"unified,omitempty"`
}

// LinuxMemory is the memory controller configuration.
type LinuxMemory struct {
	Limit             *int64  `json:"limit,omitempty"`
	Reservation       *int64  `json:"reservation,omitempty"`
	Swap              *int64  `json:"swap,omitempty"`
	Kernel            *int64  `json:"kernel,omitempty"`
	KernelTCP         *int64  `json:"kernelTCP,omitempty"`
	Swappiness        *uint64 `json:"swappiness,omitempty"`
	DisableOOMKiller  *bool   `json:"disableOOMKiller,omitempty"`
	UseHierarchy      *bool   `json:"useHierarchy,omitempty"`
	CheckBeforeUpdate *bool   `json:"checkBeforeUpdate,omitempty"`
}

// LinuxCPU is the cpu and cpuset controller configuration.
type LinuxCPU struct {
	Shares          *uint64 `json:"shares,omitempty"`
	Quota           *int64  `json:"quota,omitempty"`
	Period          *uint64 `json:"period,omitempty"`
	RealtimeRuntime *int64  `json:"realtimeRuntime,omitempty"`
	RealtimePeriod  *uint64 `json:"realtimePeriod,omitempty"`
	Cpus            string  `json:"cpus,omitempty"`
	Mems            string  `json:"mems,omitempty"`
	Idle            *int64  `json:"idle,omitempty"`
	Burst           *uint64 `json:"burst,omitempty"`
}

// LinuxPids is the pids controller configuration.
type LinuxPids struct {
	Limit int64 `json:"limit"`
}

// LinuxBlockIO is the blkio (v1) / io (v2) controller configuration.
type LinuxBlockIO struct {
	Weight                  *uint16               `json:"weight,omitempty"`
	LeafWeight              *uint16               `json:"leafWeight,omitempty"`
	WeightDevice            []LinuxWeightDevice   `json:"weightDevice,omitempty"`
	ThrottleReadBpsDevice   []LinuxThrottleDevice `json:"throttleReadBpsDevice,omitempty"`
	ThrottleWriteBpsDevice  []LinuxThrottleDevice `json:"throttleWriteBpsDevice,omitempty"`
	ThrottleReadIOPSDevice  []LinuxThrottleDevice `json:"throttleReadIOPSDevice,omitempty"`
	ThrottleWriteIOPSDevice []LinuxThrottleDevice `json:"throttleWriteIOPSDevice,omitempty"`
}

// LinuxWeightDevice is a per-device blkio weight.
type LinuxWeightDevice struct {
	Major      int64   `json:"major"`
	Minor      int64   `json:"minor"`
	Weight     *uint16 `json:"weight,omitempty"`
	LeafWeight *uint16 `json:"leafWeight,omitempty"`
}

// LinuxThrottleDevice is a per-device I/O rate limit.
type LinuxThrottleDevice struct {
	Major int64  `json:"major"`
	Minor int64  `json:"minor"`
	Rate  uint64 `json:"rate"`
}

// LinuxHugepageLimit limits hugetlb usage for one page size.
type LinuxHugepageLimit struct {
	Pagesize string `json:"pageSize"`
	Limit    uint64 `json:"limit"`
}

// LinuxNetwork is the net_cls/net_prio controller configuration.
type LinuxNetwork struct {
	ClassID    *uint32                  `json:"classID,omitempty"`
	Priorities []LinuxInterfacePriority `json:"priorities,omitempty"`
}

// LinuxInterfacePriority is one net_prio entry.
type LinuxInterfacePriority struct {
	Name     string `json:"name"`
	Priority uint32 `json:"priority"`
}

// LinuxRdma limits RDMA resources for one device.
type LinuxRdma struct {
	HcaHandles *uint32 `json:"hcaHandles,omitempty"`
	HcaObjects *uint32 `json:"hcaObjects,omitempty"`
}

// LinuxDeviceCgroup is one device cgroup allow/deny rule.
type LinuxDeviceCgroup struct {
	Allow  bool   `json:"allow"`
	Type   string `json:"type,omitempty"`
	Major  *int64 `json:"major,omitempty"`
	Minor  *int64 `json:"minor,omitempty"`
	Access string `json:"access,omitempty"`
}

// LinuxDevice is a device node the runtime creates inside the container.
type LinuxDevice struct {
	Path     string  `json:"path"`
	Type     string  `json:"type"`
	Major    int64   `json:"major"`
	Minor    int64   `json:"minor"`
	FileMode *uint32 `json:"fileMode,omitempty"`
	UID      *uint32 `json:"uid,omitempty"`
	GID      *uint32 `json:"gid,omitempty"`
}

// LinuxIntelRdt configures Intel RDT cache and memory-bandwidth allocation.
type LinuxIntelRdt struct {
	ClosID        string `json:"closID,omitempty"`
	L3CacheSchema string `json:"l3CacheSchema,omitempty"`
	MemBwSchema   string `json:"memBwSchema,omitempty"`
	EnableCMT     bool   `json:"enableCMT,omitempty"`
	EnableMBM     bool   `json:"enableMBM,omitempty"`
}

// LinuxPersonality sets the personality(2) execution domain.
type LinuxPersonality struct {
	Domain string   `json:"domain"`
	Flags  []string `json:"flags,omitempty"`
}

// Personality domains accepted in LinuxPersonality.Domain.
const (
	PerLinux   = "LINUX"
	PerLinux32 = "LINUX32"
)
