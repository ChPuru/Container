package engine

import (
	"io"
	"time"
)

// AttachConfig describes one client's attachment to a container's or an exec's
// standard streams.
//
// Stdin, Stdout and Stderr are the client's ends. A nil stream means the
// caller does not want that direction, which is also what the Use* flags say;
// both are honoured, so a caller may pass a writer and still disable the
// stream.
type AttachConfig struct {
	// Stdin is read and forwarded to the container. Nil disables input.
	Stdin io.Reader
	// Stdout and Stderr receive container output. For a tty container the
	// two streams are merged and everything arrives on Stdout.
	Stdout io.Writer
	Stderr io.Writer
	// UseStdin, UseStdout and UseStderr select the streams. A stream that is
	// not selected is never requested from the shim, so it is not carried
	// over the wire at all.
	UseStdin  bool
	UseStdout bool
	UseStderr bool
	// DetachKeys is the key sequence that ends the attachment without
	// signalling the container, e.g. "ctrl-p,ctrl-q". Empty means the shim's
	// default.
	DetachKeys string
	// Logs replays the container's existing log before the live stream
	// starts, which is what "docker attach --logs" does.
	Logs bool
	// Framed multiplexes output with the 8-byte Docker stream header instead
	// of writing raw bytes. The API layer sets it for a non-tty attach.
	Framed bool
	// Started, when non-nil, is closed once the attachment is live, so the
	// API layer can write its HTTP headers at exactly the right moment.
	Started chan struct{}
}

// wantsAnyStream reports whether the attachment asks for at least one stream.
func (a AttachConfig) wantsAnyStream() bool {
	return (a.UseStdin && a.Stdin != nil) ||
		(a.UseStdout && a.Stdout != nil) ||
		(a.UseStderr && a.Stderr != nil)
}

// ExecConfig is one "hull exec" request.
type ExecConfig struct {
	// Cmd is the command to run. It must be non-empty.
	Cmd []string
	// Env entries are merged over the container's environment, later wins.
	Env []string
	// User is a --user string resolved against the container's /etc/passwd.
	User string
	// WorkingDir overrides the container's working directory.
	WorkingDir string
	// Tty allocates a pseudo-terminal for the exec process.
	Tty bool
	// AttachStdin, AttachStdout and AttachStderr record which streams the
	// client intends to consume when it calls ExecStart.
	AttachStdin  bool
	AttachStdout bool
	AttachStderr bool
	// Privileged gives the exec every capability regardless of the
	// container's own set.
	Privileged bool
	// DetachKeys is the detach sequence for the exec's stream.
	DetachKeys string
}

// ExecInspect is the state of one exec, as "docker exec inspect" reports it.
type ExecInspect struct {
	// ID is the exec id returned by Exec.
	ID string `json:"id"`
	// ContainerID is the container the exec belongs to.
	ContainerID string `json:"containerId"`
	// Running reports that the exec process is alive.
	Running bool `json:"running"`
	// Started reports that ExecStart has been called at least once.
	Started bool `json:"started"`
	// ExitCode is meaningful once Running is false and Started is true.
	ExitCode int `json:"exitCode"`
	// Pid is the exec process's pid, 0 before it starts.
	Pid int `json:"pid"`
	// Cmd is the command the exec runs.
	Cmd []string `json:"cmd"`
	// Env, User, WorkingDir and Tty echo the request.
	Env        []string `json:"env,omitempty"`
	User       string   `json:"user,omitempty"`
	WorkingDir string   `json:"workingDir,omitempty"`
	Tty        bool     `json:"tty"`
	// Privileged echoes the request.
	Privileged bool `json:"privileged"`
	// AttachStdin, AttachStdout and AttachStderr echo the request.
	AttachStdin  bool `json:"attachStdin"`
	AttachStdout bool `json:"attachStdout"`
	AttachStderr bool `json:"attachStderr"`
	// Created is when Exec was called.
	Created time.Time `json:"created"`
}

// ListOptions narrows a container listing. Every filter is a slice because the
// Docker API allows a key to be repeated; repeated values of one key are ORed
// and different keys are ANDed, matching Docker exactly.
type ListOptions struct {
	// All includes containers that are not running. Without it only running
	// containers are listed.
	All bool
	// Limit returns only the most recently created n containers; 0 means no
	// limit.
	Limit int
	// Size asks for the writable-layer size to be computed. It is off by
	// default because it costs a filesystem walk per container.
	Size bool
	// Status matches types.Container.State exactly.
	Status []string
	// Name matches a substring of the container name, as Docker does.
	Name []string
	// ID matches a container id prefix.
	ID []string
	// Label holds "key" or "key=value" terms; all of them must match.
	Label []string
	// Ancestor matches containers created from an image id, or from a
	// reference that resolves to one.
	Ancestor []string
	// Network matches containers attached to a network by id or name.
	Network []string
	// Volume matches containers referencing a volume by name, or having a
	// mount whose target is the given path.
	Volume []string
	// Before and Since bound the listing by creation order relative to the
	// named container.
	Before []string
	Since  []string
	// Exited matches containers that exited with exactly this code.
	Exited []int
	// Health matches types.HealthState.Status.
	Health []string
}

// ImageListOptions narrows an image listing.
type ImageListOptions struct {
	// All includes untagged images. Without it, images with no repo tag are
	// hidden unless Dangling asks for them.
	All bool
	// Reference matches a repository[:tag] pattern, with "*" wildcards.
	Reference []string
	// Label holds "key" or "key=value" terms; all of them must match.
	Label []string
	// Dangling, when set, selects images that have no repo tag (true) or that
	// have one (false).
	Dangling *bool
	// Before and Since bound the listing by creation time relative to the
	// named image.
	Before []string
	Since  []string
}

// ImageDelete is one entry of the report ImageRemove returns, matching the
// Docker API's Untagged/Deleted shape.
type ImageDelete struct {
	// Untagged is the reference that was removed from an image.
	Untagged string `json:"untagged,omitempty"`
	// Deleted is the image id that was removed entirely.
	Deleted string `json:"deleted,omitempty"`
}

// HistoryEntry is one layer of an image's build history.
type HistoryEntry struct {
	// ID is the image id for the topmost entry and "<missing>" for the
	// intermediate ones, whose configs hull does not keep.
	ID string `json:"id"`
	// Created is when the build step ran.
	Created time.Time `json:"created"`
	// CreatedBy is the build instruction, verbatim.
	CreatedBy string `json:"createdBy"`
	// Size is the uncompressed size of the layer the step produced.
	Size int64 `json:"size"`
	// Comment is the config's comment for the step.
	Comment string `json:"comment,omitempty"`
	// Tags are the repo tags pointing at this entry, only ever set on the
	// topmost one.
	Tags []string `json:"tags,omitempty"`
	// EmptyLayer reports a step that produced no filesystem change.
	EmptyLayer bool `json:"emptyLayer,omitempty"`
}

// CommitOptions configures Commit.
type CommitOptions struct {
	// Repo and Tag name the resulting image; an empty Repo leaves it
	// dangling.
	Repo string
	Tag  string
	// Comment and Author are recorded in the new image's history.
	Comment string
	Author  string
	// Pause freezes the container for the duration of the commit so the
	// captured filesystem is consistent. Nil means "not specified", which
	// the engine reads as true.
	Pause *bool
	// Changes are build instructions applied to the committed config, such as
	// ENV, CMD, ENTRYPOINT, LABEL, USER, WORKDIR, EXPOSE or VOLUME.
	Changes []string
}

// CopyOptions configures CopyTo.
type CopyOptions struct {
	// AllowOverwriteDirWithFile permits replacing a directory with a file,
	// which Docker refuses by default.
	AllowOverwriteDirWithFile bool
	// CopyUIDGID preserves the uid and gid recorded in the archive.
	CopyUIDGID bool
}

// CopyStat describes the object CopyFrom is about to stream, and is what the
// Docker API returns in its path-stat header.
type CopyStat struct {
	// Name is the base name of the path inside the container.
	Name string `json:"name"`
	// Size is the file size in bytes, or the directory's own size.
	Size int64 `json:"size"`
	// Mode is the file mode bits.
	Mode uint32 `json:"mode"`
	// Mtime is the modification time.
	Mtime time.Time `json:"mtime"`
	// LinkTarget is the symlink target when the path is a symlink.
	LinkTarget string `json:"linkTarget,omitempty"`
}

// TopResult is the process table of one container.
type TopResult struct {
	// Titles are the column headers.
	Titles []string `json:"titles"`
	// Processes is one row per process, in the same column order.
	Processes [][]string `json:"processes"`
}

// PruneResult summarises one prune sweep.
type PruneResult struct {
	// ContainersDeleted, ImagesDeleted, VolumesDeleted and NetworksDeleted
	// name what was removed.
	ContainersDeleted []string `json:"containersDeleted,omitempty"`
	ImagesDeleted     []string `json:"imagesDeleted,omitempty"`
	VolumesDeleted    []string `json:"volumesDeleted,omitempty"`
	NetworksDeleted   []string `json:"networksDeleted,omitempty"`
	// SnapshotsDeleted names the dangling overlay snapshots that were
	// dropped.
	SnapshotsDeleted []string `json:"snapshotsDeleted,omitempty"`
	// SpaceReclaimed is the total number of bytes freed.
	SpaceReclaimed int64 `json:"spaceReclaimed"`
}

// LockEntry is one line of hull.lock: an image reference pinned to the exact
// digest it resolved to.
type LockEntry struct {
	// Ref is the reference as the user wrote it.
	Ref string `json:"ref"`
	// Resolved is the fully qualified reference.
	Resolved string `json:"resolved"`
	// Digest is the manifest digest the reference resolved to.
	Digest string `json:"digest"`
	// MediaType is the manifest's media type.
	MediaType string `json:"mediaType,omitempty"`
	// Size is the manifest size in bytes.
	Size int64 `json:"size,omitempty"`
	// Platform is the platform the digest was resolved for, when the caller
	// asked for one.
	Platform string `json:"platform,omitempty"`
}

// Info is the /info payload: what this daemon is, and what this host can do.
type Info struct {
	// ID is the daemon's stable identity, derived from the data root.
	ID string `json:"id"`
	// Name is the host name.
	Name string `json:"name"`
	// ServerVersion is hull's version string.
	ServerVersion string `json:"serverVersion"`
	// Containers and the three per-state counters describe the container
	// population.
	Containers        int `json:"containers"`
	ContainersRunning int `json:"containersRunning"`
	ContainersPaused  int `json:"containersPaused"`
	ContainersStopped int `json:"containersStopped"`
	// Images is how many images the local store holds.
	Images int `json:"images"`
	// Driver is the storage driver name.
	Driver string `json:"driver"`
	// DriverStatus is a list of key/value pairs the CLI prints verbatim.
	DriverStatus [][2]string `json:"driverStatus,omitempty"`
	// LoggingDriver, CgroupDriver and CgroupVersion describe the subsystems.
	LoggingDriver string `json:"loggingDriver"`
	CgroupDriver  string `json:"cgroupDriver"`
	CgroupVersion string `json:"cgroupVersion"`
	// CgroupV2Delegated reports whether the unified hierarchy actually offers
	// the controllers hull needs. It is false on a stock WSL 2.4 host, and it
	// is the single most important thing this payload says.
	CgroupV2Delegated bool `json:"cgroupV2Delegated"`
	// KernelVersion, OperatingSystem, OSType and Architecture describe the
	// host.
	KernelVersion   string `json:"kernelVersion"`
	OperatingSystem string `json:"operatingSystem"`
	OSType          string `json:"osType"`
	Architecture    string `json:"architecture"`
	// NCPU and MemTotal are the host's capacity.
	NCPU     int   `json:"ncpu"`
	MemTotal int64 `json:"memTotal"`
	// DataRoot is hull's data directory.
	DataRoot string `json:"dataRoot"`
	// DockerRootDir is DataRoot under the name Docker clients look for.
	DockerRootDir string `json:"dockerRootDir"`
	// DefaultRuntime is the runtime new containers get, and Runtimes lists
	// the drivers this daemon can use.
	DefaultRuntime string   `json:"defaultRuntime"`
	Runtimes       []string `json:"runtimes"`
	// RuntimeVersion is the selected driver's own version string.
	RuntimeVersion string `json:"runtimeVersion,omitempty"`
	// OCIVersion is the runtime-spec version hull writes into bundles on this
	// host, after negotiating with the driver.
	OCIVersion string `json:"ociVersion,omitempty"`
	// SecurityOptions lists the isolation features in effect.
	SecurityOptions []string `json:"securityOptions,omitempty"`
	// Warnings are the host problems "hull doctor" would report, phrased as
	// something the operator can act on.
	Warnings []string `json:"warnings,omitempty"`
	// Plugins names the built-in drivers.
	Plugins InfoPlugins `json:"plugins"`
}

// InfoPlugins lists the drivers hull ships.
type InfoPlugins struct {
	// Volume, Network and Log are the built-in driver names.
	Volume  []string `json:"volume"`
	Network []string `json:"network"`
	Log     []string `json:"log"`
}
