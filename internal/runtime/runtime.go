// Package runtime turns an OCI bundle into a running container.
//
// It offers two drivers behind one interface:
//
//   - CrunRuntime shells out to an installed OCI runtime binary (crun, or runc
//     as a fallback). It works on every host that has one, and is hull's
//     documented default until the native driver has passed the regression
//     suite in test/cve.
//   - NativeRuntime is hull's own implementation: clone3 into a pre-created
//     cgroup, a sealed-memfd init binary, fd-relative mount setup, pivot_root,
//     an in-process cBPF seccomp compiler, and pidfd-based signalling.
//
// Only the native driver is Linux-only in substance; the package as a whole
// builds on Windows so the CLI can name a runtime and render its state.
package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

// Errors the drivers return. Callers should test them with errors.Is rather
// than matching on message text.
var (
	// ErrNotFound means no container with that id exists in this runtime's
	// state directory.
	ErrNotFound = errors.New("runtime: container not found")
	// ErrExists means a container with that id already exists.
	ErrExists = errors.New("runtime: container already exists")
	// ErrNotRunning means the operation needs a running container.
	ErrNotRunning = errors.New("runtime: container is not running")
	// ErrRunning means the operation needs a stopped container.
	ErrRunning = errors.New("runtime: container is still running")
	// ErrUnsupported means this driver, or this kernel, cannot do it. The
	// wrapped message always says which feature is missing and what to do
	// about it; hull never silently degrades.
	ErrUnsupported = errors.New("runtime: operation not supported")
)

// Container status strings, matching the OCI runtime-spec "state" vocabulary
// so the crun driver and the native driver report the same words.
const (
	// StatusCreating is set between Create being called and the container
	// process reaching its ready point.
	StatusCreating = "creating"
	// StatusCreated means the container process exists and is blocked
	// waiting for Start.
	StatusCreated = "created"
	// StatusRunning means the entrypoint has been exec'd.
	StatusRunning = "running"
	// StatusPaused means every process in the container is frozen.
	StatusPaused = "paused"
	// StatusStopped means the container process has exited.
	StatusStopped = "stopped"
)

// Status is one container's runtime state.
type Status struct {
	// ID is the container id.
	ID string `json:"id"`
	// Pid is the container init process, as seen from the host. It is zero
	// once the container has exited.
	Pid int `json:"pid"`
	// Status is one of the Status* constants.
	Status string `json:"status"`
	// Bundle is the absolute path of the OCI bundle directory.
	Bundle string `json:"bundle"`
	// Created is when Create returned.
	Created time.Time `json:"created"`
	// ExitCode is meaningful only when Exited is true. A process killed by
	// signal N reports 128+N, matching the shell and Docker.
	ExitCode int `json:"exitCode"`
	// Exited reports that the container process has been reaped.
	Exited bool `json:"exited"`
	// OOMKilled reports that the cgroup's memory controller killed it.
	OOMKilled bool `json:"oomKilled"`
	// Annotations are the bundle's annotations, echoed back.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// CreateOptions carries everything about a Create that is not in the bundle.
type CreateOptions struct {
	// Stdin, Stdout and Stderr are wired to the container process when
	// Terminal is false. A nil stream becomes /dev/null.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Terminal allocates a pty for the container process. The bundle's
	// process.terminal must agree.
	Terminal bool
	// ConsoleSocket is an AF_UNIX path the runtime sends the pty master
	// over, as SCM_RIGHTS. Required by the crun driver when Terminal is
	// set; optional for the native driver, which can keep the master
	// itself.
	ConsoleSocket string
	// PidFile is a path the runtime writes the container init pid to.
	PidFile string
	// CgroupFD is an open descriptor on an existing cgroup v2 directory the
	// container should be born into. Zero or negative means the runtime
	// creates its own.
	CgroupFD int
	// ExtraFiles are additional descriptors to pass to the container
	// process, starting at fd 3 after the runtime's own. They are closed
	// before execve unless the driver documents otherwise; the native
	// driver closes every one of them (CVE-2024-21626).
	ExtraFiles []*os.File
}

// ExecOptions carries everything about an Exec that is not in the process.
type ExecOptions struct {
	// Stdin, Stdout and Stderr are wired to the exec'd process.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Terminal allocates a pty for the exec'd process.
	Terminal bool
	// ConsoleSocket is an AF_UNIX path the runtime sends the pty master over.
	ConsoleSocket string
	// PidFile is a path the runtime writes the exec'd pid to.
	PidFile string
	// Detach returns as soon as the process has been started instead of
	// waiting for it to exit.
	Detach bool
	// ExtraFiles are additional descriptors to pass. As with Create, the
	// native driver closes them before execve.
	ExtraFiles []*os.File
}

// RuntimeFeatures is a driver's self-description: what it is, and which kernel
// facilities it found. hull doctor renders it, and the engine uses it to pick
// a driver and to refuse a container the host cannot actually isolate.
type RuntimeFeatures struct {
	// Name is the driver name, matching Runtime.Name.
	Name string `json:"name"`
	// Version is the runtime binary's version for the crun driver, or
	// hull's own version for the native one.
	Version string `json:"version"`
	// OCIVersions are the runtime-spec versions the driver accepts.
	OCIVersions []string `json:"ociVersions,omitempty"`
	// Kernel is the uname release string.
	Kernel string `json:"kernel,omitempty"`
	// Namespaces are the namespace types the driver can create.
	Namespaces []string `json:"namespaces,omitempty"`
	// Capabilities are the capability tokens the driver understands.
	Capabilities []string `json:"capabilities,omitempty"`
	// SeccompEnabled reports that the driver can install a seccomp filter.
	SeccompEnabled bool `json:"seccompEnabled"`
	// SeccompActions is /proc/sys/kernel/seccomp/actions_avail.
	SeccompActions []string `json:"seccompActions,omitempty"`
	// Kernel facilities the native driver probed. The crun driver leaves
	// this zero except for the fields it can answer cheaply.
	Probe Features `json:"probe"`
	// Warnings are host problems the operator should know about, each
	// phrased as something they can act on.
	Warnings []string `json:"warnings,omitempty"`
}

// Features is the result of probing the kernel for the facilities the native
// runtime is built on. Every one is probed, never inferred from a version
// number, because WSL ships kernels that disagree with their own version.
type Features struct {
	// Clone3 reports clone3(2).
	Clone3 bool `json:"clone3"`
	// CloneIntoCgroup reports CLONE_INTO_CGROUP, which lets a child be born
	// inside its cgroup instead of being migrated into it afterwards.
	CloneIntoCgroup bool `json:"cloneIntoCgroup"`
	// Openat2 reports openat2(2) with RESOLVE_IN_ROOT.
	Openat2 bool `json:"openat2"`
	// MountAPI reports the fd-based mount API
	// (fsopen/fsconfig/fsmount/move_mount).
	MountAPI bool `json:"mountApi"`
	// OpenTree reports open_tree(2), the detached-mount half of the new API.
	OpenTree bool `json:"openTree"`
	// PidfdSendSignal reports pidfd_open(2) plus pidfd_send_signal(2).
	PidfdSendSignal bool `json:"pidfdSendSignal"`
	// CloseRange reports close_range(2).
	CloseRange bool `json:"closeRange"`
	// Seccomp reports that seccomp(2) filters can be installed.
	Seccomp bool `json:"seccomp"`
	// SeccompActions is the kernel's actions_avail list.
	SeccompActions []string `json:"seccompActions,omitempty"`
	// IDMappedMounts reports mount_setattr(2) with MOUNT_ATTR_IDMAP. On the
	// WSL 5.15 kernel this is true for ext4 and btrfs but NOT for overlay
	// (5.19) or tmpfs (6.3), so it is not on its own enough for a
	// rootless-idmap container root.
	IDMappedMounts bool `json:"idmappedMounts"`
	// UserNamespaces reports that unprivileged user namespaces are enabled.
	UserNamespaces bool `json:"userNamespaces"`
	// CgroupV2 reports a usable cgroup v2 hierarchy with controllers.
	CgroupV2 bool `json:"cgroupV2"`
	// CgroupKill reports cgroup.kill, which kills a whole cgroup without
	// racing against fork bombs.
	CgroupKill bool `json:"cgroupKill"`
	// Kernel is the uname release string the probe ran against.
	Kernel string `json:"kernel,omitempty"`
	// Warnings explain, in the operator's terms, anything missing that hull
	// would otherwise have used.
	Warnings []string `json:"warnings,omitempty"`
}

// Runtime is the contract every hull container driver satisfies.
//
// Every method that blocks or does I/O takes a context and honours its
// cancellation; a cancelled Create leaves no container behind.
type Runtime interface {
	// Create builds the container from the bundle and leaves its init
	// process alive and blocked, waiting for Start.
	Create(ctx context.Context, id, bundleDir string, opts CreateOptions) (*Status, error)
	// Start releases a created container's init process into its
	// entrypoint.
	Start(ctx context.Context, id string) error
	// State reports what the runtime knows about a container.
	State(ctx context.Context, id string) (*Status, error)
	// Kill signals the container init process, or every process in the
	// container when all is set.
	Kill(ctx context.Context, id string, sig syscall.Signal, all bool) error
	// Delete removes a stopped container's runtime state. force kills it
	// first.
	Delete(ctx context.Context, id string, force bool) error
	// Exec runs an extra process inside an existing container.
	Exec(ctx context.Context, id string, process *runtimespec.Process, opts ExecOptions) (*Status, error)
	// Pause freezes every process in the container.
	Pause(ctx context.Context, id string) error
	// Resume thaws a paused container.
	Resume(ctx context.Context, id string) error
	// Features describes the driver and the host it found.
	Features(ctx context.Context) (RuntimeFeatures, error)
	// Name is the driver name, as it appears in HostConfig.Runtime.
	Name() string
}

// ConfigFileName is the file inside a bundle directory that holds the OCI
// runtime spec.
const ConfigFileName = "config.json"

// LoadSpec reads and validates bundleDir/config.json.
//
// The bundle directory is hull's own, but its config.json may have been
// written by an earlier version or edited by hand, so it is validated before
// any of it is acted on.
func LoadSpec(bundleDir string) (*runtimespec.Spec, error) {
	p := filepath.Join(bundleDir, ConfigFileName)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("runtime: read bundle config %s: %w", p, err)
	}
	var spec runtimespec.Spec
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		// An unknown field is a warning, not a failure: the runtime spec
		// grows, and refusing a bundle a newer hull wrote is worse than
		// ignoring a field this one does not use.
		if err := json.Unmarshal(b, &spec); err != nil {
			return nil, fmt.Errorf("runtime: parse bundle config %s: %w", p, err)
		}
	}
	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("runtime: invalid bundle config %s: %w", p, err)
	}
	return &spec, nil
}

// SaveStatus writes a status file atomically enough for hull's purposes: the
// state directory is hull-owned and single-writer per container.
func saveStatus(dir string, st *Status) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("runtime: encode state for %s: %w", st.ID, err)
	}
	tmp := filepath.Join(dir, ".state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("runtime: write state for %s: %w", st.ID, err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "state.json")); err != nil {
		return fmt.Errorf("runtime: commit state for %s: %w", st.ID, err)
	}
	return nil
}

func loadStatus(dir string) (*Status, error) {
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return nil, err
	}
	var st Status
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("runtime: parse state in %s: %w", dir, err)
	}
	return &st, nil
}

// ValidID rejects a container id that could escape the runtime state
// directory or collide with the runtime's own files. It is deliberately
// stricter than the OCI spec, which allows almost anything.
func ValidID(id string) error {
	if id == "" {
		return fmt.Errorf("runtime: empty container id")
	}
	if len(id) > 128 {
		return fmt.Errorf("runtime: container id is %d characters, the maximum is 128", len(id))
	}
	if id == "." || id == ".." {
		return fmt.Errorf("runtime: container id %q is a path component", id)
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return fmt.Errorf("runtime: container id %q contains %q; only letters, digits, "+
				"'_', '-' and '.' are allowed", id, string(r))
		}
	}
	return nil
}

// ExitCodeOf turns a wait status into the 0-255 code hull reports: the exit
// status for a normal exit, and 128+N for a process killed by signal N.
func ExitCodeOf(ws syscall.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}
