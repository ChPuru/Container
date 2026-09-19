package shim

import (
	"fmt"
	"path/filepath"
	"time"
)

// Default supervision timings. They are fields on Config so hulld can tune
// them, but every one of them has a working default.
const (
	// DefaultExitGrace is how long the shim keeps serving State and Wait after
	// the container has exited, so a daemon that is restarting at that exact
	// moment does not lose the exit status. The shim leaves early if the
	// daemon acknowledges with OpAck.
	DefaultExitGrace = 5 * time.Minute
	// DefaultStopTimeout is how long the shim waits after forwarding the stop
	// signal before it resorts to SIGKILL.
	DefaultStopTimeout = 10 * time.Second
	// DefaultReadyTimeout bounds Spawn: how long hulld waits for a freshly
	// spawned shim to report ready.
	DefaultReadyTimeout = 30 * time.Second
)

// Config is everything the shim needs to supervise one container. hulld
// marshals it as JSON and hands it over on a pipe rather than in argv, so a
// container id, log path or runtime root never shows up in /proc/*/cmdline.
type Config struct {
	// ID is the container id, used as the runtime's container id too.
	ID string `json:"id"`
	// BundleDir holds the OCI bundle: config.json and the rootfs mount.
	BundleDir string `json:"bundleDir"`
	// ContainerDir is /var/lib/hull/containers/<id>; the shim's socket,
	// shim.json and exit.json live here.
	ContainerDir string `json:"containerDir"`
	// RuntimeName is the runtime hull was asked for ("hull" or "crun"), used
	// only in messages.
	RuntimeName string `json:"runtimeName"`
	// RuntimeBinary is the absolute path of the OCI runtime executable.
	RuntimeBinary string `json:"runtimeBinary"`
	// RuntimeRoot is the runtime's state root, passed as --root.
	RuntimeRoot string `json:"runtimeRoot"`

	// Terminal asks for a pty. The runtime is then invoked with
	// --console-socket and the shim keeps the master.
	Terminal bool `json:"terminal"`
	// OpenStdin keeps the container's stdin open so an attacher can type into
	// it. Without it stdin is /dev/null and attachers get ErrStdinUnavailable.
	OpenStdin bool `json:"openStdin"`

	// LogPath is the json-file log. Empty disables logging entirely, which is
	// what the "none" log driver means.
	LogPath string `json:"logPath"`
	// LogMaxSize is the rotation threshold in bytes; 0 means never rotate.
	LogMaxSize int64 `json:"logMaxSize"`
	// LogMaxFiles is how many log files to keep, the active one included.
	LogMaxFiles int `json:"logMaxFiles"`

	// CgroupPath is the absolute path of the container's cgroup directory,
	// e.g. /sys/fs/cgroup/hull/<id>. Empty disables stats and OOM detection,
	// which is the honest answer on a host with no v2 delegation.
	CgroupPath string `json:"cgroupPath"`

	// StopSignal is what SIGTERM to the shim forwards to the container.
	// Empty means SIGTERM.
	StopSignal string `json:"stopSignal,omitempty"`
	// StopTimeout is how long to wait after StopSignal before SIGKILL.
	// Zero means DefaultStopTimeout.
	StopTimeout time.Duration `json:"stopTimeout,omitempty"`
	// ExitGrace is how long to keep serving the exit status after the
	// container exits. Zero means DefaultExitGrace.
	ExitGrace time.Duration `json:"exitGrace,omitempty"`
	// RingSize is the replay buffer in bytes; zero means DefaultRingSize.
	RingSize int `json:"ringSize,omitempty"`
}

// SocketPath is the control socket for this container.
func (c Config) SocketPath() string { return SocketPath(c.ContainerDir) }

// StatePath is the shim.json for this container.
func (c Config) StatePath() string { return StatePath(c.ContainerDir) }

// ExitPath is the exit.json for this container.
func (c Config) ExitPath() string { return ExitPath(c.ContainerDir) }

// ConsolePath is the transient console socket used to receive the pty master.
func (c Config) ConsolePath() string { return filepath.Join(c.ContainerDir, ConsoleName) }

// PidPath is where the runtime is told to write the container init's pid.
func (c Config) PidPath() string { return filepath.Join(c.ContainerDir, PidFileName) }

// ShimLogPath is where the shim writes its own diagnostics.
func (c Config) ShimLogPath() string { return filepath.Join(c.ContainerDir, ShimLogName) }

// stopTimeout resolves StopTimeout against its default.
func (c Config) stopTimeout() time.Duration {
	if c.StopTimeout <= 0 {
		return DefaultStopTimeout
	}
	return c.StopTimeout
}

// exitGrace resolves ExitGrace against its default.
func (c Config) exitGrace() time.Duration {
	if c.ExitGrace <= 0 {
		return DefaultExitGrace
	}
	return c.ExitGrace
}

// Validate checks the fields the shim cannot run without. It runs in the
// intermediate fork, before the shim detaches, so a bad config is reported to
// hulld synchronously instead of vanishing into a log file.
func (c Config) Validate() error {
	switch {
	case c.ID == "":
		return fmt.Errorf("shim: config has no container id")
	case c.BundleDir == "":
		return fmt.Errorf("shim: config for %s has no bundle directory", c.ID)
	case !filepath.IsAbs(c.BundleDir):
		return fmt.Errorf("shim: bundle directory %q for %s must be absolute", c.BundleDir, c.ID)
	case c.ContainerDir == "":
		return fmt.Errorf("shim: config for %s has no container directory", c.ID)
	case !filepath.IsAbs(c.ContainerDir):
		return fmt.Errorf("shim: container directory %q for %s must be absolute", c.ContainerDir, c.ID)
	case c.RuntimeBinary == "":
		return fmt.Errorf("shim: config for %s names no runtime binary", c.ID)
	case !filepath.IsAbs(c.RuntimeBinary):
		return fmt.Errorf("shim: runtime binary %q for %s must be absolute", c.RuntimeBinary, c.ID)
	case c.LogPath != "" && !filepath.IsAbs(c.LogPath):
		return fmt.Errorf("shim: log path %q for %s must be absolute", c.LogPath, c.ID)
	case c.CgroupPath != "" && !filepath.IsAbs(c.CgroupPath):
		return fmt.Errorf("shim: cgroup path %q for %s must be absolute", c.CgroupPath, c.ID)
	}
	// The unix socket path has to fit in sockaddr_un.sun_path.
	if n := len(c.SocketPath()); n >= 108 {
		return fmt.Errorf("shim: control socket path %s is %d bytes, over the %d byte sockaddr_un limit; shorten the container root", c.SocketPath(), n, 108)
	}
	return nil
}
