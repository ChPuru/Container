package shim

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/rahuldhali/hull/internal/fsutil"
)

// File names the shim owns inside a container directory.
const (
	// SocketName is the shim's control socket.
	SocketName = "shim.sock"
	// StateName records the running shim so a restarted daemon can find it.
	StateName = "shim.json"
	// ExitName records the container's exit status durably.
	ExitName = "exit.json"
	// ConsoleName is the transient console socket used to hand the pty over.
	ConsoleName = "console.sock"
	// PidFileName is where the runtime writes the container init's pid.
	PidFileName = "init.pid"
	// ShimLogName collects the shim's own diagnostics.
	ShimLogName = "shim.log"
)

// SocketPath returns the control socket path for a container directory.
func SocketPath(containerDir string) string { return filepath.Join(containerDir, SocketName) }

// StatePath returns the shim.json path for a container directory.
func StatePath(containerDir string) string { return filepath.Join(containerDir, StateName) }

// ExitPath returns the exit.json path for a container directory.
func ExitPath(containerDir string) string { return filepath.Join(containerDir, ExitName) }

// ShimState is what a shim publishes about itself, atomically, before it
// starts serving. A daemon that restarts reads it to find live shims.
//
// Pid alone is not enough to trust: pids are recycled. StartTime is field 22
// of /proc/<pid>/stat, the process start time in clock ticks since boot, which
// together with the pid identifies a process uniquely for the life of the
// boot. Validate always compares both.
type ShimState struct {
	// Pid is the shim process's pid.
	Pid int `json:"pid"`
	// StartTime is the shim's /proc/<pid>/stat starttime field.
	StartTime uint64 `json:"startTime"`
	// Socket is the absolute path of the control socket.
	Socket string `json:"socket"`
	// ContainerID is the container the shim supervises.
	ContainerID string `json:"containerId"`
	// ContainerPid is the container init's pid, 0 until it is created.
	ContainerPid int `json:"containerPid"`
	// CreatedAt is when the shim published this record.
	CreatedAt time.Time `json:"createdAt"`
	// Version is the record format version, so a newer daemon can refuse a
	// shim it does not understand rather than misread it.
	Version int `json:"version"`
}

// ShimStateVersion is the current ShimState format version.
const ShimStateVersion = 1

// WriteShimState writes s to path atomically and durably.
func WriteShimState(path string, s ShimState) error {
	if s.Version == 0 {
		s.Version = ShimStateVersion
	}
	if err := fsutil.WriteJSONAtomic(path, s, 0o600); err != nil {
		return fmt.Errorf("shim: write %s: %w", path, err)
	}
	return nil
}

// ReadShimState reads a shim.json. A missing file is reported as an error
// wrapping fs.ErrNotExist.
func ReadShimState(path string) (ShimState, error) {
	var s ShimState
	if err := fsutil.ReadJSON(path, &s); err != nil {
		return ShimState{}, err
	}
	if s.Version > ShimStateVersion {
		return s, fmt.Errorf("shim: %s was written by a newer hull (format %d, this one understands %d)", path, s.Version, ShimStateVersion)
	}
	return s, nil
}

// ExitStatus is the container's final disposition, written before the shim
// stops serving so it survives even a shim crash.
type ExitStatus struct {
	// ExitCode is the container init's exit code, or 128+signal when it was
	// killed, matching Docker.
	ExitCode int `json:"exitCode"`
	// FinishedAt is when the init was reaped.
	FinishedAt time.Time `json:"finishedAt"`
	// OOMKilled reports an OOM kill recorded by the container's cgroup.
	OOMKilled bool `json:"oomKilled"`
	// Error describes a supervision failure, e.g. the runtime never started.
	Error string `json:"error,omitempty"`
}

// WriteExitStatus writes st to path atomically and durably. It is the single
// most important write the shim makes: once it returns, the container's fate
// survives a crash of the shim, the daemon and the machine.
func WriteExitStatus(path string, st ExitStatus) error {
	if err := fsutil.WriteJSONAtomic(path, st, 0o600); err != nil {
		return fmt.Errorf("shim: write %s: %w", path, err)
	}
	return nil
}

// ReadExitStatus reads an exit.json. A missing file is reported as an error
// wrapping fs.ErrNotExist, which callers read as "the container has not
// exited, or its shim never got that far".
func ReadExitStatus(path string) (ExitStatus, error) {
	var st ExitStatus
	if err := fsutil.ReadJSON(path, &st); err != nil {
		return ExitStatus{}, err
	}
	return st, nil
}

// Validate reports whether the process recorded in s is still the shim it
// claims to be, by comparing the pid's start time with the recorded one. A
// recycled pid, a dead shim or an unreadable /proc all report false.
func (s ShimState) Validate() bool {
	if s.Pid <= 0 {
		return false
	}
	st, err := ProcessStartTime(s.Pid)
	if err != nil {
		return false
	}
	// A record written by an older hull that could not read the start time
	// falls back to "the pid exists", which is all it ever promised.
	if s.StartTime == 0 {
		return true
	}
	return st == s.StartTime
}

// Reconnect finds the live shim for a container directory and connects to it.
// It is how hulld re-adopts its containers after a restart.
//
// It returns an error wrapping ErrShimGone when there is no shim.json, when
// the recorded process is gone or has been replaced by an unrelated one, or
// when the socket refuses a connection. In that case the caller should fall
// back to ReadExitStatus to learn whether the container finished.
func Reconnect(containerDir string) (*Client, error) {
	statePath := StatePath(containerDir)
	s, err := ReadShimState(statePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: no %s in %s", ErrShimGone, StateName, containerDir)
		}
		return nil, err
	}
	if !s.Validate() {
		return nil, fmt.Errorf("%w: pid %d recorded in %s is not the shim any more", ErrShimGone, s.Pid, statePath)
	}
	sock := s.Socket
	if sock == "" {
		sock = SocketPath(containerDir)
	}
	c, err := Connect(sock)
	if err != nil {
		return nil, fmt.Errorf("%w: shim %d is alive but its socket %s did not answer: %v", ErrShimGone, s.Pid, sock, err)
	}
	return c, nil
}

// CleanStale removes a shim.json and socket left behind by a shim that is
// gone, so a fresh shim can take the container over. It is a no-op when the
// recorded shim is still alive, and reports whether anything was removed.
func CleanStale(containerDir string) (bool, error) {
	statePath := StatePath(containerDir)
	s, err := ReadShimState(statePath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Nothing claims the directory; drop a stray socket if one is there.
		if err := os.Remove(SocketPath(containerDir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("shim: remove stale socket: %w", err)
		}
		return false, nil
	case err != nil:
		return false, err
	}
	if s.Validate() {
		return false, nil
	}
	if err := os.Remove(statePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("shim: remove stale %s: %w", StateName, err)
	}
	sock := s.Socket
	if sock == "" {
		sock = SocketPath(containerDir)
	}
	if err := os.Remove(sock); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("shim: remove stale socket: %w", err)
	}
	return true, nil
}
