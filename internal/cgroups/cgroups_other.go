//go:build !linux

package cgroups

import (
	"fmt"
	"os"
	"runtime"

	"github.com/ChPuru/hull/internal/types"
)

// This file exists so cross-platform code - the hull CLI, which also builds
// for windows - can reference this package's types and call its API without
// build tags of its own. Every operation reports ErrUnsupported: cgroups are a
// Linux kernel facility and there is nothing to degrade to.

// Manager is the non-Linux placeholder for a cgroup v2 directory. It is never
// constructed successfully: every constructor returns ErrUnsupported.
type Manager struct {
	info Info
	path string
}

// Detect reports that no cgroup hierarchy exists, because this build does not
// target Linux.
func Detect() (Info, error) {
	return Info{
		Mode:     ModeUnavailable,
		Warnings: []string{fmt.Sprintf("cgroups are a Linux facility; this is a %s build", runtime.GOOS)},
	}, nil
}

// New always fails on a non-Linux build.
func New(info Info, path string) (*Manager, error) {
	return nil, fmt.Errorf("cgroups: New(%q): %w", path, ErrUnsupported)
}

// Load always fails on a non-Linux build.
func Load(info Info, path string) (*Manager, error) {
	return nil, fmt.Errorf("cgroups: Load(%q): %w", path, ErrUnsupported)
}

// Path returns the cgroup's absolute filesystem path.
func (m *Manager) Path() string { return m.path }

// Rel returns the cgroup's path relative to the cgroup v2 root.
func (m *Manager) Rel() string { return "" }

// Info returns the host cgroup information this Manager was built with.
func (m *Manager) Info() Info { return m.info }

// Warnings returns the non-fatal problems recorded for this cgroup.
func (m *Manager) Warnings() []string { return nil }

// FD is unsupported on a non-Linux build.
func (m *Manager) FD() (int, error) { return -1, ErrUnsupported }

// Apply is unsupported on a non-Linux build.
func (m *Manager) Apply(r types.Resources) error { return ErrUnsupported }

// SetPidsLimit is unsupported on a non-Linux build.
func (m *Manager) SetPidsLimit(limit int64) error { return ErrUnsupported }

// SetCPUBurst is unsupported on a non-Linux build.
func (m *Manager) SetCPUBurst(burstUsec uint64) error { return ErrUnsupported }

// SetOOMGroup is unsupported on a non-Linux build.
func (m *Manager) SetOOMGroup(on bool) error { return ErrUnsupported }

// AddProcess is unsupported on a non-Linux build.
func (m *Manager) AddProcess(pid int) error { return ErrUnsupported }

// Procs is unsupported on a non-Linux build.
func (m *Manager) Procs() ([]int, error) { return nil, ErrUnsupported }

// Stat is unsupported on a non-Linux build.
func (m *Manager) Stat() (Stat, error) { return Stat{}, ErrUnsupported }

// Freeze is unsupported on a non-Linux build.
func (m *Manager) Freeze() error { return ErrUnsupported }

// Thaw is unsupported on a non-Linux build.
func (m *Manager) Thaw() error { return ErrUnsupported }

// Frozen is unsupported on a non-Linux build.
func (m *Manager) Frozen() (bool, error) { return false, ErrUnsupported }

// Kill is unsupported on a non-Linux build.
func (m *Manager) Kill() error { return ErrUnsupported }

// Delete is unsupported on a non-Linux build.
func (m *Manager) Delete() error { return ErrUnsupported }

// EventFD is unsupported on a non-Linux build.
func (m *Manager) EventFD() (*os.File, error) { return nil, ErrUnsupported }

// SystemUsageUsec is unsupported on a non-Linux build.
func SystemUsageUsec() (uint64, error) { return 0, ErrUnsupported }

// OnlineCPUs returns the number of CPUs the Go runtime sees.
func OnlineCPUs() int { return runtime.NumCPU() }
