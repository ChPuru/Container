package engine

import (
	"errors"
	"fmt"

	"github.com/ChPuru/hull/internal/cgroups"
	"github.com/ChPuru/hull/internal/types"
)

// cgroupFor opens the container's cgroup without creating it.
//
// It returns ErrUnsupported when the host has no usable unified hierarchy,
// which on a stock WSL 2.4 kernel it does not. Callers treat that as "this
// host cannot do it" and say so, rather than pretending the operation worked.
func (e *Engine) cgroupFor(id string) (*cgroups.Manager, error) {
	if !e.cgroupInfo.Usable() {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, cgroups.HybridRemedy)
	}
	m, err := cgroups.Load(e.cgroupInfo, cgroupRel(id))
	if err != nil {
		return nil, fmt.Errorf("engine: open the cgroup for %s: %w", idShort(id), err)
	}
	return m, nil
}

// ensureCgroup creates the container's cgroup, applying its resource limits.
// It returns the warning to record when the host cannot enforce them.
func (e *Engine) ensureCgroup(c *types.Container) string {
	if !e.cgroupInfo.Usable() {
		if hasAnyLimit(c.HostConfig.Resources) || c.HostConfig.PidsLimit != nil {
			return "resource limits were requested but this host has no delegated cgroup v2 controllers, " +
				"so the container runs unlimited. " + cgroups.HybridRemedy
		}
		return ""
	}
	m, err := cgroups.New(e.cgroupInfo, cgroupRel(c.ID))
	if err != nil {
		return fmt.Sprintf("could not create the container's cgroup: %v", err)
	}
	if err := m.Apply(c.HostConfig.Resources); err != nil {
		return fmt.Sprintf("could not apply resource limits: %v", err)
	}
	if c.HostConfig.PidsLimit != nil {
		if err := m.SetPidsLimit(*c.HostConfig.PidsLimit); err != nil {
			return fmt.Sprintf("could not apply the pids limit: %v", err)
		}
	}
	if warnings := m.Warnings(); len(warnings) > 0 {
		return warnings[0]
	}
	return ""
}

// applyResources updates a live container's limits, returning a warning when
// this host cannot enforce them.
func (e *Engine) applyResources(id string, r types.Resources) string {
	m, err := e.cgroupFor(id)
	if err != nil {
		if errors.Is(err, ErrUnsupported) && hasAnyLimit(r) {
			return "resource limits were updated in the container's record but cannot be enforced here: " +
				cgroups.HybridRemedy
		}
		return ""
	}
	if err := m.Apply(r); err != nil {
		return fmt.Sprintf("could not apply the updated resource limits: %v", err)
	}
	return ""
}

// removeCgroup deletes a container's cgroup, tolerating a host that never had
// one.
func (e *Engine) removeCgroup(id string) {
	m, err := e.cgroupFor(id)
	if err != nil {
		return
	}
	if err := m.Delete(); err != nil {
		e.log.Debug("hull: could not remove a container cgroup", "container", idShort(id), "err", err)
	}
}

// hasAnyLimit reports whether the caller asked for any resource limit at all.
func hasAnyLimit(r types.Resources) bool {
	return r.Memory != 0 || r.MemoryReservation != 0 || r.MemorySwap != 0 ||
		r.CPUShares != 0 || r.CPUQuota != 0 || r.NanoCPUs != 0 ||
		r.CpusetCpus != "" || r.CpusetMems != "" || r.BlkioWeight != 0
}

// freeze suspends every process in a container's cgroup.
func (e *Engine) freeze(id string) error {
	m, err := e.cgroupFor(id)
	if err != nil {
		return err
	}
	if !e.cgroupInfo.HasFreezer {
		return fmt.Errorf("%w: this kernel's cgroup v2 hierarchy has no cgroup.freeze, so containers cannot be paused",
			ErrUnsupported)
	}
	if err := m.Freeze(); err != nil {
		return fmt.Errorf("engine: freeze %s: %w", idShort(id), err)
	}
	return nil
}

// thaw resumes a frozen container.
func (e *Engine) thaw(id string) error {
	m, err := e.cgroupFor(id)
	if err != nil {
		return err
	}
	if err := m.Thaw(); err != nil {
		return fmt.Errorf("engine: unfreeze %s: %w", idShort(id), err)
	}
	return nil
}

// cgroupProcs lists the pids in a container's cgroup, which is what Top reads
// its process table from.
func (e *Engine) cgroupProcs(id string) ([]int, error) {
	m, err := e.cgroupFor(id)
	if err != nil {
		return nil, err
	}
	pids, err := m.Procs()
	if err != nil {
		return nil, fmt.Errorf("engine: read the process list of %s: %w", idShort(id), err)
	}
	return pids, nil
}

// cgroupStat samples a container's cgroup counters directly. It is the
// fallback for a container whose shim is not answering.
func (e *Engine) cgroupStat(id string) (cgroups.Stat, error) {
	m, err := e.cgroupFor(id)
	if err != nil {
		return cgroups.Stat{}, err
	}
	st, err := m.Stat()
	if err != nil {
		return cgroups.Stat{}, fmt.Errorf("engine: sample the cgroup of %s: %w", idShort(id), err)
	}
	return st, nil
}
