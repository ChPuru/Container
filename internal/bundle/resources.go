package bundle

import (
	"fmt"
	"path"
	"strings"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

// DefaultCPUPeriod is the cpu.max period hull uses when a quota is requested
// without one. 100ms is the kernel default and what Docker emits.
const DefaultCPUPeriod uint64 = 100000

// buildResources translates types.Resources into linux.resources and builds the
// device cgroup rule list and the device nodes to create.
//
// The device rules are always "deny everything, then allow exactly this list",
// never the other way round: a default-allow list with denies bolted on is how
// a forgotten device becomes a host escape.
func (b *builder) buildResources() (*runtimespec.LinuxResources, []runtimespec.LinuxDevice, error) {
	r := b.c.HostConfig.Resources
	out := &runtimespec.LinuxResources{}

	// ---- memory ----
	if r.Memory != 0 || r.MemoryReservation != 0 || r.MemorySwap != 0 {
		mem := &runtimespec.LinuxMemory{}
		if r.Memory != 0 {
			mem.Limit = i64p(r.Memory)
		}
		if r.MemoryReservation != 0 {
			mem.Reservation = i64p(r.MemoryReservation)
		}
		if r.MemorySwap != 0 {
			// Docker's memory-swap is the combined memory+swap total, which is
			// also the runtime-spec's meaning, so it passes straight through.
			mem.Swap = i64p(r.MemorySwap)
		}
		out.Memory = mem
	}

	// ---- cpu ----
	cpu := &runtimespec.LinuxCPU{}
	haveCPU := false
	if r.CPUShares != 0 {
		if r.CPUShares < 0 {
			return nil, nil, fmt.Errorf("bundle: cpu shares %d must not be negative", r.CPUShares)
		}
		cpu.Shares = u64p(uint64(r.CPUShares))
		haveCPU = true
	}
	switch {
	case r.NanoCPUs != 0 && r.CPUQuota != 0:
		return nil, nil, fmt.Errorf("bundle: --cpus and --cpu-quota are mutually exclusive")
	case r.NanoCPUs != 0:
		if r.NanoCPUs < 0 {
			return nil, nil, fmt.Errorf("bundle: --cpus %d must not be negative", r.NanoCPUs)
		}
		period := DefaultCPUPeriod
		if r.CPUPeriod != 0 {
			period = uint64(r.CPUPeriod)
		}
		quota := r.NanoCPUs * int64(period) / 1e9
		if quota <= 0 {
			return nil, nil, fmt.Errorf("bundle: --cpus value %d nanocpus rounds to a zero cpu quota over a %dus period", r.NanoCPUs, period)
		}
		cpu.Quota = i64p(quota)
		cpu.Period = u64p(period)
		haveCPU = true
	case r.CPUQuota != 0:
		period := DefaultCPUPeriod
		if r.CPUPeriod != 0 {
			period = uint64(r.CPUPeriod)
		}
		cpu.Quota = i64p(r.CPUQuota)
		cpu.Period = u64p(period)
		haveCPU = true
	case r.CPUPeriod != 0:
		cpu.Period = u64p(uint64(r.CPUPeriod))
		haveCPU = true
	}
	if r.CpusetCpus != "" {
		cpu.Cpus = r.CpusetCpus
		haveCPU = true
	}
	if r.CpusetMems != "" {
		cpu.Mems = r.CpusetMems
		haveCPU = true
	}
	if haveCPU {
		out.CPU = cpu
	}

	// ---- blkio ----
	if r.BlkioWeight != 0 {
		if r.BlkioWeight < 10 || r.BlkioWeight > 1000 {
			return nil, nil, fmt.Errorf("bundle: --blkio-weight %d is out of range 10-1000", r.BlkioWeight)
		}
		w := r.BlkioWeight
		out.BlockIO = &runtimespec.LinuxBlockIO{Weight: &w}
	}

	// ---- pids ----
	if pl := b.c.HostConfig.PidsLimit; pl != nil && *pl != 0 {
		out.Pids = &runtimespec.LinuxPids{Limit: *pl}
	}

	// ---- devices ----
	rules, nodes, err := b.buildDevices()
	if err != nil {
		return nil, nil, err
	}
	out.Devices = rules

	// A container with limits on a kernel whose cgroup v2 controllers are not
	// delegated would silently run unlimited. Say so rather than pretend.
	if !b.opts.Features.CgroupV2 && hasLimits(out) {
		b.warnf("resource limits were requested but this kernel has no delegated cgroup v2 controllers " +
			"(the hybrid WSL 2.4.13 layout); run `wsl --update`, or set kernelCommandLine=cgroup_no_v1=all in .wslconfig, " +
			"or the limits will not be enforced")
	}
	return out, nodes, nil
}

// hasLimits reports whether anything in r would actually need a controller.
func hasLimits(r *runtimespec.LinuxResources) bool {
	return r.Memory != nil || r.CPU != nil || r.Pids != nil || r.BlockIO != nil
}

// defaultDeviceRules is the OCI allow-list every container gets: the standard
// character devices plus the whole pts range, on top of a deny-all rule.
func defaultDeviceRules() []runtimespec.LinuxDeviceCgroup {
	allow := func(major, minor int64) runtimespec.LinuxDeviceCgroup {
		return runtimespec.LinuxDeviceCgroup{
			Allow: true, Type: "c", Major: i64p(major), Minor: i64p(minor), Access: "rwm",
		}
	}
	return []runtimespec.LinuxDeviceCgroup{
		{Allow: false, Access: "rwm"}, // deny everything first
		allow(1, 3),                   // /dev/null
		allow(1, 5),                   // /dev/zero
		allow(1, 7),                   // /dev/full
		allow(1, 8),                   // /dev/random
		allow(1, 9),                   // /dev/urandom
		allow(5, 0),                   // /dev/tty
		allow(5, 1),                   // /dev/console
		allow(5, 2),                   // /dev/ptmx
		{Allow: true, Type: "c", Major: i64p(136), Access: "rwm"}, // the pts range, 136:*
	}
}

// buildDevices produces the device cgroup rules and the linux.devices nodes.
//
// A privileged container gets a single "allow all" rule; its /dev is a
// recursive bind of the host's, so there is nothing to re-create.
func (b *builder) buildDevices() ([]runtimespec.LinuxDeviceCgroup, []runtimespec.LinuxDevice, error) {
	if b.privileged {
		if len(b.c.HostConfig.Devices) > 0 {
			b.warnf("--device was given together with --privileged; the container already has the host's whole /dev")
		}
		return []runtimespec.LinuxDeviceCgroup{{Allow: true, Access: "rwm"}}, nil, nil
	}

	rules := defaultDeviceRules()
	var nodes []runtimespec.LinuxDevice

	for _, d := range b.c.HostConfig.Devices {
		hostPath := d.PathOnHost
		if hostPath == "" {
			return nil, nil, fmt.Errorf("bundle: --device entry with an empty host path")
		}
		translated, err := TranslateWindowsPath(hostPath)
		if err != nil {
			return nil, nil, fmt.Errorf("bundle: --device %q: %w", hostPath, err)
		}
		inContainer := d.PathInContainer
		if inContainer == "" {
			inContainer = translated
		}
		if !strings.HasPrefix(inContainer, "/") {
			return nil, nil, fmt.Errorf("bundle: --device %q: the container path %q must be absolute", hostPath, inContainer)
		}
		access := d.CgroupPermissions
		if access == "" {
			access = "rwm"
		}
		for _, ch := range access {
			if ch != 'r' && ch != 'w' && ch != 'm' {
				return nil, nil, fmt.Errorf("bundle: --device %q: permissions %q may only contain r, w and m", hostPath, access)
			}
		}

		info, err := statDevice(translated)
		if err != nil {
			return nil, nil, fmt.Errorf("bundle: --device %q: %w", hostPath, err)
		}
		nodes = append(nodes, runtimespec.LinuxDevice{
			Path:     path.Clean(inContainer),
			Type:     info.Kind,
			Major:    info.Major,
			Minor:    info.Minor,
			FileMode: u32p(info.Mode),
			UID:      u32p(info.UID),
			GID:      u32p(info.GID),
		})
		rules = append(rules, runtimespec.LinuxDeviceCgroup{
			Allow:  true,
			Type:   info.Kind,
			Major:  i64p(info.Major),
			Minor:  i64p(info.Minor),
			Access: access,
		})
	}
	return rules, nodes, nil
}

// deviceInfo is the stat of a host device node.
type deviceInfo struct {
	Kind  string // "c" or "b"
	Major int64
	Minor int64
	Mode  uint32
	UID   uint32
	GID   uint32
}
