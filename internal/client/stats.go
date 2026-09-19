package client

import "time"

// StatsResponse is one sample of /containers/{id}/stats.
//
// The nesting is Docker's, not hull's: cgroup counters live under cpu_stats
// and memory_stats, and the previous sample is repeated under precpu_stats so
// a client can compute a percentage without keeping state of its own.
type StatsResponse struct {
	// Read and PreRead are when this sample and the previous one were taken.
	Read    time.Time `json:"read"`
	PreRead time.Time `json:"preread"`
	// Name and ID identify the container.
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`

	// PidsStats is the process count and its limit.
	PidsStats struct {
		Current uint64 `json:"current,omitempty"`
		Limit   uint64 `json:"limit,omitempty"`
	} `json:"pids_stats"`

	// BlkioStats holds the block-io counters.
	BlkioStats struct {
		IoServiceBytesRecursive []BlkioStatEntry `json:"io_service_bytes_recursive,omitempty"`
	} `json:"blkio_stats"`

	// CPUStats and PreCPUStats are this and the previous CPU sample.
	CPUStats    CPUStats `json:"cpu_stats"`
	PreCPUStats CPUStats `json:"precpu_stats"`

	// MemoryStats is the memory accounting, including the raw cgroup keys
	// under Stats which are what make the page cache subtractable.
	MemoryStats struct {
		Usage    uint64            `json:"usage,omitempty"`
		MaxUsage uint64            `json:"max_usage,omitempty"`
		Limit    uint64            `json:"limit,omitempty"`
		Stats    map[string]uint64 `json:"stats,omitempty"`
	} `json:"memory_stats"`

	// Networks is per-interface counters, absent for a container with no
	// network namespace of its own.
	Networks map[string]NetworkStats `json:"networks,omitempty"`
}

// CPUStats is one CPU sample.
type CPUStats struct {
	// CPUUsage is the container's own consumption, in nanoseconds.
	CPUUsage struct {
		TotalUsage        uint64   `json:"total_usage"`
		PercpuUsage       []uint64 `json:"percpu_usage,omitempty"`
		UsageInKernelmode uint64   `json:"usage_in_kernelmode,omitempty"`
		UsageInUsermode   uint64   `json:"usage_in_usermode,omitempty"`
	} `json:"cpu_usage"`
	// SystemUsage is the host's total CPU time over the same window.
	SystemUsage uint64 `json:"system_cpu_usage,omitempty"`
	// OnlineCPUs is how many CPUs the container could use.
	OnlineCPUs uint32 `json:"online_cpus,omitempty"`
}

// BlkioStatEntry is one block-io counter.
type BlkioStatEntry struct {
	Major uint64 `json:"major"`
	Minor uint64 `json:"minor"`
	Op    string `json:"op"`
	Value uint64 `json:"value"`
}

// NetworkStats is one interface's counters.
type NetworkStats struct {
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
	TxDropped uint64 `json:"tx_dropped"`
}

// CPUPercent computes usage between this sample and the previous one the way
// "docker stats" does: the container's delta over the system delta, scaled by
// the number of CPUs it may use.
func (s StatsResponse) CPUPercent() float64 {
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	if cpuDelta <= 0 || sysDelta <= 0 {
		return 0
	}
	cpus := float64(s.CPUStats.OnlineCPUs)
	if cpus == 0 {
		cpus = float64(len(s.CPUStats.CPUUsage.PercpuUsage))
	}
	if cpus == 0 {
		cpus = 1
	}
	return (cpuDelta / sysDelta) * cpus * 100
}

// MemoryUsage returns the memory a container is actually holding. The page
// cache is subtracted, because counting it makes every container that has read
// a file look as though it is at its limit.
func (s StatsResponse) MemoryUsage() uint64 {
	usage := s.MemoryStats.Usage
	if v, ok := s.MemoryStats.Stats["inactive_file"]; ok && v < usage {
		return usage - v
	}
	if v, ok := s.MemoryStats.Stats["cache"]; ok && v < usage {
		return usage - v
	}
	return usage
}

// MemoryPercent returns memory usage against the limit, or zero when the
// container has no limit — which on a host with no delegated cgroup v2
// controllers is every container.
func (s StatsResponse) MemoryPercent() float64 {
	limit := s.MemoryStats.Limit
	if limit == 0 {
		return 0
	}
	return float64(s.MemoryUsage()) / float64(limit) * 100
}

// NetworkIO sums the receive and transmit byte counters across interfaces.
func (s StatsResponse) NetworkIO() (rx, tx uint64) {
	for _, n := range s.Networks {
		rx += n.RxBytes
		tx += n.TxBytes
	}
	return rx, tx
}

// BlockIO sums the read and write byte counters across devices.
func (s StatsResponse) BlockIO() (read, write uint64) {
	for _, e := range s.BlkioStats.IoServiceBytesRecursive {
		switch e.Op {
		case "read", "Read":
			read += e.Value
		case "write", "Write":
			write += e.Value
		}
	}
	return read, write
}
