package runtime

import (
	"github.com/rahuldhali/hull/internal/oci/runtimespec"
	"github.com/rahuldhali/hull/internal/types"
)

// resourcesFromSpec projects the runtime-spec resource block onto the cgroup
// driver's vocabulary. Fields the spec expresses in v1 terms (cpu shares,
// blkio weight) are carried across unchanged; internal/cgroups does the v2
// conversion, so the mapping lives in exactly one place.
func resourcesFromSpec(res *runtimespec.LinuxResources) types.Resources {
	var out types.Resources
	if res == nil {
		return out
	}
	if m := res.Memory; m != nil {
		if m.Limit != nil {
			out.Memory = *m.Limit
		}
		if m.Reservation != nil {
			out.MemoryReservation = *m.Reservation
		}
		if m.Swap != nil {
			out.MemorySwap = *m.Swap
		}
	}
	if c := res.CPU; c != nil {
		if c.Shares != nil {
			out.CPUShares = int64(*c.Shares)
		}
		if c.Quota != nil {
			out.CPUQuota = *c.Quota
		}
		if c.Period != nil {
			out.CPUPeriod = int64(*c.Period)
		}
		out.CpusetCpus = c.Cpus
		out.CpusetMems = c.Mems
	}
	if b := res.BlockIO; b != nil && b.Weight != nil {
		out.BlkioWeight = *b.Weight
	}
	return out
}

// SpecResources is the exported form of the projection, so the engine can
// show an operator exactly what limits a bundle asks for without duplicating
// the mapping.
func SpecResources(res *runtimespec.LinuxResources) types.Resources {
	return resourcesFromSpec(res)
}
