package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/rahuldhali/hull/internal/cgroups"
	"github.com/rahuldhali/hull/internal/types"
)

// StatsInterval is how often a streaming Stats call samples, matching Docker.
const StatsInterval = time.Second

// Stats samples a container's resource usage and hands each sample to fn.
//
// With stream set the call blocks, sampling every StatsInterval until ctx is
// cancelled or fn returns an error. Without it exactly one sample is
// delivered, whose PreCPU fields come from the previous sample this daemon
// took, so a repeated `hull stats --no-stream` still shows a meaningful CPU
// percentage without paying a second's latency for it.
//
// On a host with no delegated cgroup v2 controllers most counters read zero.
// That is reported rather than hidden: "hull doctor" is where the missing
// delegation is explained, and inventing numbers would be worse.
func (e *Engine) Stats(ctx context.Context, idOrName string, stream bool, fn func(types.Stats) error) error {
	if fn == nil {
		return fmt.Errorf("%w: stats need a callback", ErrInvalid)
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	if c.State != types.StateRunning && c.State != types.StatePaused {
		if !stream {
			// A stopped container still has a shape; Docker answers with an
			// all-zero sample rather than an error.
			return fn(types.Stats{Read: e.now()})
		}
		return fmt.Errorf("%w: %s is %s", ErrNotRunning, idShort(id), c.State)
	}

	prev, hasPrev := e.lastStats(id)
	for {
		s, err := e.sample(ctx, id)
		if err != nil {
			return err
		}
		if hasPrev {
			s.PreRead = prev.Read
			s.PreCPUUsage = prev.CPUUsage
			s.PreSystemUsage = prev.SystemUsage
		}
		e.storeStats(id, s)
		if err := fn(s); err != nil {
			return err
		}
		if !stream {
			return nil
		}
		prev, hasPrev = s, true

		timer := time.NewTimer(StatsInterval)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-e.ctx.Done():
			timer.Stop()
			return ErrClosed
		}
	}
}

// sample takes one reading, preferring the shim (which holds the cgroup open)
// and falling back to reading the cgroup directly.
func (e *Engine) sample(ctx context.Context, id string) (types.Stats, error) {
	var s types.Stats
	if sup, err := e.supervisorFor(id); err == nil {
		if s, err = sup.Stats(ctx); err != nil {
			return types.Stats{}, fmt.Errorf("engine: sample %s: %w", idShort(id), err)
		}
	} else {
		st, cerr := e.cgroupStat(id)
		if cerr != nil {
			return types.Stats{}, cerr
		}
		s = statsFromCgroup(st)
	}
	if s.Read.IsZero() {
		s.Read = e.now()
	}
	if s.SystemUsage == 0 {
		if sys, err := cgroups.SystemUsageUsec(); err == nil {
			s.SystemUsage = sys
		}
	}
	if s.OnlineCPUs == 0 {
		s.OnlineCPUs = cgroups.OnlineCPUs()
	}
	return s, nil
}

// statsFromCgroup converts a raw cgroup sample into the engine's stats shape.
func statsFromCgroup(st cgroups.Stat) types.Stats {
	return types.Stats{
		CPUUsage:          st.CPUUsageUsec,
		MemoryUsage:       st.MemoryCurrent,
		MemoryLimit:       st.MemoryLimit,
		MemoryCache:       st.MemoryFile,
		PidsCurrent:       st.PidsCurrent,
		PidsLimit:         st.PidsLimit,
		BlkRead:           st.IORead,
		BlkWrite:          st.IOWrite,
		CPUPressureSome10: st.CPUPressureSome10,
		MemPressureSome10: st.MemPressureSome10,
		IOPressureSome10:  st.IOPressureSome10,
	}
}

// lastStats returns the most recent sample this daemon took for a container.
func (e *Engine) lastStats(id string) (types.Stats, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	st := e.rt[id]
	if st == nil || st.lastSample.Read.IsZero() {
		return types.Stats{}, false
	}
	return st.lastSample, true
}

// storeStats caches a sample for the next non-streaming call.
func (e *Engine) storeStats(id string, s types.Stats) {
	st := e.runtimeState(id)
	e.mu.Lock()
	st.lastSample = s
	e.mu.Unlock()
}
