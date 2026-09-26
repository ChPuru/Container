package shim

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ChPuru/hull/internal/types"
)

// cgroupReader samples one container's cgroup.
//
// It feature-probes rather than assuming a layout, because hull's target host
// is a WSL 2.4.13 kernel with hybrid cgroups and no v2 controllers delegated:
// memory.current simply is not there. Every read is therefore best-effort and
// a missing file leaves its field zero rather than failing the sample — the
// place that explains the missing delegation is hull doctor, not every single
// stats call.
type cgroupReader struct {
	path string

	// v2 reports that path looks like a unified hierarchy.
	v2 bool
}

// newCgroupReader returns a reader for the cgroup directory at path. An empty
// path yields a reader that reports empty samples.
func newCgroupReader(path string) *cgroupReader {
	r := &cgroupReader{path: path}
	if path == "" {
		return r
	}
	// cgroup.controllers only exists on a v2 hierarchy.
	if _, err := os.Stat(filepath.Join(path, "cgroup.controllers")); err == nil {
		r.v2 = true
		return r
	}
	if _, err := os.Stat(filepath.Join(path, "cgroup.events")); err == nil {
		r.v2 = true
	}
	return r
}

// Available reports whether the reader has a cgroup directory to read.
func (r *cgroupReader) Available() bool {
	if r.path == "" {
		return false
	}
	_, err := os.Stat(r.path)
	return err == nil
}

// readUint reads a single-integer cgroup file. A missing file, or the literal
// "max", reports 0 and false.
func (r *cgroupReader) readUint(name string) (uint64, bool) {
	data, err := os.ReadFile(filepath.Join(r.path, name))
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(data))
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// readKeyed reads a "key value" cgroup file such as memory.stat or cpu.stat.
func (r *cgroupReader) readKeyed(name string) map[string]uint64 {
	f, err := os.Open(filepath.Join(r.path, name))
	if err != nil {
		return nil
	}
	defer f.Close()
	out := make(map[string]uint64, 16)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		out[fields[0]] = v
	}
	return out
}

// OOMKills reports the cgroup's cumulative OOM kill count.
//
// On v2 it is the oom_kill counter in memory.events. On a v1 memory
// controller there is no such counter, so the v1 path falls back to
// memory.oom_control's oom_kill line where the kernel has it, and otherwise
// reports "unknown" rather than a confident zero.
func (r *cgroupReader) OOMKills() (uint64, bool) {
	if r.path == "" {
		return 0, false
	}
	if ev := r.readKeyed("memory.events"); ev != nil {
		v, ok := ev["oom_kill"]
		return v, ok
	}
	if ev := r.readKeyed("memory.oom_control"); ev != nil {
		v, ok := ev["oom_kill"]
		return v, ok
	}
	return 0, false
}

// Stats samples the cgroup into a types.Stats. prev, when non-nil, supplies
// the previous sample so the caller can compute a CPU percentage.
func (r *cgroupReader) Stats(prev *types.Stats) types.Stats {
	now := time.Now()
	st := types.Stats{Read: now, OnlineCPUs: runtime.NumCPU()}
	if prev != nil {
		st.PreRead = prev.Read
		st.PreCPUUsage = prev.CPUUsage
		st.PreSystemUsage = prev.SystemUsage
	}
	st.SystemUsage = systemCPUUsec()
	if r.path == "" {
		return st
	}

	if r.v2 {
		r.statsV2(&st)
	} else {
		r.statsV1(&st)
	}
	return st
}

// statsV2 fills st from a unified hierarchy.
func (r *cgroupReader) statsV2(st *types.Stats) {
	if cpu := r.readKeyed("cpu.stat"); cpu != nil {
		st.CPUUsage = cpu["usage_usec"]
	}
	if v, ok := r.readUint("memory.current"); ok {
		st.MemoryUsage = v
	}
	if v, ok := r.readUint("memory.max"); ok {
		st.MemoryLimit = v
	}
	if m := r.readKeyed("memory.stat"); m != nil {
		st.MemoryCache = m["file"]
		// Docker reports "usage minus page cache" as the useful number; hull
		// keeps both and lets the API layer decide.
		if st.MemoryUsage == 0 {
			st.MemoryUsage = m["anon"] + m["file"]
		}
	}
	if v, ok := r.readUint("pids.current"); ok {
		st.PidsCurrent = v
	}
	if v, ok := r.readUint("pids.max"); ok {
		st.PidsLimit = v
	}
	blk := r.readIOStat("io.stat")
	st.BlkRead, st.BlkWrite = blk[0], blk[1]
	r.readPSI(st)
}

// statsV1 fills st from a split v1 hierarchy, where the container's
// controllers hang off sibling directories. hull passes CgroupPath pointing at
// the memory controller's directory, and the other controllers are found by
// swapping the controller name in the path.
func (r *cgroupReader) statsV1(st *types.Stats) {
	if v, ok := r.readUint("memory.usage_in_bytes"); ok {
		st.MemoryUsage = v
	}
	if v, ok := r.readUint("memory.limit_in_bytes"); ok && v < 1<<62 {
		st.MemoryLimit = v
	}
	if m := r.readKeyed("memory.stat"); m != nil {
		st.MemoryCache = m["cache"]
	}
	if v, ok := r.readUint("pids.current"); ok {
		st.PidsCurrent = v
	}
	// cpuacct.usage is nanoseconds.
	if v, ok := r.readUint("cpuacct.usage"); ok {
		st.CPUUsage = v / 1000
	}
}

// readIOStat sums rbytes and wbytes across devices in a v2 io.stat.
func (r *cgroupReader) readIOStat(name string) [2]uint64 {
	var out [2]uint64
	data, err := os.ReadFile(filepath.Join(r.path, name))
	if err != nil {
		return out
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		for _, f := range strings.Fields(string(line)) {
			k, v, ok := strings.Cut(f, "=")
			if !ok {
				continue
			}
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				continue
			}
			switch k {
			case "rbytes":
				out[0] += n
			case "wbytes":
				out[1] += n
			}
		}
	}
	return out
}

// readPSI fills the pressure fields when the kernel has CONFIG_PSI. The WSL
// 5.15 kernel does not, so these stay zero there; that is why the fields are
// omitempty in types.Stats.
func (r *cgroupReader) readPSI(st *types.Stats) {
	st.MemPressureSome10 = psiSome10(filepath.Join(r.path, "memory.pressure"))
	st.CPUPressureSome10 = psiSome10(filepath.Join(r.path, "cpu.pressure"))
	st.IOPressureSome10 = psiSome10(filepath.Join(r.path, "io.pressure"))
}

// psiSome10 extracts the "some avg10" figure from a pressure file.
func psiSome10(path string) float64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if k, v, ok := strings.Cut(f, "="); ok && k == "avg10" {
				n, err := strconv.ParseFloat(v, 64)
				if err != nil {
					return 0
				}
				return n
			}
		}
	}
	return 0
}

// systemCPUUsec reads total system CPU time from /proc/stat in microseconds,
// which is the denominator Docker's CPU percentage uses.
func systemCPUUsec() uint64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	line, _, _ := bytes.Cut(data, []byte("\n"))
	fields := strings.Fields(string(line))
	if len(fields) < 8 || fields[0] != "cpu" {
		return 0
	}
	var total uint64
	for _, f := range fields[1:] {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return 0
		}
		total += v
	}
	// USER_HZ is 100 on every architecture Linux supports for containers.
	const userHZ = 100
	return total * (1_000_000 / userHZ)
}

// KillAll kills every process in the cgroup at once.
//
// cgroup.kill (v2, Linux 5.14+) is atomic: no process can fork its way out
// between the enumeration and the signal. When it is absent — which it is on a
// v1 hierarchy — the caller must fall back to the runtime's kill --all.
func (r *cgroupReader) KillAll() error {
	if r.path == "" {
		return errors.New("shim: no cgroup path is configured for this container")
	}
	f := filepath.Join(r.path, "cgroup.kill")
	err := os.WriteFile(f, []byte("1"), 0)
	if err == nil {
		return nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("shim: this kernel's cgroup has no cgroup.kill (needs cgroup v2 on Linux 5.14+)")
	}
	return err
}
