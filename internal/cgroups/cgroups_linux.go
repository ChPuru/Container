//go:build linux

package cgroups

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/types"
)

// sysClone3 is the clone3(2) syscall number. It is 435 on every Linux
// architecture, so it does not need a per-arch table.
const sysClone3 = 435

// procMounts is the file Detect parses. It is a variable so tests can point it
// at golden data.
var procMounts = "/proc/mounts"

// userHZ is the kernel's USER_HZ, which is 100 on every architecture Linux
// ships a /proc/stat in jiffies for. SystemUsageUsec converts with it.
const userHZ = 100

var (
	clone3Once sync.Once
	clone3OK   bool
)

// hasClone3 probes clone3(2) exactly once by invoking it with a NULL argument
// block. A kernel that implements clone3 rejects that with EINVAL (the size
// check runs before anything else, so no child is ever created); a kernel or
// seccomp filter without it answers ENOSYS or EPERM.
func hasClone3() bool {
	clone3Once.Do(func() {
		_, _, errno := unix.RawSyscall(sysClone3, 0, 0, 0)
		switch errno {
		case unix.ENOSYS, unix.EPERM, unix.EACCES:
			clone3OK = false
		default:
			clone3OK = true
		}
	})
	return clone3OK
}

// Detect probes the host's cgroup configuration by reading /proc/mounts and
// the cgroup2 root's interface files.
//
// It reports ModeUnified when a cgroup2 filesystem is mounted and no cgroup v1
// hierarchies are, ModeHybrid when both exist (the WSL 2.4.13 default, where
// cgroup2 sits on /sys/fs/cgroup/unified with an empty cgroup.controllers),
// ModeLegacy when only v1 is mounted and ModeUnavailable when neither is.
//
// Detect never fails because the host is misconfigured: a host hull cannot use
// comes back with Usable() false and HybridRemedy in Warnings. It only returns
// an error when /proc/mounts itself cannot be read.
func Detect() (Info, error) {
	var info Info

	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		info.KernelVersion = unix.ByteSliceToString(uts.Release[:])
	}

	data, err := os.ReadFile(procMounts)
	if err != nil {
		return info, fmt.Errorf("cgroups: read %s: %w", procMounts, err)
	}

	var v2Roots []string
	var v1Mounts []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		mountpoint, fstype := unescapeMountField(f[1]), f[2]
		switch fstype {
		case "cgroup2":
			v2Roots = append(v2Roots, mountpoint)
		case "cgroup":
			v1Mounts = append(v1Mounts, mountpoint)
		}
	}

	// Prefer /sys/fs/cgroup when it is itself the cgroup2 mount; otherwise take
	// the shortest cgroup2 mountpoint (the hybrid layout's
	// /sys/fs/cgroup/unified beats any per-container bind mount).
	for _, r := range v2Roots {
		if r == "/sys/fs/cgroup" {
			info.Root = r
			break
		}
		if info.Root == "" || len(r) < len(info.Root) {
			info.Root = r
		}
	}

	switch {
	case len(v2Roots) > 0 && len(v1Mounts) > 0:
		info.Mode = ModeHybrid
	case len(v2Roots) > 0:
		info.Mode = ModeUnified
	case len(v1Mounts) > 0:
		info.Mode = ModeLegacy
	default:
		info.Mode = ModeUnavailable
	}

	if info.Root == "" {
		info.Warnings = append(info.Warnings, HybridRemedy)
		return info, nil
	}

	if s, err := readCgroupFile(info.Root, "cgroup.controllers"); err == nil {
		info.Controllers = strings.Fields(s)
	} else if !errors.Is(err, os.ErrNotExist) {
		info.Warnings = append(info.Warnings,
			fmt.Sprintf("cannot read %s/cgroup.controllers: %v", info.Root, err))
	}
	if s, err := readCgroupFile(info.Root, "cgroup.subtree_control"); err == nil {
		info.Delegated = len(strings.Fields(s)) > 0
	}

	info.HasPSI = fileExists(filepath.Join(info.Root, "cpu.pressure"))
	info.HasKill = probeInterfaceFile(info.Root, "cgroup.kill", info.KernelVersion, 5, 14)
	info.HasFreezer = probeInterfaceFile(info.Root, "cgroup.freeze", info.KernelVersion, 5, 2)
	info.HasCloneInto = kernelAtLeast(info.KernelVersion, 5, 7) && hasClone3()

	if info.Mode != ModeUnified || len(info.Controllers) == 0 {
		info.Warnings = append(info.Warnings, HybridRemedy)
	}
	if info.Mode == ModeHybrid && len(info.Controllers) > 0 {
		info.Warnings = append(info.Warnings, fmt.Sprintf(
			"cgroup v1 hierarchies are still mounted; hull uses the cgroup2 mount at %s and ignores them",
			info.Root))
	}

	return info, nil
}

// probeInterfaceFile reports whether a per-cgroup interface file such as
// cgroup.kill exists. Those files are absent from the *root* cgroup by design,
// so the probe looks at the root first, then at up to a handful of existing
// child cgroups, and finally falls back to the kernel version.
func probeInterfaceFile(root, name, kernel string, major, minor int) bool {
	if fileExists(filepath.Join(root, name)) {
		return true
	}
	if ents, err := os.ReadDir(root); err == nil {
		checked := 0
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			if fileExists(filepath.Join(root, e.Name(), name)) {
				return true
			}
			if checked++; checked >= 8 {
				break
			}
		}
	}
	return kernelAtLeast(kernel, major, minor)
}

func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// ---------- fd-relative file helpers ----------

// openCgroupDir opens a cgroup directory with O_DIRECTORY|O_NOFOLLOW so the
// per-knob reads and writes below are all relative to a verified directory fd
// rather than re-resolving a path string on every access.
func openCgroupDir(dir string) (*os.File, error) {
	fd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	return os.NewFile(uintptr(fd), dir), nil
}

// readCgroupFile reads one interface file of a cgroup directory.
func readCgroupFile(dir, name string) (string, error) {
	d, err := openCgroupDir(dir)
	if err != nil {
		return "", err
	}
	defer d.Close()
	return readCgroupFileAt(int(d.Fd()), dir, name)
}

func readCgroupFileAt(dirfd int, dir, name string) (string, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", &os.PathError{Op: "open", Path: filepath.Join(dir, name), Err: err}
	}
	f := os.NewFile(uintptr(fd), filepath.Join(dir, name))
	defer f.Close()
	// cgroup files report size 0, so ReadAll rather than a sized read.
	b, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", filepath.Join(dir, name), err)
	}
	return string(b), nil
}

// writeCgroupFile writes one interface file of a cgroup directory. cgroupfs
// requires the value to arrive in a single write(2), so it is never buffered.
func writeCgroupFile(dir, name, value string) error {
	d, err := openCgroupDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return writeCgroupFileAt(int(d.Fd()), dir, name, value)
}

func writeCgroupFileAt(dirfd int, dir, name, value string) error {
	full := filepath.Join(dir, name)
	fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: full, Err: err}
	}
	defer unix.Close(fd)
	n, err := unix.Write(fd, []byte(value))
	if err != nil {
		return &os.PathError{Op: "write", Path: full, Err: err}
	}
	if n != len(value) {
		return fmt.Errorf("write %s: short write %d of %d bytes", full, n, len(value))
	}
	return nil
}

// ---------- Manager ----------

// Manager owns one cgroup v2 directory and all operations on it.
//
// A Manager holds no long-lived file descriptor: every operation opens the
// cgroup directory fresh with O_DIRECTORY|O_NOFOLLOW and works fd-relative
// from there, so a Manager is safe to keep for the lifetime of a container and
// safe to use from multiple goroutines.
type Manager struct {
	info Info
	rel  string // path relative to the v2 root, e.g. "hull/<id>"
	path string // absolute path, e.g. "/sys/fs/cgroup/hull/<id>"

	mu       sync.Mutex
	warnings []string
}

// New creates the cgroup at path (relative to the cgroup v2 root, e.g.
// "hull/<containerID>") together with every missing ancestor, and enables the
// controllers hull needs ("+cpu +memory +pids +io", plus cpuset when the
// kernel offers it) in each ancestor's cgroup.subtree_control.
//
// Controllers the kernel does not list in an ancestor's cgroup.controllers are
// skipped. Delegation is never attempted in a non-root cgroup that already has
// processes in it, because the kernel's no-internal-process rule forbids that;
// such a skip is recorded in Warnings instead of failing.
//
// New refuses to run on a host whose cgroup v2 hierarchy has no controllers -
// the WSL hybrid default - returning an error containing HybridRemedy rather
// than creating a cgroup whose limits would silently do nothing.
func New(info Info, path string) (*Manager, error) {
	m, err := newManager(info, path)
	if err != nil {
		return nil, err
	}
	if err := m.create(); err != nil {
		return nil, err
	}
	return m, nil
}

// Load attaches to an existing cgroup at path (relative to the cgroup v2
// root) without creating anything or touching cgroup.subtree_control.
func Load(info Info, path string) (*Manager, error) {
	m, err := newManager(info, path)
	if err != nil {
		return nil, err
	}
	d, err := openCgroupDir(m.path)
	if err != nil {
		return nil, fmt.Errorf("cgroups: load %s: %w", m.path, err)
	}
	defer d.Close()
	if _, err := readCgroupFileAt(int(d.Fd()), m.path, "cgroup.procs"); err != nil {
		return nil, fmt.Errorf("cgroups: %s is not a cgroup v2 directory: %w", m.path, err)
	}
	return m, nil
}

func newManager(info Info, path string) (*Manager, error) {
	rel, err := cleanRelPath(path)
	if err != nil {
		return nil, err
	}
	if info.Root == "" {
		return nil, fmt.Errorf("cgroups: no cgroup v2 mount found (mode %s): %s: %w",
			info.Mode, HybridRemedy, ErrUnsupported)
	}
	if len(info.Controllers) == 0 {
		return nil, fmt.Errorf("cgroups: cgroup v2 root %s lists no controllers (mode %s): %s: %w",
			info.Root, info.Mode, HybridRemedy, ErrUnsupported)
	}
	return &Manager{info: info, rel: rel, path: filepath.Join(info.Root, rel)}, nil
}

func (m *Manager) create() error {
	segs := strings.Split(m.rel, "/")

	// Ancestors, root first, excluding the leaf itself: each of them must
	// delegate the controllers downwards for the leaf to have the knobs.
	dir := m.info.Root
	for i := 0; i <= len(segs)-1; i++ {
		if i > 0 {
			dir = filepath.Join(dir, segs[i-1])
			if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("cgroups: mkdir %s: %w", dir, err)
			}
		}
		isRoot := dir == m.info.Root
		if err := m.enableControllers(dir, isRoot); err != nil {
			return err
		}
	}

	if err := os.Mkdir(m.path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("cgroups: mkdir %s: %w", m.path, err)
	}
	return nil
}

// enableControllers writes the missing "+<controller>" tokens into dir's
// cgroup.subtree_control. It never enables anything in a non-root cgroup that
// already holds processes, and it degrades to one write per controller if the
// combined write is rejected, so a single unsupported controller cannot block
// the rest.
func (m *Manager) enableControllers(dir string, isRoot bool) error {
	avail, err := readCgroupFile(dir, "cgroup.controllers")
	if err != nil {
		return fmt.Errorf("cgroups: read %s/cgroup.controllers: %w", dir, err)
	}
	have := make(map[string]bool)
	for _, c := range strings.Fields(avail) {
		have[c] = true
	}
	cur, err := readCgroupFile(dir, "cgroup.subtree_control")
	if err != nil {
		return fmt.Errorf("cgroups: read %s/cgroup.subtree_control: %w", dir, err)
	}
	enabled := make(map[string]bool)
	for _, c := range strings.Fields(cur) {
		enabled[c] = true
	}

	var want []string
	for _, c := range append(append([]string{}, hullControllers...), optionalControllers...) {
		if have[c] && !enabled[c] {
			want = append(want, c)
		}
	}
	for _, c := range hullControllers {
		if !have[c] {
			m.warn(fmt.Sprintf("controller %q is not available in %s; the matching limits cannot be applied", c, dir))
		}
	}
	if len(want) == 0 {
		return nil
	}

	// The kernel's no-internal-process rule: a non-root cgroup that contains
	// processes may not enable controllers for its children.
	if !isRoot {
		procs, err := readCgroupFile(dir, "cgroup.procs")
		if err == nil && strings.TrimSpace(procs) != "" {
			m.warn(fmt.Sprintf("not enabling %s in %s: it already contains processes",
				strings.Join(want, ","), dir))
			return nil
		}
	}

	var tokens []string
	for _, c := range want {
		tokens = append(tokens, "+"+c)
	}
	if err := writeCgroupFile(dir, "cgroup.subtree_control", strings.Join(tokens, " ")); err == nil {
		return nil
	}
	// Combined write refused: salvage whatever the kernel does accept.
	for _, c := range want {
		if err := writeCgroupFile(dir, "cgroup.subtree_control", "+"+c); err != nil {
			m.warn(fmt.Sprintf("cannot enable controller %q in %s: %v", c, dir, err))
		}
	}
	return nil
}

func (m *Manager) warn(s string) {
	m.mu.Lock()
	m.warnings = append(m.warnings, s)
	m.mu.Unlock()
}

// Warnings returns the non-fatal problems recorded while creating or using
// this cgroup, such as a controller the kernel does not offer.
func (m *Manager) Warnings() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.warnings...)
}

// Path returns the absolute filesystem path of the cgroup directory.
func (m *Manager) Path() string { return m.path }

// Rel returns the cgroup's path relative to the cgroup v2 root, which is also
// what /proc/<pid>/cgroup reports.
func (m *Manager) Rel() string { return m.rel }

// Info returns the host cgroup information this Manager was built with.
func (m *Manager) Info() Info { return m.info }

// FD returns a newly opened O_DIRECTORY file descriptor for the cgroup,
// suitable for clone3's CLONE_INTO_CGROUP. The caller owns the descriptor and
// must close it with unix.Close.
func (m *Manager) FD() (int, error) {
	fd, err := unix.Open(m.path, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: m.path, Err: err}
	}
	return fd, nil
}

// knob is one pending write, used so Apply can report every failure instead of
// only the first.
type knob struct {
	name  string
	value string
	// controller is the v2 controller that owns the knob, used to explain a
	// missing file.
	controller string
}

// Apply writes the resource limits to the cgroup's v2 knobs.
//
// Every knob is best-effort and independent: if a controller is missing or a
// write is refused, Apply records a descriptive error and continues with the
// remaining knobs, returning errors.Join of everything that failed. It never
// aborts on the first failure, because a half-applied cgroup with an
// unreported failure is worse than a fully attempted one with a precise error.
//
// cpu.max.burst is not written here: types.Resources carries no burst field.
// Use SetCPUBurst for that.
func (m *Manager) Apply(r types.Resources) error {
	var knobs []knob
	var errs []error

	if r.CPUShares != 0 {
		knobs = append(knobs, knob{"cpu.weight", strconv.FormatUint(CPUSharesToWeight(r.CPUShares), 10), "cpu"})
	}
	if v, ok := CPUMax(r.CPUQuota, r.CPUPeriod, r.NanoCPUs); ok {
		knobs = append(knobs, knob{"cpu.max", v, "cpu"})
	}
	if v, ok := MemoryMax(r.Memory); ok {
		knobs = append(knobs, knob{"memory.max", v, "memory"})
	}
	if r.MemoryReservation != 0 {
		v, ok := MemoryMax(r.MemoryReservation)
		if ok {
			if v == "max" {
				v = "0"
			}
			knobs = append(knobs, knob{"memory.low", v, "memory"})
		}
	}
	if v, ok := SwapMax(r.Memory, r.MemorySwap); ok {
		knobs = append(knobs, knob{"memory.swap.max", v, "memory"})
	} else if r.MemorySwap != 0 {
		errs = append(errs, fmt.Errorf(
			"cgroups: invalid memory-swap %d with memory %d: memory-swap is the combined memory+swap budget and must be -1 or >= memory (which must be set)",
			r.MemorySwap, r.Memory))
	}
	if r.BlkioWeight != 0 {
		knobs = append(knobs, knob{"io.weight", strconv.FormatUint(BlkioWeightToIOWeight(r.BlkioWeight), 10), "io"})
	}
	if r.CpusetCpus != "" {
		knobs = append(knobs, knob{"cpuset.cpus", r.CpusetCpus, "cpuset"})
	}
	if r.CpusetMems != "" {
		knobs = append(knobs, knob{"cpuset.mems", r.CpusetMems, "cpuset"})
	}

	d, err := openCgroupDir(m.path)
	if err != nil {
		return fmt.Errorf("cgroups: apply to %s: %w", m.path, err)
	}
	defer d.Close()
	dirfd := int(d.Fd())

	for _, k := range knobs {
		if err := writeCgroupFileAt(dirfd, m.path, k.name, k.value); err != nil {
			errs = append(errs, m.knobError(k, err))
		}
	}
	return errors.Join(errs...)
}

// SetPidsLimit writes pids.max. A limit <= 0 means unlimited ("max").
//
// It is separate from Apply because types.Resources has no pids field:
// HostConfig.PidsLimit carries it.
func (m *Manager) SetPidsLimit(limit int64) error {
	v := "max"
	if limit > 0 {
		v = strconv.FormatInt(limit, 10)
	}
	if err := writeCgroupFile(m.path, "pids.max", v); err != nil {
		return m.knobError(knob{"pids.max", v, "pids"}, err)
	}
	return nil
}

// SetCPUBurst writes cpu.max.burst, the burst budget in microseconds, when the
// kernel supports it (5.14+ with CONFIG_CFS_BANDWIDTH). On a kernel without
// the knob it reports a descriptive error naming the missing file.
func (m *Manager) SetCPUBurst(burstUsec uint64) error {
	v := strconv.FormatUint(burstUsec, 10)
	if err := writeCgroupFile(m.path, "cpu.max.burst", v); err != nil {
		return m.knobError(knob{"cpu.max.burst", v, "cpu"}, err)
	}
	return nil
}

// SetOOMGroup writes memory.oom.group, which makes the kernel kill every task
// in the cgroup when one of them is OOM-killed.
func (m *Manager) SetOOMGroup(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	if err := writeCgroupFile(m.path, "memory.oom.group", v); err != nil {
		return m.knobError(knob{"memory.oom.group", v, "memory"}, err)
	}
	return nil
}

// knobError turns a raw write failure into an actionable message that names
// the controller, and the remedy when the whole v2 hierarchy is crippled.
func (m *Manager) knobError(k knob, err error) error {
	if errors.Is(err, os.ErrNotExist) {
		if !m.info.HasController(k.controller) {
			return fmt.Errorf("cgroups: cannot set %s=%s: the %q controller is not available on this kernel: %s",
				k.name, k.value, k.controller, HybridRemedy)
		}
		return fmt.Errorf("cgroups: cannot set %s=%s: %s does not exist; the %q controller is not enabled in the parent's cgroup.subtree_control",
			k.name, k.value, filepath.Join(m.path, k.name), k.controller)
	}
	return fmt.Errorf("cgroups: cannot set %s=%s in %s: %w", k.name, k.value, m.path, err)
}

// AddProcess moves the process (and, as cgroup v2 requires, its whole thread
// group) into this cgroup by writing to cgroup.procs.
func (m *Manager) AddProcess(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("cgroups: invalid pid %d", pid)
	}
	if err := writeCgroupFile(m.path, "cgroup.procs", strconv.Itoa(pid)); err != nil {
		return fmt.Errorf("cgroups: add pid %d to %s: %w", pid, m.path, err)
	}
	return nil
}

// Procs returns the pids currently in this cgroup, not including those in
// descendant cgroups.
func (m *Manager) Procs() ([]int, error) {
	s, err := readCgroupFile(m.path, "cgroup.procs")
	if err != nil {
		return nil, fmt.Errorf("cgroups: read procs of %s: %w", m.path, err)
	}
	pids, err := parsePids(s)
	if err != nil {
		return pids, fmt.Errorf("cgroups: %s/cgroup.procs: %w", m.path, err)
	}
	return pids, nil
}

// Stat samples the cgroup's counters.
//
// Files the kernel does not provide - memory.peak before 5.19, the PSI
// pressure files on a CONFIG_PSI-less WSL 5.15 kernel - leave their fields
// zero and are not an error. Any other read or parse failure is collected and
// returned joined, alongside the partially filled Stat.
func (m *Manager) Stat() (Stat, error) {
	var st Stat
	var errs []error

	d, err := openCgroupDir(m.path)
	if err != nil {
		return st, fmt.Errorf("cgroups: stat %s: %w", m.path, err)
	}
	defer d.Close()
	dirfd := int(d.Fd())

	read := func(name string) (string, bool) {
		s, err := readCgroupFileAt(dirfd, m.path, name)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("cgroups: read %s: %w", filepath.Join(m.path, name), err))
			}
			return "", false
		}
		return s, true
	}
	readUint := func(name string) (uint64, bool) {
		s, ok := read(name)
		if !ok {
			return 0, false
		}
		v, err := parseUintFile(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("cgroups: %s: %w", filepath.Join(m.path, name), err))
			return 0, false
		}
		return v, true
	}
	readLimit := func(name string) (uint64, bool) {
		s, ok := read(name)
		if !ok {
			return 0, false
		}
		v, err := parseLimitFile(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("cgroups: %s: %w", filepath.Join(m.path, name), err))
			return 0, false
		}
		return v, true
	}

	if s, ok := read("cpu.stat"); ok {
		kv := parseKeyedUint(s)
		st.CPUUsageUsec = kv["usage_usec"]
		st.CPUUserUsec = kv["user_usec"]
		st.CPUSystemUsec = kv["system_usec"]
	}

	st.MemoryCurrent, _ = readUint("memory.current")
	st.MemoryPeak, _ = readUint("memory.peak")
	st.MemoryLimit, _ = readLimit("memory.max")
	if s, ok := read("memory.stat"); ok {
		kv := parseKeyedUint(s)
		st.MemoryAnon = kv["anon"]
		st.MemoryFile = kv["file"]
	}
	if s, ok := read("memory.events"); ok {
		st.OOMKills = parseKeyedUint(s)["oom_kill"]
	}

	st.PidsCurrent, _ = readUint("pids.current")
	st.PidsLimit, _ = readLimit("pids.max")

	if s, ok := read("io.stat"); ok {
		st.IORead, st.IOWrite = parseIOStat(s)
	}

	if s, ok := read("cpu.pressure"); ok {
		st.CPUPressureSome10 = parsePressureSome10(s)
	}
	if s, ok := read("memory.pressure"); ok {
		st.MemPressureSome10 = parsePressureSome10(s)
	}
	if s, ok := read("io.pressure"); ok {
		st.IOPressureSome10 = parsePressureSome10(s)
	}

	return st, errors.Join(errs...)
}

// Freeze suspends every task in the cgroup and its descendants by writing
// cgroup.freeze. It returns once the kernel reports the cgroup frozen.
func (m *Manager) Freeze() error { return m.setFreeze(true) }

// Thaw resumes a frozen cgroup.
func (m *Manager) Thaw() error { return m.setFreeze(false) }

func (m *Manager) setFreeze(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	if err := writeCgroupFile(m.path, "cgroup.freeze", v); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("cgroups: cgroup.freeze is missing in %s: the cgroup v2 freezer needs kernel 5.2+ (running %s)",
				m.path, m.info.KernelVersion)
		}
		return fmt.Errorf("cgroups: write cgroup.freeze=%s in %s: %w", v, m.path, err)
	}
	// cgroup.freeze is asynchronous: wait for the state to settle so callers
	// can rely on a returned nil meaning "actually frozen".
	deadline := time.Now().Add(5 * time.Second)
	for delay := 200 * time.Microsecond; time.Now().Before(deadline); delay = nextDelay(delay) {
		frozen, err := m.Frozen()
		if err != nil {
			return err
		}
		if frozen == on {
			return nil
		}
		time.Sleep(delay)
	}
	return fmt.Errorf("cgroups: timed out waiting for %s to become frozen=%v", m.path, on)
}

// Frozen reports whether the cgroup is currently frozen.
func (m *Manager) Frozen() (bool, error) {
	s, err := readCgroupFile(m.path, "cgroup.freeze")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("cgroups: read cgroup.freeze of %s: %w", m.path, err)
	}
	return strings.TrimSpace(s) == "1", nil
}

// Kill kills every process in the cgroup and its descendants.
//
// It prefers cgroup.kill (kernel 5.14+), which is atomic and immune to fork
// bombs. When that file is absent it falls back to reading cgroup.procs and
// sending SIGKILL to each pid, repeating until the cgroup is empty or a bound
// is reached.
func (m *Manager) Kill() error {
	err := writeCgroupFile(m.path, "cgroup.kill", "1")
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cgroups: write cgroup.kill in %s: %w", m.path, err)
	}
	return m.killByPid()
}

func (m *Manager) killByPid() error {
	deadline := time.Now().Add(10 * time.Second)
	for delay := time.Millisecond; ; delay = nextDelay(delay) {
		pids, err := m.Procs()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil // the cgroup is gone, so nothing is running in it
			}
			return err
		}
		if len(pids) == 0 {
			return nil
		}
		for _, pid := range pids {
			if err := unix.Kill(pid, unix.SIGKILL); err != nil &&
				!errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.EPERM) {
				return fmt.Errorf("cgroups: kill pid %d from %s: %w", pid, m.path, err)
			}
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("cgroups: %s still has %d process(es) after SIGKILL", m.path, len(pids))
		}
		time.Sleep(delay)
	}
}

// Delete kills the cgroup's processes, waits for it to drain and removes the
// directory. rmdir(2) returns EBUSY while any task remains, so the removal is
// retried with a bounded backoff.
//
// Deleting an already-removed cgroup is not an error.
func (m *Manager) Delete() error {
	if _, err := os.Lstat(m.path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := m.Kill(); err != nil {
		// Keep going: rmdir may still succeed, and its error is the better one.
		m.warn(fmt.Sprintf("kill before delete failed: %v", err))
	}

	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for delay := time.Millisecond; ; delay = nextDelay(delay) {
		// Remove descendants first: rmdir only works on an empty cgroup.
		m.removeDescendants()
		err := unix.Rmdir(m.path)
		switch {
		case err == nil, errors.Is(err, unix.ENOENT):
			return nil
		case errors.Is(err, unix.EBUSY), errors.Is(err, unix.ENOTEMPTY):
			lastErr = err
		default:
			return fmt.Errorf("cgroups: rmdir %s: %w", m.path, err)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("cgroups: rmdir %s: still busy after 10s: %w", m.path, lastErr)
		}
		time.Sleep(delay)
	}
}

// removeDescendants removes any child cgroups depth-first, ignoring failures:
// the caller retries, and a persistent failure surfaces as the rmdir error.
func (m *Manager) removeDescendants() {
	ents, err := os.ReadDir(m.path)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		child := &Manager{info: m.info, rel: filepath.Join(m.rel, e.Name()), path: filepath.Join(m.path, e.Name())}
		_ = child.Kill()
		child.removeDescendants()
		_ = unix.Rmdir(child.path)
	}
}

// nextDelay doubles a backoff delay up to 50ms.
func nextDelay(d time.Duration) time.Duration {
	d *= 2
	if d > 50*time.Millisecond {
		d = 50 * time.Millisecond
	}
	return d
}

// EventFD returns an inotify descriptor watching memory.events, wrapped in an
// *os.File. Every readable event means the file changed, so the caller should
// re-read Stat and compare OOMKills to detect an OOM kill.
//
// The descriptor is non-blocking and CLOEXEC; the caller must Close it.
func (m *Manager) EventFD() (*os.File, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("cgroups: inotify_init1: %w", err)
	}
	target := filepath.Join(m.path, "memory.events")
	if _, err := unix.InotifyAddWatch(fd, target, unix.IN_MODIFY); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("cgroups: cannot watch %s: the memory controller is not enabled for %s: %s",
				target, m.path, HybridRemedy)
		}
		return nil, fmt.Errorf("cgroups: inotify_add_watch %s: %w", target, err)
	}
	return os.NewFile(uintptr(fd), "inotify:"+target), nil
}

// ---------- host-wide helpers ----------

// procStat is the file SystemUsageUsec parses. It is a variable so tests can
// point it at golden data.
var procStat = "/proc/stat"

// SystemUsageUsec returns the host's cumulative CPU time in microseconds,
// summed over every CPU, from the aggregate "cpu" line of /proc/stat.
//
// It matches Docker's getSystemCPUUsage: the first seven fields (user, nice,
// system, idle, iowait, irq, softirq) are summed, idle included, because
// Docker's CPU percentage is cpuDelta/systemDelta*onlineCPUs*100 and that
// ratio is only meaningful against total elapsed CPU time.
func SystemUsageUsec() (uint64, error) {
	data, err := os.ReadFile(procStat)
	if err != nil {
		return 0, fmt.Errorf("cgroups: read %s: %w", procStat, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "cpu" {
			continue
		}
		if len(f) < 8 {
			return 0, fmt.Errorf("cgroups: %s: aggregate cpu line has %d fields, want at least 8", procStat, len(f))
		}
		var ticks uint64
		for _, v := range f[1:8] {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("cgroups: %s: parse %q: %w", procStat, v, err)
			}
			ticks += n
		}
		return ticks * 1_000_000 / userHZ, nil
	}
	return 0, fmt.Errorf("cgroups: %s: no aggregate cpu line", procStat)
}

// cpuOnline is the file OnlineCPUs parses. It is a variable so tests can point
// it at golden data.
var cpuOnline = "/sys/devices/system/cpu/online"

// OnlineCPUs returns the number of online CPUs, from
// /sys/devices/system/cpu/online (a list such as "0-7" or "0,2-3"), falling
// back to runtime.NumCPU when that file is unreadable.
func OnlineCPUs() int {
	data, err := os.ReadFile(cpuOnline)
	if err == nil {
		if n := countCPUList(string(data)); n > 0 {
			return n
		}
	}
	return runtime.NumCPU()
}
