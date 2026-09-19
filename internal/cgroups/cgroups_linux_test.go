//go:build linux

package cgroups

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahuldhali/hull/internal/types"
)

// writeTempFile writes content to a file in t.TempDir and returns its path.
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

const mountsUnified = `proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot 0 0
`

// mountsHybrid is the layout hull actually finds on WSL 2.4.13: cgroup2 is
// mounted on /sys/fs/cgroup/unified with no controllers, and every controller
// belongs to a cgroup v1 hierarchy.
const mountsHybrid = `tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,mode=755 0 0
cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0
cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/pids cgroup rw,nosuid,nodev,noexec,relatime,pids 0 0
`

const mountsLegacy = `tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,mode=755 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/pids cgroup rw,nosuid,nodev,noexec,relatime,pids 0 0
`

const mountsNone = `proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
`

func TestDetectModeFromMounts(t *testing.T) {
	tests := []struct {
		name     string
		mounts   string
		wantMode Mode
		wantRoot string
		wantWarn bool
	}{
		{"pure cgroup v2", mountsUnified, ModeUnified, "/sys/fs/cgroup", false},
		{"wsl hybrid", mountsHybrid, ModeHybrid, "/sys/fs/cgroup/unified", true},
		{"legacy v1 only", mountsLegacy, ModeLegacy, "", true},
		{"no cgroups at all", mountsNone, ModeUnavailable, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			saved := procMounts
			procMounts = writeTempFile(t, "mounts", tc.mounts)
			defer func() { procMounts = saved }()

			info, err := Detect()
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if info.Mode != tc.wantMode {
				t.Errorf("Mode = %v, want %v", info.Mode, tc.wantMode)
			}
			if info.Root != tc.wantRoot {
				t.Errorf("Root = %q, want %q", info.Root, tc.wantRoot)
			}
			// The mount points in the golden data do not exist as a real
			// cgroup2 fs in the test environment (except possibly the pure-v2
			// case on a modern host), so only the warning contract is asserted.
			hasRemedy := false
			for _, w := range info.Warnings {
				if w == HybridRemedy {
					hasRemedy = true
				}
			}
			if tc.wantWarn && !hasRemedy {
				t.Errorf("expected HybridRemedy in Warnings, got %q", info.Warnings)
			}
			if info.KernelVersion == "" {
				t.Error("KernelVersion is empty; uname should always succeed on linux")
			}
		})
	}
}

func TestDetectOnThisHost(t *testing.T) {
	info, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	t.Logf("mode=%s root=%s controllers=%v delegated=%v kill=%v freezer=%v psi=%v cloneinto=%v kernel=%s",
		info.Mode, info.Root, info.Controllers, info.Delegated,
		info.HasKill, info.HasFreezer, info.HasPSI, info.HasCloneInto, info.KernelVersion)
	for _, w := range info.Warnings {
		t.Logf("warning: %s", w)
	}
	if !info.Usable() {
		found := false
		for _, w := range info.Warnings {
			if w == HybridRemedy {
				found = true
			}
		}
		if !found {
			t.Errorf("host is unusable but Warnings lacks the remedy: %q", info.Warnings)
		}
	}
	// clone3 exists on every kernel hull supports (5.3+), so the probe must
	// not report a false negative on a 5.7+ kernel.
	if kernelAtLeast(info.KernelVersion, 5, 7) && !info.HasCloneInto {
		t.Errorf("kernel %s is >= 5.7 but HasCloneInto is false", info.KernelVersion)
	}
}

func TestNewRefusesUnusableHost(t *testing.T) {
	tests := []struct {
		name string
		info Info
	}{
		{"no cgroup2 mount", Info{Mode: ModeLegacy}},
		{"hybrid with no controllers", Info{Mode: ModeHybrid, Root: "/sys/fs/cgroup/unified"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.info, "hull/abc")
			if err == nil {
				t.Fatal("New succeeded on an unusable host; it must refuse")
			}
			if !errors.Is(err, ErrUnsupported) {
				t.Errorf("error does not wrap ErrUnsupported: %v", err)
			}
			if !strings.Contains(err.Error(), HybridRemedy) {
				t.Errorf("error lacks the remedy text: %v", err)
			}
		})
	}
}

func TestNewRejectsBadPaths(t *testing.T) {
	info := Info{Mode: ModeUnified, Root: "/sys/fs/cgroup", Controllers: []string{"cpu", "memory"}}
	for _, p := range []string{"", "/", "hull/../../etc", "hull/./x", "a//b", "hull/x\x00y"} {
		if _, err := New(info, p); err == nil {
			t.Errorf("New(%q) succeeded; a path escape must be rejected", p)
		}
	}
}

func TestSystemUsageUsecGolden(t *testing.T) {
	const golden = `cpu  100 200 300 400 500 600 700 0 0 0
cpu0 50 100 150 200 250 300 350 0 0 0
intr 12345
`
	saved := procStat
	procStat = writeTempFile(t, "stat", golden)
	defer func() { procStat = saved }()

	got, err := SystemUsageUsec()
	if err != nil {
		t.Fatalf("SystemUsageUsec: %v", err)
	}
	// 100+200+300+400+500+600+700 = 2800 jiffies at 100Hz = 28s = 28e6 us.
	const want = 28_000_000
	if got != want {
		t.Errorf("SystemUsageUsec = %d, want %d", got, want)
	}
}

func TestSystemUsageUsecErrors(t *testing.T) {
	tests := []struct{ name, content string }{
		{"no cpu line", "intr 1\nctxt 2\n"},
		{"short cpu line", "cpu 1 2 3\n"},
		{"unparsable", "cpu a b c d e f g\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			saved := procStat
			procStat = writeTempFile(t, "stat", tc.content)
			defer func() { procStat = saved }()
			if _, err := SystemUsageUsec(); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestSystemUsageUsecOnThisHost(t *testing.T) {
	first, err := SystemUsageUsec()
	if err != nil {
		t.Fatalf("SystemUsageUsec: %v", err)
	}
	if first == 0 {
		t.Error("SystemUsageUsec = 0 on a running host")
	}
	time.Sleep(20 * time.Millisecond)
	second, err := SystemUsageUsec()
	if err != nil {
		t.Fatalf("SystemUsageUsec: %v", err)
	}
	if second < first {
		t.Errorf("SystemUsageUsec went backwards: %d then %d", first, second)
	}
}

func TestOnlineCPUsFromFile(t *testing.T) {
	saved := cpuOnline
	cpuOnline = writeTempFile(t, "online", "0-3\n")
	defer func() { cpuOnline = saved }()
	if got := OnlineCPUs(); got != 4 {
		t.Errorf("OnlineCPUs = %d, want 4", got)
	}

	cpuOnline = filepath.Join(t.TempDir(), "does-not-exist")
	if got := OnlineCPUs(); got < 1 {
		t.Errorf("OnlineCPUs fallback = %d, want >= 1", got)
	}
}

// testRoot returns a Manager-capable Info for a real round trip, skipping the
// test when the host cannot support one.
func testRoot(t *testing.T) Info {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	info, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !info.Usable() {
		t.Skipf("host has no usable cgroup v2 controllers (mode=%s root=%q): %s",
			info.Mode, info.Root, HybridRemedy)
	}
	return info
}

func TestManagerRoundTrip(t *testing.T) {
	info := testRoot(t)

	rel := fmt.Sprintf("hull-test/%d", os.Getpid())
	m, err := New(info, rel)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := m.Delete(); err != nil {
			t.Errorf("Delete: %v", err)
		}
		// The intermediate "hull-test" cgroup is left behind on purpose by
		// Delete (it only removes its own directory); clean it up here.
		_ = unix.Rmdir(filepath.Join(info.Root, "hull-test"))
	})
	for _, w := range m.Warnings() {
		t.Logf("warning: %s", w)
	}

	if _, err := os.Stat(m.Path()); err != nil {
		t.Fatalf("cgroup directory was not created: %v", err)
	}
	if m.Rel() != rel {
		t.Errorf("Rel = %q, want %q", m.Rel(), rel)
	}

	fd, err := m.FD()
	if err != nil {
		t.Fatalf("FD: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Errorf("fstat on the cgroup fd: %v", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Errorf("FD is not a directory, mode=%o", st.Mode)
	}
	unix.Close(fd)

	res := types.Resources{
		Memory:            64 << 20,
		MemoryReservation: 32 << 20,
		MemorySwap:        64 << 20, // equal to Memory: swap disabled
		CPUShares:         1024,
		CPUQuota:          50000,
		CPUPeriod:         100000,
		BlkioWeight:       500,
	}
	if err := m.Apply(res); err != nil {
		// Apply is best-effort per knob; a controller missing on this host is
		// reported but must not be silent.
		t.Logf("Apply reported: %v", err)
	}

	readBack := func(name string) string {
		s, err := readCgroupFile(m.Path(), name)
		if err != nil {
			t.Logf("read %s: %v", name, err)
			return ""
		}
		return strings.TrimSpace(s)
	}

	if info.HasController("memory") {
		if got := readBack("memory.max"); got != "67108864" {
			t.Errorf("memory.max = %q, want 67108864", got)
		}
		if got := readBack("memory.low"); got != "33554432" {
			t.Errorf("memory.low = %q, want 33554432", got)
		}
		if got := readBack("memory.swap.max"); got != "0" {
			t.Errorf("memory.swap.max = %q, want 0 (swap disabled)", got)
		}
	}
	if info.HasController("cpu") {
		if got := readBack("cpu.weight"); got != "39" {
			t.Errorf("cpu.weight = %q, want 39", got)
		}
		if got := readBack("cpu.max"); got != "50000 100000" {
			t.Errorf("cpu.max = %q, want \"50000 100000\"", got)
		}
	}
	if info.HasController("pids") {
		if err := m.SetPidsLimit(128); err != nil {
			t.Errorf("SetPidsLimit: %v", err)
		} else if got := readBack("pids.max"); got != "128" {
			t.Errorf("pids.max = %q, want 128", got)
		}
	}
	if info.HasController("io") {
		if got := readBack("io.weight"); got != "" && !strings.Contains(got, "4950") {
			t.Errorf("io.weight = %q, want it to mention 4950", got)
		}
	}
	if info.HasController("memory") {
		if err := m.SetOOMGroup(true); err != nil {
			t.Errorf("SetOOMGroup: %v", err)
		} else if got := readBack("memory.oom.group"); got != "1" {
			t.Errorf("memory.oom.group = %q, want 1", got)
		}
	}

	stat, err := m.Stat()
	if err != nil {
		t.Logf("Stat reported: %v", err)
	}
	if info.HasController("memory") && stat.MemoryLimit != 64<<20 {
		t.Errorf("Stat.MemoryLimit = %d, want %d", stat.MemoryLimit, 64<<20)
	}
	if info.HasPSI && stat.CPUPressureSome10 < 0 {
		t.Errorf("Stat.CPUPressureSome10 = %v, want >= 0", stat.CPUPressureSome10)
	}

	pids, err := m.Procs()
	if err != nil {
		t.Fatalf("Procs: %v", err)
	}
	if len(pids) != 0 {
		t.Errorf("a fresh cgroup has %d procs, want 0", len(pids))
	}

	if info.HasFreezer {
		if err := m.Freeze(); err != nil {
			t.Errorf("Freeze: %v", err)
		}
		frozen, err := m.Frozen()
		if err != nil {
			t.Errorf("Frozen: %v", err)
		} else if !frozen {
			t.Error("Frozen = false after Freeze")
		}
		if err := m.Thaw(); err != nil {
			t.Errorf("Thaw: %v", err)
		}
	}

	if ef, err := m.EventFD(); err != nil {
		t.Logf("EventFD: %v", err)
	} else {
		ef.Close()
	}

	// Load must find the same cgroup.
	loaded, err := Load(info, rel)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Path() != m.Path() {
		t.Errorf("Load path = %q, want %q", loaded.Path(), m.Path())
	}
	if _, err := Load(info, "hull-test/definitely-not-here"); err == nil {
		t.Error("Load of a missing cgroup succeeded, want an error")
	}
}

// fakeRoot builds a directory that looks enough like a cgroup v2 root for the
// Manager's path handling, subtree_control logic, knob writes and stat parsing
// to be exercised on a host whose real hierarchy is the crippled WSL hybrid
// one. It cannot emulate kernel behaviour (a write is just a write), so the
// root-gated tests above remain the authority on real cgroup semantics.
func fakeRoot(t *testing.T, controllers string) (string, Info) {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{
		"cgroup.controllers":     controllers + "\n",
		"cgroup.subtree_control": "",
		"cgroup.procs":           "",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	return root, Info{
		Mode:          ModeUnified,
		Root:          root,
		Controllers:   strings.Fields(controllers),
		HasKill:       true,
		HasFreezer:    true,
		KernelVersion: "6.6.0-test",
	}
}

// seedKnobs creates the interface files the kernel would have materialised in
// a freshly created cgroup.
func seedKnobs(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
}

func TestNewEnablesSubtreeControl(t *testing.T) {
	root, info := fakeRoot(t, "cpu io memory pids cpuset")

	m, err := New(info, "hullctr")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.Path() != filepath.Join(root, "hullctr") {
		t.Errorf("Path = %q, want %q", m.Path(), filepath.Join(root, "hullctr"))
	}
	if fi, err := os.Stat(m.Path()); err != nil || !fi.IsDir() {
		t.Fatalf("cgroup directory not created: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
	if err != nil {
		t.Fatalf("read subtree_control: %v", err)
	}
	for _, c := range []string{"+cpu", "+memory", "+pids", "+io"} {
		if !strings.Contains(string(got), c) {
			t.Errorf("subtree_control = %q, missing %s", got, c)
		}
	}
}

func TestNewSkipsControllersTheKernelLacks(t *testing.T) {
	root, info := fakeRoot(t, "pids")

	m, err := New(info, "hullctr")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
	if err != nil {
		t.Fatalf("read subtree_control: %v", err)
	}
	if strings.Contains(string(got), "+cpu") || strings.Contains(string(got), "+memory") {
		t.Errorf("subtree_control = %q, must not enable controllers the kernel does not list", got)
	}
	if !strings.Contains(string(got), "+pids") {
		t.Errorf("subtree_control = %q, want +pids", got)
	}

	warns := strings.Join(m.Warnings(), "\n")
	for _, c := range []string{"cpu", "memory", "io"} {
		if !strings.Contains(warns, c) {
			t.Errorf("Warnings = %q, want a note about the missing %q controller", warns, c)
		}
	}
}

func TestNewDoesNotDelegateInACgroupWithProcesses(t *testing.T) {
	root, info := fakeRoot(t, "cpu memory pids io")

	// An intermediate cgroup that already holds a process: the kernel's
	// no-internal-process rule forbids enabling controllers there.
	mid := filepath.Join(root, "hull")
	if err := os.Mkdir(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	seedKnobs(t, mid, map[string]string{
		"cgroup.controllers":     "cpu memory pids io\n",
		"cgroup.subtree_control": "",
		"cgroup.procs":           "4242\n",
	})

	m, err := New(info, "hull/abc")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(mid, "cgroup.subtree_control"))
	if err != nil {
		t.Fatalf("read subtree_control: %v", err)
	}
	if strings.TrimSpace(string(got)) != "" {
		t.Errorf("subtree_control of a populated cgroup = %q, want it left untouched", got)
	}
	warns := strings.Join(m.Warnings(), "\n")
	if !strings.Contains(warns, "already contains processes") {
		t.Errorf("Warnings = %q, want an explanation of the skip", warns)
	}
}

func TestApplyWritesEveryKnobAndJoinsFailures(t *testing.T) {
	_, info := fakeRoot(t, "cpu io memory pids cpuset")
	m, err := New(info, "hullctr")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Every knob except cpuset.mems exists, so Apply must write all of them and
	// still report the one it could not.
	seedKnobs(t, m.Path(), map[string]string{
		"cpu.weight":      "",
		"cpu.max":         "",
		"memory.max":      "",
		"memory.low":      "",
		"memory.swap.max": "",
		"io.weight":       "",
		"cpuset.cpus":     "",
	})

	err = m.Apply(types.Resources{
		Memory:            64 << 20,
		MemoryReservation: 32 << 20,
		MemorySwap:        128 << 20,
		CPUShares:         1024,
		NanoCPUs:          1_500_000_000,
		BlkioWeight:       500,
		CpusetCpus:        "0-1",
		CpusetMems:        "0",
	})
	if err == nil {
		t.Fatal("Apply should have reported the missing cpuset.mems knob")
	}
	if !strings.Contains(err.Error(), "cpuset.mems") {
		t.Errorf("error does not name the failing knob: %v", err)
	}

	want := map[string]string{
		"cpu.weight":      "39",
		"cpu.max":         "150000 100000",
		"memory.max":      "67108864",
		"memory.low":      "33554432",
		"memory.swap.max": "67108864", // 128Mi total - 64Mi memory
		"io.weight":       "4950",
		"cpuset.cpus":     "0-1",
	}
	for name, wantVal := range want {
		got, rerr := os.ReadFile(filepath.Join(m.Path(), name))
		if rerr != nil {
			t.Errorf("read %s: %v", name, rerr)
			continue
		}
		if string(got) != wantVal {
			t.Errorf("%s = %q, want %q", name, got, wantVal)
		}
	}
}

func TestApplyReportsInvalidSwapCombination(t *testing.T) {
	_, info := fakeRoot(t, "memory")
	m, err := New(info, "hullctr")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	seedKnobs(t, m.Path(), map[string]string{"memory.max": ""})

	err = m.Apply(types.Resources{Memory: 1 << 30, MemorySwap: 512 << 20})
	if err == nil {
		t.Fatal("Apply accepted a memory-swap smaller than memory")
	}
	if !strings.Contains(err.Error(), "memory-swap") {
		t.Errorf("error does not explain the invalid pair: %v", err)
	}
}

func TestApplyExplainsAMissingController(t *testing.T) {
	// The kernel offers only pids, so a cpu limit cannot be honoured and the
	// error must say so and carry the remedy.
	_, info := fakeRoot(t, "pids")
	m, err := New(info, "hullctr")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = m.Apply(types.Resources{CPUShares: 1024})
	if err == nil {
		t.Fatal("Apply silently accepted a limit it could not write")
	}
	if !strings.Contains(err.Error(), "cpu.weight") || !strings.Contains(err.Error(), HybridRemedy) {
		t.Errorf("error is not actionable: %v", err)
	}
}

func TestStatParsesEveryFile(t *testing.T) {
	_, info := fakeRoot(t, "cpu io memory pids")
	m, err := New(info, "hullctr")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	seedKnobs(t, m.Path(), map[string]string{
		"cpu.stat":        goldenCPUStat,
		"memory.current":  "4194304\n",
		"memory.peak":     "8388608\n",
		"memory.max":      "67108864\n",
		"memory.stat":     goldenMemoryStat,
		"memory.events":   goldenMemoryEvents,
		"pids.current":    "7\n",
		"pids.max":        "max\n",
		"io.stat":         goldenIOStat,
		"cpu.pressure":    goldenPressure,
		"memory.pressure": goldenPressure,
		// io.pressure is deliberately absent, as on a CONFIG_PSI-less kernel.
	})

	st, err := m.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	checks := []struct {
		name      string
		got, want uint64
	}{
		{"CPUUsageUsec", st.CPUUsageUsec, 1234567},
		{"CPUUserUsec", st.CPUUserUsec, 900000},
		{"CPUSystemUsec", st.CPUSystemUsec, 334567},
		{"MemoryCurrent", st.MemoryCurrent, 4194304},
		{"MemoryPeak", st.MemoryPeak, 8388608},
		{"MemoryLimit", st.MemoryLimit, 67108864},
		{"MemoryAnon", st.MemoryAnon, 4194304},
		{"MemoryFile", st.MemoryFile, 8388608},
		{"PidsCurrent", st.PidsCurrent, 7},
		{"PidsLimit", st.PidsLimit, 0}, // "max" means unlimited
		{"IORead", st.IORead, 1536},
		{"IOWrite", st.IOWrite, 2304},
		{"OOMKills", st.OOMKills, 1},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("Stat.%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if st.CPUPressureSome10 != 1.25 || st.MemPressureSome10 != 1.25 {
		t.Errorf("pressure = (%v, %v), want 1.25 each", st.CPUPressureSome10, st.MemPressureSome10)
	}
	if st.IOPressureSome10 != 0 {
		t.Errorf("IOPressureSome10 = %v, want 0 for a missing io.pressure", st.IOPressureSome10)
	}
}

func TestProcsAndLoad(t *testing.T) {
	_, info := fakeRoot(t, "pids")
	m, err := New(info, "hullctr")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	seedKnobs(t, m.Path(), map[string]string{"cgroup.procs": "11\n22\n33\n"})

	pids, err := m.Procs()
	if err != nil {
		t.Fatalf("Procs: %v", err)
	}
	if len(pids) != 3 || pids[0] != 11 || pids[2] != 33 {
		t.Errorf("Procs = %v, want [11 22 33]", pids)
	}

	loaded, err := Load(info, "hullctr")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Path() != m.Path() {
		t.Errorf("Load path = %q, want %q", loaded.Path(), m.Path())
	}
	if _, err := Load(info, "nope"); err == nil {
		t.Error("Load of a missing cgroup succeeded")
	}
	if err := m.AddProcess(0); err == nil {
		t.Error("AddProcess(0) succeeded, want a rejection")
	}
}

func TestFDIsADirectory(t *testing.T) {
	_, info := fakeRoot(t, "pids")
	m, err := New(info, "hullctr")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fd, err := m.FD()
	if err != nil {
		t.Fatalf("FD: %v", err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatalf("fstat: %v", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Errorf("FD mode = %o, want a directory", st.Mode)
	}
}

func TestDeleteRemovesAnEmptyCgroup(t *testing.T) {
	_, info := fakeRoot(t, "pids")
	m, err := New(info, "hullctr")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	seedKnobs(t, m.Path(), map[string]string{"cgroup.kill": "0\n", "cgroup.procs": ""})
	// A real cgroup directory holds no removable entries; strip the fakes so
	// rmdir(2) can succeed.
	for _, n := range []string{"cgroup.kill", "cgroup.procs"} {
		if err := os.Remove(filepath.Join(m.Path(), n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(m.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("directory still present after Delete: %v", err)
	}
	if err := m.Delete(); err != nil {
		t.Errorf("Delete of an already-removed cgroup: %v", err)
	}
}

func TestManagerKillsAndDeletesWithProcess(t *testing.T) {
	info := testRoot(t)

	rel := fmt.Sprintf("hull-test/%d-kill", os.Getpid())
	m, err := New(info, rel)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		_ = m.Delete()
		_ = unix.Rmdir(filepath.Join(info.Root, "hull-test"))
	}()

	cmd, err := os.StartProcess("/bin/sleep", []string{"sleep", "300"}, &os.ProcAttr{})
	if err != nil {
		t.Skipf("cannot start /bin/sleep: %v", err)
	}
	defer func() {
		_ = cmd.Kill()
		_, _ = cmd.Wait()
	}()

	if err := m.AddProcess(cmd.Pid); err != nil {
		t.Fatalf("AddProcess: %v", err)
	}
	pids, err := m.Procs()
	if err != nil {
		t.Fatalf("Procs: %v", err)
	}
	found := false
	for _, p := range pids {
		if p == cmd.Pid {
			found = true
		}
	}
	if !found {
		t.Fatalf("pid %d not in cgroup.procs %v", cmd.Pid, pids)
	}

	if err := m.Delete(); err != nil {
		t.Fatalf("Delete with a live process: %v", err)
	}
	if _, err := os.Stat(m.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cgroup directory still exists after Delete: %v", err)
	}
	// Delete on an already-removed cgroup is a no-op.
	if err := m.Delete(); err != nil {
		t.Errorf("second Delete: %v", err)
	}
}
