package cgroups

import (
	"math"
	"testing"
)

func TestCPUSharesToWeight(t *testing.T) {
	tests := []struct {
		name   string
		shares int64
		want   uint64
	}{
		{"below range clamps to 1", 0, 1},
		{"one clamps to 1", 1, 1},
		{"minimum shares", 2, 1},
		{"docker default 1024", 1024, 39},
		{"512", 512, 20},
		{"2048", 2048, 79},
		{"maximum shares", 262144, 10000},
		{"above range clamps", 1 << 30, 10000},
		{"negative clamps to 1", -5, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CPUSharesToWeight(tc.shares); got != tc.want {
				t.Errorf("CPUSharesToWeight(%d) = %d, want %d", tc.shares, got, tc.want)
			}
		})
	}
}

func TestCPUSharesToWeightStaysInRange(t *testing.T) {
	for _, s := range []int64{2, 3, 100, 1023, 1024, 1025, 65535, 262143, 262144} {
		w := CPUSharesToWeight(s)
		if w < 1 || w > 10000 {
			t.Errorf("CPUSharesToWeight(%d) = %d, outside [1,10000]", s, w)
		}
	}
}

func TestBlkioWeightToIOWeight(t *testing.T) {
	tests := []struct {
		name string
		in   uint16
		want uint64
	}{
		{"minimum", 10, 1},
		{"maximum", 1000, 10000},
		{"middle 500", 500, 4950},
		{"docker default 500", 500, 4950},
		{"below range clamps", 0, 1},
		{"above range clamps", 5000, 10000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := BlkioWeightToIOWeight(tc.in)
			if got != tc.want {
				t.Errorf("BlkioWeightToIOWeight(%d) = %d, want %d", tc.in, got, tc.want)
			}
			if got < 1 || got > 10000 {
				t.Errorf("BlkioWeightToIOWeight(%d) = %d, outside [1,10000]", tc.in, got)
			}
		})
	}
}

func TestSwapMax(t *testing.T) {
	tests := []struct {
		name       string
		memory     int64
		memorySwap int64
		want       string
		wantOK     bool
	}{
		{"unset", 512 << 20, 0, "", false},
		{"unlimited swap", 512 << 20, -1, "max", true},
		{"swap disabled: equal values", 512 << 20, 512 << 20, "0", true},
		{"swap is the difference", 512 << 20, 1 << 30, "536870912", true},
		{"swap without memory limit is invalid", 0, 1 << 30, "", false},
		{"swap smaller than memory is invalid", 1 << 30, 512 << 20, "", false},
		{"other negative values are invalid", 1 << 30, -2, "", false},
		{"unlimited swap without memory", 0, -1, "max", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SwapMax(tc.memory, tc.memorySwap)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("SwapMax(%d, %d) = (%q, %v), want (%q, %v)",
					tc.memory, tc.memorySwap, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestMemoryMax(t *testing.T) {
	tests := []struct {
		name   string
		in     int64
		want   string
		wantOK bool
	}{
		{"unset", 0, "", false},
		{"explicit unlimited", -1, "max", true},
		{"bytes", 1 << 30, "1073741824", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := MemoryMax(tc.in)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("MemoryMax(%d) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestCPUMax(t *testing.T) {
	tests := []struct {
		name     string
		quota    int64
		period   int64
		nanoCPUs int64
		want     string
		wantOK   bool
	}{
		{"nothing set", 0, 0, 0, "", false},
		{"quota with default period", 50000, 0, 0, "50000 100000", true},
		{"quota with explicit period", 25000, 50000, 0, "25000 50000", true},
		{"unlimited quota", -1, 0, 0, "max 100000", true},
		{"period only", 0, 20000, 0, "max 20000", true},
		{"one and a half cpus", 0, 0, 1_500_000_000, "150000 100000", true},
		{"half a cpu", 0, 0, 500_000_000, "50000 100000", true},
		{"nanocpus win over quota", 999, 0, 2_000_000_000, "200000 100000", true},
		{"tiny nanocpus clamp to 1us", 0, 0, 1, "1 100000", true},
		{"nanocpus with custom period", 0, 50000, 1_000_000_000, "50000 50000", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CPUMax(tc.quota, tc.period, tc.nanoCPUs)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("CPUMax(%d, %d, %d) = (%q, %v), want (%q, %v)",
					tc.quota, tc.period, tc.nanoCPUs, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

const goldenCPUStat = `usage_usec 1234567
user_usec 900000
system_usec 334567
nr_periods 42
nr_throttled 3
throttled_usec 12000
`

const goldenMemoryStat = `anon 4194304
file 8388608
kernel_stack 65536
slab 1048576
sock 0
shmem 0
file_mapped 262144
pgfault 1234
pgmajfault 5
`

const goldenMemoryEvents = `low 0
high 0
max 7
oom 2
oom_kill 1
`

const goldenIOStat = `8:0 rbytes=1024 wbytes=2048 rios=10 wios=20 dbytes=0 dios=0
8:16 rbytes=512 wbytes=256 rios=1 wios=2 dbytes=0 dios=0
`

const goldenPressure = `some avg10=1.25 avg60=0.50 avg300=0.10 total=123456
full avg10=0.75 avg60=0.25 avg300=0.05 total=65432
`

func TestParseKeyedUint(t *testing.T) {
	tests := []struct {
		name string
		text string
		want map[string]uint64
	}{
		{
			name: "cpu.stat",
			text: goldenCPUStat,
			want: map[string]uint64{
				"usage_usec": 1234567, "user_usec": 900000, "system_usec": 334567,
				"nr_periods": 42, "nr_throttled": 3, "throttled_usec": 12000,
			},
		},
		{
			name: "memory.events",
			text: goldenMemoryEvents,
			want: map[string]uint64{"low": 0, "high": 0, "max": 7, "oom": 2, "oom_kill": 1},
		},
		{
			name: "garbage lines are skipped",
			text: "good 1\nbad\nalso bad here\nworse notanumber\n",
			want: map[string]uint64{"good": 1},
		},
		{
			name: "empty",
			text: "",
			want: map[string]uint64{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseKeyedUint(tc.text)
			if len(got) != len(tc.want) {
				t.Fatalf("parseKeyedUint() = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("key %q = %d, want %d", k, got[k], v)
				}
			}
		})
	}
}

func TestParseMemoryStatFields(t *testing.T) {
	kv := parseKeyedUint(goldenMemoryStat)
	if kv["anon"] != 4194304 {
		t.Errorf("anon = %d, want 4194304", kv["anon"])
	}
	if kv["file"] != 8388608 {
		t.Errorf("file = %d, want 8388608", kv["file"])
	}
}

func TestParseIOStat(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		wantR, wantW uint64
	}{
		{"two devices are summed", goldenIOStat, 1536, 2304},
		{"empty", "", 0, 0},
		{"no counters", "8:0\n", 0, 0},
		{"unparsable values are skipped", "8:0 rbytes=x wbytes=5\n", 0, 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, w := parseIOStat(tc.text)
			if r != tc.wantR || w != tc.wantW {
				t.Errorf("parseIOStat() = (%d, %d), want (%d, %d)", r, w, tc.wantR, tc.wantW)
			}
		})
	}
}

func TestParsePressureSome10(t *testing.T) {
	tests := []struct {
		name string
		text string
		want float64
	}{
		{"some line", goldenPressure, 1.25},
		{"full only, no some", "full avg10=0.75 avg60=0.25 avg300=0.05 total=1\n", 0},
		{"missing file contents", "", 0},
		{"zeroes", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n", 0},
		{"unparsable", "some avg10=abc\n", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePressureSome10(tc.text)
			if math.Abs(got-tc.want) > 1e-9 {
				t.Errorf("parsePressureSome10() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseLimitFile(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    uint64
		wantErr bool
	}{
		{"max means unlimited", "max\n", 0, false},
		{"bytes", "1073741824\n", 1073741824, false},
		{"empty", "", 0, false},
		{"cpu.max unlimited", "max 100000\n", 0, false},
		{"cpu.max quota", "50000 100000\n", 50000, false},
		{"garbage", "hello\n", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLimitFile(tc.text)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseLimitFile(%q) error = %v, wantErr %v", tc.text, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("parseLimitFile(%q) = %d, want %d", tc.text, got, tc.want)
			}
		})
	}
}

func TestParseUintFile(t *testing.T) {
	if v, err := parseUintFile(" 4096\n"); err != nil || v != 4096 {
		t.Errorf("parseUintFile = (%d, %v), want (4096, nil)", v, err)
	}
	if v, err := parseUintFile(""); err != nil || v != 0 {
		t.Errorf("parseUintFile(empty) = (%d, %v), want (0, nil)", v, err)
	}
	if _, err := parseUintFile("max\n"); err == nil {
		t.Error("parseUintFile(max) should fail; use parseLimitFile for limit files")
	}
}

func TestParsePids(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    []int
		wantErr bool
	}{
		{"three pids", "1\n42\n1234\n", []int{1, 42, 1234}, false},
		{"empty cgroup", "", nil, false},
		{"trailing blanks", "7\n\n\n", []int{7}, false},
		{"garbage", "7\nnope\n", []int{7}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePids(tc.text)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parsePids error = %v, wantErr %v", err, tc.wantErr)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parsePids = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("pid[%d] = %d, want %d", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestCleanRelPath(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"simple", "hull/abc123", "hull/abc123", false},
		{"leading slash is stripped", "/hull/abc", "hull/abc", false},
		{"trailing slash is stripped", "hull/abc/", "hull/abc", false},
		{"single segment", "hull", "hull", false},
		{"empty", "", "", true},
		{"root", "/", "", true},
		{"dotdot escape", "hull/../../etc", "", true},
		{"dot segment", "hull/./abc", "", true},
		{"double slash", "hull//abc", "", true},
		{"nul byte", "hull/a\x00b", "", true},
		{"backslash", "hull/a\\b", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cleanRelPath(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("cleanRelPath(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("cleanRelPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestKernelAtLeast(t *testing.T) {
	tests := []struct {
		release      string
		major, minor int
		want         bool
	}{
		{"5.15.167.4-microsoft-standard-WSL2", 5, 7, true},
		{"5.15.167.4-microsoft-standard-WSL2", 5, 14, true},
		{"5.15.167.4-microsoft-standard-WSL2", 5, 19, false},
		{"5.15.167.4-microsoft-standard-WSL2", 6, 1, false},
		{"6.6.87.2-microsoft-standard-WSL2", 5, 19, true},
		{"6.6.87.2-microsoft-standard-WSL2", 6, 7, false},
		{"6.18.0", 6, 7, true},
		{"4.19.0", 5, 2, false},
		{"garbage", 5, 2, false},
		{"5", 5, 2, false},
	}
	for _, tc := range tests {
		t.Run(tc.release, func(t *testing.T) {
			if got := kernelAtLeast(tc.release, tc.major, tc.minor); got != tc.want {
				t.Errorf("kernelAtLeast(%q, %d, %d) = %v, want %v",
					tc.release, tc.major, tc.minor, got, tc.want)
			}
		})
	}
}

func TestUnescapeMountField(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/sys/fs/cgroup", "/sys/fs/cgroup"},
		{`/mnt/my\040dir`, "/mnt/my dir"},
		{`/a\011b`, "/a\tb"},
		{`/a\134b`, `/a\b`},
		{`/trailing\`, `/trailing\`},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := unescapeMountField(tc.in); got != tc.want {
				t.Errorf("unescapeMountField(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestModeString(t *testing.T) {
	tests := []struct {
		m    Mode
		want string
	}{
		{ModeUnavailable, "unavailable"},
		{ModeLegacy, "legacy"},
		{ModeHybrid, "hybrid"},
		{ModeUnified, "unified"},
		{Mode(99), "unavailable"},
	}
	for _, tc := range tests {
		if got := tc.m.String(); got != tc.want {
			t.Errorf("Mode(%d).String() = %q, want %q", int(tc.m), got, tc.want)
		}
	}
}

func TestInfoHelpers(t *testing.T) {
	i := Info{Mode: ModeUnified, Root: "/sys/fs/cgroup", Controllers: []string{"cpu", "memory", "pids"}}
	if !i.HasController("memory") {
		t.Error("HasController(memory) = false, want true")
	}
	if i.HasController("io") {
		t.Error("HasController(io) = true, want false")
	}
	if !i.Usable() {
		t.Error("Usable() = false, want true")
	}

	hybrid := Info{Mode: ModeHybrid, Root: "/sys/fs/cgroup/unified"}
	if hybrid.Usable() {
		t.Error("a hybrid host with no controllers must not be Usable")
	}
	legacy := Info{Mode: ModeLegacy}
	if legacy.Usable() {
		t.Error("a legacy host must not be Usable")
	}
}

func TestHybridRemedyText(t *testing.T) {
	const want = "cgroup v2 controllers are not available. " +
		"Run 'wsl --update' (WSL 2.5.1+ removes cgroup v1), " +
		"or add 'kernelCommandLine = cgroup_no_v1=all' under [wsl2] in %USERPROFILE%\\.wslconfig and " +
		"run 'wsl --shutdown'."
	if HybridRemedy != want {
		t.Errorf("HybridRemedy = %q, want %q", HybridRemedy, want)
	}
}

func TestCountCPUList(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"0-7\n", 8},
		{"0\n", 1},
		{"0,2-3\n", 3},
		{"0-3,8-11\n", 8},
		{"", 0},
		{"garbage", 0},
		{"5-1", 0},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := countCPUList(tc.in); got != tc.want {
				t.Errorf("countCPUList(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
