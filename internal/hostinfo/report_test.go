package hostinfo

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the golden report under testdata")

// wslHybridReport is the fixture that mirrors the exact host hull targets:
// WSL 2.4.13, kernel 5.15.167.4, hybrid cgroups with no delegated v2
// controllers, no PSI, Docker Desktop sharing the VM with a FORWARD DROP
// policy, and ip_forward off.
func wslHybridReport() *Report {
	r := &Report{
		Generated: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC),
		Kernel: KernelInfo{
			Release:      "5.15.167.4-microsoft-standard-WSL2",
			Version:      "#1 SMP Tue Nov 5 00:21:55 UTC 2024",
			Arch:         "x86_64",
			Major:        5,
			Minor:        15,
			Config:       map[string]string{"CONFIG_SECCOMP": "y", "CONFIG_BRIDGE": "y", "CONFIG_VETH": "y"},
			ConfigSource: "/proc/config.gz",
		},
		WSL: WSLInfo{
			IsWSL: true, Distro: "ubuntu", Interop: true, SystemdPID1: true,
			MirroredNet: false, MirroredNetKnown: true, SharedMntWSL: true,
			WSLVersionHint: wslVersionHint(5, 15, "5.15.167.4-microsoft-standard-WSL2"),
		},
		Cgroups: CgroupInfo{
			Mode:          "hybrid",
			UnifiedRoot:   "/sys/fs/cgroup/unified",
			V1Controllers: []string{"blkio", "cpu", "memory", "pids"},
			NSDelegate:    true,
			CgroupKill:    true,
			FreezeV2:      true,
			PSI:           false,
			Warnings:      []string{"cgroup2 is mounted at /sys/fs/cgroup/unified but cgroup.controllers is empty"},
		},
		Overlay: OverlayInfo{
			Supported: true, Redirect: "N", Metacopy: "N", Index: "N", Xino: "N",
			UserXattr: true, MountTested: true, MountOK: true,
		},
		Namespaces: NamespaceInfo{
			User: true, PID: true, Net: true, Mount: true, IPC: true, UTS: true, Cgroup: true,
			MaxUserNamespaces: 31286, UnprivilegedUsernsClone: true,
			SubuidRange: "100000:65536", SubgidRange: "100000:65536",
		},
		Security: SecurityInfo{
			Seccomp:        true,
			SeccompActions: []string{"kill_process", "kill_thread", "trap", "errno", "user_notif", "trace", "log", "allow"},
			Landlock:       1,
			Capabilities:   DecodeCapMask(0x1ffffffffff),
		},
		Storage: StorageInfo{
			DataRoot: "/var/lib/hull", Probed: "/var/lib", FSType: "ext4",
			FreeBytes: 240697508 * 4096, TotalBytes: 263940717 * 4096, SupportsDType: true,
		},
		Network: NetworkInfo{
			IPForward: false, BridgeModule: true, VethModule: true, NftablesModule: true,
			NftBinary: "/usr/sbin/nft", IptablesBinary: "/usr/sbin/iptables", IptablesNAT: true,
			DockerPresent: true, DockerForwardPolicyDrop: true,
			ForwardPolicy: "DROP", ForwardPolicySource: "iptables",
			ExistingSubnets: []string{"172.17.0.0/16", "172.22.80.0/20"},
			WSLNATSubnet:    "172.22.80.0/20",
		},
	}
	r.Checks = buildChecks(r)
	return r
}

// healthyReport is a modern 6.6 WSL kernel with everything hull wants.
func healthyReport() *Report {
	r := &Report{
		Generated: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC),
		Kernel: KernelInfo{
			Release: "6.6.87.2-microsoft-standard-WSL2", Arch: "x86_64", Major: 6, Minor: 6,
			ConfigSource: "/proc/config.gz",
		},
		WSL: WSLInfo{IsWSL: true, Distro: "alpine", SystemdPID1: false, SharedMntWSL: true},
		Cgroups: CgroupInfo{
			Mode: "unified", UnifiedRoot: "/sys/fs/cgroup",
			Controllers:    []string{"cpuset", "cpu", "io", "memory", "pids"},
			SubtreeControl: []string{"cpu", "memory", "pids"},
			Delegated:      true, NSDelegate: true, CgroupKill: true, FreezeV2: true, PSI: true,
		},
		Overlay: OverlayInfo{
			Supported: true, Redirect: "N", Metacopy: "N", Index: "N",
			UserXattr: true, IdmappedLayers: true, MountTested: true, MountOK: true,
		},
		Namespaces: NamespaceInfo{
			User: true, PID: true, Net: true, Mount: true, IPC: true, UTS: true, Cgroup: true, Time: true,
			MaxUserNamespaces: 31286, UnprivilegedUsernsClone: true,
			SubuidRange: "100000:65536", SubgidRange: "100000:65536",
		},
		Security: SecurityInfo{
			Seccomp: true, SeccompActions: []string{"kill_process", "errno", "allow"},
			Landlock: 4, Capabilities: DecodeCapMask(0x1ffffffffff),
		},
		Storage: StorageInfo{
			DataRoot: "/var/lib/hull", Probed: "/var/lib/hull", FSType: "ext4",
			FreeBytes: 100 << 30, TotalBytes: 500 << 30, SupportsDType: true,
		},
		Network: NetworkInfo{
			IPForward: true, BridgeModule: true, VethModule: true, NftablesModule: true,
			NftBinary: "/usr/sbin/nft", IptablesBinary: "/usr/sbin/iptables", IptablesNAT: true,
			ForwardPolicy: "ACCEPT", ForwardPolicySource: "iptables",
			WSLNATSubnet: "172.22.80.0/20",
		},
	}
	r.Checks = buildChecks(r)
	return r
}

// brokenReport is the worst realistic case: a pre-5.10 kernel, no overlay, no
// user namespaces, no seccomp, a data root on a Windows share, and no
// netfilter tooling at all.
func brokenReport() *Report {
	r := &Report{
		Generated: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC),
		Kernel:    KernelInfo{Release: "4.19.128-generic", Arch: "x86_64", Major: 4, Minor: 19},
		Cgroups:   CgroupInfo{Mode: "legacy", V1Controllers: []string{"cpu", "memory"}},
		Overlay:   OverlayInfo{Supported: false},
		Namespaces: NamespaceInfo{
			PID: true, Net: true, Mount: true, MaxUserNamespaces: 0,
			UsernsCloneSysctl: true, UnprivilegedUsernsClone: false,
		},
		Security: SecurityInfo{Seccomp: false},
		Storage: StorageInfo{
			DataRoot: "/mnt/c/hull", Probed: "/mnt/c", FSType: "9p", OnDrvFs: true,
			FreeBytes: 1 << 30, TotalBytes: 900 << 30,
		},
		Network: NetworkInfo{IPForward: false},
	}
	r.Checks = buildChecks(r)
	return r
}

func TestFailedAndWarned(t *testing.T) {
	tests := []struct {
		name       string
		report     *Report
		wantFailed bool
		wantWarned bool
	}{
		{"wsl 5.15 hybrid host", wslHybridReport(), true, true},
		{"modern 6.6 host", healthyReport(), false, false},
		{"hopeless host", brokenReport(), true, true},
		{"empty report", &Report{}, false, false},
		{
			name:       "skip alone is neither",
			report:     &Report{Checks: []Check{{Name: "x", Status: StatusSkip}}},
			wantFailed: false, wantWarned: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.report.Failed(); got != tt.wantFailed {
				t.Errorf("Failed() = %v, want %v (checks: %s)", got, tt.wantFailed, summarise(tt.report))
			}
			if got := tt.report.Warned(); got != tt.wantWarned {
				t.Errorf("Warned() = %v, want %v (checks: %s)", got, tt.wantWarned, summarise(tt.report))
			}
		})
	}
}

func summarise(r *Report) string {
	var b strings.Builder
	for _, c := range r.Checks {
		if c.Status == StatusOK {
			continue
		}
		b.WriteString(string(c.Status) + ":" + c.Name + " ")
	}
	return b.String()
}

func TestHealthyReportHasNoFailures(t *testing.T) {
	r := healthyReport()
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			t.Errorf("unexpected failure on a healthy host: %s — %s", c.Name, c.Detail)
		}
	}
	if r.Failed() {
		t.Error("healthy report must not be Failed()")
	}
}

func TestChecksCoverTheRequiredSurface(t *testing.T) {
	want := []string{
		"kernel version", "cgroup v2 delegated", "overlayfs", "user namespaces",
		"seccomp", "data root filesystem", "free space", "ip_forward",
		"bridge + veth", "netfilter backend", "FORWARD policy",
		"pressure stall info", "landlock", "d_type support",
	}
	for _, name := range []string{"hybrid", "healthy", "broken"} {
		var r *Report
		switch name {
		case "hybrid":
			r = wslHybridReport()
		case "healthy":
			r = healthyReport()
		default:
			r = brokenReport()
		}
		t.Run(name, func(t *testing.T) {
			have := map[string]bool{}
			for _, c := range r.Checks {
				have[c.Name] = true
			}
			for _, w := range want {
				if !have[w] {
					t.Errorf("missing check %q", w)
				}
			}
		})
	}
}

func TestCheckStatusesForKnownHosts(t *testing.T) {
	tests := []struct {
		name   string
		report *Report
		check  string
		want   Status
		remedy string // substring the remedy must contain; "" means must be empty
	}{
		{"hybrid cgroups fail", wslHybridReport(), "cgroup v2 delegated", StatusFail, "cgroup_no_v1=all"},
		{"5.15 kernel warns", wslHybridReport(), "kernel version", StatusWarn, "wsl --update"},
		{"no psi warns", wslHybridReport(), "pressure stall info", StatusWarn, "pressure metrics need a 6.x WSL kernel"},
		{"docker drop warns", wslHybridReport(), "FORWARD policy", StatusWarn, "hull inserts an explicit ACCEPT for its bridge"},
		{"ip_forward off fails", wslHybridReport(), "ip_forward", StatusFail, "net.ipv4.ip_forward=1"},
		{"overlay ok", wslHybridReport(), "overlayfs", StatusOK, ""},
		{"6.6 kernel ok", healthyReport(), "kernel version", StatusOK, ""},
		{"unified cgroups ok", healthyReport(), "cgroup v2 delegated", StatusOK, ""},
		{"psi ok", healthyReport(), "pressure stall info", StatusOK, ""},
		{"accept policy ok", healthyReport(), "FORWARD policy", StatusOK, ""},
		{"4.19 kernel fails", brokenReport(), "kernel version", StatusFail, "5.10"},
		{"no overlay fails", brokenReport(), "overlayfs", StatusFail, "modprobe overlay"},
		{"no userns fails", brokenReport(), "user namespaces", StatusFail, "CONFIG_USER_NS"},
		{"no seccomp fails", brokenReport(), "seccomp", StatusFail, "CONFIG_SECCOMP_FILTER"},
		{"drvfs data root fails", brokenReport(), "data root filesystem", StatusFail, "roughly 7x slower for writes and 60x slower for metadata"},
		{"tiny disk fails", brokenReport(), "free space", StatusFail, "5.0 GiB"},
		{"no netfilter fails", brokenReport(), "netfilter backend", StatusFail, "apt install nftables"},
		{"no policy readable skips", brokenReport(), "FORWARD policy", StatusSkip, "Install nftables or iptables"},
		{"no bridge fails", brokenReport(), "bridge + veth", StatusFail, "CONFIG_BRIDGE=y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got *Check
			for i := range tt.report.Checks {
				if tt.report.Checks[i].Name == tt.check {
					got = &tt.report.Checks[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("no check named %q", tt.check)
			}
			if got.Status != tt.want {
				t.Errorf("status = %q, want %q (detail: %s)", got.Status, tt.want, got.Detail)
			}
			if tt.remedy == "" {
				if got.Remedy != "" {
					t.Errorf("remedy should be empty for an ok check, got %q", got.Remedy)
				}
				return
			}
			if !strings.Contains(got.Remedy, tt.remedy) {
				t.Errorf("remedy %q does not contain %q", got.Remedy, tt.remedy)
			}
		})
	}
}

func TestEveryNonOKCheckHasARemedy(t *testing.T) {
	for _, r := range []*Report{wslHybridReport(), healthyReport(), brokenReport()} {
		for _, c := range r.Checks {
			if c.Status == StatusOK {
				continue
			}
			if strings.TrimSpace(c.Remedy) == "" {
				t.Errorf("check %q is %q but carries no remedy", c.Name, c.Status)
			}
			if strings.TrimSpace(c.Detail) == "" {
				t.Errorf("check %q carries no detail", c.Name)
			}
		}
	}
}

func TestChecksAreSortedWorstFirst(t *testing.T) {
	for _, r := range []*Report{wslHybridReport(), healthyReport(), brokenReport()} {
		prev := 4
		for _, c := range r.Checks {
			sev := c.Status.severity()
			if sev > prev {
				t.Fatalf("check %q (%s) appears after a less severe one", c.Name, c.Status)
			}
			prev = sev
		}
	}
}

// ---------- text rendering ----------

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

func TestReportTextIsDeterministic(t *testing.T) {
	r := wslHybridReport()
	var a, b bytes.Buffer
	if err := r.Text(&a, false); err != nil {
		t.Fatalf("Text: %v", err)
	}
	if err := r.Text(&b, false); err != nil {
		t.Fatalf("Text: %v", err)
	}
	if a.String() != b.String() {
		t.Fatal("two renders of the same report differ")
	}
	// Re-deriving the checks must not change the output either.
	r.Checks = buildChecks(r)
	var c bytes.Buffer
	if err := r.Text(&c, false); err != nil {
		t.Fatalf("Text: %v", err)
	}
	if c.String() != a.String() {
		t.Fatal("rebuilding checks changed the rendered report")
	}
}

func TestReportTextColorStripsToPlain(t *testing.T) {
	for _, r := range []*Report{wslHybridReport(), healthyReport(), brokenReport()} {
		var plain, colored bytes.Buffer
		if err := r.Text(&plain, false); err != nil {
			t.Fatalf("Text: %v", err)
		}
		if err := r.Text(&colored, true); err != nil {
			t.Fatalf("Text: %v", err)
		}
		if !strings.Contains(colored.String(), "\x1b[") {
			t.Fatal("color output carries no ANSI escapes")
		}
		if got := ansiRE.ReplaceAllString(colored.String(), ""); got != plain.String() {
			t.Errorf("stripped color output differs from plain output:\n--- stripped ---\n%s\n--- plain ---\n%s", got, plain.String())
		}
	}
}

// sectionRowRE matches "  <key><padding><value>" and captures the value so the
// test can assert every value starts in the same column.
var sectionRowRE = regexp.MustCompile(`^ {2}(\S(?:.*\S)?) {2,}(\S.*)$`)

// checkRowRE matches "  [status]<pad><name><pad><detail>".
var checkRowRE = regexp.MustCompile(`^ {2}(\[[a-z]+\]) +(\S(?:.*\S)?) {2,}(\S.*)$`)

func TestReportTextIsAligned(t *testing.T) {
	for _, r := range []*Report{wslHybridReport(), healthyReport(), brokenReport()} {
		var buf bytes.Buffer
		if err := r.Text(&buf, false); err != nil {
			t.Fatalf("Text: %v", err)
		}

		inChecks := false
		sectionValueCol, checkNameCol, checkDetailCol := -1, -1, -1
		sectionRows, checkRows := 0, 0

		for _, line := range strings.Split(buf.String(), "\n") {
			if line == "Checks" {
				inChecks = true
				continue
			}
			// Remedy continuations are deeply indented; skip them.
			if strings.HasPrefix(line, strings.Repeat(" ", 10)) {
				continue
			}
			if inChecks {
				m := checkRowRE.FindStringSubmatchIndex(line)
				if m == nil {
					continue
				}
				checkRows++
				nameCol, detailCol := m[4], m[6]
				if checkNameCol == -1 {
					checkNameCol, checkDetailCol = nameCol, detailCol
					continue
				}
				if nameCol != checkNameCol {
					t.Errorf("check name column %d, want %d: %q", nameCol, checkNameCol, line)
				}
				if detailCol != checkDetailCol {
					t.Errorf("check detail column %d, want %d: %q", detailCol, checkDetailCol, line)
				}
				continue
			}
			m := sectionRowRE.FindStringSubmatchIndex(line)
			if m == nil {
				continue
			}
			sectionRows++
			if sectionValueCol == -1 {
				sectionValueCol = m[4]
				continue
			}
			if m[4] != sectionValueCol {
				t.Errorf("section value column %d, want %d: %q", m[4], sectionValueCol, line)
			}
		}

		if sectionRows < 40 {
			t.Fatalf("only matched %d section rows; the layout changed shape", sectionRows)
		}
		if checkRows < 12 {
			t.Fatalf("only matched %d check rows; the layout changed shape", checkRows)
		}
	}
}

func TestReportTextGolden(t *testing.T) {
	r := wslHybridReport()
	var buf bytes.Buffer
	if err := r.Text(&buf, false); err != nil {
		t.Fatalf("Text: %v", err)
	}
	path := filepath.Join("testdata", "wsl515.golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatalf("writing golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden (re-run with -update): %v", err)
	}
	if got := buf.String(); got != string(want) {
		t.Errorf("rendered report differs from testdata/wsl515.golden\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestReportTextSummaryLine(t *testing.T) {
	r := wslHybridReport()
	var buf bytes.Buffer
	if err := r.Text(&buf, false); err != nil {
		t.Fatalf("Text: %v", err)
	}
	counts := r.Counts()
	total := counts[StatusOK] + counts[StatusWarn] + counts[StatusFail] + counts[StatusSkip]
	if total != len(r.Checks) {
		t.Fatalf("counts sum to %d, want %d", total, len(r.Checks))
	}
	last := strings.TrimSpace(buf.String())
	last = last[strings.LastIndex(last, "\n")+1:]
	if !strings.HasSuffix(last, "skip") || !strings.Contains(last, "fail") {
		t.Errorf("summary line = %q", last)
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	r := wslHybridReport()
	var buf bytes.Buffer
	if err := r.JSON(&buf); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Checks) != len(r.Checks) {
		t.Fatalf("got %d checks after round trip, want %d", len(back.Checks), len(r.Checks))
	}
	if back.Kernel.Release != r.Kernel.Release {
		t.Errorf("kernel release = %q, want %q", back.Kernel.Release, r.Kernel.Release)
	}
	if back.Failed() != r.Failed() || back.Warned() != r.Warned() {
		t.Error("verdicts did not survive the round trip")
	}
	if !back.Generated.Equal(r.Generated) {
		t.Errorf("generated = %v, want %v", back.Generated, r.Generated)
	}
	if !strings.Contains(buf.String(), `"status": "fail"`) {
		t.Error("JSON should carry the status strings verbatim")
	}
}

func TestMissingControllers(t *testing.T) {
	tests := []struct {
		name string
		have []string
		want []string
	}{
		{"empty hybrid host", nil, []string{"cpu", "memory", "pids"}},
		{"full v2", []string{"cpuset", "cpu", "io", "memory", "pids"}, nil},
		{"partial", []string{"cpu", "io"}, []string{"memory", "pids"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CgroupInfo{Controllers: tt.have}.MissingControllers()
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{5 << 30, "5.0 GiB"},
		{20 << 30, "20.0 GiB"},
		{1 << 40, "1.0 TiB"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := humanBytes(tt.in); got != tt.want {
				t.Errorf("humanBytes(%d) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestWrapText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		n    int
		want []string
	}{
		{"empty", "", 10, nil},
		{"whitespace only", "   \n\t", 10, nil},
		{"fits", "short remedy", 40, []string{"short remedy"}},
		{"wraps on word boundary", "aaa bbb ccc ddd", 7, []string{"aaa bbb", "ccc ddd"}},
		{"long word is never split", "supercalifragilistic x", 5, []string{"supercalifragilistic", "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapText(tt.in, tt.n)
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStatusSeverityOrder(t *testing.T) {
	tests := []struct {
		a, b Status
	}{
		{StatusFail, StatusWarn},
		{StatusWarn, StatusSkip},
		{StatusSkip, StatusOK},
	}
	for _, tt := range tests {
		t.Run(string(tt.a)+" over "+string(tt.b), func(t *testing.T) {
			if tt.a.severity() <= tt.b.severity() {
				t.Errorf("%s should outrank %s", tt.a, tt.b)
			}
		})
	}
}
