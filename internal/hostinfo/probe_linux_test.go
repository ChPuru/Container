//go:build linux

package hostinfo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeOnThisHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	r, err := Probe(ctx)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	tests := []struct {
		name string
		ok   func() bool
		why  string
	}{
		{"kernel release is populated", func() bool { return r.Kernel.Release != "" }, "uname returned no release"},
		{"kernel major parsed", func() bool { return r.Kernel.Major > 0 }, "release did not parse"},
		{"arch is populated", func() bool { return r.Kernel.Arch != "" }, "uname returned no machine"},
		{"generated is recent", func() bool { return time.Since(r.Generated) < time.Minute }, "timestamp is stale"},
		{"checks were produced", func() bool { return len(r.Checks) >= 12 }, "too few checks"},
		{"storage data root set", func() bool { return r.Storage.DataRoot != "" }, "no data root"},
		{"cgroup mode known", func() bool { return r.Cgroups.Mode != "" }, "cgroup mode is empty"},
		{"namespaces probed", func() bool { return r.Namespaces.MaxUserNamespaces != 0 || !r.Namespaces.User }, "userns probe is inconsistent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.ok() {
				t.Errorf("%s", tt.why)
			}
		})
	}

	for _, c := range r.Checks {
		if c.Status != StatusOK && strings.TrimSpace(c.Remedy) == "" {
			t.Errorf("live check %q is %q with no remedy", c.Name, c.Status)
		}
	}

	// The rendered report must not blow up on real data.
	if err := r.Text(&nopWriter{}, false); err != nil {
		t.Fatalf("Text: %v", err)
	}
	if err := r.JSON(&nopWriter{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestProbeHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Probe(ctx); err == nil {
		t.Fatal("Probe must refuse a cancelled context")
	}
}

func TestProbeHonoursHullDataRoot(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HULL_DATA_ROOT", dir)

	mounts, err := readMounts()
	if err != nil {
		t.Fatalf("readMounts: %v", err)
	}
	st := probeStorage(mounts)

	if st.DataRoot != dir {
		t.Errorf("DataRoot = %q, want %q", st.DataRoot, dir)
	}
	if st.Probed != dir {
		t.Errorf("Probed = %q, want %q (the dir exists, so no walk up)", st.Probed, dir)
	}
	if st.TotalBytes == 0 {
		t.Error("statfs reported a zero-sized filesystem")
	}
	if st.FSType == "" {
		t.Error("no filesystem type identified")
	}
}

func TestNearestExisting(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"exists", dir, dir},
		{"one missing level", filepath.Join(dir, "nope"), dir},
		{"many missing levels", filepath.Join(dir, "a", "b", "c"), dir},
		{"root always exists", "/definitely/not/here/at/all", "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nearestExisting(tt.in); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProbeDType(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name  string
		setup func(t *testing.T) string
		want  bool
	}{
		{
			name:  "empty dir still answers",
			setup: func(t *testing.T) string { return t.TempDir() },
			want:  true,
		},
		{
			name: "dir with a file",
			setup: func(t *testing.T) string {
				d := filepath.Join(dir, "withfile")
				if err := os.Mkdir(d, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(d, "f"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
				return d
			},
			want: true,
		},
		{
			name:  "nonexistent dir",
			setup: func(t *testing.T) string { return filepath.Join(dir, "missing") },
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := probeDType(tt.setup(t)); got != tt.want {
				t.Errorf("probeDType = %v, want %v (tmpdir fs must support d_type)", got, tt.want)
			}
		})
	}
}

func TestProbeKernelMatchesProcOSRelease(t *testing.T) {
	k, err := probeKernel()
	if err != nil {
		t.Fatalf("probeKernel: %v", err)
	}
	want, err := readTrimmed("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Skipf("no /proc/sys/kernel/osrelease: %v", err)
	}
	if k.Release != want {
		t.Errorf("uname release %q != /proc/sys/kernel/osrelease %q", k.Release, want)
	}
	if k.ConfigSource == "" {
		t.Error("ConfigSource must always explain where the config came from, or why it is missing")
	}
}

func TestProbeCgroupsAgainstGoldenMounts(t *testing.T) {
	mounts, err := ParseMounts(strings.NewReader(goldenMounts))
	if err != nil {
		t.Fatalf("ParseMounts: %v", err)
	}
	cg := probeCgroups(KernelInfo{Major: 5, Minor: 15}, mounts)

	if cg.Mode != "hybrid" {
		t.Errorf("Mode = %q, want hybrid", cg.Mode)
	}
	if cg.UnifiedRoot != "/sys/fs/cgroup/unified" {
		t.Errorf("UnifiedRoot = %q", cg.UnifiedRoot)
	}
	if !cg.NSDelegate {
		t.Error("nsdelegate option was not detected")
	}
	for _, want := range []string{"cpuset", "memory", "pids", "name=systemd"} {
		if !containsStr(cg.V1Controllers, want) {
			t.Errorf("v1 controllers %v missing %q", cg.V1Controllers, want)
		}
	}
	// This golden host's /sys/fs/cgroup/unified does not exist on the test
	// machine's real filesystem, so no controllers can be read: the honest
	// result is "not delegated".
	if cg.Delegated {
		t.Error("a hybrid host with unreadable cgroup.controllers must not report delegation")
	}
	if c := cgroupCheck(cg); c.Status != StatusFail {
		t.Errorf("cgroupCheck status = %q, want fail", c.Status)
	}
}

func TestProbeOverlayReportsHonestly(t *testing.T) {
	o := probeOverlay(context.Background(), KernelInfo{Major: 5, Minor: 15})
	if !o.Supported {
		t.Skip("this kernel has no overlayfs")
	}
	if o.IdmappedLayers {
		t.Error("kernel 5.15 must not claim idmapped overlay layers")
	}
	if o.LowerdirPlus {
		t.Error("kernel 5.15 must not claim lowerdir+ support")
	}
	if !o.UserXattr {
		t.Error("kernel 5.15 supports the userxattr mount option")
	}
	if os.Geteuid() != 0 {
		if o.MountTested {
			t.Error("a non-root probe must not claim it test-mounted overlay")
		}
		return
	}
	if !o.MountTested {
		t.Fatal("running as root, the probe must test a real overlay mount")
	}
	if !o.MountOK {
		t.Errorf("live overlay mount failed: %s", o.MountError)
	}
}

func TestTestOverlayMountNeedsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if err := testOverlayMount(context.Background()); err != nil {
		t.Fatalf("testOverlayMount: %v", err)
	}
}

func TestLandlockABIIsPlausible(t *testing.T) {
	v := landlockABI()
	if v < 0 || v > 16 {
		t.Fatalf("landlockABI() = %d, which is not a plausible ABI version", v)
	}
}

func TestProbeSecurityNoNewPrivs(t *testing.T) {
	s := probeSecurity(KernelInfo{})
	if len(s.Capabilities) == 0 && os.Geteuid() == 0 {
		t.Error("root should have a non-empty capability bounding set")
	}
	if s.Seccomp && len(s.SeccompActions) == 0 {
		t.Log("seccomp is compiled in but actions_avail is unreadable; the check warns")
	}
}

func TestLookPathLinuxOnlyRejectsWindowsInterop(t *testing.T) {
	// /mnt/c/.../docker.exe is reachable through WSL interop but cannot touch
	// the Linux netfilter tables, so it must never be selected.
	if got := lookPathLinuxOnly("this-binary-does-not-exist-hull"); got != "" {
		t.Errorf("got %q for a nonexistent binary", got)
	}
}

func TestRunToolTimesOutCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runTool(ctx, "/bin/true"); err == nil {
		t.Fatal("runTool must fail on a cancelled context")
	}
}
