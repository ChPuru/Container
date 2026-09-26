package bundle

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ChPuru/hull/internal/oci/runtimespec"
	"github.com/ChPuru/hull/internal/seccompprof"
	"github.com/ChPuru/hull/internal/types"
)

func TestNormalizeCapability(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "NET_ADMIN", want: "CAP_NET_ADMIN"},
		{in: "net_admin", want: "CAP_NET_ADMIN"},
		{in: "CAP_NET_ADMIN", want: "CAP_NET_ADMIN"},
		{in: "  sys_admin  ", want: "CAP_SYS_ADMIN"},
		{in: "all", want: "ALL"},
		{in: "CAP_NOT_A_THING", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := NormalizeCapability(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveCapabilities(t *testing.T) {
	base := runtimespec.DefaultCapabilities()

	tests := []struct {
		name       string
		add        []string
		drop       []string
		privileged bool
		wantHas    []string
		wantNot    []string
		wantLen    int
		wantErr    bool
	}{
		{name: "defaults", wantHas: []string{"CAP_CHOWN", "CAP_NET_RAW"}, wantNot: []string{"CAP_SYS_ADMIN"}, wantLen: len(base)},
		{name: "add one", add: []string{"NET_ADMIN"}, wantHas: []string{"CAP_NET_ADMIN"}, wantLen: len(base) + 1},
		{name: "drop one", drop: []string{"NET_RAW"}, wantNot: []string{"CAP_NET_RAW"}, wantLen: len(base) - 1},
		{name: "drop all", drop: []string{"ALL"}, wantLen: 0},
		{name: "drop all then add back", drop: []string{"ALL"}, add: []string{"CHOWN"}, wantHas: []string{"CAP_CHOWN"}, wantLen: 1},
		{name: "add all", add: []string{"ALL"}, wantLen: len(AllCapabilities())},
		{name: "privileged gets everything", privileged: true, wantLen: len(AllCapabilities())},
		{name: "unknown cap in add", add: []string{"CAP_BOGUS"}, wantErr: true},
		{name: "unknown cap in drop", drop: []string{"CAP_BOGUS"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveCapabilities(base, tt.add, tt.drop, tt.privileged)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Fatalf("got %d caps, want %d: %v", len(got), tt.wantLen, got)
			}
			for _, w := range tt.wantHas {
				if !contains(got, w) {
					t.Errorf("%v is missing %s", got, w)
				}
			}
			for _, w := range tt.wantNot {
				if contains(got, w) {
					t.Errorf("%v should not contain %s", got, w)
				}
			}
		})
	}
}

func TestResolveCapabilitiesIsDeterministic(t *testing.T) {
	base := runtimespec.DefaultCapabilities()
	a, err := ResolveCapabilities(base, []string{"NET_ADMIN", "SYS_PTRACE"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ResolveCapabilities(base, []string{"SYS_PTRACE", "NET_ADMIN"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("capability order must not depend on flag order:\n%v\n%v", a, b)
	}
}

func TestIsNamespacedSysctl(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"net.ipv4.ip_forward", true},
		{"net.core.somaxconn", true},
		{"fs.mqueue.msg_max", true},
		{"kernel.shmmax", true},
		{"kernel.shm_rmid_forced", true},
		{"kernel.msgmnb", true},
		{"kernel.sem", true},
		{"kernel.domainname", true},
		{"kernel.hostname", true},
		{"kernel.pid_max", false},
		{"vm.swappiness", false},
		{"fs.file-max", false},
		{"net.", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := IsNamespacedSysctl(tt.key); got != tt.want {
				t.Fatalf("IsNamespacedSysctl(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestSysctlValidationInGenerate(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)

	t.Run("namespaced sysctl is accepted", func(t *testing.T) {
		c := newTestContainer()
		c.HostConfig.Sysctls = map[string]string{"net.ipv4.ip_forward": "1"}
		spec, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if spec.Linux.Sysctl["net.ipv4.ip_forward"] != "1" {
			t.Fatalf("sysctl missing: %v", spec.Linux.Sysctl)
		}
	})

	t.Run("host-wide sysctl is rejected", func(t *testing.T) {
		c := newTestContainer()
		c.HostConfig.Sysctls = map[string]string{"vm.swappiness": "10"}
		_, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
		if err == nil || !strings.Contains(err.Error(), "not namespaced") {
			t.Fatalf("want a clear rejection, got %v", err)
		}
	})

	t.Run("net sysctl with host networking is rejected", func(t *testing.T) {
		c := newTestContainer()
		c.HostConfig.NetworkMode = "host"
		c.HostConfig.Sysctls = map[string]string{"net.ipv4.ip_forward": "1"}
		_, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
		if err == nil || !strings.Contains(err.Error(), "network mode") {
			t.Fatalf("want a rejection naming the network mode, got %v", err)
		}
	})
}

func TestParseSecurityOpt(t *testing.T) {
	tests := []struct {
		name    string
		opts    []string
		wantNNP bool
		wantUnc bool
		wantErr bool
	}{
		{name: "default", wantNNP: true},
		{name: "explicit no-new-privileges", opts: []string{"no-new-privileges"}, wantNNP: true},
		{name: "no-new-privileges=false", opts: []string{"no-new-privileges=false"}, wantNNP: false},
		{name: "colon separator", opts: []string{"no-new-privileges:false"}, wantNNP: false},
		{name: "seccomp unconfined", opts: []string{"seccomp=unconfined"}, wantNNP: true, wantUnc: true},
		{name: "apparmor unconfined", opts: []string{"apparmor=unconfined"}, wantNNP: true},
		{name: "bad boolean", opts: []string{"no-new-privileges=maybe"}, wantErr: true},
		{name: "unknown option", opts: []string{"cheese=brie"}, wantErr: true},
		{name: "seccomp with no value", opts: []string{"seccomp"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSecurityOpt(tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.noNewPrivileges != tt.wantNNP {
				t.Errorf("noNewPrivileges = %v, want %v", got.noNewPrivileges, tt.wantNNP)
			}
			if got.seccompUnconfine != tt.wantUnc {
				t.Errorf("seccompUnconfine = %v, want %v", got.seccompUnconfine, tt.wantUnc)
			}
		})
	}
}

// TestPrivilegedVsUnprivileged pins down every difference between the two
// modes in one place, because this is the pair of specs that decides whether
// the engine is a sandbox or a shell script with extra steps.
func TestPrivilegedVsUnprivileged(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	opts := Options{RootFS: root, CgroupsPath: "hull/x", Features: Features{CgroupV2: true, Seccomp: true, KernelMajor: 5, KernelMinor: 15}}

	plain, _, err := Generate(newTestContainer(), newTestImage(), opts)
	if err != nil {
		t.Fatalf("unprivileged Generate: %v", err)
	}

	pc := newTestContainer()
	pc.HostConfig.Privileged = true
	priv, _, err := Generate(pc, newTestImage(), opts)
	if err != nil {
		t.Fatalf("privileged Generate: %v", err)
	}

	// Capabilities.
	if len(plain.Process.Capabilities.Bounding) != len(runtimespec.DefaultCapabilities()) {
		t.Errorf("unprivileged caps = %d, want the OCI default set", len(plain.Process.Capabilities.Bounding))
	}
	if len(priv.Process.Capabilities.Bounding) != len(AllCapabilities()) {
		t.Errorf("privileged caps = %d, want all %d", len(priv.Process.Capabilities.Bounding), len(AllCapabilities()))
	}
	if len(plain.Process.Capabilities.Ambient) != 0 || len(plain.Process.Capabilities.Inheritable) != 0 {
		t.Error("inheritable and ambient sets must stay empty")
	}

	// Seccomp.
	if plain.Linux.Seccomp == nil {
		t.Error("an unprivileged container must have a seccomp filter")
	} else if plain.Linux.Seccomp.DefaultAction != runtimespec.ActErrno {
		t.Errorf("default seccomp action = %q, want a default-deny", plain.Linux.Seccomp.DefaultAction)
	}
	if priv.Linux.Seccomp != nil {
		t.Error("a privileged container must have no seccomp filter")
	}

	// Masked and read-only paths.
	if len(plain.Linux.MaskedPaths) != len(MaskedPaths()) || len(plain.Linux.ReadonlyPaths) != len(ReadonlyPaths()) {
		t.Error("unprivileged masked/readonly path lists are wrong")
	}
	if len(priv.Linux.MaskedPaths) != 0 || len(priv.Linux.ReadonlyPaths) != 0 {
		t.Error("a privileged container must have no masked or read-only paths")
	}

	// Device cgroup.
	if got := plain.Linux.Resources.Devices; len(got) == 0 || got[0].Allow {
		t.Error("the device rules must start with a deny-all")
	}
	if got := priv.Linux.Resources.Devices; len(got) != 1 || !got[0].Allow || got[0].Access != "rwm" {
		t.Errorf("privileged device rules = %+v, want a single allow-all", got)
	}

	// /sys and /proc writability, and /dev.
	mountByDest := func(s *runtimespec.Spec, dest string) runtimespec.Mount {
		for _, m := range s.Mounts {
			if m.Destination == dest {
				return m
			}
		}
		return runtimespec.Mount{}
	}
	if !contains(mountByDest(plain, "/sys").Options, "ro") {
		t.Error("unprivileged /sys must be read-only")
	}
	if contains(mountByDest(priv, "/sys").Options, "ro") {
		t.Error("privileged /sys must be writable")
	}
	if !contains(mountByDest(priv, "/sys/fs/cgroup").Options, "rw") {
		t.Error("privileged /sys/fs/cgroup must be writable")
	}
	if got := mountByDest(priv, "/dev"); got.Type != "bind" || got.Source != "/dev" {
		t.Errorf("privileged /dev = %+v, want a recursive bind of the host /dev", got)
	}
	if got := mountByDest(plain, "/dev"); got.Type != "tmpfs" {
		t.Errorf("unprivileged /dev = %+v, want a tmpfs", got)
	}

	// AppArmor.
	if priv.Process.ApparmorProfile != "unconfined" {
		t.Errorf("privileged apparmorProfile = %q, want unconfined", priv.Process.ApparmorProfile)
	}
	if plain.Process.ApparmorProfile != "" {
		t.Errorf("unprivileged apparmorProfile = %q, want empty", plain.Process.ApparmorProfile)
	}

	// no_new_privs is on in both: privileged is about capabilities, not about
	// letting a setuid binary silently gain more than it was given.
	if !plain.Process.NoNewPrivileges || !priv.Process.NoNewPrivileges {
		t.Error("noNewPrivileges must default to true in both modes")
	}
}

func TestSeccompUnconfinedWarnsAndDisables(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	c.HostConfig.SecurityOpt = []string{"seccomp=unconfined"}

	spec, warnings, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if spec.Linux.Seccomp != nil {
		t.Error("seccomp=unconfined must remove the filter")
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "seccomp is disabled") {
		t.Fatalf("disabling seccomp must be announced, got %v", warnings)
	}
}

func TestNoNewPrivilegesFalseWithSeccompIsRejected(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	c.HostConfig.SecurityOpt = []string{"no-new-privileges=false"}

	_, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
	if err == nil || !strings.Contains(err.Error(), "no-new-privileges") {
		t.Fatalf("want a rejection explaining the interaction, got %v", err)
	}
}

func TestMissingSeccompSupportWarns(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	spec, warnings, err := Generate(newTestContainer(), newTestImage(), Options{
		RootFS:   root,
		Features: Features{CgroupV2: true, Seccomp: false},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if spec.Linux.Seccomp != nil {
		t.Error("no kernel seccomp means no filter")
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "no seccomp") {
		t.Fatalf("missing seccomp support must be announced, got %v", warnings)
	}
}

func TestSeccompProfileGatesOnCapabilities(t *testing.T) {
	withoutAdmin := seccompprof.ForCapabilities(runtimespec.DefaultCapabilities(), false)
	withAdmin := seccompprof.ForCapabilities(append(runtimespec.DefaultCapabilities(), "CAP_SYS_ADMIN"), false)

	allowed := func(p *runtimespec.LinuxSeccomp, name string) bool {
		for _, s := range p.Syscalls {
			if s.Action != runtimespec.ActAllow {
				continue
			}
			if contains(s.Names, name) {
				return true
			}
		}
		return false
	}
	if allowed(withoutAdmin, "mount") {
		t.Error("mount must not be allowed without CAP_SYS_ADMIN")
	}
	if !allowed(withAdmin, "mount") {
		t.Error("mount must be allowed with CAP_SYS_ADMIN")
	}
	if !allowed(withoutAdmin, "openat2") {
		t.Error("openat2 belongs in the base allowlist")
	}
	if withoutAdmin.DefaultAction == runtimespec.ActAllow {
		t.Error("the default profile must deny, not allow")
	}
	if seccompprof.ForCapabilities(nil, true) != nil {
		t.Error("a privileged container gets no profile")
	}
}

// TestSeccompProfileHookIsHonoured proves Options.SeccompProfile replaces the
// default provider, which is how a caller pins a custom profile.
func TestSeccompProfileHookIsHonoured(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	marker := &runtimespec.LinuxSeccomp{DefaultAction: runtimespec.ActKillProcess}
	var gotCaps []string
	var gotPriv bool

	spec, _, err := Generate(newTestContainer(), newTestImage(), Options{
		RootFS:   root,
		Features: Features{CgroupV2: true, Seccomp: true},
		SeccompProfile: func(caps []string, privileged bool) *runtimespec.LinuxSeccomp {
			gotCaps, gotPriv = caps, privileged
			return marker
		},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if spec.Linux.Seccomp != marker {
		t.Fatalf("seccomp = %+v, want the hook's profile", spec.Linux.Seccomp)
	}
	if gotPriv {
		t.Error("privileged flag should be false")
	}
	if !contains(gotCaps, "CAP_CHOWN") {
		t.Errorf("the hook must receive the resolved capability set, got %v", gotCaps)
	}
}

func TestReadonlyRootfs(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	c.HostConfig.ReadonlyRootfs = true

	spec, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !spec.Root.Readonly {
		t.Fatal("ReadonlyRootfs must set root.readonly")
	}
}

func TestUnknownCapabilityIsRejected(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	c.HostConfig.CapAdd = []string{"CAP_TIME_TRAVEL"}

	_, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
	if err == nil || !strings.Contains(err.Error(), "unknown capability") {
		t.Fatalf("want a clear rejection, got %v", err)
	}
}

func TestResourceTranslation(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	limit := int64(100)

	c := newTestContainer()
	c.HostConfig.Resources = types.Resources{
		Memory:            512 << 20,
		MemoryReservation: 256 << 20,
		MemorySwap:        1 << 30,
		CPUShares:         512,
		NanoCPUs:          1_500_000_000, // 1.5 cpus
		CpusetCpus:        "0-3",
		BlkioWeight:       500,
	}
	c.HostConfig.PidsLimit = &limit

	spec, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	r := spec.Linux.Resources
	if r.Memory == nil || *r.Memory.Limit != 512<<20 || *r.Memory.Reservation != 256<<20 || *r.Memory.Swap != 1<<30 {
		t.Errorf("memory = %+v", r.Memory)
	}
	if r.CPU == nil || *r.CPU.Shares != 512 || *r.CPU.Period != DefaultCPUPeriod || *r.CPU.Quota != 150000 || r.CPU.Cpus != "0-3" {
		t.Errorf("cpu = %+v", r.CPU)
	}
	if r.Pids == nil || r.Pids.Limit != 100 {
		t.Errorf("pids = %+v", r.Pids)
	}
	if r.BlockIO == nil || *r.BlockIO.Weight != 500 {
		t.Errorf("blkio = %+v", r.BlockIO)
	}
}

func TestCpusAndCpuQuotaConflict(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	c.HostConfig.Resources = types.Resources{NanoCPUs: 1e9, CPUQuota: 50000}

	_, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want a conflict error, got %v", err)
	}
}

func TestHybridCgroupsWarn(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	c.HostConfig.Resources = types.Resources{Memory: 256 << 20}

	_, warnings, err := Generate(c, newTestImage(), Options{
		RootFS:   root,
		Features: Features{CgroupV2: false, Seccomp: true, KernelMajor: 5, KernelMinor: 15},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "cgroup v2") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limits on a hybrid-cgroup kernel must warn, got %v", warnings)
	}
}

func TestDefaultDeviceRules(t *testing.T) {
	rules := defaultDeviceRules()
	if rules[0].Allow || rules[0].Access != "rwm" {
		t.Fatalf("rule 0 = %+v, want deny-all", rules[0])
	}
	want := [][2]int64{{1, 3}, {1, 5}, {1, 7}, {1, 8}, {1, 9}, {5, 0}, {5, 1}, {5, 2}}
	for _, w := range want {
		found := false
		for _, r := range rules[1:] {
			if r.Allow && r.Type == "c" && r.Major != nil && *r.Major == w[0] && r.Minor != nil && *r.Minor == w[1] {
				found = true
			}
		}
		if !found {
			t.Errorf("no allow rule for char device %d:%d", w[0], w[1])
		}
	}
	last := rules[len(rules)-1]
	if !last.Allow || last.Type != "c" || last.Major == nil || *last.Major != 136 || last.Minor != nil {
		t.Errorf("last rule = %+v, want the open pts range c 136:*", last)
	}
}
