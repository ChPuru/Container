package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
	"github.com/rahuldhali/hull/internal/types"
)

// newTestContainer is a plausible `docker run -d --name web alpine` record with
// nothing exotic switched on, so each test can turn on exactly one thing.
func newTestContainer() *types.Container {
	return &types.Container{
		ID:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Name:     "web",
		Created:  time.Unix(1700000000, 0).UTC(),
		Image:    "sha256:deadbeef",
		ImageRef: "alpine:3.20",
		Config: types.ContainerConfig{
			Hostname: "web",
		},
		HostConfig: types.HostConfig{
			NetworkMode: "bridge",
			LogConfig:   types.LogConfig{Type: "json-file"},
		},
	}
}

// newTestImage is a minimal alpine-shaped image config.
func newTestImage() *types.Image {
	return &types.Image{
		ID:           "sha256:deadbeef",
		Architecture: "amd64",
		OS:           "linux",
		Config: types.ImageConfig{
			Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
			Cmd: []string{"/bin/sh"},
		},
	}
}

func testFeatures() Features {
	return Features{CgroupV2: true, Seccomp: true, KernelMajor: 5, KernelMinor: 15}
}

// ---------- golden config.json ----------

// TestGoldenSpec compares a complete generated spec field by field against the
// config.json hull is contracted to produce for a representative container. It
// is deliberately explicit rather than a blob comparison, so a failure names
// the field that changed.
func TestGoldenSpec(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	hostDir := t.TempDir()

	c := newTestContainer()
	c.Config.User = "app"
	c.Config.Tty = true
	c.Config.WorkingDir = "/srv"
	c.Config.Env = []string{"LANG=C.UTF-8"}
	c.Config.Cmd = []string{"nginx", "-g", "daemon off;"}
	c.HostConfig.Binds = []string{hostDir + ":/srv:ro"}
	c.HostConfig.CapAdd = []string{"NET_ADMIN"}
	c.HostConfig.CapDrop = []string{"MKNOD"}
	c.HostConfig.Sysctls = map[string]string{"net.core.somaxconn": "1024"}
	c.HostConfig.Ulimits = []types.Ulimit{{Name: "nproc", Soft: 4096, Hard: 8192}}
	c.HostConfig.ShmSize = 64 << 20

	img := newTestImage()
	img.Config.Env = append(img.Config.Env, "LANG=POSIX")

	spec, warnings, err := Generate(c, img, Options{
		RootFS:      root,
		BundleDir:   "/var/lib/hull/containers/abc",
		CgroupsPath: "hull/abc",
		Features:    testFeatures(),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	// --- top level ---
	if spec.Version != runtimespec.Version {
		t.Errorf("ociVersion = %q, want %q", spec.Version, runtimespec.Version)
	}
	if spec.Hostname != "web" {
		t.Errorf("hostname = %q, want web", spec.Hostname)
	}
	if spec.Root.Path != root || spec.Root.Readonly {
		t.Errorf("root = %+v", spec.Root)
	}
	if spec.Hooks != nil {
		t.Error("hooks must be empty: hull does networking from the daemon")
	}
	if spec.Annotations[AnnotationContainerID] != c.ID || spec.Annotations[AnnotationContainerName] != "web" {
		t.Errorf("annotations = %v", spec.Annotations)
	}
	if _, ok := spec.Annotations[AnnotationNoPivot]; ok {
		t.Error("no-pivot annotation must be absent unless requested")
	}

	// --- process ---
	p := spec.Process
	if !p.Terminal {
		t.Error("terminal must follow Config.Tty")
	}
	if want := []string{"nginx", "-g", "daemon off;"}; !reflect.DeepEqual(p.Args, want) {
		t.Errorf("args = %q, want %q", p.Args, want)
	}
	if p.Cwd != "/srv" {
		t.Errorf("cwd = %q, want /srv", p.Cwd)
	}
	wantEnv := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
		"HOSTNAME=web",
		"TERM=xterm",
		"HOME=/home/app",
	}
	if !reflect.DeepEqual(p.Env, wantEnv) {
		t.Errorf("env =\n%q\nwant\n%q", p.Env, wantEnv)
	}
	if p.User.UID != 1000 || p.User.GID != 1000 {
		t.Errorf("user = %d:%d, want 1000:1000", p.User.UID, p.User.GID)
	}
	if p.User.Umask == nil || *p.User.Umask != 0o022 {
		t.Errorf("umask = %v, want 0022", p.User.Umask)
	}
	if want := []uint32{10, 999}; !reflect.DeepEqual(p.User.AdditionalGids, want) {
		t.Errorf("additionalGids = %v, want %v", p.User.AdditionalGids, want)
	}
	if !p.NoNewPrivileges {
		t.Error("noNewPrivileges must default to true")
	}
	if !contains(p.Capabilities.Bounding, "CAP_NET_ADMIN") {
		t.Error("--cap-add NET_ADMIN did not take effect")
	}
	if contains(p.Capabilities.Bounding, "CAP_MKNOD") {
		t.Error("--cap-drop MKNOD did not take effect")
	}
	wantRlimits := []runtimespec.POSIXRlimit{
		{Type: "RLIMIT_NOFILE", Soft: DefaultNofile, Hard: DefaultNofile},
		{Type: "RLIMIT_NPROC", Soft: 4096, Hard: 8192},
	}
	if !reflect.DeepEqual(p.Rlimits, wantRlimits) {
		t.Errorf("rlimits = %+v, want %+v", p.Rlimits, wantRlimits)
	}

	// --- mounts ---
	wantMounts := []struct {
		dest string
		typ  string
		src  string
	}{
		{"/proc", "proc", "proc"},
		{"/dev", "tmpfs", "tmpfs"},
		{"/sys", "sysfs", "sysfs"},
		{"/srv", "bind", hostDir},
		{"/dev/pts", "devpts", "devpts"},
		{"/dev/shm", "tmpfs", "shm"},
		{"/dev/mqueue", "mqueue", "mqueue"},
		{"/sys/fs/cgroup", "cgroup", "cgroup"},
	}
	if len(spec.Mounts) != len(wantMounts) {
		t.Fatalf("got %d mounts, want %d: %+v", len(spec.Mounts), len(wantMounts), spec.Mounts)
	}
	for i, w := range wantMounts {
		got := spec.Mounts[i]
		if got.Destination != w.dest || got.Type != w.typ || got.Source != w.src {
			t.Errorf("mounts[%d] = %s %s %s, want %s %s %s", i, got.Destination, got.Type, got.Source, w.dest, w.typ, w.src)
		}
	}
	if !contains(spec.Mounts[3].Options, "ro") || !contains(spec.Mounts[3].Options, "rbind") {
		t.Errorf("/srv options = %v, want a read-only rbind", spec.Mounts[3].Options)
	}
	if !contains(spec.Mounts[5].Options, "size=65536k") {
		t.Errorf("/dev/shm options = %v, want the default 64MiB", spec.Mounts[5].Options)
	}
	for _, o := range []string{"newinstance", "ptmxmode=0666", "mode=0620", "gid=5"} {
		if !contains(spec.Mounts[4].Options, o) {
			t.Errorf("/dev/pts options %v missing %q", spec.Mounts[4].Options, o)
		}
	}

	// --- linux ---
	l := spec.Linux
	if l.CgroupsPath != "hull/abc" {
		t.Errorf("cgroupsPath = %q", l.CgroupsPath)
	}
	if l.RootfsPropagation != "rprivate" {
		t.Errorf("rootfsPropagation = %q, want rprivate", l.RootfsPropagation)
	}
	wantNS := []runtimespec.LinuxNamespaceType{
		runtimespec.PIDNamespace,
		runtimespec.IPCNamespace,
		runtimespec.UTSNamespace,
		runtimespec.MountNamespace,
		runtimespec.NetworkNamespace,
		runtimespec.CgroupNamespace,
	}
	if len(l.Namespaces) != len(wantNS) {
		t.Fatalf("namespaces = %+v, want %v", l.Namespaces, wantNS)
	}
	for i, w := range wantNS {
		if l.Namespaces[i].Type != w || l.Namespaces[i].Path != "" {
			t.Errorf("namespaces[%d] = %+v, want %s", i, l.Namespaces[i], w)
		}
	}
	if !reflect.DeepEqual(l.MaskedPaths, MaskedPaths()) {
		t.Errorf("maskedPaths = %v", l.MaskedPaths)
	}
	if !reflect.DeepEqual(l.ReadonlyPaths, ReadonlyPaths()) {
		t.Errorf("readonlyPaths = %v", l.ReadonlyPaths)
	}
	if l.Sysctl["net.core.somaxconn"] != "1024" {
		t.Errorf("sysctl = %v", l.Sysctl)
	}
	if l.Seccomp == nil || l.Seccomp.DefaultAction != runtimespec.ActErrno {
		t.Errorf("seccomp = %+v, want a default-deny profile", l.Seccomp)
	}
	if len(l.UIDMappings) != 0 || len(l.GIDMappings) != 0 {
		t.Error("no user namespace was requested, so there must be no id mappings")
	}
	if !reflect.DeepEqual(l.Resources.Devices, defaultDeviceRules()) {
		t.Errorf("device rules = %+v", l.Resources.Devices)
	}

	// The spec must survive a JSON round trip unchanged, since that is how the
	// runtime will read it back.
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back runtimespec.Spec
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(spec, &back) {
		t.Error("the spec does not survive a JSON round trip unchanged")
	}
}

// ---------- namespaces ----------

func TestNamespaces(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)

	tests := []struct {
		name     string
		netMode  string
		pid      int
		userNS   *UserNS
		kernel   [2]int
		wantHas  []runtimespec.LinuxNamespaceType
		wantNot  []runtimespec.LinuxNamespaceType
		wantPath string
		wantErr  bool
	}{
		{
			name:    "bridge",
			netMode: "bridge",
			kernel:  [2]int{5, 15},
			wantHas: []runtimespec.LinuxNamespaceType{"pid", "ipc", "uts", "mount", "network", "cgroup"},
			wantNot: []runtimespec.LinuxNamespaceType{"user"},
		},
		{
			name:    "host networking drops the network namespace",
			netMode: "host",
			kernel:  [2]int{5, 15},
			wantHas: []runtimespec.LinuxNamespaceType{"pid", "ipc", "uts", "mount", "cgroup"},
			wantNot: []runtimespec.LinuxNamespaceType{"network"},
		},
		{
			name:     "container network mode joins by pid",
			netMode:  "container:abcdef",
			pid:      4242,
			kernel:   [2]int{5, 15},
			wantHas:  []runtimespec.LinuxNamespaceType{"network"},
			wantPath: "/proc/4242/ns/net",
		},
		{
			name:    "container network mode without a pid is an error",
			netMode: "container:abcdef",
			kernel:  [2]int{5, 15},
			wantErr: true,
		},
		{
			name:    "an ancient kernel gets no cgroup namespace",
			netMode: "bridge",
			kernel:  [2]int{4, 4},
			wantNot: []runtimespec.LinuxNamespaceType{"cgroup"},
		},
		{
			name:    "user namespace when mappings are given",
			netMode: "bridge",
			kernel:  [2]int{5, 15},
			userNS: &UserNS{
				UIDMappings: []runtimespec.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}},
				GIDMappings: []runtimespec.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}},
			},
			wantHas: []runtimespec.LinuxNamespaceType{"user"},
		},
		{
			name:    "user namespace with an empty mapping is rejected",
			netMode: "bridge",
			kernel:  [2]int{5, 15},
			userNS:  &UserNS{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestContainer()
			c.HostConfig.NetworkMode = tt.netMode
			spec, _, err := Generate(c, newTestImage(), Options{
				RootFS:           root,
				SharedNetworkPID: tt.pid,
				UserNS:           tt.userNS,
				Features:         Features{CgroupV2: true, Seccomp: true, KernelMajor: tt.kernel[0], KernelMinor: tt.kernel[1]},
			})
			if tt.wantErr {
				if err == nil {
					t.Fatal("want an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			have := make(map[runtimespec.LinuxNamespaceType]string, len(spec.Linux.Namespaces))
			for _, ns := range spec.Linux.Namespaces {
				have[ns.Type] = ns.Path
			}
			for _, w := range tt.wantHas {
				if _, ok := have[w]; !ok {
					t.Errorf("namespace %s is missing: %+v", w, spec.Linux.Namespaces)
				}
			}
			for _, w := range tt.wantNot {
				if _, ok := have[w]; ok {
					t.Errorf("namespace %s should be absent: %+v", w, spec.Linux.Namespaces)
				}
			}
			if tt.wantPath != "" && have["network"] != tt.wantPath {
				t.Errorf("network ns path = %q, want %q", have["network"], tt.wantPath)
			}
			if tt.userNS != nil {
				if !reflect.DeepEqual(spec.Linux.UIDMappings, tt.userNS.UIDMappings) {
					t.Errorf("uidMappings = %+v", spec.Linux.UIDMappings)
				}
			}
		})
	}
}

// ---------- user namespace and idmapped binds ----------

func TestUserNSBindMappings(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	hostDir := t.TempDir()
	uns := &UserNS{
		UIDMappings: []runtimespec.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}},
		GIDMappings: []runtimespec.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}},
	}

	t.Run("idmapped kernel annotates the bind", func(t *testing.T) {
		c := newTestContainer()
		c.HostConfig.Binds = []string{hostDir + ":/data"}
		spec, warnings, err := Generate(c, newTestImage(), Options{
			RootFS:   root,
			UserNS:   uns,
			Features: Features{CgroupV2: true, Seccomp: true, IdmappedMounts: true, KernelMajor: 6, KernelMinor: 6},
		})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if len(warnings) != 0 {
			t.Fatalf("unexpected warnings: %v", warnings)
		}
		for _, m := range spec.Mounts {
			if m.Destination != "/data" {
				continue
			}
			if !reflect.DeepEqual(m.UIDMappings, uns.UIDMappings) || !reflect.DeepEqual(m.GIDMappings, uns.GIDMappings) {
				t.Fatalf("/data has no id mappings: %+v", m)
			}
			return
		}
		t.Fatal("/data is missing")
	})

	t.Run("kernel without idmapped mounts warns instead", func(t *testing.T) {
		c := newTestContainer()
		c.HostConfig.Binds = []string{hostDir + ":/data"}
		spec, warnings, err := Generate(c, newTestImage(), Options{
			RootFS:   root,
			UserNS:   uns,
			Features: Features{CgroupV2: true, Seccomp: true, IdmappedMounts: false, KernelMajor: 5, KernelMinor: 15},
		})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		found := false
		for _, w := range warnings {
			if strings.Contains(w, "/data") && strings.Contains(w, "kernel 5.15") {
				found = true
			}
		}
		if !found {
			t.Fatalf("want an ownership caveat naming /data, got %v", warnings)
		}
		for _, m := range spec.Mounts {
			if m.Destination == "/data" && (len(m.UIDMappings) != 0 || len(m.GIDMappings) != 0) {
				t.Fatal("mappings must not be claimed on a kernel that cannot apply them")
			}
		}
	})
}

// ---------- init ----------

func TestInitInjection(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	initBin := filepath.Join(t.TempDir(), "hull-init")
	if err := os.WriteFile(initBin, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := newTestContainer()
	c.HostConfig.Init = true
	spec, _, err := Generate(c, newTestImage(), Options{
		RootFS:   root,
		Init:     true,
		InitPath: initBin,
		Features: testFeatures(),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want := []string{InitTarget, "--", "/bin/sh"}
	if !reflect.DeepEqual(spec.Process.Args, want) {
		t.Fatalf("args = %q, want %q", spec.Process.Args, want)
	}
	for _, m := range spec.Mounts {
		if m.Destination != InitTarget {
			continue
		}
		if m.Source != initBin || m.Type != "bind" || !contains(m.Options, "ro") {
			t.Fatalf("%s = %+v, want a read-only bind of the init binary", InitTarget, m)
		}
		return
	}
	t.Fatalf("%s is not mounted", InitTarget)
}

func TestInitWithoutAPathIsRejected(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	_, _, err := Generate(newTestContainer(), newTestImage(), Options{RootFS: root, Init: true, Features: testFeatures()})
	if err == nil || !strings.Contains(err.Error(), "InitPath") {
		t.Fatalf("want a clear error about the init path, got %v", err)
	}
}

func TestNoPivotAnnotation(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	spec, _, err := Generate(newTestContainer(), newTestImage(), Options{RootFS: root, NoPivot: true, Features: testFeatures()})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if spec.Annotations[AnnotationNoPivot] != "true" {
		t.Fatalf("annotations = %v, want the no-pivot marker", spec.Annotations)
	}
}

// ---------- error paths ----------

func TestGenerateErrors(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)

	t.Run("no rootfs", func(t *testing.T) {
		if _, _, err := Generate(newTestContainer(), newTestImage(), Options{}); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("nil container", func(t *testing.T) {
		if _, _, err := Generate(nil, newTestImage(), Options{RootFS: root}); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("nil image", func(t *testing.T) {
		if _, _, err := Generate(newTestContainer(), nil, Options{RootFS: root}); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("no command", func(t *testing.T) {
		img := newTestImage()
		img.Config.Cmd = nil
		_, _, err := Generate(newTestContainer(), img, Options{RootFS: root, Features: testFeatures()})
		if err == nil || !strings.Contains(err.Error(), "no command specified") {
			t.Fatalf("want ErrNoCommand, got %v", err)
		}
	})
	t.Run("relative working directory", func(t *testing.T) {
		c := newTestContainer()
		c.Config.WorkingDir = "srv"
		_, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: testFeatures()})
		if err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("want an absolute-path error, got %v", err)
		}
	})
}

func TestHostnameFallsBackToTheShortID(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	c.Config.Hostname = ""
	spec, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: testFeatures()})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if spec.Hostname != c.ID[:12] {
		t.Fatalf("hostname = %q, want %q", spec.Hostname, c.ID[:12])
	}
	if !contains(spec.Process.Env, "HOSTNAME="+c.ID[:12]) {
		t.Fatalf("HOSTNAME env is out of step with the hostname: %v", spec.Process.Env)
	}
}

// ---------- Write / Read ----------

func TestWriteAndRead(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	dir := t.TempDir()

	spec, _, err := Generate(newTestContainer(), newTestImage(), Options{RootFS: root, BundleDir: dir, Features: testFeatures()})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := Write(spec, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	p := filepath.Join(dir, ConfigName)
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("config.json mode = %o, want 600", got)
		}
	}

	back, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !reflect.DeepEqual(spec, back) {
		t.Error("the spec did not survive Write/Read unchanged")
	}

	if err := Write(nil, dir); err == nil {
		t.Error("Write(nil) must fail")
	}
	if _, err := Read(filepath.Join(dir, "nope")); err == nil {
		t.Error("Read of a missing bundle must fail")
	}

	// A corrupted bundle must be rejected, not half-loaded.
	if err := os.WriteFile(p, []byte(`{"ociVersion":"1.2.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil {
		t.Error("Read of an incomplete spec must fail validation")
	}
}

// ---------- exec ----------

func TestGenerateExec(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	c.RootFS = root
	spec, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: testFeatures()})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	t.Run("inherits the container process", func(t *testing.T) {
		p, err := GenerateExec(c, spec, []string{"sh", "-c", "id"}, ExecOptions{})
		if err != nil {
			t.Fatalf("GenerateExec: %v", err)
		}
		if !reflect.DeepEqual(p.Args, []string{"sh", "-c", "id"}) {
			t.Errorf("args = %q", p.Args)
		}
		if p.Cwd != spec.Process.Cwd {
			t.Errorf("cwd = %q, want the container's %q", p.Cwd, spec.Process.Cwd)
		}
		if !reflect.DeepEqual(p.Env, spec.Process.Env) {
			t.Errorf("env = %q, want the container's", p.Env)
		}
		if p.User.UID != spec.Process.User.UID {
			t.Errorf("user = %d, want the container's %d", p.User.UID, spec.Process.User.UID)
		}
		if !p.NoNewPrivileges {
			t.Error("noNewPrivileges must be inherited")
		}
		if p.Terminal {
			t.Error("terminal must follow ExecOptions, not the container")
		}
	})

	t.Run("overrides apply", func(t *testing.T) {
		p, err := GenerateExec(c, spec, []string{"env"}, ExecOptions{
			User:       "app",
			WorkingDir: "/tmp",
			Env:        []string{"EXTRA=1", "PATH=/only/here"},
			Tty:        true,
		})
		if err != nil {
			t.Fatalf("GenerateExec: %v", err)
		}
		if p.User.UID != 1000 || p.User.GID != 1000 {
			t.Errorf("user = %d:%d, want 1000:1000", p.User.UID, p.User.GID)
		}
		if p.Cwd != "/tmp" {
			t.Errorf("cwd = %q", p.Cwd)
		}
		if !contains(p.Env, "EXTRA=1") || !contains(p.Env, "PATH=/only/here") {
			t.Errorf("env = %q", p.Env)
		}
		if !contains(p.Env, "HOME=/home/app") {
			t.Errorf("exec --user must bring its HOME: %q", p.Env)
		}
		if !p.Terminal || !contains(p.Env, "TERM=xterm") {
			t.Errorf("a tty exec needs TERM: %q", p.Env)
		}
	})

	t.Run("privileged exec gets every capability", func(t *testing.T) {
		p, err := GenerateExec(c, spec, []string{"sh"}, ExecOptions{Privileged: true})
		if err != nil {
			t.Fatalf("GenerateExec: %v", err)
		}
		if len(p.Capabilities.Bounding) != len(AllCapabilities()) {
			t.Errorf("caps = %d, want all", len(p.Capabilities.Bounding))
		}
		if p.ApparmorProfile != "unconfined" {
			t.Errorf("apparmorProfile = %q", p.ApparmorProfile)
		}
	})

	t.Run("cap-add beyond the bounding set is rejected", func(t *testing.T) {
		_, err := GenerateExec(c, spec, []string{"sh"}, ExecOptions{CapAdd: []string{"SYS_ADMIN"}})
		if err == nil || !strings.Contains(err.Error(), "bounding set") {
			t.Fatalf("want a bounding-set error, got %v", err)
		}
	})

	t.Run("cap-add inside the bounding set is accepted", func(t *testing.T) {
		if _, err := GenerateExec(c, spec, []string{"sh"}, ExecOptions{CapAdd: []string{"CHOWN"}}); err != nil {
			t.Fatalf("GenerateExec: %v", err)
		}
	})

	t.Run("errors", func(t *testing.T) {
		if _, err := GenerateExec(c, spec, nil, ExecOptions{}); err == nil {
			t.Error("an empty command must fail")
		}
		if _, err := GenerateExec(c, nil, []string{"sh"}, ExecOptions{}); err == nil {
			t.Error("a nil spec must fail")
		}
		if _, err := GenerateExec(c, spec, []string{"sh"}, ExecOptions{WorkingDir: "tmp"}); err == nil {
			t.Error("a relative working directory must fail")
		}
	})
}

// ---------- device mapping ----------

func TestDeviceMapping(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("device nodes are a Linux concept")
	}
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("/dev/null is unavailable")
	}
	root := fakeRootfs(t, testPasswd, testGroup)

	c := newTestContainer()
	c.HostConfig.Devices = []types.DeviceMapping{
		{PathOnHost: "/dev/null", PathInContainer: "/dev/zilch", CgroupPermissions: "rw"},
	}
	spec, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: testFeatures()})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(spec.Linux.Devices) != 1 {
		t.Fatalf("devices = %+v", spec.Linux.Devices)
	}
	d := spec.Linux.Devices[0]
	if d.Path != "/dev/zilch" || d.Type != "c" || d.Major != 1 || d.Minor != 3 {
		t.Errorf("device = %+v, want /dev/zilch c 1:3", d)
	}
	last := spec.Linux.Resources.Devices[len(spec.Linux.Resources.Devices)-1]
	if !last.Allow || last.Access != "rw" || last.Major == nil || *last.Major != 1 {
		t.Errorf("device rule = %+v", last)
	}

	c.HostConfig.Devices = []types.DeviceMapping{{PathOnHost: "/dev/definitely-not-here"}}
	if _, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: testFeatures()}); err == nil {
		t.Error("a missing device must be rejected")
	}
}
