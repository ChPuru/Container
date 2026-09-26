package bundle

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ChPuru/hull/internal/oci/runtimespec"
	"github.com/ChPuru/hull/internal/types"
)

func TestTranslateWindowsPath(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
		errHas  string
	}{
		{name: "backslash drive path", in: `C:\Users\x`, want: "/mnt/c/Users/x"},
		{name: "lowercase forward-slash drive path", in: "c:/Users/x", want: "/mnt/c/Users/x"},
		{name: "mixed separators", in: `D:\src/hull\internal`, want: "/mnt/d/src/hull/internal"},
		{name: "bare drive", in: "C:", want: "/mnt/c"},
		{name: "drive root", in: `C:\`, want: "/mnt/c"},
		{name: "already translated", in: "/mnt/c/Users/x", want: "/mnt/c/Users/x"},
		{name: "plain linux path", in: "/srv/data", want: "/srv/data"},
		{name: "linux path is cleaned", in: "/srv//data/", want: "/srv/data"},
		{name: "wsl$ UNC is rejected", in: `\\wsl$\Ubuntu\home\me`, wantErr: true, errHas: "wsl$"},
		{name: "wsl.localhost UNC is rejected", in: `\\wsl.localhost\Ubuntu\home\me`, wantErr: true, errHas: "engine distro"},
		{name: "forward-slash wsl UNC is rejected", in: "//wsl$/Ubuntu/home/me", wantErr: true},
		{name: "other UNC is rejected", in: `\\fileserver\share\dir`, wantErr: true, errHas: "network share"},
		{name: "drive-relative path is rejected", in: `C:Users`, wantErr: true, errHas: "drive-relative"},
		{name: "windows relative path is rejected", in: `Users\x`, wantErr: true},
		{name: "posix relative path is rejected", in: "data", wantErr: true},
		{name: "empty is rejected", in: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TranslateWindowsPath(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %q", got)
				}
				if tt.errHas != "" && !strings.Contains(err.Error(), tt.errHas) {
					t.Fatalf("error %q should mention %q", err, tt.errHas)
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

func TestTranslateWindowsPathUNCIsTyped(t *testing.T) {
	_, err := TranslateWindowsPath(`\\wsl$\Ubuntu\home\me`)
	if !errors.Is(err, ErrUNCPath) {
		t.Fatalf("want ErrUNCPath, got %v", err)
	}
}

func TestParseBind(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    types.Mount
		wantErr bool
	}{
		{name: "anonymous volume", spec: "/data", want: types.Mount{Type: "volume", Target: "/data"}},
		{name: "named volume", spec: "cache:/var/cache", want: types.Mount{Type: "volume", Source: "cache", Target: "/var/cache"}},
		{name: "host bind", spec: "/srv/app:/app", want: types.Mount{Type: "bind", Source: "/srv/app", Target: "/app"}},
		{name: "read-only host bind", spec: "/srv/app:/app:ro", want: types.Mount{Type: "bind", Source: "/srv/app", Target: "/app", ReadOnly: true}},
		{
			name: "windows source with options",
			spec: `C:\Users\me\src:/src:ro`,
			want: types.Mount{Type: "bind", Source: "/mnt/c/Users/me/src", Target: "/src", ReadOnly: true},
		},
		{
			name: "forward-slash windows source",
			spec: "c:/Users/me:/work",
			want: types.Mount{Type: "bind", Source: "/mnt/c/Users/me", Target: "/work"},
		},
		{
			name: "propagation option",
			spec: "/srv:/srv:rslave",
			want: types.Mount{Type: "bind", Source: "/srv", Target: "/srv", BindOptions: &types.BindOptions{Propagation: "rslave"}},
		},
		{name: "selinux labels are accepted and ignored", spec: "/srv:/srv:z", want: types.Mount{Type: "bind", Source: "/srv", Target: "/srv"}},
		{name: "relative container path is rejected", spec: "/srv:app", wantErr: true},
		{name: "unknown option is rejected", spec: "/srv:/srv:bogus", wantErr: true},
		{name: "wsl UNC source is rejected", spec: `\\wsl$\Ubuntu\home:/home`, wantErr: true},
		{name: "empty spec is rejected", spec: "", wantErr: true},
		{name: "windows source without a target is rejected", spec: `C:\Users`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseBind(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSortMountsByDepth(t *testing.T) {
	ms := []runtimespec.Mount{
		{Destination: "/a/b/c"},
		{Destination: "/proc"},
		{Destination: "/a/b"},
		{Destination: "/dev/shm"},
		{Destination: "/a"},
	}
	sortMountsByDepth(ms)
	want := []string{"/proc", "/a", "/a/b", "/dev/shm", "/a/b/c"}
	got := make([]string, len(ms))
	for i, m := range ms {
		got[i] = m.Destination
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestDedupeMountsKeepsTheLast(t *testing.T) {
	ms := []runtimespec.Mount{
		{Destination: "/dev/shm", Type: "tmpfs", Source: "shm"},
		{Destination: "/data", Type: "bind", Source: "/a"},
		{Destination: "/dev/shm/", Type: "bind", Source: "/host/shm"},
	}
	got := dedupeMounts(ms)
	if len(got) != 2 {
		t.Fatalf("want 2 mounts, got %d: %+v", len(got), got)
	}
	if got[1].Destination != "/dev/shm" || got[1].Source != "/host/shm" {
		t.Fatalf("the later /dev/shm must shadow the default: %+v", got[1])
	}
	if got[0].Destination != "/data" {
		t.Fatalf("surviving order changed: %+v", got)
	}
}

// TestMountOrderingAndShadowing exercises the whole pipeline: defaults, image
// volumes, tmpfs and user binds, with a user bind deliberately shadowing a
// default and a nested target proving the depth sort.
func TestMountOrderingAndShadowing(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	hostDir := t.TempDir()

	c := newTestContainer()
	c.HostConfig.Tmpfs = map[string]string{"/run": "rw,size=1024k"}
	c.HostConfig.Binds = []string{
		hostDir + ":/srv/app/data",
		hostDir + ":/srv",
		hostDir + ":/dev/shm", // shadows the default tmpfs /dev/shm
	}
	img := newTestImage()
	img.Config.Volumes = map[string]struct{}{"/var/lib/data": {}}

	spec, warnings, err := Generate(c, img, Options{
		RootFS:           root,
		CgroupsPath:      "hull/test",
		ImageVolumePaths: map[string]string{"/var/lib/data": hostDir},
		Features:         Features{CgroupV2: true, Seccomp: true, KernelMajor: 5, KernelMinor: 15},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	dests := make([]string, len(spec.Mounts))
	byDest := make(map[string]runtimespec.Mount, len(spec.Mounts))
	for i, m := range spec.Mounts {
		dests[i] = m.Destination
		if _, dup := byDest[m.Destination]; dup {
			t.Fatalf("duplicate mount destination %q", m.Destination)
		}
		byDest[m.Destination] = m
	}

	// A parent must always come before its child.
	for i := range dests {
		for j := i + 1; j < len(dests); j++ {
			if dests[i] != dests[j] && strings.HasPrefix(dests[i]+"/", dests[j]+"/") {
				t.Errorf("parent %q (index %d) is mounted after its child %q (index %d): %v", dests[j], j, dests[i], i, dests)
			}
		}
	}
	if mountDepth(dests[0]) != 1 {
		t.Errorf("first mount %q should be a depth-1 mount", dests[0])
	}

	// The user bind shadows the default /dev/shm tmpfs entirely.
	shm := byDest["/dev/shm"]
	if shm.Type != "bind" || shm.Source != hostDir {
		t.Errorf("/dev/shm = %+v, want the user bind", shm)
	}

	// Image volume survived, backed by the anonymous volume.
	if v := byDest["/var/lib/data"]; v.Type != "bind" || v.Source != hostDir {
		t.Errorf("/var/lib/data = %+v, want a bind of the anonymous volume", v)
	}

	// tmpfs carries the user's options on top of hull's hardening defaults.
	run := byDest["/run"]
	if run.Type != "tmpfs" {
		t.Fatalf("/run = %+v, want tmpfs", run)
	}
	for _, want := range []string{"nosuid", "nodev", "noexec", "size=1024k"} {
		if !contains(run.Options, want) {
			t.Errorf("/run options %v missing %q", run.Options, want)
		}
	}

	// Nested bind under another bind is ordered correctly.
	if idx(dests, "/srv") > idx(dests, "/srv/app/data") {
		t.Errorf("/srv must be mounted before /srv/app/data: %v", dests)
	}
}

func TestExplicitMountShadowsImageVolume(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	hostDir := t.TempDir()

	c := newTestContainer()
	c.HostConfig.Binds = []string{hostDir + ":/var/lib/data"}
	img := newTestImage()
	img.Config.Volumes = map[string]struct{}{"/var/lib/data": {}}

	spec, warnings, err := Generate(c, img, Options{
		RootFS:   root,
		Features: Features{CgroupV2: true, Seccomp: true},
		// Deliberately no ImageVolumePaths: the explicit -v takes over, so
		// there must be no "unbacked volume" warning either.
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("an explicitly mounted image VOLUME must not warn: %v", warnings)
	}
	for _, m := range spec.Mounts {
		if m.Destination == "/var/lib/data" && m.Source != hostDir {
			t.Fatalf("/var/lib/data = %+v, want the explicit bind", m)
		}
	}
}

func TestUnbackedImageVolumeWarns(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	img := newTestImage()
	img.Config.Volumes = map[string]struct{}{"/var/lib/data": {}}

	_, warnings, err := Generate(c, img, Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "/var/lib/data") {
		t.Fatalf("want one warning about /var/lib/data, got %v", warnings)
	}
}

func TestMissingBindSourceIsRejected(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	c.HostConfig.Binds = []string{"/definitely/not/here/hull-test:/app"}

	_, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
	if err == nil {
		t.Fatal("a bind of a missing host path must be rejected")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("error should say the source does not exist: %v", err)
	}
}

func TestCreateMountpointSkipsTheExistenceCheck(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	c.HostConfig.Mounts = []types.Mount{{
		Type:        "bind",
		Source:      "/definitely/not/here/hull-test",
		Target:      "/app",
		BindOptions: &types.BindOptions{CreateMountpoint: true},
	}}

	spec, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
	if err != nil {
		t.Fatalf("createMountpoint should allow a missing source: %v", err)
	}
	found := false
	for _, m := range spec.Mounts {
		if m.Destination == "/app" {
			found = true
		}
	}
	if !found {
		t.Fatal("/app bind is missing from the spec")
	}
}

func TestVolumeWithoutHostPathIsRejected(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	c.HostConfig.Binds = []string{"cache:/var/cache"}

	_, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
	if err == nil || !strings.Contains(err.Error(), "has no host path") {
		t.Fatalf("want a clear volume error, got %v", err)
	}
}

func TestBindOptions(t *testing.T) {
	tests := []struct {
		name string
		m    types.Mount
		want []string
	}{
		{name: "default", m: types.Mount{}, want: []string{"rbind", "rprivate", "rw"}},
		{name: "read-only", m: types.Mount{ReadOnly: true}, want: []string{"rbind", "rprivate", "ro"}},
		{
			name: "propagation honoured",
			m:    types.Mount{BindOptions: &types.BindOptions{Propagation: "rshared"}},
			want: []string{"rbind", "rshared", "rw"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bindOptions(tt.m); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShmSizeOption(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	c := newTestContainer()
	c.HostConfig.ShmSize = 128 << 20

	spec, _, err := Generate(c, newTestImage(), Options{RootFS: root, Features: Features{CgroupV2: true, Seccomp: true}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, m := range spec.Mounts {
		if m.Destination != "/dev/shm" {
			continue
		}
		if !contains(m.Options, "size=131072k") {
			t.Fatalf("/dev/shm options %v, want size=131072k", m.Options)
		}
		return
	}
	t.Fatal("/dev/shm is missing")
}

func TestSysIsABindWhenTheNetnsIsShared(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)
	for _, mode := range []string{"host", "container:abc"} {
		t.Run(mode, func(t *testing.T) {
			c := newTestContainer()
			c.HostConfig.NetworkMode = mode
			spec, _, err := Generate(c, newTestImage(), Options{
				RootFS:           root,
				SharedNetworkPID: 4242,
				Features:         Features{CgroupV2: true, Seccomp: true},
			})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			for _, m := range spec.Mounts {
				if m.Destination != "/sys" {
					continue
				}
				if m.Type != "bind" {
					t.Fatalf("/sys = %+v, want a read-only bind when the netns is shared", m)
				}
				if !contains(m.Options, "ro") {
					t.Fatalf("/sys options %v, want ro", m.Options)
				}
				return
			}
			t.Fatal("/sys is missing")
		})
	}
}

func idx(list []string, want string) int {
	for i, s := range list {
		if s == want {
			return i
		}
	}
	return -1
}
