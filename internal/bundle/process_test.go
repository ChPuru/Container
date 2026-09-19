package bundle

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rahuldhali/hull/internal/types"
)

// ---------- entrypoint / cmd matrix ----------

func TestResolveArgs(t *testing.T) {
	tests := []struct {
		name    string
		imgEnt  []string
		imgCmd  []string
		ctrEnt  []string
		ctrCmd  []string
		want    []string
		wantErr error
	}{
		{
			name:   "image entrypoint and cmd, nothing overridden",
			imgEnt: []string{"/entry.sh"},
			imgCmd: []string{"--serve"},
			want:   []string{"/entry.sh", "--serve"},
		},
		{
			name:   "image cmd only",
			imgCmd: []string{"/bin/sh"},
			want:   []string{"/bin/sh"},
		},
		{
			name:   "image entrypoint only",
			imgEnt: []string{"/entry.sh"},
			want:   []string{"/entry.sh"},
		},
		{
			name:   "container cmd replaces image cmd, entrypoint kept",
			imgEnt: []string{"/entry.sh"},
			imgCmd: []string{"--serve"},
			ctrCmd: []string{"--version"},
			want:   []string{"/entry.sh", "--version"},
		},
		{
			name:   "container entrypoint with no cmd CLEARS the image cmd",
			imgEnt: []string{"/entry.sh"},
			imgCmd: []string{"--serve"},
			ctrEnt: []string{"/bin/sh"},
			want:   []string{"/bin/sh"},
		},
		{
			name:   "container entrypoint and cmd together",
			imgEnt: []string{"/entry.sh"},
			imgCmd: []string{"--serve"},
			ctrEnt: []string{"/bin/sh"},
			ctrCmd: []string{"-c", "echo hi"},
			want:   []string{"/bin/sh", "-c", "echo hi"},
		},
		{
			name:    "empty entrypoint clears the image entrypoint and its cmd",
			imgEnt:  []string{"/entry.sh"},
			imgCmd:  []string{"--serve"},
			ctrEnt:  []string{""},
			wantErr: ErrNoCommand,
		},
		{
			name:    "nothing anywhere is an error",
			wantErr: ErrNoCommand,
		},
		{
			name:   "empty entrypoint with a container cmd runs the cmd alone",
			imgEnt: []string{"/entry.sh"},
			imgCmd: []string{"--serve"},
			ctrEnt: []string{""},
			ctrCmd: []string{"/bin/true"},
			want:   []string{"/bin/true"},
		},
		{
			name:   "container cmd only, no entrypoint anywhere",
			ctrCmd: []string{"sleep", "1"},
			want:   []string{"sleep", "1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &types.Container{Config: types.ContainerConfig{Entrypoint: tt.ctrEnt, Cmd: tt.ctrCmd}}
			img := &types.Image{Config: types.ImageConfig{Entrypoint: tt.imgEnt, Cmd: tt.imgCmd}}
			got, err := ResolveArgs(c, img)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("want error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("args = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------- environment ----------

func TestMergeEnv(t *testing.T) {
	tests := []struct {
		name    string
		base    []string
		over    []string
		want    []string
		wantErr bool
	}{
		{
			name: "container value wins and keeps the image position",
			base: []string{"A=1", "B=2", "C=3"},
			over: []string{"B=overridden"},
			want: []string{"A=1", "B=overridden", "C=3"},
		},
		{
			name: "new keys are appended in order",
			base: []string{"A=1"},
			over: []string{"Z=26", "M=13"},
			want: []string{"A=1", "Z=26", "M=13"},
		},
		{
			name: "split happens on the first equals only",
			base: []string{"URL=https://x/?a=b&c=d"},
			over: []string{"URL=https://y/?e=f"},
			want: []string{"URL=https://y/?e=f"},
		},
		{
			name: "later duplicate within the same list still wins",
			base: []string{"A=1", "A=2"},
			want: []string{"A=2"},
		},
		{
			name:    "entry without an equals is rejected",
			base:    []string{"NOPE"},
			wantErr: true,
		},
		{
			name:    "entry with an empty name is rejected",
			base:    []string{"=value"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MergeEnv(tt.base, tt.over)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("env = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildEnvDefaults(t *testing.T) {
	tests := []struct {
		name    string
		imgEnv  []string
		ctrEnv  []string
		tty     bool
		home    string
		want    []string
		notWant []string
	}{
		{
			name: "path and hostname are injected",
			want: []string{"PATH=" + DefaultPath, "HOSTNAME=box"},
		},
		{
			name:    "image PATH is kept",
			imgEnv:  []string{"PATH=/opt/bin"},
			want:    []string{"PATH=/opt/bin"},
			notWant: []string{"PATH=" + DefaultPath},
		},
		{
			name: "TERM is added only with a tty",
			tty:  true,
			want: []string{"TERM=xterm"},
		},
		{
			name:    "TERM is not added without a tty",
			notWant: []string{"TERM=xterm"},
		},
		{
			name:   "an explicit TERM survives a tty",
			ctrEnv: []string{"TERM=dumb"},
			tty:    true,
			want:   []string{"TERM=dumb"},
		},
		{
			name: "HOME comes from the passwd entry",
			home: "/home/app",
			want: []string{"HOME=/home/app"},
		},
		{
			name:   "an explicit HOME is not overwritten",
			ctrEnv: []string{"HOME=/elsewhere"},
			home:   "/home/app",
			want:   []string{"HOME=/elsewhere"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &builder{
				c:        &types.Container{Config: types.ContainerConfig{Env: tt.ctrEnv, Tty: tt.tty}},
				img:      &types.Image{Config: types.ImageConfig{Env: tt.imgEnv}},
				hostname: "box",
			}
			got, err := b.buildEnv(tt.home)
			if err != nil {
				t.Fatalf("buildEnv: %v", err)
			}
			for _, w := range tt.want {
				if !contains(got, w) {
					t.Errorf("env %q is missing %q", got, w)
				}
			}
			for _, w := range tt.notWant {
				if contains(got, w) {
					t.Errorf("env %q should not contain %q", got, w)
				}
			}
		})
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ---------- user parsing ----------

// fakeRootfs builds a throwaway container rootfs with an /etc/passwd and
// /etc/group, so user resolution can be tested without root and without a real
// image.
func fakeRootfs(t *testing.T, passwd, group string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if passwd != "" {
		if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte(passwd), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if group != "" {
		if err := os.WriteFile(filepath.Join(root, "etc", "group"), []byte(group), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const testPasswd = `root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
app:x:1000:1000:Application:/home/app:/bin/sh
nobody:x:65534:65534:nobody:/:/sbin/nologin
`

const testGroup = `root:x:0:
bin:x:1:root,daemon
wheel:x:10:app
docker:x:999:app
app:x:1000:
nobody:x:65534:
`

func TestResolveUser(t *testing.T) {
	root := fakeRootfs(t, testPasswd, testGroup)

	tests := []struct {
		name     string
		spec     string
		groupAdd []string
		wantUID  uint32
		wantGID  uint32
		wantName string
		wantHome string
		wantAdd  []uint32
		wantErr  bool
	}{
		{name: "empty means root", spec: "", wantUID: 0, wantGID: 0, wantName: "root", wantHome: "/root"},
		{name: "numeric uid picks up the passwd gid", spec: "1000", wantUID: 1000, wantGID: 1000, wantName: "app", wantHome: "/home/app", wantAdd: []uint32{10, 999}},
		{name: "unknown numeric uid still works", spec: "4242", wantUID: 4242, wantGID: 0},
		{name: "uid:gid", spec: "1000:1", wantUID: 1000, wantGID: 1, wantName: "app", wantHome: "/home/app", wantAdd: []uint32{10, 999}},
		{name: "name", spec: "app", wantUID: 1000, wantGID: 1000, wantName: "app", wantHome: "/home/app", wantAdd: []uint32{10, 999}},
		{name: "name:group", spec: "app:wheel", wantUID: 1000, wantGID: 10, wantName: "app", wantHome: "/home/app", wantAdd: []uint32{999}},
		{name: "name:gid", spec: "nobody:65534", wantUID: 65534, wantGID: 65534, wantName: "nobody", wantHome: "/"},
		{name: "uid:group", spec: "1000:docker", wantUID: 1000, wantGID: 999, wantName: "app", wantHome: "/home/app", wantAdd: []uint32{10}},
		{name: "group-add by name", spec: "app:app", groupAdd: []string{"bin"}, wantUID: 1000, wantGID: 1000, wantName: "app", wantHome: "/home/app", wantAdd: []uint32{10, 999, 1}},
		{name: "group-add by gid", spec: "app:app", groupAdd: []string{"4000"}, wantUID: 1000, wantGID: 1000, wantName: "app", wantHome: "/home/app", wantAdd: []uint32{10, 999, 4000}},
		{name: "unknown user name", spec: "ghost", wantErr: true},
		{name: "unknown group name", spec: "app:ghosts", wantErr: true},
		{name: "unknown group-add", spec: "app", groupAdd: []string{"ghosts"}, wantErr: true},
		{name: "empty group after colon", spec: "app:", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveUser(root, tt.spec, tt.groupAdd)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.UID != tt.wantUID || got.GID != tt.wantGID {
				t.Errorf("uid:gid = %d:%d, want %d:%d", got.UID, got.GID, tt.wantUID, tt.wantGID)
			}
			if tt.wantName != "" && got.Username != tt.wantName {
				t.Errorf("username = %q, want %q", got.Username, tt.wantName)
			}
			if tt.wantHome != "" && got.Home != tt.wantHome {
				t.Errorf("home = %q, want %q", got.Home, tt.wantHome)
			}
			if tt.wantAdd != nil && !reflect.DeepEqual(got.AdditionalGids, tt.wantAdd) {
				t.Errorf("additionalGids = %v, want %v", got.AdditionalGids, tt.wantAdd)
			}
		})
	}
}

func TestResolveUserDistroless(t *testing.T) {
	root := fakeRootfs(t, "", "") // no /etc/passwd, no /etc/group

	got, err := ResolveUser(root, "65532:65532", nil)
	if err != nil {
		t.Fatalf("numeric user must resolve without /etc/passwd: %v", err)
	}
	if got.UID != 65532 || got.GID != 65532 {
		t.Fatalf("uid:gid = %d:%d, want 65532:65532", got.UID, got.GID)
	}

	if _, err := ResolveUser(root, "nonroot", nil); err == nil {
		t.Fatal("a name lookup with no /etc/passwd must fail with an explanation")
	} else if !strings.Contains(err.Error(), "/etc/passwd") {
		t.Fatalf("error should mention the missing /etc/passwd, got %v", err)
	}
}

// TestResolveUserDoesNotEscapeRootfs proves the passwd lookup is anchored: an
// /etc/passwd that is a symlink to an absolute host path must resolve inside
// the rootfs, not on the host.
func TestResolveUserDoesNotEscapeRootfs(t *testing.T) {
	root := fakeRootfs(t, "", testGroup)
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "etc", "passwd")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// The host really does have a root user; if the lookup escaped, this would
	// succeed. Anchored in the rootfs, /etc/passwd points at itself and fails.
	if _, err := ResolveUser(root, "root", nil); err == nil {
		t.Fatal("a symlinked /etc/passwd must not resolve to the host's file")
	}
}

// ---------- rlimits ----------

func TestBuildRlimits(t *testing.T) {
	tests := []struct {
		name     string
		ulimits  []types.Ulimit
		wantType string
		wantSoft uint64
		wantHard uint64
		wantLen  int
		wantErr  bool
	}{
		{name: "default nofile", wantType: "RLIMIT_NOFILE", wantSoft: DefaultNofile, wantHard: DefaultNofile, wantLen: 1},
		{
			name:     "nofile override replaces the default",
			ulimits:  []types.Ulimit{{Name: "nofile", Soft: 1024, Hard: 2048}},
			wantType: "RLIMIT_NOFILE", wantSoft: 1024, wantHard: 2048, wantLen: 1,
		},
		{
			name:     "nproc is appended",
			ulimits:  []types.Ulimit{{Name: "nproc", Soft: 100, Hard: 200}},
			wantType: "RLIMIT_NPROC", wantSoft: 100, wantHard: 200, wantLen: 2,
		},
		{
			name:     "already-prefixed name is accepted",
			ulimits:  []types.Ulimit{{Name: "RLIMIT_CORE", Soft: 0, Hard: 0}},
			wantType: "RLIMIT_CORE", wantLen: 2,
		},
		{
			name:     "minus one means unlimited",
			ulimits:  []types.Ulimit{{Name: "memlock", Soft: -1, Hard: -1}},
			wantType: "RLIMIT_MEMLOCK", wantSoft: ^uint64(0), wantHard: ^uint64(0), wantLen: 2,
		},
		{name: "unknown rlimit", ulimits: []types.Ulimit{{Name: "bogus"}}, wantErr: true},
		{name: "soft above hard", ulimits: []types.Ulimit{{Name: "nofile", Soft: 10, Hard: 5}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildRlimits(tt.ulimits)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Fatalf("got %d rlimits, want %d: %+v", len(got), tt.wantLen, got)
			}
			found := false
			for _, rl := range got {
				if rl.Type != tt.wantType {
					continue
				}
				found = true
				if rl.Soft != tt.wantSoft || rl.Hard != tt.wantHard {
					t.Errorf("%s = %d/%d, want %d/%d", rl.Type, rl.Soft, rl.Hard, tt.wantSoft, tt.wantHard)
				}
			}
			if !found {
				t.Fatalf("no %s in %+v", tt.wantType, got)
			}
		})
	}
}
