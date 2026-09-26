package volume

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ChPuru/hull/internal/types"
)

func TestResolveOrdersAndMaterialises(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)

	c := mkContainer("container-one", types.HostConfig{
		Binds: []string{
			"db:/var/lib/db",
			`C:\Users\me\proj:/app:ro`,
		},
		Mounts: []types.Mount{
			{Type: TypeBind, Source: "/srv/cfg", Target: "/etc/app", ReadOnly: true},
		},
		Tmpfs: map[string]string{"/run": "rw,size=64m,mode=1777"},
	}, types.ContainerConfig{
		Volumes: map[string]struct{}{"/cache": {}},
	}, "")

	got, err := m.Resolve(ctx, c)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("Resolve returned %d mounts: %+v", len(got), got)
	}

	// Parent targets come first, so the runtime can apply the list in order.
	wantOrder := []string{"/app", "/cache", "/run", "/etc/app", "/var/lib/db"}
	for i, w := range wantOrder {
		if got[i].Target != w {
			t.Fatalf("mount %d target = %q, want %q (full order %v)", i, got[i].Target, w, targets(got))
		}
	}

	byTarget := map[string]types.Mount{}
	for _, mnt := range got {
		byTarget[mnt.Target] = mnt
	}

	// The named volume was created and its source replaced with the _data path.
	dbData := filepath.Join(m.Root(), "db", dataDirName)
	if mnt := byTarget["/var/lib/db"]; mnt.Type != TypeVolume || mnt.Source != dbData {
		t.Fatalf("/var/lib/db = %+v, want a volume sourced at %s", mnt, dbData)
	}
	if _, err := m.Get("db"); err != nil {
		t.Fatalf("named volume was not created: %v", err)
	}
	if n, err := m.RefCount("db"); err != nil || n != 1 {
		t.Fatalf("RefCount(db) = %d, %v, want 1, nil", n, err)
	}

	// The Windows bind was translated.
	if mnt := byTarget["/app"]; mnt.Type != TypeBind || mnt.Source != "/mnt/c/Users/me/proj" || !mnt.ReadOnly {
		t.Fatalf("/app = %+v", mnt)
	}

	// The image VOLUME became an anonymous volume.
	cache := byTarget["/cache"]
	if cache.Type != TypeVolume || cache.Source == "" {
		t.Fatalf("/cache = %+v", cache)
	}
	anonName := filepath.Base(filepath.Dir(cache.Source))
	av, err := m.Get(anonName)
	if err != nil {
		t.Fatalf("anonymous volume %q: %v", anonName, err)
	}
	if !IsAnonymous(av) {
		t.Fatalf("volume for an image VOLUME must be anonymous: %+v", av)
	}

	// The tmpfs kept its size and mode.
	run := byTarget["/run"]
	if run.Type != TypeTmpfs || run.TmpfsOptions == nil {
		t.Fatalf("/run = %+v", run)
	}
	if run.TmpfsOptions.SizeBytes != 64<<20 || run.TmpfsOptions.Mode != 0o1777 {
		t.Fatalf("/run tmpfs options = %+v", run.TmpfsOptions)
	}

	// Release drops both references; only the anonymous one is deleted.
	if err := m.Release(ctx, c, true); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if n, err := m.RefCount("db"); err != nil || n != 0 {
		t.Fatalf("RefCount(db) after Release = %d, %v", n, err)
	}
	if _, err := m.Get("db"); err != nil {
		t.Fatalf("a named volume must survive Release: %v", err)
	}
	if _, err := m.Get(anonName); !errors.Is(err, ErrNotFound) {
		t.Fatalf("anonymous volume survived Release: %v", err)
	}
}

func TestResolveAnonymousBindForm(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)

	c := mkContainer("c1", types.HostConfig{Binds: []string{"/data"}}, types.ContainerConfig{}, "")
	got, err := m.Resolve(ctx, c)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 || got[0].Type != TypeVolume || got[0].Target != "/data" {
		t.Fatalf("Resolve = %+v", got)
	}
	name := filepath.Base(filepath.Dir(got[0].Source))
	v, err := m.Get(name)
	if err != nil {
		t.Fatalf("Get %q: %v", name, err)
	}
	if !IsAnonymous(v) {
		t.Fatalf("-v /data must create an anonymous volume, got %+v", v)
	}

	// Release without removeAnonymous keeps the volume but drops the reference.
	if err := m.Release(ctx, c, false); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if n, err := m.RefCount(name); err != nil || n != 0 {
		t.Fatalf("RefCount = %d, %v", n, err)
	}
	if _, err := m.Get(name); err != nil {
		t.Fatalf("volume should still exist: %v", err)
	}
}

func TestResolveExplicitMountBeatsImageVolume(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)

	c := mkContainer("c1", types.HostConfig{
		Binds: []string{"/host/cache:/cache"},
	}, types.ContainerConfig{
		Volumes: map[string]struct{}{"/cache": {}},
	}, "")

	got, err := m.Resolve(ctx, c)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Resolve returned %d mounts, want 1: %+v", len(got), got)
	}
	if got[0].Type != TypeBind || got[0].Source != "/host/cache" {
		t.Fatalf("explicit bind did not win: %+v", got[0])
	}
}

func TestResolveDuplicateTarget(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)

	c := mkContainer("c1", types.HostConfig{
		Binds:  []string{"/host:/data"},
		Mounts: []types.Mount{{Type: TypeVolume, Source: "db", Target: "/data"}},
	}, types.ContainerConfig{}, "")

	if _, err := m.Resolve(ctx, c); !errors.Is(err, ErrConflict) {
		t.Fatalf("Resolve with a duplicate target = %v, want ErrConflict", err)
	}
}

func TestResolveRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)

	tests := []struct {
		name string
		hc   types.HostConfig
		want error
	}{
		{name: "bad bind", hc: types.HostConfig{Binds: []string{"/host:relative"}}, want: ErrInvalidMount},
		{name: "unc bind", hc: types.HostConfig{Binds: []string{`\\wsl$\Ubuntu\home:/app`}}, want: ErrUNCPath},
		{name: "mount without type", hc: types.HostConfig{Mounts: []types.Mount{{Target: "/x"}}}, want: ErrInvalidMount},
		{name: "tmpfs with a source", hc: types.HostConfig{Mounts: []types.Mount{{Type: TypeTmpfs, Source: "/y", Target: "/x"}}}, want: ErrInvalidMount},
		{name: "tmpfs exec", hc: types.HostConfig{Tmpfs: map[string]string{"/run": "exec"}}, want: ErrInvalidMount},
		{name: "tmpfs unknown option", hc: types.HostConfig{Tmpfs: map[string]string{"/run": "wat"}}, want: ErrInvalidMount},
		{name: "bad volume name", hc: types.HostConfig{Mounts: []types.Mount{{Type: TypeVolume, Source: "../escape", Target: "/x"}}}, want: ErrInvalidName},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := mkContainer("c1", tc.hc, types.ContainerConfig{}, "")
			if _, err := m.Resolve(ctx, c); !errors.Is(err, tc.want) {
				t.Fatalf("Resolve = %v, want %v", err, tc.want)
			}
		})
	}

	if _, err := m.Resolve(ctx, nil); err == nil {
		t.Fatal("Resolve(nil) should fail")
	}
	if _, err := m.Resolve(ctx, mkContainer("", types.HostConfig{}, types.ContainerConfig{}, "")); err == nil {
		t.Fatal("Resolve without a container id should fail")
	}
}

func TestResolveTmpfsFlagsAccepted(t *testing.T) {
	m, err := tmpfsMount("/run", "rw,nosuid,nodev,noexec,size=32m,mode=0755")
	if err != nil {
		t.Fatalf("tmpfsMount: %v", err)
	}
	if m.TmpfsOptions == nil || m.TmpfsOptions.SizeBytes != 32<<20 || m.TmpfsOptions.Mode != 0o755 {
		t.Fatalf("tmpfsMount = %+v", m.TmpfsOptions)
	}
	if ro, err := tmpfsMount("/run", "ro"); err != nil || !ro.ReadOnly {
		t.Fatalf("tmpfsMount ro = %+v, %v", ro, err)
	}
	if plain, err := tmpfsMount("/run", ""); err != nil || plain.TmpfsOptions != nil {
		t.Fatalf("tmpfsMount with no options = %+v, %v", plain, err)
	}
}

// targets is a small helper for failure messages.
func targets(ms []types.Mount) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Target)
	}
	return out
}
