package volume

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/rahuldhali/hull/internal/state"
	"github.com/rahuldhali/hull/internal/types"
)

var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// newTestManager opens a throwaway state store and a manager over it.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	root := t.TempDir()
	store, err := state.Open(root)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	m, err := New(filepath.Join(root, "volumes"), store)
	if err != nil {
		t.Fatalf("volume.New: %v", err)
	}
	return m
}

func TestNewDerivesRootFromStore(t *testing.T) {
	root := t.TempDir()
	store, err := state.Open(root)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	defer store.Close()
	m, err := New("", store)
	if err != nil {
		t.Fatalf("volume.New: %v", err)
	}
	if want := filepath.Join(root, "volumes"); m.Root() != want {
		t.Fatalf("Root() = %q, want %q", m.Root(), want)
	}
	if _, err := New("", nil); err == nil {
		t.Fatal("New with a nil store should fail")
	}
}

func TestCreate(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)

	v, err := m.Create(ctx, "db", "", nil, map[string]string{"env": "dev"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if v.Name != "db" || v.Driver != DriverLocal || v.Scope != ScopeLocal {
		t.Fatalf("Create returned %+v", v)
	}
	want := filepath.Join(m.Root(), "db", dataDirName)
	if v.Mountpoint != want {
		t.Fatalf("Mountpoint = %q, want %q", v.Mountpoint, want)
	}
	fi, err := os.Stat(want)
	if err != nil {
		t.Fatalf("stat data dir: %v", err)
	}
	if !fi.IsDir() {
		t.Fatal("data dir is not a directory")
	}
	if got := fi.Mode().Perm(); got != 0o755 {
		t.Fatalf("data dir mode = %o, want 0755", got)
	}
	if IsAnonymous(v) {
		t.Fatal("a named volume must not carry the anonymous label")
	}
	if v.Labels["env"] != "dev" {
		t.Fatalf("labels = %v", v.Labels)
	}

	// Create is idempotent for an identical request.
	again, err := m.Create(ctx, "db", DriverLocal, nil, nil)
	if err != nil {
		t.Fatalf("Create again: %v", err)
	}
	if !again.Created.Equal(v.Created) {
		t.Fatalf("Create recreated the volume: %v vs %v", again.Created, v.Created)
	}
}

func TestCreateAnonymous(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)

	v, err := m.Create(ctx, "", "", nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !hex64RE.MatchString(v.Name) {
		t.Fatalf("anonymous name %q is not 64 hex characters", v.Name)
	}
	if _, ok := v.Labels[AnonymousLabel]; !ok {
		t.Fatalf("anonymous volume is missing the %q label: %v", AnonymousLabel, v.Labels)
	}
	if !IsAnonymous(v) {
		t.Fatal("IsAnonymous should be true")
	}
	other, err := m.Create(ctx, "", "", nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if other.Name == v.Name {
		t.Fatal("two anonymous volumes collided")
	}
}

func TestCreateDriverAndOptions(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)

	if _, err := m.Create(ctx, "nfsvol", "nfs", nil, nil); !errors.Is(err, ErrDriverUnsupported) {
		t.Fatalf("Create with driver nfs = %v, want ErrDriverUnsupported", err)
	}
	if _, err := m.Create(ctx, "bad", DriverLocal, map[string]string{"nosuchopt": "1"}, nil); !errors.Is(err, ErrDriverUnsupported) {
		t.Fatalf("Create with an unknown local option = %v, want ErrDriverUnsupported", err)
	}

	opts := map[string]string{"type": "tmpfs", "device": "tmpfs", "o": "size=64m,uid=1000"}
	v, err := m.Create(ctx, "scratch", DriverLocal, opts, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for k, want := range opts {
		if got := v.Options[k]; got != want {
			t.Fatalf("Options[%q] = %q, want %q", k, got, want)
		}
	}
	// The record must survive a round trip through the store.
	back, err := m.Get("scratch")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if back.Options["o"] != opts["o"] {
		t.Fatalf("options lost in the store: %v", back.Options)
	}
}

func TestGetMissing(t *testing.T) {
	m := newTestManager(t)
	_, err := m.Get("nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
	var nf *NotFoundError
	if !errors.As(err, &nf) || nf.Name != "nope" {
		t.Fatalf("Get missing error = %#v", err)
	}
}

func TestRefUnrefRemove(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)

	if _, err := m.Create(ctx, "db", "", nil, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Ref("db", "container-one"); err != nil {
		t.Fatalf("Ref: %v", err)
	}
	// Ref is idempotent.
	if err := m.Ref("db", "container-one"); err != nil {
		t.Fatalf("Ref twice: %v", err)
	}
	if err := m.Ref("db", "container-two"); err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if n, err := m.RefCount("db"); err != nil || n != 2 {
		t.Fatalf("RefCount = %d, %v, want 2, nil", n, err)
	}

	err := m.Remove(ctx, "db", false)
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("Remove while in use = %v, want ErrInUse", err)
	}
	var inUse *InUseError
	if !errors.As(err, &inUse) {
		t.Fatalf("Remove error is not an *InUseError: %#v", err)
	}
	if len(inUse.Containers) != 2 {
		t.Fatalf("InUseError.Containers = %v", inUse.Containers)
	}

	if err := m.Unref("db", "container-one"); err != nil {
		t.Fatalf("Unref: %v", err)
	}
	if err := m.Remove(ctx, "db", false); !errors.Is(err, ErrInUse) {
		t.Fatalf("Remove with one reference left = %v, want ErrInUse", err)
	}
	if err := m.Unref("db", "container-two"); err != nil {
		t.Fatalf("Unref: %v", err)
	}
	// Unref of an unknown reference is a no-op, not an error.
	if err := m.Unref("db", "never-referenced"); err != nil {
		t.Fatalf("Unref unknown: %v", err)
	}

	if err := m.Remove(ctx, "db", false); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := m.Get("db"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Remove = %v, want ErrNotFound", err)
	}
	if _, err := os.Stat(filepath.Join(m.Root(), "db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("volume directory survived Remove: %v", err)
	}

	// Removing a missing volume is an error unless forced.
	if err := m.Remove(ctx, "db", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Remove missing = %v, want ErrNotFound", err)
	}
	if err := m.Remove(ctx, "db", true); err != nil {
		t.Fatalf("Remove missing with force = %v, want nil", err)
	}

	// Ref of a missing volume must fail rather than invent a reference.
	if err := m.Ref("db", "container-one"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Ref missing = %v, want ErrNotFound", err)
	}
}

func TestRemoveForceWhileInUse(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)
	if _, err := m.Create(ctx, "db", "", nil, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Ref("db", "c1"); err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if err := m.Remove(ctx, "db", true); err != nil {
		t.Fatalf("forced Remove: %v", err)
	}
	if n, err := m.RefCount("db"); err != nil || n != 0 {
		t.Fatalf("RefCount after forced remove = %d, %v", n, err)
	}
}

func TestUsage(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)
	if _, err := m.Create(ctx, "data", "", nil, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	data, err := m.DataDir("data")
	if err != nil {
		t.Fatalf("DataDir: %v", err)
	}
	if got, err := m.Usage("data"); err != nil || got != 0 {
		t.Fatalf("Usage of an empty volume = %d, %v", got, err)
	}
	writeFile(t, filepath.Join(data, "a"), 100)
	if err := os.Mkdir(filepath.Join(data, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(data, "sub", "b"), 250)
	if got, err := m.Usage("data"); err != nil || got != 350 {
		t.Fatalf("Usage = %d, %v, want 350, nil", got, err)
	}
	if _, err := m.Usage("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Usage of a missing volume = %v, want ErrNotFound", err)
	}
}

func TestListFilters(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)

	if _, err := m.Create(ctx, "alpha", "", nil, map[string]string{"team": "infra"}); err != nil {
		t.Fatalf("Create alpha: %v", err)
	}
	if _, err := m.Create(ctx, "beta", "", nil, map[string]string{"team": "apps"}); err != nil {
		t.Fatalf("Create beta: %v", err)
	}
	anon, err := m.Create(ctx, "", "", nil, nil)
	if err != nil {
		t.Fatalf("Create anonymous: %v", err)
	}
	if err := m.Ref("alpha", "c1"); err != nil {
		t.Fatalf("Ref: %v", err)
	}

	yes, no := true, false
	tests := []struct {
		name string
		f    Filters
		want []string
	}{
		{name: "all", f: Filters{}, want: []string{"alpha", anon.Name, "beta"}},
		{name: "name substring", f: Filters{Names: []string{"lph"}}, want: []string{"alpha"}},
		{name: "name miss", f: Filters{Names: []string{"zzz"}}},
		{name: "driver local", f: Filters{Drivers: []string{DriverLocal}}, want: []string{"alpha", anon.Name, "beta"}},
		{name: "driver other", f: Filters{Drivers: []string{"nfs"}}},
		{name: "label key", f: Filters{Labels: []string{"team"}}, want: []string{"alpha", "beta"}},
		{name: "label key value", f: Filters{Labels: []string{"team=apps"}}, want: []string{"beta"}},
		{name: "anonymous label", f: Filters{Labels: []string{AnonymousLabel}}, want: []string{anon.Name}},
		{name: "dangling true", f: Filters{Dangling: &yes}, want: []string{anon.Name, "beta"}},
		{name: "dangling false", f: Filters{Dangling: &no}, want: []string{"alpha"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := m.List(tc.f)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			names := make([]string, 0, len(got))
			for _, v := range got {
				names = append(names, v.Name)
			}
			assertNames(t, names, tc.want)
		})
	}
}

func TestParseFilters(t *testing.T) {
	f, err := ParseFilters(map[string][]string{
		"name":     {"db"},
		"driver":   {"local"},
		"label":    {"team=infra"},
		"dangling": {"true"},
		"all":      {"1"},
	})
	if err != nil {
		t.Fatalf("ParseFilters: %v", err)
	}
	if len(f.Names) != 1 || f.Names[0] != "db" || f.Dangling == nil || !*f.Dangling || !f.All {
		t.Fatalf("ParseFilters = %+v", f)
	}
	if _, err := ParseFilters(map[string][]string{"nope": {"x"}}); err == nil {
		t.Fatal("ParseFilters should reject an unknown key")
	}
	if _, err := ParseFilters(map[string][]string{"dangling": {"maybe"}}); err == nil {
		t.Fatal("ParseFilters should reject a non-boolean dangling value")
	}
}

func TestPrune(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)

	named, err := m.Create(ctx, "keep", "", nil, nil)
	if err != nil {
		t.Fatalf("Create keep: %v", err)
	}
	free, err := m.Create(ctx, "", "", nil, map[string]string{"team": "infra"})
	if err != nil {
		t.Fatalf("Create anonymous: %v", err)
	}
	busy, err := m.Create(ctx, "", "", nil, nil)
	if err != nil {
		t.Fatalf("Create anonymous: %v", err)
	}
	if err := m.Ref(busy.Name, "c1"); err != nil {
		t.Fatalf("Ref: %v", err)
	}
	freeData, err := m.DataDir(free.Name)
	if err != nil {
		t.Fatalf("DataDir: %v", err)
	}
	writeFile(t, filepath.Join(freeData, "blob"), 4096)

	removed, reclaimed, err := m.Prune(ctx, Filters{})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	assertNames(t, removed, []string{free.Name})
	if reclaimed != 4096 {
		t.Fatalf("reclaimed = %d, want 4096", reclaimed)
	}
	if _, err := m.Get(named.Name); err != nil {
		t.Fatalf("a named volume must survive the default prune: %v", err)
	}
	if _, err := m.Get(busy.Name); err != nil {
		t.Fatalf("a referenced volume must survive prune: %v", err)
	}

	// A label filter narrows what prune considers.
	other, err := m.Create(ctx, "", "", nil, map[string]string{"team": "apps"})
	if err != nil {
		t.Fatalf("Create anonymous: %v", err)
	}
	removed, _, err = m.Prune(ctx, Filters{Labels: []string{"team=infra"}})
	if err != nil {
		t.Fatalf("Prune with a label filter: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("label filter should have matched nothing, removed %v", removed)
	}
	removed, _, err = m.Prune(ctx, Filters{Labels: []string{"team=apps"}})
	if err != nil {
		t.Fatalf("Prune with a label filter: %v", err)
	}
	assertNames(t, removed, []string{other.Name})

	// All also sweeps named volumes, but still never a referenced one.
	removed, _, err = m.Prune(ctx, Filters{All: true})
	if err != nil {
		t.Fatalf("Prune all: %v", err)
	}
	assertNames(t, removed, []string{"keep"})
	if _, err := m.Get(busy.Name); err != nil {
		t.Fatalf("a referenced volume must survive prune --all: %v", err)
	}
}

func TestRefIndexSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := state.Open(root)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	m, err := New(filepath.Join(root, "volumes"), store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := m.Create(ctx, "db", "", nil, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Ref("db", "c1"); err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	store2, err := state.Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store2.Close()
	m2, err := New(filepath.Join(root, "volumes"), store2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if n, err := m2.RefCount("db"); err != nil || n != 1 {
		t.Fatalf("RefCount after reopen = %d, %v, want 1, nil", n, err)
	}
	if err := m2.Remove(ctx, "db", false); !errors.Is(err, ErrInUse) {
		t.Fatalf("Remove after reopen = %v, want ErrInUse", err)
	}
}

// writeFile writes n bytes of filler at path.
func writeFile(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, n), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// assertNames compares two name lists as sets, reported in order.
func assertNames(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	seen := map[string]int{}
	for _, n := range got {
		seen[n]++
	}
	for _, n := range want {
		if seen[n] == 0 {
			t.Fatalf("got %v, want %v (missing %s)", got, want, n)
		}
		seen[n]--
	}
}

// mkContainer builds the minimum container record the resolver needs.
func mkContainer(id string, hc types.HostConfig, cfg types.ContainerConfig, rootfs string) *types.Container {
	return &types.Container{ID: id, HostConfig: hc, Config: cfg, RootFS: rootfs}
}
