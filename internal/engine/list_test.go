package engine

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/ChPuru/hull/internal/idutil"
	"github.com/ChPuru/hull/internal/types"
)

// putContainer writes a container record straight into the store, so a listing
// test can control creation times and states without driving the whole
// lifecycle.
func putContainer(t *testing.T, te *testEngine, c *types.Container) *types.Container {
	t.Helper()
	if c.ID == "" {
		c.ID = idutil.NewID()
	}
	if c.State == "" {
		c.State = types.StateExited
	}
	if c.Created.IsZero() {
		c.Created = time.Now().UTC()
	}
	if err := te.state.ReserveName(c.Name, c.ID); err != nil {
		t.Fatalf("reserve %q: %v", c.Name, err)
	}
	if err := te.state.PutContainer(c); err != nil {
		t.Fatalf("put container %q: %v", c.Name, err)
	}
	return c
}

// names renders a listing as a sorted name slice for comparison.
func names(list []*types.Container) []string {
	out := make([]string, 0, len(list))
	for _, c := range list {
		out = append(out, c.Name)
	}
	sort.Strings(out)
	return out
}

// equalStrings compares two string slices.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestListFilters(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)

	alpine := te.seedImage(t, "alpine:3.20", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	nginx := te.seedImage(t, "nginx:1.27", types.ImageConfig{Cmd: []string{"/bin/sh"}})

	putContainer(t, te, &types.Container{
		Name: "running-web", State: types.StateRunning, Created: base,
		Image: nginx.ID, ImageRef: "nginx:1.27",
		Config: types.ContainerConfig{Labels: map[string]string{"tier": "web", "env": "prod"}},
		NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{
			"bridge": {NetworkID: "net-bridge"},
		}},
		Health: &types.HealthState{Status: HealthHealthy},
	})
	putContainer(t, te, &types.Container{
		Name: "exited-db", State: types.StateExited, ExitCode: 1,
		Created: base.Add(time.Minute),
		Image:   alpine.ID, ImageRef: "alpine:3.20",
		Config: types.ContainerConfig{Labels: map[string]string{"tier": "db"}},
		HostConfig: types.HostConfig{Mounts: []types.Mount{
			{Type: "volume", Source: "/data/pgdata/_data", Target: "/var/lib/postgresql/data"},
		}},
		Health: &types.HealthState{Status: HealthUnhealthy},
	})
	putContainer(t, te, &types.Container{
		Name: "paused-cache", State: types.StatePaused,
		Created: base.Add(2 * time.Minute),
		Image:   alpine.ID, ImageRef: "alpine:3.20",
		NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{
			"backend": {NetworkID: "net-backend"},
		}},
	})
	putContainer(t, te, &types.Container{
		Name: "exited-job", State: types.StateExited, ExitCode: 0,
		Created: base.Add(3 * time.Minute),
		Image:   alpine.ID, ImageRef: "alpine:3.20",
	})

	tests := []struct {
		name string
		opts ListOptions
		want []string
	}{
		{
			name: "default shows only live containers",
			opts: ListOptions{},
			want: []string{"paused-cache", "running-web"},
		},
		{
			name: "all shows everything",
			opts: ListOptions{All: true},
			want: []string{"exited-db", "exited-job", "paused-cache", "running-web"},
		},
		{
			name: "status filter implies all",
			opts: ListOptions{Status: []string{"exited"}},
			want: []string{"exited-db", "exited-job"},
		},
		{
			name: "two status values are ORed",
			opts: ListOptions{Status: []string{"exited", "paused"}},
			want: []string{"exited-db", "exited-job", "paused-cache"},
		},
		{
			name: "name matches a substring",
			opts: ListOptions{All: true, Name: []string{"exited"}},
			want: []string{"exited-db", "exited-job"},
		},
		{
			name: "a label key must be present",
			opts: ListOptions{All: true, Label: []string{"tier"}},
			want: []string{"exited-db", "running-web"},
		},
		{
			name: "a label pair must match",
			opts: ListOptions{All: true, Label: []string{"tier=db"}},
			want: []string{"exited-db"},
		},
		{
			name: "label filters are ANDed with each other",
			opts: ListOptions{All: true, Label: []string{"tier=web", "env=prod"}},
			want: []string{"running-web"},
		},
		{
			name: "two label filters that cannot both hold match nothing",
			opts: ListOptions{All: true, Label: []string{"tier=web", "tier=db"}},
			want: []string{},
		},
		{
			name: "ancestor matches by reference",
			opts: ListOptions{All: true, Ancestor: []string{"nginx:1.27"}},
			want: []string{"running-web"},
		},
		{
			name: "ancestor matches by image id",
			opts: ListOptions{All: true, Ancestor: []string{alpine.ID}},
			want: []string{"exited-db", "exited-job", "paused-cache"},
		},
		{
			name: "network matches by name",
			opts: ListOptions{All: true, Network: []string{"backend"}},
			want: []string{"paused-cache"},
		},
		{
			name: "volume matches a mount target",
			opts: ListOptions{All: true, Volume: []string{"/var/lib/postgresql/data"}},
			want: []string{"exited-db"},
		},
		{
			name: "volume matches a source path",
			opts: ListOptions{All: true, Volume: []string{"/data/pgdata/_data"}},
			want: []string{"exited-db"},
		},
		{
			name: "exited code filter",
			opts: ListOptions{All: true, Exited: []int{1}},
			want: []string{"exited-db"},
		},
		{
			name: "health filter",
			opts: ListOptions{All: true, Health: []string{HealthUnhealthy}},
			want: []string{"exited-db"},
		},
		{
			name: "before is exclusive and ordered by creation",
			opts: ListOptions{All: true, Before: []string{"paused-cache"}},
			want: []string{"exited-db", "running-web"},
		},
		{
			name: "since is exclusive and ordered by creation",
			opts: ListOptions{All: true, Since: []string{"exited-db"}},
			want: []string{"exited-job", "paused-cache"},
		},
		{
			name: "before and since together bound a window",
			opts: ListOptions{All: true, Before: []string{"exited-job"}, Since: []string{"running-web"}},
			want: []string{"exited-db", "paused-cache"},
		},
		{
			name: "different keys are ANDed",
			opts: ListOptions{All: true, Status: []string{"exited"}, Label: []string{"tier=db"}},
			want: []string{"exited-db"},
		},
		{
			name: "id prefix",
			opts: ListOptions{All: true, ID: []string{"nope"}},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := te.List(ctx, tt.opts)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if !equalStrings(names(got), tt.want) {
				t.Errorf("List = %v, want %v", names(got), tt.want)
			}
		})
	}
}

func TestListOrdersNewestFirstAndHonoursLimit(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	for i, name := range []string{"oldest", "middle", "newest"} {
		putContainer(t, te, &types.Container{
			Name: name, State: types.StateExited,
			Created: base.Add(time.Duration(i) * time.Minute),
		})
	}
	got, err := te.List(ctx, ListOptions{All: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 || got[0].Name != "newest" || got[2].Name != "oldest" {
		t.Fatalf("List order = %v, want newest first", names(got))
	}
	limited, err := te.List(ctx, ListOptions{All: true, Limit: 2})
	if err != nil {
		t.Fatalf("List with a limit: %v", err)
	}
	if len(limited) != 2 || limited[0].Name != "newest" {
		t.Errorf("limited list = %v, want the two newest", names(limited))
	}
}

func TestListRejectsAnUnknownStatus(t *testing.T) {
	te := newTestEngine(t)
	if _, err := te.List(context.Background(), ListOptions{Status: []string{"sleeping"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("List with an unknown status = %v, want ErrInvalid", err)
	}
}

func TestListRejectsAnUnknownAnchor(t *testing.T) {
	te := newTestEngine(t)
	if _, err := te.List(context.Background(), ListOptions{Before: []string{"ghost"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("List with an unknown before anchor = %v, want ErrNotFound", err)
	}
}

func TestListReturnsCopies(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	putContainer(t, te, &types.Container{
		Name:   "shared",
		State:  types.StateExited,
		Config: types.ContainerConfig{Labels: map[string]string{"a": "b"}},
	})
	got, err := te.List(ctx, ListOptions{All: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got[0].Config.Labels["a"] = "tampered"
	got[0].Name = "renamed"

	again, err := te.List(ctx, ListOptions{All: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if again[0].Name != "shared" || again[0].Config.Labels["a"] != "b" {
		t.Errorf("the engine handed out a mutable view of its state: %+v", again[0])
	}
}
