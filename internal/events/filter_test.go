package events

import (
	"errors"
	"reflect"
	"testing"

	"github.com/rahuldhali/hull/internal/types"
)

func ev(typ, action, id string, attrs map[string]string) types.Event {
	return types.Event{
		Type:   typ,
		Action: action,
		Scope:  ScopeLocal,
		Actor:  types.EventActor{ID: id, Attributes: attrs},
	}
}

func TestFilterMatch(t *testing.T) {
	const ctrID = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	ctrStart := ev(TypeContainer, ActionStart, ctrID, map[string]string{
		"name":                  "web",
		"image":                 "alpine:3.20",
		"com.docker.compose.pj": "demo",
		"tier":                  "front",
	})
	ctrDie := ev(TypeContainer, ActionDie, ctrID, map[string]string{
		"name": "web", "image": "alpine:3.20", "exitCode": "0",
	})
	imgPull := ev(TypeImage, ActionPull, "sha256:1111", map[string]string{"name": "alpine:3.20"})
	netConnect := ev(TypeNetwork, ActionConnect, "netid99999", map[string]string{
		"name": "hullnet", "type": "bridge", "container": ctrID,
	})
	volCreate := ev(TypeVolume, ActionCreate, "pgdata", nil)
	execCreate := ev(TypeContainer, "exec_create: /bin/sh -c ls", ctrID, map[string]string{"name": "web"})

	tests := []struct {
		name   string
		filter Filter
		event  types.Event
		want   bool
	}{
		{"empty filter matches everything", Filter{}, ctrStart, true},
		{"type match", Filter{Types: []string{TypeContainer}}, ctrStart, true},
		{"type mismatch", Filter{Types: []string{TypeContainer}}, imgPull, false},
		{"type OR", Filter{Types: []string{TypeImage, TypeContainer}}, imgPull, true},

		{"action match", Filter{Actions: []string{ActionStart}}, ctrStart, true},
		{"action mismatch", Filter{Actions: []string{ActionStart}}, ctrDie, false},
		{"action OR", Filter{Actions: []string{ActionStart, ActionDie}}, ctrDie, true},
		{"compound action prefix", Filter{Actions: []string{ActionExecCreate}}, execCreate, true},
		{"compound action exact", Filter{Actions: []string{"exec_create: /bin/sh -c ls"}}, execCreate, true},
		{"compound action wrong", Filter{Actions: []string{ActionExecStart}}, execCreate, false},

		{"keys are ANDed: both hold", Filter{Types: []string{TypeContainer}, Actions: []string{ActionStart}}, ctrStart, true},
		{"keys are ANDed: one fails", Filter{Types: []string{TypeContainer}, Actions: []string{ActionStart}}, ctrDie, false},
		{"keys are ANDed across type+container", Filter{Types: []string{TypeImage}, Containers: []string{ctrID}}, ctrStart, false},

		{"container exact id", Filter{Containers: []string{ctrID}}, ctrStart, true},
		{"container prefix >=3", Filter{Containers: []string{"abcdef"}}, ctrStart, true},
		{"container prefix exactly 3", Filter{Containers: []string{"abc"}}, ctrStart, true},
		{"container prefix too short", Filter{Containers: []string{"ab"}}, ctrStart, false},
		{"container by name", Filter{Containers: []string{"web"}}, ctrStart, true},
		{"container wrong name", Filter{Containers: []string{"api"}}, ctrStart, false},
		{"container filter excludes other types", Filter{Containers: []string{ctrID}}, netConnect, false},
		{"container OR", Filter{Containers: []string{"api", "web"}}, ctrStart, true},

		{"image by name", Filter{Images: []string{"alpine:3.20"}}, imgPull, true},
		{"image by id", Filter{Images: []string{"sha256:1111"}}, imgPull, true},
		{"image wrong", Filter{Images: []string{"busybox"}}, imgPull, false},

		{"network by name", Filter{Networks: []string{"hullnet"}}, netConnect, true},
		{"network by id prefix", Filter{Networks: []string{"netid"}}, netConnect, true},
		{"network wrong", Filter{Networks: []string{"bridge"}}, netConnect, false},

		{"volume by name", Filter{Volumes: []string{"pgdata"}}, volCreate, true},
		{"volume wrong", Filter{Volumes: []string{"other"}}, volCreate, false},

		{"label key present", Filter{Labels: []string{"tier"}}, ctrStart, true},
		{"label key absent", Filter{Labels: []string{"nope"}}, ctrStart, false},
		{"label pair matches", Filter{LabelPairs: map[string]string{"tier": "front"}}, ctrStart, true},
		{"label pair wrong value", Filter{LabelPairs: map[string]string{"tier": "back"}}, ctrStart, false},
		{"label filters are ANDed", Filter{
			Labels:     []string{"tier"},
			LabelPairs: map[string]string{"com.docker.compose.pj": "demo"},
		}, ctrStart, true},
		{"label filters are ANDed: one fails", Filter{
			Labels:     []string{"tier"},
			LabelPairs: map[string]string{"com.docker.compose.pj": "other"},
		}, ctrStart, false},
		{"label filter on event without that label", Filter{Labels: []string{"tier"}}, ctrDie, false},

		{"scope match", Filter{Scopes: []string{ScopeLocal}}, ctrStart, true},
		{"scope mismatch", Filter{Scopes: []string{"swarm"}}, ctrStart, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.filter.Match(tc.event); got != tc.want {
				t.Fatalf("Match() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFilterIsEmpty(t *testing.T) {
	if !(Filter{}).IsEmpty() {
		t.Fatal("zero Filter should be empty")
	}
	if (Filter{Types: []string{"container"}}).IsEmpty() {
		t.Fatal("populated Filter should not be empty")
	}
	if (Filter{LabelPairs: map[string]string{"a": "b"}}).IsEmpty() {
		t.Fatal("label-pair Filter should not be empty")
	}
}

func TestParseFilters(t *testing.T) {
	tests := []struct {
		name    string
		in      map[string][]string
		want    Filter
		wantErr string
	}{
		{name: "nil is empty", in: nil, want: Filter{}},
		{
			name: "docker keys",
			in: map[string][]string{
				"type":      {"container"},
				"event":     {"start", "die"},
				"container": {"web"},
				"image":     {"alpine"},
				"network":   {"hullnet"},
				"volume":    {"pgdata"},
				"scope":     {"local"},
				"daemon":    {"hulld"},
			},
			want: Filter{
				Types:      []string{"container"},
				Actions:    []string{"start", "die"},
				Containers: []string{"web"},
				Images:     []string{"alpine"},
				Networks:   []string{"hullnet"},
				Volumes:    []string{"pgdata"},
				Scopes:     []string{"local"},
				Daemons:    []string{"hulld"},
			},
		},
		{
			name: "action is an alias for event",
			in:   map[string][]string{"action": {"pull"}},
			want: Filter{Actions: []string{"pull"}},
		},
		{
			name: "labels split into presence and pairs",
			in:   map[string][]string{"label": {"tier", "app=web", "empty="}},
			want: Filter{
				Labels:     []string{"tier"},
				LabelPairs: map[string]string{"app": "web", "empty": ""},
			},
		},
		{name: "unknown key", in: map[string][]string{"bogus": {"x"}}, wantErr: "Invalid filter 'bogus'"},
		{
			name:    "swarm-only key is refused with a reason",
			in:      map[string][]string{"node": {"n1"}},
			wantErr: "Invalid filter 'node': hull is not a swarm manager",
		},
		{
			name:    "empty label key",
			in:      map[string][]string{"label": {"=value"}},
			wantErr: "Invalid filter 'label': empty label key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseFilters(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want error %q, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("error = %q, want %q", err.Error(), tc.wantErr)
				}
				var ife *InvalidFilterError
				if !errors.As(err, &ife) {
					t.Fatalf("error %T is not *InvalidFilterError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Filter = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestHelpers(t *testing.T) {
	c := &types.Container{
		ID:       "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Name:     "web",
		Image:    "sha256:deadbeef",
		ImageRef: "alpine:3.20",
		Config: types.ContainerConfig{
			Labels: map[string]string{"com.docker.compose.project": "demo", "tier": "front"},
		},
	}

	e := Container(ActionDie, c, map[string]string{"exitCode": "137"})
	if e.Type != TypeContainer || e.Action != ActionDie || e.Actor.ID != c.ID {
		t.Fatalf("unexpected container event: %+v", e)
	}
	for k, want := range map[string]string{
		"image":                      "alpine:3.20",
		"name":                       "web",
		"com.docker.compose.project": "demo",
		"tier":                       "front",
		"exitCode":                   "137",
	} {
		if got := e.Actor.Attributes[k]; got != want {
			t.Fatalf("attribute %q = %q, want %q", k, got, want)
		}
	}

	// extra wins over derived attributes, and the caller's maps are copied.
	e2 := Container(ActionStart, c, map[string]string{"name": "renamed"})
	if e2.Actor.Attributes["name"] != "renamed" {
		t.Fatalf("extra should override name, got %q", e2.Actor.Attributes["name"])
	}
	e2.Actor.Attributes["tier"] = "mutated"
	if c.Config.Labels["tier"] != "front" {
		t.Fatal("Container() must not alias the container label map")
	}

	if got := Container(ActionStart, nil, nil); got.Actor.ID != "" || got.Actor.Attributes == nil {
		t.Fatalf("nil container should yield an empty actor with a non-nil map: %+v", got)
	}

	// ImageRef falls back to the image ID.
	noRef := &types.Container{ID: "x", Image: "sha256:abc"}
	if got := Container(ActionCreate, noRef, nil).Actor.Attributes["image"]; got != "sha256:abc" {
		t.Fatalf("image attribute = %q, want the image id", got)
	}

	img := Image(ActionPull, "sha256:1111", []string{"alpine:3.20", "alpine:latest"})
	if img.Actor.Attributes["name"] != "alpine:3.20" {
		t.Fatalf("image name = %q", img.Actor.Attributes["name"])
	}
	if img.Actor.Attributes["tags"] != "alpine:3.20,alpine:latest" {
		t.Fatalf("image tags = %q", img.Actor.Attributes["tags"])
	}
	if got := Image(ActionDelete, "sha256:2222", nil); got.Actor.Attributes["name"] != "sha256:2222" {
		t.Fatalf("untagged image name = %q", got.Actor.Attributes["name"])
	}

	n := &types.Network{ID: "nnnn1111", Name: "hullnet", Driver: "bridge", Labels: map[string]string{"k": "v"}}
	ne := Network(ActionConnect, n, "ctr1")
	if ne.Type != TypeNetwork || ne.Actor.Attributes["container"] != "ctr1" ||
		ne.Actor.Attributes["type"] != "bridge" || ne.Actor.Attributes["name"] != "hullnet" ||
		ne.Actor.Attributes["k"] != "v" {
		t.Fatalf("unexpected network event: %+v", ne)
	}
	if got := Network(ActionCreate, n, ""); got.Actor.Attributes["container"] != "" {
		t.Fatal("container attribute should be absent when no container is involved")
	}

	labels := map[string]string{"owner": "me"}
	v := Volume(ActionCreate, "pgdata", labels)
	if v.Actor.ID != "pgdata" || v.Actor.Attributes["owner"] != "me" {
		t.Fatalf("unexpected volume event: %+v", v)
	}
	v.Actor.Attributes["owner"] = "mutated"
	if labels["owner"] != "me" {
		t.Fatal("Volume() must not alias the label map")
	}

	d := Daemon(ActionReload, map[string]string{"id": "hulld-1", "config": "/etc/hull.json"})
	if d.Type != TypeDaemon || d.Actor.ID != "hulld-1" || d.Actor.Attributes["config"] != "/etc/hull.json" {
		t.Fatalf("unexpected daemon event: %+v", d)
	}
	if got := Daemon(ActionReload, nil); got.Actor.Attributes == nil {
		t.Fatal("Daemon() should always carry a non-nil attribute map")
	}
}

func TestContainerActionsComplete(t *testing.T) {
	want := []string{
		"create", "start", "restart", "stop", "die", "kill", "oom", "pause",
		"unpause", "destroy", "rename", "update", "attach", "commit", "copy",
		"exec_create", "exec_start", "exec_die", "export", "health_status",
		"resize", "top", "prune",
	}
	if !reflect.DeepEqual(ContainerActions, want) {
		t.Fatalf("ContainerActions = %v, want %v", ContainerActions, want)
	}
}
