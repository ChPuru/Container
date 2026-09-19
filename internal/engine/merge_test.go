package engine

import (
	"reflect"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

func TestMergeImageConfig(t *testing.T) {
	img := func(c types.ImageConfig) *types.Image { return &types.Image{Config: c} }

	tests := []struct {
		name  string
		user  types.ContainerConfig
		image *types.Image
		want  types.ContainerConfig
	}{
		{
			name:  "image supplies everything",
			user:  types.ContainerConfig{},
			image: img(types.ImageConfig{Entrypoint: []string{"/entry"}, Cmd: []string{"a", "b"}}),
			want:  types.ContainerConfig{Entrypoint: []string{"/entry"}, Cmd: []string{"a", "b"}},
		},
		{
			name:  "user command keeps the image entrypoint",
			user:  types.ContainerConfig{Cmd: []string{"echo", "hi"}},
			image: img(types.ImageConfig{Entrypoint: []string{"/entry"}, Cmd: []string{"a"}}),
			want:  types.ContainerConfig{Entrypoint: []string{"/entry"}, Cmd: []string{"echo", "hi"}},
		},
		{
			name:  "user entrypoint clears the image command",
			user:  types.ContainerConfig{Entrypoint: []string{"/other"}},
			image: img(types.ImageConfig{Entrypoint: []string{"/entry"}, Cmd: []string{"a"}}),
			want:  types.ContainerConfig{Entrypoint: []string{"/other"}},
		},
		{
			name:  "user entrypoint and command both win",
			user:  types.ContainerConfig{Entrypoint: []string{"/other"}, Cmd: []string{"x"}},
			image: img(types.ImageConfig{Entrypoint: []string{"/entry"}, Cmd: []string{"a"}}),
			want:  types.ContainerConfig{Entrypoint: []string{"/other"}, Cmd: []string{"x"}},
		},
		{
			name:  "cleared entrypoint is preserved verbatim",
			user:  types.ContainerConfig{Entrypoint: []string{""}, Cmd: []string{"sh"}},
			image: img(types.ImageConfig{Entrypoint: []string{"/entry"}, Cmd: []string{"a"}}),
			want:  types.ContainerConfig{Entrypoint: []string{""}, Cmd: []string{"sh"}},
		},
		{
			name: "environment merges with the user winning per key",
			user: types.ContainerConfig{Env: []string{"A=user", "C=new"}},
			image: img(types.ImageConfig{
				Env: []string{"A=image", "B=image"},
				Cmd: []string{"sh"},
			}),
			want: types.ContainerConfig{
				Env: []string{"A=user", "B=image", "C=new"},
				Cmd: []string{"sh"},
			},
		},
		{
			name:  "user, workdir and stop signal fall back to the image",
			user:  types.ContainerConfig{},
			image: img(types.ImageConfig{User: "nobody", WorkingDir: "/srv", StopSignal: "SIGQUIT", Cmd: []string{"sh"}}),
			want:  types.ContainerConfig{User: "nobody", WorkingDir: "/srv", StopSignal: "SIGQUIT", Cmd: []string{"sh"}},
		},
		{
			name: "explicit user, workdir and stop signal beat the image",
			user: types.ContainerConfig{User: "root", WorkingDir: "/", StopSignal: "SIGTERM"},
			image: img(types.ImageConfig{
				User: "nobody", WorkingDir: "/srv", StopSignal: "SIGQUIT", Cmd: []string{"sh"},
			}),
			want: types.ContainerConfig{User: "root", WorkingDir: "/", StopSignal: "SIGTERM", Cmd: []string{"sh"}},
		},
		{
			name: "exposed ports and volumes are unions",
			user: types.ContainerConfig{
				ExposedPorts: map[string]struct{}{"443/tcp": {}},
				Volumes:      map[string]struct{}{"/user": {}},
			},
			image: img(types.ImageConfig{
				ExposedPorts: map[string]struct{}{"80/tcp": {}},
				Volumes:      map[string]struct{}{"/data": {}},
				Cmd:          []string{"sh"},
			}),
			want: types.ContainerConfig{
				ExposedPorts: map[string]struct{}{"80/tcp": {}, "443/tcp": {}},
				Volumes:      map[string]struct{}{"/data": {}, "/user": {}},
				Cmd:          []string{"sh"},
			},
		},
		{
			name: "labels layer with the user on top",
			user: types.ContainerConfig{Labels: map[string]string{"a": "user", "c": "user"}},
			image: img(types.ImageConfig{
				Labels: map[string]string{"a": "image", "b": "image"},
				Cmd:    []string{"sh"},
			}),
			want: types.ContainerConfig{
				Labels: map[string]string{"a": "user", "b": "image", "c": "user"},
				Cmd:    []string{"sh"},
			},
		},
		{
			name: "image healthcheck is adopted with defaults filled in",
			user: types.ContainerConfig{},
			image: img(types.ImageConfig{
				Cmd:         []string{"sh"},
				Healthcheck: &types.Healthcheck{Test: []string{"CMD", "true"}},
			}),
			want: types.ContainerConfig{
				Cmd: []string{"sh"},
				Healthcheck: &types.Healthcheck{
					Test:     []string{"CMD", "true"},
					Interval: DefaultHealthInterval,
					Timeout:  DefaultHealthTimeout,
					Retries:  DefaultHealthRetries,
				},
			},
		},
		{
			name: "NONE disables the image healthcheck",
			user: types.ContainerConfig{Healthcheck: &types.Healthcheck{Test: []string{"NONE"}}},
			image: img(types.ImageConfig{
				Cmd:         []string{"sh"},
				Healthcheck: &types.Healthcheck{Test: []string{"CMD", "true"}},
			}),
			want: types.ContainerConfig{Cmd: []string{"sh"}},
		},
		{
			name:  "a nil image leaves the request untouched",
			user:  types.ContainerConfig{Cmd: []string{"sh"}},
			image: nil,
			want:  types.ContainerConfig{Cmd: []string{"sh"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MergeImageConfig(tt.user, tt.image)
			if err != nil {
				t.Fatalf("MergeImageConfig: %v", err)
			}
			if !reflect.DeepEqual(got.Entrypoint, tt.want.Entrypoint) {
				t.Errorf("entrypoint = %q, want %q", got.Entrypoint, tt.want.Entrypoint)
			}
			if !reflect.DeepEqual(got.Cmd, tt.want.Cmd) {
				t.Errorf("cmd = %q, want %q", got.Cmd, tt.want.Cmd)
			}
			if !reflect.DeepEqual(got.Env, tt.want.Env) {
				t.Errorf("env = %q, want %q", got.Env, tt.want.Env)
			}
			if got.User != tt.want.User {
				t.Errorf("user = %q, want %q", got.User, tt.want.User)
			}
			if got.WorkingDir != tt.want.WorkingDir {
				t.Errorf("workingDir = %q, want %q", got.WorkingDir, tt.want.WorkingDir)
			}
			if got.StopSignal != tt.want.StopSignal {
				t.Errorf("stopSignal = %q, want %q", got.StopSignal, tt.want.StopSignal)
			}
			if !reflect.DeepEqual(got.ExposedPorts, tt.want.ExposedPorts) {
				t.Errorf("exposedPorts = %v, want %v", got.ExposedPorts, tt.want.ExposedPorts)
			}
			if !reflect.DeepEqual(got.Volumes, tt.want.Volumes) {
				t.Errorf("volumes = %v, want %v", got.Volumes, tt.want.Volumes)
			}
			if !reflect.DeepEqual(got.Labels, tt.want.Labels) {
				t.Errorf("labels = %v, want %v", got.Labels, tt.want.Labels)
			}
			if !reflect.DeepEqual(got.Healthcheck, tt.want.Healthcheck) {
				t.Errorf("healthcheck = %+v, want %+v", got.Healthcheck, tt.want.Healthcheck)
			}
		})
	}
}

func TestMergeImageConfigDoesNotMutateInputs(t *testing.T) {
	user := types.ContainerConfig{
		Env:    []string{"A=1"},
		Labels: map[string]string{"k": "v"},
	}
	img := &types.Image{Config: types.ImageConfig{
		Env:    []string{"B=2"},
		Labels: map[string]string{"j": "w"},
		Cmd:    []string{"sh"},
	}}
	if _, err := MergeImageConfig(user, img); err != nil {
		t.Fatalf("MergeImageConfig: %v", err)
	}
	if len(user.Env) != 1 || user.Env[0] != "A=1" {
		t.Errorf("the request's environment was mutated: %q", user.Env)
	}
	if len(user.Labels) != 1 {
		t.Errorf("the request's labels were mutated: %v", user.Labels)
	}
	if len(img.Config.Labels) != 1 {
		t.Errorf("the image's labels were mutated: %v", img.Config.Labels)
	}
}

func TestMergeImageConfigRejectsMalformedEnv(t *testing.T) {
	_, err := MergeImageConfig(
		types.ContainerConfig{Env: []string{"NOT_KEY_VALUE"}},
		&types.Image{Config: types.ImageConfig{Cmd: []string{"sh"}}},
	)
	if err == nil {
		t.Fatal("an environment entry without '=' should be rejected")
	}
}

func TestNormalizeHealthcheck(t *testing.T) {
	tests := []struct {
		name string
		in   *types.Healthcheck
		want *types.Healthcheck
	}{
		{name: "nil stays nil"},
		{name: "empty test is dropped", in: &types.Healthcheck{}},
		{name: "NONE is dropped", in: &types.Healthcheck{Test: []string{"NONE"}}},
		{name: "CMD with no command is dropped", in: &types.Healthcheck{Test: []string{"CMD"}}},
		{
			name: "explicit values survive",
			in: &types.Healthcheck{
				Test:        []string{"CMD", "true"},
				Interval:    time.Second,
				Timeout:     2 * time.Second,
				StartPeriod: 3 * time.Second,
				Retries:     7,
			},
			want: &types.Healthcheck{
				Test:        []string{"CMD", "true"},
				Interval:    time.Second,
				Timeout:     2 * time.Second,
				StartPeriod: 3 * time.Second,
				Retries:     7,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeHealthcheck(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("normalizeHealthcheck = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestHealthcheckCommand(t *testing.T) {
	tests := []struct {
		name    string
		test    []string
		shell   []string
		want    []string
		wantErr bool
	}{
		{name: "exec form", test: []string{"CMD", "curl", "-f", "/"}, want: []string{"curl", "-f", "/"}},
		{
			name: "shell form uses the default shell",
			test: []string{"CMD-SHELL", "curl -f /"},
			want: []string{"/bin/sh", "-c", "curl -f /"},
		},
		{
			name:  "shell form honours the image shell",
			test:  []string{"CMD-SHELL", "check"},
			shell: []string{"/bin/bash", "-c"},
			want:  []string{"/bin/bash", "-c", "check"},
		},
		{
			name: "legacy bare string is treated as a shell command",
			test: []string{"check", "me"},
			want: []string{"/bin/sh", "-c", "check me"},
		},
		{name: "NONE is an error", test: []string{"NONE"}, wantErr: true},
		{name: "CMD with no command is an error", test: []string{"CMD"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HealthcheckCommand(&types.Healthcheck{Test: tt.test}, tt.shell)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("HealthcheckCommand: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HealthcheckCommand = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPublishAllBindings(t *testing.T) {
	cfg := types.ContainerConfig{ExposedPorts: map[string]struct{}{
		"80/tcp":  {},
		"443/tcp": {},
		"53/udp":  {},
	}}
	existing := map[string][]types.PortBinding{"80/tcp": {{HostPort: "8080"}}}
	got := publishAllBindings(cfg, existing)
	if len(got) != 3 {
		t.Fatalf("publishAllBindings produced %d bindings, want 3: %v", len(got), got)
	}
	if got["80/tcp"][0].HostPort != "8080" {
		t.Errorf("an explicit binding was overwritten: %v", got["80/tcp"])
	}
	if got["443/tcp"][0].HostPort != "" {
		t.Errorf("a synthesised binding should leave the host port to the kernel: %v", got["443/tcp"])
	}
}
