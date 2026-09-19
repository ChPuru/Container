package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/engine"
	"github.com/rahuldhali/hull/internal/logbuf"
	"github.com/rahuldhali/hull/internal/oci/registry"
	"github.com/rahuldhali/hull/internal/types"
)

// newTestServer builds a server over a fresh fake backend.
func newTestServer(t *testing.T) (*Server, *fakeBackend) {
	t.Helper()
	be := newFakeBackend()
	// A buildkit address that cannot exist keeps the probe deterministic:
	// every test host must answer "no buildkitd" the same way.
	srv, err := NewWithBackend(be, Options{
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		BuildKitAddr: filepath.Join(t.TempDir(), "absent-buildkitd.sock"),
		DataRoot:     "/var/lib/hull",
	})
	if err != nil {
		t.Fatalf("NewWithBackend: %v", err)
	}
	return srv, be
}

// do runs one request against the server's handler.
func do(t *testing.T, s *Server, method, target string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// decode unmarshals a recorder's body, failing the test on bad JSON.
func decode(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Version
		wantErr bool
	}{
		{name: "plain", in: "1.43", want: Version{1, 43}},
		{name: "v prefixed", in: "v1.24", want: Version{1, 24}},
		{name: "spaces", in: " 1.41 ", want: Version{1, 41}},
		{name: "no minor", in: "1", wantErr: true},
		{name: "not a number", in: "x.y", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "negative", in: "1.-2", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseVersion(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseVersion(%q) = %v, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseVersion(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseVersion(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSplitVersionPrefix(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		wantRest    string
		wantVersion string
		wantPrefix  bool
	}{
		{name: "versioned", path: "/v1.43/containers/json", wantRest: "/containers/json", wantVersion: "1.43", wantPrefix: true},
		{name: "versioned root", path: "/v1.43", wantRest: "/", wantVersion: "1.43", wantPrefix: true},
		{name: "unversioned", path: "/containers/json", wantRest: "/containers/json"},
		{name: "volumes is not a version", path: "/volumes", wantRest: "/volumes"},
		{name: "version is not a version", path: "/version", wantRest: "/version"},
		{name: "v with no dot", path: "/v143/info", wantRest: "/v143/info"},
		{name: "ping", path: "/v1.24/_ping", wantRest: "/_ping", wantVersion: "1.24", wantPrefix: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rest, version, had := splitVersionPrefix(tc.path)
			if rest != tc.wantRest || version != tc.wantVersion || had != tc.wantPrefix {
				t.Fatalf("splitVersionPrefix(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.path, rest, version, had, tc.wantRest, tc.wantVersion, tc.wantPrefix)
			}
		})
	}
}

func TestVersionGating(t *testing.T) {
	s, _ := newTestServer(t)
	tests := []struct {
		name       string
		target     string
		wantStatus int
		wantSubstr string
	}{
		{name: "current", target: "/v1.43/_ping", wantStatus: http.StatusOK},
		{name: "older supported", target: "/v1.24/_ping", wantStatus: http.StatusOK},
		{name: "unversioned", target: "/_ping", wantStatus: http.StatusOK},
		{
			name: "too new", target: "/v1.99/_ping",
			wantStatus: http.StatusBadRequest,
			wantSubstr: "client version 1.99 is too new. Maximum supported API version is 1.43",
		},
		{
			name: "too old", target: "/v1.20/_ping",
			wantStatus: http.StatusBadRequest,
			wantSubstr: "client version 1.20 is too old. Minimum supported API version is 1.24",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, s, http.MethodGet, tc.target, nil)
			if rec.Code != tc.wantStatus {
				t.Fatalf("GET %s = %d, want %d (body %q)", tc.target, rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantSubstr != "" {
				var e ErrorResponse
				decode(t, rec, &e)
				if !strings.Contains(e.Message, tc.wantSubstr) {
					t.Fatalf("message = %q, want it to contain %q", e.Message, tc.wantSubstr)
				}
			}
		})
	}
}

func TestPingHeaders(t *testing.T) {
	s, _ := newTestServer(t)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			rec := do(t, s, method, "/v1.43/_ping", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s /_ping = %d", method, rec.Code)
			}
			want := map[string]string{
				"Api-Version":         "1.43",
				"Docker-Experimental": "false",
				"OSType":              "linux",
				"Builder-Version":     "1",
			}
			for k, v := range want {
				if got := rec.Header().Get(k); got != v {
					t.Errorf("header %s = %q, want %q", k, got, v)
				}
			}
			if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
				t.Errorf("Cache-Control = %q, want it to contain no-cache", cc)
			}
			if method == http.MethodGet && rec.Body.String() != "OK" {
				t.Errorf("body = %q, want OK", rec.Body.String())
			}
		})
	}
}

func TestRouterMatching(t *testing.T) {
	rt := &router{}
	hit := func(name string) handlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("X-Route", name)
			return nil
		}
	}
	rt.handle(http.MethodGet, "/images/json", hit("images-list"))
	rt.handle(http.MethodGet, "/images/{name...}/json", hit("image-inspect"))
	rt.handle(http.MethodDelete, "/images/{name...}", hit("image-delete"))
	rt.handle(http.MethodGet, "/containers/{id}/json", hit("container-inspect"))

	tests := []struct {
		name      string
		method    string
		path      string
		wantRoute string
		wantVar   string
		wantVal   string
		wantMiss  bool
	}{
		{name: "fixed beats greedy", method: http.MethodGet, path: "/images/json", wantRoute: "images-list"},
		{name: "single segment name", method: http.MethodGet, path: "/images/alpine/json", wantRoute: "image-inspect", wantVar: "name", wantVal: "alpine"},
		{
			name: "reference with slashes", method: http.MethodGet,
			path: "/images/ghcr.io/team/app/json", wantRoute: "image-inspect",
			wantVar: "name", wantVal: "ghcr.io/team/app",
		},
		{name: "delete with slashes", method: http.MethodDelete, path: "/images/ghcr.io/team/app", wantRoute: "image-delete", wantVar: "name", wantVal: "ghcr.io/team/app"},
		{name: "container id", method: http.MethodGet, path: "/containers/abc/json", wantRoute: "container-inspect", wantVar: "id", wantVal: "abc"},
		{name: "unknown path", method: http.MethodGet, path: "/nope", wantMiss: true},
		{name: "wrong method", method: http.MethodPost, path: "/images/json", wantMiss: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, v, _ := rt.lookup(tc.method, tc.path)
			if tc.wantMiss {
				if h != nil {
					t.Fatalf("lookup(%s %s) matched, want no handler", tc.method, tc.path)
				}
				return
			}
			if h == nil {
				t.Fatalf("lookup(%s %s) found no handler", tc.method, tc.path)
			}
			rec := httptest.NewRecorder()
			if err := h(rec, httptest.NewRequest(tc.method, tc.path, nil)); err != nil {
				t.Fatalf("handler: %v", err)
			}
			if got := rec.Header().Get("X-Route"); got != tc.wantRoute {
				t.Fatalf("route = %q, want %q", got, tc.wantRoute)
			}
			if tc.wantVar != "" && v[tc.wantVar] != tc.wantVal {
				t.Fatalf("var %s = %q, want %q", tc.wantVar, v[tc.wantVar], tc.wantVal)
			}
		})
	}
}

func TestUnknownRouteAndMethod(t *testing.T) {
	s, _ := newTestServer(t)

	rec := do(t, s, http.MethodGet, "/v1.43/nope", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d, want 404", rec.Code)
	}
	var e ErrorResponse
	decode(t, rec, &e)
	if e.Message != "page not found" {
		t.Fatalf("message = %q", e.Message)
	}

	rec = do(t, s, http.MethodDelete, "/v1.43/_ping", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "GET") {
		t.Fatalf("Allow = %q, want it to list GET", allow)
	}
}

func TestParseFilterArgs(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		want    map[string][]string
		wantErr bool
	}{
		{name: "absent", query: "", want: nil},
		{
			name:  "modern",
			query: `{"status":["running"],"label":["a=b","c"]}`,
			want:  map[string][]string{"status": {"running"}, "label": {"a=b", "c"}},
		},
		{
			name:  "legacy map of bool",
			query: `{"status":{"running":true,"paused":false}}`,
			want:  map[string][]string{"status": {"running"}},
		},
		{name: "malformed", query: `{`, wantErr: true},
		{name: "wrong shape", query: `["running"]`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := "/containers/json"
			if tc.query != "" {
				target += "?filters=" + url.QueryEscape(tc.query)
			}
			r := httptest.NewRequest(http.MethodGet, target, nil)
			got, err := parseFilterArgs(r)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseFilterArgs(%q) = %v, want an error", tc.query, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFilterArgs(%q): %v", tc.query, err)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("parseFilterArgs(%q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}

func TestFilterKeysAllowed(t *testing.T) {
	tests := []struct {
		name    string
		filters map[string][]string
		allowed []string
		wantErr string
	}{
		{name: "empty", filters: nil, allowed: []string{"label"}},
		{name: "known", filters: map[string][]string{"label": {"a"}}, allowed: []string{"label", "until"}},
		{
			name:    "unknown",
			filters: map[string][]string{"bogus": {"a"}},
			allowed: []string{"label"},
			wantErr: "Invalid filter 'bogus'",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := filterKeysAllowed(tc.filters, tc.allowed...)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("filterKeysAllowed: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
			if got := httpStatusOf(err); got != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", got)
			}
		})
	}
}

func TestContainerListRejectsUnknownFilter(t *testing.T) {
	s, _ := newTestServer(t)
	rec := do(t, s, http.MethodGet,
		"/v1.43/containers/json?filters="+url.QueryEscape(`{"bogus":["x"]}`), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var e ErrorResponse
	decode(t, rec, &e)
	if !strings.Contains(e.Message, "Invalid filter 'bogus'") {
		t.Fatalf("message = %q", e.Message)
	}
}

func TestErrorShapes(t *testing.T) {
	s, be := newTestServer(t)
	be.images["alpine:3.20"] = &types.Image{ID: "sha256:img", RepoTags: []string{"alpine:3.20"}}
	running, err := be.Create(context.Background(), "web", types.ContainerConfig{}, types.HostConfig{}, "alpine:3.20")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	running.State = types.StateRunning

	tests := []struct {
		name       string
		method     string
		target     string
		body       io.Reader
		wantStatus int
		wantSubstr string
	}{
		{
			name: "no such container", method: http.MethodGet, target: "/v1.43/containers/ghost/json",
			wantStatus: http.StatusNotFound, wantSubstr: "No such container: ghost",
		},
		{
			name: "no such image", method: http.MethodGet, target: "/v1.43/images/ghost/json",
			wantStatus: http.StatusNotFound, wantSubstr: "No such image: ghost",
		},
		{
			name: "no such network", method: http.MethodGet, target: "/v1.43/networks/ghost",
			wantStatus: http.StatusNotFound, wantSubstr: "network ghost not found",
		},
		{
			name: "no such volume", method: http.MethodGet, target: "/v1.43/volumes/ghost",
			wantStatus: http.StatusNotFound, wantSubstr: "no such volume",
		},
		{
			name: "name conflict", method: http.MethodPost, target: "/v1.43/containers/create?name=web",
			body:       strings.NewReader(`{"Image":"alpine:3.20"}`),
			wantStatus: http.StatusConflict, wantSubstr: `The container name "/web" is already in use`,
		},
		{
			name: "running container cannot be removed", method: http.MethodDelete,
			target:     "/v1.43/containers/web",
			wantStatus: http.StatusConflict, wantSubstr: "You cannot remove a running container",
		},
		{
			name: "missing image field", method: http.MethodPost, target: "/v1.43/containers/create",
			body:       strings.NewReader(`{}`),
			wantStatus: http.StatusBadRequest, wantSubstr: "Config.Image is required",
		},
		{
			name: "malformed json", method: http.MethodPost, target: "/v1.43/containers/create",
			body:       strings.NewReader(`{oops`),
			wantStatus: http.StatusBadRequest, wantSubstr: "invalid JSON body",
		},
		{
			name: "bad wait condition", method: http.MethodPost, target: "/v1.43/containers/web/wait?condition=soon",
			wantStatus: http.StatusBadRequest, wantSubstr: `invalid condition "soon"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, s, tc.method, tc.target, tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s = %d, want %d (body %q)", tc.method, tc.target, rec.Code, tc.wantStatus, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			var e ErrorResponse
			decode(t, rec, &e)
			if !strings.Contains(e.Message, tc.wantSubstr) {
				t.Fatalf("message = %q, want it to contain %q", e.Message, tc.wantSubstr)
			}
		})
	}
}

func TestHTTPStatusOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "not found", err: fmt.Errorf("x: %w", engine.ErrNotFound), want: http.StatusNotFound},
		{name: "conflict", err: fmt.Errorf("x: %w", engine.ErrConflict), want: http.StatusConflict},
		{name: "running", err: fmt.Errorf("x: %w", engine.ErrRunning), want: http.StatusConflict},
		{name: "not running", err: fmt.Errorf("x: %w", engine.ErrNotRunning), want: http.StatusConflict},
		{name: "paused", err: fmt.Errorf("x: %w", engine.ErrPaused), want: http.StatusConflict},
		{name: "invalid", err: fmt.Errorf("x: %w", engine.ErrInvalid), want: http.StatusBadRequest},
		{name: "unsupported", err: fmt.Errorf("x: %w", engine.ErrUnsupported), want: http.StatusNotImplemented},
		{name: "closed", err: fmt.Errorf("x: %w", engine.ErrClosed), want: http.StatusServiceUnavailable},
		{name: "cancelled", err: context.Canceled, want: statusClientClosedRequest},
		{name: "explicit", err: errStatus(http.StatusTeapot, "nope"), want: http.StatusTeapot},
		{name: "unknown", err: errors.New("boom"), want: http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := httpStatusOf(tc.err); got != tc.want {
				t.Fatalf("httpStatusOf(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

func TestErrorMessageStripsEnginePrefixes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "sentinel prefix", err: fmt.Errorf("%w: web is running", engine.ErrRunning), want: "web is running"},
		{name: "plain engine prefix", err: errors.New("engine: open state store: denied"), want: "open state store: denied"},
		{name: "explicit message wins", err: errStatus(404, "No such container: x"), want: "No such container: x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := errorMessage(tc.err); got != tc.want {
				t.Fatalf("errorMessage = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestContainerInspectShape(t *testing.T) {
	s, be := newTestServer(t)
	c := be.addContainer(&types.Container{
		ID:       "abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
		Name:     "web",
		Created:  time.Unix(1700000000, 0).UTC(),
		Image:    "sha256:img",
		ImageRef: "nginx:1.27",
		State:    types.StateRunning,
		Pid:      1234,
		Config: types.ContainerConfig{
			Hostname:     "web",
			Entrypoint:   []string{"/docker-entrypoint.sh"},
			Cmd:          []string{"nginx", "-g", "daemon off;"},
			ExposedPorts: map[string]struct{}{"80/tcp": {}, "443/tcp": {}},
			Labels:       map[string]string{"com.example": "yes"},
		},
		HostConfig: types.HostConfig{
			NetworkMode: "bridge",
			LogConfig:   types.LogConfig{Type: "json-file"},
		},
		NetworkSettings: types.NetworkSettings{
			SandboxKey: "/proc/1234/ns/net",
			Networks: map[string]types.EndpointSettings{
				"hull0": {
					NetworkID:   "net1",
					EndpointID:  "ep1",
					IPAddress:   "10.66.0.2",
					IPPrefixLen: 24,
					Gateway:     "10.66.0.1",
					MacAddress:  "5a:69:1b:d6:a6:fd",
				},
			},
			Ports: map[string][]types.PortBinding{
				"80/tcp": {{HostIP: "0.0.0.0", HostPort: "8080"}},
			},
		},
	})
	be.warnings[c.ID] = []string{"memory limit not enforced: no cgroup v2 controllers are delegated"}

	rec := do(t, s, http.MethodGet, "/v1.43/containers/web/json", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var doc ContainerJSON
	decode(t, rec, &doc)

	if doc.Name != "/web" {
		t.Errorf("Name = %q, want %q — compose matches on the leading slash", doc.Name, "/web")
	}
	if doc.ID != c.ID {
		t.Errorf("Id = %q, want %q", doc.ID, c.ID)
	}
	if doc.Path != "/docker-entrypoint.sh" {
		t.Errorf("Path = %q", doc.Path)
	}
	if strings.Join(doc.Args, " ") != "nginx -g daemon off;" {
		t.Errorf("Args = %v", doc.Args)
	}
	if doc.State == nil || doc.State.Status != "running" || !doc.State.Running || doc.State.Pid != 1234 {
		t.Errorf("State = %+v", doc.State)
	}
	if doc.Platform != "linux" || doc.Driver != "overlay2" {
		t.Errorf("Platform/Driver = %q/%q", doc.Platform, doc.Driver)
	}
	wantResolv := filepath.Join("/var/lib/hull", "containers", c.ID, "resolv.conf")
	if doc.ResolvConfPath != wantResolv {
		t.Errorf("ResolvConfPath = %q, want %q", doc.ResolvConfPath, wantResolv)
	}
	if doc.HostConfig == nil || doc.HostConfig.NetworkMode != "bridge" {
		t.Errorf("HostConfig = %+v", doc.HostConfig)
	}
	if doc.Config == nil || doc.Config.Image != "nginx:1.27" {
		t.Errorf("Config = %+v", doc.Config)
	}
	if doc.NetworkSettings == nil {
		t.Fatal("NetworkSettings is nil")
	}
	if doc.NetworkSettings.IPAddress != "10.66.0.2" {
		t.Errorf("flattened IPAddress = %q", doc.NetworkSettings.IPAddress)
	}
	ep := doc.NetworkSettings.Networks["hull0"]
	if ep == nil || ep.IPAddress != "10.66.0.2" || ep.IPPrefixLen != 24 {
		t.Errorf("Networks[hull0] = %+v", ep)
	}
	// Published and exposed ports are both present, and an unpublished one
	// maps to null exactly as Docker sends it.
	if got := doc.NetworkSettings.Ports["80/tcp"]; len(got) != 1 || got[0].HostPort != "8080" {
		t.Errorf("Ports[80/tcp] = %+v", got)
	}
	if got, ok := doc.NetworkSettings.Ports["443/tcp"]; !ok || got != nil {
		t.Errorf("Ports[443/tcp] = %+v, want a present null", got)
	}
	if doc.Config.Labels[WarningsLabel] == "" {
		t.Errorf("warnings did not reach the inspect document: %v", doc.Config.Labels)
	}
}

func TestContainerListShape(t *testing.T) {
	s, be := newTestServer(t)
	be.addContainer(&types.Container{
		ID:        "1111111111111111111111111111111111111111111111111111111111111111",
		Name:      "web",
		Created:   time.Unix(1700000000, 0).UTC(),
		Image:     "sha256:img",
		ImageRef:  "nginx:1.27",
		State:     types.StateRunning,
		StartedAt: time.Now().Add(-3 * time.Minute),
		Config: types.ContainerConfig{
			Cmd:          []string{"nginx"},
			ExposedPorts: map[string]struct{}{"443/tcp": {}},
		},
		HostConfig: types.HostConfig{NetworkMode: "bridge"},
		NetworkSettings: types.NetworkSettings{
			Networks: map[string]types.EndpointSettings{},
			Ports:    map[string][]types.PortBinding{"80/tcp": {{HostIP: "0.0.0.0", HostPort: "8080"}}},
		},
	})

	rec := do(t, s, http.MethodGet, "/v1.43/containers/json", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var list []ContainerSummary
	decode(t, rec, &list)
	if len(list) != 1 {
		t.Fatalf("got %d containers, want 1", len(list))
	}
	got := list[0]
	if len(got.Names) != 1 || got.Names[0] != "/web" {
		t.Errorf("Names = %v, want [/web]", got.Names)
	}
	if got.State != "running" {
		t.Errorf("State = %q", got.State)
	}
	if !strings.HasPrefix(got.Status, "Up ") {
		t.Errorf("Status = %q, want it to start with \"Up \"", got.Status)
	}
	if got.Created != time.Unix(1700000000, 0).Unix() {
		t.Errorf("Created = %d, want unix seconds", got.Created)
	}
	// The list uses the flat Port shape, not the inspect map.
	var published, exposed bool
	for _, p := range got.Ports {
		if p.PrivatePort == 80 && p.PublicPort == 8080 && p.Type == "tcp" && p.IP == "0.0.0.0" {
			published = true
		}
		if p.PrivatePort == 443 && p.PublicPort == 0 {
			exposed = true
		}
	}
	if !published || !exposed {
		t.Errorf("Ports = %+v, want both the published 80 and the exposed 443", got.Ports)
	}
}

func TestHumanStatus(t *testing.T) {
	now := time.Unix(1700003600, 0).UTC()
	tests := []struct {
		name string
		c    *types.Container
		want string
	}{
		{name: "created", c: &types.Container{State: types.StateCreated}, want: "Created"},
		{
			name: "running", c: &types.Container{State: types.StateRunning, StartedAt: now.Add(-3 * time.Minute)},
			want: "Up 3 minutes",
		},
		{
			name: "healthy", c: &types.Container{
				State: types.StateRunning, StartedAt: now.Add(-3 * time.Minute),
				Health: &types.HealthState{Status: "healthy"},
			},
			want: "Up 3 minutes (healthy)",
		},
		{
			name: "paused", c: &types.Container{State: types.StatePaused, StartedAt: now.Add(-time.Hour)},
			want: "Up About an hour (Paused)",
		},
		{
			name: "exited", c: &types.Container{State: types.StateExited, ExitCode: 137, FinishedAt: now.Add(-2 * time.Hour)},
			want: "Exited (137) 2 hours ago",
		},
		{name: "dead", c: &types.Container{State: types.StateDead}, want: "Dead"},
		{name: "removing", c: &types.Container{State: types.StateRemoving}, want: "Removal In Progress"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := humanStatus(tc.c, now); got != tc.want {
				t.Fatalf("humanStatus = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCreateSurfacesWarnings(t *testing.T) {
	s, be := newTestServer(t)
	be.images["alpine:3.20"] = &types.Image{ID: "sha256:img"}
	// The engine records a warning against the new id; the fake keys it off
	// the id it is about to mint.
	be.warnings[fmt.Sprintf("%064x", 1)] = []string{
		"memory limit not enforced: this host delegates no cgroup v2 controllers",
	}

	rec := do(t, s, http.MethodPost, "/v1.43/containers/create",
		strings.NewReader(`{"Image":"alpine:3.20","Cmd":["sh"]}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp ContainerCreateResponse
	decode(t, rec, &resp)
	if resp.ID == "" {
		t.Fatal("no id returned")
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "memory limit not enforced") {
		t.Fatalf("Warnings = %v, want the unenforceable-limit warning to reach the client", resp.Warnings)
	}
}

func TestProgressStreamCarriesErrorInsideA200(t *testing.T) {
	s, be := newTestServer(t)
	be.pullFn = func(_ context.Context, _ string, _ *types.Platform, _ func(registry.ProgressEvent)) (*types.Image, error) {
		return nil, errors.New("engine: pull alpine: manifest unknown")
	}

	rec := do(t, s, http.MethodPost, "/v1.43/images/create?fromImage=alpine&tag=3.20", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: a failure after the header must live in the stream", rec.Code)
	}
	msgs := decodeStream(t, rec.Body.Bytes())
	last := msgs[len(msgs)-1]
	if last.Error == "" || last.ErrorDetail == nil {
		t.Fatalf("last message = %+v, want errorDetail and error", last)
	}
	if !strings.Contains(last.Error, "manifest unknown") {
		t.Fatalf("error = %q", last.Error)
	}
}

func TestPullProgressObjects(t *testing.T) {
	s, be := newTestServer(t)
	be.images["alpine:3.20"] = &types.Image{ID: "sha256:img"}

	rec := do(t, s, http.MethodPost, "/v1.43/images/create?fromImage=alpine&tag=3.20", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	msgs := decodeStream(t, rec.Body.Bytes())
	if len(msgs) < 3 {
		t.Fatalf("got %d messages, want at least 3: %+v", len(msgs), msgs)
	}
	var sawDownloading bool
	for _, m := range msgs {
		if m.Status == "Downloading" {
			sawDownloading = true
			if m.ProgressDetail == nil || m.ProgressDetail.Total != 10 || m.ProgressDetail.Current != 5 {
				t.Fatalf("progressDetail = %+v", m.ProgressDetail)
			}
			if m.Progress == "" {
				t.Fatal("progress bar is empty")
			}
			if m.ID == "" {
				t.Fatal("progress object has no layer id")
			}
		}
	}
	if !sawDownloading {
		t.Fatalf("no Downloading object in %+v", msgs)
	}
}

// decodeStream parses a newline-delimited JSON progress stream.
func decodeStream(t *testing.T, body []byte) []JSONMessage {
	t.Helper()
	var out []JSONMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	for {
		var m JSONMessage
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("decode progress stream %q: %v", body, err)
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		t.Fatalf("empty progress stream")
	}
	return out
}

func TestProgressWriterFlushesEachObject(t *testing.T) {
	var buf bytes.Buffer
	pw := newProgressWriterTo(&buf)
	pw.Status("Pulling from %s", "alpine")
	pw.Write(JSONMessage{ID: "abc", Status: "Downloading", ProgressDetail: &ProgressDetail{Current: 1, Total: 2}})
	pw.Fail(errors.New("engine: boom"))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3 newline-delimited objects:\n%s", len(lines), buf.String())
	}
	var last JSONMessage
	if err := json.Unmarshal([]byte(lines[2]), &last); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if last.Error != "boom" || last.ErrorDetail == nil || last.ErrorDetail.Message != "boom" {
		t.Fatalf("final object = %+v, want the engine prefix stripped", last)
	}
}

func TestHijackHandshakeBytes(t *testing.T) {
	tests := []struct {
		name          string
		upgradeHeader string
		wantFirstLine string
		wantUpgrade   bool
	}{
		{
			name: "with upgrade", upgradeHeader: "tcp",
			wantFirstLine: "HTTP/1.1 101 UPGRADED", wantUpgrade: true,
		},
		{
			name: "without upgrade", upgradeHeader: "",
			wantFirstLine: "HTTP/1.1 200 OK",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, be := newTestServer(t)
			c := be.addContainer(&types.Container{
				ID: "cafe000000000000000000000000000000000000000000000000000000000000", Name: "web",
				State:           types.StateRunning,
				NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{}},
			})
			_ = c

			hs := httptest.NewServer(s.Handler())
			defer hs.Close()

			conn, err := net.Dial("tcp", strings.TrimPrefix(hs.URL, "http://"))
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = conn.Close() }()

			req := "POST /v1.43/containers/web/attach?stream=1&stdout=1 HTTP/1.1\r\n" +
				"Host: hull\r\n"
			if tc.upgradeHeader != "" {
				req += "Upgrade: " + tc.upgradeHeader + "\r\nConnection: Upgrade\r\n"
			}
			req += "\r\n"
			if _, err := conn.Write([]byte(req)); err != nil {
				t.Fatalf("write: %v", err)
			}

			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			br := bufio.NewReader(conn)
			line, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("read status line: %v", err)
			}
			if strings.TrimRight(line, "\r\n") != tc.wantFirstLine {
				t.Fatalf("status line = %q, want %q", strings.TrimRight(line, "\r\n"), tc.wantFirstLine)
			}

			headers := map[string]string{}
			for {
				h, herr := br.ReadString('\n')
				if herr != nil {
					t.Fatalf("read header: %v", herr)
				}
				h = strings.TrimRight(h, "\r\n")
				if h == "" {
					break
				}
				k, v, _ := strings.Cut(h, ": ")
				headers[k] = v
			}
			if headers["Content-Type"] != RawStreamContentType {
				t.Fatalf("Content-Type = %q, want %q", headers["Content-Type"], RawStreamContentType)
			}
			if tc.wantUpgrade {
				if headers["Connection"] != "Upgrade" || headers["Upgrade"] != "tcp" {
					t.Fatalf("headers = %v, want Connection: Upgrade and Upgrade: tcp", headers)
				}
			} else if _, ok := headers["Upgrade"]; ok {
				t.Fatalf("plain handshake must not carry an Upgrade header: %v", headers)
			}

			payload := make([]byte, len("attached"))
			if _, err := io.ReadFull(br, payload); err != nil {
				t.Fatalf("read stream payload: %v", err)
			}
			if string(payload) != "attached" {
				t.Fatalf("payload = %q, want %q", payload, "attached")
			}
		})
	}
}

func TestHandshakeBytesAreExact(t *testing.T) {
	upReq := httptest.NewRequest(http.MethodPost, "/containers/x/attach", nil)
	upReq.Header.Set("Upgrade", "tcp")
	got := string(handshakeFor(upReq))
	want := "HTTP/1.1 101 UPGRADED\r\n" +
		"Content-Type: application/vnd.docker.raw-stream\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: tcp\r\n" +
		"\r\n"
	if got != want {
		t.Fatalf("upgrade handshake = %q, want %q", got, want)
	}

	plainReq := httptest.NewRequest(http.MethodPost, "/containers/x/attach", nil)
	got = string(handshakeFor(plainReq))
	want = "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/vnd.docker.raw-stream\r\n" +
		"\r\n"
	if got != want {
		t.Fatalf("plain handshake = %q, want %q", got, want)
	}
}

func TestExecLifecycle(t *testing.T) {
	s, be := newTestServer(t)
	be.addContainer(&types.Container{
		ID: "beef000000000000000000000000000000000000000000000000000000000000", Name: "web",
		State:           types.StateRunning,
		NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{}},
	})

	rec := do(t, s, http.MethodPost, "/v1.43/containers/web/exec",
		strings.NewReader(`{"Cmd":["sh","-c","echo hi"],"AttachStdout":true}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("exec create = %d: %s", rec.Code, rec.Body.String())
	}
	var created IDResponse
	decode(t, rec, &created)
	if created.ID == "" {
		t.Fatal("no exec id")
	}

	rec = do(t, s, http.MethodGet, "/v1.43/exec/"+created.ID+"/json", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("exec inspect = %d", rec.Code)
	}
	var in ExecInspect
	decode(t, rec, &in)
	if in.ProcessConfig == nil || in.ProcessConfig.Entrypoint != "sh" {
		t.Fatalf("ProcessConfig = %+v", in.ProcessConfig)
	}
	if len(in.ProcessConfig.Arguments) != 2 {
		t.Fatalf("Arguments = %v", in.ProcessConfig.Arguments)
	}

	rec = do(t, s, http.MethodGet, "/v1.43/exec/nope/json", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing exec = %d, want 404", rec.Code)
	}
	var e ErrorResponse
	decode(t, rec, &e)
	if !strings.Contains(e.Message, "No such exec instance") {
		t.Fatalf("message = %q", e.Message)
	}
}

func TestExecStartDetachIsNotHijacked(t *testing.T) {
	s, be := newTestServer(t)
	be.addContainer(&types.Container{
		ID: "beef000000000000000000000000000000000000000000000000000000000000", Name: "web",
		State:           types.StateRunning,
		NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{}},
	})
	done := make(chan struct{})
	be.execFn = func(_ context.Context, _ string, _ engine.AttachConfig) error {
		close(done)
		return nil
	}

	rec := do(t, s, http.MethodPost, "/v1.43/containers/web/exec",
		strings.NewReader(`{"Cmd":["true"]}`))
	var created IDResponse
	decode(t, rec, &created)

	rec = do(t, s, http.MethodPost, "/v1.43/exec/"+created.ID+"/start",
		strings.NewReader(`{"Detach":true}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("detached start = %d: %s", rec.Code, rec.Body.String())
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a detached exec never ran")
	}
}

func TestEventsReplaysFromSince(t *testing.T) {
	s, be := newTestServer(t)
	be.bus.Publish(types.Event{
		Type:   "container",
		Action: "create",
		Actor:  types.EventActor{ID: "abc", Attributes: map[string]string{"name": "web", "image": "alpine"}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/v1.43/events?since=1", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var ev Event
	line, _, _ := strings.Cut(strings.TrimSpace(rec.Body.String()), "\n")
	if line == "" {
		t.Fatal("no replayed event: compose would hang waiting for the container it just created")
	}
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		t.Fatalf("decode %q: %v", line, err)
	}
	if ev.Type != "container" || ev.Action != "create" || ev.Actor.ID != "abc" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Status != "create" || ev.ID != "abc" || ev.From != "alpine" {
		t.Fatalf("legacy fields missing: %+v", ev)
	}
}

func TestEventsRejectsUnknownFilter(t *testing.T) {
	s, _ := newTestServer(t)
	rec := do(t, s, http.MethodGet,
		"/v1.43/events?filters="+url.QueryEscape(`{"bogus":["x"]}`), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %q)", rec.Code, rec.Body.String())
	}
	var e ErrorResponse
	decode(t, rec, &e)
	if !strings.Contains(e.Message, "Invalid filter") {
		t.Fatalf("message = %q", e.Message)
	}
}

func TestLogsFramingFollowsTheContainerNotTheClient(t *testing.T) {
	tests := []struct {
		name       string
		tty        bool
		wantFramed bool
		wantType   string
	}{
		{name: "no tty is framed", tty: false, wantFramed: true, wantType: MultiplexedStreamContentType},
		{name: "tty is raw", tty: true, wantFramed: false, wantType: RawStreamContentType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, be := newTestServer(t)
			be.addContainer(&types.Container{
				ID: "1234000000000000000000000000000000000000000000000000000000000000", Name: "web",
				State:           types.StateRunning,
				Config:          types.ContainerConfig{Tty: tc.tty},
				NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{}},
			})
			var gotFramed bool
			be.logsFn = func(_ context.Context, _ string, _ logbuf.ReadOptions, w io.Writer, framed bool) error {
				gotFramed = framed
				_, err := w.Write([]byte("line\n"))
				return err
			}
			rec := do(t, s, http.MethodGet, "/v1.43/containers/web/logs?stdout=1", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}
			if gotFramed != tc.wantFramed {
				t.Fatalf("framed = %v, want %v", gotFramed, tc.wantFramed)
			}
			if ct := rec.Header().Get("Content-Type"); ct != tc.wantType {
				t.Fatalf("Content-Type = %q, want %q", ct, tc.wantType)
			}
		})
	}
}

func TestLogsRequireAStream(t *testing.T) {
	s, be := newTestServer(t)
	be.addContainer(&types.Container{
		ID: "1234000000000000000000000000000000000000000000000000000000000000", Name: "web",
		NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{}},
	})
	rec := do(t, s, http.MethodGet, "/v1.43/containers/web/logs", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestArchiveStatHeader(t *testing.T) {
	s, be := newTestServer(t)
	be.addContainer(&types.Container{
		ID: "1234000000000000000000000000000000000000000000000000000000000000", Name: "web",
		NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{}},
	})

	rec := do(t, s, http.MethodHead, "/v1.43/containers/web/archive?path=/etc/hosts", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD = %d: %s", rec.Code, rec.Body.String())
	}
	raw := rec.Header().Get(pathStatHeader)
	if raw == "" {
		t.Fatal("no path-stat header: docker cp reads it before anything else")
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("stat header is not base64: %v", err)
	}
	var stat struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}
	if err := json.Unmarshal(decoded, &stat); err != nil {
		t.Fatalf("stat header is not JSON: %v", err)
	}
	if stat.Name != "file" || stat.Size != 3 {
		t.Fatalf("stat = %+v", stat)
	}

	rec = do(t, s, http.MethodGet, "/v1.43/containers/web/archive", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing path = %d, want 400", rec.Code)
	}
}

func TestChangesUseDockerNumericKinds(t *testing.T) {
	s, be := newTestServer(t)
	be.addContainer(&types.Container{
		ID: "1234000000000000000000000000000000000000000000000000000000000000", Name: "web",
		NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{}},
	})
	rec := do(t, s, http.MethodGet, "/v1.43/containers/web/changes", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var changes []ContainerChange
	decode(t, rec, &changes)
	want := map[string]int{"/etc/hosts": ChangeModify, "/new": ChangeAdd, "/gone": ChangeDelete}
	if len(changes) != len(want) {
		t.Fatalf("got %d changes, want %d", len(changes), len(want))
	}
	for _, ch := range changes {
		if want[ch.Path] != ch.Kind {
			t.Errorf("%s kind = %d, want %d", ch.Path, ch.Kind, want[ch.Path])
		}
	}
}

func TestBuildRefusalNamesTheFix(t *testing.T) {
	s, _ := newTestServer(t)
	rec := do(t, s, http.MethodPost, "/v1.43/build?t=demo", strings.NewReader("tar-context"))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
	var e ErrorResponse
	decode(t, rec, &e)
	if !strings.Contains(e.Message, "hull engine install-buildkit") {
		t.Fatalf("message = %q, want it to name the fix", e.Message)
	}
}

func TestGRPCWithoutBuildKitIsAnHonest501(t *testing.T) {
	s, _ := newTestServer(t)
	for _, path := range []string{"/v1.43/grpc", "/v1.43/session"} {
		rec := do(t, s, http.MethodPost, path, strings.NewReader(""))
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("POST %s = %d, want 501", path, rec.Code)
		}
	}
}

func TestSplitEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantNetwork string
		wantAddress string
	}{
		{name: "unix url", in: "unix:///run/buildkit/buildkitd.sock", wantNetwork: "unix", wantAddress: "/run/buildkit/buildkitd.sock"},
		{name: "tcp url", in: "tcp://127.0.0.1:1234", wantNetwork: "tcp", wantAddress: "127.0.0.1:1234"},
		{name: "bare path", in: "/run/x.sock", wantNetwork: "unix", wantAddress: "/run/x.sock"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, a := splitEndpoint(tc.in)
			if n != tc.wantNetwork || a != tc.wantAddress {
				t.Fatalf("splitEndpoint(%q) = (%q, %q), want (%q, %q)", tc.in, n, a, tc.wantNetwork, tc.wantAddress)
			}
		})
	}
}

func TestInfoReportsUnenforceableLimits(t *testing.T) {
	s, _ := newTestServer(t)
	rec := do(t, s, http.MethodGet, "/v1.43/info", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var info InfoResponse
	decode(t, rec, &info)
	if info.MemoryLimit || info.CPUCfsQuota || info.PidsLimit {
		t.Fatalf("the feature booleans claim limits work on a host with no delegated controllers: %+v", info)
	}
	if len(info.Warnings) == 0 {
		t.Fatal("no warnings: the missing cgroup delegation must reach the CLI")
	}
	if info.OSType != "linux" || info.ServerVersion == "" {
		t.Fatalf("info = %+v", info)
	}
}

func TestVersionEndpoint(t *testing.T) {
	s, _ := newTestServer(t)
	rec := do(t, s, http.MethodGet, "/v1.43/version", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var v VersionResponse
	decode(t, rec, &v)
	if v.APIVersion != "1.43" || v.MinAPIVersion != "1.24" {
		t.Fatalf("versions = %q/%q", v.APIVersion, v.MinAPIVersion)
	}
	if v.Os != "linux" || v.Platform.Name != "hull" {
		t.Fatalf("version = %+v", v)
	}
	if len(v.Components) == 0 {
		t.Fatal("no components")
	}
}

func TestSystemDF(t *testing.T) {
	s, be := newTestServer(t)
	be.images["alpine:3.20"] = &types.Image{ID: "sha256:img", Size: 3600000, RepoTags: []string{"alpine:3.20"}}
	_, _ = be.VolumeCreate(context.Background(), "data", "local", nil, nil)

	rec := do(t, s, http.MethodGet, "/v1.43/system/df", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var df DiskUsage
	decode(t, rec, &df)
	if df.LayersSize != 3600000 {
		t.Fatalf("LayersSize = %d", df.LayersSize)
	}
	if len(df.Volumes) != 1 || df.Volumes[0].UsageData == nil || df.Volumes[0].UsageData.Size != -1 {
		t.Fatalf("volumes = %+v, want an honest -1 for an uncomputed size", df.Volumes)
	}
	if df.BuildCache == nil {
		t.Fatal("BuildCache must be a present empty array, not null")
	}
}

func TestNetworkAndVolumeRoundTrip(t *testing.T) {
	s, _ := newTestServer(t)

	rec := do(t, s, http.MethodPost, "/v1.43/networks/create",
		strings.NewReader(`{"Name":"proj_default","Driver":"bridge","IPAM":{"Config":[{"Subnet":"10.66.9.0/24"}]}}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("network create = %d: %s", rec.Code, rec.Body.String())
	}
	var created NetworkCreateResponse
	decode(t, rec, &created)

	rec = do(t, s, http.MethodGet, "/v1.43/networks/"+created.ID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("network inspect = %d", rec.Code)
	}
	var n NetworkResource
	decode(t, rec, &n)
	if n.Name != "proj_default" || len(n.IPAM.Config) != 1 || n.IPAM.Config[0].Subnet != "10.66.9.0/24" {
		t.Fatalf("network = %+v", n)
	}
	if n.Containers == nil {
		t.Fatal("Containers must be a present empty object")
	}

	rec = do(t, s, http.MethodPost, "/v1.43/networks/create", strings.NewReader(`{"Name":"proj_default"}`))
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate network = %d, want 409", rec.Code)
	}

	rec = do(t, s, http.MethodPost, "/v1.43/volumes/create", strings.NewReader(`{"Name":"proj_data"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("volume create = %d: %s", rec.Code, rec.Body.String())
	}
	rec = do(t, s, http.MethodGet, "/v1.43/volumes", nil)
	var list VolumeListResponse
	decode(t, rec, &list)
	if len(list.Volumes) != 1 || list.Volumes[0].Name != "proj_data" {
		t.Fatalf("volumes = %+v", list.Volumes)
	}
	if list.Warnings == nil {
		t.Fatal("Warnings must be a present empty array")
	}
}

func TestStatsShape(t *testing.T) {
	s, be := newTestServer(t)
	be.addContainer(&types.Container{
		ID: "5555000000000000000000000000000000000000000000000000000000000000", Name: "web",
		State:           types.StateRunning,
		NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{}},
	})
	rec := do(t, s, http.MethodGet, "/v1.43/containers/web/stats?stream=0", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var st StatsJSON
	if err := json.Unmarshal([]byte(strings.SplitN(strings.TrimSpace(rec.Body.String()), "\n", 2)[0]), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.Name != "/web" {
		t.Fatalf("name = %q, want a leading slash", st.Name)
	}
	// hull records microseconds; Docker's clients divide nanoseconds.
	if st.CPUStats.CPUUsage.TotalUsage != 1000*1000 {
		t.Fatalf("total_usage = %d, want microseconds scaled to nanoseconds", st.CPUStats.CPUUsage.TotalUsage)
	}
	if st.MemoryStats.Limit != 8192 {
		t.Fatalf("memory limit = %d", st.MemoryStats.Limit)
	}
}

func TestServeTCPRequiresAToken(t *testing.T) {
	s, _ := newTestServer(t)
	err := s.ServeTCP(context.Background(), "127.0.0.1:0", "  ")
	if err == nil {
		t.Fatal("an unauthenticated TCP listener was accepted; that is a DNS-rebinding hole")
	}
	if !strings.Contains(err.Error(), "shared-secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestTokenGuard(t *testing.T) {
	s, _ := newTestServer(t)
	guarded := s.tokenGuard("s3cret", s.Handler())

	tests := []struct {
		name       string
		header     string
		wantStatus int
	}{
		{name: "bearer", header: "Bearer s3cret", wantStatus: http.StatusOK},
		{name: "bare", header: "s3cret", wantStatus: http.StatusOK},
		{name: "wrong", header: "Bearer nope", wantStatus: http.StatusUnauthorized},
		{name: "absent", header: "", wantStatus: http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			guarded.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestClearStaleSocket(t *testing.T) {
	dir := t.TempDir()

	t.Run("absent is fine", func(t *testing.T) {
		if err := ClearStaleSocket(filepath.Join(dir, "missing.sock")); err != nil {
			t.Fatalf("ClearStaleSocket: %v", err)
		}
	})

	t.Run("a regular file is refused", func(t *testing.T) {
		p := filepath.Join(dir, "regular")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		err := ClearStaleSocket(p)
		if err == nil || !strings.Contains(err.Error(), "not a socket") {
			t.Fatalf("err = %v, want a refusal", err)
		}
		if _, serr := os.Stat(p); serr != nil {
			t.Fatalf("the file was removed anyway: %v", serr)
		}
	})

	t.Run("a live socket is refused", func(t *testing.T) {
		p := filepath.Join(dir, "live.sock")
		ln, err := net.Listen("unix", p)
		if err != nil {
			t.Skipf("unix sockets unavailable here: %v", err)
		}
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				c, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				_ = c.Close()
			}
		}()
		err = ClearStaleSocket(p)
		if err == nil || !strings.Contains(err.Error(), "live daemon") {
			t.Fatalf("err = %v, want a refusal naming the live daemon", err)
		}
	})

	t.Run("a stale socket is removed", func(t *testing.T) {
		p := filepath.Join(dir, "stale.sock")
		ln, err := net.Listen("unix", p)
		if err != nil {
			t.Skipf("unix sockets unavailable here: %v", err)
		}
		// Leaving the inode behind on close is exactly what a crashed daemon
		// leaves: a socket file with no listener.
		ul, ok := ln.(*net.UnixListener)
		if !ok {
			t.Skip("not a unix listener")
		}
		ul.SetUnlinkOnClose(false)
		if err := ul.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		if _, serr := os.Stat(p); serr != nil {
			t.Skipf("no stale socket to clear: %v", serr)
		}
		if err := ClearStaleSocket(p); err != nil {
			t.Fatalf("ClearStaleSocket: %v", err)
		}
		if _, serr := os.Stat(p); !os.IsNotExist(serr) {
			t.Fatalf("the stale socket survived: %v", serr)
		}
	})
}

func TestServeShutsDownOnContextCancel(t *testing.T) {
	s, _ := newTestServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Serve(ctx, ln) }()

	// The listener must actually answer before the drain is meaningful.
	resp, err := http.Get("http://" + ln.Addr().String() + "/_ping")
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	_ = resp.Body.Close()

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not drain")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want string
	}{
		{name: "sub-second", in: 500 * time.Millisecond, want: "Less than a second"},
		{name: "one second", in: time.Second, want: "1 second"},
		{name: "seconds", in: 45 * time.Second, want: "45 seconds"},
		{name: "one minute", in: 70 * time.Second, want: "About a minute"},
		{name: "minutes", in: 20 * time.Minute, want: "20 minutes"},
		{name: "one hour", in: 61 * time.Minute, want: "About an hour"},
		{name: "hours", in: 5 * time.Hour, want: "5 hours"},
		{name: "days", in: 72 * time.Hour, want: "3 days"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatDuration(tc.in); got != tc.want {
				t.Fatalf("formatDuration(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
