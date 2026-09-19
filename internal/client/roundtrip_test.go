package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestClient starts an httptest server with the given handler and returns a
// client pointed at it over TCP, which is the one transport a test can use on
// every platform.
func newTestClient(t *testing.T, h http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Options{Host: "tcp://" + strings.TrimPrefix(srv.URL, "http://")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// writeJSON is the test server's reply helper.
func writeJSON(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encoding test response: %v", err)
	}
}

func TestPingAndVersionNegotiation(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_ping" {
			t.Errorf("ping path = %q, want /_ping", r.URL.Path)
		}
		w.Header().Set("Api-Version", "1.41")
		w.Header().Set("Ostype", "linux")
		w.Header().Set("Builder-Version", "2")
		w.Header().Set("Docker-Experimental", "false")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "OK")
	}))

	got, err := c.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if got.APIVersion != "1.41" {
		t.Errorf("APIVersion = %q, want 1.41", got.APIVersion)
	}
	if got.OSType != "linux" {
		t.Errorf("OSType = %q, want linux", got.OSType)
	}
	if got.BuilderVersion != "2" {
		t.Errorf("BuilderVersion = %q, want 2", got.BuilderVersion)
	}
	if got.Experimental {
		t.Error("Experimental = true, want false")
	}

	// An engine older than hull must drag the client's version down, because
	// hull's own paths would 400 against it.
	c.NegotiateAPIVersion(context.Background())
	if v := c.ClientVersion(); v != "1.41" {
		t.Errorf("ClientVersion after negotiation = %q, want 1.41", v)
	}
}

func TestNegotiationDoesNotRaiseVersion(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A newer engine must not pull the client up past what it knows.
		w.Header().Set("Api-Version", "1.99")
		w.WriteHeader(http.StatusOK)
	}))
	before := c.ClientVersion()
	c.NegotiateAPIVersion(context.Background())
	if got := c.ClientVersion(); got != before {
		t.Errorf("ClientVersion = %q, want it to stay at %q", got, before)
	}
}

func TestPinnedVersionIsNotNegotiated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Api-Version", "1.24")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c, err := New(Options{Host: "tcp://" + strings.TrimPrefix(srv.URL, "http://"), Version: "1.43"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.NegotiateAPIVersion(context.Background())
	if got := c.ClientVersion(); got != "1.43" {
		t.Errorf("ClientVersion = %q, want the pinned 1.43", got)
	}
}

func TestContainerListRoundTrip(t *testing.T) {
	var gotPath, gotQuery, gotUA string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotUA = r.URL.Path, r.URL.RawQuery, r.Header.Get("User-Agent")
		writeJSON(t, w, http.StatusOK, []ContainerSummary{{
			ID:      "abc123def4567890",
			Names:   []string{"/web"},
			Image:   "nginx:1.27",
			ImageID: "sha256:deadbeef",
			Command: "nginx -g daemon off;",
			Created: 1_700_000_000,
			State:   "running",
			Status:  "Up 3 minutes",
			Ports: []Port{
				{IP: "0.0.0.0", PrivatePort: 80, PublicPort: 8080, Type: "tcp"},
				{PrivatePort: 443, Type: "tcp"},
			},
		}})
	}))

	list, err := c.ContainerList(context.Background(), ContainerListOptions{
		All:     true,
		Limit:   5,
		Filters: Filters{"status": {"running"}},
	})
	if err != nil {
		t.Fatalf("ContainerList: %v", err)
	}
	if want := "/v" + c.ClientVersion() + "/containers/json"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	for _, want := range []string{"all=1", "limit=5", "filters="} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query %q is missing %q", gotQuery, want)
		}
	}
	if !strings.HasPrefix(gotUA, "hull/") {
		t.Errorf("User-Agent = %q, want a hull/ prefix", gotUA)
	}
	if len(list) != 1 {
		t.Fatalf("got %d containers, want 1", len(list))
	}
	if got := list[0].Name(); got != "web" {
		t.Errorf("Name() = %q, want web without the leading slash", got)
	}
	if got, want := list[0].PortString(), "0.0.0.0:8080->80/tcp, 443/tcp"; got != want {
		t.Errorf("PortString() = %q, want %q", got, want)
	}
}

func TestCreateCarriesWarnings(t *testing.T) {
	var body ContainerCreateRequest
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decoding create body: %v", err)
		}
		if r.URL.Query().Get("name") != "web" {
			t.Errorf("name = %q, want web", r.URL.Query().Get("name"))
		}
		writeJSON(t, w, http.StatusCreated, ContainerCreateResponse{
			ID: "abc123",
			Warnings: []string{
				"memory limit not applied: no cgroup v2 controllers are delegated on this host",
			},
		})
	}))

	limit := int64(64)
	resp, err := c.ContainerCreate(context.Background(), "web", "linux/amd64", ContainerCreateRequest{
		Config: Config{Image: "alpine:3.20", Cmd: []string{"sh"}, Tty: true},
		HostConfig: &HostConfig{
			NetworkMode: "bridge",
			Resources:   Resources{Memory: 512 << 20, PidsLimit: &limit},
		},
	})
	if err != nil {
		t.Fatalf("ContainerCreate: %v", err)
	}
	if resp.ID != "abc123" {
		t.Errorf("ID = %q, want abc123", resp.ID)
	}
	if len(resp.Warnings) != 1 {
		t.Fatalf("got %d warnings, want 1 — a dropped warning means a silently unlimited container", len(resp.Warnings))
	}
	// The body must be Docker's flat shape: Config at the top level.
	if body.Image != "alpine:3.20" {
		t.Errorf("request Image = %q, want it flattened to the top level", body.Image)
	}
	if body.HostConfig == nil || body.HostConfig.Memory != 512<<20 {
		t.Errorf("request HostConfig = %+v, want the memory limit carried", body.HostConfig)
	}
}

func TestErrorsCarryTheEngineMessage(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		message string
		check   func(error) bool
	}{
		{"not found", http.StatusNotFound, "No such container: nope", IsNotFound},
		{"conflict", http.StatusConflict, `Conflict. The container name "/web" is already in use by container "abc"`, IsConflict},
		{"unauthorized", http.StatusUnauthorized, "unauthorized: incorrect username or password", IsUnauthorized},
		{"not implemented", http.StatusNotImplemented, "build requires buildkit: run 'hull engine install-buildkit'", IsNotImplemented},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(t, w, tc.status, map[string]string{"message": tc.message})
			}))
			_, err := c.ContainerInspect(context.Background(), "nope", false)
			if err == nil {
				t.Fatal("ContainerInspect returned no error")
			}
			if !tc.check(err) {
				t.Errorf("classifier rejected %v", err)
			}
			// Compose and Testcontainers match on the text, so it must
			// survive the round trip verbatim.
			if !strings.Contains(err.Error(), tc.message) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.message)
			}
			var apiErr *Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("error is %T, want *client.Error", err)
			}
			if apiErr.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, tc.status)
			}
		})
	}
}

func TestUnreachableEngineIsAConnectionFailure(t *testing.T) {
	// Port 1 on loopback is reserved and refuses immediately.
	c, err := New(Options{Host: "tcp://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Ping(context.Background()); !IsConnectionFailed(err) {
		t.Fatalf("Ping error = %v, want a connection failure so the CLI can say the engine is down", err)
	}
}

func TestEventDecodingAcceptsBothSpellings(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "docker spelling",
			body: `{"Type":"container","Action":"start","Actor":{"ID":"abc","Attributes":{"name":"web"}},"scope":"local","time":1700000000,"timeNano":1700000000000000000}`,
		},
		{
			name: "hull internal spelling",
			body: `{"type":"container","action":"start","actor":{"id":"abc","attributes":{"name":"web"}},"scope":"local","time":1700000000,"timeNano":1700000000000000000}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ev Event
			if err := json.Unmarshal([]byte(tc.body), &ev); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if ev.Type != "container" || ev.Action != "start" {
				t.Errorf("type/action = %q/%q, want container/start", ev.Type, ev.Action)
			}
			if ev.Actor.ID != "abc" {
				t.Errorf("actor id = %q, want abc", ev.Actor.ID)
			}
			if ev.Actor.Attributes["name"] != "web" {
				t.Errorf("actor name = %q, want web", ev.Actor.Attributes["name"])
			}
			if ev.At().Unix() != 1_700_000_000 {
				t.Errorf("At() = %v, want the timeNano value", ev.At())
			}
		})
	}
}

func TestStatsComputation(t *testing.T) {
	var s StatsResponse
	s.CPUStats.CPUUsage.TotalUsage = 200_000_000
	s.PreCPUStats.CPUUsage.TotalUsage = 100_000_000
	s.CPUStats.SystemUsage = 4_000_000_000
	s.PreCPUStats.SystemUsage = 2_000_000_000
	s.CPUStats.OnlineCPUs = 4
	s.MemoryStats.Usage = 300 << 20
	s.MemoryStats.Limit = 1 << 30
	s.MemoryStats.Stats = map[string]uint64{"inactive_file": 100 << 20}
	s.Networks = map[string]NetworkStats{
		"eth0": {RxBytes: 1000, TxBytes: 2000},
		"eth1": {RxBytes: 5, TxBytes: 7},
	}

	if got, want := s.CPUPercent(), 20.0; got != want {
		t.Errorf("CPUPercent() = %v, want %v", got, want)
	}
	if got, want := s.MemoryUsage(), uint64(200<<20); got != want {
		t.Errorf("MemoryUsage() = %d, want %d with the page cache subtracted", got, want)
	}
	if got := s.MemoryPercent(); got < 19.5 || got > 19.6 {
		t.Errorf("MemoryPercent() = %v, want about 19.53", got)
	}
	rx, tx := s.NetworkIO()
	if rx != 1005 || tx != 2007 {
		t.Errorf("NetworkIO() = %d/%d, want 1005/2007 summed across interfaces", rx, tx)
	}
}

func TestStatsWithNoPreviousSampleIsZero(t *testing.T) {
	var s StatsResponse
	s.CPUStats.CPUUsage.TotalUsage = 200_000_000
	s.CPUStats.SystemUsage = 0
	if got := s.CPUPercent(); got != 0 {
		t.Errorf("CPUPercent() = %v, want 0 when there is nothing to difference against", got)
	}
	if got := s.MemoryPercent(); got != 0 {
		t.Errorf("MemoryPercent() = %v, want 0 when the container has no limit", got)
	}
}
