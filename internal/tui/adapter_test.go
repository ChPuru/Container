package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ChPuru/hull/internal/client"
	"github.com/ChPuru/hull/internal/logbuf"
	"github.com/ChPuru/hull/internal/types"
)

// newTestEngine starts an HTTP server speaking the Docker Engine API and
// returns an EngineClient pointed at it. TCP is the one transport a test can
// use on both linux and windows.
func newTestEngine(t *testing.T, h http.Handler) *EngineClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := client.New(client.Options{Host: "tcp://" + strings.TrimPrefix(srv.URL, "http://")})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return NewEngineClient(c)
}

// apiPath strips the /v1.43 prefix the client puts on every request, so a test
// handler can switch on the endpoint rather than on the version.
func apiPath(r *http.Request) string {
	p := r.URL.Path
	if strings.HasPrefix(p, "/v") {
		if i := strings.Index(p[1:], "/"); i >= 0 {
			return p[i+1:]
		}
	}
	return p
}

// writeJSON replies with a JSON body.
func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

// ---------- pure conversions ----------

func TestFirstParenAndSummaryKey(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   string
	}{
		{name: "no parentheses", status: "Up 3 minutes", want: ""},
		{name: "health suffix", status: "Up 3 minutes (healthy)", want: "(healthy)"},
		{name: "paused", status: "Up 2 hours (Paused)", want: "(Paused)"},
		{name: "exit code", status: "Exited (7) 4 seconds ago", want: "(7)"},
		{name: "unclosed", status: "Up (weird", want: ""},
		{name: "empty", status: "", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstParen(tc.status); got != tc.want {
				t.Errorf("firstParen(%q) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}

	a := client.ContainerSummary{State: "running", Status: "Up 3 minutes (healthy)"}
	b := client.ContainerSummary{State: "running", Status: "Up 9 minutes (healthy)"}
	c := client.ContainerSummary{State: "running", Status: "Up 9 minutes (unhealthy)"}
	if summaryKey(a) != summaryKey(b) {
		t.Error("a passing minute must not invalidate the cached inspect")
	}
	if summaryKey(b) == summaryKey(c) {
		t.Error("a health change must invalidate the cached inspect")
	}
}

func TestStateFromAPI(t *testing.T) {
	tests := []struct {
		name  string
		state *client.ContainerState
		want  types.State
	}{
		{name: "nil is created", state: nil, want: types.StateCreated},
		{name: "status word wins", state: &client.ContainerState{Status: "running"}, want: types.StateRunning},
		{name: "mixed case", state: &client.ContainerState{Status: "Paused"}, want: types.StatePaused},
		{
			name:  "unknown word falls back to the flags",
			state: &client.ContainerState{Status: "confused", Running: true},
			want:  types.StateRunning,
		},
		{
			name:  "paused beats running in the flags",
			state: &client.ContainerState{Running: true, Paused: true},
			want:  types.StatePaused,
		},
		{name: "nothing set is exited", state: &client.ContainerState{}, want: types.StateExited},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := stateFromAPI(tc.state); got != tc.want {
				t.Errorf("stateFromAPI = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestContainerFromSummary(t *testing.T) {
	sum := client.ContainerSummary{
		ID:      "abc123def456789",
		Names:   []string{"/web"},
		Image:   "nginx:1.27",
		ImageID: "sha256:deadbeef",
		Created: 1700000000,
		State:   "running",
		Status:  "Up 3 minutes",
		Ports: []client.Port{
			{PrivatePort: 80, PublicPort: 8080, IP: "0.0.0.0", Type: "tcp"},
			{PrivatePort: 443, Type: "tcp"},
		},
	}
	sum.HostConfig.NetworkMode = "bridge"
	sum.NetworkSettings = &client.SummaryNetworkSettings{
		Networks: map[string]*client.EndpointSettings{
			"bridge": {IPAddress: "10.66.7.2", MacAddress: "36:cf:9d:90:3f:e3"},
		},
	}

	got := containerFromSummary(sum)
	if got.Name != "web" {
		t.Errorf("Name = %q, want web (the slash is the wire's, not ours)", got.Name)
	}
	if got.State != types.StateRunning {
		t.Errorf("State = %q, want running", got.State)
	}
	if got.ImageRef != "nginx:1.27" || got.Image != "sha256:deadbeef" {
		t.Errorf("image fields = %q / %q", got.ImageRef, got.Image)
	}
	if !got.Created.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("Created = %v", got.Created)
	}
	ports := PortStrings(got)
	want := []string{"0.0.0.0:8080->80/tcp", "443/tcp"}
	if len(ports) != len(want) {
		t.Fatalf("PortStrings = %v, want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Errorf("PortStrings[%d] = %q, want %q", i, ports[i], want[i])
		}
	}
	if ep := got.NetworkSettings.Networks["bridge"]; ep.IPAddress != "10.66.7.2" {
		t.Errorf("bridge endpoint = %+v", ep)
	}
}

func TestContainerFromInspect(t *testing.T) {
	init := true
	limit := int64(512)
	in := &client.ContainerInspect{
		ID:           "0123456789abcdef",
		Name:         "/api",
		Created:      "2026-09-19T10:00:00Z",
		Image:        "sha256:cafe",
		RestartCount: 2,
		State: &client.ContainerState{
			Status:     "running",
			Running:    true,
			Pid:        4242,
			ExitCode:   0,
			StartedAt:  "2026-09-19T10:00:01Z",
			FinishedAt: "0001-01-01T00:00:00Z",
			Health:     &client.Health{Status: "unhealthy", FailingStreak: 3},
		},
		Config: &client.Config{
			Image:       "api:latest",
			Hostname:    "api",
			Tty:         true,
			Env:         []string{"A=1"},
			Cmd:         []string{"/app"},
			Healthcheck: &client.HealthConfig{Test: []string{"CMD", "true"}, Retries: 3},
		},
		HostConfig: &client.HostConfig{
			Resources:   client.Resources{Memory: 1 << 20, PidsLimit: &limit},
			NetworkMode: "bridge",
			Init:        &init,
			Binds:       []string{"/tmp:/tmp"},
			RestartPolicy: client.RestartPolicy{
				Name: "on-failure", MaximumRetryCount: 5,
			},
		},
		NetworkSettings: &client.NetworkSettings{
			SandboxKey: "/var/run/netns/x",
			Ports: map[string][]client.PortBinding{
				"80/tcp": {{HostIP: "127.0.0.1", HostPort: "18080"}},
				"53/udp": nil,
			},
			Networks: map[string]*client.EndpointSettings{
				"hullnet": {IPAddress: "10.66.2.2", Gateway: "10.66.2.1", IPPrefixLen: 24},
			},
		},
		HullWarnings: []string{"memory limit not enforced"},
	}

	got := containerFromInspect(in)
	if got.Name != "api" || got.ID != "0123456789abcdef" {
		t.Errorf("identity = %q / %q", got.ID, got.Name)
	}
	if got.State != types.StateRunning || got.Pid != 4242 || got.RestartCount != 2 {
		t.Errorf("state fields = %+v", got)
	}
	if got.StartedAt.IsZero() {
		t.Error("StartedAt must be parsed: it is the only source of the uptime column")
	}
	if !got.FinishedAt.IsZero() {
		t.Errorf("FinishedAt = %v, want the zero time for Docker's 0001 stamp", got.FinishedAt)
	}
	if got.Health == nil || got.Health.Status != "unhealthy" || got.Health.FailingStreak != 3 {
		t.Errorf("Health = %+v", got.Health)
	}
	if got.ImageRef != "api:latest" || !got.Config.Tty {
		t.Errorf("config = %+v", got.Config)
	}
	if got.Config.Healthcheck == nil || got.Config.Healthcheck.Retries != 3 {
		t.Errorf("healthcheck = %+v", got.Config.Healthcheck)
	}
	if !got.HostConfig.Init || got.HostConfig.Resources.Memory != 1<<20 {
		t.Errorf("host config = %+v", got.HostConfig)
	}
	if got.HostConfig.PidsLimit == nil || *got.HostConfig.PidsLimit != 512 {
		t.Errorf("pids limit = %v", got.HostConfig.PidsLimit)
	}
	if got.HostConfig.RestartPolicy.Name != "on-failure" {
		t.Errorf("restart policy = %+v", got.HostConfig.RestartPolicy)
	}
	if got.NetworkSettings.SandboxKey != "/var/run/netns/x" {
		t.Errorf("sandbox key = %q", got.NetworkSettings.SandboxKey)
	}
	if b := got.NetworkSettings.Ports["80/tcp"]; len(b) != 1 || b[0].HostPort != "18080" {
		t.Errorf("port bindings = %+v", got.NetworkSettings.Ports)
	}
	if _, ok := got.NetworkSettings.Ports["53/udp"]; !ok {
		t.Error("an exposed-but-unpublished port must survive the conversion")
	}
	if ep := got.NetworkSettings.Networks["hullnet"]; ep.IPAddress != "10.66.2.2" {
		t.Errorf("endpoint = %+v", ep)
	}
	if summary := StateSummary(got); summary != "running (unhealthy)" {
		t.Errorf("StateSummary = %q, want the health to reach the state column", summary)
	}
}

func TestStatsFromResponse(t *testing.T) {
	var s client.StatsResponse
	s.Read = time.Unix(1700000001, 0)
	s.PreRead = time.Unix(1700000000, 0)
	s.CPUStats.CPUUsage.TotalUsage = 2000
	s.PreCPUStats.CPUUsage.TotalUsage = 1000
	s.CPUStats.SystemUsage = 20000
	s.PreCPUStats.SystemUsage = 10000
	s.CPUStats.CPUUsage.PercpuUsage = []uint64{1, 2, 3, 4}
	s.MemoryStats.Usage = 300
	s.MemoryStats.Limit = 1000
	s.MemoryStats.Stats = map[string]uint64{"inactive_file": 100}
	s.PidsStats.Current = 7
	s.PidsStats.Limit = 64
	s.Networks = map[string]client.NetworkStats{
		"eth0": {RxBytes: 10, TxBytes: 20, RxPackets: 1, TxPackets: 2},
		"eth1": {RxBytes: 5, TxBytes: 6, RxPackets: 3, TxPackets: 4},
	}
	s.BlkioStats.IoServiceBytesRecursive = []client.BlkioStatEntry{
		{Op: "read", Value: 111}, {Op: "Write", Value: 222},
	}

	got := statsFromResponse(s)
	if got.CPUUsage != 2000 || got.PreCPUUsage != 1000 {
		t.Errorf("cpu usage = %d / %d", got.CPUUsage, got.PreCPUUsage)
	}
	if got.OnlineCPUs != 4 {
		t.Errorf("OnlineCPUs = %d, want the percpu length when online_cpus is absent", got.OnlineCPUs)
	}
	if got.MemoryCache != 100 {
		t.Errorf("MemoryCache = %d, want inactive_file", got.MemoryCache)
	}
	if MemoryUsage(got) != 200 {
		t.Errorf("MemoryUsage = %d, want usage minus cache", MemoryUsage(got))
	}
	if got.RxBytes != 15 || got.TxBytes != 26 || got.RxPackets != 4 || got.TxPackets != 6 {
		t.Errorf("network counters = %+v", got)
	}
	if got.BlkRead != 111 || got.BlkWrite != 222 {
		t.Errorf("block counters = %d / %d", got.BlkRead, got.BlkWrite)
	}
	if cpu := CPUPercent(got); cpu <= 0 {
		t.Errorf("CPUPercent = %v, want a positive percentage", cpu)
	}

	var online client.StatsResponse
	online.CPUStats.OnlineCPUs = 2
	if got := statsFromResponse(online); got.OnlineCPUs != 2 {
		t.Errorf("OnlineCPUs = %d, want the reported value", got.OnlineCPUs)
	}
}

func TestEventFromClient(t *testing.T) {
	got := eventFromClient(client.Event{
		Type:     "container",
		Action:   "die",
		Actor:    client.EventActor{ID: "abc", Attributes: map[string]string{"name": "web"}},
		Scope:    "local",
		Time:     1700000000,
		TimeNano: 1700000000123456789,
	})
	if got.Type != "container" || got.Action != "die" || got.Scope != "local" {
		t.Errorf("event = %+v", got)
	}
	if got.Actor.ID != "abc" || got.Actor.Attributes["name"] != "web" {
		t.Errorf("actor = %+v", got.Actor)
	}
	if !strings.Contains(EventLine(got, time.UTC), "web") {
		t.Errorf("EventLine = %q", EventLine(got, time.UTC))
	}
}

func TestTailParam(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want string
	}{
		{name: "none", n: 0, want: "0"},
		{name: "some", n: 200, want: "200"},
		{name: "all", n: -1, want: "all"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tailParam(tc.n); got != tc.want {
				t.Errorf("tailParam(%d) = %q, want %q", tc.n, got, tc.want)
			}
		})
	}
}

// ---------- log stream ----------

func TestSplitLogTimestamp(t *testing.T) {
	stamp := "2026-09-19T10:11:12.000000000Z"
	tests := []struct {
		name     string
		line     string
		wantTime bool
		wantText string
	}{
		{name: "engine stamp", line: stamp + " hello", wantTime: true, wantText: "hello"},
		{name: "rfc3339 without nanos", line: "2026-09-19T10:11:12Z hi", wantTime: true, wantText: "hi"},
		{name: "no stamp", line: "plain line", wantText: "plain line"},
		{name: "no space at all", line: "single", wantText: "single"},
		{name: "empty", line: "", wantText: ""},
		{name: "stamp only", line: stamp + " ", wantTime: true, wantText: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts, text := splitLogTimestamp(tc.line)
			if ts.IsZero() == tc.wantTime {
				t.Errorf("time = %v, wantTime = %v", ts, tc.wantTime)
			}
			if text != tc.wantText {
				t.Errorf("text = %q, want %q", text, tc.wantText)
			}
		})
	}
}

func TestLogSplitterReassemblesLines(t *testing.T) {
	var got []LogLine
	sp := &logSplitter{
		fn:      func(l LogLine) error { got = append(got, l); return nil },
		pending: map[string][]byte{},
	}
	// Two lines arrive in three chunks, with an stderr frame interleaved in
	// the middle of an unfinished stdout line.
	if err := sp.write("stdout", []byte("one\ntw")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sp.write("stderr", []byte("boom\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sp.write("stdout", []byte("o\r\nthree")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sp.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	want := []LogLine{
		{Stream: "stdout", Line: "one"},
		{Stream: "stderr", Line: "boom"},
		{Stream: "stdout", Line: "two"},
		{Stream: "stdout", Line: "three"},
	}
	if len(got) != len(want) {
		t.Fatalf("lines = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].Stream != want[i].Stream || got[i].Line != want[i].Line {
			t.Errorf("line %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestLogSplitterBoundsAnEndlessLine(t *testing.T) {
	n := 0
	sp := &logSplitter{
		fn:      func(LogLine) error { n++; return nil },
		pending: map[string][]byte{},
	}
	if err := sp.write("stdout", bytes.Repeat([]byte("x"), maxPendingLine+1)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != 1 {
		t.Fatalf("emitted %d lines, want the over-long one flushed once", n)
	}
	if len(sp.pending["stdout"]) != 0 {
		t.Errorf("pending = %d bytes, want the buffer released", len(sp.pending["stdout"]))
	}
}

func TestLogSplitterPropagatesConsumerErrors(t *testing.T) {
	want := errors.New("stop")
	sp := &logSplitter{
		fn:      func(LogLine) error { return want },
		pending: map[string][]byte{},
	}
	if err := sp.write("stdout", []byte("line\n")); !errors.Is(err, want) {
		t.Errorf("write err = %v, want %v", err, want)
	}
}

// ---------- adapter against a server ----------

// engineStub is a hand-rolled Docker API server: enough of the endpoints for
// the adapter to be exercised, and a record of what it was asked.
type engineStub struct {
	mu       sync.Mutex
	hits     map[string]int
	state    string
	warnings []string
	logs     []byte
	ttyLogs  bool
}

func newEngineStub() *engineStub {
	return &engineStub{hits: map[string]int{}, state: "running", warnings: []string{"limits not enforced"}}
}

func (s *engineStub) hit(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits[name]++
	return s.hits[name]
}

func (s *engineStub) count(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[name]
}

func (s *engineStub) setState(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = v
}

func (s *engineStub) currentState() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *engineStub) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := apiPath(r)
		switch {
		case path == "/containers/json":
			s.hit("list")
			state := s.currentState()
			status := "Up 3 minutes"
			if state != "running" {
				status = "Exited (0) 1 second ago"
			}
			writeJSON(t, w, []client.ContainerSummary{{
				ID:      "cafe1234567890",
				Names:   []string{"/web"},
				Image:   "nginx:1.27",
				ImageID: "sha256:beef",
				Created: 1700000000,
				State:   state,
				Status:  status,
			}})
		case strings.HasSuffix(path, "/json") && strings.HasPrefix(path, "/containers/"):
			s.hit("inspect")
			state := s.currentState()
			writeJSON(t, w, client.ContainerInspect{
				ID:      "cafe1234567890",
				Name:    "/web",
				Created: "2026-09-19T10:00:00Z",
				Image:   "sha256:beef",
				State: &client.ContainerState{
					Status:    state,
					Running:   state == "running",
					StartedAt: "2026-09-19T10:00:01Z",
				},
				Config:       &client.Config{Image: "nginx:1.27", Tty: s.ttyLogs},
				HullWarnings: s.warnings,
			})
		case strings.HasSuffix(path, "/warnings"):
			if s.hit("warnings"); s.warnings == nil {
				http.Error(w, `{"message":"no such endpoint"}`, http.StatusNotFound)
				return
			}
			writeJSON(t, w, s.warnings)
		case strings.HasSuffix(path, "/logs"):
			s.hit("logs")
			w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
			_, _ = w.Write(s.logs)
		case strings.HasSuffix(path, "/stats"):
			s.hit("stats")
			var sample client.StatsResponse
			sample.MemoryStats.Usage = 500
			sample.MemoryStats.Limit = 1000
			sample.CPUStats.OnlineCPUs = 2
			writeJSON(t, w, sample)
		case path == "/events":
			s.hit("events")
			writeJSON(t, w, client.Event{Type: "container", Action: "start",
				Actor: client.EventActor{ID: "cafe1234567890"}, Time: 1700000000})
		case path == "/info":
			s.hit("info")
			writeJSON(t, w, client.Info{
				ServerVersion:     "0.1.0",
				Name:              "hull-engine",
				Containers:        3,
				ContainersRunning: 1,
				ContainersStopped: 2,
				CgroupVersion:     "1",
				CgroupV2Delegated: false,
				DefaultRuntime:    "crun",
				RuntimeVersion:    "1.14.1",
				OCIVersion:        "1.1.0",
				DataRoot:          "/var/lib/hull",
				Warnings:          []string{"no delegated cgroup v2 controllers"},
			})
		case strings.HasSuffix(path, "/start"):
			s.hit("start")
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/stop"):
			s.hit("stop")
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/restart"):
			s.hit("restart")
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/pause"):
			s.hit("pause")
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/unpause"):
			s.hit("unpause")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete:
			s.hit("remove")
			if r.URL.Query().Get("force") != "1" && r.URL.Query().Get("force") != "true" {
				t.Errorf("remove without force: %s", r.URL.RawQuery)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, path)
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
		}
	})
}

func TestEngineClientContainersCachesTheInspect(t *testing.T) {
	stub := newEngineStub()
	e := newTestEngine(t, stub.handler(t))
	ctx := context.Background()

	got, err := e.Containers(ctx)
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d containers, want 1", len(got))
	}
	if got[0].Name != "web" || got[0].State != types.StateRunning {
		t.Errorf("container = %+v", got[0])
	}
	if got[0].StartedAt.IsZero() {
		t.Error("StartedAt is empty: the uptime column would read zero for every container")
	}
	if n := stub.count("inspect"); n != 1 {
		t.Fatalf("inspects after the first poll = %d, want 1", n)
	}

	for i := 0; i < 5; i++ {
		if _, err := e.Containers(ctx); err != nil {
			t.Fatalf("Containers: %v", err)
		}
	}
	if n := stub.count("inspect"); n != 1 {
		t.Errorf("inspects after six polls = %d, want 1: an unchanged container must be served from cache", n)
	}

	stub.setState("exited")
	after, err := e.Containers(ctx)
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	if after[0].State != types.StateExited {
		t.Errorf("state after the change = %q", after[0].State)
	}
	if n := stub.count("inspect"); n != 2 {
		t.Errorf("inspects after the state change = %d, want 2", n)
	}
}

func TestEngineClientContainersDegradesWhenInspectFails(t *testing.T) {
	e := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiPath(r) == "/containers/json" {
			writeJSON(t, w, []client.ContainerSummary{{
				ID: "abc", Names: []string{"/solo"}, State: "running",
				Status: "Up 1 second", Created: 1700000000,
			}})
			return
		}
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
	}))

	got, err := e.Containers(context.Background())
	if err != nil {
		t.Fatalf("Containers must survive a failing inspect: %v", err)
	}
	if len(got) != 1 || got[0].Name != "solo" || got[0].State != types.StateRunning {
		t.Errorf("degraded container = %+v", got)
	}
}

func TestEngineClientContainersReportsAFailedList(t *testing.T) {
	e := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"engine is down"}`, http.StatusInternalServerError)
	}))
	if _, err := e.Containers(context.Background()); err == nil {
		t.Fatal("a failing list must surface as an error")
	}
}

func TestEngineClientInfo(t *testing.T) {
	stub := newEngineStub()
	e := newTestEngine(t, stub.handler(t))

	got, err := e.Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if got.Version != "0.1.0" || got.Name != "hull-engine" {
		t.Errorf("identity = %+v", got)
	}
	if got.ContainersRunning != 1 || got.ContainersStopped != 2 {
		t.Errorf("counts = %+v", got)
	}
	if got.Runtime != "crun 1.14.1" {
		t.Errorf("Runtime = %q, want the driver and its version", got.Runtime)
	}
	if got.OCIVersion != "1.1.0" {
		t.Errorf("OCIVersion = %q", got.OCIVersion)
	}
	if got.CgroupV2Delegated {
		t.Error("CgroupV2Delegated must survive as false: it is the status bar's most important field")
	}
	if len(got.Warnings) != 1 {
		t.Errorf("Warnings = %v", got.Warnings)
	}
	if got.DataRoot != "/var/lib/hull" {
		t.Errorf("DataRoot = %q", got.DataRoot)
	}
	if got.APIVersion == "" {
		t.Error("APIVersion must carry the version the client speaks")
	}
}

func TestEngineClientLogsDemuxesAndStamps(t *testing.T) {
	stub := newEngineStub()
	ts := time.Date(2026, 9, 19, 10, 11, 12, 0, time.UTC)
	var framed bytes.Buffer
	for _, e := range []logbuf.Entry{
		{Log: []byte("hello\n"), Stream: logbuf.StreamStdout, Time: ts},
		{Log: []byte("bad thing\n"), Stream: logbuf.StreamStderr, Time: ts.Add(time.Second)},
		{Log: []byte("no newline at the end"), Stream: logbuf.StreamStdout, Time: ts.Add(2 * time.Second)},
	} {
		if err := logbuf.WriteFramed(&framed, e, true); err != nil {
			t.Fatalf("WriteFramed: %v", err)
		}
	}
	stub.logs = framed.Bytes()
	e := newTestEngine(t, stub.handler(t))

	var got []LogLine
	err := e.Logs(context.Background(), "web", LogOptions{Tail: 100}, func(l LogLine) error {
		got = append(got, l)
		return nil
	})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("lines = %+v, want 3", got)
	}
	if got[0].Line != "hello" || got[0].Stream != "stdout" {
		t.Errorf("line 0 = %+v", got[0])
	}
	if !got[0].Time.Equal(ts) {
		t.Errorf("line 0 time = %v, want %v", got[0].Time, ts)
	}
	if got[1].Line != "bad thing" || got[1].Stream != "stderr" {
		t.Errorf("line 1 = %+v", got[1])
	}
	if got[2].Line != "no newline at the end" {
		t.Errorf("a final line with no newline must still arrive: %+v", got[2])
	}
}

func TestEngineClientLogsReadsATTYStreamUnframed(t *testing.T) {
	stub := newEngineStub()
	stub.ttyLogs = true
	stub.logs = []byte("2026-09-19T10:11:12.000000000Z tty line\n")
	e := newTestEngine(t, stub.handler(t))

	var got []LogLine
	if err := e.Logs(context.Background(), "web", LogOptions{}, func(l LogLine) error {
		got = append(got, l)
		return nil
	}); err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if len(got) != 1 || got[0].Line != "tty line" {
		t.Fatalf("tty lines = %+v", got)
	}
	if got[0].Time.IsZero() {
		t.Error("a tty line still carries the engine's timestamp")
	}
}

func TestEngineClientStatsAndEvents(t *testing.T) {
	stub := newEngineStub()
	e := newTestEngine(t, stub.handler(t))
	ctx := context.Background()

	var samples []types.Stats
	if err := e.Stats(ctx, "web", func(s types.Stats) error {
		samples = append(samples, s)
		return nil
	}); err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(samples) != 1 || samples[0].MemoryLimit != 1000 || samples[0].OnlineCPUs != 2 {
		t.Fatalf("samples = %+v", samples)
	}

	var events []types.Event
	if err := e.Events(ctx, func(ev types.Event) error {
		events = append(events, ev)
		return nil
	}); err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 1 || events[0].Action != "start" {
		t.Fatalf("events = %+v", events)
	}
}

func TestEngineClientWarningsFallBackToInspect(t *testing.T) {
	stub := newEngineStub()
	e := newTestEngine(t, stub.handler(t))

	got, err := e.Warnings(context.Background(), "web")
	if err != nil {
		t.Fatalf("Warnings: %v", err)
	}
	if len(got) != 1 || got[0] != "limits not enforced" {
		t.Fatalf("warnings = %v", got)
	}

	// An engine that does not serve hull's own endpoint still answers
	// through inspect, which carries the same list.
	fallback := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(apiPath(r), "/warnings") {
			http.Error(w, `{"message":"page not found"}`, http.StatusNotFound)
			return
		}
		writeJSON(t, w, client.ContainerInspect{
			ID: "abc", Name: "/web", State: &client.ContainerState{Status: "running"},
			HullWarnings: []string{"from inspect"},
		})
	}))
	got, err = fallback.Warnings(context.Background(), "web")
	if err != nil {
		t.Fatalf("fallback Warnings: %v", err)
	}
	if len(got) != 1 || got[0] != "from inspect" {
		t.Errorf("fallback warnings = %v", got)
	}
}

func TestContainerWarningsReadsTheEngineLabel(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   []string
	}{
		{name: "no labels at all"},
		{name: "unrelated labels", labels: map[string]string{"app": "web"}},
		{
			name:   "one warning",
			labels: map[string]string{warningsLabel: "memory limit not enforced"},
			want:   []string{"memory limit not enforced"},
		},
		{
			name:   "several, as the engine joins them",
			labels: map[string]string{warningsLabel: "no memory limit; no cpu quota"},
			want:   []string{"no memory limit", "no cpu quota"},
		},
		{
			name:   "empty label is not a warning",
			labels: map[string]string{warningsLabel: ""},
		},
		{
			name:   "stray separators are dropped",
			labels: map[string]string{warningsLabel: "; only one ;"},
			want:   []string{"only one"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var c types.Container
			c.Config.Labels = tc.labels
			got := ContainerWarnings(c)
			if len(got) != len(tc.want) {
				t.Fatalf("ContainerWarnings = %q, want %q", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("warning %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestEngineClientWarningsFallBackToTheLabel(t *testing.T) {
	e := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(apiPath(r), "/warnings") {
			http.Error(w, `{"message":"page not found"}`, http.StatusNotFound)
			return
		}
		writeJSON(t, w, client.ContainerInspect{
			ID:    "abc",
			Name:  "/web",
			State: &client.ContainerState{Status: "running"},
			Config: &client.Config{
				Labels: map[string]string{warningsLabel: "memory limit not enforced"},
			},
		})
	}))

	got, err := e.Warnings(context.Background(), "web")
	if err != nil {
		t.Fatalf("Warnings: %v", err)
	}
	if len(got) != 1 || got[0] != "memory limit not enforced" {
		t.Fatalf("warnings = %q, want the label's contents", got)
	}
}

func TestModelMarksAWarnedContainerFromItsOwnRecord(t *testing.T) {
	m := NewModel()
	m.SetSize(100, 24)
	var c types.Container
	c.ID = "abc123def456"
	c.Name = "web"
	c.State = types.StateRunning
	c.Config.Labels = map[string]string{warningsLabel: "memory limit not enforced"}
	m.SetContainers([]types.Container{c})
	m.Refresh()

	if len(m.table.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(m.table.Rows))
	}
	if name := m.table.Rows[0].Cells[1]; !strings.HasPrefix(name, "! ") {
		t.Errorf("row name = %q, want it marked: the dashboard never inspected this container", name)
	}
}

func TestEngineClientLifecycleActions(t *testing.T) {
	stub := newEngineStub()
	e := newTestEngine(t, stub.handler(t))
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
		hit  string
	}{
		{name: "start", call: func() error { return e.Start(ctx, "web") }, hit: "start"},
		{name: "stop", call: func() error { return e.Stop(ctx, "web") }, hit: "stop"},
		{name: "restart", call: func() error { return e.Restart(ctx, "web") }, hit: "restart"},
		{name: "pause", call: func() error { return e.Pause(ctx, "web") }, hit: "pause"},
		{name: "unpause", call: func() error { return e.Unpause(ctx, "web") }, hit: "unpause"},
		{name: "remove", call: func() error { return e.Remove(ctx, "web", true) }, hit: "remove"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if stub.count(tc.hit) != 1 {
				t.Errorf("%s hit %d times, want 1", tc.hit, stub.count(tc.hit))
			}
		})
	}
}

func TestEngineClientImplementsTheOptionalCapabilities(t *testing.T) {
	var e any = NewEngineClient(nil)
	if _, ok := e.(Client); !ok {
		t.Error("EngineClient must satisfy Client")
	}
	if _, ok := e.(DiskReporter); !ok {
		t.Error("EngineClient must report free space: the status bar has a slot for it")
	}
	if _, ok := e.(WarningReporter); !ok {
		t.Error("EngineClient must report per-container warnings")
	}
}

func TestExecShellRefusesAContainerThatIsNotRunning(t *testing.T) {
	c, err := client.New(client.Options{Host: "tcp://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	err = ExecShell(c)(context.Background(), types.Container{Name: "web", State: types.StateExited})
	if err == nil {
		t.Fatal("exec into a stopped container must fail before it dials anything")
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("err = %v, want it to name the reason", err)
	}
}

func TestDefaultShellCommandIsAFixedLiteral(t *testing.T) {
	if len(DefaultShellCommand) != 3 || DefaultShellCommand[0] != "/bin/sh" {
		t.Fatalf("DefaultShellCommand = %q", DefaultShellCommand)
	}
	if !strings.Contains(DefaultShellCommand[2], "exec /bin/sh") {
		t.Errorf("the shell probe must always end at sh: %q", DefaultShellCommand[2])
	}
}
