package tui

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ChPuru/hull/internal/types"
)

// fakeClient is a Client that answers from fixed data and records what was
// asked of it. It implements the optional capabilities too, so the sources can
// be exercised on both paths.
type fakeClient struct {
	mu   sync.Mutex
	call []string

	containers []types.Container
	info       Info
	disk       DiskUsage
	events     []types.Event
	stats      []types.Stats
	logs       []LogLine
	warnings   []string

	failContainers error
	failEvents     error
	actionErr      error
}

func (f *fakeClient) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call = append(f.call, name)
}

func (f *fakeClient) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.call...)
}

func (f *fakeClient) Info(context.Context) (Info, error) {
	f.record("info")
	return f.info, nil
}

func (f *fakeClient) Containers(context.Context) ([]types.Container, error) {
	f.record("containers")
	if f.failContainers != nil {
		return nil, f.failContainers
	}
	return f.containers, nil
}

func (f *fakeClient) Inspect(_ context.Context, id string) (types.Container, error) {
	f.record("inspect")
	for _, c := range f.containers {
		if c.ID == id {
			return c, nil
		}
	}
	return types.Container{}, errors.New("no such container")
}

func (f *fakeClient) Logs(ctx context.Context, _ string, _ LogOptions, fn func(LogLine) error) error {
	f.record("logs")
	for _, l := range f.logs {
		if err := fn(l); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return nil
}

func (f *fakeClient) Stats(ctx context.Context, _ string, fn func(types.Stats) error) error {
	f.record("stats")
	for _, s := range f.stats {
		if err := fn(s); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return nil
}

func (f *fakeClient) Events(ctx context.Context, fn func(types.Event) error) error {
	f.record("events")
	if f.failEvents != nil {
		return f.failEvents
	}
	for _, e := range f.events {
		if err := fn(e); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return nil
}

func (f *fakeClient) DiskUsage(context.Context) (DiskUsage, error) {
	f.record("disk")
	return f.disk, nil
}

func (f *fakeClient) Warnings(context.Context, string) ([]string, error) {
	f.record("warnings")
	return f.warnings, nil
}

// lifecycle methods.
func (f *fakeClient) doAction(name string) error {
	f.record(name)
	return f.actionErr
}

func (f *fakeClient) Pause(context.Context, string) error   { return f.doAction("pause") }
func (f *fakeClient) Unpause(context.Context, string) error { return f.doAction("unpause") }
func (f *fakeClient) Stop(context.Context, string) error    { return f.doAction("stop") }
func (f *fakeClient) Restart(context.Context, string) error { return f.doAction("restart") }
func (f *fakeClient) Remove(_ context.Context, _ string, _ bool) error {
	return f.doAction("remove")
}

// startClient completes the Client interface over fakeClient.
type startClient struct{ *fakeClient }

func (s startClient) Start(context.Context, string) error { return s.doAction("start") }

// bareClient hides the optional capabilities by embedding only the interface,
// which is how a client that cannot report free space or warnings behaves.
type bareClient struct{ Client }

// newFake returns a client holding one running container and some data on
// every stream.
func newFake() startClient {
	cs := sampleContainers()
	return startClient{&fakeClient{
		containers: cs,
		info: Info{
			Version:           "0.1.0-dev",
			DataRoot:          "/var/lib/hull",
			ContainersRunning: 1,
		},
		disk:     DiskUsage{Path: "/var/lib/hull", Free: 1 << 30, Total: 4 << 30},
		events:   []types.Event{{Type: "container", Action: "start"}},
		stats:    []types.Stats{{OnlineCPUs: 2, MemoryUsage: 1000}},
		logs:     []LogLine{{Line: "hello", Stream: "stdout"}},
		warnings: []string{"memory limit not applied"},
	}}
}

// collect drains messages until want kinds have all been seen or the deadline
// passes, and returns what arrived.
func collect(t *testing.T, ch <-chan msg, want map[msgKind]bool) map[msgKind]msg {
	t.Helper()
	got := map[msgKind]msg{}
	deadline := time.After(3 * time.Second)
	for {
		if len(want) == 0 {
			return got
		}
		select {
		case m := <-ch:
			got[m.kind] = m
			delete(want, m.kind)
		case <-deadline:
			t.Fatalf("timed out waiting for %v, got %v", want, got)
		}
	}
}

func TestPollContainers(t *testing.T) {
	c := newFake()
	ch := make(chan msg, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go pollContainers(ctx, c, 10*time.Millisecond, ch)

	got := collect(t, ch, map[msgKind]bool{msgContainers: true, msgInfo: true, msgDisk: true})
	if n := len(got[msgContainers].containers); n != 3 {
		t.Errorf("container message carried %d containers, want 3", n)
	}
	if got[msgInfo].info.Version != "0.1.0-dev" {
		t.Errorf("info message = %+v", got[msgInfo].info)
	}
	if got[msgDisk].disk.Free != 1<<30 {
		t.Errorf("disk message = %+v", got[msgDisk].disk)
	}
}

func TestPollContainersReportsErrors(t *testing.T) {
	c := newFake()
	c.failContainers = errors.New("engine is not running")
	ch := make(chan msg, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go pollContainers(ctx, c, 10*time.Millisecond, ch)
	got := collect(t, ch, map[msgKind]bool{msgError: true})
	if !strings.Contains(got[msgError].err.Error(), "engine is not running") {
		t.Errorf("error message = %v", got[msgError].err)
	}
}

func TestStreamsStopWithTheContext(t *testing.T) {
	c := newFake()
	ch := make(chan msg, 16)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{}, 3)
	go func() { streamEvents(ctx, c, ch); done <- struct{}{} }()
	go func() { streamStats(ctx, c, "id", ch); done <- struct{}{} }()
	go func() { tailLogs(ctx, c, "id", 10, ch); done <- struct{}{} }()

	collect(t, ch, map[msgKind]bool{msgEvent: true, msgStats: true, msgLog: true, msgLogReset: true})

	cancel()
	for i := 0; i < 3; i++ {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("a source did not stop when its context was cancelled")
		}
	}
}

func TestInspectContainerFetchesWarnings(t *testing.T) {
	c := newFake()
	ch := make(chan msg, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go inspectContainer(ctx, c, c.containers[0].ID, ch)
	got := collect(t, ch, map[msgKind]bool{msgInspect: true, msgWarnings: true})
	if got[msgInspect].container.Name != "web" {
		t.Errorf("inspect message = %+v", got[msgInspect].container)
	}
	if len(got[msgWarnings].warnings) != 1 {
		t.Errorf("warnings message = %+v", got[msgWarnings].warnings)
	}
}

func TestDiskUsageFallsBackWhenTheClientCannotAnswer(t *testing.T) {
	bare := bareClient{Client: newFake()}
	if _, ok := diskUsage(context.Background(), bare, ""); ok {
		t.Error("with no data root there is nothing to report")
	}
	if _, ok := diskUsage(context.Background(), bare, "/definitely/not/a/path"); ok {
		t.Error("a path that does not exist must not produce a figure")
	}
	// The real client answers directly.
	d, ok := diskUsage(context.Background(), newFake(), "/var/lib/hull")
	if !ok || d.Free != 1<<30 {
		t.Errorf("diskUsage = %+v, %v", d, ok)
	}
}

func TestKeyReaderDecodesAndPauses(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	ch := make(chan msg, 16)
	kr := newKeyReader(r, ch)
	if !kr.deadlines {
		t.Skip("this platform cannot put a read deadline on a pipe")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go kr.run(ctx)

	if _, err := w.WriteString("j\x1b[B"); err != nil {
		t.Fatalf("write: %v", err)
	}
	want := []Key{RuneKey('j'), {Type: KeyDown}}
	for i, k := range want {
		select {
		case m := <-ch:
			if m.kind != msgKey || m.key != k {
				t.Fatalf("key %d = %+v, want %+v", i, m, k)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for key %d", i)
		}
	}

	// While paused the reader must leave the terminal alone, so an
	// interactive exec gets every byte the user types.
	kr.pause()
	time.Sleep(2 * inputPollInterval)
	if _, err := w.WriteString("qqqq"); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case m := <-ch:
		t.Fatalf("paused reader consumed %+v", m)
	case <-time.After(4 * inputPollInterval):
	}

	kr.resume()
	select {
	case m := <-ch:
		if m.key != RuneKey('q') {
			t.Fatalf("after resume got %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reader did not resume")
	}
}

func TestRunRefusesANonTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	err = RunWith(context.Background(), newFake(), Options{In: r, Out: w})
	if !errors.Is(err, ErrNotTerminal) {
		t.Errorf("RunWith on a pipe = %v, want ErrNotTerminal", err)
	}
}

func TestRunRejectsANilClient(t *testing.T) {
	if err := Run(context.Background(), nil, Options{}); err == nil {
		t.Error("Run with no client must fail")
	}
	if err := RunWith(context.Background(), nil, Options{}); err == nil {
		t.Error("RunWith with no client must fail")
	}
}

func TestOptionsDefaults(t *testing.T) {
	o := Options{}.withDefaults()
	if o.In == nil || o.Out == nil {
		t.Error("streams not defaulted")
	}
	if o.PollInterval != DefaultPollInterval || o.FrameInterval != DefaultFrameInterval {
		t.Errorf("timings not defaulted: %+v", o)
	}
	if o.StatsHistory != DefaultStatsHistory || o.LogTail != DefaultLogTail {
		t.Errorf("history not defaulted: %+v", o)
	}
	if o.Now == nil {
		t.Error("clock not defaulted")
	}
	custom := Options{PollInterval: time.Minute, StatsHistory: 5, LogTail: -1}.withDefaults()
	if custom.PollInterval != time.Minute || custom.StatsHistory != 5 || custom.LogTail != -1 {
		t.Errorf("defaults overrode explicit options: %+v", custom)
	}
}
