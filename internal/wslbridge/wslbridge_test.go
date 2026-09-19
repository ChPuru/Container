package wslbridge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
)

// ---------- transport selection ----------

// fakeTransport records probe order and answers with a scripted result.
type fakeTransport struct {
	name      string
	probeErr  error
	order     *[]string
	mu        *sync.Mutex
	closed    bool
	dialCount int
}

func (f *fakeTransport) Name() string { return f.name }

func (f *fakeTransport) Probe(ctx context.Context) error {
	f.mu.Lock()
	*f.order = append(*f.order, f.name)
	f.mu.Unlock()
	return f.probeErr
}

func (f *fakeTransport) Dial(ctx context.Context) (net.Conn, error) {
	f.dialCount++
	if f.probeErr != nil {
		return nil, f.probeErr
	}
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(b, b) }()
	return a, nil
}

func (f *fakeTransport) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func TestSelectProbesInOrder(t *testing.T) {
	t.Parallel()

	boom := errors.New("not available here")

	tests := []struct {
		name      string
		probeErrs []error
		wantWin   string
		wantOrder []string
		wantErr   bool
	}{
		{
			name:      "first candidate wins and later ones are never probed",
			probeErrs: []error{nil, nil, nil},
			wantWin:   "stdio",
			wantOrder: []string{"stdio"},
		},
		{
			name:      "falls through to the second",
			probeErrs: []error{boom, nil, nil},
			wantWin:   "vsock",
			wantOrder: []string{"stdio", "vsock"},
		},
		{
			name:      "falls all the way through to the last",
			probeErrs: []error{boom, boom, nil},
			wantWin:   "tcp",
			wantOrder: []string{"stdio", "vsock", "tcp"},
		},
		{
			name:      "every candidate fails",
			probeErrs: []error{boom, boom, boom},
			wantOrder: []string{"stdio", "vsock", "tcp"},
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var (
				order []string
				mu    sync.Mutex
			)
			names := []string{"stdio", "vsock", "tcp"}
			candidates := make([]Transport, 0, len(names))
			fakes := make([]*fakeTransport, 0, len(names))
			for i, n := range names {
				f := &fakeTransport{name: n, probeErr: tc.probeErrs[i], order: &order, mu: &mu}
				fakes = append(fakes, f)
				candidates = append(candidates, f)
			}

			got, err := Select(context.Background(), Config{}, candidates...)
			if tc.wantErr {
				if err == nil {
					t.Fatal("Select succeeded, want an error")
				}
				if !errors.Is(err, ErrNoTransport) {
					t.Errorf("error = %v, want one wrapping ErrNoTransport", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Select: %v", err)
				}
				if got.Name() != tc.wantWin {
					t.Errorf("selected %q, want %q", got.Name(), tc.wantWin)
				}
			}

			mu.Lock()
			defer mu.Unlock()
			if strings.Join(order, ",") != strings.Join(tc.wantOrder, ",") {
				t.Errorf("probe order = %v, want %v", order, tc.wantOrder)
			}
			// Everything that is not the winner must be closed, so a transport
			// that spawned a process during construction does not leak one.
			for _, f := range fakes {
				isWinner := !tc.wantErr && f.name == tc.wantWin
				if isWinner && f.closed {
					t.Errorf("%s won the selection but was closed", f.name)
				}
				// Every non-winner must be closed, whether it lost its probe
				// or was never reached because an earlier candidate won.
				if !isWinner && !f.closed {
					t.Errorf("%s lost the selection but was not closed", f.name)
				}
			}
		})
	}
}

func TestSelectTransportUsesConfiguredCandidates(t *testing.T) {
	t.Parallel()

	var (
		order []string
		mu    sync.Mutex
	)
	only := &fakeTransport{name: "injected", order: &order, mu: &mu}
	got, err := SelectTransport(context.Background(), Config{Transports: []Transport{only}})
	if err != nil {
		t.Fatalf("SelectTransport: %v", err)
	}
	if got.Name() != "injected" {
		t.Errorf("selected %q, want the injected transport", got.Name())
	}
}

func TestBuildTransportsRespectsTheOrderAndTheSwitches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
		want []string
	}{
		{
			name: "stdio only by default",
			cfg:  Config{},
			want: []string{"stdio"},
		},
		{
			name: "vsock is opt-in and comes after stdio",
			cfg:  Config{EnableVsock: true},
			want: []string{"stdio", "vsock"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := buildTransports(context.Background(), tc.cfg.WithDefaults())
			if err != nil {
				t.Fatalf("buildTransports: %v", err)
			}
			var names []string
			for _, tr := range got {
				names = append(names, tr.Name())
				closeTransport(tr)
			}
			if strings.Join(names, ",") != strings.Join(tc.want, ",") {
				t.Errorf("candidates = %v, want %v", names, tc.want)
			}
		})
	}
}

func TestBuildTransportsSkipsTCPWithoutAToken(t *testing.T) {
	t.Parallel()

	cfg := Config{EnableTCP: true, TokenPath: filepath.Join(t.TempDir(), "absent")}.WithDefaults()
	got, err := buildTransports(context.Background(), cfg)
	if err != nil {
		t.Fatalf("buildTransports: %v", err)
	}
	for _, tr := range got {
		defer closeTransport(tr)
		if tr.Name() == "tcp" {
			t.Fatal("the tcp transport was offered with no shared secret")
		}
	}
}

// ---------- the stdio transport and the relay, end to end ----------

// relaySpawner backs the stdio transport with an in-process relay, so the whole
// path -- multiplexer, relay, engine socket -- is exercised on Linux.
type relaySpawner struct {
	socket string

	mu      sync.Mutex
	spawns  int
	failNow error
}

func (r *relaySpawner) Describe(cfg Config) string { return "fake relay" }

func (r *relaySpawner) Spawn(ctx context.Context, cfg Config) (io.ReadWriteCloser, error) {
	r.mu.Lock()
	if r.failNow != nil {
		err := r.failNow
		r.mu.Unlock()
		return nil, err
	}
	r.spawns++
	r.mu.Unlock()

	windowsSide, relaySide := net.Pipe()
	go func() {
		defer relaySide.Close()
		_ = RunRelay(ctx, RelayOptions{
			Config: Config{SocketPath: r.socket, Logger: cfg.Logger},
			In:     relaySide,
			Out:    relaySide,
		})
	}()
	return windowsSide, nil
}

func (r *relaySpawner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.spawns
}

// startEngine runs a unix-socket server that answers every request with a
// greeting, standing in for hulld's API socket.
func startEngine(t *testing.T) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "hull.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_, _ = fmt.Fprintf(c, "engine saw %q", buf[:n])
			}(conn)
		}
	}()
	return socket
}

func TestStdioTransportRoundTrip(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	socket := startEngine(t)
	spawner := &relaySpawner{socket: socket}
	cfg := Config{SocketPath: socket, Spawner: spawner}.WithDefaults()

	transport := NewStdioTransport(ctx, cfg)
	defer transport.Close()

	if err := transport.Probe(ctx); err != nil {
		t.Fatalf("probe: %v", err)
	}

	conn, err := transport.Dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET /_ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if hc, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = hc.CloseWrite()
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := `engine saw "GET /_ping"`; string(got) != want {
		t.Errorf("response = %q, want %q", got, want)
	}
	if n := spawner.count(); n != 1 {
		t.Errorf("spawned %d relays, want 1 shared by every stream", n)
	}
}

func TestStdioTransportSharesOneRelayAcrossStreams(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	socket := startEngine(t)
	spawner := &relaySpawner{socket: socket}
	transport := NewStdioTransport(ctx, Config{SocketPath: socket, Spawner: spawner}.WithDefaults())
	defer transport.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := transport.Dial(ctx)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			msg := fmt.Sprintf("request-%d", i)
			if _, err := conn.Write([]byte(msg)); err != nil {
				errs <- err
				return
			}
			_ = conn.(*Stream).CloseWrite()
			got, err := io.ReadAll(conn)
			if err != nil {
				errs <- err
				return
			}
			if want := fmt.Sprintf("engine saw %q", msg); string(got) != want {
				errs <- fmt.Errorf("got %q, want %q", got, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := spawner.count(); n != 1 {
		t.Errorf("spawned %d relays for 8 connections, want 1", n)
	}
}

func TestStdioTransportRespawnsAfterTheDistroGoesAway(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	socket := startEngine(t)
	spawner := &relaySpawner{socket: socket}
	transport := NewStdioTransport(ctx, Config{SocketPath: socket, Spawner: spawner}.WithDefaults())
	defer transport.Close()

	if err := transport.Probe(ctx); err != nil {
		t.Fatalf("first probe: %v", err)
	}

	// WSL reclaimed the VM: the relay child is gone and its session is dead.
	transport.mu.Lock()
	sess := transport.sess
	transport.mu.Unlock()
	_ = sess.Close()

	if err := transport.Probe(ctx); err != nil {
		t.Fatalf("probe after the relay died: %v", err)
	}
	if n := spawner.count(); n != 2 {
		t.Errorf("spawned %d relays, want 2 (one before and one after the restart)", n)
	}
}

func TestRelaySurfacesADialFailure(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A socket path that cannot be dialled: the engine is not running.
	missing := filepath.Join(t.TempDir(), "absent.sock")
	spawner := &relaySpawner{socket: missing}
	transport := NewStdioTransport(ctx, Config{SocketPath: missing, Spawner: spawner}.WithDefaults())
	defer transport.Close()

	err := transport.Probe(ctx)
	if err == nil {
		t.Fatal("probe succeeded with no engine listening")
	}
	// The whole point of acknowledging an open: the dial failure reaches the
	// Windows side as a reason, not as an unexplained EOF later on.
	var reset *ResetError
	if !errors.As(err, &reset) {
		t.Fatalf("error = %v (%T), want a *ResetError", err, err)
	}
	if !strings.Contains(reset.Reason, missing) {
		t.Errorf("reason = %q, want it to name %s", reset.Reason, missing)
	}
}

// ---------- keep-alive ----------

// fakeKeepAliveProcess stands in for a wsl.exe holder.
type fakeKeepAliveProcess struct {
	instant bool
	err     error
	stopped chan struct{}
	once    sync.Once
}

func (p *fakeKeepAliveProcess) Wait() error {
	if p.instant {
		return p.err
	}
	<-p.stopped
	return p.err
}

func (p *fakeKeepAliveProcess) Stop() error {
	p.once.Do(func() { close(p.stopped) })
	return nil
}

// fakeKeepAliveSpawner hands out fakeKeepAliveProcess values and counts them.
type fakeKeepAliveSpawner struct {
	instant bool
	err     error

	mu      sync.Mutex
	spawned int
	last    *fakeKeepAliveProcess
	notify  chan struct{}
}

func (f *fakeKeepAliveSpawner) Spawn(ctx context.Context, cfg Config) (KeepAliveProcess, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.spawned++
	p := &fakeKeepAliveProcess{instant: f.instant, stopped: make(chan struct{})}
	f.last = p
	if f.notify != nil {
		select {
		case f.notify <- struct{}{}:
		default:
		}
	}
	return p, nil
}

func (f *fakeKeepAliveSpawner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.spawned
}

func (f *fakeKeepAliveSpawner) current() *fakeKeepAliveProcess {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

func TestKeepAliveRestartBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		min, max      time.Duration
		restarts      int
		wantSleepsMS  []int64
		spawnerFails  bool
		wantSpawnsMin int
	}{
		{
			name: "doubles and then caps",
			min:  10 * time.Millisecond, max: 80 * time.Millisecond,
			restarts:     5,
			wantSleepsMS: []int64{10, 20, 40, 80, 80},
		},
		{
			name: "a max below the min is clamped up",
			min:  25 * time.Millisecond, max: 5 * time.Millisecond,
			restarts:     3,
			wantSleepsMS: []int64{25, 25, 25},
		},
		{
			name: "a spawn failure backs off the same way",
			min:  10 * time.Millisecond, max: 40 * time.Millisecond,
			restarts:     4,
			wantSleepsMS: []int64{10, 20, 40, 40},
			spawnerFails: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spawner := &fakeKeepAliveSpawner{instant: true}
			if tc.spawnerFails {
				spawner.err = errors.New("wsl.exe: there is no distribution with the supplied name")
			}

			var (
				mu     sync.Mutex
				sleeps []time.Duration
			)
			enough := make(chan struct{})
			var once sync.Once

			opts := KeepAliveOptions{
				Config:     Config{Distro: "hull-engine"},
				Spawner:    spawner,
				MinBackoff: tc.min,
				MaxBackoff: tc.max,
				// A holder that dies immediately must never look like a
				// recovery, so the reset window is pushed far out of reach.
				ResetAfter: time.Hour,
				Sleep: func(ctx context.Context, d time.Duration) error {
					mu.Lock()
					sleeps = append(sleeps, d)
					n := len(sleeps)
					mu.Unlock()
					if n >= tc.restarts {
						once.Do(func() { close(enough) })
						return context.Canceled
					}
					return nil
				},
			}

			keep, err := StartKeepAliveWith(context.Background(), opts)
			if err != nil {
				t.Fatalf("StartKeepAliveWith: %v", err)
			}
			defer keep.Close()

			select {
			case <-enough:
			case <-time.After(10 * time.Second):
				t.Fatal("the supervisor never reached the expected number of restarts")
			}

			mu.Lock()
			got := append([]time.Duration(nil), sleeps...)
			mu.Unlock()

			if len(got) != len(tc.wantSleepsMS) {
				t.Fatalf("recorded %d backoffs (%v), want %d", len(got), got, len(tc.wantSleepsMS))
			}
			for i, want := range tc.wantSleepsMS {
				if got[i] != time.Duration(want)*time.Millisecond {
					t.Errorf("backoff %d = %s, want %dms", i, got[i], want)
				}
			}
			if !tc.spawnerFails && spawner.count() < tc.restarts {
				t.Errorf("spawned %d holders, want at least %d", spawner.count(), tc.restarts)
			}
		})
	}
}

func TestKeepAliveBackoffResetsAfterALongLife(t *testing.T) {
	t.Parallel()

	spawner := &fakeKeepAliveSpawner{instant: true}
	var (
		mu     sync.Mutex
		sleeps []time.Duration
	)
	done := make(chan struct{})
	var once sync.Once

	keep, err := StartKeepAliveWith(context.Background(), KeepAliveOptions{
		Config:     Config{Distro: "hull-engine"},
		Spawner:    spawner,
		MinBackoff: 10 * time.Millisecond,
		MaxBackoff: 80 * time.Millisecond,
		// Any holder counts as having survived long enough, so the backoff must
		// snap back to the minimum every time instead of climbing.
		ResetAfter: time.Nanosecond,
		Sleep: func(ctx context.Context, d time.Duration) error {
			mu.Lock()
			sleeps = append(sleeps, d)
			n := len(sleeps)
			mu.Unlock()
			if n >= 4 {
				once.Do(func() { close(done) })
				return context.Canceled
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("StartKeepAliveWith: %v", err)
	}
	defer keep.Close()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the supervisor never restarted enough times")
	}

	mu.Lock()
	defer mu.Unlock()
	for i, d := range sleeps {
		if d != 10*time.Millisecond {
			t.Errorf("backoff %d = %s, want it reset to 10ms after a long-lived holder", i, d)
		}
	}
}

func TestKeepAliveReleaseAndHold(t *testing.T) {
	t.Parallel()

	spawner := &fakeKeepAliveSpawner{notify: make(chan struct{}, 8)}
	keep, err := StartKeepAliveWith(context.Background(), KeepAliveOptions{
		Config:     Config{Distro: "hull-engine"},
		Spawner:    spawner,
		MinBackoff: time.Millisecond,
		MaxBackoff: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("StartKeepAliveWith: %v", err)
	}
	defer keep.Close()

	waitFor(t, "the first holder to start", func() bool { return keep.Alive() })
	first := keep.LastRestart()
	if first.IsZero() {
		t.Error("LastRestart is zero while a holder is running")
	}
	if keep.Restarts() != 1 {
		t.Errorf("Restarts = %d, want 1", keep.Restarts())
	}

	// Release is the idle-exit signal: the hold goes away so WSL can reclaim
	// the VM, and nothing restarts it.
	keep.Release()
	waitFor(t, "the holder to stop after Release", func() bool { return !keep.Alive() })
	if !keep.Released() {
		t.Error("Released() is false after Release()")
	}
	countAfterRelease := spawner.count()
	time.Sleep(50 * time.Millisecond)
	if spawner.count() != countAfterRelease {
		t.Errorf("a holder was restarted while released (%d -> %d)", countAfterRelease, spawner.count())
	}

	// Release is idempotent.
	keep.Release()

	if err := keep.Hold(context.Background()); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	waitFor(t, "a holder to come back after Hold", func() bool { return keep.Alive() })
	if keep.Restarts() < 2 {
		t.Errorf("Restarts = %d after Hold, want at least 2", keep.Restarts())
	}
	if !keep.LastRestart().After(first) {
		t.Error("LastRestart did not move when the holder was restarted")
	}
}

func TestKeepAliveCloseStopsTheHolder(t *testing.T) {
	t.Parallel()

	spawner := &fakeKeepAliveSpawner{}
	keep, err := StartKeepAliveWith(context.Background(), KeepAliveOptions{
		Config:     Config{Distro: "hull-engine"},
		Spawner:    spawner,
		MinBackoff: time.Millisecond,
		MaxBackoff: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("StartKeepAliveWith: %v", err)
	}
	waitFor(t, "the holder to start", func() bool { return keep.Alive() })
	proc := spawner.current()

	if err := keep.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-proc.stopped:
	default:
		t.Error("Close did not stop the running holder")
	}
	if err := keep.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if err := keep.Hold(context.Background()); err == nil {
		t.Error("Hold succeeded after Close")
	}
}

func TestKeepAliveClosesWhenItsContextDoes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	spawner := &fakeKeepAliveSpawner{}
	keep, err := StartKeepAliveWith(ctx, KeepAliveOptions{
		Config:     Config{Distro: "hull-engine"},
		Spawner:    spawner,
		MinBackoff: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("StartKeepAliveWith: %v", err)
	}
	waitFor(t, "the holder to start", func() bool { return keep.Alive() })

	cancel()
	waitFor(t, "the agent to shut down with its context", func() bool { return !keep.Alive() })
}

// waitFor polls cond until it holds or the test gives up.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ---------- pipe naming and the security descriptor ----------

func TestPipeSDDL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sid  string
		want string
	}{
		{
			name: "with a user SID",
			sid:  "S-1-5-21-1111111111-2222222222-3333333333-1001",
			want: `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-1111111111-2222222222-3333333333-1001)`,
		},
		{
			name: "no SID degrades to SYSTEM and Administrators only",
			sid:  "",
			want: `D:P(A;;GA;;;SY)(A;;GA;;;BA)`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := PipeSDDL(tc.sid)
			if got != tc.want {
				t.Errorf("PipeSDDL(%q) = %q, want %q", tc.sid, got, tc.want)
			}
			// The DACL must be protected, or an inherited ACE could widen it.
			if !strings.HasPrefix(got, "D:P") {
				t.Errorf("descriptor %q does not start a protected DACL", got)
			}
			if strings.Contains(got, ";WD)") || strings.Contains(got, ";AU)") {
				t.Errorf("descriptor %q grants Everyone or Authenticated Users", got)
			}
		})
	}
}

func TestDefaultPipeNames(t *testing.T) {
	t.Parallel()
	if DefaultPipeName != `\\.\pipe\hull_engine` {
		t.Errorf("DefaultPipeName = %q", DefaultPipeName)
	}
	if DockerPipeName != `\\.\pipe\docker_engine` {
		t.Errorf("DockerPipeName = %q", DockerPipeName)
	}
}

func TestListenPipeOffWindows(t *testing.T) {
	if runtimeIsWindows() {
		t.Skip("this asserts the non-Windows stub")
	}
	if _, err := ListenPipe(PipeConfig{Name: DefaultPipeName}); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("ListenPipe error = %v, want ErrUnsupportedPlatform", err)
	}
}

// runtimeIsWindows reports whether these tests are running on Windows.
func runtimeIsWindows() bool { return os.PathSeparator == '\\' }

// ---------- hvsock helpers ----------

func TestHVServiceGUID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		port uint32
		want string
	}{
		{port: 0, want: "00000000-facb-11e6-bd58-64006a7986d3"},
		{port: 2376, want: "00000948-facb-11e6-bd58-64006a7986d3"},
		{port: 0xFFFFFFFF, want: "ffffffff-facb-11e6-bd58-64006a7986d3"},
	}
	for _, tc := range tests {
		if got := HVServiceGUID(tc.port); got != tc.want {
			t.Errorf("HVServiceGUID(%d) = %q, want %q", tc.port, got, tc.want)
		}
	}
}

func TestGUIDHelpers(t *testing.T) {
	t.Parallel()

	const good = "9a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "canonical", in: good, want: true},
		{name: "uppercase is normalised", in: strings.ToUpper(good), want: true},
		{name: "braced is normalised", in: "{" + good + "}", want: true},
		{name: "too few groups", in: "9a1b2c3d-4e5f-6071-8293", want: false},
		{name: "wrong group length", in: "9a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f", want: false},
		{name: "not hex", in: "9a1b2c3z-4e5f-6071-8293-a4b5c6d7e8f9", want: false},
		{name: "empty", in: "", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := looksLikeGUID(normaliseGUID(tc.in)); got != tc.want {
				t.Errorf("looksLikeGUID(normaliseGUID(%q)) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}

	got := dedupeGUIDs([]string{good, strings.ToUpper(good), "{" + good + "}", "not-a-guid", ""})
	if len(got) != 1 || got[0] != good {
		t.Errorf("dedupeGUIDs = %v, want exactly [%s]", got, good)
	}
}

// ---------- the TCP transport's shared secret ----------

func TestEnsureTokenAndLoadToken(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hull", "token")
	if _, err := LoadToken(path); !errors.Is(err, ErrTokenMissing) {
		t.Fatalf("LoadToken on a missing file = %v, want ErrTokenMissing", err)
	}

	token, err := EnsureToken(path)
	if err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	if len(token) != 64 {
		t.Errorf("token is %d characters, want 64 hex characters of 256-bit secret", len(token))
	}
	again, err := EnsureToken(path)
	if err != nil {
		t.Fatalf("second EnsureToken: %v", err)
	}
	if again != token {
		t.Error("EnsureToken minted a second secret instead of reusing the stored one")
	}
	loaded, err := LoadToken(path)
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if loaded != token {
		t.Errorf("LoadToken = %q, want %q", loaded, token)
	}

	if !runtimeIsWindows() {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("token file mode = %04o, want 0600", perm)
		}
	}
}

func TestTCPHandshake(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		clientToken     string
		serverToken     string
		wantClientError bool
	}{
		{name: "matching secret", clientToken: "correct-horse", serverToken: "correct-horse"},
		{name: "wrong secret", clientToken: "guess", serverToken: "correct-horse", wantClientError: true},
		{name: "empty secret is still compared", clientToken: "", serverToken: "correct-horse", wantClientError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			serverErr := make(chan error, 1)
			go func() { serverErr <- TCPServerHandshake(server, tc.serverToken) }()

			err := TCPClientHandshake(client, tc.clientToken)
			if tc.wantClientError {
				if err == nil {
					t.Fatal("client handshake succeeded with the wrong secret")
				}
				if !errors.Is(err, ErrHandshakeRejected) {
					t.Errorf("client error = %v, want ErrHandshakeRejected", err)
				}
				if serr := <-serverErr; !errors.Is(serr, ErrHandshakeRejected) {
					t.Errorf("server error = %v, want ErrHandshakeRejected", serr)
				}
				return
			}
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			if serr := <-serverErr; serr != nil {
				t.Errorf("server handshake: %v", serr)
			}
		})
	}
}

// ---------- configuration ----------

func TestConfigWithDefaultsIsIdempotent(t *testing.T) {
	t.Setenv(EnvDistro, "")
	once := Config{}.WithDefaults()
	twice := once.WithDefaults()

	if once.Distro != DefaultDistro || twice.Distro != DefaultDistro {
		t.Errorf("distro = %q then %q, want %q", once.Distro, twice.Distro, DefaultDistro)
	}
	if once.SocketPath != twice.SocketPath || once.PipeName != twice.PipeName {
		t.Error("WithDefaults is not idempotent")
	}
	if once.DialTimeout != twice.DialTimeout || once.Window != twice.Window {
		t.Error("WithDefaults changed a timeout or window on the second application")
	}
	if once.Runner == nil {
		t.Error("WithDefaults left Runner nil")
	}
}

func TestConfigHonoursHullDistro(t *testing.T) {
	t.Setenv(EnvDistro, "my-engine")
	if got := (Config{}).WithDefaults().Distro; got != "my-engine" {
		t.Errorf("distro = %q, want the value of %s", got, EnvDistro)
	}
	if got := (Config{Distro: "explicit"}).WithDefaults().Distro; got != "explicit" {
		t.Errorf("distro = %q, want the explicit value to win over %s", got, EnvDistro)
	}
}

func TestRelayArgsMatchTheDistroLayout(t *testing.T) {
	t.Parallel()

	cfg := Config{Distro: "hull-engine"}.WithDefaults()
	got := strings.Join(cfg.relayArgs(), " ")
	want := "-d hull-engine -u root --exec /usr/local/bin/hull __relay --socket /run/hull/hull.sock"
	if got != want {
		t.Errorf("relayArgs = %q, want %q", got, want)
	}

	keep := strings.Join(cfg.keepAliveArgs(), " ")
	if !strings.Contains(keep, "-d hull-engine -u root --exec /bin/sh -c") {
		t.Errorf("keepAliveArgs = %q", keep)
	}
	if !strings.Contains(keep, "sleep 3600") {
		t.Errorf("keepAliveArgs = %q, want a long sleep loop", keep)
	}
}

func TestWSLEnvForcesUTF8(t *testing.T) {
	t.Setenv(EnvUTF8, "0")
	env := wslEnv(nil)
	seen := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, EnvUTF8+"=") {
			seen++
			if kv != EnvUTF8+"=1" {
				t.Errorf("%s set to %q, want 1", EnvUTF8, kv)
			}
		}
	}
	if seen != 1 {
		t.Errorf("%s appears %d times in the child environment, want exactly once", EnvUTF8, seen)
	}
}

// ---------- the proxy's half-close ----------

func TestProxyHalfCloses(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Two socket pairs joined by proxy, standing in for a pipe client on one
	// side and the engine on the other.
	clientSide, bridgeLeft := net.Pipe()
	bridgeRight, engineSide := net.Pipe()

	go func() { _ = proxy(ctx, bridgeLeft, bridgeRight) }()

	go func() {
		buf := make([]byte, 64)
		n, err := engineSide.Read(buf)
		if err != nil {
			return
		}
		_, _ = engineSide.Write([]byte("echo:" + string(buf[:n])))
		_ = engineSide.Close()
	}()

	if _, err := clientSide.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := io.ReadAll(clientSide)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := "echo:hello"; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestIsExpectedClose(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: true},
		{name: "EOF", err: io.EOF, want: true},
		{name: "closed net conn", err: net.ErrClosed, want: true},
		{name: "closed stream", err: ErrStreamClosed, want: true},
		{name: "closed session", err: ErrSessionClosed, want: true},
		{name: "wrapped session close", err: fmt.Errorf("relay: %w", ErrSessionClosed), want: true},
		{name: "peer reset", err: &ResetError{StreamID: 3, Reason: "engine restarted"}, want: true},
		{name: "a real failure", err: errors.New("connection reset by peer"), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isExpectedClose(tc.err); got != tc.want {
				t.Errorf("isExpectedClose(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// ---------- shared test helpers ----------

// utf16leBytes encodes s as UTF-16LE with no byte-order mark, which is what an
// older wsl.exe writes to a redirected pipe when WSL_UTF8 is not honoured.
func utf16leBytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}

// utf16beBytes encodes s as UTF-16BE with no byte-order mark. wsl.exe does not
// emit this, but the decoder claims to handle it and the claim is tested.
func utf16beBytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.BigEndian.PutUint16(out[2*i:], u)
	}
	return out
}

// fakeRunner stands in for wsl.exe. It records every invocation so a test can
// assert on the exact argument list, and answers from a scripted handler so no
// WSL installation is needed.
type fakeRunner struct {
	handler func(name string, args []string) ([]byte, error)

	mu    sync.Mutex
	calls [][]string
}

// Run implements CommandRunner.
func (r *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.calls = append(r.calls, append([]string{}, args...))
	h := r.handler
	r.mu.Unlock()
	if h == nil {
		return nil, nil
	}
	return h(name, args)
}

// count reports how many commands have been run.
func (r *fakeRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}
