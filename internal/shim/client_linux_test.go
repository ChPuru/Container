package shim

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testShim is a real server and a real Client either side of a real unix
// socket, with a supervisor that has no runtime behind it. Everything the
// protocol touches — framing, the hub, the detach filter, the event bus — is
// the production code; only the container is imaginary.
type testShim struct {
	t      *testing.T
	cfg    Config
	sup    *supervisor
	srv    *server
	client *Client
	sink   *recordingSink
}

func newTestShim(t *testing.T, terminal bool) *testShim {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		ID:            "testcontainer",
		BundleDir:     dir,
		ContainerDir:  dir,
		RuntimeName:   "none",
		RuntimeBinary: "/bin/true",
		Terminal:      terminal,
		OpenStdin:     true,
	}
	sink := &recordingSink{}
	sup := &supervisor{
		cfg:     cfg,
		cg:      newCgroupReader(""),
		events:  newEventBus(),
		exited:  make(chan struct{}),
		acked:   make(chan struct{}),
		execs:   make(map[string]*execProc),
		st:      State{Status: StatusRunning, Pid: 4242, StartedAt: time.Unix(1700000000, 0).UTC()},
		started: true,
	}
	sup.hub = NewHub(sink, 1024)

	l, err := listenControl(cfg.SocketPath())
	if err != nil {
		t.Fatalf("listenControl: %v", err)
	}
	srv := newServer(context.Background(), cfg, sup, l)
	go srv.Serve()

	client, err := Connect(cfg.SocketPath())
	if err != nil {
		srv.Close()
		t.Fatalf("Connect: %v", err)
	}
	ts := &testShim{t: t, cfg: cfg, sup: sup, srv: srv, client: client, sink: sink}
	t.Cleanup(func() {
		client.Close()
		srv.Close()
	})
	return ts
}

// finish marks the imaginary container as exited with the given code.
func (ts *testShim) finish(code int) {
	ts.sup.mu.Lock()
	ts.sup.st.Exited = true
	ts.sup.st.Status = StatusStopped
	ts.sup.st.ExitCode = code
	ts.sup.st.Pid = 0
	ts.sup.st.FinishedAt = time.Now()
	ts.sup.mu.Unlock()
	ts.sup.events.Publish(Event{Type: EventExit, ID: ts.cfg.ID, ExitCode: code, Time: time.Now()})
	close(ts.sup.exited)
}

func TestConnectRefusesADeadSocket(t *testing.T) {
	t.Parallel()
	_, err := Connect(filepath.Join(t.TempDir(), "shim.sock"))
	if !errors.Is(err, ErrShimGone) {
		t.Fatalf("err = %v, want ErrShimGone", err)
	}
}

func TestClientStateAndStats(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	ctx := context.Background()

	st, err := ts.client.State(ctx)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.Status != StatusRunning || st.Pid != 4242 || st.Exited {
		t.Fatalf("State = %+v, want a running container", st)
	}
	if !st.StartedAt.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Errorf("StartedAt = %v, did not survive the wire", st.StartedAt)
	}

	sample, err := ts.client.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if sample.OnlineCPUs <= 0 {
		t.Errorf("OnlineCPUs = %d, want a positive count even with no cgroup", sample.OnlineCPUs)
	}
	if sample.Read.IsZero() {
		t.Error("Stats.Read should be stamped")
	}
}

func TestClientWaitReturnsTheExitCode(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)

	done := make(chan int, 1)
	go func() {
		code, err := ts.client.Wait(context.Background())
		if err != nil {
			t.Errorf("Wait: %v", err)
			close(done)
			return
		}
		done <- code
	}()

	time.Sleep(50 * time.Millisecond)
	ts.finish(137)

	select {
	case code, ok := <-done:
		if !ok {
			t.Fatal("Wait failed")
		}
		if code != 137 {
			t.Fatalf("Wait = %d, want 137", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait never returned")
	}

	// A Wait after the fact returns immediately: that is what lets a
	// restarted daemon collect a status it missed.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	code, err := ts.client.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait after exit: %v", err)
	}
	if code != 137 {
		t.Fatalf("Wait after exit = %d, want 137", code)
	}
}

func TestClientWaitHonoursContext(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := ts.client.Wait(ctx); err == nil {
		t.Fatal("Wait should have been cancelled")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Wait took %v to notice the cancellation", elapsed)
	}
}

func TestClientSentinelErrorsCrossTheSocket(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	ctx := context.Background()

	// No pty was set up, so Resize must say so precisely.
	if err := ts.client.Resize(ctx, 24, 80); !errors.Is(err, ErrNoTerminal) {
		t.Errorf("Resize = %v, want ErrNoTerminal", err)
	}
	// Started already, so Start must refuse.
	if err := ts.client.Start(ctx); !errors.Is(err, ErrAlreadyStarted) {
		t.Errorf("Start = %v, want ErrAlreadyStarted", err)
	}
	// No pidfd behind this supervisor, so a signal cannot be delivered.
	if err := ts.client.Kill(ctx, 15, false); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Kill = %v, want ErrNotRunning", err)
	}
	// An exec id that could escape the container directory is refused before
	// anything touches the filesystem.
	if _, err := ts.client.Exec(ctx, "../../etc/passwd", []byte(`{"args":["/bin/true"]}`), AttachOptions{}); err == nil {
		t.Error("Exec accepted a path-traversing exec id")
	} else if !strings.Contains(err.Error(), "alphanumeric") {
		t.Errorf("Exec error %q does not explain the rejected id", err)
	}
	if _, err := ts.client.Exec(ctx, "ok1", []byte(`{"args":["/bin/true"]}`), AttachOptions{}); err == nil {
		t.Error("Exec against a supervisor with no runtime should fail")
	}
	if err := ts.client.Resize(ctx, 0, 0); err == nil {
		t.Error("a 0x0 resize should be refused")
	}
}

func TestClientCloseStopsFurtherCalls(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	if err := ts.client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := ts.client.State(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("State after Close = %v, want ErrClosed", err)
	}
	if err := ts.client.Close(); err != nil {
		t.Errorf("a second Close returned %v", err)
	}
}

// readN reads exactly n bytes or fails.
func readN(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	buf := make([]byte, n)
	type result struct {
		s   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		_, err := io.ReadFull(r, buf)
		ch <- result{string(buf), err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("read %d bytes: %v (got %q)", n, res.err, res.s)
		}
		return res.s
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out reading %d bytes", n)
		return ""
	}
}

func TestAttachDeliversToEveryClient(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	ctx := context.Background()

	const n = 4
	streams := make([]*AttachStream, n)
	for i := range streams {
		s, err := ts.client.Attach(ctx, AttachOptions{Stdout: true, Stderr: true})
		if err != nil {
			t.Fatalf("attacher %d: %v", i, err)
		}
		streams[i] = s
		defer s.Close()
	}
	// Give the server time to register every attacher before writing.
	deadline := time.Now().Add(2 * time.Second)
	for ts.sup.hub.Count() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := ts.sup.hub.Count(); got != n {
		t.Fatalf("hub has %d attachers, want %d", got, n)
	}

	ts.sup.hub.Write(KindStdout, []byte("shared output"))
	ts.sup.hub.Write(KindStderr, []byte("shared error"))

	var wg sync.WaitGroup
	for i, s := range streams {
		wg.Add(1)
		go func(i int, s *AttachStream) {
			defer wg.Done()
			if got := readN(t, s.Stdout, len("shared output")); got != "shared output" {
				t.Errorf("attacher %d stdout = %q", i, got)
			}
			if got := readN(t, s.Stderr, len("shared error")); got != "shared error" {
				t.Errorf("attacher %d stderr = %q", i, got)
			}
		}(i, s)
	}
	wg.Wait()
}

func TestAttachGrantsStdinToOneClient(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	ctx := context.Background()

	first, err := ts.client.Attach(ctx, AttachOptions{Stdin: true, Stdout: true})
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}
	defer first.Close()
	if first.Stdin == nil {
		t.Fatal("the first attacher should have a stdin writer")
	}

	_, err = ts.client.Attach(ctx, AttachOptions{Stdin: true, Stdout: true})
	if !errors.Is(err, ErrStdinInUse) {
		t.Fatalf("second attach = %v, want ErrStdinInUse", err)
	}
	// The refusal must be specific enough for a user to act on.
	if !strings.Contains(err.Error(), "already attached") {
		t.Errorf("error %q does not explain the refusal", err)
	}

	// An output-only attacher is still welcome.
	observer, err := ts.client.Attach(ctx, AttachOptions{Stdout: true})
	if err != nil {
		t.Fatalf("output-only attach: %v", err)
	}
	defer observer.Close()

	if _, err := first.Stdin.Write([]byte("whoami\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for ts.sink.String() != "whoami\n" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := ts.sink.String(); got != "whoami\n" {
		t.Fatalf("container stdin = %q, want %q", got, "whoami\n")
	}
}

func TestAttachStdinPassesToTheNextClientAfterDetach(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	ctx := context.Background()

	first, err := ts.client.Attach(ctx, AttachOptions{Stdin: true, Stdout: true})
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for ts.sup.hub.Count() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	second, err := ts.client.Attach(ctx, AttachOptions{Stdin: true, Stdout: true})
	if err != nil {
		t.Fatalf("second attach after the first detached: %v", err)
	}
	defer second.Close()
	if _, err := second.Stdin.Write([]byte("second\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for ts.sink.String() != "second\n" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := ts.sink.String(); got != "second\n" {
		t.Fatalf("container stdin = %q", got)
	}
}

func TestAttachReplaysRecentOutput(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	ts.sup.hub.Write(KindStdout, []byte("earlier output\n"))

	s, err := ts.client.Attach(context.Background(), AttachOptions{Stdout: true, Stderr: true})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer s.Close()
	if got := readN(t, s.Stdout, len("earlier output\n")); got != "earlier output\n" {
		t.Fatalf("late attacher saw %q, want the replayed output", got)
	}
}

func TestAttachDetachKeysEndTheStreamWithoutKillingTheContainer(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)

	s, err := ts.client.Attach(context.Background(), AttachOptions{
		Stdin: true, Stdout: true, DetachKeys: "ctrl-p,ctrl-q",
	})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer s.Close()

	// Ordinary typing, then a lone ctrl-p with an unrelated byte after it
	// (which must be forwarded), then the real sequence.
	if _, err := s.Stdin.Write([]byte("echo hi\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := s.Stdin.Write([]byte{0x10, 'x'}); err != nil {
		t.Fatalf("write: %v", err)
	}
	want := "echo hi\n" + string([]byte{0x10, 'x'})
	deadline := time.Now().Add(2 * time.Second)
	for ts.sink.String() != want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := ts.sink.String(); got != want {
		t.Fatalf("container stdin = %q, want %q", got, want)
	}

	if _, err := s.Stdin.Write([]byte{0x10, 0x11}); err != nil {
		t.Fatalf("write detach sequence: %v", err)
	}
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the detach sequence did not end the stream")
	}
	if !errors.Is(s.Err(), ErrDetached) {
		t.Fatalf("Err = %v, want ErrDetached", s.Err())
	}
	// The detach bytes themselves must not reach the container.
	if got := ts.sink.String(); got != want {
		t.Fatalf("container stdin = %q, want the detach keys withheld", got)
	}
	// And the container is untouched: the shim still answers.
	if _, err := ts.client.State(context.Background()); err != nil {
		t.Fatalf("State after detaching: %v", err)
	}
}

func TestAttachStdinCloseHalfClosesTheContainer(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	s, err := ts.client.Attach(context.Background(), AttachOptions{Stdin: true, Stdout: true})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer s.Close()
	if _, err := s.Stdin.Write([]byte("input\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.Stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !ts.sink.isClosed() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !ts.sink.isClosed() {
		t.Fatal("closing the attach stdin did not close the container's input")
	}
	// The output half is still live.
	ts.sup.hub.Write(KindStdout, []byte("still talking"))
	if got := readN(t, s.Stdout, len("still talking")); got != "still talking" {
		t.Fatalf("stdout after half-close = %q", got)
	}
}

func TestAttachTerminalMergesStreams(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, true)
	s, err := ts.client.Attach(context.Background(), AttachOptions{Stdout: true, Stderr: true})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer s.Close()
	if !s.Terminal {
		t.Fatal("the stream should report a terminal")
	}
	if s.Stderr != nil {
		t.Error("a terminal stream must not expose a separate stderr")
	}
	ts.sup.hub.Write(KindStdout, []byte("merged"))
	if got := readN(t, s.Stdout, len("merged")); got != "merged" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestAttachEndsWhenTheContainerOutputEnds(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	s, err := ts.client.Attach(context.Background(), AttachOptions{Stdout: true, Stderr: true})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer s.Close()
	ts.sup.hub.Write(KindStdout, []byte("last words"))
	ts.sup.hub.Close()

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(&buf, s.Stdout)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stdout reader never saw EOF")
	}
	if buf.String() != "last words" {
		t.Fatalf("stdout = %q, want %q", buf.String(), "last words")
	}
}

func TestEventsStream(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := ts.client.Events(ctx)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	ts.sup.events.Publish(Event{Type: EventOOM, ID: ts.cfg.ID, Time: time.Now()})
	ts.finish(137)

	var got []Event
	deadline := time.After(5 * time.Second)
	for len(got) < 2 {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("the event stream closed after %d events", len(got))
			}
			got = append(got, ev)
		case <-deadline:
			t.Fatalf("timed out after %d events", len(got))
		}
	}
	if got[0].Type != EventOOM {
		t.Errorf("first event = %q, want %q", got[0].Type, EventOOM)
	}
	if got[1].Type != EventExit || got[1].ExitCode != 137 {
		t.Errorf("second event = %+v, want an exit with code 137", got[1])
	}
}

// TestEventsReplayReachesALateDaemon is the restart case: hulld was not
// listening when the container died, reconnects afterwards, and must still be
// told what happened.
func TestEventsReplayReachesALateDaemon(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	ts.finish(42)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := ts.client.Events(ctx)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	select {
	case ev := <-ch:
		if ev.Type != EventExit || ev.ExitCode != 42 {
			t.Fatalf("replayed event = %+v, want an exit with code 42", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a client that subscribed after the exit was never told about it")
	}
}

func TestAckReleasesTheGracePeriod(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	select {
	case <-ts.sup.Acked():
		t.Fatal("the exit status is acknowledged before anyone asked")
	default:
	}
	if err := ts.client.Ack(context.Background()); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	select {
	case <-ts.sup.Acked():
	case <-time.After(2 * time.Second):
		t.Fatal("Ack did not release the grace period")
	}
	// Acking twice must not panic on a closed channel.
	if err := ts.client.Ack(context.Background()); err != nil {
		t.Fatalf("second Ack: %v", err)
	}
}

func TestUnknownOperationIsReported(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	conn, err := net.Dial("unix", ts.cfg.SocketPath())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := WriteJSONFrame(conn, KindRequest, Request{Op: "teleport"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := ReadResponse(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.Error == "" || !strings.Contains(resp.Error, "teleport") {
		t.Fatalf("response = %+v, want a complaint naming the operation", resp)
	}
}

func TestControlSocketIsOwnerOnly(t *testing.T) {
	t.Parallel()
	ts := newTestShim(t, false)
	st, err := os.Stat(ts.cfg.SocketPath())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("control socket mode = %o, want 600: it can signal the container", perm)
	}
}
