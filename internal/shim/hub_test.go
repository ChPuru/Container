package shim

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingSink stands in for the container's stdin.
type recordingSink struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func (s *recordingSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, errors.New("closed")
	}
	return s.buf.Write(p)
}

func (s *recordingSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *recordingSink) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *recordingSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// drain collects everything an attacher receives until its channel closes.
func drain(a *Attacher) (string, string) {
	var out, errOut strings.Builder
	for c := range a.Chunks() {
		switch c.Stream {
		case KindStdout:
			out.Write(c.Data)
		case KindStderr:
			errOut.Write(c.Data)
		}
	}
	return out.String(), errOut.String()
}

// collect reads exactly n bytes worth of chunks or times out.
func collect(t *testing.T, a *Attacher, want string) string {
	t.Helper()
	var got strings.Builder
	deadline := time.After(2 * time.Second)
	for got.Len() < len(want) {
		select {
		case c, ok := <-a.Chunks():
			if !ok {
				return got.String()
			}
			got.Write(c.Data)
		case <-deadline:
			t.Fatalf("timed out waiting for %q, have %q", want, got.String())
		}
	}
	return got.String()
}

func TestHubDeliversToEveryAttacher(t *testing.T) {
	t.Parallel()
	const n = 5
	h := NewHub(&recordingSink{}, 1024)

	attachers := make([]*Attacher, n)
	for i := range attachers {
		a := NewAttacher(AttachOptions{Stdout: true, Stderr: true})
		if err := h.Attach(a); err != nil {
			t.Fatalf("attacher %d: %v", i, err)
		}
		attachers[i] = a
	}
	if h.Count() != n {
		t.Fatalf("Count = %d, want %d", h.Count(), n)
	}

	if _, err := h.Write(KindStdout, []byte("hello ")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := h.Write(KindStderr, []byte("warn")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := h.Write(KindStdout, []byte("world")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	h.Close()

	for i, a := range attachers {
		out, errOut := drain(a)
		if out != "hello world" {
			t.Errorf("attacher %d stdout = %q, want %q", i, out, "hello world")
		}
		if errOut != "warn" {
			t.Errorf("attacher %d stderr = %q, want %q", i, errOut, "warn")
		}
	}
}

func TestHubStreamSelection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		opts       AttachOptions
		wantStdout string
		wantStderr string
	}{
		{"both", AttachOptions{Stdout: true, Stderr: true}, "out", "err"},
		{"stdout only", AttachOptions{Stdout: true}, "out", ""},
		{"stderr only subscribes to both because a tty merges them", AttachOptions{Stderr: true}, "out", "err"},
		{"neither", AttachOptions{}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := NewHub(nil, 1024)
			a := NewAttacher(tt.opts)
			if err := h.Attach(a); err != nil {
				t.Fatalf("Attach: %v", err)
			}
			h.Write(KindStdout, []byte("out"))
			h.Write(KindStderr, []byte("err"))
			h.Close()
			out, errOut := drain(a)
			if out != tt.wantStdout || errOut != tt.wantStderr {
				t.Errorf("got (%q, %q), want (%q, %q)", out, errOut, tt.wantStdout, tt.wantStderr)
			}
		})
	}
}

func TestHubGrantsStdinToTheFirstAttacherOnly(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	h := NewHub(sink, 1024)

	first := NewAttacher(AttachOptions{Stdin: true, Stdout: true})
	if err := h.Attach(first); err != nil {
		t.Fatalf("first attacher: %v", err)
	}
	if !first.StdinGranted() {
		t.Fatal("the first attacher should hold stdin")
	}

	for i := 0; i < 3; i++ {
		second := NewAttacher(AttachOptions{Stdin: true, Stdout: true})
		err := h.Attach(second)
		if !errors.Is(err, ErrStdinInUse) {
			t.Fatalf("attacher %d: err = %v, want ErrStdinInUse", i+2, err)
		}
		if second.StdinGranted() {
			t.Fatalf("attacher %d was refused but thinks it holds stdin", i+2)
		}
	}

	// An attacher that does not ask for stdin still gets in.
	observer := NewAttacher(AttachOptions{Stdout: true})
	if err := h.Attach(observer); err != nil {
		t.Fatalf("output-only attacher: %v", err)
	}
	if observer.StdinGranted() {
		t.Fatal("an attacher that did not ask for stdin must not hold it")
	}
	if _, err := observer.Write([]byte("nope")); !errors.Is(err, ErrStdinInUse) {
		t.Fatalf("observer.Write err = %v, want ErrStdinInUse", err)
	}

	if _, err := first.Write([]byte("ls\n")); err != nil {
		t.Fatalf("first.Write: %v", err)
	}
	if got := sink.String(); got != "ls\n" {
		t.Fatalf("container stdin = %q, want %q", got, "ls\n")
	}
}

func TestHubReleasesStdinOnDetach(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	h := NewHub(sink, 1024)

	first := NewAttacher(AttachOptions{Stdin: true, Stdout: true})
	if err := h.Attach(first); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	first.Detach(ErrDetached)
	if !errors.Is(first.Err(), ErrDetached) {
		t.Errorf("Err = %v, want ErrDetached", first.Err())
	}
	select {
	case <-first.Done():
	case <-time.After(time.Second):
		t.Fatal("Done was not closed after Detach")
	}

	second := NewAttacher(AttachOptions{Stdin: true, Stdout: true})
	if err := h.Attach(second); err != nil {
		t.Fatalf("the second attacher should inherit stdin, got %v", err)
	}
	if !second.StdinGranted() {
		t.Fatal("the second attacher should now hold stdin")
	}
	if _, err := second.Write([]byte("who\n")); err != nil {
		t.Fatalf("second.Write: %v", err)
	}
	if got := sink.String(); got != "who\n" {
		t.Fatalf("container stdin = %q, want %q", got, "who\n")
	}
}

func TestHubRefusesStdinWithoutASink(t *testing.T) {
	t.Parallel()
	h := NewHub(nil, 1024)
	if h.HasStdin() {
		t.Fatal("a hub with no sink should report no stdin")
	}
	a := NewAttacher(AttachOptions{Stdin: true, Stdout: true})
	if err := h.Attach(a); !errors.Is(err, ErrStdinUnavailable) {
		t.Fatalf("err = %v, want ErrStdinUnavailable", err)
	}
}

func TestHubCloseStdinIsOwnerOnly(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	h := NewHub(sink, 1024)

	owner := NewAttacher(AttachOptions{Stdin: true, Stdout: true})
	if err := h.Attach(owner); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	observer := NewAttacher(AttachOptions{Stdout: true})
	if err := h.Attach(observer); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := observer.CloseStdin(); !errors.Is(err, ErrStdinInUse) {
		t.Fatalf("observer.CloseStdin err = %v, want ErrStdinInUse", err)
	}
	if err := owner.CloseStdin(); err != nil {
		t.Fatalf("owner.CloseStdin: %v", err)
	}
	if !sink.isClosed() {
		t.Fatal("closing stdin should have closed the container's input sink")
	}
	if h.HasStdin() {
		t.Fatal("HasStdin should be false once stdin is closed")
	}
}

func TestHubReplaysTheRingToALateAttacher(t *testing.T) {
	t.Parallel()
	h := NewHub(nil, 1024)

	early := NewAttacher(AttachOptions{Stdout: true, Stderr: true})
	if err := h.Attach(early); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	h.Write(KindStdout, []byte("step 1\n"))
	h.Write(KindStderr, []byte("note\n"))
	h.Write(KindStdout, []byte("step 2\n"))

	late := NewAttacher(AttachOptions{Stdout: true, Stderr: true})
	if err := h.Attach(late); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	// The late attacher sees the replay immediately, before any new output.
	if got := collect(t, late, "step 1\nnote\nstep 2\n"); got != "step 1\nnote\nstep 2\n" {
		t.Fatalf("replay = %q", got)
	}

	h.Write(KindStdout, []byte("step 3\n"))
	h.Close()

	earlyOut, _ := drain(early)
	if earlyOut != "step 1\nstep 2\nstep 3\n" {
		t.Errorf("early attacher stdout = %q", earlyOut)
	}
	lateOut, _ := drain(late)
	if lateOut != "step 3\n" {
		t.Errorf("late attacher saw %q after the replay, want %q", lateOut, "step 3\n")
	}
}

func TestHubReplayIsBoundedByTheRing(t *testing.T) {
	t.Parallel()
	h := NewHub(nil, 16)
	h.Write(KindStdout, []byte("0123456789"))
	h.Write(KindStdout, []byte("ABCDEFGHIJ"))

	late := NewAttacher(AttachOptions{Stdout: true})
	if err := h.Attach(late); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	h.Close()
	out, _ := drain(late)
	if out != "456789ABCDEFGHIJ" {
		t.Fatalf("replay = %q, want the last 16 bytes", out)
	}
}

func TestHubDropsAStalledAttacher(t *testing.T) {
	t.Parallel()
	h := NewHub(nil, 64)
	slow := NewAttacher(AttachOptions{Stdout: true})
	if err := h.Attach(slow); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	// A bystander that subscribes to nothing can never stall, so it is a
	// deterministic witness that the hub drops only the attacher at fault.
	bystander := NewAttacher(AttachOptions{})
	if err := h.Attach(bystander); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	// Nobody reads `slow`, so its queue fills and the hub disconnects it
	// rather than letting the container block on it.
	for i := 0; i < attacherQueue*4; i++ {
		if _, err := h.Write(KindStdout, []byte("x")); err != nil {
			t.Errorf("Write: %v", err)
		}
	}

	select {
	case <-slow.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the stalled attacher was never disconnected")
	}
	if !errors.Is(slow.Err(), errAttacherStalled) {
		t.Errorf("Err = %v, want errAttacherStalled", slow.Err())
	}
	if h.Count() != 1 {
		t.Errorf("Count = %d, want only the bystander left", h.Count())
	}
	select {
	case <-bystander.Done():
		t.Error("the bystander was disconnected too")
	default:
	}
	h.Close()
}

func TestHubCloseEndsEveryStream(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	h := NewHub(sink, 64)
	var as []*Attacher
	for i := 0; i < 3; i++ {
		a := NewAttacher(AttachOptions{Stdout: true})
		if err := h.Attach(a); err != nil {
			t.Fatalf("Attach: %v", err)
		}
		as = append(as, a)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for i, a := range as {
		select {
		case <-a.Done():
		case <-time.After(time.Second):
			t.Fatalf("attacher %d was not ended by Close", i)
		}
	}
	if !sink.isClosed() {
		t.Error("Close should close the container's stdin sink")
	}
	if err := h.Close(); err != nil {
		t.Errorf("a second Close returned %v, want nil", err)
	}
	a := NewAttacher(AttachOptions{Stdout: true})
	if err := h.Attach(a); !errors.Is(err, ErrNotRunning) {
		t.Errorf("attaching to a closed hub = %v, want ErrNotRunning", err)
	}
}

func TestHubConcurrentAttachAndWrite(t *testing.T) {
	t.Parallel()
	h := NewHub(&recordingSink{}, 4096)
	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			h.Write(KindStdout, []byte("tick "))
		}
	}()

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := NewAttacher(AttachOptions{Stdout: true})
			if err := h.Attach(a); err != nil {
				return
			}
			go func() {
				for range a.Chunks() {
				}
			}()
			time.Sleep(time.Millisecond)
			a.Detach(nil)
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
	h.Close()
}
