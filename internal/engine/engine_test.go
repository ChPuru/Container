package engine

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ChPuru/hull/internal/types"
)

func TestNegotiateSpecVersion(t *testing.T) {
	tests := []struct {
		name     string
		hull     string
		accepted []string
		want     string
	}{
		{
			name:     "crun reports a min and a max with a dev suffix",
			hull:     "1.2.0",
			accepted: []string{"1.0.0", "1.1.0+dev"},
			want:     "1.1.0",
		},
		{
			name:     "a runtime that understands exactly what hull models",
			hull:     "1.2.0",
			accepted: []string{"1.2.0"},
			want:     "1.2.0",
		},
		{
			name:     "a runtime newer than hull does not raise the version",
			hull:     "1.0.2",
			accepted: []string{"1.0.0", "1.2.0"},
			want:     "1.0.2",
		},
		{
			name:     "no answer falls back to hull's own version",
			hull:     "1.2.0",
			accepted: nil,
			want:     "1.2.0",
		},
		{
			name:     "unparsable entries are ignored",
			hull:     "1.2.0",
			accepted: []string{"whatever", "1.0.2"},
			want:     "1.0.2",
		},
		{
			name:     "the highest mutually understood version wins",
			hull:     "1.2.0",
			accepted: []string{"1.0.0", "1.0.2", "1.1.0"},
			want:     "1.1.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NegotiateSpecVersion(tt.hull, tt.accepted); got != tt.want {
				t.Errorf("NegotiateSpecVersion(%q, %q) = %q, want %q",
					tt.hull, tt.accepted, got, tt.want)
			}
		})
	}
}

func TestParseSignal(t *testing.T) {
	tests := []struct {
		in      string
		want    syscall.Signal
		wantErr bool
	}{
		{in: "SIGTERM", want: 15},
		{in: "TERM", want: 15},
		{in: "term", want: 15},
		{in: "15", want: 15},
		{in: "SIGKILL", want: 9},
		{in: "SIGUSR1", want: 10},
		{in: "", wantErr: true},
		{in: "SIGNOPE", wantErr: true},
		{in: "0", wantErr: true},
		{in: "200", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseSignal(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseSignal(%q) = %d, want an error", tt.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Errorf("error should wrap ErrInvalid, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSignal(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseSignal(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestSignalNameRoundTrip(t *testing.T) {
	for _, name := range []string{"SIGTERM", "SIGKILL", "SIGHUP", "SIGUSR2"} {
		sig, err := ParseSignal(name)
		if err != nil {
			t.Fatalf("ParseSignal(%q): %v", name, err)
		}
		if got := SignalName(sig); got != name {
			t.Errorf("SignalName(%d) = %q, want %q", sig, got, name)
		}
	}
}

func TestKeyedLockSerialisesOneKey(t *testing.T) {
	k := newKeyedLock()
	ctx := context.Background()

	const workers = 32
	var (
		mu      sync.Mutex
		inside  int
		maxSeen int
		total   int
	)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := k.Lock(ctx, "same")
			if err != nil {
				t.Errorf("Lock: %v", err)
				return
			}
			defer unlock()
			mu.Lock()
			inside++
			if inside > maxSeen {
				maxSeen = inside
			}
			total++
			mu.Unlock()

			time.Sleep(time.Millisecond)

			mu.Lock()
			inside--
			mu.Unlock()
		}()
	}
	wg.Wait()

	if maxSeen != 1 {
		t.Errorf("%d goroutines were inside the same key's lock at once, want 1", maxSeen)
	}
	if total != workers {
		t.Errorf("%d goroutines ran, want %d", total, workers)
	}
	if held := k.Held(); held != 0 {
		t.Errorf("%d lock entries leaked", held)
	}
}

func TestKeyedLockDoesNotBlockOtherKeys(t *testing.T) {
	k := newKeyedLock()
	ctx := context.Background()

	unlockA, err := k.Lock(ctx, "a")
	if err != nil {
		t.Fatalf("Lock(a): %v", err)
	}
	// A long-running operation on one container must never delay another.
	done := make(chan struct{})
	go func() {
		defer close(done)
		unlockB, err := k.Lock(ctx, "b")
		if err != nil {
			t.Errorf("Lock(b): %v", err)
			return
		}
		unlockB()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("locking a different key blocked behind an unrelated key")
	}
	unlockA()
	if held := k.Held(); held != 0 {
		t.Errorf("%d lock entries leaked", held)
	}
}

func TestKeyedLockHonoursContextCancellation(t *testing.T) {
	k := newKeyedLock()
	unlock, err := k.Lock(context.Background(), "busy")
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := k.Lock(ctx, "busy"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Lock on a held key = %v, want a deadline error", err)
	}
	if _, ok := k.TryLock("busy"); ok {
		t.Fatal("TryLock succeeded on a held key")
	}
}

func TestNotifierDeliversToEverySubscriber(t *testing.T) {
	n := newNotifier()
	a, cancelA := n.subscribe("c1")
	b, cancelB := n.subscribe("c1")
	other, cancelOther := n.subscribe("c2")
	defer cancelA()
	defer cancelB()
	defer cancelOther()

	n.publish("c1", lifecycleEvent{kind: notifyExit, exitCode: 7})

	for i, ch := range []<-chan lifecycleEvent{a, b} {
		select {
		case ev := <-ch:
			if ev.kind != notifyExit || ev.exitCode != 7 {
				t.Errorf("subscriber %d got %+v", i, ev)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d never woke up", i)
		}
	}
	select {
	case ev := <-other:
		t.Fatalf("a subscriber of another container received %+v", ev)
	default:
	}

	cancelA()
	n.publish("c1", lifecycleEvent{kind: notifyRemoved})
	select {
	case ev := <-a:
		t.Fatalf("a cancelled subscriber still received %+v", ev)
	default:
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{in: "10m", want: 10 << 20},
		{in: "10MB", want: 10 << 20},
		{in: "512k", want: 512 << 10},
		{in: "2g", want: 2 << 30},
		{in: "1024", want: 1024},
		{in: "", wantErr: true},
		{in: "big", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseSize(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSize(%q) = %d, want an error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSize(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("parseSize(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestLogRotationOptions(t *testing.T) {
	size, files := logRotation(types.LogConfig{
		Type:   "json-file",
		Config: map[string]string{"max-size": "10m", "max-file": "3"},
	})
	if size != 10<<20 {
		t.Errorf("max-size = %d, want %d", size, 10<<20)
	}
	if files != 3 {
		t.Errorf("max-file = %d, want 3", files)
	}

	size, files = logRotation(types.LogConfig{Type: "json-file"})
	if size != 0 || files != 1 {
		t.Errorf("defaults = (%d, %d), want (0, 1)", size, files)
	}
}

func TestContainerRelPath(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "/etc/hosts", want: "etc/hosts"},
		{in: "etc/hosts", want: "etc/hosts"},
		{in: "/", want: "."},
		{in: "/a/../b", want: "b"},
		// A climb out of the root is clamped to it, not honoured.
		{in: "../escape", want: "escape"},
		{in: "/../escape", want: "escape"},
		{in: "../../etc/passwd", want: "etc/passwd"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := containerRelPath(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("containerRelPath(%q) = %q, want an error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("containerRelPath(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("containerRelPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestImageStoreResolution(t *testing.T) {
	te := newTestEngine(t)
	img := te.seedImage(t, "alpine:3.20", types.ImageConfig{Cmd: []string{"/bin/sh"}})

	for _, ref := range []string{
		"alpine:3.20",
		img.ID,
		img.ID[len("sha256:") : len("sha256:")+12],
	} {
		got, err := te.images.Get(ref)
		if err != nil {
			t.Fatalf("Get(%q): %v", ref, err)
		}
		if got.ID != img.ID {
			t.Errorf("Get(%q) resolved to %s, want %s", ref, got.ID, img.ID)
		}
	}
	if _, err := te.images.Get("nope:latest"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get on an unknown reference = %v, want ErrNotFound", err)
	}
}

func TestImageStoreTagMovesBetweenImages(t *testing.T) {
	te := newTestEngine(t)
	first := te.seedImage(t, "app:v1", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	second := te.seedImage(t, "app:v2", types.ImageConfig{Cmd: []string{"/bin/sh"}})

	if err := te.Tag(context.Background(), second.ID, "app:v1"); err != nil {
		t.Fatalf("Tag: %v", err)
	}
	got, err := te.images.Get("app:v1")
	if err != nil {
		t.Fatalf("Get after tagging: %v", err)
	}
	if got.ID != second.ID {
		t.Errorf("app:v1 points at %s, want %s", idShort(got.ID), idShort(second.ID))
	}
	old, err := te.images.Get(first.ID)
	if err != nil {
		t.Fatalf("Get by id: %v", err)
	}
	for _, tag := range old.RepoTags {
		if tag == "app:v1" {
			t.Error("the previous holder kept the tag")
		}
	}
}

func TestImageStorePersistsAcrossReopen(t *testing.T) {
	te := newTestEngine(t)
	img := te.seedImage(t, "keep:me", types.ImageConfig{Cmd: []string{"/bin/sh"}})

	reopened, err := openImageStore(te.root)
	if err != nil {
		t.Fatalf("reopen the image store: %v", err)
	}
	got, err := reopened.Get("keep:me")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.ID != img.ID {
		t.Errorf("reopened store resolved %s, want %s", got.ID, img.ID)
	}
}

func TestStopTimeoutResolution(t *testing.T) {
	five := 5
	twenty := 20
	tests := []struct {
		name       string
		configured *int
		override   *int
		want       time.Duration
	}{
		{name: "neither", want: time.Duration(DefaultStopTimeout) * time.Second},
		{name: "configured only", configured: &five, want: 5 * time.Second},
		{name: "override wins", configured: &five, override: &twenty, want: 20 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &types.Container{Config: types.ContainerConfig{StopTimeout: tt.configured}}
			if got := stopTimeoutFor(c, tt.override); got != tt.want {
				t.Errorf("stopTimeoutFor = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDaemonIDIsStableAndDistinct(t *testing.T) {
	a := daemonID("/var/lib/hull")
	if a != daemonID("/var/lib/hull") {
		t.Error("daemonID is not stable for the same root")
	}
	if a == daemonID("/var/lib/other") {
		t.Error("daemonID collided for different roots")
	}
	if len(a) != 32 {
		t.Errorf("daemonID is %d characters, want 32", len(a))
	}
}

func TestParseSubIDRange(t *testing.T) {
	tests := []struct {
		in         string
		start, cnt int
		ok         bool
	}{
		{in: "100000:65536", start: 100000, cnt: 65536, ok: true},
		{in: " 100000 : 65536 ", start: 100000, cnt: 65536, ok: true},
		{in: "", ok: false},
		{in: "100000", ok: false},
		{in: "0:65536", ok: false},
		{in: "abc:def", ok: false},
	}
	for _, tt := range tests {
		t.Run(strconv.Quote(tt.in), func(t *testing.T) {
			start, cnt, ok := parseSubIDRange(tt.in)
			if ok != tt.ok {
				t.Fatalf("parseSubIDRange(%q) ok = %v, want %v", tt.in, ok, tt.ok)
			}
			if ok && (start != tt.start || cnt != tt.cnt) {
				t.Errorf("parseSubIDRange(%q) = (%d, %d), want (%d, %d)",
					tt.in, start, cnt, tt.start, tt.cnt)
			}
		})
	}
}
