package explain

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixedClock returns a now function that always reports the same instant, so a
// timestamped trace is byte-for-byte comparable.
func fixedClock() func() time.Time {
	t := time.Date(2026, 9, 19, 16, 45, 12, 345_000_000, time.UTC)
	return func() time.Time { return t }
}

// newTestTracer builds a tracer on buf with a frozen clock.
func newTestTracer(buf *bytes.Buffer, opts Options) *tracer {
	tr := New(buf, opts).(*tracer)
	tr.now = fixedClock()
	return tr
}

func TestStepColumnAndIndentation(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tr := newTestTracer(&buf, Options{})

	tr.Step(KindNamespace, "clone3(%s)", CloneFlags("user", "mnt", "pid", "net", "uts", "ipc"))
	done := tr.Enter("write id maps")
	tr.Step(KindNamespace, "wrote /proc/%d/uid_map: %q", 4812, "0 100000 65536")
	inner := tr.Enter("gid")
	tr.Step(KindNamespace, "wrote /proc/%d/gid_map: %q", 4812, "0 100000 65536")
	inner()
	done()
	tr.Step(KindMount, "pivot_root(%q, %q)", "/var/lib/hull/containers/ab12/merged", ".put_old")

	want := []string{
		"namespace  clone3(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWUTS|CLONE_NEWIPC)",
		"           + write id maps",
		"namespace    wrote /proc/4812/uid_map: \"0 100000 65536\"",
		"             + gid",
		"namespace      wrote /proc/4812/gid_map: \"0 100000 65536\"",
		"mount      pivot_root(\"/var/lib/hull/containers/ab12/merged\", \".put_old\")",
	}
	got := lines(buf.String())
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(got), len(want), buf.String())
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d:\n got %q\nwant %q", i, got[i], want[i])
		}
	}
}

func TestTextColumnIsConstant(t *testing.T) {
	t.Parallel()
	// Every kind must leave the text starting in the same column, or a trace
	// stops reading as a table.
	kinds := []Kind{
		KindImage, KindSnapshot, KindMount, KindNamespace, KindCgroup,
		KindSeccomp, KindCap, KindNetwork, KindProcess, KindSignal,
	}
	for _, k := range kinds {
		var buf bytes.Buffer
		tr := newTestTracer(&buf, Options{})
		tr.Step(k, "X")
		line := strings.TrimSuffix(buf.String(), "\n")
		if col := strings.IndexByte(line, 'X'); col != kindWidth+len(gutter) {
			t.Errorf("kind %q: text starts at column %d, want %d (%q)", k, col, kindWidth+len(gutter), line)
		}
	}
}

func TestVerboseFiltering(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		verbose        bool
		wantDetail     bool
		wantExit       bool
		wantStepAlways bool
	}{
		{name: "quiet", verbose: false, wantDetail: false, wantExit: false, wantStepAlways: true},
		{name: "verbose", verbose: true, wantDetail: true, wantExit: true, wantStepAlways: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tr := newTestTracer(&buf, Options{Verbose: tc.verbose})
			done := tr.Enter("prepare snapshot")
			tr.Step(KindSnapshot, "overlay lowerdirs resolved")
			tr.Detail("chainID", "sha256:deadbeef")
			done()

			out := buf.String()
			if got := strings.Contains(out, "chainID = sha256:deadbeef"); got != tc.wantDetail {
				t.Errorf("detail present = %v, want %v:\n%s", got, tc.wantDetail, out)
			}
			if got := strings.Contains(out, exitMarker+"prepare snapshot"); got != tc.wantExit {
				t.Errorf("exit line present = %v, want %v:\n%s", got, tc.wantExit, out)
			}
			if got := strings.Contains(out, "overlay lowerdirs resolved"); got != tc.wantStepAlways {
				t.Errorf("step present = %v, want %v:\n%s", got, tc.wantStepAlways, out)
			}
			// The scope header is unconditional; only its timing is verbose.
			if !strings.Contains(out, enterMarker+"prepare snapshot") {
				t.Errorf("enter line missing:\n%s", out)
			}
		})
	}
}

func TestVerboseExitReportsElapsed(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tr := newTestTracer(&buf, Options{Verbose: true})
	done := tr.Enter("mount overlay")
	done()
	// The frozen clock makes the elapsed time exactly zero, which keeps the
	// assertion exact rather than a regexp over a real duration.
	if want := exitMarker + "mount overlay (0s)"; !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in:\n%s", want, buf.String())
	}
}

func TestColorOnAndOff(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		color bool
	}{
		{name: "off", color: false},
		{name: "on", color: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tr := newTestTracer(&buf, Options{Color: tc.color, Verbose: true})
			tr.Step(KindCgroup, "cpu.max <- %q", "50000 100000")
			tr.Detail("flag", "--cpus 0.5")
			tr.Err(errors.New("write cpu.max: permission denied"))
			out := buf.String()
			if got := strings.Contains(out, "\x1b["); got != tc.color {
				t.Fatalf("escape sequences present = %v, want %v: %q", got, tc.color, out)
			}
			// Colour must never change the words, only their dress.
			plain := regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(out, "")
			for _, want := range []string{
				`cgroup     cpu.max <- "50000 100000"`,
				`flag = --cpus 0.5`,
				`error      write cpu.max: permission denied`,
			} {
				if !strings.Contains(plain, want) {
					t.Errorf("want %q in de-coloured output:\n%s", want, plain)
				}
			}
		})
	}
}

func TestTimestamps(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tr := newTestTracer(&buf, Options{Timestamps: true})
	tr.Step(KindProcess, "execve(\"/bin/sh\")")
	line := strings.TrimSuffix(buf.String(), "\n")
	if !strings.HasPrefix(line, "16:45:12.345 process") {
		t.Fatalf("timestamped line = %q", line)
	}

	buf.Reset()
	tr2 := newTestTracer(&buf, Options{})
	tr2.Step(KindProcess, "execve(\"/bin/sh\")")
	if got := strings.TrimSuffix(buf.String(), "\n"); !strings.HasPrefix(got, "process") {
		t.Fatalf("untimestamped line = %q", got)
	}
}

func TestErrNilPrintsNothing(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tr := newTestTracer(&buf, Options{})
	tr.Err(nil)
	if buf.Len() != 0 {
		t.Fatalf("Err(nil) wrote %q", buf.String())
	}
}

func TestEnterExitIsIdempotent(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tr := newTestTracer(&buf, Options{})
	done := tr.Enter("scope")
	done()
	done()
	done()
	tr.Step(KindImage, "back at depth zero")
	last := lines(buf.String())
	got := last[len(last)-1]
	if want := "image      back at depth zero"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if tr.depth != 0 {
		t.Fatalf("depth = %d, want 0", tr.depth)
	}
}

func TestConcurrentTracingKeepsLinesWhole(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	// syncWriter models a writer that is not itself serialised, so any
	// interleaving would have to come from the tracer.
	w := &syncWriter{buf: &buf}
	tr := New(w, Options{Verbose: true})

	const goroutines, perGoroutine = 16, 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				done := tr.Enter("worker")
				tr.Step(KindNetwork, "veth%d-%d created", g, i)
				tr.Detail("peer", "eth0")
				tr.Err(errors.New("boom"))
				done()
			}
		}(g)
	}
	wg.Wait()

	got := lines(buf.String())
	// 5 lines per iteration: enter, step, detail, error, exit.
	if want := goroutines * perGoroutine * 5; len(got) != want {
		t.Fatalf("got %d lines, want %d", len(got), want)
	}
	steps := 0
	for _, l := range got {
		if strings.HasPrefix(l, "network") {
			steps++
			if !strings.Contains(l, " created") {
				t.Fatalf("spliced line: %q", l)
			}
		}
	}
	if want := goroutines * perGoroutine; steps != want {
		t.Fatalf("got %d step lines, want %d", steps, want)
	}
}

func TestNopAndContext(t *testing.T) {
	t.Parallel()
	if Enabled(Nop()) {
		t.Error("Nop must report itself disabled")
	}
	if Enabled(nil) {
		t.Error("a nil Tracer must report itself disabled")
	}
	if got := FromContext(nil); got != Nop() {
		t.Error("FromContext(nil) must be Nop")
	}
	//nolint:staticcheck // deliberately passing a nil-valued context key path
	if got := FromContext(context.Background()); got != Nop() {
		t.Error("an untraced context must yield Nop")
	}
	if got := OrNop(nil); got != Nop() {
		t.Error("OrNop(nil) must be Nop")
	}

	var buf bytes.Buffer
	tr := New(&buf, Options{})
	ctx := WithTracer(context.Background(), tr)
	if got := FromContext(ctx); got != tr {
		t.Fatal("FromContext must return the installed tracer")
	}
	if !Enabled(FromContext(ctx)) {
		t.Error("a writing tracer must report itself enabled")
	}
	FromContext(ctx).Step(KindImage, "pulled")
	if !strings.Contains(buf.String(), "pulled") {
		t.Errorf("tracer from context wrote nothing: %q", buf.String())
	}

	// Installing nil must not panic and must not shadow with a nil value.
	if got := FromContext(WithTracer(context.Background(), nil)); got != Nop() {
		t.Error("WithTracer(nil) must install Nop")
	}

	// A nil writer degrades to Nop rather than panicking on first use.
	if got := New(nil, Options{Verbose: true}); got != Nop() {
		t.Error("New(nil, ...) must be Nop")
	}
}

func TestNopMethodsAreSafe(t *testing.T) {
	t.Parallel()
	n := Nop()
	n.Step(KindSeccomp, "%d", 1)
	n.Detail("k", "v")
	n.Err(errors.New("ignored"))
	exit := n.Enter("scope")
	exit()
	exit()
}

func TestCloneFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		names []string
		want  string
	}{
		{name: "empty", names: nil, want: "0"},
		{name: "only blanks", names: []string{"", "  "}, want: "0"},
		{
			name:  "full set in caller order",
			names: []string{"user", "mnt", "pid", "net", "uts", "ipc"},
			want:  "CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWUTS|CLONE_NEWIPC",
		},
		{
			name:  "debug shell default set",
			names: []string{"pid", "net", "ipc", "uts"},
			want:  "CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWUTS",
		},
		{
			name:  "aliases and case",
			names: []string{"MOUNT", "Network", "ns"},
			want:  "CLONE_NEWNS|CLONE_NEWNET",
		},
		{name: "cgroup and time", names: []string{"cgroup", "time"}, want: "CLONE_NEWCGROUP|CLONE_NEWTIME"},
		{name: "passthrough", names: []string{"CLONE_INTO_CGROUP"}, want: "CLONE_INTO_CGROUP"},
		{name: "dedupe", names: []string{"net", "network", "net"}, want: "CLONE_NEWNET"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CloneFlags(tc.names...); got != tc.want {
				t.Errorf("CloneFlags(%q) = %q, want %q", tc.names, got, tc.want)
			}
		})
	}
}

// lines splits a trace into its lines, dropping the trailing empty one.
func lines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// syncWriter serialises writes to buf so the test measures the tracer's
// framing rather than bytes.Buffer's lack of thread safety.
type syncWriter struct {
	mu  sync.Mutex
	buf *bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
