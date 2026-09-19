package logbuf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// collect runs Read and returns every entry it delivers.
func collect(t *testing.T, ctx context.Context, path string, opts ReadOptions) []Entry {
	t.Helper()
	var got []Entry
	if err := Read(ctx, path, opts, func(e Entry) error {
		cp := e
		cp.Log = append([]byte(nil), e.Log...)
		got = append(got, cp)
		return nil
	}); err != nil {
		t.Fatalf("Read: %v", err)
	}
	return got
}

// logsOf renders the Log field of each entry.
func logsOf(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, string(e.Log))
	}
	return out
}

// writeLog writes n numbered lines with the given options and returns the path.
func writeLog(t *testing.T, opts WriterOptions, base time.Time, n int, stream func(int) string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c-json.log")
	w, err := newWriter(path, opts, time.Hour)
	if err != nil {
		t.Fatalf("newWriter: %v", err)
	}
	w.setClock(fixedClock(base, time.Second))
	for i := 0; i < n; i++ {
		s := StreamStdout
		if stream != nil {
			s = stream(i)
		}
		if _, err := w.Write(s, []byte(fmt.Sprintf("line-%d\n", i))); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

func TestReadRoundTrip(t *testing.T) {
	base := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	path := writeLog(t, WriterOptions{}, base, 5, func(i int) string {
		if i%2 == 1 {
			return StreamStderr
		}
		return StreamStdout
	})
	ctx := context.Background()

	tests := []struct {
		name string
		opts ReadOptions
		want []string
	}{
		{
			name: "both streams",
			opts: ReadOptions{Tail: -1, Stdout: true, Stderr: true},
			want: []string{"line-0\n", "line-1\n", "line-2\n", "line-3\n", "line-4\n"},
		},
		{
			name: "stdout only",
			opts: ReadOptions{Tail: -1, Stdout: true},
			want: []string{"line-0\n", "line-2\n", "line-4\n"},
		},
		{
			name: "stderr only",
			opts: ReadOptions{Tail: -1, Stderr: true},
			want: []string{"line-1\n", "line-3\n"},
		},
		{
			name: "tail zero delivers nothing",
			opts: ReadOptions{Tail: 0, Stdout: true, Stderr: true},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := logsOf(collect(t, ctx, path, tc.opts))
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReadRequiresAStream(t *testing.T) {
	path := writeLog(t, WriterOptions{}, time.Now(), 1, nil)
	err := Read(context.Background(), path, ReadOptions{Tail: -1}, func(Entry) error { return nil })
	if !errors.Is(err, ErrNoStreams) {
		t.Fatalf("Read with no streams = %v, want ErrNoStreams", err)
	}
}

func TestReadMissingLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope-json.log")
	err := Read(context.Background(), path, ReadOptions{Tail: -1, Stdout: true}, func(Entry) error { return nil })
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Read of a missing log = %v, want os.ErrNotExist", err)
	}
}

func TestReadCallbackErrorPropagates(t *testing.T) {
	path := writeLog(t, WriterOptions{}, time.Now(), 5, nil)
	sentinel := errors.New("stop")
	n := 0
	err := Read(context.Background(), path, ReadOptions{Tail: -1, Stdout: true}, func(Entry) error {
		n++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Read = %v, want the callback's error", err)
	}
	if n != 1 {
		t.Fatalf("callback ran %d times, want 1", n)
	}
}

func TestReadTail(t *testing.T) {
	base := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()
	tests := []struct {
		name  string
		lines int
		tail  int
		want  []string
	}{
		{name: "tail 5 of 15", lines: 15, tail: 5, want: []string{"line-10\n", "line-11\n", "line-12\n", "line-13\n", "line-14\n"}},
		{name: "tail 1 of 11", lines: 11, tail: 1, want: []string{"line-10\n"}},
		{name: "tail larger than file", lines: 3, tail: 10, want: []string{"line-0\n", "line-1\n", "line-2\n"}},
		{name: "tail equals file", lines: 4, tail: 4, want: []string{"line-0\n", "line-1\n", "line-2\n", "line-3\n"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeLog(t, WriterOptions{}, base, tc.lines, nil)
			got := logsOf(collect(t, ctx, path, ReadOptions{Tail: tc.tail, Stdout: true, Stderr: true}))
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReadTailScansBackwardsAcrossChunks(t *testing.T) {
	// Force the backward scan to need several 32 KiB reads.
	path := filepath.Join(t.TempDir(), "c-json.log")
	w, err := newWriter(path, WriterOptions{}, time.Hour)
	if err != nil {
		t.Fatalf("newWriter: %v", err)
	}
	const total = 4000
	for i := 0; i < total; i++ {
		if _, err := w.Write(StreamStdout, []byte(fmt.Sprintf("%d-%s\n", i, strings.Repeat("p", 60)))); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := collect(t, context.Background(), path, ReadOptions{Tail: 3, Stdout: true, Stderr: true})
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	for i, e := range got {
		want := fmt.Sprintf("%d-", total-3+i)
		if !bytes.HasPrefix(e.Log, []byte(want)) {
			t.Fatalf("entry %d = %q, want prefix %q", i, e.Log, want)
		}
	}
}

func TestReadSinceUntil(t *testing.T) {
	base := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	path := writeLog(t, WriterOptions{}, base, 10, nil) // line-i at base+i seconds
	ctx := context.Background()
	tests := []struct {
		name  string
		since time.Time
		until time.Time
		want  []string
	}{
		{
			name:  "since is inclusive",
			since: base.Add(7 * time.Second),
			want:  []string{"line-7\n", "line-8\n", "line-9\n"},
		},
		{
			name:  "until is inclusive",
			until: base.Add(2 * time.Second),
			want:  []string{"line-0\n", "line-1\n", "line-2\n"},
		},
		{
			name:  "window",
			since: base.Add(3 * time.Second),
			until: base.Add(5 * time.Second),
			want:  []string{"line-3\n", "line-4\n", "line-5\n"},
		},
		{
			name:  "empty window",
			since: base.Add(20 * time.Second),
			want:  nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := ReadOptions{Tail: -1, Stdout: true, Stderr: true, Since: tc.since, Until: tc.until}
			got := logsOf(collect(t, ctx, path, opts))
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReadAcrossRotation(t *testing.T) {
	base := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	for _, compress := range []bool{false, true} {
		name := "plain"
		if compress {
			name = "gzip"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c-json.log")
			w, err := newWriter(path, WriterOptions{MaxSize: 400, MaxFiles: 3, Compress: compress}, time.Hour)
			if err != nil {
				t.Fatalf("newWriter: %v", err)
			}
			w.setClock(fixedClock(base, time.Second))
			const total = 30
			for i := 0; i < total; i++ {
				if _, err := w.Write(StreamStdout, []byte(fmt.Sprintf("line-%02d\n", i))); err != nil {
					t.Fatalf("Write: %v", err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			all := logsOf(collect(t, context.Background(), path, ReadOptions{Tail: -1, Stdout: true, Stderr: true}))
			if len(all) < 12 {
				t.Fatalf("only %d records survived rotation, expected the three newest generations", len(all))
			}
			// Records must come back in write order and be contiguous.
			for i := 1; i < len(all); i++ {
				var prev, cur int
				fmt.Sscanf(all[i-1], "line-%d\n", &prev)
				fmt.Sscanf(all[i], "line-%d\n", &cur)
				if cur != prev+1 {
					t.Fatalf("records out of order at %d: %q then %q", i, all[i-1], all[i])
				}
			}
			if all[len(all)-1] != fmt.Sprintf("line-%02d\n", total-1) {
				t.Fatalf("last record = %q, want the newest line", all[len(all)-1])
			}

			// A tail that reaches past the active file must walk generations.
			tailN := len(all)
			tailed := logsOf(collect(t, context.Background(), path, ReadOptions{Tail: tailN, Stdout: true, Stderr: true}))
			if strings.Join(tailed, "|") != strings.Join(all, "|") {
				t.Fatalf("tail across rotation\n got %q\nwant %q", tailed, all)
			}
			// Since must also reach back into the rotated generations.
			sinceAll := logsOf(collect(t, context.Background(), path, ReadOptions{
				Tail: -1, Stdout: true, Stderr: true, Since: base,
			}))
			if strings.Join(sinceAll, "|") != strings.Join(all, "|") {
				t.Fatalf("since across rotation\n got %q\nwant %q", sinceAll, all)
			}
		})
	}
}

func TestReadFollow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c-json.log")
	w, err := newWriter(path, WriterOptions{}, time.Hour)
	if err != nil {
		t.Fatalf("newWriter: %v", err)
	}
	defer w.Close()
	if _, err := w.Write(StreamStdout, []byte("first\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := make(chan string, 8)
	done := make(chan error, 1)
	go func() {
		done <- Read(ctx, path, ReadOptions{Tail: -1, Follow: true, Stdout: true, Stderr: true}, func(e Entry) error {
			got <- string(e.Log)
			return nil
		})
	}()

	if s := <-got; s != "first\n" {
		t.Fatalf("history record = %q, want %q", s, "first\n")
	}
	if _, err := w.Write(StreamStdout, []byte("second\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case s := <-got:
		if s != "second\n" {
			t.Fatalf("followed record = %q, want %q", s, "second\n")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow did not deliver the appended record")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Read returned %v, want nil on cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not return after cancellation")
	}
}

func TestReadFollowAcrossRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c-json.log")
	// Small cap so every few records rotate the file under the follower.
	w, err := newWriter(path, WriterOptions{MaxSize: 200, MaxFiles: 4}, time.Hour)
	if err != nil {
		t.Fatalf("newWriter: %v", err)
	}
	defer w.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	got := make(chan string, 64)
	done := make(chan error, 1)
	go func() {
		done <- Read(ctx, path, ReadOptions{Tail: -1, Follow: true, Stdout: true, Stderr: true}, func(e Entry) error {
			got <- string(e.Log)
			return nil
		})
	}()

	const total = 12
	for i := 0; i < total; i++ {
		if _, err := w.Write(StreamStdout, []byte(fmt.Sprintf("r-%02d\n", i))); err != nil {
			t.Fatalf("Write: %v", err)
		}
		// Let the follower catch up before the next rotation retires the inode.
		select {
		case s := <-got:
			if s != fmt.Sprintf("r-%02d\n", i) {
				t.Fatalf("record %d = %q", i, s)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("follow lost record %d across rotation", i)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Read returned %v, want nil", err)
	}
}

func TestLastLinesAt(t *testing.T) {
	tests := []struct {
		name string
		data string
		n    int
		want []string
	}{
		{name: "exact", data: "a\nb\nc\n", n: 2, want: []string{"b\n", "c\n"}},
		{name: "all", data: "a\nb\nc\n", n: 5, want: []string{"a\n", "b\n", "c\n"}},
		{name: "one", data: "a\nb\nc\n", n: 1, want: []string{"c\n"}},
		{name: "unterminated tail", data: "a\nb\nc", n: 2, want: []string{"b\n", "c"}},
		{name: "empty", data: "", n: 3, want: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := strings.NewReader(tc.data)
			got, err := lastLinesAt(r, int64(len(tc.data)), tc.n)
			if err != nil {
				t.Fatalf("lastLinesAt: %v", err)
			}
			var gs []string
			for _, l := range got {
				gs = append(gs, string(l))
			}
			if strings.Join(gs, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("got %q, want %q", gs, tc.want)
			}
		})
	}
}

func TestReadIgnoresTornAndForeignLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c-json.log")
	good := `{"log":"ok\n","stream":"stdout","time":"2026-09-19T09:51:02.123456789Z"}`
	content := good + "\n" + "not json at all\n" + `{"log":"trunca`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got := logsOf(collect(t, context.Background(), path, ReadOptions{Tail: -1, Stdout: true, Stderr: true}))
	if len(got) != 1 || got[0] != "ok\n" {
		t.Fatalf("got %q, want just the one valid record", got)
	}
}
