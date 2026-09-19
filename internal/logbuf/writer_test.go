package logbuf

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixedClock returns a deterministic clock advancing by step on every call.
func fixedClock(start time.Time, step time.Duration) func() time.Time {
	t := start.Add(-step)
	return func() time.Time {
		t = t.Add(step)
		return t
	}
}

func readFileLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(b) == 0 {
		return nil
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestMarshalRecordIsDockerCompatible(t *testing.T) {
	ts := time.Date(2026, 9, 19, 9, 51, 2, 123456789, time.UTC)
	tests := []struct {
		name  string
		entry Entry
		want  string
	}{
		{
			name:  "stdout line",
			entry: Entry{Log: []byte("hello\n"), Stream: StreamStdout, Time: ts},
			want:  `{"log":"hello\n","stream":"stdout","time":"2026-09-19T09:51:02.123456789Z"}`,
		},
		{
			name:  "stderr line",
			entry: Entry{Log: []byte("boom\n"), Stream: StreamStderr, Time: ts},
			want:  `{"log":"boom\n","stream":"stderr","time":"2026-09-19T09:51:02.123456789Z"}`,
		},
		{
			name:  "partial flag",
			entry: Entry{Log: []byte("frag"), Stream: StreamStdout, Time: ts, Partial: true},
			want:  `{"log":"frag","stream":"stdout","time":"2026-09-19T09:51:02.123456789Z","partial":true}`,
		},
		{
			name:  "html is escaped like docker",
			entry: Entry{Log: []byte("<b>&</b>\n"), Stream: StreamStdout, Time: ts},
			want:  "{\"log\":\"\\u003cb\\u003e\\u0026\\u003c/b\\u003e\\n\",\"stream\":\"stdout\",\"time\":\"2026-09-19T09:51:02.123456789Z\"}",
		},
		{
			name:  "non-utc time is normalised",
			entry: Entry{Log: []byte("x\n"), Stream: StreamStdout, Time: ts.In(time.FixedZone("IST", 5*3600+1800))},
			want:  `{"log":"x\n","stream":"stdout","time":"2026-09-19T09:51:02.123456789Z"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := marshalRecord(tc.entry)
			if err != nil {
				t.Fatalf("marshalRecord: %v", err)
			}
			if string(got) != tc.want+"\n" {
				t.Fatalf("record mismatch\n got: %s\nwant: %s\n", got, tc.want)
			}
			back, err := unmarshalRecord(got)
			if err != nil {
				t.Fatalf("unmarshalRecord: %v", err)
			}
			if !bytes.Equal(back.Log, tc.entry.Log) || back.Stream != tc.entry.Stream ||
				back.Partial != tc.entry.Partial || !back.Time.Equal(tc.entry.Time) {
				t.Fatalf("round trip mismatch: got %+v want %+v", back, tc.entry)
			}
		})
	}
}

func TestWriterSplitsAndBuffers(t *testing.T) {
	base := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		writes   [][2]string // stream, payload
		wantLogs []string
		wantPart []bool
	}{
		{
			name:     "single line",
			writes:   [][2]string{{StreamStdout, "hello\n"}},
			wantLogs: []string{"hello\n"},
			wantPart: []bool{false},
		},
		{
			name:     "two lines in one write",
			writes:   [][2]string{{StreamStdout, "a\nb\n"}},
			wantLogs: []string{"a\n", "b\n"},
			wantPart: []bool{false, false},
		},
		{
			name:     "fragment completed by next write",
			writes:   [][2]string{{StreamStdout, "he"}, {StreamStdout, "llo\n"}},
			wantLogs: []string{"hello\n"},
			wantPart: []bool{false},
		},
		{
			name:     "fragment flushed on close is not partial",
			writes:   [][2]string{{StreamStdout, "tail-no-newline"}},
			wantLogs: []string{"tail-no-newline"},
			wantPart: []bool{false},
		},
		{
			name:     "streams are buffered independently",
			writes:   [][2]string{{StreamStdout, "out"}, {StreamStderr, "err\n"}, {StreamStdout, "put\n"}},
			wantLogs: []string{"err\n", "output\n"},
			wantPart: []bool{false, false},
		},
		{
			name:     "empty line",
			writes:   [][2]string{{StreamStdout, "\n"}},
			wantLogs: []string{"\n"},
			wantPart: []bool{false},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c-json.log")
			w, err := newWriter(path, WriterOptions{}, time.Hour)
			if err != nil {
				t.Fatalf("NewWriter: %v", err)
			}
			w.setClock(fixedClock(base, time.Second))
			for _, wr := range tc.writes {
				n, err := w.Write(wr[0], []byte(wr[1]))
				if err != nil {
					t.Fatalf("Write(%q): %v", wr[1], err)
				}
				if n != len(wr[1]) {
					t.Fatalf("Write returned %d, want %d", n, len(wr[1]))
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			lines := readFileLines(t, path)
			if len(lines) != len(tc.wantLogs) {
				t.Fatalf("got %d records %q, want %d", len(lines), lines, len(tc.wantLogs))
			}
			for i, line := range lines {
				e, err := unmarshalRecord([]byte(line))
				if err != nil {
					t.Fatalf("record %d: %v", i, err)
				}
				if string(e.Log) != tc.wantLogs[i] {
					t.Errorf("record %d log = %q, want %q", i, e.Log, tc.wantLogs[i])
				}
				if e.Partial != tc.wantPart[i] {
					t.Errorf("record %d partial = %v, want %v", i, e.Partial, tc.wantPart[i])
				}
				if e.Time.IsZero() {
					t.Errorf("record %d has no timestamp", i)
				}
			}
		})
	}
}

func TestWriterRejectsBadStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c-json.log")
	w, err := newWriter(path, WriterOptions{}, time.Hour)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()
	if _, err := w.Write("stdin", []byte("x\n")); err == nil {
		t.Fatal("expected an error for an unknown stream")
	}
}

func TestWriterWriteAfterCloseFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c-json.log")
	w, err := newWriter(path, WriterOptions{}, time.Hour)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := w.Write(StreamStdout, []byte("x\n")); err != ErrClosed {
		t.Fatalf("Write after Close = %v, want ErrClosed", err)
	}
}

func TestWriterIdleTimerFlushesFragment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c-json.log")
	w, err := NewWriter(path, WriterOptions{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write(StreamStdout, []byte("progress...")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The fragment must reach disk without a terminating newline and without
	// waiting for Close.
	deadline := time.Now().Add(3 * time.Second)
	var lines []string
	for time.Now().Before(deadline) {
		lines = readFileLines(t, path)
		if len(lines) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(lines) != 1 {
		t.Fatalf("idle timer did not flush: got %d records", len(lines))
	}
	e, err := unmarshalRecord([]byte(lines[0]))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(e.Log) != "progress..." {
		t.Fatalf("log = %q, want %q", e.Log, "progress...")
	}
	if !e.Partial {
		t.Fatal("timer-flushed fragment must be marked partial")
	}
	if _, err := w.Write(StreamStdout, []byte(" done\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	lines = readFileLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("got %d records, want 2", len(lines))
	}
	e2, err := unmarshalRecord([]byte(lines[1]))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(e2.Log) != " done\n" || e2.Partial {
		t.Fatalf("second record = %q partial=%v, want %q partial=false", e2.Log, e2.Partial, " done\n")
	}
}

func TestWriterSplitsOversizeLineIntoPartials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c-json.log")
	w, err := newWriter(path, WriterOptions{}, time.Hour)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	// 2.5 records worth of payload on one logical line.
	payload := bytes.Repeat([]byte("x"), MaxRecordPayload*2+1024)
	line := append(append([]byte(nil), payload...), '\n')
	if _, err := w.Write(StreamStdout, line); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	lines := readFileLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("got %d records, want 3", len(lines))
	}
	var joined []byte
	for i, l := range lines {
		e, err := unmarshalRecord([]byte(l))
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		wantPartial := i < 2
		if e.Partial != wantPartial {
			t.Errorf("record %d partial = %v, want %v", i, e.Partial, wantPartial)
		}
		wantLen := MaxRecordPayload
		if i == 2 {
			wantLen = 1024 + 1 // remainder plus the newline
		}
		if len(e.Log) != wantLen {
			t.Errorf("record %d len = %d, want %d", i, len(e.Log), wantLen)
		}
		joined = append(joined, e.Log...)
	}
	if !bytes.Equal(joined, line) {
		t.Fatal("re-joined partials do not reproduce the original line")
	}
}

func TestWriterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c-json.log")
	// Each record is ~90 bytes; 300 bytes therefore holds three of them.
	w, err := newWriter(path, WriterOptions{MaxSize: 300, MaxFiles: 3}, time.Hour)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	w.setClock(fixedClock(time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC), time.Second))
	for i := 0; i < 40; i++ {
		if _, err := w.Write(StreamStdout, []byte("line\n")); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, name := range []string{path, path + ".1", path + ".2"} {
		st, err := os.Stat(name)
		if err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
		if st.Size() > 300 {
			t.Errorf("%s is %d bytes, over the 300 byte cap", name, st.Size())
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf("MaxFiles=3 must not keep a .3 generation (err=%v)", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 3 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("got %d files %v, want 3", len(entries), names)
	}
}

func TestWriterRotationCompress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c-json.log")
	w, err := newWriter(path, WriterOptions{MaxSize: 300, MaxFiles: 3, Compress: true}, time.Hour)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i := 0; i < 40; i++ {
		if _, err := w.Write(StreamStdout, []byte("line\n")); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, name := range []string{path + ".1.gz", path + ".2.gz"} {
		f, err := os.Open(name)
		if err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			t.Fatalf("gzip %s: %v", name, err)
		}
		b, err := io.ReadAll(zr)
		zr.Close()
		f.Close()
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Contains(b, []byte(`"log":"line\n"`)) {
			t.Fatalf("%s does not contain decompressible records", name)
		}
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("uncompressed .1 should have been removed (err=%v)", err)
	}
}

func TestWriterMaxFilesOneTruncates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c-json.log")
	w, err := newWriter(path, WriterOptions{MaxSize: 300, MaxFiles: 1}, time.Hour)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i := 0; i < 40; i++ {
		if _, err := w.Write(StreamStdout, []byte("line\n")); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("MaxFiles=1 must not create a .1 generation (err=%v)", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() > 300 {
		t.Errorf("log is %d bytes, over the 300 byte cap", st.Size())
	}
}

func TestNewWriterRejectsBadOptions(t *testing.T) {
	if _, err := NewWriter("", WriterOptions{}); err == nil {
		t.Error("empty path must fail")
	}
	if _, err := NewWriter(filepath.Join(t.TempDir(), "x.log"), WriterOptions{MaxSize: -1}); err == nil {
		t.Error("negative MaxSize must fail")
	}
	if _, err := NewWriter(filepath.Join(t.TempDir(), "missing-dir", "x.log"), WriterOptions{}); err == nil {
		t.Error("unopenable path must fail")
	}
}
