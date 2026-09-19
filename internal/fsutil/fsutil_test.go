package fsutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestWriteFileAtomicLeavesNoDebris(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{"empty", nil, 0o644},
		{"small", []byte("hello hull"), 0o600},
		{"binary", bytes.Repeat([]byte{0x00, 0xff, 0x7f}, 1024), 0o640},
		{"large", bytes.Repeat([]byte("abcdefgh"), 256*1024), 0o644},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "state.json")

			if err := WriteFileAtomic(target, tt.data, tt.perm); err != nil {
				t.Fatalf("WriteFileAtomic() error = %v", err)
			}

			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			if !bytes.Equal(got, tt.data) {
				t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(tt.data))
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("ReadDir() error = %v", err)
			}
			if len(entries) != 1 || entries[0].Name() != "state.json" {
				var names []string
				for _, e := range entries {
					names = append(names, e.Name())
				}
				t.Fatalf("directory holds %v, want only state.json (temp file left behind?)", names)
			}

			fi, err := os.Stat(target)
			if err != nil {
				t.Fatalf("Stat() error = %v", err)
			}
			if fi.Mode().Perm() != tt.perm {
				t.Fatalf("mode = %v, want %v", fi.Mode().Perm(), tt.perm)
			}
		})
	}
}

func TestWriteFileAtomicReplacesCompletely(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")

	long := bytes.Repeat([]byte("x"), 4096)
	if err := WriteFileAtomic(target, long, 0o644); err != nil {
		t.Fatalf("first write: %v", err)
	}
	short := []byte("short")
	if err := WriteFileAtomic(target, short, 0o644); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, short) {
		t.Fatalf("got %q, want %q (truncation failed)", got, short)
	}
}

func TestWriteFileAtomicMissingDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nope", "f")
	if err := WriteFileAtomic(target, []byte("x"), 0o644); err == nil {
		t.Fatal("WriteFileAtomic() into a missing directory = nil, want error")
	}
}

// TestWriteFileAtomicConcurrentReaders asserts a reader never observes a
// partial file while writers churn: every read is either empty (not yet
// created) or one of the complete payloads.
func TestWriteFileAtomicConcurrentReaders(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")

	payloads := [][]byte{
		bytes.Repeat([]byte("a"), 1<<16),
		bytes.Repeat([]byte("b"), 1<<17),
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if err := WriteFileAtomic(target, payloads[i%len(payloads)], 0o644); err != nil {
				t.Errorf("writer: %v", err)
				break
			}
		}
		close(stop)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			got, err := os.ReadFile(target)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				t.Errorf("reader: %v", err)
				return
			}
			if len(got) == 0 {
				continue
			}
			ok := false
			for _, p := range payloads {
				if bytes.Equal(got, p) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("reader saw a torn file of %d bytes", len(got))
				return
			}
		}
	}()
	wg.Wait()
}

type jsonDoc struct {
	Name   string            `json:"name"`
	Count  int               `json:"count"`
	Labels map[string]string `json:"labels,omitempty"`
}

func TestWriteJSONAtomicRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   jsonDoc
	}{
		{"zero", jsonDoc{}},
		{"simple", jsonDoc{Name: "web", Count: 3}},
		{"labels", jsonDoc{Name: "db", Count: 1, Labels: map[string]string{"app": "hull"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "doc.json")
			if err := WriteJSONAtomic(p, tt.in, 0o600); err != nil {
				t.Fatalf("WriteJSONAtomic() error = %v", err)
			}
			var got jsonDoc
			if err := ReadJSON(p, &got); err != nil {
				t.Fatalf("ReadJSON() error = %v", err)
			}
			if got.Name != tt.in.Name || got.Count != tt.in.Count || len(got.Labels) != len(tt.in.Labels) {
				t.Fatalf("round trip mismatch: got %+v, want %+v", got, tt.in)
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if !strings.HasSuffix(string(raw), "}\n") {
				t.Fatalf("json file does not end with a newline: %q", raw)
			}
		})
	}
}

func TestReadJSONErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	var v jsonDoc
	if err := ReadJSON(filepath.Join(dir, "missing.json"), &v); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadJSON(missing) error = %v, want fs.ErrNotExist", err)
	}
	if err := ReadJSON(bad, &v); err == nil {
		t.Fatal("ReadJSON(malformed) = nil, want error")
	}
}

func TestMkdirAllChown(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c")

	if err := MkdirAllChown(deep, 0o750, -1, -1); err != nil {
		t.Fatalf("MkdirAllChown() error = %v", err)
	}
	for _, p := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b"), deep} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("Stat(%s): %v", p, err)
		}
		if !fi.IsDir() {
			t.Fatalf("%s is not a directory", p)
		}
		if fi.Mode().Perm() != 0o750 {
			t.Fatalf("%s mode = %v, want 0750", p, fi.Mode().Perm())
		}
	}

	// Idempotent.
	if err := MkdirAllChown(deep, 0o750, -1, -1); err != nil {
		t.Fatalf("second MkdirAllChown() error = %v", err)
	}

	// A file in the way is an error, not a silent success.
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAllChown(filepath.Join(file, "sub"), 0o755, -1, -1); err == nil {
		t.Fatal("MkdirAllChown() through a regular file = nil, want error")
	}
	if err := MkdirAllChown("", 0o755, -1, -1); err == nil {
		t.Fatal("MkdirAllChown(\"\") = nil, want error")
	}
}

func TestCopyFile(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{"empty", nil, 0o644},
		{"text", []byte("layer blob"), 0o600},
		{"big", bytes.Repeat([]byte("z"), 1<<20), 0o444},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "src")
			dst := filepath.Join(dir, "dst")
			if err := os.WriteFile(src, tt.data, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := CopyFile(dst, src, tt.perm); err != nil {
				t.Fatalf("CopyFile() error = %v", err)
			}
			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if !bytes.Equal(got, tt.data) {
				t.Fatalf("copied %d bytes, want %d", len(got), len(tt.data))
			}
			fi, err := os.Stat(dst)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != tt.perm {
				t.Fatalf("mode = %v, want %v", fi.Mode().Perm(), tt.perm)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 2 {
				t.Fatalf("directory holds %d entries, want 2 (temp file left behind?)", len(entries))
			}
		})
	}
}

func TestCopyFileMissingSource(t *testing.T) {
	dir := t.TempDir()
	if err := CopyFile(filepath.Join(dir, "dst"), filepath.Join(dir, "nope"), 0o644); err == nil {
		t.Fatal("CopyFile() from a missing source = nil, want error")
	}
}

func TestExistsAndIsDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	tests := []struct {
		name          string
		path          string
		exists, isDir bool
	}{
		{"dir", dir, true, true},
		{"file", file, true, false},
		{"missing", filepath.Join(dir, "missing"), false, false},
		{"dangling symlink", dangling, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Exists(tt.path); got != tt.exists {
				t.Fatalf("Exists(%s) = %v, want %v", tt.path, got, tt.exists)
			}
			if got := IsDir(tt.path); got != tt.isDir {
				t.Fatalf("IsDir(%s) = %v, want %v", tt.path, got, tt.isDir)
			}
		})
	}
}

func TestIsEscape(t *testing.T) {
	root := filepath.FromSlash("/var/lib/hull/containers/abc/merged")
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"empty", "", false},
		{"plain", "etc/passwd", false},
		{"dot", ".", false},
		{"inner dotdot", "etc/../etc/passwd", false},
		{"leading dotdot", "../etc/passwd", true},
		{"bare dotdot", "..", true},
		{"deep escape", "a/b/../../../etc/passwd", true},
		{"balanced", "a/b/../c", false},
		{"absolute outside", filepath.FromSlash("/etc/passwd"), true},
		{"absolute inside", filepath.FromSlash("/var/lib/hull/containers/abc/merged/etc"), false},
		{"absolute equal to root", root, false},
		{"absolute sibling prefix", filepath.FromSlash("/var/lib/hull/containers/abc/merged-evil/x"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsEscape(root, tt.path); got != tt.want {
				t.Fatalf("IsEscape(%q, %q) = %v, want %v", root, tt.path, got, tt.want)
			}
		})
	}
}

func TestSplitComponents(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a/b/c", []string{"a", "b", "c"}},
		{"a//b/./c", []string{"a", "b", "c"}},
		{"/a/b", []string{"a", "b"}},
		{"a/../b", []string{"a", "..", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := splitComponents(tt.in)
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Fatalf("splitComponents(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
