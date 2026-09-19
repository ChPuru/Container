package cli

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTarRoundTrip checks that a directory survives a tar and an untar with
// its layout intact, which is the whole of "hull cp" in both directions.
func TestTarRoundTrip(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "top.txt"), "top")
	if err := os.MkdirAll(filepath.Join(src, "sub", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, "sub", "deep", "leaf.txt"), "leaf")

	var buf bytes.Buffer
	if err := tarPath(&buf, src, tarOptions{Rename: "payload"}); err != nil {
		t.Fatalf("tarPath: %v", err)
	}

	dst := t.TempDir()
	if err := untarTo(bytes.NewReader(buf.Bytes()), dst, ""); err != nil {
		t.Fatalf("untarTo: %v", err)
	}
	for path, want := range map[string]string{
		filepath.Join(dst, "payload", "top.txt"):                  "top",
		filepath.Join(dst, "payload", "sub", "deep", "leaf.txt"): "leaf",
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
}

// TestTarRenameOnExtract checks the rename an extraction applies when the
// destination names a new file, which is how "hull cp ctr:/a ./b" works.
func TestTarRenameOnExtract(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "original.txt"), "hello")

	var buf bytes.Buffer
	if err := tarPath(&buf, filepath.Join(src, "original.txt"), tarOptions{}); err != nil {
		t.Fatalf("tarPath: %v", err)
	}
	dst := t.TempDir()
	if err := untarTo(bytes.NewReader(buf.Bytes()), dst, "renamed.txt"); err != nil {
		t.Fatalf("untarTo: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "renamed.txt"))
	if err != nil {
		t.Fatalf("reading the renamed file: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("renamed file = %q, want %q", got, "hello")
	}
}

// TestUntarRefusesEscape is the security case: the archive comes out of a
// container, whose filesystem is attacker-controlled by assumption, so an
// entry that climbs out of the destination must be refused rather than
// written.
func TestUntarRefusesEscape(t *testing.T) {
	tests := []struct {
		name string
		// entry is the archive member's name.
		entry string
		// wantContained, when set, says the entry should be rooted at the
		// destination under this relative path instead of being refused.
		wantContained string
	}{
		{name: "relative traversal", entry: "../escaped.txt"},
		{name: "deep traversal", entry: "a/b/../../../escaped.txt"},
		{name: "absolute path", entry: "/etc/escaped.txt", wantContained: filepath.Join("etc", "escaped.txt")},
		{name: "windows separators", entry: `..\escaped.txt`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			body := []byte("pwned")
			if err := tw.WriteHeader(&tar.Header{
				Name:     tt.entry,
				Mode:     0o644,
				Size:     int64(len(body)),
				Typeflag: tar.TypeReg,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(body); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}

			parent := t.TempDir()
			canary := filepath.Join(parent, "escaped.txt")
			dst := filepath.Join(parent, "dest")
			if err := os.MkdirAll(dst, 0o755); err != nil {
				t.Fatal(err)
			}

			err := untarTo(bytes.NewReader(buf.Bytes()), dst, "")
			if _, statErr := os.Stat(canary); statErr == nil {
				t.Fatalf("entry %q escaped the destination and wrote %s", tt.entry, canary)
			}
			if tt.wantContained != "" {
				// An absolute name is neutralised by being rooted at the
				// destination rather than refused, which is what every tar
				// tool does and is safe.
				if err != nil {
					t.Fatalf("entry %q should have been contained, not refused: %v", tt.entry, err)
				}
				if _, statErr := os.Stat(filepath.Join(dst, tt.wantContained)); statErr != nil {
					t.Fatalf("entry %q was neither refused nor contained at %s", tt.entry, tt.wantContained)
				}
				return
			}
			if err == nil {
				t.Fatalf("entry %q was accepted; a traversal must be refused", tt.entry)
			}
			if !strings.Contains(err.Error(), "escapes") {
				t.Fatalf("entry %q was refused with an unhelpful error: %v", tt.entry, err)
			}
		})
	}
}

// TestDockerIgnoreMatching covers the patterns a build context actually
// carries. Getting this wrong ships a .git directory to the engine.
func TestDockerIgnoreMatching(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".dockerignore"), strings.Join([]string{
		"# a comment",
		"",
		".git",
		"node_modules",
		"*.log",
		"**/tmp",
		"!keep.log",
	}, "\n"))
	di, err := loadDockerIgnore(dir)
	if err != nil {
		t.Fatalf("loadDockerIgnore: %v", err)
	}
	tests := []struct {
		path string
		want bool
	}{
		{".git", true},
		{".git/config", true},
		{"node_modules/left-pad/index.js", true},
		{"server.log", true},
		{"keep.log", false},
		{"src/main.go", false},
		{"a/b/tmp", true},
		{"Dockerfile", false},
	}
	for _, tt := range tests {
		if got := di.Match(tt.path); got != tt.want {
			t.Errorf("Match(%q) = %t, want %t", tt.path, got, tt.want)
		}
	}
}

// TestDockerIgnoreAbsentIsEmpty checks that a context with no .dockerignore
// excludes nothing rather than failing.
func TestDockerIgnoreAbsentIsEmpty(t *testing.T) {
	di, err := loadDockerIgnore(t.TempDir())
	if err != nil {
		t.Fatalf("loadDockerIgnore: %v", err)
	}
	if di.Match("anything") {
		t.Errorf("an absent .dockerignore excluded something")
	}
}

// TestSplitCopyArgument covers the one place a Windows path and a container
// reference are ambiguous.
func TestSplitCopyArgument(t *testing.T) {
	tests := []struct {
		arg           string
		wantContainer string
		wantPath      string
	}{
		{arg: "web:/etc/passwd", wantContainer: "web", wantPath: "/etc/passwd"},
		{arg: `C:\Users\me\src`, wantContainer: "", wantPath: `C:\Users\me\src`},
		{arg: "c:/Users/me/src", wantContainer: "", wantPath: "c:/Users/me/src"},
		{arg: "./local/path", wantContainer: "", wantPath: "./local/path"},
		{arg: "/abs/path", wantContainer: "", wantPath: "/abs/path"},
		{arg: "-", wantContainer: "", wantPath: "-"},
		{arg: "deadbeef1234:/data", wantContainer: "deadbeef1234", wantPath: "/data"},
	}
	for _, tt := range tests {
		gotCtr, gotPath := splitCopyArg(tt.arg)
		if gotCtr != tt.wantContainer || gotPath != tt.wantPath {
			t.Errorf("splitCopyArg(%q) = (%q, %q), want (%q, %q)",
				tt.arg, gotCtr, gotPath, tt.wantContainer, tt.wantPath)
		}
	}
}

// writeFile writes a test fixture, creating its parent directory.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
