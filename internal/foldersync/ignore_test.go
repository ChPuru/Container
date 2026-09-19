package foldersync

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIgnorerMatch(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		path     string
		isDir    bool
		want     bool
	}{
		// Plain basename patterns match at any depth.
		{"basename at root", []string{"*.swp"}, ".main.go.swp", false, true},
		{"basename nested", []string{"*.swp"}, "src/deep/.main.go.swp", false, true},
		{"basename no match", []string{"*.swp"}, "src/main.go", false, false},
		{"exact name nested", []string{"node_modules"}, "packages/app/node_modules", true, true},

		// Directory-only patterns.
		{"dir-only matches dir", []string{"build/"}, "build", true, true},
		{"dir-only skips file", []string{"build/"}, "build", false, false},
		{"dir-only nested dir", []string{"build/"}, "sub/build", true, true},
		{"dir-only content of dir", []string{"build/"}, "build/out.o", false, true},

		// Anchoring: a slash anywhere anchors to the sync root.
		{"anchored leading slash", []string{"/dist"}, "dist", true, true},
		{"anchored leading slash nested", []string{"/dist"}, "app/dist", true, false},
		{"anchored by inner slash", []string{"docs/build"}, "docs/build", true, true},
		{"anchored by inner slash elsewhere", []string{"docs/build"}, "a/docs/build", true, false},

		// Globs never cross a separator; ** does.
		{"star stops at slash", []string{"src/*.go"}, "src/pkg/main.go", false, false},
		{"star within segment", []string{"src/*.go"}, "src/main.go", false, true},
		{"doublestar spans", []string{"src/**/*.go"}, "src/a/b/main.go", false, true},
		{"doublestar spans zero", []string{"src/**/main.go"}, "src/main.go", false, true},
		{"leading doublestar", []string{"**/fixtures"}, "test/data/fixtures", true, true},
		{"trailing doublestar", []string{"logs/**"}, "logs/a/b.txt", false, true},
		{"question mark", []string{"?.txt"}, "a.txt", false, true},
		{"character class", []string{"[abc].txt"}, "b.txt", false, true},
		{"character class miss", []string{"[abc].txt"}, "d.txt", false, false},

		// Negation, last match wins.
		{"negation re-includes", []string{"*.log", "!keep.log"}, "keep.log", false, false},
		{"negation order matters", []string{"!keep.log", "*.log"}, "keep.log", false, true},
		{"negation leaves others", []string{"*.log", "!keep.log"}, "drop.log", false, true},
		{"negation cannot escape an ignored directory", []string{"node_modules/", "!node_modules/mine.js"}, "node_modules/mine.js", false, true},

		// Comments, blanks and escapes.
		{"comment ignored", []string{"# *.go"}, "main.go", false, false},
		{"blank ignored", []string{"   "}, "main.go", false, false},
		{"escaped hash is literal", []string{`\#notes`}, "#notes", false, true},
		{"trailing space trimmed", []string{"*.log   "}, "a.log", false, true},

		// The path itself is never confused with the root.
		{"root is never ignored", []string{"*"}, "", true, false},
		{"dot is never ignored", []string{"*"}, ".", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ig, err := NewIgnorer(tt.patterns...)
			if err != nil {
				t.Fatalf("NewIgnorer(%q) error = %v", tt.patterns, err)
			}
			if got := ig.Match(tt.path, tt.isDir); got != tt.want {
				t.Fatalf("Match(%q, isDir=%v) = %v, want %v (patterns %q)", tt.path, tt.isDir, got, tt.want, tt.patterns)
			}
		})
	}
}

func TestDefaultIgnoresCoverTheExpensiveDirectories(t *testing.T) {
	ig, err := NewIgnorer(DefaultIgnores()...)
	if err != nil {
		t.Fatalf("NewIgnorer(defaults) error = %v", err)
	}
	tests := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{"node_modules", true, true},
		{"node_modules/react/index.js", false, true},
		{"packages/app/node_modules/x", false, true},
		{".git", true, true},
		{".git/objects/ab/cd", false, true},
		{"target", true, true},
		{"vendor", true, true},
		{"__pycache__", true, true},
		{".venv", true, true},
		{"dist", true, true},
		{"build", true, true},
		{".main.go.swp", false, true},
		{"app.js.hull-conflict-20260919T101010.000", false, true},
		{tmpPrefix + "123456", false, true},

		// Things a project actually edits must never be excluded.
		{"src/index.js", false, false},
		{"README.md", false, false},
		{"build.sh", false, false},
		{"build", false, false}, // a file called build is not the build dir
		{"cmd/hull/main.go", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := ig.Match(tt.path, tt.isDir); got != tt.want {
				t.Fatalf("Match(%q, isDir=%v) = %v, want %v", tt.path, tt.isDir, got, tt.want)
			}
		})
	}
}

func TestNewIgnorerRejectsBadPattern(t *testing.T) {
	if _, err := NewIgnorer("[unterminated"); !errors.Is(err, ErrBadPattern) {
		t.Fatalf("NewIgnorer(bad) error = %v, want ErrBadPattern", err)
	}
}

func TestIgnorerPatternsRoundTrip(t *testing.T) {
	ig, err := NewIgnorer("# comment", "", "*.log", "!keep.log")
	if err != nil {
		t.Fatalf("NewIgnorer() error = %v", err)
	}
	got := ig.Patterns()
	want := []string{"*.log", "!keep.log"}
	if len(got) != len(want) {
		t.Fatalf("Patterns() = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Patterns() = %q, want %q", got, want)
		}
	}
}

func TestLoadIgnoreFile(t *testing.T) {
	dir := t.TempDir()

	got, err := LoadIgnoreFile(filepath.Join(dir, ".hullignore"))
	if err != nil {
		t.Fatalf("LoadIgnoreFile(missing) error = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Fatalf("LoadIgnoreFile(missing) = %q, want none", got)
	}

	name := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(name, []byte("# comment\n*.log\n\n!keep.log\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	got, err = LoadIgnoreFile(name)
	if err != nil {
		t.Fatalf("LoadIgnoreFile() error = %v", err)
	}
	want := []string{"# comment", "*.log", "", "!keep.log"}
	if len(got) != len(want) {
		t.Fatalf("LoadIgnoreFile() = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("LoadIgnoreFile() = %q, want %q", got, want)
		}
	}
}
