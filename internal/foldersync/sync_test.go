package foldersync

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pair creates a host and a volume directory under a fresh temp dir.
func pair(t *testing.T) (host, volume string) {
	t.Helper()
	root := t.TempDir()
	host = filepath.Join(root, "host")
	volume = filepath.Join(root, "volume")
	for _, d := range []string{host, volume} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll(%s) error = %v", d, err)
		}
	}
	return host, volume
}

// write puts content at root/rel, creating parents, and stamps it with mtime
// when one is given. Tests set mtimes explicitly because every decision this
// package makes is a timestamp comparison.
func write(t *testing.T, root, rel, content string, mode os.FileMode, mtime time.Time) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), mode); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", full, err)
	}
	if err := os.Chmod(full, mode); err != nil {
		t.Fatalf("Chmod(%s) error = %v", full, err)
	}
	if !mtime.IsZero() {
		if err := os.Chtimes(full, mtime, mtime); err != nil {
			t.Fatalf("Chtimes(%s) error = %v", full, err)
		}
	}
}

// read returns the contents of root/rel, failing the test if it is missing.
func read(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("ReadFile(%s/%s) error = %v", root, rel, err)
	}
	return string(b)
}

// present reports whether root/rel exists.
func present(root, rel string) bool {
	_, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil
}

// mtimeOf returns the modification time of root/rel.
func mtimeOf(t *testing.T, root, rel string) time.Time {
	t.Helper()
	fi, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("Lstat(%s/%s) error = %v", root, rel, err)
	}
	return fi.ModTime()
}

// newSyncer builds a Syncer over the pair with the ignore files disabled, so a
// test only ever sees the patterns it asked for plus the built-in defaults.
func newSyncer(t *testing.T, host, volume string, tweak func(*Config)) *Syncer {
	t.Helper()
	cfg := Config{
		HostPath:      host,
		VolumePath:    volume,
		NoIgnoreFiles: true,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return s
}

// syncOnce runs a pass and fails on a fatal error or any per-path error.
func syncOnce(t *testing.T, s *Syncer) Result {
	t.Helper()
	res, err := s.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("Sync() reported per-path errors: %v", res.Errors)
	}
	return res
}

func TestSyncFullReconciliation(t *testing.T) {
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		direction Direction
		// seed writes the starting trees.
		seed func(t *testing.T, host, volume string)
		// wantHost and wantVolume are path -> expected content after one pass.
		wantHost   map[string]string
		wantVolume map[string]string
		// wantAbsent lists paths that must not exist, as "side:path".
		wantAbsent []string
	}{
		{
			name:      "host to volume copies a whole tree",
			direction: Bidirectional,
			seed: func(t *testing.T, host, volume string) {
				write(t, host, "main.go", "package main", 0o644, base)
				write(t, host, "src/app/index.js", "console.log(1)", 0o600, base)
				write(t, host, "README.md", "hi", 0o644, base)
			},
			wantVolume: map[string]string{
				"main.go":          "package main",
				"src/app/index.js": "console.log(1)",
				"README.md":        "hi",
			},
		},
		{
			name:      "volume to host copies a whole tree",
			direction: Bidirectional,
			seed: func(t *testing.T, host, volume string) {
				write(t, volume, "dist/bundle.js", "built", 0o644, base)
				write(t, volume, "coverage.out", "mode: set", 0o644, base)
			},
			wantHost: map[string]string{
				"coverage.out": "mode: set",
			},
			// dist/ is excluded by default and must not reach the host.
			wantAbsent: []string{"host:dist", "host:dist/bundle.js"},
		},
		{
			name:      "bidirectional merges both sides",
			direction: Bidirectional,
			seed: func(t *testing.T, host, volume string) {
				write(t, host, "from-host.txt", "H", 0o644, base)
				write(t, volume, "sub/from-volume.txt", "V", 0o644, base)
			},
			wantHost: map[string]string{
				"from-host.txt":       "H",
				"sub/from-volume.txt": "V",
			},
			wantVolume: map[string]string{
				"from-host.txt":       "H",
				"sub/from-volume.txt": "V",
			},
		},
		{
			name:      "host-to-volume leaves volume-only files alone",
			direction: HostToVolume,
			seed: func(t *testing.T, host, volume string) {
				write(t, host, "src/main.go", "package main", 0o644, base)
				write(t, volume, "artifact.bin", "built here", 0o644, base)
			},
			wantVolume: map[string]string{
				"src/main.go":  "package main",
				"artifact.bin": "built here",
			},
			wantAbsent: []string{"host:artifact.bin"},
		},
		{
			name:      "volume-to-host leaves host-only files alone",
			direction: VolumeToHost,
			seed: func(t *testing.T, host, volume string) {
				write(t, volume, "out/report.txt", "done", 0o644, base)
				write(t, host, "notes.md", "mine", 0o644, base)
			},
			wantHost: map[string]string{
				"out/report.txt": "done",
				"notes.md":       "mine",
			},
			wantAbsent: []string{"volume:notes.md"},
		},
		{
			name:      "ignored directories never cross",
			direction: Bidirectional,
			seed: func(t *testing.T, host, volume string) {
				write(t, host, "node_modules/react/index.js", "huge", 0o644, base)
				write(t, host, ".git/HEAD", "ref: refs/heads/main", 0o644, base)
				write(t, host, "app.js", "small", 0o644, base)
			},
			wantVolume: map[string]string{"app.js": "small"},
			wantAbsent: []string{"volume:node_modules", "volume:.git", "volume:node_modules/react/index.js"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, volume := pair(t)
			tt.seed(t, host, volume)
			dir := tt.direction
			s := newSyncer(t, host, volume, func(c *Config) { c.Direction = dir })

			syncOnce(t, s)

			for rel, want := range tt.wantHost {
				if got := read(t, host, rel); got != want {
					t.Errorf("host %s = %q, want %q", rel, got, want)
				}
			}
			for rel, want := range tt.wantVolume {
				if got := read(t, volume, rel); got != want {
					t.Errorf("volume %s = %q, want %q", rel, got, want)
				}
			}
			for _, spec := range tt.wantAbsent {
				side, rel, _ := strings.Cut(spec, ":")
				root := host
				if side == "volume" {
					root = volume
				}
				if present(root, rel) {
					t.Errorf("%s %s exists, want it absent", side, rel)
				}
			}

			// A second pass must be a no-op: the first one is only correct if
			// it left both sides agreeing.
			res := syncOnce(t, s)
			if res.Changed() {
				t.Errorf("second pass changed things: %+v", res)
			}
		})
	}
}

func TestSyncPreservesModeAndMTime(t *testing.T) {
	host, volume := pair(t)
	stamp := time.Date(2026, 3, 1, 12, 30, 15, 0, time.UTC)
	write(t, host, "script.sh", "#!/bin/sh\n", 0o750, stamp)

	s := newSyncer(t, host, volume, nil)
	syncOnce(t, s)

	fi, err := os.Lstat(filepath.Join(volume, "script.sh"))
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o750 {
		t.Errorf("copied mode = %v, want %v", got, os.FileMode(0o750))
	}
	if got := fi.ModTime().UTC(); !got.Equal(stamp) {
		t.Errorf("copied mtime = %v, want %v", got, stamp)
	}
}

func TestSyncPropagatesDeletes(t *testing.T) {
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		// remove names the side the deletion happens on.
		remove Side
	}{
		{"deleted on the host", SideHost},
		{"deleted on the volume", SideVolume},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, volume := pair(t)
			write(t, host, "pkg/a.txt", "a", 0o644, base)
			write(t, host, "pkg/b.txt", "b", 0o644, base)

			s := newSyncer(t, host, volume, nil)
			syncOnce(t, s)
			if !present(volume, "pkg/a.txt") {
				t.Fatalf("setup failed: volume pkg/a.txt missing")
			}

			root := host
			otherRoot := volume
			if tt.remove == SideVolume {
				root, otherRoot = volume, host
			}
			if err := os.Remove(filepath.Join(root, "pkg", "a.txt")); err != nil {
				t.Fatalf("Remove() error = %v", err)
			}

			res := syncOnce(t, s)
			if present(otherRoot, "pkg/a.txt") {
				t.Fatalf("deletion on %s did not propagate: %s still has pkg/a.txt", tt.remove, otherRoot)
			}
			if !present(otherRoot, "pkg/b.txt") {
				t.Fatalf("deletion propagated too far: pkg/b.txt is gone from %s", otherRoot)
			}
			if res.DeletedHost+res.DeletedVolume != 1 {
				t.Fatalf("deleted host=%d volume=%d, want exactly one", res.DeletedHost, res.DeletedVolume)
			}
		})
	}
}

func TestSyncWithoutBaselineNeverDeletes(t *testing.T) {
	// A restarted syncer has no baseline. A path on one side and not the other
	// must then be read as a creation, never as a deletion, or restarting the
	// daemon would eat the user's files.
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	write(t, host, "only-host.txt", "H", 0o644, base)
	write(t, volume, "only-volume.txt", "V", 0o644, base)

	s := newSyncer(t, host, volume, nil)
	res := syncOnce(t, s)

	if res.DeletedHost+res.DeletedVolume != 0 {
		t.Fatalf("first pass deleted %d paths, want 0", res.DeletedHost+res.DeletedVolume)
	}
	if !present(volume, "only-host.txt") || !present(host, "only-volume.txt") {
		t.Fatalf("first pass did not propagate both creations")
	}
}

func TestSyncConflictNewestWinsAndLoserIsKept(t *testing.T) {
	older := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	newer := older.Add(30 * time.Second)

	tests := []struct {
		name        string
		hostMTime   time.Time
		volumeMTime time.Time
		wantWinner  Side
		wantContent string
		loserEmpty  bool
	}{
		{
			name:        "volume is newer",
			hostMTime:   older,
			volumeMTime: newer,
			wantWinner:  SideVolume,
			wantContent: "from the container",
		},
		{
			name:        "host is newer",
			hostMTime:   newer,
			volumeMTime: older,
			wantWinner:  SideHost,
			wantContent: "from the editor",
		},
		{
			name:        "empty loser is not kept",
			hostMTime:   older,
			volumeMTime: newer,
			wantWinner:  SideVolume,
			wantContent: "from the container",
			loserEmpty:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, volume := pair(t)
			hostContent := "from the editor"
			if tt.loserEmpty && tt.wantWinner == SideVolume {
				hostContent = ""
			}
			write(t, host, "app.js", hostContent, 0o644, tt.hostMTime)
			write(t, volume, "app.js", "from the container", 0o644, tt.volumeMTime)

			var events []Event
			s := newSyncer(t, host, volume, func(c *Config) {
				c.OnEvent = func(e Event) { events = append(events, e) }
			})
			res := syncOnce(t, s)

			if res.Conflicts != 1 {
				t.Fatalf("Conflicts = %d, want 1", res.Conflicts)
			}
			if got := read(t, host, "app.js"); got != tt.wantContent {
				t.Errorf("host app.js = %q, want %q", got, tt.wantContent)
			}
			if got := read(t, volume, "app.js"); got != tt.wantContent {
				t.Errorf("volume app.js = %q, want %q", got, tt.wantContent)
			}

			// The conflict must be reported, naming both sides.
			var conflict *Event
			for i := range events {
				if events[i].Kind == EventConflict {
					conflict = &events[i]
				}
			}
			if conflict == nil {
				t.Fatalf("no conflict event was emitted; got %v", events)
			}
			if conflict.Side != tt.wantWinner {
				t.Errorf("conflict winner = %s, want %s", conflict.Side, tt.wantWinner)
			}
			if conflict.LoserSide != other(tt.wantWinner) {
				t.Errorf("conflict loser = %s, want %s", conflict.LoserSide, other(tt.wantWinner))
			}
			if !conflict.HostMTime.Equal(tt.hostMTime) || !conflict.VolumeMTime.Equal(tt.volumeMTime) {
				t.Errorf("conflict mtimes = host %v volume %v, want host %v volume %v",
					conflict.HostMTime, conflict.VolumeMTime, tt.hostMTime, tt.volumeMTime)
			}

			loserRoot := host
			if tt.wantWinner == SideHost {
				loserRoot = volume
			}
			kept, err := filepath.Glob(filepath.Join(loserRoot, "app.js.hull-conflict-*"))
			if err != nil {
				t.Fatalf("Glob() error = %v", err)
			}
			if tt.loserEmpty {
				if len(kept) != 0 {
					t.Fatalf("empty loser was kept as %v, want nothing kept", kept)
				}
				if conflict.Kept != "" {
					t.Errorf("event Kept = %q, want empty", conflict.Kept)
				}
				return
			}
			if len(kept) != 1 {
				t.Fatalf("kept copies = %v, want exactly one", kept)
			}
			if conflict.Kept == "" {
				t.Errorf("event Kept is empty, want the preserved name")
			}
			if got := read(t, loserRoot, filepath.Base(kept[0])); got == tt.wantContent {
				t.Errorf("kept copy holds the winner's content %q; the loser's bytes were lost", got)
			}

			// The preserved copy is hull's own debris and must never be
			// propagated to the other side.
			res = syncOnce(t, s)
			if res.Changed() {
				t.Fatalf("second pass changed things: %+v", res)
			}
			winnerRoot := host
			if tt.wantWinner == SideVolume {
				winnerRoot = volume
			}
			crossed, err := filepath.Glob(filepath.Join(winnerRoot, "app.js.hull-conflict-*"))
			if err != nil {
				t.Fatalf("Glob() error = %v", err)
			}
			if len(crossed) != 0 {
				t.Fatalf("conflict copy crossed to the other side: %v", crossed)
			}
		})
	}
}

func TestSyncOnlyChangedSideWinsWithoutConflict(t *testing.T) {
	// One side edited since the last pass, the other untouched: no conflict,
	// no kept copy, even when the untouched side has the newer timestamp
	// (which happens whenever a copy landed after the edit).
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	write(t, host, "app.js", "v1", 0o644, base)

	s := newSyncer(t, host, volume, nil)
	syncOnce(t, s)

	// Edit the host with an *older* timestamp than the volume's copy.
	write(t, host, "app.js", "v2", 0o644, base.Add(-time.Hour))

	res := syncOnce(t, s)
	if res.Conflicts != 0 {
		t.Fatalf("Conflicts = %d, want 0", res.Conflicts)
	}
	if got := read(t, volume, "app.js"); got != "v2" {
		t.Fatalf("volume app.js = %q, want %q", got, "v2")
	}
	kept, _ := filepath.Glob(filepath.Join(volume, "app.js.hull-conflict-*"))
	if len(kept) != 0 {
		t.Fatalf("kept %v for a non-conflict", kept)
	}
}

func TestSyncDeleteVersusModifyKeepsTheBytes(t *testing.T) {
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	write(t, host, "app.js", "v1", 0o644, base)

	var events []Event
	s := newSyncer(t, host, volume, func(c *Config) {
		c.OnEvent = func(e Event) { events = append(events, e) }
	})
	syncOnce(t, s)

	// Deleted on the volume, edited on the host, in the same window.
	if err := os.Remove(filepath.Join(volume, "app.js")); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	write(t, host, "app.js", "v2", 0o644, base.Add(time.Minute))

	events = nil
	res := syncOnce(t, s)
	if res.Conflicts != 1 {
		t.Fatalf("Conflicts = %d, want 1", res.Conflicts)
	}
	if got := read(t, volume, "app.js"); got != "v2" {
		t.Fatalf("volume app.js = %q, want the surviving edit %q", got, "v2")
	}
	found := false
	for _, e := range events {
		if e.Kind == EventConflict && e.Side == SideHost && e.LoserSide == SideVolume {
			found = true
		}
	}
	if !found {
		t.Fatalf("no delete-versus-modify conflict event: %v", events)
	}
}

func TestSyncOneWayDirectionRestoresDeletedDestination(t *testing.T) {
	// In host-to-volume the host is the source of truth, so deleting the
	// volume's copy must restore it, not delete the original.
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	write(t, host, "app.js", "v1", 0o644, base)

	s := newSyncer(t, host, volume, func(c *Config) { c.Direction = HostToVolume })
	syncOnce(t, s)
	if err := os.Remove(filepath.Join(volume, "app.js")); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	syncOnce(t, s)
	if !present(host, "app.js") {
		t.Fatalf("host app.js was deleted; the host is the source of truth")
	}
	if got := read(t, volume, "app.js"); got != "v1" {
		t.Fatalf("volume app.js = %q, want it restored to %q", got, "v1")
	}
}

func TestSyncOneWayDirectionStillReportsConflicts(t *testing.T) {
	// The source of truth wins even when it is the older copy - but the
	// overwrite is never silent, and the bytes that lose are kept.
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	write(t, host, "app.js", "from the editor", 0o644, base)
	write(t, volume, "app.js", "from the container", 0o644, base.Add(time.Hour))

	var events []Event
	s := newSyncer(t, host, volume, func(c *Config) {
		c.Direction = HostToVolume
		c.OnEvent = func(e Event) { events = append(events, e) }
	})
	res := syncOnce(t, s)

	if res.Conflicts != 1 {
		t.Fatalf("Conflicts = %d, want 1", res.Conflicts)
	}
	if got := read(t, volume, "app.js"); got != "from the editor" {
		t.Fatalf("volume app.js = %q, want the host's copy", got)
	}
	kept, err := filepath.Glob(filepath.Join(volume, "app.js.hull-conflict-*"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(kept) != 1 {
		t.Fatalf("kept copies = %v, want exactly one on the volume", kept)
	}
	if got := read(t, volume, filepath.Base(kept[0])); got != "from the container" {
		t.Fatalf("kept copy = %q, want the overwritten bytes", got)
	}
	var winner Side
	for _, e := range events {
		if e.Kind == EventConflict {
			winner = e.Side
		}
	}
	if winner != SideHost {
		t.Fatalf("conflict winner = %q, want the source of truth (%s)", winner, SideHost)
	}
}

func TestSyncDirectoryDeletePropagates(t *testing.T) {
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	write(t, host, "pkg/sub/a.txt", "a", 0o644, base)

	s := newSyncer(t, host, volume, nil)
	syncOnce(t, s)
	if !present(volume, "pkg/sub/a.txt") {
		t.Fatalf("setup failed")
	}

	if err := os.RemoveAll(filepath.Join(host, "pkg")); err != nil {
		t.Fatalf("RemoveAll() error = %v", err)
	}
	syncOnce(t, s)

	if present(volume, "pkg") {
		t.Fatalf("volume pkg/ survived a host-side directory deletion")
	}
}

func TestSyncSymlinks(t *testing.T) {
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	write(t, host, "real.txt", "real", 0o644, base)
	if err := os.Symlink("real.txt", filepath.Join(host, "link.txt")); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	s := newSyncer(t, host, volume, nil)
	syncOnce(t, s)

	target, err := os.Readlink(filepath.Join(volume, "link.txt"))
	if err != nil {
		t.Fatalf("Readlink() error = %v", err)
	}
	if target != "real.txt" {
		t.Fatalf("copied symlink target = %q, want %q", target, "real.txt")
	}
	if res := syncOnce(t, s); res.Changed() {
		t.Fatalf("second pass changed things: %+v", res)
	}
}

func TestSyncLeavesNoTemporaryDebris(t *testing.T) {
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	for _, rel := range []string{"a.txt", "b/c.txt", "b/d.txt"} {
		write(t, host, rel, "x", 0o644, base)
	}

	s := newSyncer(t, host, volume, nil)
	syncOnce(t, s)

	err := filepath.WalkDir(volume, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), tmpPrefix) {
			t.Errorf("temporary file left behind: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir() error = %v", err)
	}
}

func TestSyncUsesIgnoreFilesFromTheRoots(t *testing.T) {
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	write(t, host, ".gitignore", "*.log\n", 0o644, base)
	write(t, host, ".hullignore", "secret/\n", 0o644, base)
	write(t, host, "app.log", "noise", 0o644, base)
	write(t, host, "secret/key.pem", "shh", 0o644, base)
	write(t, host, "app.js", "code", 0o644, base)

	s, err := New(Config{HostPath: host, VolumePath: volume})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	if !present(volume, "app.js") {
		t.Errorf("app.js was not synced")
	}
	if present(volume, "app.log") {
		t.Errorf("app.log was synced despite .gitignore")
	}
	if present(volume, "secret") {
		t.Errorf("secret/ was synced despite .hullignore")
	}
}

func TestSyncConfigIgnoreCanNegateADefault(t *testing.T) {
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	write(t, host, "dist/bundle.js", "built", 0o644, base)

	s := newSyncer(t, host, volume, func(c *Config) { c.Ignore = []string{"!dist/"} })
	syncOnce(t, s)

	if !present(volume, "dist/bundle.js") {
		t.Fatalf("a negation in Config.Ignore did not re-include dist/")
	}
}

func TestSyncStatus(t *testing.T) {
	host, volume := pair(t)
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	write(t, host, "a.txt", "a", 0o644, base)
	write(t, volume, "a.txt", "b", 0o644, base.Add(time.Hour))

	s := newSyncer(t, host, volume, nil)
	if st := s.Status(); st.Syncs != 0 || st.Running {
		t.Fatalf("fresh Status() = %+v, want no syncs and not running", st)
	}

	syncOnce(t, s)
	st := s.Status()
	if st.Syncs != 1 {
		t.Errorf("Status().Syncs = %d, want 1", st.Syncs)
	}
	if st.Conflicts != 1 {
		t.Errorf("Status().Conflicts = %d, want 1", st.Conflicts)
	}
	if st.HostPath != s.HostPath() || st.VolumePath != s.VolumePath() {
		t.Errorf("Status() paths = %s/%s, want %s/%s", st.HostPath, st.VolumePath, s.HostPath(), s.VolumePath())
	}
	if st.LastSync.IsZero() {
		t.Errorf("Status().LastSync is zero after a pass")
	}
	if st.Direction != Bidirectional {
		t.Errorf("Status().Direction = %v, want %v", st.Direction, Bidirectional)
	}
}

func TestSyncCancelledContext(t *testing.T) {
	host, volume := pair(t)
	s := newSyncer(t, host, volume, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Sync(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sync(cancelled) error = %v, want context.Canceled", err)
	}
}

func TestNewValidation(t *testing.T) {
	host, volume := pair(t)
	file := filepath.Join(host, "a-file")
	write(t, host, "a-file", "x", 0o644, time.Time{})

	tests := []struct {
		name string
		cfg  Config
		want error
	}{
		{"empty host", Config{VolumePath: volume}, ErrInvalidConfig},
		{"empty volume", Config{HostPath: host}, ErrInvalidConfig},
		{"missing host", Config{HostPath: filepath.Join(host, "nope"), VolumePath: volume}, ErrNotDirectory},
		{"host is a file", Config{HostPath: file, VolumePath: volume}, ErrNotDirectory},
		{"same directory", Config{HostPath: host, VolumePath: host}, ErrOverlap},
		{"volume inside host", Config{HostPath: host, VolumePath: filepath.Dir(host)}, ErrOverlap},
		{"windows drive path", Config{HostPath: `C:\Users\me\proj`, VolumePath: volume}, ErrWindowsPath},
		{"unc path", Config{HostPath: `\\wsl$\Ubuntu\home`, VolumePath: volume}, ErrWindowsPath},
		{"unknown direction", Config{HostPath: host, VolumePath: volume, Direction: Direction(7)}, ErrInvalidConfig},
		{"bad ignore pattern", Config{HostPath: host, VolumePath: volume, Ignore: []string{"[bad"}}, ErrBadPattern},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.cfg)
			if !errors.Is(err, tt.want) {
				t.Fatalf("New() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestNewAcceptsAValidPair(t *testing.T) {
	host, volume := pair(t)
	s, err := New(Config{HostPath: host, VolumePath: volume})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if s.Status().PollInterval != DefaultPollInterval {
		t.Errorf("default PollInterval = %v, want %v", s.Status().PollInterval, DefaultPollInterval)
	}
	if len(s.Ignorer().Patterns()) < len(DefaultIgnores()) {
		t.Errorf("Ignorer() lost the default patterns")
	}
}

func TestDirectionString(t *testing.T) {
	tests := []struct {
		d    Direction
		want string
	}{
		{Bidirectional, "bidirectional"},
		{HostToVolume, "host-to-volume"},
		{VolumeToHost, "volume-to-host"},
		{Direction(9), "direction(9)"},
	}
	for _, tt := range tests {
		if got := tt.d.String(); got != tt.want {
			t.Errorf("Direction(%d).String() = %q, want %q", int(tt.d), got, tt.want)
		}
	}
}
