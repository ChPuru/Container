//go:build linux

package volume

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ChPuru/hull/internal/types"
)

// mkImageRootfs builds a miniature "image rootfs" with content at
// /var/lib/db: a file with a distinctive mode, a nested directory, a relative
// symlink and an empty directory.
func mkImageRootfs(t *testing.T) string {
	t.Helper()
	rootfs := t.TempDir()
	db := filepath.Join(rootfs, "var", "lib", "db")
	mustMkdirAll(t, filepath.Join(db, "base", "1"), 0o755)
	mustMkdirAll(t, filepath.Join(db, "empty"), 0o750)
	mustWrite(t, filepath.Join(db, "PG_VERSION"), "16\n", 0o640)
	mustWrite(t, filepath.Join(db, "base", "1", "data.bin"), "rows", 0o600)
	if err := os.Symlink("PG_VERSION", filepath.Join(db, "version.link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// The directory mode has to survive the copy: postgres refuses to start if
	// its data directory is group-readable.
	if err := os.Chmod(db, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return rootfs
}

func TestResolveSeedsFreshVolumeFromImage(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)
	rootfs := mkImageRootfs(t)

	c := mkContainer("c1", types.HostConfig{Binds: []string{"db:/var/lib/db"}}, types.ContainerConfig{}, rootfs)
	got, err := m.Resolve(ctx, c)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Resolve = %+v", got)
	}
	data := got[0].Source

	if b, err := os.ReadFile(filepath.Join(data, "PG_VERSION")); err != nil || string(b) != "16\n" {
		t.Fatalf("PG_VERSION = %q, %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(data, "base", "1", "data.bin")); err != nil || string(b) != "rows" {
		t.Fatalf("base/1/data.bin = %q, %v", b, err)
	}
	if fi, err := os.Stat(filepath.Join(data, "empty")); err != nil || !fi.IsDir() {
		t.Fatalf("empty dir not copied: %v", err)
	}

	// Modes are preserved, including on the volume root itself.
	assertPerm(t, data, 0o700)
	assertPerm(t, filepath.Join(data, "PG_VERSION"), 0o640)
	assertPerm(t, filepath.Join(data, "base", "1", "data.bin"), 0o600)
	assertPerm(t, filepath.Join(data, "empty"), 0o750)

	// A symlink is recreated as a symlink, never dereferenced into a copy.
	target, err := os.Readlink(filepath.Join(data, "version.link"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != "PG_VERSION" {
		t.Fatalf("symlink target = %q, want PG_VERSION", target)
	}
}

func TestResolveDoesNotSeedNonEmptyVolume(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)
	rootfs := mkImageRootfs(t)

	if _, err := m.Create(ctx, "db", "", nil, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	data, err := m.DataDir("db")
	if err != nil {
		t.Fatalf("DataDir: %v", err)
	}
	mustWrite(t, filepath.Join(data, "existing"), "mine", 0o644)

	c := mkContainer("c1", types.HostConfig{Binds: []string{"db:/var/lib/db"}}, types.ContainerConfig{}, rootfs)
	if _, err := m.Resolve(ctx, c); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	entries, err := os.ReadDir(data)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "existing" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("a non-empty volume must not be seeded, found %v", names)
	}
}

func TestResolveNoCopySkipsSeeding(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)
	rootfs := mkImageRootfs(t)

	c := mkContainer("c1", types.HostConfig{Binds: []string{"db:/var/lib/db:nocopy"}}, types.ContainerConfig{}, rootfs)
	got, err := m.Resolve(ctx, c)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	entries, err := os.ReadDir(got[0].Source)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("nocopy volume was seeded anyway: %v", entries)
	}
	// nocopy is a hull-internal carrier and must not leak into the mount record.
	if got[0].Consistency != "" {
		t.Fatalf("Consistency leaked into the resolved mount: %q", got[0].Consistency)
	}
}

func TestResolveSeedsNothingWhenImageHasNoContent(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)
	rootfs := t.TempDir() // no /var/lib/db at all

	c := mkContainer("c1", types.HostConfig{Binds: []string{"db:/var/lib/db"}}, types.ContainerConfig{}, rootfs)
	got, err := m.Resolve(ctx, c)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	entries, err := os.ReadDir(got[0].Source)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("seeded from an image with no content: %v", entries)
	}

	// A regular file where a directory was expected is also "nothing to seed".
	mustMkdirAll(t, filepath.Join(rootfs, "etc"), 0o755)
	mustWrite(t, filepath.Join(rootfs, "etc", "passwd"), "root:x:0:0:::", 0o644)
	c2 := mkContainer("c2", types.HostConfig{Binds: []string{"pw:/etc/passwd"}}, types.ContainerConfig{}, rootfs)
	got2, err := m.Resolve(ctx, c2)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	entries2, err := os.ReadDir(got2[0].Source)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries2) != 0 {
		t.Fatalf("seeded from a non-directory: %v", entries2)
	}
}

// TestSeedContainsSymlinkEscapes is the security regression: an absolute
// symlink inside a container-controlled rootfs must resolve *inside* that
// rootfs, never on the host, and a symlink below the seeded directory must be
// copied rather than followed.
func TestSeedContainsSymlinkEscapes(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(t)
	rootfs := t.TempDir()

	// rootfs/etc holds the in-image file an absolute symlink should reach.
	mustMkdirAll(t, filepath.Join(rootfs, "etc"), 0o755)
	mustWrite(t, filepath.Join(rootfs, "etc", "marker"), "in-image", 0o644)

	// rootfs/seed is a symlink to the absolute path /etc. Resolved inside the
	// rootfs it is rootfs/etc; resolved on the host it would be /etc.
	if err := os.Symlink("/etc", filepath.Join(rootfs, "seed")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// And a dangling escape attempt below the seeded directory.
	if err := os.Symlink("/etc/shadow", filepath.Join(rootfs, "etc", "escape")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	c := mkContainer("c1", types.HostConfig{Binds: []string{"seeded:/seed"}}, types.ContainerConfig{}, rootfs)
	got, err := m.Resolve(ctx, c)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	data := got[0].Source

	b, err := os.ReadFile(filepath.Join(data, "marker"))
	if err != nil {
		t.Fatalf("the absolute symlink did not resolve inside the rootfs: %v", err)
	}
	if string(b) != "in-image" {
		t.Fatalf("marker = %q, want in-image", b)
	}

	fi, err := os.Lstat(filepath.Join(data, "escape"))
	if err != nil {
		t.Fatalf("lstat escape: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("an escaping symlink was dereferenced into a copy instead of recreated as a link")
	}
	if tgt, err := os.Readlink(filepath.Join(data, "escape")); err != nil || tgt != "/etc/shadow" {
		t.Fatalf("escape link target = %q, %v", tgt, err)
	}
}

func mustMkdirAll(t *testing.T, path string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, perm); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func mustWrite(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}
