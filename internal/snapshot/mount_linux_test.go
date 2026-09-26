//go:build linux

package snapshot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/fsutil"
)

// newMountSnapshotter builds a snapshotter that probed overlayfs for real, and
// skips the test when overlay cannot be used here.
func newMountSnapshotter(t *testing.T, root string) *Snapshotter {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	s, err := New(root, Features{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Features().Err(); err != nil {
		t.Skipf("overlayfs is not usable on this host: %v", err)
	}
	return s
}

// layerWith commits one snapshot holding the given files, on top of parent.
func layerWith(t *testing.T, s *Snapshotter, parent string, n int, files map[string]string) string {
	t.Helper()
	ctx := context.Background()
	diff := fmt.Sprintf("sha256:%064x", n)
	chain, err := ChainID(parent, diff)
	if err != nil {
		t.Fatalf("ChainID: %v", err)
	}
	fsDir, err := s.Prepare(ctx, chain, parent)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	for name, body := range files {
		mustWrite(t, filepath.Join(fsDir, name), body)
	}
	if err := s.Commit(ctx, chain, diff, int64(len(files))); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return chain
}

func TestRealOverlayMountRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newMountSnapshotter(t, shortTempRoot(t))

	base := layerWith(t, s, "", 1, map[string]string{
		"etc/base":    "base",
		"etc/shadow":  "from-base",
		"etc/deleted": "doomed",
	})
	top := layerWith(t, s, base, 2, map[string]string{
		"etc/top":    "top",
		"etc/shadow": "from-top",
	})

	merged, err := s.Mount(ctx, "ctr", top, false)
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	t.Cleanup(func() { _ = s.Unmount(context.Background(), "ctr") })

	if live, err := s.IsMounted("ctr"); err != nil || !live {
		t.Fatalf("IsMounted = %v, %v after a successful Mount", live, err)
	}

	// Upper layers win, and everything below is still visible.
	for name, want := range map[string]string{
		"etc/base":   "base",
		"etc/top":    "top",
		"etc/shadow": "from-top",
	} {
		got, rerr := os.ReadFile(filepath.Join(merged, name))
		if rerr != nil || string(got) != want {
			t.Fatalf("merged %s = %q, %v; want %q", name, got, rerr, want)
		}
	}

	// A write lands in the upperdir, not in any layer.
	if err := os.WriteFile(filepath.Join(merged, "etc", "written"), []byte("live"), 0o644); err != nil {
		t.Fatalf("write into the merged view: %v", err)
	}
	upper, _ := s.UpperPath("ctr")
	got, err := os.ReadFile(filepath.Join(upper, "etc", "written"))
	if err != nil || string(got) != "live" {
		t.Fatalf("upperdir etc/written = %q, %v; want %q", got, err, "live")
	}
	for _, chain := range []string{base, top} {
		fsDir, _ := s.FSDir(chain)
		if _, serr := os.Lstat(filepath.Join(fsDir, "etc", "written")); !errors.Is(serr, os.ErrNotExist) {
			t.Fatalf("the write leaked into the read-only layer %s: %v", chain, serr)
		}
	}

	// A deletion becomes a whiteout in the upperdir.
	if err := os.Remove(filepath.Join(merged, "etc", "deleted")); err != nil {
		t.Fatalf("remove through the merged view: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(upper, "etc", "deleted"), &st); err != nil {
		t.Fatalf("no whiteout in the upperdir: %v", err)
	}
	if !isWhiteout(&st) {
		t.Fatalf("upperdir etc/deleted is mode %#o rdev %d, want a character device 0:0", st.Mode, st.Rdev)
	}

	changes, err := s.Changes(ctx, "ctr")
	if err != nil {
		t.Fatalf("Changes: %v", err)
	}
	kinds := map[string]ChangeKind{}
	for _, c := range changes {
		kinds[c.Path] = c.Kind
	}
	if kinds["/etc/written"] != KindAdded {
		t.Fatalf("/etc/written is %q, want added (all changes: %+v)", kinds["/etc/written"], changes)
	}
	if kinds["/etc/deleted"] != KindDeleted {
		t.Fatalf("/etc/deleted is %q, want deleted (all changes: %+v)", kinds["/etc/deleted"], changes)
	}

	// Mount is idempotent while the mount is live.
	again, err := s.Mount(ctx, "ctr", top, false)
	if err != nil || again != merged {
		t.Fatalf("second Mount = %q, %v; want %q", again, err, merged)
	}

	if err := s.Unmount(ctx, "ctr"); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	still, err := fsutil.IsMountpoint(merged)
	if err != nil {
		t.Fatalf("IsMountpoint: %v", err)
	}
	if still {
		t.Fatal("merged is still a mountpoint after Unmount")
	}
	if err := s.Unmount(ctx, "ctr"); err != nil {
		t.Fatalf("Unmount twice: %v", err)
	}

	// The upperdir survives the unmount; Remove takes it away.
	if _, err := os.Stat(filepath.Join(upper, "etc", "written")); err != nil {
		t.Fatalf("Unmount destroyed the upperdir: %v", err)
	}
	if err := s.Remove(ctx, "ctr"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(upper); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Remove kept the upperdir: %v", err)
	}
	if _, err := s.record("ctr"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Remove kept the mount record: %v", err)
	}
}

func TestReadonlyMounts(t *testing.T) {
	ctx := context.Background()
	s := newMountSnapshotter(t, shortTempRoot(t))

	base := layerWith(t, s, "", 1, map[string]string{"a": "a"})

	// One layer: a read-only bind, because overlayfs needs two lowers without
	// an upperdir.
	single, err := s.Mount(ctx, "one", base, true)
	if err != nil {
		t.Fatalf("Mount one layer read-only: %v", err)
	}
	t.Cleanup(func() { _ = s.Unmount(context.Background(), "one") })
	if got, rerr := os.ReadFile(filepath.Join(single, "a")); rerr != nil || string(got) != "a" {
		t.Fatalf("read-only bind a = %q, %v", got, rerr)
	}
	if err := os.WriteFile(filepath.Join(single, "b"), []byte("b"), 0o644); err == nil {
		t.Fatal("a read-only mount accepted a write")
	}
	if err := s.Unmount(ctx, "one"); err != nil {
		t.Fatalf("Unmount: %v", err)
	}

	// Two layers: a real read-only overlay.
	top := layerWith(t, s, base, 2, map[string]string{"b": "b"})
	stacked, err := s.Mount(ctx, "two", top, true)
	if err != nil {
		t.Fatalf("Mount two layers read-only: %v", err)
	}
	t.Cleanup(func() { _ = s.Unmount(context.Background(), "two") })
	for name, want := range map[string]string{"a": "a", "b": "b"} {
		got, rerr := os.ReadFile(filepath.Join(stacked, name))
		if rerr != nil || string(got) != want {
			t.Fatalf("read-only overlay %s = %q, %v", name, got, rerr)
		}
	}
	if err := os.WriteFile(filepath.Join(stacked, "c"), []byte("c"), 0o644); err == nil {
		t.Fatal("a read-only overlay accepted a write")
	}
	upper, _ := s.UpperPath("two")
	if fsutil.Exists(upper) {
		t.Fatalf("a read-only mount created an upperdir at %s", upper)
	}
	if err := s.Unmount(ctx, "two"); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
}

// TestMountFoldsLowersWhenOptionsOverflow drives the nested-lower fallback by
// putting the snapshotter root behind a deliberately long path, so that the
// lowerdir list for a moderate number of layers no longer fits in one page.
func TestMountFoldsLowersWhenOptionsOverflow(t *testing.T) {
	ctx := context.Background()
	deep := filepath.Join(shortTempRoot(t), strings.Repeat("d", 90))
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	s := newMountSnapshotter(t, deep)

	const layers = 40
	parent := ""
	for i := 0; i < layers; i++ {
		parent = layerWith(t, s, parent, i+1, map[string]string{fmt.Sprintf("f%d", i): fmt.Sprint(i)})
	}

	_, dirs, err := s.lowerDirsFor(ctx, parent)
	if err != nil {
		t.Fatalf("lowerDirsFor: %v", err)
	}
	cdir, _ := s.ContainerDir("deep")
	flat, err := buildOverlayOptions(dirs, filepath.Join(cdir, DirUpper), filepath.Join(cdir, DirWork), false)
	if err != nil {
		t.Fatalf("buildOverlayOptions: %v", err)
	}
	if fitsOnePage(flat) {
		t.Skipf("this root is not long enough to overflow a page (%d bytes); the fallback is untested here", len(flat))
	}

	merged, err := s.Mount(ctx, "deep", parent, false)
	if err != nil {
		t.Fatalf("Mount with a folded lower stack: %v", err)
	}
	t.Cleanup(func() { _ = s.Unmount(context.Background(), "deep") })

	rec, err := s.record("deep")
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(rec.Stack) == 0 {
		t.Fatal("the mount fit in one page after all; the fallback did not run")
	}
	// Every layer, including the oldest ones that were folded away, is visible.
	for i := 0; i < layers; i++ {
		got, rerr := os.ReadFile(filepath.Join(merged, fmt.Sprintf("f%d", i)))
		if rerr != nil || string(got) != fmt.Sprint(i) {
			t.Fatalf("layer %d is not visible through the folded stack: %q, %v", i, got, rerr)
		}
	}
	if err := s.Unmount(ctx, "deep"); err != nil {
		t.Fatalf("Unmount a folded stack: %v", err)
	}
	for _, mp := range rec.Stack {
		still, merr := fsutil.IsMountpoint(mp)
		if merr != nil {
			t.Fatalf("IsMountpoint(%s): %v", mp, merr)
		}
		if still {
			t.Fatalf("the nested lower mount %s survived Unmount", mp)
		}
	}
}

func TestMountRefusesWhenOverlayIsUnusable(t *testing.T) {
	s, err := New(shortTempRoot(t), Features{Supported: true, MountTested: true, MountOK: false, MountError: "EPERM"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = s.Mount(context.Background(), "ctr", diffA, false)
	if !errors.Is(err, ErrOverlayUnsupported) {
		t.Fatalf("Mount with a failed probe = %v, want ErrOverlayUnsupported", err)
	}
	if !strings.Contains(err.Error(), "EPERM") {
		t.Fatalf("the error does not carry the probe's diagnosis: %v", err)
	}
}

func TestMountRejectsABadContainerID(t *testing.T) {
	s := newTestSnapshotter(t)
	for _, id := range []string{"", "..", "a/b"} {
		if _, err := s.Mount(context.Background(), id, diffA, false); err == nil {
			t.Fatalf("Mount accepted the container ID %q", id)
		}
	}
}

func TestUnmountAndRemoveAreIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	if err := s.Unmount(ctx, "never-mounted"); err != nil {
		t.Fatalf("Unmount of an unknown container: %v", err)
	}
	if err := s.Remove(ctx, "never-mounted"); err != nil {
		t.Fatalf("Remove of an unknown container: %v", err)
	}
}

func TestCleanupReconcilesStaleMountRecords(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	merged, _ := s.MergedPath("ghost")
	if err := os.MkdirAll(merged, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := s.withMounts(ctx, func(mf *mountsFile) error {
		mf.Mounts["ghost"] = &mountRecord{
			ContainerID: "ghost",
			Merged:      merged,
			Mounted:     true,
			Stack:       []string{filepath.Join(merged, "..", DirStack, "0")},
		}
		return nil
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := s.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	rec, err := s.record("ghost")
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if rec.Mounted {
		t.Fatal("Cleanup left a dead mount recorded as live")
	}
	if len(rec.Stack) != 0 {
		t.Fatalf("Cleanup kept a stale nested stack: %v", rec.Stack)
	}
}
