//go:build linux

package snapshot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// mkWhiteout creates an overlayfs whiteout: a character device 0:0. Linux 5.8
// and later let an unprivileged process create exactly this device, which is
// what makes rootless layer extraction possible at all.
func mkWhiteout(t *testing.T, path string) {
	t.Helper()
	if err := unix.Mknod(path, unix.S_IFCHR|0o600, 0); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("this kernel refuses an unprivileged whiteout mknod: %v", err)
		}
		t.Fatalf("mknod whiteout %s: %v", path, err)
	}
}

// mustWrite writes a file, creating parents.
func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// imageWithUpper builds a one-layer image, an upperdir for container "ctr" and
// the mount record that ties them together, without needing a real mount.
func imageWithUpper(t *testing.T) (*Snapshotter, string, string) {
	t.Helper()
	ctx := context.Background()
	s := newTestSnapshotter(t)

	fsDir, err := s.Prepare(ctx, diffA, "")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	mustWrite(t, filepath.Join(fsDir, "etc", "keep"), "keep")
	mustWrite(t, filepath.Join(fsDir, "etc", "edit"), "original")
	mustWrite(t, filepath.Join(fsDir, "etc", "gone"), "doomed")
	if err := s.Commit(ctx, diffA, diffA, 10); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	upper, err := s.UpperPath("ctr")
	if err != nil {
		t.Fatalf("UpperPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(upper, "etc"), 0o755); err != nil {
		t.Fatalf("mkdir upper: %v", err)
	}
	merged, _ := s.MergedPath("ctr")
	if err := s.withMounts(ctx, func(mf *mountsFile) error {
		mf.Mounts["ctr"] = &mountRecord{
			ContainerID: "ctr",
			ChainID:     diffA,
			Lowers:      []string{diffA},
			Upper:       upper,
			Merged:      merged,
		}
		return nil
	}); err != nil {
		t.Fatalf("record the mount: %v", err)
	}
	return s, upper, fsDir
}

func TestChangesClassifiesAddedModifiedDeleted(t *testing.T) {
	ctx := context.Background()
	s, upper, _ := imageWithUpper(t)

	mustWrite(t, filepath.Join(upper, "etc", "edit"), "changed")
	mustWrite(t, filepath.Join(upper, "etc", "new"), "new")
	mkWhiteout(t, filepath.Join(upper, "etc", "gone"))

	got, err := s.Changes(ctx, "ctr")
	if err != nil {
		t.Fatalf("Changes: %v", err)
	}
	want := map[string]ChangeKind{
		"/etc":      KindModified,
		"/etc/edit": KindModified,
		"/etc/gone": KindDeleted,
		"/etc/new":  KindAdded,
	}
	if len(got) != len(want) {
		t.Fatalf("Changes = %+v, want %d entries", got, len(want))
	}
	for _, c := range got {
		w, ok := want[c.Path]
		if !ok {
			t.Fatalf("unexpected change %+v", c)
		}
		if c.Kind != w {
			t.Fatalf("%s is %s, want %s", c.Path, c.Kind, w)
		}
	}
	// The result must be sorted, because the API renders it straight out.
	for i := 1; i < len(got); i++ {
		if got[i-1].Path > got[i].Path {
			t.Fatalf("Changes is not sorted: %q before %q", got[i-1].Path, got[i].Path)
		}
	}
}

func TestChangesWithNoUpperdirIsEmpty(t *testing.T) {
	s := newTestSnapshotter(t)
	got, err := s.Changes(context.Background(), "never-started")
	if err != nil {
		t.Fatalf("Changes: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Changes = %+v, want none", got)
	}
}

func TestChangesNeedsAMountRecord(t *testing.T) {
	s := newTestSnapshotter(t)
	upper, _ := s.UpperPath("orphan")
	if err := os.MkdirAll(upper, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	mustWrite(t, filepath.Join(upper, "f"), "f")
	_, err := s.Changes(context.Background(), "orphan")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Changes without a mount record = %v, want ErrNotFound", err)
	}
}

// ---------- checkpoints ----------

func TestCheckpointRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, upper, _ := imageWithUpper(t)

	mustWrite(t, filepath.Join(upper, "etc", "edit"), "checkpointed")
	mkWhiteout(t, filepath.Join(upper, "etc", "gone"))
	if err := os.Symlink("edit", filepath.Join(upper, "etc", "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	cp, err := s.CheckpointCopy(ctx, "ctr", "v1")
	if err != nil {
		t.Fatalf("CheckpointCopy: %v", err)
	}
	if cp.Name != "v1" || cp.ContainerID != "ctr" || cp.Created.IsZero() {
		t.Fatalf("Checkpoint = %+v", cp)
	}
	if cp.Parent != diffA {
		t.Fatalf("checkpoint Parent = %q, want the container's chain ID %q", cp.Parent, diffA)
	}
	if cp.Size == 0 {
		t.Fatal("checkpoint Size was not recorded")
	}

	list, err := s.ListCheckpoints("ctr")
	if err != nil {
		t.Fatalf("ListCheckpoints: %v", err)
	}
	if len(list) != 1 || list[0].Name != "v1" {
		t.Fatalf("ListCheckpoints = %+v", list)
	}
	if _, err := s.CheckpointCopy(ctx, "ctr", "v1"); !errors.Is(err, ErrExists) {
		t.Fatalf("a second checkpoint under the same name = %v, want ErrExists", err)
	}

	// Move on: change the file, delete the whiteout, add something new.
	mustWrite(t, filepath.Join(upper, "etc", "edit"), "later")
	if err := os.Remove(filepath.Join(upper, "etc", "gone")); err != nil {
		t.Fatalf("remove whiteout: %v", err)
	}
	mustWrite(t, filepath.Join(upper, "etc", "after"), "after")

	if err := s.Restore(ctx, "ctr", "v1"); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(upper, "etc", "edit"))
	if err != nil || string(got) != "checkpointed" {
		t.Fatalf("after Restore etc/edit = %q, %v; want %q", got, err, "checkpointed")
	}
	if _, err := os.Lstat(filepath.Join(upper, "etc", "after")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Restore kept a file written after the checkpoint: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(upper, "etc", "gone"), &st); err != nil {
		t.Fatalf("Restore lost the whiteout: %v", err)
	}
	if !isWhiteout(&st) {
		t.Fatalf("restored etc/gone is mode %#o rdev %d, want a character device 0:0", st.Mode, st.Rdev)
	}
	target, err := os.Readlink(filepath.Join(upper, "etc", "link"))
	if err != nil || target != "edit" {
		t.Fatalf("Restore lost the symlink: %q, %v", target, err)
	}
	// The workdir is reset, because its leftovers belonged to the old upperdir.
	work, _ := s.ContainerDir("ctr")
	if fi, err := os.Stat(filepath.Join(work, DirWork)); err != nil || !fi.IsDir() {
		t.Fatalf("Restore did not recreate the workdir: %v", err)
	}
	// Nothing is left lying around next to the upperdir.
	entries, err := os.ReadDir(work)
	if err != nil {
		t.Fatalf("read the container directory: %v", err)
	}
	for _, e := range entries {
		if e.Name() != DirUpper && e.Name() != DirWork && e.Name() != DirMerged {
			t.Fatalf("Restore left %q behind in the container directory", e.Name())
		}
	}
}

func TestCheckpointSharesInodesWhenItCan(t *testing.T) {
	ctx := context.Background()
	s, upper, _ := imageWithUpper(t)
	mustWrite(t, filepath.Join(upper, "etc", "big"), "contents")

	if _, err := s.Checkpoint(ctx, "ctr", "cheap"); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	cpUpper, err := s.checkpointUpper("ctr", "cheap")
	if err != nil {
		t.Fatalf("checkpointUpper: %v", err)
	}
	var live, copied unix.Stat_t
	if err := unix.Lstat(filepath.Join(upper, "etc", "big"), &live); err != nil {
		t.Fatalf("lstat live: %v", err)
	}
	if err := unix.Lstat(filepath.Join(cpUpper, "etc", "big"), &copied); err != nil {
		t.Fatalf("lstat checkpoint: %v", err)
	}
	if live.Size != copied.Size {
		t.Fatalf("checkpoint size %d, live size %d", copied.Size, live.Size)
	}
	// A reflink gives distinct inodes, a hardlink shares one; either is a pass,
	// a byte copy on a filesystem that could have done better is not the point
	// of the test, so only the contents are asserted here.
	got, err := os.ReadFile(filepath.Join(cpUpper, "etc", "big"))
	if err != nil || string(got) != "contents" {
		t.Fatalf("checkpointed contents = %q, %v", got, err)
	}
}

func TestDeleteCheckpoint(t *testing.T) {
	ctx := context.Background()
	s, upper, _ := imageWithUpper(t)
	mustWrite(t, filepath.Join(upper, "f"), "f")

	if _, err := s.Checkpoint(ctx, "ctr", "gone"); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if _, err := s.StatCheckpoint("ctr", "gone"); err != nil {
		t.Fatalf("StatCheckpoint: %v", err)
	}
	if err := s.DeleteCheckpoint(ctx, "ctr", "gone"); err != nil {
		t.Fatalf("DeleteCheckpoint: %v", err)
	}
	if err := s.DeleteCheckpoint(ctx, "ctr", "gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting it twice = %v, want ErrNotFound", err)
	}
	list, err := s.ListCheckpoints("ctr")
	if err != nil {
		t.Fatalf("ListCheckpoints: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("ListCheckpoints = %+v, want none", list)
	}
}

func TestCheckpointRejectsBadNames(t *testing.T) {
	ctx := context.Background()
	s, upper, _ := imageWithUpper(t)
	mustWrite(t, filepath.Join(upper, "f"), "f")
	for _, name := range []string{"", "..", "a/b", "../escape"} {
		if _, err := s.Checkpoint(ctx, "ctr", name); err == nil {
			t.Fatalf("Checkpoint with the name %q was accepted", name)
		}
	}
}

func TestRestoreRejectsAMissingCheckpoint(t *testing.T) {
	ctx := context.Background()
	s, _, _ := imageWithUpper(t)
	if err := s.Restore(ctx, "ctr", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Restore of a missing checkpoint = %v, want ErrNotFound", err)
	}
}

func TestRestoreRefusesWhileMounted(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ctx := context.Background()
	s, upper, _ := imageWithUpper(t)
	mustWrite(t, filepath.Join(upper, "f"), "f")
	if _, err := s.Checkpoint(ctx, "ctr", "v1"); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}

	merged, _ := s.MergedPath("ctr")
	if err := os.MkdirAll(merged, 0o755); err != nil {
		t.Fatalf("mkdir merged: %v", err)
	}
	// A plain bind mount is enough to make merged a mountpoint.
	if err := unix.Mount(upper, merged, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("cannot bind mount here: %v", err)
	}
	defer func() { _ = unix.Unmount(merged, unix.MNT_DETACH) }()

	if err := s.Restore(ctx, "ctr", "v1"); !errors.Is(err, ErrMounted) {
		t.Fatalf("Restore while mounted = %v, want ErrMounted", err)
	}
}

func TestDiffCheckpoints(t *testing.T) {
	ctx := context.Background()
	s, upper, _ := imageWithUpper(t)

	mustWrite(t, filepath.Join(upper, "etc", "edit"), "first")
	mustWrite(t, filepath.Join(upper, "etc", "dropped"), "dropped")
	if _, err := s.CheckpointCopy(ctx, "ctr", "one"); err != nil {
		t.Fatalf("CheckpointCopy one: %v", err)
	}

	mustWrite(t, filepath.Join(upper, "etc", "edit"), "second-and-longer")
	if err := os.Remove(filepath.Join(upper, "etc", "dropped")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	mustWrite(t, filepath.Join(upper, "etc", "fresh"), "fresh")
	mkWhiteout(t, filepath.Join(upper, "etc", "gone"))
	if _, err := s.CheckpointCopy(ctx, "ctr", "two"); err != nil {
		t.Fatalf("CheckpointCopy two: %v", err)
	}

	got, err := s.DiffCheckpoints(ctx, "ctr", "one", "two")
	if err != nil {
		t.Fatalf("DiffCheckpoints: %v", err)
	}
	kinds := map[string]ChangeKind{}
	for _, c := range got {
		kinds[c.Path] = c.Kind
	}
	want := map[string]ChangeKind{
		"/etc/edit":    KindModified,
		"/etc/dropped": KindDeleted,
		"/etc/fresh":   KindAdded,
		"/etc/gone":    KindDeleted,
	}
	for p, w := range want {
		if kinds[p] != w {
			t.Fatalf("%s is %q, want %q (full diff %+v)", p, kinds[p], w, got)
		}
	}
	if _, unchanged := kinds["/etc"]; unchanged {
		t.Fatalf("the unchanged directory /etc was reported: %+v", got)
	}

	// Reversing the comparison turns additions into deletions.
	back, err := s.DiffCheckpoints(ctx, "ctr", "two", "one")
	if err != nil {
		t.Fatalf("DiffCheckpoints reversed: %v", err)
	}
	rev := map[string]ChangeKind{}
	for _, c := range back {
		rev[c.Path] = c.Kind
	}
	if rev["/etc/fresh"] != KindDeleted {
		t.Fatalf("reversed /etc/fresh = %q, want deleted", rev["/etc/fresh"])
	}
	if rev["/etc/dropped"] != KindAdded {
		t.Fatalf("reversed /etc/dropped = %q, want added", rev["/etc/dropped"])
	}
	if rev["/etc/gone"] != KindAdded {
		t.Fatalf("reversed /etc/gone = %q, want added: a whiteout that is not in the other side means the file is back",
			rev["/etc/gone"])
	}
}

func TestDiffCheckpointsRejectsMissingNames(t *testing.T) {
	ctx := context.Background()
	s, upper, _ := imageWithUpper(t)
	mustWrite(t, filepath.Join(upper, "f"), "f")
	if _, err := s.CheckpointCopy(ctx, "ctr", "one"); err != nil {
		t.Fatalf("CheckpointCopy: %v", err)
	}
	if _, err := s.DiffCheckpoints(ctx, "ctr", "one", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DiffCheckpoints with a missing side = %v, want ErrNotFound", err)
	}
}

func TestCopyTreePreservesDirectoryModes(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	src := filepath.Join(shortTempRoot(t), "src")
	if err := os.MkdirAll(filepath.Join(src, "a", "b"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(filepath.Join(src, "a"), 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	mustWrite(t, filepath.Join(src, "a", "b", "f"), "body")
	if err := os.Chmod(filepath.Join(src, "a", "b", "f"), 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	dst := filepath.Join(shortTempRoot(t), "dst")
	size, err := s.copyTree(ctx, src, dst, false)
	if err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	if size != int64(len("body")) {
		t.Fatalf("copyTree reported %d bytes, want %d", size, len("body"))
	}
	fi, err := os.Stat(filepath.Join(dst, "a"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %#o, want 0700", fi.Mode().Perm())
	}
	fi, err = os.Stat(filepath.Join(dst, "a", "b", "f"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %#o, want 0600", fi.Mode().Perm())
	}
	got, err := os.ReadFile(filepath.Join(dst, "a", "b", "f"))
	if err != nil || string(got) != "body" {
		t.Fatalf("contents = %q, %v", got, err)
	}
}

// TestCopyTreePreservesTimestamps matters twice over: a checkpoint that loses
// mtimes is not a faithful copy of the container's filesystem, and
// DiffCheckpoints uses mtime to decide whether a file was modified.
func TestCopyTreePreservesTimestamps(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	src := filepath.Join(shortTempRoot(t), "src")
	if err := os.MkdirAll(filepath.Join(src, "d"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	mustWrite(t, filepath.Join(src, "d", "f"), "body")
	if err := os.Symlink("f", filepath.Join(src, "d", "l")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	stamp := []unix.Timespec{{Sec: 1500000000, Nsec: 123456789}, {Sec: 1500000001, Nsec: 987654321}}
	for _, rel := range []string{"d/f", "d/l", "d"} {
		if err := unix.UtimesNanoAt(unix.AT_FDCWD, filepath.Join(src, rel), stamp, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Fatalf("set times on %s: %v", rel, err)
		}
	}

	dst := filepath.Join(shortTempRoot(t), "dst")
	if _, err := s.copyTree(ctx, src, dst, false); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	for _, rel := range []string{"d/f", "d/l", "d"} {
		var st unix.Stat_t
		if err := unix.Lstat(filepath.Join(dst, rel), &st); err != nil {
			t.Fatalf("lstat %s: %v", rel, err)
		}
		if st.Mtim.Sec != stamp[1].Sec || st.Mtim.Nsec != stamp[1].Nsec {
			t.Fatalf("%s mtime = %d.%09d, want %d.%09d", rel, st.Mtim.Sec, st.Mtim.Nsec, stamp[1].Sec, stamp[1].Nsec)
		}
	}
}

func TestCopyTreeKeepsHardlinksLinked(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	src := filepath.Join(shortTempRoot(t), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	mustWrite(t, filepath.Join(src, "one"), "shared")
	if err := os.Link(filepath.Join(src, "one"), filepath.Join(src, "two")); err != nil {
		t.Fatalf("link: %v", err)
	}
	dst := filepath.Join(shortTempRoot(t), "dst")
	if _, err := s.copyTree(ctx, src, dst, false); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	var a, b unix.Stat_t
	if err := unix.Lstat(filepath.Join(dst, "one"), &a); err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if err := unix.Lstat(filepath.Join(dst, "two"), &b); err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if a.Ino != b.Ino {
		t.Fatalf("copyTree broke a hardlink: inodes %d and %d", a.Ino, b.Ino)
	}
}

func TestLookupLowerStopsAtAWhiteout(t *testing.T) {
	top := filepath.Join(shortTempRoot(t), "top")
	bottom := filepath.Join(shortTempRoot(t), "bottom")
	for _, d := range []string{top, bottom} {
		if err := os.MkdirAll(filepath.Join(d, "etc"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	mustWrite(t, filepath.Join(bottom, "etc", "hidden"), "x")
	mustWrite(t, filepath.Join(bottom, "etc", "plain"), "x")
	mkWhiteout(t, filepath.Join(top, "etc", "hidden"))

	lowers := []string{top, bottom}
	for _, tc := range []struct {
		rel  string
		want bool
	}{
		{rel: "etc/plain", want: true},
		{rel: "etc/hidden", want: false},
		{rel: "etc/absent", want: false},
		{rel: "etc", want: true},
	} {
		got, err := lookupLower(lowers, tc.rel)
		if err != nil {
			t.Fatalf("lookupLower(%q): %v", tc.rel, err)
		}
		if got != tc.want {
			t.Fatalf("lookupLower(%q) = %v, want %v", tc.rel, got, tc.want)
		}
	}
}

func TestListCheckpointsOfAnUnknownContainerIsEmpty(t *testing.T) {
	s := newTestSnapshotter(t)
	list, err := s.ListCheckpoints("nobody")
	if err != nil {
		t.Fatalf("ListCheckpoints: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("ListCheckpoints = %+v, want none", list)
	}
	if _, err := s.StatCheckpoint("nobody", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("StatCheckpoint = %v, want ErrNotFound", err)
	}

}
