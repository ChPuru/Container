//go:build linux

package snapshot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/content"
	"github.com/ChPuru/hull/internal/layer"
	"github.com/ChPuru/hull/internal/types"
)

// testFeatures pretends overlayfs is usable so the non-mount tests do not need
// the privileges a real probe mount takes. Mount itself is exercised in
// mount_linux_test.go, which probes for real and skips without root.
func testFeatures() Features {
	return Features{Supported: true, MountTested: true, MountOK: true}
}

// shortTempRoot returns a temporary directory with a short name.
//
// t.TempDir() names its directory after the test, which can run to eighty
// characters; hull's real root is /var/lib/hull. Since the length of the root
// is exactly what the one-page mount option budget is spent on, a test root has
// to be realistically short or it measures the test's own name.
func shortTempRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hull")
	if err != nil {
		t.Fatalf("create a temporary root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// newTestSnapshotter returns a snapshotter on a fresh temporary root.
func newTestSnapshotter(t *testing.T) *Snapshotter {
	t.Helper()
	s, err := New(shortTempRoot(t), testFeatures())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// tarEntry describes one entry to put in a synthetic layer tar.
type tarEntry struct {
	name string
	typ  byte
	mode int64
	body string
	link string
}

// buildLayer renders entries as a gzip-compressed layer blob and returns the
// blob, the DiffID of the uncompressed tar and the uncompressed size, which is
// exactly the triple a manifest plus an image config carries.
func buildLayer(t *testing.T, entries []tarEntry) (blob []byte, diffID string, size int64) {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			if typ == tar.TypeDir {
				mode = 0o755
			} else {
				mode = 0o644
			}
		}
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: typ,
			Mode:     mode,
			Size:     int64(len(e.body)),
			Linkname: e.link,
			ModTime:  time.Unix(1700000000, 0),
			Format:   tar.FormatPAX,
		}
		if typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %q: %v", e.name, err)
		}
		if typ == tar.TypeReg && e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write tar body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	sum := sha256.Sum256(raw.Bytes())

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		t.Fatalf("gzip layer: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return gz.Bytes(), "sha256:" + hex.EncodeToString(sum[:]), int64(raw.Len())
}

// putBlob stores a blob and returns its descriptor.
func putBlob(t *testing.T, store *content.Store, blob []byte) types.Descriptor {
	t.Helper()
	info, err := store.WriteBlob(context.Background(), bytes.NewReader(blob), "", int64(len(blob)))
	if err != nil {
		t.Fatalf("WriteBlob: %v", err)
	}
	return types.Descriptor{
		MediaType: layer.MediaTypeTarGzip,
		Digest:    info.Digest,
		Size:      info.Size,
	}
}

// commitChain creates n empty, committed snapshots stacked on each other and
// returns their chain IDs, base first.
func commitChain(t *testing.T, s *Snapshotter, n int) []string {
	t.Helper()
	ctx := context.Background()
	chains := make([]string, 0, n)
	parent := ""
	for i := 0; i < n; i++ {
		diff := fmt.Sprintf("sha256:%064x", i+1)
		chain, err := ChainID(parent, diff)
		if err != nil {
			t.Fatalf("ChainID: %v", err)
		}
		if _, err := s.Prepare(ctx, chain, parent); err != nil {
			t.Fatalf("Prepare layer %d: %v", i, err)
		}
		if err := s.Commit(ctx, chain, diff, int64(i)); err != nil {
			t.Fatalf("Commit layer %d: %v", i, err)
		}
		chains = append(chains, chain)
		parent = chain
	}
	return chains
}

func TestPrepareCommitExistsLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)

	if s.Exists(diffA) {
		t.Fatal("a snapshot that was never prepared must not exist")
	}
	fsDir, err := s.Prepare(ctx, diffA, "")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	wantDir := filepath.Join(s.Root(), DirSnapshots, strings.TrimPrefix(diffA, "sha256:"), DirFS)
	if fsDir != wantDir {
		t.Fatalf("Prepare returned %q, want %q", fsDir, wantDir)
	}
	if fi, serr := os.Stat(fsDir); serr != nil || !fi.IsDir() {
		t.Fatalf("Prepare did not create %q: %v", fsDir, serr)
	}
	if s.Exists(diffA) {
		t.Fatal("a prepared but uncommitted snapshot must not report as existing")
	}
	if err := os.WriteFile(filepath.Join(fsDir, "hello"), []byte("hi"), 0o644); err != nil {
		t.Fatalf("write into the prepared snapshot: %v", err)
	}
	if err := s.Commit(ctx, diffA, diffA, 42); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !s.Exists(diffA) {
		t.Fatal("a committed snapshot must exist")
	}

	info, err := s.Stat(diffA)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.ChainID != diffA || info.DiffID != diffA || info.Parent != "" || info.Size != 42 {
		t.Fatalf("Stat = %+v", info)
	}
	if info.Kind != SnapshotKindLayer {
		t.Fatalf("Kind = %q, want %q", info.Kind, SnapshotKindLayer)
	}
	if info.Created.IsZero() {
		t.Fatal("Created was not recorded")
	}

	list, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ChainID != diffA {
		t.Fatalf("List = %+v, want exactly the one snapshot", list)
	}

	// A second Prepare of a committed chain ID is refused rather than silently
	// wiping a layer other snapshots may be stacked on.
	if _, err := s.Prepare(ctx, diffA, ""); !errors.Is(err, ErrExists) {
		t.Fatalf("Prepare of a committed snapshot = %v, want ErrExists", err)
	}
}

func TestPrepareRejectsUncommittedParent(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	chain, err := ChainID(diffA, diffB)
	if err != nil {
		t.Fatalf("ChainID: %v", err)
	}
	if _, err := s.Prepare(ctx, chain, diffA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Prepare with a missing parent = %v, want ErrNotFound", err)
	}
}

// TestPartialSnapshotIsDetectedAndReExtracted covers the crash case the
// .complete marker exists for: a snapshot directory with contents but no
// marker is a lie, and must be thrown away rather than used as a lower layer.
func TestPartialSnapshotIsDetectedAndReExtracted(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)

	fsDir, err := s.Prepare(ctx, diffA, "")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fsDir, "half-written"), []byte("junk"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Simulate the daemon dying here: the lock and the in-process state go away
	// with the process, but the partial directory stays behind.
	if err := s.releasePrep(diffA, nil); err != nil {
		t.Fatalf("release: %v", err)
	}

	if s.Exists(diffA) {
		t.Fatal("a snapshot without .complete must not report as existing")
	}
	again, err := s.Prepare(ctx, diffA, "")
	if err != nil {
		t.Fatalf("second Prepare: %v", err)
	}
	if again != fsDir {
		t.Fatalf("second Prepare returned %q, want %q", again, fsDir)
	}
	entries, err := os.ReadDir(again)
	if err != nil {
		t.Fatalf("read the re-prepared snapshot: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("the re-prepared snapshot still holds %d entries, want an empty directory", len(entries))
	}
	if err := s.Abort(ctx, diffA); err != nil {
		t.Fatalf("Abort: %v", err)
	}
}

func TestAbortDiscardsThePartialSnapshot(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	fsDir, err := s.Prepare(ctx, diffA, "")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fsDir, "x"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.Abort(ctx, diffA); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if _, err := os.Stat(fsDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Abort left %q behind: %v", fsDir, err)
	}
	// Abort after a successful Commit is a no-op, so a deferred Abort is safe.
	if _, err := s.Prepare(ctx, diffA, ""); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := s.Commit(ctx, diffA, diffA, 1); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s.Abort(ctx, diffA); err != nil {
		t.Fatalf("Abort after Commit: %v", err)
	}
	if !s.Exists(diffA) {
		t.Fatal("Abort after Commit destroyed the committed snapshot")
	}
}

// TestPrepareSerialisesConcurrentPulls is the race two `docker pull`s of
// different images that share a base layer would otherwise hit.
func TestPrepareSerialisesConcurrentPulls(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)

	first, err := s.Prepare(ctx, diffA, "")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	var wg sync.WaitGroup
	var secondErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, secondErr = s.Prepare(ctx, diffA, "")
	}()

	// Give the second goroutine time to block, then finish the first pull.
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(first, "base"), []byte("base"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.Commit(ctx, diffA, diffA, 4); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	wg.Wait()

	if !errors.Is(secondErr, ErrExists) {
		t.Fatalf("the second Prepare returned %v, want ErrExists once the first committed", secondErr)
	}
	if _, err := os.Stat(filepath.Join(first, "base")); err != nil {
		t.Fatalf("the second Prepare clobbered the committed layer: %v", err)
	}
}

func TestPrepareIsCancellable(t *testing.T) {
	s := newTestSnapshotter(t)
	if _, err := s.Prepare(context.Background(), diffA, ""); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := s.Prepare(ctx, diffA, ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a contended Prepare with a deadline returned %v, want DeadlineExceeded", err)
	}
}

// ---------- unpack ----------

func TestUnpackTwoLayersWithAWhiteout(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	store, err := content.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	blob1, diff1, _ := buildLayer(t, []tarEntry{
		{name: "etc/", typ: tar.TypeDir},
		{name: "etc/hello", body: "one"},
		{name: "etc/keep", body: "keep"},
	})
	blob2, diff2, _ := buildLayer(t, []tarEntry{
		{name: "etc/", typ: tar.TypeDir},
		{name: "etc/.wh.hello"},
		{name: "etc/new", body: "two"},
	})
	desc1 := putBlob(t, store, blob1)
	desc2 := putBlob(t, store, blob2)

	img := &types.Image{ID: "sha256:" + strings.Repeat("c", 64), DiffIDs: []string{diff1, diff2}}
	var events []string
	err = s.Unpack(ctx, img, store, []types.Descriptor{desc1, desc2}, func(dgst, status string) {
		events = append(events, status)
	})
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	chain1, _ := ChainID("", diff1)
	chain2, _ := ChainID(chain1, diff2)
	if !s.Exists(chain1) || !s.Exists(chain2) {
		t.Fatalf("Unpack did not commit both layers: %v %v", s.Exists(chain1), s.Exists(chain2))
	}
	if img.ChainID != chain2 {
		t.Fatalf("image ChainID = %q, want %q", img.ChainID, chain2)
	}
	if len(events) != 4 || events[0] != "extracting" || events[1] != "extracted" {
		t.Fatalf("progress events = %v", events)
	}

	fs1, _ := s.FSDir(chain1)
	if got, rerr := os.ReadFile(filepath.Join(fs1, "etc", "hello")); rerr != nil || string(got) != "one" {
		t.Fatalf("layer 1 etc/hello = %q, %v", got, rerr)
	}

	// The second layer holds only its own files, containerd-style: no copy of
	// etc/keep, and the deletion of etc/hello expressed as an overlay whiteout.
	fs2, _ := s.FSDir(chain2)
	if _, serr := os.Lstat(filepath.Join(fs2, "etc", "keep")); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("layer 2 should not hold the parent's etc/keep: %v", serr)
	}
	if got, rerr := os.ReadFile(filepath.Join(fs2, "etc", "new")); rerr != nil || string(got) != "two" {
		t.Fatalf("layer 2 etc/new = %q, %v", got, rerr)
	}
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(fs2, "etc", "hello"), &st); err != nil {
		t.Fatalf("layer 2 has no whiteout for etc/hello: %v", err)
	}
	if !isWhiteout(&st) {
		t.Fatalf("layer 2 etc/hello is mode %#o rdev %d, want a character device 0:0", st.Mode, st.Rdev)
	}
	// The AUFS marker itself must not survive into the layer directory.
	if _, serr := os.Lstat(filepath.Join(fs2, "etc", ".wh.hello")); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("the .wh. marker leaked into the snapshot: %v", serr)
	}
}

func TestUnpackIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	store, err := content.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	blob, diff, _ := buildLayer(t, []tarEntry{{name: "a", body: "a"}})
	desc := putBlob(t, store, blob)
	img := &types.Image{ID: "sha256:" + strings.Repeat("d", 64), DiffIDs: []string{diff}}

	if err := s.Unpack(ctx, img, store, []types.Descriptor{desc}, nil); err != nil {
		t.Fatalf("first Unpack: %v", err)
	}
	var events []string
	if err := s.Unpack(ctx, img, store, []types.Descriptor{desc}, func(_, status string) {
		events = append(events, status)
	}); err != nil {
		t.Fatalf("second Unpack: %v", err)
	}
	if len(events) != 1 || events[0] != "exists" {
		t.Fatalf("the second Unpack reported %v, want a single \"exists\"", events)
	}
}

func TestUnpackRejectsADiffIDMismatch(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	store, err := content.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	blob, _, _ := buildLayer(t, []tarEntry{{name: "a", body: "a"}})
	desc := putBlob(t, store, blob)

	lie := "sha256:" + strings.Repeat("9", 64)
	img := &types.Image{ID: "sha256:" + strings.Repeat("e", 64), DiffIDs: []string{lie}}
	err = s.Unpack(ctx, img, store, []types.Descriptor{desc}, nil)
	if !errors.Is(err, ErrDiffIDMismatch) {
		t.Fatalf("Unpack with a lying config = %v, want ErrDiffIDMismatch", err)
	}
	if s.Exists(lie) {
		t.Fatal("a layer that failed verification must not be committed")
	}
	fsDir, _ := s.FSDir(lie)
	if _, serr := os.Stat(fsDir); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("Unpack left the partial snapshot %q behind: %v", fsDir, serr)
	}
}

func TestUnpackRejectsAMismatchedLayerCount(t *testing.T) {
	s := newTestSnapshotter(t)
	store, err := content.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	img := &types.Image{ID: "sha256:" + strings.Repeat("f", 64), DiffIDs: []string{diffA, diffB}}
	err = s.Unpack(context.Background(), img, store, []types.Descriptor{{Digest: diffA}}, nil)
	if err == nil || !strings.Contains(err.Error(), "diff ids") && !strings.Contains(err.Error(), "diff IDs") {
		t.Fatalf("Unpack with a length mismatch = %v, want a clear error", err)
	}
}

// ---------- short links ----------

// TestShortLinkAllocatorHandlesSixtyLayers is the whole point of the l/
// directory: a 60-layer image has to mount, and its option string has to fit in
// the single page mount(2) copies.
func TestShortLinkAllocatorHandlesSixtyLayers(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	chains := commitChain(t, s, 60)
	top := chains[len(chains)-1]

	gotChains, dirs, err := s.lowerDirsFor(ctx, top)
	if err != nil {
		t.Fatalf("lowerDirsFor: %v", err)
	}
	if len(dirs) != 60 {
		t.Fatalf("got %d lower dirs, want 60", len(dirs))
	}
	if gotChains[0] != top {
		t.Fatalf("lowerdir order is bottom-up: first entry is %q, want the newest layer %q", gotChains[0], top)
	}
	if gotChains[len(gotChains)-1] != chains[0] {
		t.Fatalf("last lower is %q, want the base layer %q", gotChains[len(gotChains)-1], chains[0])
	}

	seen := make(map[string]string, len(dirs))
	for i, d := range dirs {
		name := filepath.Base(d)
		if len(name) < 2 || len(name) > 3 {
			t.Fatalf("short link %q is %d characters, want 2 or 3", name, len(name))
		}
		if prev, dup := seen[name]; dup {
			t.Fatalf("short link %q is shared by %s and %s", name, prev, gotChains[i])
		}
		seen[name] = gotChains[i]

		target, rerr := os.Readlink(d)
		if rerr != nil {
			t.Fatalf("short link %q is not a symlink: %v", d, rerr)
		}
		want, _ := s.FSDir(gotChains[i])
		resolved := filepath.Join(filepath.Dir(d), target)
		if filepath.Clean(resolved) != want {
			t.Fatalf("short link %q resolves to %q, want %q", d, resolved, want)
		}
		if fi, serr := os.Stat(d); serr != nil || !fi.IsDir() {
			t.Fatalf("short link %q does not lead to a directory: %v", d, serr)
		}
	}

	cdir, _ := s.ContainerDir("c")
	opts, err := buildOverlayOptions(dirs, filepath.Join(cdir, DirUpper), filepath.Join(cdir, DirWork), false)
	if err != nil {
		t.Fatalf("buildOverlayOptions: %v", err)
	}
	if len(opts) >= 4096 {
		t.Fatalf("60 layers need %d bytes of mount options, want under 4096:\n%s", len(opts), opts)
	}
	if !fitsOnePage(opts) {
		t.Fatalf("options do not fit one page: %d bytes", len(opts))
	}
}

func TestShortLinkIsStable(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	commitChain(t, s, 1)
	chain, _ := ChainID("", fmt.Sprintf("sha256:%064x", 1))

	first, err := s.shortLink(ctx, chain)
	if err != nil {
		t.Fatalf("shortLink: %v", err)
	}
	second, err := s.shortLink(ctx, chain)
	if err != nil {
		t.Fatalf("shortLink again: %v", err)
	}
	if first != second {
		t.Fatalf("shortLink is not stable: %q then %q", first, second)
	}
}

// ---------- usage, cleanup and removal ----------

func TestUsage(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	fsDir, err := s.Prepare(ctx, diffA, "")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fsDir, "big"), bytes.Repeat([]byte("x"), 128<<10), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.Commit(ctx, diffA, diffA, 1); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	used, err := s.Usage(diffA)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if used < 128<<10 {
		t.Fatalf("Usage = %d, want at least %d", used, 128<<10)
	}
	if _, err := s.Usage(diffB); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Usage of a missing snapshot = %v, want ErrNotFound", err)
	}
}

func TestCleanupDropsPartialSnapshotsAndStaleLinks(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	chains := commitChain(t, s, 2)

	// A live short link for a real layer must survive.
	live, err := s.shortLink(ctx, chains[0])
	if err != nil {
		t.Fatalf("shortLink: %v", err)
	}

	// A partial snapshot left by a crash.
	partialDir := filepath.Join(s.Root(), DirSnapshots, strings.TrimPrefix(diffC, "sha256:"))
	if err := os.MkdirAll(filepath.Join(partialDir, DirFS), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(partialDir, DirFS, "half"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A short link pointing at a snapshot that no longer exists.
	dangling := filepath.Join(s.Root(), DirLinks, "zz")
	if err := os.Symlink(filepath.Join("..", DirSnapshots, strings.Repeat("0", 64), DirFS), dangling); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := s.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(partialDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Cleanup kept the partial snapshot %q: %v", partialDir, err)
	}
	if _, err := os.Lstat(dangling); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Cleanup kept the dangling link %q: %v", dangling, err)
	}
	if _, err := os.Lstat(live); err != nil {
		t.Fatalf("Cleanup removed the live link %q: %v", live, err)
	}
	for _, c := range chains {
		if !s.Exists(c) {
			t.Fatalf("Cleanup destroyed the committed snapshot %s", c)
		}
	}
}

func TestRemoveSnapshotRefusesWhileReferenced(t *testing.T) {
	ctx := context.Background()
	s := newTestSnapshotter(t)
	chains := commitChain(t, s, 2)

	// The base layer is the parent of the top layer.
	if err := s.RemoveSnapshot(ctx, chains[0]); !errors.Is(err, ErrInUse) {
		t.Fatalf("RemoveSnapshot of a parent = %v, want ErrInUse", err)
	}

	// Pretend a container is mounted on the top layer.
	if err := s.withMounts(ctx, func(mf *mountsFile) error {
		mf.Mounts["ctr"] = &mountRecord{
			ContainerID: "ctr",
			ChainID:     chains[1],
			Lowers:      []string{chains[1], chains[0]},
			Merged:      filepath.Join(s.Root(), DirContainers, "ctr", DirMerged),
			Mounted:     true,
		}
		return nil
	}); err != nil {
		t.Fatalf("record a mount: %v", err)
	}
	if err := s.RemoveSnapshot(ctx, chains[1]); !errors.Is(err, ErrInUse) {
		t.Fatalf("RemoveSnapshot of a mounted layer = %v, want ErrInUse", err)
	}

	list, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, in := range list {
		if in.Refs != 1 {
			t.Fatalf("snapshot %s has Refs = %d, want 1", in.ChainID, in.Refs)
		}
	}

	// Once nothing references it, the top layer goes, link and all.
	if err := s.withMounts(ctx, func(mf *mountsFile) error {
		delete(mf.Mounts, "ctr")
		return nil
	}); err != nil {
		t.Fatalf("drop the mount record: %v", err)
	}
	link, err := s.shortLink(ctx, chains[1])
	if err != nil {
		t.Fatalf("shortLink: %v", err)
	}
	if err := s.RemoveSnapshot(ctx, chains[1]); err != nil {
		t.Fatalf("RemoveSnapshot: %v", err)
	}
	if s.Exists(chains[1]) {
		t.Fatal("the removed snapshot still exists")
	}
	if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("RemoveSnapshot kept the short link %q: %v", link, err)
	}
	if err := s.RemoveSnapshot(ctx, chains[1]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removing it twice = %v, want ErrNotFound", err)
	}
}

func TestChainRejectsAMissingLayer(t *testing.T) {
	s := newTestSnapshotter(t)
	if _, err := s.Chain(diffA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Chain of an unknown layer = %v, want ErrNotFound", err)
	}
}

func TestKernelAtLeast(t *testing.T) {
	tests := []struct {
		release string
		major   int
		minor   int
		want    bool
	}{
		{release: "5.15.167.4-microsoft-standard-WSL2", major: 5, minor: 19, want: false},
		{release: "5.15.167.4-microsoft-standard-WSL2", major: 5, minor: 15, want: true},
		{release: "6.6.87.2-microsoft-standard-WSL2", major: 5, minor: 19, want: true},
		{release: "6.6.87.2-microsoft-standard-WSL2", major: 6, minor: 7, want: false},
		{release: "6.18.0", major: 6, minor: 7, want: true},
		{release: "", major: 5, minor: 15, want: false},
		{release: "garbage", major: 5, minor: 15, want: false},
	}
	for _, tt := range tests {
		if got := kernelAtLeast(tt.release, tt.major, tt.minor); got != tt.want {
			t.Fatalf("kernelAtLeast(%q, %d, %d) = %v, want %v", tt.release, tt.major, tt.minor, got, tt.want)
		}
	}
}

func TestDetectReportsThisHost(t *testing.T) {
	f, err := Detect(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !f.Supported {
		t.Skip("this kernel has no overlayfs")
	}
	if !f.MountTested {
		t.Fatal("Detect claimed overlay support without probing a mount")
	}
	if os.Geteuid() != 0 && !f.MountOK {
		t.Logf("unprivileged probe failed as expected: %s", f.MountError)
		if f.Err() == nil {
			t.Fatal("a failed probe must produce an actionable Features.Err")
		}
		return
	}
	if !f.MountOK {
		t.Fatalf("overlay probe failed as root: %s", f.MountError)
	}
	if err := f.Err(); err != nil {
		t.Fatalf("a successful probe still reports %v", err)
	}
}

func TestWalkTreeDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "d"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "d", "escape")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	var seen []string
	if err := walkTree(context.Background(), root, func(rel string, _ int, _ string, _ *unix.Stat_t) error {
		seen = append(seen, rel)
		return nil
	}); err != nil {
		t.Fatalf("walkTree: %v", err)
	}
	for _, p := range seen {
		if strings.Contains(p, "secret") {
			t.Fatalf("walkTree followed a symlink out of the tree: %v", seen)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("walkTree saw %v, want the directory and the symlink only", seen)
	}
}
