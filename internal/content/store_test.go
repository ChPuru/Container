package content

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestStore returns a Store rooted in a fresh temp directory.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "content"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

// mustWrite commits payload and returns its digest.
func mustWrite(t *testing.T, s *Store, payload []byte) string {
	t.Helper()
	info, err := s.WriteBlob(context.Background(), bytes.NewReader(payload), DigestBytes(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("WriteBlob: %v", err)
	}
	return info.Digest
}

func TestNewStoreCreatesLayout(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "nested", "content")
	s, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.Root() != root {
		t.Fatalf("Root() = %q, want %q", s.Root(), root)
	}
	for _, dir := range []string{s.BlobRoot(), s.IngestRoot()} {
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %q: %v", dir, err)
		}
		if !fi.IsDir() {
			t.Fatalf("%q is not a directory", dir)
		}
		if perm := fi.Mode().Perm(); perm != dirPerm {
			t.Fatalf("%q mode = %o, want %o", dir, perm, dirPerm)
		}
	}
	if want := filepath.Join(root, "blobs", "sha256"); s.BlobRoot() != want {
		t.Fatalf("BlobRoot() = %q, want %q", s.BlobRoot(), want)
	}
	// Re-opening an existing store must succeed.
	if _, err := NewStore(root); err != nil {
		t.Fatalf("NewStore (reopen): %v", err)
	}
	if _, err := NewStore(""); err == nil {
		t.Fatal("NewStore(\"\") = nil error, want an error")
	}
}

func TestWriteCommitAndRead(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	payload := []byte("hull content store happy path")
	want := DigestBytes(payload)

	w, err := s.Writer(context.Background(), want, int64(len(payload)))
	if err != nil {
		t.Fatalf("Writer: %v", err)
	}
	defer w.Close()

	n, err := w.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	if got := w.Size(); got != int64(len(payload)) {
		t.Fatalf("Writer.Size = %d, want %d", got, len(payload))
	}
	if got := w.Digest(); got != want {
		t.Fatalf("Writer.Digest = %s, want %s", got, want)
	}

	info, err := w.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if info.Digest != want || info.Size != int64(len(payload)) {
		t.Fatalf("Commit info = %+v, want digest %s size %d", info, want, len(payload))
	}
	if info.CreatedAt.IsZero() {
		t.Fatal("Commit info.CreatedAt is zero")
	}

	if !s.Exists(want) {
		t.Fatalf("Exists(%s) = false after commit", want)
	}
	p, err := s.Path(want)
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat blob: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != blobPerm {
		t.Fatalf("blob mode = %o, want %o", perm, blobPerm)
	}
	if got, err := s.ReadAll(want); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("ReadAll = (%q, %v), want (%q, nil)", got, err, payload)
	}

	f, err := s.Open(want)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("Open+ReadAll = (%q, %v)", got, err)
	}

	// The ingest directory must be empty again.
	entries, err := os.ReadDir(s.IngestRoot())
	if err != nil {
		t.Fatalf("ReadDir ingest: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("ingest has %d leftover entries, want 0", len(entries))
	}

	// Commit is not repeatable.
	if _, err := w.Commit(); !errors.Is(err, ErrCommitted) {
		t.Fatalf("second Commit = %v, want ErrCommitted", err)
	}
	// Close after a successful Commit must not remove the blob.
	if err := w.Close(); err != nil {
		t.Fatalf("Close after Commit: %v", err)
	}
	if !s.Exists(want) {
		t.Fatal("blob disappeared after Close")
	}
}

func TestWriteBlobUnknownDigestAndSize(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	payload := []byte("digest not known ahead of time")

	info, err := s.WriteBlob(context.Background(), bytes.NewReader(payload), "", SizeUnknown)
	if err != nil {
		t.Fatalf("WriteBlob: %v", err)
	}
	if info.Digest != DigestBytes(payload) {
		t.Fatalf("Digest = %s, want %s", info.Digest, DigestBytes(payload))
	}
	if info.Size != int64(len(payload)) {
		t.Fatalf("Size = %d, want %d", info.Size, len(payload))
	}
}

func TestCommitMismatches(t *testing.T) {
	t.Parallel()
	payload := []byte("the bytes that are actually written")
	other := []byte("completely different bytes")

	tests := []struct {
		name         string
		expected     string
		expectedSize int64
		body         []byte
		wantSentinel error
		wantWriteErr bool
	}{
		{
			name:         "digest mismatch",
			expected:     DigestBytes(other),
			expectedSize: SizeUnknown,
			body:         payload,
			wantSentinel: ErrDigestMismatch,
		},
		{
			name:         "size too small",
			expected:     DigestBytes(payload),
			expectedSize: int64(len(payload)) + 8,
			body:         payload,
			wantSentinel: ErrSizeMismatch,
		},
		{
			name:         "size too large is refused at write time",
			expected:     "",
			expectedSize: 4,
			body:         payload,
			wantSentinel: ErrSizeMismatch,
			wantWriteErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newTestStore(t)
			w, err := s.Writer(context.Background(), tc.expected, tc.expectedSize)
			if err != nil {
				t.Fatalf("Writer: %v", err)
			}
			defer w.Close()

			_, werr := w.Write(tc.body)
			if tc.wantWriteErr {
				if !errors.Is(werr, tc.wantSentinel) {
					t.Fatalf("Write = %v, want %v", werr, tc.wantSentinel)
				}
			} else {
				if werr != nil {
					t.Fatalf("Write: %v", werr)
				}
				_, cerr := w.Commit()
				if !errors.Is(cerr, tc.wantSentinel) {
					t.Fatalf("Commit = %v, want %v", cerr, tc.wantSentinel)
				}
				if errors.Is(cerr, ErrDigestMismatch) {
					var dm *DigestMismatchError
					if !errors.As(cerr, &dm) {
						t.Fatalf("Commit error %v is not a *DigestMismatchError", cerr)
					}
					if dm.Expected != tc.expected || dm.Actual != DigestBytes(tc.body) {
						t.Fatalf("DigestMismatchError = %+v", dm)
					}
				}
				if errors.Is(cerr, ErrSizeMismatch) && !errors.Is(cerr, ErrDigestMismatch) {
					var sm *SizeMismatchError
					if !errors.As(cerr, &sm) {
						t.Fatalf("Commit error %v is not a *SizeMismatchError", cerr)
					}
					if sm.Expected != tc.expectedSize || sm.Actual != int64(len(tc.body)) {
						t.Fatalf("SizeMismatchError = %+v", sm)
					}
				}
			}

			// Release the writer explicitly: an aborted write must leave
			// nothing behind once the caller is done with it.
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			// Nothing may be committed and no ingest may survive.
			if n := countDir(t, s.BlobRoot()); n != 0 {
				t.Fatalf("%d blobs committed after a failed write, want 0", n)
			}
			if n := countDir(t, s.IngestRoot()); n != 0 {
				t.Fatalf("%d ingest files left behind, want 0", n)
			}
		})
	}
}

func TestCloseWithoutCommitAborts(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	payload := []byte("abandoned pull")

	w, err := s.Writer(context.Background(), DigestBytes(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("Writer: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n := countDir(t, s.IngestRoot()); n != 1 {
		t.Fatalf("ingest has %d entries mid-write, want 1", n)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if n := countDir(t, s.IngestRoot()); n != 0 {
		t.Fatalf("ingest has %d entries after abort, want 0", n)
	}
	if s.Exists(DigestBytes(payload)) {
		t.Fatal("blob was committed despite Close without Commit")
	}
	if _, err := w.Write(payload); !errors.Is(err, ErrClosed) {
		t.Fatalf("Write after Close = %v, want ErrClosed", err)
	}
	if _, err := w.Commit(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Commit after Close = %v, want ErrClosed", err)
	}
}

func TestConcurrentWritersSameDigest(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	payload := bytes.Repeat([]byte("racy layer bytes "), 512)
	want := DigestBytes(payload)

	const writers = 8
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		infos []Info
		errs  []error
		start = make(chan struct{})
	)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			info, err := s.WriteBlob(context.Background(), bytes.NewReader(payload), want, int64(len(payload)))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			infos = append(infos, info)
		}()
	}
	close(start)
	wg.Wait()

	if len(errs) != 0 {
		t.Fatalf("concurrent commits failed: %v", errs)
	}
	if len(infos) != writers {
		t.Fatalf("got %d infos, want %d", len(infos), writers)
	}
	for _, info := range infos {
		if info.Digest != want || info.Size != int64(len(payload)) {
			t.Fatalf("info = %+v, want digest %s size %d", info, want, len(payload))
		}
	}
	if n := countDir(t, s.BlobRoot()); n != 1 {
		t.Fatalf("blob directory holds %d files, want 1", n)
	}
	if n := countDir(t, s.IngestRoot()); n != 0 {
		t.Fatalf("ingest holds %d files, want 0", n)
	}
	got, err := s.ReadAll(want)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("ReadAll after concurrent commits: len=%d err=%v", len(got), err)
	}
	total, err := s.Size()
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if total != int64(len(payload)) {
		t.Fatalf("Store.Size = %d, want %d", total, len(payload))
	}
}

func TestMissingBlobErrors(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	missing := DigestBytes([]byte("never written"))
	bad := "sha256:not-a-digest"

	if s.Exists(missing) {
		t.Fatal("Exists reported a missing blob as present")
	}
	if s.Exists(bad) {
		t.Fatal("Exists reported an invalid digest as present")
	}
	if _, err := s.Stat(missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat = %v, want ErrNotFound", err)
	}
	if _, err := s.Open(missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open = %v, want ErrNotFound", err)
	}
	if _, err := s.ReadAll(missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadAll = %v, want ErrNotFound", err)
	}
	if err := s.Delete(missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete = %v, want ErrNotFound", err)
	}
	for _, fn := range []func() error{
		func() error { _, err := s.Path(bad); return err },
		func() error { _, err := s.Stat(bad); return err },
		func() error { _, err := s.Open(bad); return err },
		func() error { _, err := s.ReadAll(bad); return err },
		func() error { return s.Delete(bad) },
		func() error { _, err := s.Writer(context.Background(), bad, SizeUnknown); return err },
	} {
		if err := fn(); !errors.Is(err, ErrInvalidDigest) {
			t.Fatalf("invalid digest accepted: %v", err)
		}
	}
}

func TestReadAllGuardsMemory(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	payload := bytes.Repeat([]byte("x"), 1024)
	dgst := mustWrite(t, s, payload)

	s.MaxInlineRead = 128
	if _, err := s.ReadAll(dgst); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadAll = %v, want ErrTooLarge", err)
	}
	s.MaxInlineRead = 1024
	if got, err := s.ReadAll(dgst); err != nil || len(got) != 1024 {
		t.Fatalf("ReadAll = (%d bytes, %v), want (1024, nil)", len(got), err)
	}
	if DefaultMaxInlineRead <= 0 {
		t.Fatal("DefaultMaxInlineRead must be positive")
	}
	s.MaxInlineRead = 0 // falls back to DefaultMaxInlineRead
	if got, err := s.ReadAll(dgst); err != nil || len(got) != 1024 {
		t.Fatalf("ReadAll with zero limit = (%d bytes, %v), want the default limit to apply", len(got), err)
	}
}

func TestEmptyBlobRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	info, err := s.WriteBlob(context.Background(), strings.NewReader(""), DigestBytes(nil), 0)
	if err != nil {
		t.Fatalf("WriteBlob(empty): %v", err)
	}
	if info.Size != 0 {
		t.Fatalf("empty blob size = %d, want 0", info.Size)
	}
	got, err := s.ReadAll(info.Digest)
	if err != nil || len(got) != 0 {
		t.Fatalf("ReadAll(empty) = (%q, %v)", got, err)
	}
}

func TestWalkSizeAndDelete(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	payloads := [][]byte{[]byte("one"), []byte("two-two"), []byte("three-three-three")}
	want := map[string]int64{}
	var wantTotal int64
	for _, p := range payloads {
		want[mustWrite(t, s, p)] = int64(len(p))
		wantTotal += int64(len(p))
	}

	// Stray files must not be mistaken for blobs.
	if err := os.WriteFile(filepath.Join(s.BlobRoot(), "not-a-digest"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("writing stray file: %v", err)
	}

	seen := map[string]int64{}
	if err := s.Walk(func(i Info) error {
		seen[i.Digest] = i.Size
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(seen) != len(want) {
		t.Fatalf("Walk saw %d blobs, want %d", len(seen), len(want))
	}
	for d, size := range want {
		if seen[d] != size {
			t.Fatalf("Walk size for %s = %d, want %d", d, seen[d], size)
		}
	}

	total, err := s.Size()
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if total != wantTotal {
		t.Fatalf("Size = %d, want %d", total, wantTotal)
	}

	// Walk propagates the error from fn.
	sentinel := errors.New("stop")
	if err := s.Walk(func(Info) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("Walk error = %v, want %v", err, sentinel)
	}
	// filepath.SkipAll ends the walk quietly.
	calls := 0
	if err := s.Walk(func(Info) error { calls++; return filepath.SkipAll }); err != nil {
		t.Fatalf("Walk with SkipAll: %v", err)
	}
	if calls != 1 {
		t.Fatalf("Walk called fn %d times after SkipAll, want 1", calls)
	}

	for d := range want {
		if err := s.Delete(d); err != nil {
			t.Fatalf("Delete: %v", err)
		}
	}
	if total, err := s.Size(); err != nil || total != 0 {
		t.Fatalf("Size after deleting everything = (%d, %v)", total, err)
	}
}

func TestCleanIngest(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	stale := filepath.Join(s.IngestRoot(), "ingest-stale")
	if err := os.WriteFile(stale, []byte("half a layer"), 0o600); err != nil {
		t.Fatalf("writing stale ingest: %v", err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	fresh := filepath.Join(s.IngestRoot(), "ingest-fresh")
	if err := os.WriteFile(fresh, []byte("in flight"), 0o600); err != nil {
		t.Fatalf("writing fresh ingest: %v", err)
	}

	if err := s.CleanIngest(time.Hour); err != nil {
		t.Fatalf("CleanIngest: %v", err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale ingest survived: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh ingest was removed: %v", err)
	}

	if err := s.CleanIngest(0); err != nil {
		t.Fatalf("CleanIngest(0): %v", err)
	}
	if n := countDir(t, s.IngestRoot()); n != 0 {
		t.Fatalf("ingest has %d entries after a full clean, want 0", n)
	}
}

func TestWriterHonoursContext(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())

	w, err := s.Writer(ctx, "", SizeUnknown)
	if err != nil {
		t.Fatalf("Writer: %v", err)
	}
	defer w.Close()
	if _, err := w.Write([]byte("partial")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	cancel()
	if _, err := w.Write([]byte("more")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Write after cancel = %v, want context.Canceled", err)
	}
	if _, err := w.Commit(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Commit after cancel = %v, want context.Canceled", err)
	}
	if n := countDir(t, s.IngestRoot()); n != 0 {
		t.Fatalf("ingest has %d entries after a cancelled write, want 0", n)
	}
	if _, err := s.Writer(ctx, "", SizeUnknown); !errors.Is(err, context.Canceled) {
		t.Fatalf("Writer with a cancelled context = %v, want context.Canceled", err)
	}
}

// countDir returns the number of entries in dir.
func countDir(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir %q: %v", dir, err)
	}
	return len(entries)
}
