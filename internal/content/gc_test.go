package content

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestGC(t *testing.T) {
	t.Parallel()

	// A tiny image graph: manifest -> {config, layer}. plus two orphans.
	manifest := []byte("manifest")
	config := []byte("config")
	layer := []byte("layer-bytes")
	orphanA := []byte("orphan-a")
	orphanB := []byte("orphan-b-is-longer")

	type fixture struct {
		store *Store
		dg    map[string]string
	}
	setup := func(t *testing.T) fixture {
		t.Helper()
		s := newTestStore(t)
		dg := map[string]string{}
		for name, p := range map[string][]byte{
			"manifest": manifest,
			"config":   config,
			"layer":    layer,
			"orphanA":  orphanA,
			"orphanB":  orphanB,
		} {
			dg[name] = mustWrite(t, s, p)
		}
		return fixture{store: s, dg: dg}
	}

	edges := func(dg map[string]string) func(string) ([]string, error) {
		return func(d string) ([]string, error) {
			if d == dg["manifest"] {
				return []string{dg["config"], dg["layer"]}, nil
			}
			return nil, nil
		}
	}

	t.Run("keeps reachable and deletes the rest", func(t *testing.T) {
		t.Parallel()
		f := setup(t)
		res, err := f.store.GC(context.Background(), []string{f.dg["manifest"]}, edges(f.dg))
		if err != nil {
			t.Fatalf("GC: %v", err)
		}
		if res.Kept != 3 {
			t.Fatalf("Kept = %d, want 3", res.Kept)
		}
		if res.Deleted != 2 {
			t.Fatalf("Deleted = %d, want 2", res.Deleted)
		}
		if want := int64(len(orphanA) + len(orphanB)); res.FreedBytes != want {
			t.Fatalf("FreedBytes = %d, want %d", res.FreedBytes, want)
		}
		for _, name := range []string{"manifest", "config", "layer"} {
			if !f.store.Exists(f.dg[name]) {
				t.Fatalf("%s was deleted but is reachable", name)
			}
		}
		for _, name := range []string{"orphanA", "orphanB"} {
			if f.store.Exists(f.dg[name]) {
				t.Fatalf("%s survived but is unreachable", name)
			}
		}
		// A second pass is a no-op.
		res2, err := f.store.GC(context.Background(), []string{f.dg["manifest"]}, edges(f.dg))
		if err != nil {
			t.Fatalf("second GC: %v", err)
		}
		if res2.Deleted != 0 || res2.Kept != 3 {
			t.Fatalf("second GC = %+v, want 0 deleted / 3 kept", res2)
		}
	})

	t.Run("no roots deletes everything", func(t *testing.T) {
		t.Parallel()
		f := setup(t)
		res, err := f.store.GC(context.Background(), nil, nil)
		if err != nil {
			t.Fatalf("GC: %v", err)
		}
		if res.Deleted != 5 || res.Kept != 0 {
			t.Fatalf("GC = %+v, want 5 deleted / 0 kept", res)
		}
		total, err := f.store.Size()
		if err != nil {
			t.Fatalf("Size: %v", err)
		}
		if total != 0 {
			t.Fatalf("Size after full GC = %d, want 0", total)
		}
	})

	t.Run("nil reachable keeps only the roots", func(t *testing.T) {
		t.Parallel()
		f := setup(t)
		res, err := f.store.GC(context.Background(), []string{f.dg["manifest"], f.dg["layer"]}, nil)
		if err != nil {
			t.Fatalf("GC: %v", err)
		}
		if res.Kept != 2 || res.Deleted != 3 {
			t.Fatalf("GC = %+v, want 2 kept / 3 deleted", res)
		}
	})

	t.Run("invalid root is refused before anything is deleted", func(t *testing.T) {
		t.Parallel()
		f := setup(t)
		_, err := f.store.GC(context.Background(), []string{"sha256:../../etc/passwd"}, nil)
		if !errors.Is(err, ErrInvalidDigest) {
			t.Fatalf("GC = %v, want ErrInvalidDigest", err)
		}
		if n := countDir(t, f.store.BlobRoot()); n != 5 {
			t.Fatalf("%d blobs remain, want all 5 untouched", n)
		}
	})

	t.Run("reachable failure aborts without deleting", func(t *testing.T) {
		t.Parallel()
		f := setup(t)
		boom := errors.New("manifest is not parseable")
		_, err := f.store.GC(context.Background(), []string{f.dg["manifest"]}, func(string) ([]string, error) {
			return nil, boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("GC = %v, want %v", err, boom)
		}
		if n := countDir(t, f.store.BlobRoot()); n != 5 {
			t.Fatalf("%d blobs remain, want all 5 untouched", n)
		}
	})

	t.Run("cancelled context aborts", func(t *testing.T) {
		t.Parallel()
		f := setup(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := f.store.GC(ctx, []string{f.dg["manifest"]}, edges(f.dg)); !errors.Is(err, context.Canceled) {
			t.Fatalf("GC = %v, want context.Canceled", err)
		}
		if n := countDir(t, f.store.BlobRoot()); n != 5 {
			t.Fatalf("%d blobs remain, want all 5 untouched", n)
		}
	})

	t.Run("cycles terminate", func(t *testing.T) {
		t.Parallel()
		f := setup(t)
		cyclic := func(d string) ([]string, error) {
			switch d {
			case f.dg["manifest"]:
				return []string{f.dg["config"]}, nil
			case f.dg["config"]:
				return []string{f.dg["manifest"], f.dg["layer"]}, nil
			case f.dg["layer"]:
				return []string{f.dg["config"]}, nil
			}
			return nil, nil
		}
		res, err := f.store.GC(context.Background(), []string{f.dg["manifest"]}, cyclic)
		if err != nil {
			t.Fatalf("GC: %v", err)
		}
		if res.Kept != 3 || res.Deleted != 2 {
			t.Fatalf("GC = %+v, want 3 kept / 2 deleted", res)
		}
	})
}

func TestGCLockIsExclusive(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	unlock, err := s.Lock(context.Background())
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := os.Stat(s.LockPath()); err != nil {
		t.Fatalf("lock file missing: %v", err)
	}

	// A second acquisition must block until the first is released; with an
	// already-expired context it must give up rather than hang.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := s.Lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Lock = %v, want context.DeadlineExceeded", err)
	}

	if err := unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	// After release the lock is available again.
	unlock2, err := s.Lock(context.Background())
	if err != nil {
		t.Fatalf("Lock after release: %v", err)
	}
	if err := unlock2(); err != nil {
		t.Fatalf("second unlock: %v", err)
	}

	// The lock file must never be mistaken for a blob.
	if n := countDir(t, s.BlobRoot()); n != 0 {
		t.Fatalf("blob directory holds %d entries, want 0", n)
	}
}
