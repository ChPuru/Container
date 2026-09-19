package fsutil

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestTryFileLockRefusesSecondHolder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hull.lock")

	first, err := TryFileLock(p)
	if err != nil {
		t.Fatalf("TryFileLock() error = %v", err)
	}
	if first.Path() != p {
		t.Fatalf("Path() = %q, want %q", first.Path(), p)
	}

	second, err := TryFileLock(p)
	if !errors.Is(err, ErrLocked) {
		if err == nil {
			second.Unlock()
		}
		t.Fatalf("second TryFileLock() error = %v, want ErrLocked", err)
	}

	if err := first.Unlock(); err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}

	third, err := TryFileLock(p)
	if err != nil {
		t.Fatalf("TryFileLock() after release error = %v", err)
	}
	if err := third.Unlock(); err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
}

// TestFileLockBlocksSecondHolder proves the blocking variant actually waits:
// the second acquisition must not complete while the first is held, and must
// complete promptly once it is released.
func TestFileLockBlocksSecondHolder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.lock")

	first, err := FileLock(p)
	if err != nil {
		t.Fatalf("FileLock() error = %v", err)
	}

	type result struct {
		l   *Lock
		err error
	}
	got := make(chan result, 1)
	go func() {
		l, err := FileLock(p)
		got <- result{l, err}
	}()

	select {
	case r := <-got:
		if r.l != nil {
			r.l.Unlock()
		}
		t.Fatalf("second FileLock() returned while the lock was held (err = %v)", r.err)
	case <-time.After(150 * time.Millisecond):
		// Still blocked, which is the point.
	}

	if err := first.Unlock(); err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}

	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("second FileLock() error = %v", r.err)
		}
		if err := r.l.Unlock(); err != nil {
			t.Fatalf("Unlock() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second FileLock() did not acquire after release")
	}
}

func TestLockUnlockTwice(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	l, err := FileLock(p)
	if err != nil {
		t.Fatalf("FileLock() error = %v", err)
	}
	if err := l.Unlock(); err != nil {
		t.Fatalf("first Unlock() error = %v", err)
	}
	if err := l.Unlock(); err == nil {
		t.Fatal("second Unlock() = nil, want error")
	}
	var nilLock *Lock
	if nilLock.Path() != "" {
		t.Fatal("nil Lock.Path() should be empty")
	}
	if err := nilLock.Unlock(); err == nil {
		t.Fatal("nil Lock.Unlock() = nil, want error")
	}
}

func TestFileLockCreatesParentDir(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nested", "dirs", "hull.lock")
	l, err := FileLock(p)
	if err != nil {
		t.Fatalf("FileLock() error = %v", err)
	}
	defer l.Unlock()
	if !Exists(p) {
		t.Fatalf("lock file %s was not created", p)
	}
}
