package content

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"sync"
)

// SizeUnknown is the value to pass for a blob whose length is not known ahead of
// time. Any negative size means the same thing.
const SizeUnknown int64 = -1

// Writer streams one blob into the store.
//
// Bytes land in <root>/ingest/<random> and are only promoted into
// blobs/sha256/<hex> by Commit, after the running SHA-256 has been checked
// against the expected digest, the file has been fsynced and its parent
// directory has been fsynced. A Writer that is closed without a successful
// Commit removes its ingest file, so an aborted pull leaves nothing behind.
//
// A Writer is safe for concurrent use, though streaming a blob from several
// goroutines is not meaningful.
type Writer struct {
	store *Store
	ctx   context.Context

	mu        sync.Mutex
	f         *os.File
	path      string
	hash      hash.Hash
	size      int64
	committed bool
	closed    bool

	expected     string
	expectedSize int64
	info         Info
}

// Writer returns a Writer that will store the bytes written to it.
//
// expected may be "" when the digest is not known ahead of time; otherwise it
// must be a canonical digest and Commit fails with a *DigestMismatchError if the
// content hashes to anything else. expectedSize may be negative (see
// SizeUnknown) when the length is unknown; otherwise a write that would exceed
// it fails immediately and Commit fails with a *SizeMismatchError if fewer bytes
// arrived.
func (s *Store) Writer(ctx context.Context, expected string, expectedSize int64) (*Writer, error) {
	if ctx == nil {
		return nil, errors.New("content: Writer requires a non-nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("content: opening writer: %w", err)
	}
	if expected != "" {
		if err := ValidateDigest(expected); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(s.ingest, dirPerm); err != nil {
		return nil, fmt.Errorf("content: creating %q: %w", s.ingest, err)
	}
	f, err := os.CreateTemp(s.ingest, "ingest-")
	if err != nil {
		return nil, fmt.Errorf("content: creating ingest file: %w", err)
	}
	if err := f.Chmod(ingestPerm); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, fmt.Errorf("content: setting ingest mode: %w", err)
	}
	if expectedSize < 0 {
		expectedSize = SizeUnknown
	}
	return &Writer{
		store:        s,
		ctx:          ctx,
		f:            f,
		path:         f.Name(),
		hash:         sha256.New(),
		expected:     expected,
		expectedSize: expectedSize,
	}, nil
}

// Write implements io.Writer.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.committed {
		return 0, ErrCommitted
	}
	if w.closed {
		return 0, ErrClosed
	}
	if err := w.ctx.Err(); err != nil {
		return 0, fmt.Errorf("content: writing blob: %w", err)
	}
	if w.expectedSize >= 0 && w.size+int64(len(p)) > w.expectedSize {
		return 0, &SizeMismatchError{
			Digest:   w.expected,
			Expected: w.expectedSize,
			Actual:   w.size + int64(len(p)),
		}
	}
	n, err := w.f.Write(p)
	if n > 0 {
		w.size += int64(n)
		// hash.Hash never returns an error.
		_, _ = w.hash.Write(p[:n])
	}
	if err != nil {
		return n, fmt.Errorf("content: writing ingest file %q: %w", w.path, err)
	}
	return n, nil
}

// Digest returns the digest of the bytes written so far. It is the final digest
// once Commit has succeeded.
func (w *Writer) Digest() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.digestLocked()
}

func (w *Writer) digestLocked() string {
	return digestPrefix + hex.EncodeToString(w.hash.Sum(nil))
}

// Size returns the number of bytes written so far.
func (w *Writer) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.size
}

// Commit verifies the content, durably stores it and atomically renames it into
// the blob directory.
//
// It fails with a *DigestMismatchError (errors.Is ErrDigestMismatch) if the
// content does not hash to the expected digest, and with a *SizeMismatchError
// (errors.Is ErrSizeMismatch) if the length disagrees. In both cases the ingest
// file is discarded.
//
// A concurrent commit of the same digest is not an error: blobs are immutable,
// so if the blob already exists the existing one wins, the ingest file is
// discarded and the metadata of the existing blob is returned.
func (w *Writer) Commit() (Info, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.committed {
		return w.info, ErrCommitted
	}
	if w.closed {
		return Info{}, ErrClosed
	}
	if err := w.ctx.Err(); err != nil {
		w.abortLocked()
		return Info{}, fmt.Errorf("content: committing blob: %w", err)
	}

	actual := w.digestLocked()
	if w.expected != "" && actual != w.expected {
		w.abortLocked()
		return Info{}, &DigestMismatchError{Expected: w.expected, Actual: actual}
	}
	if w.expectedSize >= 0 && w.size != w.expectedSize {
		w.abortLocked()
		return Info{}, &SizeMismatchError{Digest: actual, Expected: w.expectedSize, Actual: w.size}
	}

	target, err := w.store.Path(actual)
	if err != nil {
		w.abortLocked()
		return Info{}, err
	}

	if err := w.f.Sync(); err != nil {
		w.abortLocked()
		return Info{}, fmt.Errorf("content: fsync ingest file %q: %w", w.path, err)
	}
	if err := w.f.Close(); err != nil {
		w.abortLocked()
		return Info{}, fmt.Errorf("content: closing ingest file %q: %w", w.path, err)
	}
	w.f = nil // the handle is gone; from here on only the path matters
	if err := fsyncDir(w.store.ingest); err != nil {
		os.Remove(w.path)
		w.closed = true
		return Info{}, err
	}

	// Blobs are immutable: an existing one is byte-identical by construction.
	if fi, statErr := os.Stat(target); statErr == nil && fi.Mode().IsRegular() {
		os.Remove(w.path)
		w.committed = true
		w.closed = true
		w.info = Info{Digest: actual, Size: fi.Size(), CreatedAt: fi.ModTime()}
		return w.info, nil
	}

	if err := os.Rename(w.path, target); err != nil {
		os.Remove(w.path)
		w.closed = true
		return Info{}, fmt.Errorf("content: committing %s: %w", actual, err)
	}
	// Best effort from here: the blob is already correct and durable-on-rename.
	if err := os.Chmod(target, blobPerm); err != nil && !errors.Is(err, os.ErrPermission) {
		return Info{}, fmt.Errorf("content: sealing %s: %w", actual, err)
	}
	if err := fsyncDir(w.store.blobs); err != nil {
		return Info{}, err
	}

	created, err := os.Stat(target)
	if err != nil {
		return Info{}, fmt.Errorf("content: stat committed %s: %w", actual, err)
	}
	w.committed = true
	w.closed = true
	w.info = Info{Digest: actual, Size: created.Size(), CreatedAt: created.ModTime()}
	return w.info, nil
}

// Close releases the Writer. If Commit has not succeeded, the in-flight ingest
// file is removed. Close is idempotent and safe to defer next to Commit.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.abortLocked()
	return nil
}

// abortLocked discards the ingest file. The caller must hold w.mu.
func (w *Writer) abortLocked() {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
	if w.path != "" {
		os.Remove(w.path)
	}
	w.closed = true
}
