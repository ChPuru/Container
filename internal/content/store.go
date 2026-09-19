package content

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// DefaultMaxInlineRead is the default ceiling for Store.ReadAll. Manifests and
// image configs are kilobytes; anything near 32 MiB is either a layer (which
// must be streamed) or an attempt to make the daemon allocate until it dies.
const DefaultMaxInlineRead int64 = 32 << 20

// dirPerm is the mode of every directory the store creates. The blob store can
// contain registry credentials embedded in manifests, so it is owner-only.
const dirPerm os.FileMode = 0o700

// ingestPerm is the mode of an in-flight ingest file.
const ingestPerm os.FileMode = 0o600

// blobPerm is the mode of a committed blob: read-only, because blobs are
// immutable and are read by the snapshotter and the layer applier.
const blobPerm os.FileMode = 0o444

// Info describes one committed blob.
type Info struct {
	// Digest is the canonical "sha256:<64 hex>" name of the blob.
	Digest string `json:"digest"`
	// Size is the blob's length in bytes.
	Size int64 `json:"size"`
	// CreatedAt is when the blob was committed (the file's modification time).
	CreatedAt time.Time `json:"createdAt"`
}

// Store is a content-addressed blob store rooted at a directory.
//
// A Store is safe for concurrent use by multiple goroutines, and its on-disk
// format is safe for concurrent use by multiple processes: writes land through
// atomic renames and garbage collection takes an exclusive flock.
type Store struct {
	root   string
	blobs  string
	ingest string

	// MaxInlineRead caps ReadAll. It defaults to DefaultMaxInlineRead and may
	// be raised by the caller for trusted content.
	MaxInlineRead int64
}

// NewStore opens (creating if necessary) a content store rooted at root. It
// creates <root>/blobs/sha256 and <root>/ingest with mode 0700.
func NewStore(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("content: store root must not be empty")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("content: resolving store root %q: %w", root, err)
	}
	s := &Store{
		root:          abs,
		blobs:         filepath.Join(abs, "blobs", Algorithm),
		ingest:        filepath.Join(abs, "ingest"),
		MaxInlineRead: DefaultMaxInlineRead,
	}
	for _, dir := range []string{s.root, s.blobs, s.ingest} {
		if err := os.MkdirAll(dir, dirPerm); err != nil {
			return nil, fmt.Errorf("content: creating %q: %w", dir, err)
		}
	}
	return s, nil
}

// Root returns the absolute root directory of the store.
func (s *Store) Root() string { return s.root }

// IngestRoot returns the absolute directory holding in-flight writes.
func (s *Store) IngestRoot() string { return s.ingest }

// BlobRoot returns the absolute directory holding committed blobs.
func (s *Store) BlobRoot() string { return s.blobs }

// Path returns the absolute path of the committed blob named by dgst. The
// digest is validated first, so the returned path is always a direct child of
// the blob directory. The blob need not exist; use Exists or Stat for that.
func (s *Store) Path(dgst string) (string, error) {
	if err := ValidateDigest(dgst); err != nil {
		return "", err
	}
	return filepath.Join(s.blobs, encodedOf(dgst)), nil
}

// Exists reports whether a committed blob with this digest is present. An
// invalid digest is simply absent.
func (s *Store) Exists(dgst string) bool {
	p, err := s.Path(dgst)
	if err != nil {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// Stat returns metadata for a committed blob, or an error wrapping ErrNotFound.
func (s *Store) Stat(dgst string) (Info, error) {
	p, err := s.Path(dgst)
	if err != nil {
		return Info{}, err
	}
	fi, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Info{}, fmt.Errorf("content: %s: %w", dgst, ErrNotFound)
		}
		return Info{}, fmt.Errorf("content: stat %s: %w", dgst, err)
	}
	if !fi.Mode().IsRegular() {
		return Info{}, fmt.Errorf("content: %s is not a regular file: %w", dgst, ErrNotFound)
	}
	return Info{Digest: dgst, Size: fi.Size(), CreatedAt: fi.ModTime()}, nil
}

// Open opens a committed blob for reading. The caller owns the returned file and
// must close it. A missing blob yields an error wrapping ErrNotFound.
func (s *Store) Open(dgst string) (*os.File, error) {
	p, err := s.Path(dgst)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("content: %s: %w", dgst, ErrNotFound)
		}
		return nil, fmt.Errorf("content: open %s: %w", dgst, err)
	}
	return f, nil
}

// ReadAll returns the whole blob in memory. It refuses blobs larger than
// MaxInlineRead with an error wrapping ErrTooLarge, so a hostile manifest that
// claims a multi-gigabyte config cannot exhaust the memory of the daemon. Use
// Open for layers.
//
// The length is re-checked while reading, so a blob that grew between the stat
// and the read (impossible for an immutable blob, possible in a tampered store)
// still cannot exceed the limit.
func (s *Store) ReadAll(dgst string) ([]byte, error) {
	limit := s.MaxInlineRead
	if limit <= 0 {
		limit = DefaultMaxInlineRead
	}
	info, err := s.Stat(dgst)
	if err != nil {
		return nil, err
	}
	if info.Size > limit {
		return nil, fmt.Errorf("content: %s is %d bytes, limit is %d: %w", dgst, info.Size, limit, ErrTooLarge)
	}
	f, err := s.Open(dgst)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, info.Size)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("content: reading %s: %w", dgst, err)
	}
	buf = buf[:n]

	var probe [1]byte
	if extra, _ := f.Read(probe[:]); extra > 0 {
		return nil, fmt.Errorf("content: %s grew past its recorded size %d: %w", dgst, info.Size, ErrSizeMismatch)
	}
	return buf, nil
}

// Delete removes a committed blob. A missing blob yields an error wrapping
// ErrNotFound. Callers are responsible for making sure nothing references the
// blob; GC does that bookkeeping.
func (s *Store) Delete(dgst string) error {
	p, err := s.Path(dgst)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("content: %s: %w", dgst, ErrNotFound)
		}
		return fmt.Errorf("content: deleting %s: %w", dgst, err)
	}
	return nil
}

// Walk calls fn for every committed blob. Entries whose names are not canonical
// 64-character hex digests are skipped, so a stray file cannot be mistaken for a
// blob. If fn returns an error, Walk stops and returns it; returning
// filepath.SkipAll stops the walk without an error.
func (s *Store) Walk(fn func(Info) error) error {
	entries, err := os.ReadDir(s.blobs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("content: listing %q: %w", s.blobs, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		dgst := digestPrefix + e.Name()
		if ValidateDigest(dgst) != nil {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // raced with a Delete or a GC
			}
			return fmt.Errorf("content: stat %s: %w", dgst, err)
		}
		if !fi.Mode().IsRegular() {
			continue
		}
		if err := fn(Info{Digest: dgst, Size: fi.Size(), CreatedAt: fi.ModTime()}); err != nil {
			if errors.Is(err, filepath.SkipAll) {
				return nil
			}
			return err
		}
	}
	return nil
}

// Size returns the total number of bytes held by committed blobs. In-flight
// ingests are not counted.
func (s *Store) Size() (int64, error) {
	var total int64
	err := s.Walk(func(i Info) error {
		total += i.Size
		return nil
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}

// WriteBlob streams r into the store and commits it. It is the convenience form
// of Writer + io.Copy + Commit. expected may be "" when the digest is not known
// ahead of time, and size may be negative for an unknown length.
func (s *Store) WriteBlob(ctx context.Context, r io.Reader, expected string, size int64) (Info, error) {
	w, err := s.Writer(ctx, expected, size)
	if err != nil {
		return Info{}, err
	}
	defer w.Close()

	if _, err := io.Copy(w, r); err != nil {
		return Info{}, fmt.Errorf("content: writing blob: %w", err)
	}
	return w.Commit()
}

// CleanIngest removes ingest files that have not been touched for olderThan,
// i.e. writes abandoned by a crashed pull. A non-positive olderThan removes
// every ingest file, which is only safe when no writer is active.
func (s *Store) CleanIngest(olderThan time.Duration) error {
	entries, err := os.ReadDir(s.ingest)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("content: listing %q: %w", s.ingest, err)
	}
	cutoff := time.Now().Add(-olderThan)
	var errs []error
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			errs = append(errs, fmt.Errorf("content: stat ingest %q: %w", e.Name(), err))
			continue
		}
		if olderThan > 0 && fi.ModTime().After(cutoff) {
			continue
		}
		p := filepath.Join(s.ingest, e.Name())
		if err := os.RemoveAll(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("content: removing ingest %q: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

// fsyncDir flushes a directory entry change (a rename or a create) to stable
// storage. Without it a crash can resurrect a blob name whose data never landed.
func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("content: opening %q for fsync: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("content: fsync %q: %w", dir, err)
	}
	return nil
}
