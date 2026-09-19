package content

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by the content store. Callers should match them with
// errors.Is; the typed errors below also satisfy these.
var (
	// ErrNotFound means no committed blob exists for the requested digest.
	ErrNotFound = errors.New("content: blob not found")

	// ErrDigestMismatch means the bytes written did not hash to the digest the
	// caller promised. DigestMismatchError carries the two digests.
	ErrDigestMismatch = errors.New("content: digest mismatch")

	// ErrSizeMismatch means the number of bytes written disagreed with the size
	// the caller promised. SizeMismatchError carries the two sizes.
	ErrSizeMismatch = errors.New("content: size mismatch")

	// ErrInvalidDigest means a digest string was not a canonical
	// "sha256:<64 hex>" value and was refused before any path was built from it.
	ErrInvalidDigest = errors.New("content: invalid digest")

	// ErrCommitted means Commit was called twice, or after Close, on one Writer.
	ErrCommitted = errors.New("content: writer is already committed")

	// ErrClosed means the Writer was used after Close aborted it.
	ErrClosed = errors.New("content: writer is closed")

	// ErrTooLarge means ReadAll refused a blob bigger than Store.MaxInlineRead.
	ErrTooLarge = errors.New("content: blob exceeds the maximum inline read size")
)

// DigestMismatchError reports a blob whose contents did not hash to the expected
// digest. It matches ErrDigestMismatch under errors.Is.
type DigestMismatchError struct {
	// Expected is the digest the caller promised.
	Expected string
	// Actual is the digest of the bytes that were actually written.
	Actual string
}

// Error implements error.
func (e *DigestMismatchError) Error() string {
	return fmt.Sprintf("content: digest mismatch: expected %s, got %s", e.Expected, e.Actual)
}

// Is makes errors.Is(err, ErrDigestMismatch) true for this type.
func (e *DigestMismatchError) Is(target error) bool { return target == ErrDigestMismatch }

// SizeMismatchError reports a blob whose length did not match the expected size.
// It matches ErrSizeMismatch under errors.Is.
type SizeMismatchError struct {
	// Digest is the digest of the blob being written, when known.
	Digest string
	// Expected is the size the caller promised.
	Expected int64
	// Actual is the number of bytes that were actually written.
	Actual int64
}

// Error implements error.
func (e *SizeMismatchError) Error() string {
	if e.Digest != "" {
		return fmt.Sprintf("content: size mismatch for %s: expected %d bytes, got %d", e.Digest, e.Expected, e.Actual)
	}
	return fmt.Sprintf("content: size mismatch: expected %d bytes, got %d", e.Expected, e.Actual)
}

// Is makes errors.Is(err, ErrSizeMismatch) true for this type.
func (e *SizeMismatchError) Is(target error) bool { return target == ErrSizeMismatch }
