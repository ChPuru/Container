// Package content implements hull's content-addressed blob store.
//
// Every image manifest, image config and image layer hull ever sees is stored
// here, named by the SHA-256 digest of its bytes. The on-disk layout is:
//
//	<root>/blobs/sha256/<64 hex chars>   committed, immutable, mode 0444
//	<root>/ingest/<random>               in-flight writes, fsync+rename into blobs
//	<root>/gc.lock                       exclusive flock held for the duration of a GC
//
// A blob only ever appears under blobs/sha256 by an atomic rename of a fully
// written, fsynced and digest-verified ingest file, so a crash can never leave a
// truncated or mis-named blob behind: it leaves at worst an abandoned ingest
// file, which CleanIngest removes.
//
// Digests are always the canonical lowercase string form "sha256:<64 hex>".
// Every exported entry point that accepts a digest validates it before touching
// the filesystem, so a hostile manifest cannot steer a read or a delete out of
// the blob directory with "../" or an absolute path.
package content

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Algorithm is the only digest algorithm hull's content store supports.
const Algorithm = "sha256"

const digestPrefix = Algorithm + ":"

// encodedLen is the number of hex characters in a sha256 digest.
const encodedLen = sha256.Size * 2

// shortLen is how many hex characters ShortDigest keeps.
const shortLen = 12

// ValidateDigest reports whether s is a well-formed canonical digest that this
// store is willing to use as a file name, i.e. exactly "sha256:" followed by 64
// lowercase hexadecimal characters. It returns an error wrapping
// ErrInvalidDigest otherwise.
//
// Rejecting uppercase, padding, alternate algorithms and any non-hex byte is
// what makes it safe to build a path from a digest: the validated string cannot
// contain a path separator, a dot segment or a NUL.
func ValidateDigest(s string) error {
	algo, enc, ok := strings.Cut(s, ":")
	if !ok {
		return fmt.Errorf("content: digest %q has no algorithm prefix: %w", s, ErrInvalidDigest)
	}
	if algo != Algorithm {
		return fmt.Errorf("content: digest algorithm %q is not supported, want %q: %w", algo, Algorithm, ErrInvalidDigest)
	}
	if len(enc) != encodedLen {
		return fmt.Errorf("content: digest %q has %d hex characters, want %d: %w", s, len(enc), encodedLen, ErrInvalidDigest)
	}
	for i := 0; i < len(enc); i++ {
		c := enc[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return fmt.Errorf("content: digest %q contains a non-hex character %q: %w", s, string(c), ErrInvalidDigest)
	}
	return nil
}

// encodedOf returns the hex half of an already validated digest.
func encodedOf(dgst string) string {
	return dgst[len(digestPrefix):]
}

// DigestBytes returns the canonical digest of b.
func DigestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return digestPrefix + hex.EncodeToString(sum[:])
}

// DigestReader reads r to EOF and returns its canonical digest and the number of
// bytes read. It never buffers the whole stream.
func DigestReader(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", n, fmt.Errorf("content: digesting reader: %w", err)
	}
	return digestPrefix + hex.EncodeToString(h.Sum(nil)), n, nil
}

// ShortDigest returns the first 12 hex characters of s, the form hull prints in
// the CLI and TUI. The algorithm prefix is stripped if present, and a string
// shorter than 12 characters is returned unchanged.
func ShortDigest(s string) string {
	if _, enc, ok := strings.Cut(s, ":"); ok {
		s = enc
	}
	if len(s) <= shortLen {
		return s
	}
	return s[:shortLen]
}
