package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/oci/imagespec"
	"github.com/rahuldhali/hull/internal/oci/reference"
	"github.com/rahuldhali/hull/internal/types"
)

// blobResumeAttempts is how many times a partially read blob is resumed with a
// Range request before the read is given up on.
const blobResumeAttempts = 3

// blobSource is one place a blob can be fetched from.
type blobSource struct {
	url string
	// auth is false for the non-distributable URLs carried in a descriptor,
	// which point at third-party servers that must never see a registry token.
	auth bool
}

// FetchBlob opens a blob for reading.
//
// The registry's 307 to a CDN is followed automatically, and the Authorization
// header is dropped whenever the redirect crosses to a different host: S3 and
// GCS presigned URLs reject a request that carries one, and sending it would
// leak the registry token to a third party.
//
// The returned reader survives a connection that breaks part-way through: it
// reopens the blob with "Range: bytes=<n>-", accepts the 206, and carries on
// from exactly where it stopped, so the caller's running digest stays valid.
// Non-distributable ("foreign") layers are fetched from the descriptor's URLs,
// without credentials.
//
// The caller must close the reader. The blob's digest is NOT verified here
// because the bytes are streamed; verification is the job of the
// content.Writer the caller pipes them into.
func (c *Client) FetchBlob(ctx context.Context, repo reference.Reference, d types.Descriptor) (io.ReadCloser, error) {
	if err := content.ValidateDigest(d.Digest); err != nil {
		return nil, fmt.Errorf("registry: fetching blob from %s: %w", repo.FamiliarString(), err)
	}

	var sources []blobSource
	if !imagespec.IsForeignLayer(d.MediaType) {
		sources = append(sources, blobSource{url: c.repoURL(repo, "blobs", d.Digest), auth: true})
	}
	for _, u := range d.URLs {
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			sources = append(sources, blobSource{url: u})
		}
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("registry: %s: blob %s is non-distributable and the descriptor lists no URLs: %w",
			repo.FamiliarString(), content.ShortDigest(d.Digest), ErrMalformed)
	}

	b := &resumableBlob{
		client: c,
		ctx:    ctx,
		ref:    repo,
		digest: d.Digest,
		total:  d.Size,
		scope:  pullScope(repo),
		srcs:   sources,
	}
	if err := b.open(); err != nil {
		return nil, err
	}
	return b, nil
}

// resumableBlob is a blob body that reopens itself with a Range request when
// the connection drops part-way through.
type resumableBlob struct {
	client *Client
	ctx    context.Context
	ref    reference.Reference
	digest string
	total  int64
	scope  string

	srcs []blobSource
	src  int

	rc       io.ReadCloser
	off      int64
	attempts int
	closed   bool
	// pending is a fatal error that was discovered after some bytes had
	// already been read; those bytes are delivered first and the error is
	// returned by the following Read.
	pending error
}

// Read implements io.Reader, transparently resuming a broken download.
func (b *resumableBlob) Read(p []byte) (int, error) {
	if b.closed {
		return 0, errors.New("registry: blob reader is closed")
	}
	if b.pending != nil {
		return 0, b.pending
	}
	for {
		if b.rc == nil {
			if b.total > 0 && b.off >= b.total {
				return 0, io.EOF
			}
			if err := b.open(); err != nil {
				return 0, err
			}
		}
		n, err := b.rc.Read(p)
		if n > 0 {
			b.off += int64(n)
		}
		if err == nil || errors.Is(err, io.EOF) {
			return n, err
		}
		wrapped := b.readError(err)
		resumable := b.canResume(err)
		b.rc.Close()
		b.rc = nil
		b.attempts++

		if n > 0 {
			// Hand over the bytes that did arrive; the next Read either
			// resumes or reports the failure.
			if !resumable {
				b.pending = wrapped
			}
			return n, nil
		}
		if !resumable {
			return 0, wrapped
		}
		select {
		case <-b.ctx.Done():
			return 0, b.ctx.Err()
		case <-time.After(b.client.backoff(b.attempts - 1)):
		}
	}
}

// readError annotates a mid-stream failure with what was being read.
func (b *resumableBlob) readError(err error) error {
	return fmt.Errorf("registry: reading blob %s from %s at offset %d: %w",
		content.ShortDigest(b.digest), b.ref.FamiliarString(), b.off, err)
}

// canResume reports whether a mid-stream failure is worth a Range retry.
func (b *resumableBlob) canResume(err error) bool {
	if b.attempts >= blobResumeAttempts || !errIsTemporary(err) {
		return false
	}
	if b.ctx.Err() != nil {
		return false
	}
	// Without a known length a resumed read could silently truncate, so only
	// resume when the descriptor told us how long the blob is.
	return b.total > 0 && b.off < b.total
}

// Close releases the underlying body.
func (b *resumableBlob) Close() error {
	b.closed = true
	if b.rc == nil {
		return nil
	}
	err := b.rc.Close()
	b.rc = nil
	return err
}

// open starts (or restarts) the transfer at b.off.
func (b *resumableBlob) open() error {
	for {
		src := b.srcs[b.src]
		req, err := b.client.newRequest(b.ctx, http.MethodGet, src.url, nil)
		if err != nil {
			return err
		}
		if b.off > 0 {
			req.Header.Set("Range", "bytes="+strconv.FormatInt(b.off, 10)+"-")
		}

		var resp *http.Response
		if src.auth {
			resp, err = b.client.do(b.ctx, req, b.scope)
		} else {
			resp, err = b.client.attempt(b.ctx, req)
			b.client.recordRateLimit(resp)
		}
		if err != nil {
			return err
		}

		if resp.StatusCode == http.StatusNotFound && b.src+1 < len(b.srcs) {
			drain(resp)
			b.src++
			continue
		}
		if err := checkResponse(resp); err != nil {
			return err
		}

		switch {
		case b.off == 0:
			// Nothing to reconcile.
		case resp.StatusCode == http.StatusPartialContent:
			if err := verifyContentRange(resp.Header.Get("Content-Range"), b.off); err != nil {
				drain(resp)
				return fmt.Errorf("registry: resuming blob %s: %w", content.ShortDigest(b.digest), err)
			}
		default:
			// The server ignored the Range header and restarted the blob, so
			// skip the prefix we already have rather than corrupting the hash.
			if _, err := io.CopyN(io.Discard, resp.Body, b.off); err != nil {
				drain(resp)
				return fmt.Errorf("registry: resuming blob %s: discarding %d already-read bytes: %w",
					content.ShortDigest(b.digest), b.off, err)
			}
		}

		b.rc = resp.Body
		return nil
	}
}

// verifyContentRange checks that a 206 really starts where we asked it to.
func verifyContentRange(v string, want int64) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return fmt.Errorf("registry: 206 response carried no Content-Range: %w", ErrMalformed)
	}
	unit, spec, ok := strings.Cut(v, " ")
	if !ok || !strings.EqualFold(strings.TrimSpace(unit), "bytes") {
		return fmt.Errorf("registry: unsupported Content-Range %q: %w", v, ErrMalformed)
	}
	rangePart, _, _ := strings.Cut(strings.TrimSpace(spec), "/")
	startStr, _, ok := strings.Cut(rangePart, "-")
	if !ok {
		return fmt.Errorf("registry: malformed Content-Range %q: %w", v, ErrMalformed)
	}
	start, err := strconv.ParseInt(strings.TrimSpace(startStr), 10, 64)
	if err != nil {
		return fmt.Errorf("registry: malformed Content-Range %q: %w", v, ErrMalformed)
	}
	if start != want {
		return fmt.Errorf("registry: resumed at byte %d but asked for %d: %w", start, want, ErrMalformed)
	}
	return nil
}

// BlobExists reports whether the registry already holds a blob, using
// HEAD /v2/<name>/blobs/<digest>. It is how a push skips layers the registry
// has already seen.
func (c *Client) BlobExists(ctx context.Context, repo reference.Reference, dgst string) (bool, error) {
	if err := content.ValidateDigest(dgst); err != nil {
		return false, err
	}
	req, err := c.newRequest(ctx, http.MethodHead, c.repoURL(repo, "blobs", dgst), nil)
	if err != nil {
		return false, err
	}
	resp, err := c.do(ctx, req, pushScope(repo))
	if err != nil {
		return false, err
	}
	defer drain(resp)

	switch {
	case success(resp.StatusCode):
		return true, nil
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	default:
		return false, statusError(resp)
	}
}
