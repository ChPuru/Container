package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/oci/imagespec"
	"github.com/rahuldhali/hull/internal/oci/reference"
	"github.com/rahuldhali/hull/internal/types"
)

// DefaultPushChunkSize is the largest body hull sends in one piece. A blob
// bigger than this is uploaded with chunked PATCH requests so a broken
// connection does not throw away the whole transfer, and so that proxies with
// a request-size ceiling do not reject it.
const DefaultPushChunkSize int64 = 16 << 20

// Push uploads an image and its manifest to the registry named by ref.
//
// The manifest, the config and every layer are read out of store, which must
// already hold them — Push never invents content. Blobs the registry already
// has are skipped with a HEAD check, small blobs go up as a monolithic PUT and
// large ones as chunked PATCH requests, and the manifest is PUT last so the tag
// only ever becomes visible once all of its blobs are present.
//
// No upload request is ever retried: a PUT, POST or PATCH may have applied
// before the connection failed, and replaying it could corrupt an upload
// session.
func (c *Client) Push(ctx context.Context, ref reference.Reference, img *types.Image, store *content.Store) error {
	if img == nil {
		return errors.New("registry: Push requires an image")
	}
	if store == nil {
		return errors.New("registry: Push requires a content store")
	}
	if err := content.ValidateDigest(img.Digest); err != nil {
		return fmt.Errorf("registry: pushing %s: manifest digest: %w", ref.FamiliarString(), err)
	}

	manifestBytes, err := store.ReadAll(img.Digest)
	if err != nil {
		return fmt.Errorf("registry: pushing %s: reading manifest %s from the content store: %w",
			ref.FamiliarString(), content.ShortDigest(img.Digest), err)
	}
	if actual := content.DigestBytes(manifestBytes); actual != img.Digest {
		return &DigestMismatchError{Ref: ref.FamiliarString(), Expected: img.Digest, Actual: actual}
	}

	var m imagespec.Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return fmt.Errorf("registry: pushing %s: parsing manifest: %w: %w", ref.FamiliarString(), err, ErrMalformed)
	}
	if err := validateManifest(ref, m); err != nil {
		return err
	}

	blobs := make([]types.Descriptor, 0, len(m.Layers)+1)
	blobs = append(blobs, m.Config)
	blobs = append(blobs, m.Layers...)
	for _, d := range blobs {
		if err := c.pushBlob(ctx, ref, store, d); err != nil {
			return err
		}
	}

	mediaType := img.ManifestType
	if !imagespec.IsManifest(mediaType) && !imagespec.IsManifestList(mediaType) {
		if sniffed := sniffManifestType(manifestBytes); sniffed != "" {
			mediaType = sniffed
		} else {
			mediaType = imagespec.MediaTypeImageManifest
		}
	}
	return c.putManifest(ctx, ref, img.Digest, mediaType, manifestBytes)
}

// pushBlob uploads one blob unless the registry already has it.
func (c *Client) pushBlob(ctx context.Context, ref reference.Reference, store *content.Store, d types.Descriptor) error {
	exists, err := c.BlobExists(ctx, ref, d.Digest)
	if err != nil {
		return fmt.Errorf("registry: pushing %s: checking blob %s: %w",
			ref.FamiliarString(), content.ShortDigest(d.Digest), err)
	}
	if exists {
		c.emit(ProgressEvent{Digest: d.Digest, Status: StatusExists, Current: d.Size, Total: d.Size})
		c.emit(ProgressEvent{Digest: d.Digest, Status: StatusDone, Current: d.Size, Total: d.Size})
		return nil
	}

	info, err := store.Stat(d.Digest)
	if err != nil {
		return fmt.Errorf("registry: pushing %s: blob %s is not in the content store: %w",
			ref.FamiliarString(), content.ShortDigest(d.Digest), err)
	}

	location, err := c.startUpload(ctx, ref)
	if err != nil {
		return err
	}
	c.emit(ProgressEvent{Digest: d.Digest, Status: StatusDownloading, Current: 0, Total: info.Size})

	if info.Size > c.pushChunkSize {
		location, err = c.uploadChunks(ctx, ref, store, d.Digest, info.Size, location)
		if err != nil {
			return err
		}
		if err := c.finishUpload(ctx, ref, location, d.Digest, nil, 0); err != nil {
			return err
		}
	} else {
		body, err := openBlobSection(store, d.Digest, 0, info.Size)
		if err != nil {
			return err
		}
		defer body.Close()
		getBody := func() (io.ReadCloser, error) { return openBlobSection(store, d.Digest, 0, info.Size) }
		if err := c.finishUpload(ctx, ref, location, d.Digest, getBody, info.Size); err != nil {
			return err
		}
	}

	c.emit(ProgressEvent{Digest: d.Digest, Status: StatusDone, Current: info.Size, Total: info.Size})
	return nil
}

// startUpload opens an upload session and returns its absolute Location.
func (c *Client) startUpload(ctx context.Context, ref reference.Reference) (string, error) {
	u := c.repoURL(ref, "blobs", "uploads") + "/"
	req, err := c.newRequest(ctx, http.MethodPost, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Length", "0")

	resp, err := c.do(ctx, req, pushScope(ref))
	if err != nil {
		return "", err
	}
	defer drain(resp)
	if !success(resp.StatusCode) {
		return "", fmt.Errorf("registry: pushing %s: starting blob upload: %w", ref.FamiliarString(), statusError(resp))
	}
	return uploadLocation(resp)
}

// uploadLocation resolves the Location header of an upload response against the
// request URL, because registries are allowed to answer with a relative path.
func uploadLocation(resp *http.Response) (string, error) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("registry: upload response %s carried no Location header: %w", resp.Status, ErrMalformed)
	}
	u, err := url.Parse(loc)
	if err != nil {
		return "", fmt.Errorf("registry: upload Location %q is not a URL: %w", loc, ErrMalformed)
	}
	return resp.Request.URL.ResolveReference(u).String(), nil
}

// uploadChunks streams a large blob with successive PATCH requests and returns
// the Location the final PUT must go to.
func (c *Client) uploadChunks(ctx context.Context, ref reference.Reference, store *content.Store, dgst string, size int64, location string) (string, error) {
	var offset int64
	for offset < size {
		n := c.pushChunkSize
		if remaining := size - offset; remaining < n {
			n = remaining
		}
		body, err := openBlobSection(store, dgst, offset, n)
		if err != nil {
			return "", err
		}
		req, err := c.newRequest(ctx, http.MethodPatch, location, body)
		if err != nil {
			body.Close()
			return "", err
		}
		start, end := offset, offset+n-1
		req.ContentLength = n
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Range", strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10))
		req.GetBody = func() (io.ReadCloser, error) { return openBlobSection(store, dgst, start, n) }

		resp, err := c.do(ctx, req, pushScope(ref))
		if err != nil {
			return "", err
		}
		if !success(resp.StatusCode) {
			err := statusError(resp)
			return "", fmt.Errorf("registry: pushing %s: uploading bytes %d-%d of %s: %w",
				ref.FamiliarString(), start, end, content.ShortDigest(dgst), err)
		}
		next, err := uploadLocation(resp)
		drain(resp)
		if err != nil {
			return "", err
		}
		location = next
		offset += n
		c.emit(ProgressEvent{Digest: dgst, Status: StatusDownloading, Current: offset, Total: size})
	}
	return location, nil
}

// finishUpload closes an upload session with the final PUT, which carries the
// digest query parameter and, for a monolithic upload, the whole blob.
func (c *Client) finishUpload(ctx context.Context, ref reference.Reference, location, dgst string, getBody func() (io.ReadCloser, error), size int64) error {
	u, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("registry: upload location %q is not a URL: %w", location, ErrMalformed)
	}
	q := u.Query()
	q.Set("digest", dgst)
	u.RawQuery = q.Encode()

	var body io.Reader
	if getBody != nil {
		rc, err := getBody()
		if err != nil {
			return err
		}
		defer rc.Close()
		body = rc
	}
	req, err := c.newRequest(ctx, http.MethodPut, u.String(), body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	if getBody != nil {
		req.GetBody = getBody
	}

	resp, err := c.do(ctx, req, pushScope(ref))
	if err != nil {
		return err
	}
	defer drain(resp)
	if !success(resp.StatusCode) {
		return fmt.Errorf("registry: pushing %s: committing blob %s: %w",
			ref.FamiliarString(), content.ShortDigest(dgst), statusError(resp))
	}
	return nil
}

// putManifest uploads the manifest itself, tagging it when ref carries a tag.
func (c *Client) putManifest(ctx context.Context, ref reference.Reference, dgst, mediaType string, body []byte) error {
	target := ref.Tag
	if target == "" {
		target = dgst
	}
	if err := validateManifestTarget(target); err != nil {
		return err
	}
	u := c.repoURL(ref, "manifests", target)
	req, err := c.newRequest(ctx, http.MethodPut, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", mediaType)

	resp, err := c.do(ctx, req, pushScope(ref))
	if err != nil {
		return err
	}
	defer drain(resp)
	if !success(resp.StatusCode) {
		return fmt.Errorf("registry: pushing %s: uploading manifest: %w", ref.FamiliarString(), statusError(resp))
	}
	if hdr := resp.Header.Get("Docker-Content-Digest"); hdr != "" && hdr != dgst {
		return &DigestMismatchError{Ref: ref.FamiliarString(), Expected: dgst, Actual: hdr}
	}
	return nil
}

// sectionReader is a bounded reader over an open blob file.
type sectionReader struct {
	r io.Reader
	f *os.File
}

func (s *sectionReader) Read(p []byte) (int, error) { return s.r.Read(p) }

func (s *sectionReader) Close() error { return s.f.Close() }

// openBlobSection opens length bytes of a committed blob starting at off. A
// negative length means "to the end".
func openBlobSection(store *content.Store, dgst string, off, length int64) (io.ReadCloser, error) {
	f, err := store.Open(dgst)
	if err != nil {
		return nil, fmt.Errorf("registry: opening blob %s: %w", content.ShortDigest(dgst), err)
	}
	if off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			f.Close()
			return nil, fmt.Errorf("registry: seeking blob %s to %d: %w", content.ShortDigest(dgst), off, err)
		}
	}
	if length < 0 {
		return &sectionReader{r: f, f: f}, nil
	}
	return &sectionReader{r: io.LimitReader(f, length), f: f}, nil
}
