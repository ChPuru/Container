package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/ChPuru/hull/internal/content"
	"github.com/ChPuru/hull/internal/oci/imagespec"
	"github.com/ChPuru/hull/internal/oci/reference"
	"github.com/ChPuru/hull/internal/types"
)

// Progress statuses reported through Options.Progress.
const (
	// StatusDownloading means bytes are arriving; Current counts them.
	StatusDownloading = "downloading"
	// StatusExtracting is emitted by the snapshotter once a layer is being
	// unpacked. The puller never emits it; the constant lives here so the
	// whole pipeline shares one vocabulary.
	StatusExtracting = "extracting"
	// StatusExists means the blob was already in the content store and no
	// bytes were transferred.
	StatusExists = "exists"
	// StatusDone means the blob is committed and verified.
	StatusDone = "done"
)

// progressInterval and progressBytes throttle download progress so a fast
// layer does not flood the callback.
const (
	progressInterval = 200 * time.Millisecond
	progressBytes    = 512 << 10
)

// ProgressEvent reports the state of one blob during a pull.
type ProgressEvent struct {
	// Digest is the blob the event is about.
	Digest string
	// Status is one of StatusDownloading, StatusExtracting, StatusExists or
	// StatusDone.
	Status string
	// Current is how many bytes have been transferred so far.
	Current int64
	// Total is the blob's size from its descriptor, or zero when unknown.
	Total int64
	// Err is set when the blob failed; Status is then the state it failed in.
	Err error
}

// emit delivers one progress event. Events are serialised, so a callback may
// touch shared state without locking.
func (c *Client) emit(ev ProgressEvent) {
	if c.progress == nil {
		return
	}
	c.progressMu.Lock()
	defer c.progressMu.Unlock()
	c.progress(ev)
}

// ChainID returns the ChainID of the topmost layer of a stack of diff IDs, as
// defined by the OCI image-spec:
//
//	chain[0] = diffID[0]
//	chain[n] = sha256(chain[n-1] + " " + diffID[n])
//
// It returns "" for an empty stack.
func ChainID(diffIDs []string) string {
	if len(diffIDs) == 0 {
		return ""
	}
	chain := diffIDs[0]
	for _, id := range diffIDs[1:] {
		sum := sha256.Sum256([]byte(chain + " " + id))
		chain = content.Algorithm + ":" + hex.EncodeToString(sum[:])
	}
	return chain
}

// ChainIDs returns the ChainID of every prefix of the stack, so ChainIDs(d)[i]
// identifies the filesystem produced by applying d[0] through d[i]. That is
// exactly the key the snapshotter stores each extracted layer under.
func ChainIDs(diffIDs []string) []string {
	if len(diffIDs) == 0 {
		return nil
	}
	out := make([]string, len(diffIDs))
	out[0] = diffIDs[0]
	for i := 1; i < len(diffIDs); i++ {
		sum := sha256.Sum256([]byte(out[i-1] + " " + diffIDs[i]))
		out[i] = content.Algorithm + ":" + hex.EncodeToString(sum[:])
	}
	return out
}

// Pull resolves ref, stores its manifest, config and every layer in store, and
// returns the resulting image record.
//
// Layers are fetched concurrently, bounded by Options.Concurrency, and blobs
// already present in the store are skipped. Every blob is verified against its
// digest as it streams into the store, so a truncated or tampered layer is
// discarded rather than committed. plat may be nil, meaning DefaultPlatform.
func (c *Client) Pull(ctx context.Context, ref reference.Reference, store *content.Store, plat *types.Platform) (*types.Image, error) {
	if store == nil {
		return nil, errors.New("registry: Pull requires a content store")
	}

	root, desc, manifestBytes, err := c.ResolveAll(ctx, ref, plat)
	if err != nil {
		return nil, err
	}

	if !store.Exists(desc.Digest) {
		if _, err := store.WriteBlob(ctx, bytes.NewReader(manifestBytes), desc.Digest, desc.Size); err != nil {
			return nil, fmt.Errorf("registry: storing manifest of %s: %w", ref.FamiliarString(), err)
		}
	}

	var m imagespec.Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("registry: %s: parsing manifest: %w: %w", ref.FamiliarString(), err, ErrMalformed)
	}
	if err := validateManifest(ref, m); err != nil {
		return nil, err
	}

	cfgBytes, err := c.pullConfig(ctx, ref, store, m.Config)
	if err != nil {
		return nil, err
	}
	var cfg imagespec.ImageConfig
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		return nil, fmt.Errorf("registry: %s: parsing image config %s: %w: %w",
			ref.FamiliarString(), content.ShortDigest(m.Config.Digest), err, ErrMalformed)
	}
	if cfg.RootFS.Type != "" && cfg.RootFS.Type != imagespec.RootFSTypeLayers {
		return nil, fmt.Errorf("registry: %s: image config has rootfs.type %q, want %q: %w",
			ref.FamiliarString(), cfg.RootFS.Type, imagespec.RootFSTypeLayers, ErrMalformed)
	}
	if len(cfg.RootFS.DiffIDs) != len(m.Layers) {
		return nil, fmt.Errorf("registry: %s: image config lists %d diff_ids but the manifest has %d layers: %w",
			ref.FamiliarString(), len(cfg.RootFS.DiffIDs), len(m.Layers), ErrMalformed)
	}
	for i, id := range cfg.RootFS.DiffIDs {
		if err := content.ValidateDigest(id); err != nil {
			return nil, fmt.Errorf("registry: %s: rootfs.diff_ids[%d]: %w", ref.FamiliarString(), i, err)
		}
	}

	if err := c.pullLayers(ctx, ref, store, m.Layers); err != nil {
		return nil, err
	}

	var size int64
	for _, l := range m.Layers {
		size += l.Size
	}

	img := &types.Image{
		ID:           m.Config.Digest,
		Digest:       desc.Digest,
		Size:         size,
		Architecture: cfg.Architecture,
		OS:           cfg.OS,
		DiffIDs:      append([]string(nil), cfg.RootFS.DiffIDs...),
		ChainID:      ChainID(cfg.RootFS.DiffIDs),
		Config:       imagespec.ToTypesConfig(cfg.Config),
		ManifestType: desc.MediaType,
	}
	if cfg.Created != nil {
		img.Created = *cfg.Created
	}
	if len(cfg.Config.Labels) > 0 {
		img.Labels = make(map[string]string, len(cfg.Config.Labels))
		for k, v := range cfg.Config.Labels {
			img.Labels[k] = v
		}
	}
	if ref.IsTagged() {
		tagged := reference.Reference{Domain: ref.Domain, Path: ref.Path, Tag: ref.Tag}
		img.RepoTags = []string{tagged.FamiliarString()}
	}
	// RepoDigests names the digest the whole reference resolves to, which for
	// a multi-platform tag is the index rather than the per-platform manifest.
	// That is the digest a user can re-pull the same image by, and the one
	// hull.lock pins.
	pinned := reference.Reference{Domain: ref.Domain, Path: ref.Path, Digest: root.Digest}
	img.RepoDigests = []string{pinned.FamiliarString()}

	return img, nil
}

// validateManifest checks the structural invariants hull relies on before it
// starts transferring anything.
func validateManifest(ref reference.Reference, m imagespec.Manifest) error {
	if err := content.ValidateDigest(m.Config.Digest); err != nil {
		return fmt.Errorf("registry: %s: manifest config digest: %w", ref.FamiliarString(), err)
	}
	if !imagespec.IsConfig(m.Config.MediaType) && m.Config.MediaType != imagespec.MediaTypeEmptyJSON {
		return fmt.Errorf("registry: %s: manifest config has media type %q, which is not an image config: %w",
			ref.FamiliarString(), m.Config.MediaType, ErrMalformed)
	}
	if len(m.Layers) == 0 {
		return fmt.Errorf("registry: %s: manifest has no layers: %w", ref.FamiliarString(), ErrMalformed)
	}
	for i, l := range m.Layers {
		if err := content.ValidateDigest(l.Digest); err != nil {
			return fmt.Errorf("registry: %s: layer %d digest: %w", ref.FamiliarString(), i, err)
		}
		if l.Size < 0 {
			return fmt.Errorf("registry: %s: layer %d has a negative size: %w", ref.FamiliarString(), i, ErrMalformed)
		}
		if !imagespec.IsLayer(l.MediaType) {
			return fmt.Errorf("registry: %s: layer %d has media type %q, which is not a layer: %w",
				ref.FamiliarString(), i, l.MediaType, ErrMalformed)
		}
	}
	return nil
}

// pullConfig fetches (or reuses) the image config blob and returns its bytes.
func (c *Client) pullConfig(ctx context.Context, ref reference.Reference, store *content.Store, d types.Descriptor) ([]byte, error) {
	if !store.Exists(d.Digest) {
		if err := c.fetchIntoStore(ctx, ref, store, d, false); err != nil {
			return nil, err
		}
	}
	b, err := store.ReadAll(d.Digest)
	if err != nil {
		return nil, fmt.Errorf("registry: %s: reading image config %s: %w",
			ref.FamiliarString(), content.ShortDigest(d.Digest), err)
	}
	return b, nil
}

// pullLayers downloads every layer, at most Concurrency at a time. The first
// failure cancels the rest.
func (c *Client) pullLayers(ctx context.Context, ref reference.Reference, store *content.Store, layers []types.Descriptor) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sem := make(chan struct{}, c.concurrency)
	var (
		wg       sync.WaitGroup
		errMu    sync.Mutex
		firstErr error
	)
	fail := func(err error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
			cancel()
		}
		errMu.Unlock()
	}

	for _, layer := range layers {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			errMu.Lock()
			defer errMu.Unlock()
			if firstErr != nil {
				return firstErr
			}
			return ctx.Err()
		}
		wg.Add(1)
		go func(d types.Descriptor) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := c.fetchIntoStore(ctx, ref, store, d, true); err != nil {
				fail(err)
			}
		}(layer)
	}
	wg.Wait()

	errMu.Lock()
	defer errMu.Unlock()
	return firstErr
}

// fetchIntoStore streams one blob into the content store, verifying its digest,
// and reports progress when progress is true.
func (c *Client) fetchIntoStore(ctx context.Context, ref reference.Reference, store *content.Store, d types.Descriptor, progress bool) error {
	if store.Exists(d.Digest) {
		if progress {
			c.emit(ProgressEvent{Digest: d.Digest, Status: StatusExists, Current: d.Size, Total: d.Size})
			c.emit(ProgressEvent{Digest: d.Digest, Status: StatusDone, Current: d.Size, Total: d.Size})
		}
		return nil
	}

	fail := func(err error) error {
		if progress {
			c.emit(ProgressEvent{Digest: d.Digest, Status: StatusDownloading, Total: d.Size, Err: err})
		}
		return err
	}

	rc, err := c.FetchBlob(ctx, ref, d)
	if err != nil {
		return fail(err)
	}
	defer rc.Close()

	w, err := store.Writer(ctx, d.Digest, d.Size)
	if err != nil {
		return fail(fmt.Errorf("registry: opening writer for %s: %w", content.ShortDigest(d.Digest), err))
	}
	defer w.Close()

	if progress {
		c.emit(ProgressEvent{Digest: d.Digest, Status: StatusDownloading, Current: 0, Total: d.Size})
	}

	var dst io.Writer = w
	if progress {
		dst = &progressWriter{
			w:     w,
			total: d.Size,
			emit: func(n int64) {
				c.emit(ProgressEvent{Digest: d.Digest, Status: StatusDownloading, Current: n, Total: d.Size})
			},
		}
	}
	if _, err := io.Copy(dst, rc); err != nil {
		return fail(c.blobError(ref, d, err))
	}
	if _, err := w.Commit(); err != nil {
		return fail(c.blobError(ref, d, err))
	}
	if progress {
		c.emit(ProgressEvent{Digest: d.Digest, Status: StatusDone, Current: d.Size, Total: d.Size})
	}
	return nil
}

// blobError translates a content-store failure into the registry package's own
// typed errors, so callers only have to know one vocabulary.
func (c *Client) blobError(ref reference.Reference, d types.Descriptor, err error) error {
	var dm *content.DigestMismatchError
	if errors.As(err, &dm) {
		return &DigestMismatchError{
			Ref:      ref.FamiliarString() + " blob " + content.ShortDigest(d.Digest),
			Expected: dm.Expected,
			Actual:   dm.Actual,
		}
	}
	var sm *content.SizeMismatchError
	if errors.As(err, &sm) {
		return fmt.Errorf("registry: %s: blob %s is %d bytes but the manifest says %d: %w",
			ref.FamiliarString(), content.ShortDigest(d.Digest), sm.Actual, sm.Expected, ErrMalformed)
	}
	return fmt.Errorf("registry: %s: transferring blob %s: %w",
		ref.FamiliarString(), content.ShortDigest(d.Digest), err)
}

// progressWriter counts bytes on their way into the content store and reports
// them, throttled so that a fast layer does not drown the caller in events.
type progressWriter struct {
	w     io.Writer
	total int64
	emit  func(int64)

	n        int64
	lastN    int64
	lastTime time.Time
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	if n > 0 {
		p.n += int64(n)
		now := time.Now()
		if p.n-p.lastN >= progressBytes || now.Sub(p.lastTime) >= progressInterval {
			p.lastN, p.lastTime = p.n, now
			p.emit(p.n)
		}
	}
	return n, err
}
