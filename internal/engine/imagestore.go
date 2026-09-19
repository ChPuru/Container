package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/fsutil"
	"github.com/rahuldhali/hull/internal/oci/imagespec"
	"github.com/rahuldhali/hull/internal/oci/reference"
	"github.com/rahuldhali/hull/internal/snapshot"
	"github.com/rahuldhali/hull/internal/types"
)

// imageIndexVersion is the on-disk format version of images.json, so a newer
// hull's index is refused rather than misread.
const imageIndexVersion = 1

// minImagePrefix is the shortest id prefix that may identify an image, so a
// two-character typo cannot silently select something.
const minImagePrefix = 3

// imageIndex is the on-disk shape of images/images.json.
type imageIndex struct {
	Version int                     `json:"version"`
	Images  map[string]*types.Image `json:"images"`
}

// imageStore is hull's local image index: image id to record, with the tag and
// digest references each one answers to.
//
// It is the authority on what images exist; the content store is the authority
// on the bytes. The two are reconciled by the garbage collector, which treats
// every manifest named here as a GC root.
type imageStore struct {
	path string

	mu   sync.RWMutex
	imgs map[string]*types.Image
}

// openImageStore loads, or creates, the image index under root.
func openImageStore(root string) (*imageStore, error) {
	dir := filepath.Join(root, "images")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("engine: create image directory %s: %w", dir, err)
	}
	s := &imageStore{
		path: filepath.Join(dir, "images.json"),
		imgs: make(map[string]*types.Image),
	}
	var idx imageIndex
	err := fsutil.ReadJSON(s.path, &idx)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("engine: read image index %s: %w", s.path, err)
	}
	if idx.Version > imageIndexVersion {
		return nil, fmt.Errorf("engine: image index %s was written by a newer hull (format %d, this one understands %d)",
			s.path, idx.Version, imageIndexVersion)
	}
	for id, img := range idx.Images {
		if img == nil {
			continue
		}
		if img.ID == "" {
			img.ID = id
		}
		s.imgs[img.ID] = img
	}
	return s, nil
}

// saveLocked writes the index atomically. The caller holds the write lock.
func (s *imageStore) saveLocked() error {
	idx := imageIndex{Version: imageIndexVersion, Images: s.imgs}
	if err := fsutil.WriteJSONAtomic(s.path, idx, 0o600); err != nil {
		return fmt.Errorf("engine: write image index %s: %w", s.path, err)
	}
	return nil
}

// Len reports how many images are indexed.
func (s *imageStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.imgs)
}

// List returns a copy of every image, newest first.
func (s *imageStore) List() []*types.Image {
	s.mu.RLock()
	out := make([]*types.Image, 0, len(s.imgs))
	for _, img := range s.imgs {
		out = append(out, copyImage(img))
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.After(out[j].Created)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Put records an image, merging its references with any already held for the
// same id, and persists the index.
func (s *imageStore) Put(img *types.Image) (*types.Image, error) {
	if img == nil || img.ID == "" {
		return nil, fmt.Errorf("%w: image record has no id", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	merged := copyImage(img)
	if old, ok := s.imgs[img.ID]; ok {
		merged.RepoTags = mergeStrings(old.RepoTags, merged.RepoTags)
		merged.RepoDigests = mergeStrings(old.RepoDigests, merged.RepoDigests)
		if merged.Created.IsZero() {
			merged.Created = old.Created
		}
	}
	// A tag can only name one image: adopting it here means taking it away
	// from whoever held it, exactly as "docker pull" does.
	for _, tag := range merged.RepoTags {
		for id, other := range s.imgs {
			if id == merged.ID {
				continue
			}
			other.RepoTags = removeString(other.RepoTags, tag)
		}
	}
	s.imgs[merged.ID] = merged
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return copyImage(merged), nil
}

// Get resolves an image by id, id prefix, repo:tag or repo@digest.
func (s *imageStore) Get(ref string) (*types.Image, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	img, err := s.lookupLocked(ref)
	if err != nil {
		return nil, err
	}
	return copyImage(img), nil
}

// lookupLocked resolves a reference against the index. The caller holds at
// least the read lock and must not retain the result.
func (s *imageStore) lookupLocked(ref string) (*types.Image, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("%w: empty image reference", ErrInvalid)
	}
	if img, ok := s.imgs[ref]; ok {
		return img, nil
	}
	// A bare digest, or "sha256:" plus a prefix.
	if id, ok := s.matchIDLocked(ref); ok {
		return s.imgs[id], nil
	}

	parsed, perr := reference.Parse(ref)
	if perr == nil {
		want := parsed.FamiliarString()
		full := parsed.String()
		for _, img := range s.imgs {
			for _, t := range img.RepoTags {
				if t == want || t == full {
					return img, nil
				}
			}
			for _, d := range img.RepoDigests {
				if d == want || d == full {
					return img, nil
				}
			}
		}
		if parsed.IsDigest() {
			if img, ok := s.imgs[parsed.Digest]; ok {
				return img, nil
			}
			for _, img := range s.imgs {
				if img.Digest == parsed.Digest {
					return img, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("%w: no such image: %s", ErrNotFound, ref)
}

// matchIDLocked resolves a full or partial image id. An ambiguous prefix is a
// conflict, never a silent pick.
func (s *imageStore) matchIDLocked(ref string) (string, bool) {
	hex := strings.TrimPrefix(ref, content.Algorithm+":")
	if hex == "" || len(hex) < minImagePrefix {
		return "", false
	}
	for _, r := range hex {
		if !isHexRune(r) {
			return "", false
		}
	}
	var hit string
	n := 0
	for id := range s.imgs {
		if strings.HasPrefix(strings.TrimPrefix(id, content.Algorithm+":"), hex) {
			hit = id
			n++
		}
	}
	if n == 1 {
		return hit, true
	}
	return "", false
}

// isHexRune reports whether r is a lowercase hex digit.
func isHexRune(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
}

// Tag adds target to the image src resolves to, taking the tag away from
// whichever image held it before.
func (s *imageStore) Tag(src, target string) (*types.Image, string, error) {
	parsed, err := reference.Parse(target)
	if err != nil {
		return nil, "", fmt.Errorf("%w: target %q: %w", ErrInvalid, target, err)
	}
	if parsed.IsDigest() && !parsed.IsTagged() {
		return nil, "", fmt.Errorf("%w: %q names a digest; a tag is required", ErrInvalid, target)
	}
	tag := parsed.FamiliarString()

	s.mu.Lock()
	defer s.mu.Unlock()
	img, err := s.lookupLocked(src)
	if err != nil {
		return nil, "", err
	}
	for id, other := range s.imgs {
		if id == img.ID {
			continue
		}
		other.RepoTags = removeString(other.RepoTags, tag)
	}
	img.RepoTags = mergeStrings(img.RepoTags, []string{tag})
	if err := s.saveLocked(); err != nil {
		return nil, "", err
	}
	return copyImage(img), tag, nil
}

// Untag removes one reference from an image and reports whether the image
// still has any reference left.
func (s *imageStore) Untag(ref string) (img *types.Image, removed string, remaining int, err error) {
	parsed, perr := reference.Parse(ref)
	if perr != nil {
		return nil, "", 0, fmt.Errorf("%w: %q: %w", ErrInvalid, ref, perr)
	}
	want := parsed.FamiliarString()

	s.mu.Lock()
	defer s.mu.Unlock()
	target, lerr := s.lookupLocked(ref)
	if lerr != nil {
		return nil, "", 0, lerr
	}
	before := len(target.RepoTags) + len(target.RepoDigests)
	target.RepoTags = removeString(target.RepoTags, want)
	target.RepoDigests = removeString(target.RepoDigests, want)
	if len(target.RepoTags)+len(target.RepoDigests) == before {
		// The reference named the image by id, not by tag; nothing to untag.
		return copyImage(target), "", before, nil
	}
	if err := s.saveLocked(); err != nil {
		return nil, "", 0, err
	}
	return copyImage(target), want, len(target.RepoTags) + len(target.RepoDigests), nil
}

// Delete removes an image record entirely.
func (s *imageStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.imgs[id]; !ok {
		return fmt.Errorf("%w: no such image: %s", ErrNotFound, id)
	}
	delete(s.imgs, id)
	return s.saveLocked()
}

// Roots returns every digest the index keeps alive: each image's manifest and
// its config. They are the garbage collector's starting points.
func (s *imageStore) Roots() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.imgs)*2)
	for id, img := range s.imgs {
		if img.Digest != "" {
			out = append(out, img.Digest)
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// copyImage deep-copies an image record so callers cannot mutate the index.
func copyImage(img *types.Image) *types.Image {
	if img == nil {
		return nil
	}
	c := *img
	c.RepoTags = append([]string(nil), img.RepoTags...)
	c.RepoDigests = append([]string(nil), img.RepoDigests...)
	c.DiffIDs = append([]string(nil), img.DiffIDs...)
	c.Labels = copyStringMap(img.Labels)
	c.Config = copyImageConfig(img.Config)
	return &c
}

// copyImageConfig deep-copies the runtime-relevant half of an image config.
func copyImageConfig(in types.ImageConfig) types.ImageConfig {
	out := in
	out.Env = append([]string(nil), in.Env...)
	out.Entrypoint = append([]string(nil), in.Entrypoint...)
	out.Cmd = append([]string(nil), in.Cmd...)
	out.Shell = append([]string(nil), in.Shell...)
	out.Labels = copyStringMap(in.Labels)
	out.ExposedPorts = copySet(in.ExposedPorts)
	out.Volumes = copySet(in.Volumes)
	if in.Healthcheck != nil {
		hc := *in.Healthcheck
		hc.Test = append([]string(nil), in.Healthcheck.Test...)
		out.Healthcheck = &hc
	}
	return out
}

// copyStringMap copies a string map, returning nil for an empty one.
func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// copySet copies a set-shaped map, returning nil for an empty one.
func copySet(in map[string]struct{}) map[string]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

// mergeStrings appends the entries of add that base does not already have,
// keeping base's order and sorting the additions.
func mergeStrings(base, add []string) []string {
	have := make(map[string]bool, len(base))
	out := make([]string, 0, len(base)+len(add))
	for _, s := range base {
		if s == "" || have[s] {
			continue
		}
		have[s] = true
		out = append(out, s)
	}
	extra := make([]string, 0, len(add))
	for _, s := range add {
		if s == "" || have[s] {
			continue
		}
		have[s] = true
		extra = append(extra, s)
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// removeString returns list without want.
func removeString(list []string, want string) []string {
	if want == "" {
		return list
	}
	out := list[:0]
	for _, s := range list {
		if s != want {
			out = append(out, s)
		}
	}
	return out
}

// imageFromManifest builds a types.Image from a manifest and config blob that
// are already in the content store. It is what Commit and Load use; Pull gets
// its record from the registry client instead.
func imageFromManifest(manifestBytes, configBytes []byte, manifestType string, layers []types.Descriptor) (*types.Image, error) {
	var cfg imagespec.ImageConfig
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return nil, fmt.Errorf("engine: parse image config: %w", err)
	}
	img := &types.Image{
		ID:           content.DigestBytes(configBytes),
		Digest:       content.DigestBytes(manifestBytes),
		Architecture: cfg.Architecture,
		OS:           cfg.OS,
		DiffIDs:      append([]string(nil), cfg.RootFS.DiffIDs...),
		Config:       imagespec.ToTypesConfig(cfg.Config),
		Labels:       copyStringMap(cfg.Config.Labels),
		ManifestType: manifestType,
	}
	if cfg.Created != nil {
		img.Created = *cfg.Created
	}
	for _, l := range layers {
		img.Size += l.Size
	}
	if len(img.DiffIDs) > 0 {
		chain, err := snapshot.TopChainID(img.DiffIDs)
		if err != nil {
			return nil, fmt.Errorf("engine: compute chain ID: %w", err)
		}
		img.ChainID = chain
	}
	return img, nil
}
