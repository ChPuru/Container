package engine

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/oci/imagespec"
	"github.com/rahuldhali/hull/internal/oci/reference"
	"github.com/rahuldhali/hull/internal/types"
)

// Archive layout constants. hull writes the hybrid archive modern Docker
// writes: a real OCI image layout that "docker load", "podman load" and any
// OCI tool can read, plus the legacy manifest.json and repositories files that
// older tooling still looks for.
const (
	// ociLayoutFile declares the archive as an OCI image layout.
	ociLayoutFile = "oci-layout"
	// ociIndexFile is the layout's entry point.
	ociIndexFile = "index.json"
	// ociBlobPrefix is where every blob lives inside the archive.
	ociBlobPrefix = "blobs/sha256/"
	// dockerManifestFile is the legacy docker-archive manifest.
	dockerManifestFile = "manifest.json"
	// dockerRepositoriesFile is the legacy tag index.
	dockerRepositoriesFile = "repositories"
	// ociLayoutVersion is the image-layout version hull writes.
	ociLayoutVersion = "1.0.0"
)

// dockerArchiveEntry is one element of the legacy manifest.json.
type dockerArchiveEntry struct {
	// Config is the archive path of the image config blob.
	Config string `json:"Config"`
	// RepoTags are the references this image answers to.
	RepoTags []string `json:"RepoTags"`
	// Layers are the archive paths of the layer blobs, base first.
	Layers []string `json:"Layers"`
}

// Save writes the named images to w as a tar archive.
//
// The archive is an OCI image layout (oci-layout, index.json and
// blobs/sha256/*) with the legacy docker-archive manifest.json and
// repositories files alongside, so it loads into hull, Docker and podman
// alike.
func (e *Engine) Save(ctx context.Context, refs []string, w io.Writer) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	if len(refs) == 0 {
		return fmt.Errorf("%w: save needs at least one image", ErrInvalid)
	}

	type saved struct {
		img       *types.Image
		layers    []types.Descriptor
		configRaw []byte
	}
	images := make([]saved, 0, len(refs))
	blobs := map[string]int64{}
	seen := map[string]bool{}

	for _, ref := range refs {
		img, err := e.images.Get(ref)
		if err != nil {
			return err
		}
		if seen[img.ID] {
			continue
		}
		seen[img.ID] = true
		layers, err := e.manifestLayers(img)
		if err != nil {
			return err
		}
		cfgRaw, err := e.content.ReadAll(img.ID)
		if err != nil {
			return fmt.Errorf("engine: read the config of %s: %w", idShort(img.ID), err)
		}
		images = append(images, saved{img: img, layers: layers, configRaw: cfgRaw})

		blobs[img.Digest] = 0
		blobs[img.ID] = int64(len(cfgRaw))
		for _, l := range layers {
			blobs[l.Digest] = l.Size
		}
	}

	tw := tar.NewWriter(w)
	defer tw.Close()

	if err := writeArchiveFile(tw, ociLayoutFile,
		[]byte(fmt.Sprintf("{\"imageLayoutVersion\":%q}\n", ociLayoutVersion))); err != nil {
		return err
	}

	index := imagespec.Index{SchemaVersion: imagespec.SchemaVersion, MediaType: imagespec.MediaTypeImageIndex}
	var manifest []dockerArchiveEntry
	for _, s := range images {
		desc := types.Descriptor{
			MediaType: s.img.ManifestType,
			Digest:    s.img.Digest,
			Platform:  &types.Platform{Architecture: s.img.Architecture, OS: s.img.OS},
		}
		if info, err := e.content.Stat(s.img.Digest); err == nil {
			desc.Size = info.Size
			blobs[s.img.Digest] = info.Size
		}
		if len(s.img.RepoTags) > 0 {
			desc.Annotations = map[string]string{"org.opencontainers.image.ref.name": s.img.RepoTags[0]}
		}
		index.Manifests = append(index.Manifests, desc)

		entry := dockerArchiveEntry{
			Config:   ociBlobPrefix + digestHex(s.img.ID),
			RepoTags: append([]string(nil), s.img.RepoTags...),
		}
		for _, l := range s.layers {
			entry.Layers = append(entry.Layers, ociBlobPrefix+digestHex(l.Digest))
		}
		manifest = append(manifest, entry)
	}

	indexRaw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("engine: encode the archive index: %w", err)
	}
	if err := writeArchiveFile(tw, ociIndexFile, indexRaw); err != nil {
		return err
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("engine: encode the archive manifest: %w", err)
	}
	if err := writeArchiveFile(tw, dockerManifestFile, manifestRaw); err != nil {
		return err
	}
	var allTags []struct{ tag, id string }
	for _, s := range images {
		for _, t := range s.img.RepoTags {
			allTags = append(allTags, struct{ tag, id string }{t, s.img.ID})
		}
	}
	if err := writeArchiveFile(tw, dockerRepositoriesFile, repositoriesJSON(allTags)); err != nil {
		return err
	}

	for _, dgst := range sortedKeys(blobs) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := e.writeBlobEntry(tw, dgst); err != nil {
			return err
		}
	}

	for _, s := range images {
		e.bus.Publish(events.Image(events.ActionSave, s.img.ID, s.img.RepoTags))
	}
	return tw.Close()
}

// repositoriesJSON renders the legacy repositories file, which maps
// repository to tag to image id.
func repositoriesJSON(tags []struct{ tag, id string }) []byte {
	repos := map[string]map[string]string{}
	for _, t := range tags {
		repo, tag, ok := strings.Cut(t.tag, ":")
		if !ok {
			continue
		}
		if repos[repo] == nil {
			repos[repo] = map[string]string{}
		}
		repos[repo][tag] = digestHex(t.id)
	}
	b, err := json.MarshalIndent(repos, "", "  ")
	if err != nil {
		return []byte("{}\n")
	}
	return b
}

// writeArchiveFile puts one small file into the archive.
func writeArchiveFile(tw *tar.Writer, name string, body []byte) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
		ModTime:  time.Unix(0, 0),
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("engine: write %s into the archive: %w", name, err)
	}
	if _, err := tw.Write(body); err != nil {
		return fmt.Errorf("engine: write %s into the archive: %w", name, err)
	}
	return nil
}

// writeBlobEntry streams one blob out of the content store into the archive.
func (e *Engine) writeBlobEntry(tw *tar.Writer, dgst string) error {
	info, err := e.content.Stat(dgst)
	if err != nil {
		return fmt.Errorf("engine: stat blob %s: %w", content.ShortDigest(dgst), err)
	}
	f, err := e.content.Open(dgst)
	if err != nil {
		return fmt.Errorf("engine: open blob %s: %w", content.ShortDigest(dgst), err)
	}
	defer f.Close()
	hdr := &tar.Header{
		Name:     ociBlobPrefix + digestHex(dgst),
		Mode:     0o444,
		Size:     info.Size,
		Typeflag: tar.TypeReg,
		ModTime:  time.Unix(0, 0),
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("engine: write blob %s into the archive: %w", content.ShortDigest(dgst), err)
	}
	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("engine: write blob %s into the archive: %w", content.ShortDigest(dgst), err)
	}
	return nil
}

// digestHex strips the algorithm prefix from a digest.
func digestHex(d string) string { return strings.TrimPrefix(d, content.Algorithm+":") }

// Load reads an image archive written by Save, "docker save" or any OCI tool
// and registers every image it carries.
//
// quiet suppresses the per-layer progress lines; progress, when non-nil,
// receives the status lines the CLI prints.
func (e *Engine) Load(ctx context.Context, r io.Reader, quiet bool, progress func(string)) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	say := func(format string, args ...any) {
		if quiet || progress == nil {
			return
		}
		progress(fmt.Sprintf(format, args...))
	}

	var manifestRaw, indexRaw []byte
	tr := tar.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("engine: read the image archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		switch {
		case name == dockerManifestFile:
			if manifestRaw, err = io.ReadAll(io.LimitReader(tr, 8<<20)); err != nil {
				return fmt.Errorf("engine: read %s: %w", name, err)
			}
		case name == ociIndexFile:
			if indexRaw, err = io.ReadAll(io.LimitReader(tr, 8<<20)); err != nil {
				return fmt.Errorf("engine: read %s: %w", name, err)
			}
		case strings.HasPrefix(name, ociBlobPrefix):
			dgst := content.Algorithm + ":" + strings.TrimPrefix(name, ociBlobPrefix)
			if err := content.ValidateDigest(dgst); err != nil {
				return fmt.Errorf("engine: archive entry %s: %w", name, err)
			}
			if e.content.Exists(dgst) {
				continue
			}
			if _, err := e.content.WriteBlob(ctx, tr, dgst, hdr.Size); err != nil {
				return fmt.Errorf("engine: store blob %s from the archive: %w", content.ShortDigest(dgst), err)
			}
			say("Loaded blob %s", content.ShortDigest(dgst))
		}
	}

	manifests, err := e.archiveManifests(manifestRaw, indexRaw)
	if err != nil {
		return err
	}
	for _, m := range manifests {
		if err := ctx.Err(); err != nil {
			return err
		}
		img, err := e.registerArchiveImage(ctx, m)
		if err != nil {
			return err
		}
		say("Loaded image: %s", firstOr(img.RepoTags, img.ID))
		e.bus.Publish(events.Image(events.ActionLoad, img.ID, img.RepoTags))
	}
	return nil
}

// archiveImage is one image found in a loaded archive.
type archiveImage struct {
	// digest is the manifest digest.
	digest string
	// tags are the references the archive claimed for it.
	tags []string
}

// archiveManifests works out which manifests an archive carries, preferring
// the OCI index and falling back to the legacy manifest.json.
func (e *Engine) archiveManifests(manifestRaw, indexRaw []byte) ([]archiveImage, error) {
	var out []archiveImage
	if len(indexRaw) > 0 {
		var idx imagespec.Index
		if err := json.Unmarshal(indexRaw, &idx); err != nil {
			return nil, fmt.Errorf("engine: parse the archive index: %w", err)
		}
		for _, d := range idx.Manifests {
			ai := archiveImage{digest: d.Digest}
			if name := d.Annotations["org.opencontainers.image.ref.name"]; name != "" {
				ai.tags = append(ai.tags, name)
			}
			out = append(out, ai)
		}
	}
	if len(out) == 0 && len(manifestRaw) > 0 {
		var entries []dockerArchiveEntry
		if err := json.Unmarshal(manifestRaw, &entries); err != nil {
			return nil, fmt.Errorf("engine: parse the archive manifest: %w", err)
		}
		for _, entry := range entries {
			// A legacy archive names the config, not the manifest, so the
			// manifest has to be rebuilt from what the archive holds.
			dgst, err := e.synthesiseManifest(entry)
			if err != nil {
				return nil, err
			}
			out = append(out, archiveImage{digest: dgst, tags: entry.RepoTags})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: the archive carries neither %s nor %s",
			ErrInvalid, ociIndexFile, dockerManifestFile)
	}
	return out, nil
}

// synthesiseManifest builds and stores an OCI manifest for a legacy archive
// entry that only named its config and layers.
func (e *Engine) synthesiseManifest(entry dockerArchiveEntry) (string, error) {
	cfgDigest := content.Algorithm + ":" + strings.TrimPrefix(entry.Config, ociBlobPrefix)
	cfgDigest = strings.TrimSuffix(cfgDigest, ".json")
	if err := content.ValidateDigest(cfgDigest); err != nil {
		return "", fmt.Errorf("engine: archive config %q: %w", entry.Config, err)
	}
	cfgInfo, err := e.content.Stat(cfgDigest)
	if err != nil {
		return "", fmt.Errorf("engine: the archive names config %s but does not carry it: %w",
			content.ShortDigest(cfgDigest), err)
	}
	m := imagespec.Manifest{
		SchemaVersion: imagespec.SchemaVersion,
		MediaType:     imagespec.MediaTypeImageManifest,
		Config: types.Descriptor{
			MediaType: imagespec.MediaTypeImageConfig,
			Digest:    cfgDigest,
			Size:      cfgInfo.Size,
		},
	}
	for _, l := range entry.Layers {
		dgst := content.Algorithm + ":" + strings.TrimPrefix(l, ociBlobPrefix)
		if err := content.ValidateDigest(dgst); err != nil {
			return "", fmt.Errorf("engine: archive layer %q: %w", l, err)
		}
		info, serr := e.content.Stat(dgst)
		if serr != nil {
			return "", fmt.Errorf("engine: the archive names layer %s but does not carry it: %w",
				content.ShortDigest(dgst), serr)
		}
		m.Layers = append(m.Layers, types.Descriptor{
			MediaType: imagespec.MediaTypeImageLayerGzip,
			Digest:    dgst,
			Size:      info.Size,
		})
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("engine: encode a synthesised manifest: %w", err)
	}
	dgst := content.DigestBytes(raw)
	if !e.content.Exists(dgst) {
		if _, err := e.content.WriteBlob(context.Background(), bytes.NewReader(raw), dgst, int64(len(raw))); err != nil {
			return "", fmt.Errorf("engine: store a synthesised manifest: %w", err)
		}
	}
	return dgst, nil
}

// registerArchiveImage turns one loaded manifest into a local image and
// unpacks its layers.
func (e *Engine) registerArchiveImage(ctx context.Context, ai archiveImage) (*types.Image, error) {
	manifestRaw, err := e.content.ReadAll(ai.digest)
	if err != nil {
		return nil, fmt.Errorf("engine: read the archived manifest %s: %w", content.ShortDigest(ai.digest), err)
	}
	var m imagespec.Manifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		return nil, fmt.Errorf("engine: parse the archived manifest %s: %w", content.ShortDigest(ai.digest), err)
	}
	cfgRaw, err := e.content.ReadAll(m.Config.Digest)
	if err != nil {
		return nil, fmt.Errorf("engine: read the archived config %s: %w", content.ShortDigest(m.Config.Digest), err)
	}
	img, err := imageFromManifest(manifestRaw, cfgRaw, m.MediaType, m.Layers)
	if err != nil {
		return nil, err
	}
	for _, t := range ai.tags {
		if parsed, perr := reference.Parse(t); perr == nil && parsed.IsTagged() {
			img.RepoTags = append(img.RepoTags, parsed.FamiliarString())
		}
	}
	sort.Strings(img.RepoTags)

	if err := e.snaps.Unpack(ctx, img, e.content, m.Layers, nil); err != nil {
		return nil, fmt.Errorf("engine: unpack the loaded image %s: %w", idShort(img.ID), err)
	}
	return e.images.Put(img)
}

// firstOr returns the first entry of list, or fallback when it is empty.
func firstOr(list []string, fallback string) string {
	if len(list) > 0 {
		return list[0]
	}
	return fallback
}
