package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/oci/imagespec"
	"github.com/rahuldhali/hull/internal/oci/reference"
	"github.com/rahuldhali/hull/internal/oci/registry"
	"github.com/rahuldhali/hull/internal/types"
)

// Pull fetches an image and unpacks its layers so a container can be created
// from it without any further network access.
//
// progress may be nil. When it is not, it receives one event per blob state
// change during the download and one per layer during extraction, so a CLI can
// draw the familiar per-layer progress bars.
func (e *Engine) Pull(ctx context.Context, ref string, plat *types.Platform, progress func(registry.ProgressEvent)) (*types.Image, error) {
	if err := e.checkOpen(); err != nil {
		return nil, err
	}
	parsed, err := reference.Parse(ref)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrInvalid, ref, err)
	}

	// Bound concurrent pulls so a compose file with twelve services does not
	// open twelve simultaneous layer downloads and starve them all.
	select {
	case e.pullSem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-e.pullSem }()

	client := e.newRegistry(progress)
	img, err := client.Pull(ctx, parsed, e.content, plat)
	if err != nil {
		return nil, fmt.Errorf("engine: pull %s: %w", parsed.FamiliarString(), err)
	}

	layers, err := e.manifestLayers(img)
	if err != nil {
		return nil, err
	}
	unpackProgress := func(digest, status string) {
		if progress != nil {
			progress(registry.ProgressEvent{Digest: digest, Status: status})
		}
	}
	if err := e.snaps.Unpack(ctx, img, e.content, layers, unpackProgress); err != nil {
		return nil, fmt.Errorf("engine: unpack %s: %w", parsed.FamiliarString(), err)
	}

	stored, err := e.images.Put(img)
	if err != nil {
		return nil, err
	}
	e.bus.Publish(events.Image(events.ActionPull, stored.ID, stored.RepoTags))
	return stored, nil
}

// manifestLayers reads an image's layer descriptors back out of the content
// store, which is where Pull left the manifest.
func (e *Engine) manifestLayers(img *types.Image) ([]types.Descriptor, error) {
	body, err := e.content.ReadAll(img.Digest)
	if err != nil {
		return nil, fmt.Errorf("engine: read the manifest of %s: %w", idShort(img.ID), err)
	}
	var m imagespec.Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("engine: parse the manifest of %s: %w", idShort(img.ID), err)
	}
	return m.Layers, nil
}

// Push uploads a local image to its registry.
func (e *Engine) Push(ctx context.Context, ref string, progress func(registry.ProgressEvent)) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	parsed, err := reference.Parse(ref)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrInvalid, ref, err)
	}
	img, err := e.images.Get(ref)
	if err != nil {
		return err
	}
	client := e.newRegistry(progress)
	if err := client.Push(ctx, parsed, img, e.content); err != nil {
		return fmt.Errorf("engine: push %s: %w", parsed.FamiliarString(), err)
	}
	e.bus.Publish(events.Image(events.ActionPush, img.ID, img.RepoTags))
	return nil
}

// Images lists the local images matching opts, newest first.
func (e *Engine) Images(ctx context.Context, opts ImageListOptions) ([]*types.Image, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	all := e.images.List()

	anchor := func(names []string) (*time.Time, error) {
		if len(names) == 0 {
			return nil, nil
		}
		img, err := e.images.Get(names[0])
		if err != nil {
			return nil, err
		}
		t := img.Created
		return &t, nil
	}
	before, err := anchor(opts.Before)
	if err != nil {
		return nil, err
	}
	since, err := anchor(opts.Since)
	if err != nil {
		return nil, err
	}

	labels, err := parseLabelFilters(opts.Label)
	if err != nil {
		return nil, err
	}

	out := make([]*types.Image, 0, len(all))
	for _, img := range all {
		dangling := len(img.RepoTags) == 0
		switch {
		case opts.Dangling != nil && *opts.Dangling != dangling:
			continue
		case opts.Dangling == nil && dangling && !opts.All:
			continue
		}
		if len(opts.Reference) > 0 && !matchAnyReference(opts.Reference, img) {
			continue
		}
		if !matchLabels(labels, img.Labels) && !matchLabels(labels, img.Config.Labels) {
			continue
		}
		if before != nil && !img.Created.Before(*before) {
			continue
		}
		if since != nil && !img.Created.After(*since) {
			continue
		}
		out = append(out, img)
	}
	return out, nil
}

// labelTerm is one parsed "key" or "key=value" label filter.
//
// The terms are a slice rather than a map because Docker ANDs them all, and
// two terms may name the same key: "label=tier=web label=tier=db" must match
// nothing at all, which a map keyed by label name silently turns into "match
// tier=db".
type labelTerm struct {
	// key is the label name.
	key string
	// value is the required value, meaningful only when hasValue is set.
	value string
	// hasValue distinguishes "the label exists" from "the label equals".
	hasValue bool
}

// parseLabelFilters turns "key" and "key=value" terms into a filter list.
func parseLabelFilters(in []string) ([]labelTerm, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]labelTerm, 0, len(in))
	for _, l := range in {
		k, v, hasValue := strings.Cut(l, "=")
		if k == "" {
			return nil, fmt.Errorf("%w: empty label filter", ErrInvalid)
		}
		out = append(out, labelTerm{key: k, value: v, hasValue: hasValue})
	}
	return out, nil
}

// matchLabels reports whether every label term is satisfied.
func matchLabels(want []labelTerm, got map[string]string) bool {
	for _, term := range want {
		actual, ok := got[term.key]
		if !ok {
			return false
		}
		if term.hasValue && actual != term.value {
			return false
		}
	}
	return true
}

// matchAnyReference reports whether any of an image's references matches one of
// the patterns, which may contain "*" wildcards.
func matchAnyReference(patterns []string, img *types.Image) bool {
	refs := append(append([]string(nil), img.RepoTags...), img.RepoDigests...)
	for _, p := range patterns {
		for _, r := range refs {
			if ok, _ := path.Match(p, r); ok {
				return true
			}
			// A bare repository pattern matches every tag of it.
			if repo, _, found := strings.Cut(r, ":"); found && repo == p {
				return true
			}
		}
	}
	return false
}

// ImageInspect returns one image's full record.
func (e *Engine) ImageInspect(ctx context.Context, ref string) (*types.Image, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return e.images.Get(ref)
}

// Tag adds a second reference to an existing image.
func (e *Engine) Tag(ctx context.Context, src, target string) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	img, tag, err := e.images.Tag(src, target)
	if err != nil {
		return err
	}
	e.bus.Publish(events.Image(events.ActionTag, img.ID, []string{tag}))
	return nil
}

// ImageRemove removes a reference, and the image itself once nothing names it.
//
// A tagged image with more than one reference loses only the named one, which
// is what makes "hull rmi alpine:3.19" safe when alpine:3.20 points at the
// same layers. force removes an image even while a stopped container still
// refers to it; a running container's image is never removed.
func (e *Engine) ImageRemove(ctx context.Context, ref string, force, prune bool) ([]ImageDelete, error) {
	if err := e.checkOpen(); err != nil {
		return nil, err
	}
	img, err := e.images.Get(ref)
	if err != nil {
		return nil, err
	}

	users, err := e.containersUsing(img.ID)
	if err != nil {
		return nil, err
	}
	for _, c := range users {
		if c.State == types.StateRunning || c.State == types.StatePaused {
			return nil, fmt.Errorf("%w: %s is in use by the running container %s",
				ErrConflict, ref, idShort(c.ID))
		}
		if !force {
			return nil, fmt.Errorf("%w: %s is in use by container %s; stop and remove it, or use force",
				ErrConflict, ref, idShort(c.ID))
		}
	}

	var report []ImageDelete
	// Removing by tag only untags, as long as another reference survives.
	if !isIDReference(ref, img) {
		_, removed, remaining, uerr := e.images.Untag(ref)
		if uerr != nil {
			return nil, uerr
		}
		if removed != "" {
			report = append(report, ImageDelete{Untagged: removed})
			e.bus.Publish(events.Image(events.ActionUntag, img.ID, []string{removed}))
		}
		if remaining > 0 && !force {
			return report, nil
		}
	}

	if err := e.images.Delete(img.ID); err != nil && !errors.Is(err, ErrNotFound) {
		return report, err
	}
	report = append(report, ImageDelete{Deleted: img.ID})
	e.bus.Publish(events.Image(events.ActionDelete, img.ID, img.RepoTags))

	if prune {
		if _, err := e.collectGarbage(ctx); err != nil {
			e.log.Warn("hull: garbage collection after an image removal failed", "err", err)
		}
	}
	return report, nil
}

// isIDReference reports whether ref names the image by id rather than by tag.
func isIDReference(ref string, img *types.Image) bool {
	if ref == img.ID {
		return true
	}
	hex := strings.TrimPrefix(ref, content.Algorithm+":")
	if hex == "" || len(hex) < minImagePrefix {
		return false
	}
	for _, r := range hex {
		if !isHexRune(r) {
			return false
		}
	}
	return strings.HasPrefix(strings.TrimPrefix(img.ID, content.Algorithm+":"), hex)
}

// containersUsing lists the containers created from an image.
func (e *Engine) containersUsing(imageID string) ([]*types.Container, error) {
	all, err := e.state.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("engine: list containers: %w", err)
	}
	var out []*types.Container
	for _, c := range all {
		if c.Image == imageID {
			out = append(out, c)
		}
	}
	return out, nil
}

// ImageHistory returns an image's build history, newest layer first.
//
// hull keeps only the topmost config, so the intermediate entries report
// "<missing>" for their id, exactly as Docker does for an image it pulled
// rather than built.
func (e *Engine) ImageHistory(ctx context.Context, ref string) ([]HistoryEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	img, err := e.images.Get(ref)
	if err != nil {
		return nil, err
	}
	body, err := e.content.ReadAll(img.ID)
	if err != nil {
		return nil, fmt.Errorf("engine: read the config of %s: %w", idShort(img.ID), err)
	}
	var cfg imagespec.ImageConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("engine: parse the config of %s: %w", idShort(img.ID), err)
	}
	layers, lerr := e.manifestLayers(img)
	if lerr != nil {
		layers = nil
	}

	out := make([]HistoryEntry, 0, len(cfg.History))
	layerIdx := 0
	for _, h := range cfg.History {
		entry := HistoryEntry{
			ID:         "<missing>",
			CreatedBy:  h.CreatedBy,
			Comment:    h.Comment,
			EmptyLayer: h.EmptyLayer,
		}
		if h.Created != nil {
			entry.Created = *h.Created
		}
		if !h.EmptyLayer && layerIdx < len(layers) {
			entry.Size = layers[layerIdx].Size
			layerIdx++
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		// An image with no history block still has one honest entry.
		out = append(out, HistoryEntry{ID: img.ID, Created: img.Created, Size: img.Size})
	}
	// Newest first, and only the top entry carries the id and the tags.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	out[0].ID = img.ID
	out[0].Tags = append([]string(nil), img.RepoTags...)
	return out, nil
}

// Lockfile resolves each reference to the exact digest it points at right now,
// without downloading any layer.
//
// It is what "hull lock" writes: pinning every image in a project to a digest
// is the difference between a rebuild that reproduces byte for byte and one
// that silently picks up a new base image.
func (e *Engine) Lockfile(ctx context.Context, refs []string) ([]LockEntry, error) {
	if err := e.checkOpen(); err != nil {
		return nil, err
	}
	client := e.newRegistry(nil)
	out := make([]LockEntry, 0, len(refs))
	for _, raw := range refs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		parsed, err := reference.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalid, raw, err)
		}
		desc, _, rerr := client.Resolve(ctx, parsed, nil)
		if rerr != nil {
			return nil, fmt.Errorf("engine: resolve %s: %w", parsed.FamiliarString(), rerr)
		}
		entry := LockEntry{
			Ref:       raw,
			Resolved:  parsed.String(),
			Digest:    desc.Digest,
			MediaType: desc.MediaType,
			Size:      desc.Size,
		}
		if desc.Platform != nil {
			entry.Platform = registry.PlatformString(*desc.Platform)
		}
		out = append(out, entry)
	}
	return out, nil
}

// Login verifies credentials against a registry and reports the status string
// the Docker API returns.
//
// hull does not write the credential file itself: the CLI owns
// ~/.docker/config.json and the platform keychain, and a daemon quietly
// rewriting a user's credential store would be a surprise nobody asked for.
func (e *Engine) Login(ctx context.Context, registryHost, user, pass string) (string, error) {
	if err := e.checkOpen(); err != nil {
		return "", err
	}
	if registryHost == "" {
		registryHost = registry.DockerHubEndpoint
	}
	client := registry.NewClient(registry.Options{
		Auth:     registry.NewStaticAuth(user, pass),
		Insecure: e.insecureFor(registryHost),
	})
	if err := client.Ping(ctx, registryHost); err != nil {
		return "", fmt.Errorf("engine: log in to %s: %w", registryHost, err)
	}
	return "Login Succeeded", nil
}

// Logout is a no-op beyond confirming the registry name, for the same reason
// Login does not write: the credential store belongs to the client.
func (e *Engine) Logout(ctx context.Context, registryHost string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if registryHost == "" {
		return fmt.Errorf("%w: logout needs a registry", ErrInvalid)
	}
	return nil
}

// insecureFor reports whether a host was configured as an insecure registry.
func (e *Engine) insecureFor(host string) bool {
	for _, h := range e.cfg.InsecureRegistries {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}
