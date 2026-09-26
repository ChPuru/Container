package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ChPuru/hull/internal/content"
	"github.com/ChPuru/hull/internal/events"
	"github.com/ChPuru/hull/internal/snapshot"
	"github.com/ChPuru/hull/internal/types"
	"github.com/ChPuru/hull/internal/volume"
)

// maxManifestBlob bounds what the garbage collector is willing to parse while
// walking the reachability graph. Manifests and configs are kilobytes; a blob
// larger than this is a layer and has no children worth chasing.
const maxManifestBlob = 8 << 20

// Prune reclaims space: stopped containers, unused images, dangling snapshots
// and unreferenced blobs, plus networks and volumes when asked.
//
// filters follows the Docker vocabulary: "until" bounds by age, "label"
// narrows by label, "all=true" prunes every unused image rather than only the
// dangling ones, and "volumes=true" includes unused volumes.
func (e *Engine) Prune(ctx context.Context, filters map[string][]string) (PruneResult, error) {
	var res PruneResult
	if err := e.checkOpen(); err != nil {
		return res, err
	}
	until, err := pruneUntil(filters)
	if err != nil {
		return res, err
	}
	labels, err := parseLabelFilters(filters["label"])
	if err != nil {
		return res, err
	}
	all := boolFilter(filters, "all")
	withVolumes := boolFilter(filters, "volumes")

	// Containers first: they are what holds images and volumes alive.
	ctrs, err := e.state.ListContainers()
	if err != nil {
		return res, fmt.Errorf("engine: list containers: %w", err)
	}
	for _, c := range ctrs {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if c.State != types.StateExited && c.State != types.StateCreated && c.State != types.StateDead {
			continue
		}
		if until != nil && !c.Created.Before(*until) {
			continue
		}
		if !matchLabels(labels, c.Config.Labels) {
			continue
		}
		if err := e.Remove(ctx, c.ID, false, false); err != nil {
			if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
				continue
			}
			return res, err
		}
		res.ContainersDeleted = append(res.ContainersDeleted, c.ID)
	}

	// Images: dangling ones always, everything unused when all=true.
	inUse, err := e.imagesInUse()
	if err != nil {
		return res, err
	}
	for _, img := range e.images.List() {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if inUse[img.ID] {
			continue
		}
		if !all && len(img.RepoTags) > 0 {
			continue
		}
		if until != nil && !img.Created.Before(*until) {
			continue
		}
		if !matchLabels(labels, img.Labels) {
			continue
		}
		if err := e.images.Delete(img.ID); err != nil {
			continue
		}
		res.ImagesDeleted = append(res.ImagesDeleted, img.ID)
		res.SpaceReclaimed += img.Size
		e.bus.Publish(events.Image(events.ActionDelete, img.ID, img.RepoTags))
	}

	if withVolumes {
		removed, reclaimed, verr := e.VolumePrune(ctx, volume.Filters{All: all})
		if verr != nil {
			return res, verr
		}
		res.VolumesDeleted = removed
		res.SpaceReclaimed += reclaimed
	}

	nets, nerr := e.NetworkPrune(ctx)
	if nerr != nil {
		return res, nerr
	}
	res.NetworksDeleted = nets

	gc, gerr := e.collectGarbage(ctx)
	if gerr != nil {
		return res, gerr
	}
	res.SnapshotsDeleted = gc.SnapshotsDeleted
	res.SpaceReclaimed += gc.SpaceReclaimed

	e.bus.Publish(events.Daemon(events.ActionPrune, map[string]string{
		"containers": strconv.Itoa(len(res.ContainersDeleted)),
		"images":     strconv.Itoa(len(res.ImagesDeleted)),
		"reclaimed":  strconv.FormatInt(res.SpaceReclaimed, 10),
	}))
	return res, nil
}

// pruneUntil reads the "until" filter as either an RFC3339 instant or a
// duration ago.
func pruneUntil(filters map[string][]string) (*time.Time, error) {
	vals := filters["until"]
	if len(vals) == 0 {
		return nil, nil
	}
	v := strings.TrimSpace(vals[0])
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return &t, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		t := time.Now().UTC().Add(-d)
		return &t, nil
	}
	return nil, fmt.Errorf("%w: until filter %q is neither an RFC3339 time nor a duration", ErrInvalid, v)
}

// boolFilter reads a boolean filter value.
func boolFilter(filters map[string][]string, key string) bool {
	for _, v := range filters[key] {
		if b, err := strconv.ParseBool(v); err == nil && b {
			return true
		}
	}
	return false
}

// imagesInUse is the set of image ids some container still refers to.
func (e *Engine) imagesInUse() (map[string]bool, error) {
	ctrs, err := e.state.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("engine: list containers: %w", err)
	}
	out := make(map[string]bool, len(ctrs))
	for _, c := range ctrs {
		out[c.Image] = true
	}
	return out, nil
}

// gcResult is what one garbage-collection pass reclaimed.
type gcResult struct {
	// SnapshotsDeleted names the overlay snapshots that were dropped.
	SnapshotsDeleted []string
	// BlobsDeleted is how many content-store blobs went.
	BlobsDeleted int
	// SpaceReclaimed is the total number of bytes freed.
	SpaceReclaimed int64
}

// collectGarbage drops dangling snapshots and unreferenced blobs.
//
// It is deliberately conservative and fail-closed: a snapshot that any image
// or container still reaches is kept, and the blob sweep abandons the whole
// pass rather than delete anything if the reachability graph cannot be walked.
// Deleting a live layer would turn a working image into an unexplainable
// runtime failure much later.
func (e *Engine) collectGarbage(ctx context.Context) (gcResult, error) {
	var res gcResult
	if err := e.snaps.Cleanup(ctx); err != nil && !errors.Is(err, snapshot.ErrUnsupportedPlatform) {
		return res, fmt.Errorf("engine: clean up partial snapshots: %w", err)
	}

	live, err := e.liveChainIDs()
	if err != nil {
		return res, err
	}
	infos, err := e.snaps.List()
	if err != nil {
		if errors.Is(err, snapshot.ErrUnsupportedPlatform) {
			return res, nil
		}
		return res, fmt.Errorf("engine: list snapshots: %w", err)
	}
	for _, info := range infos {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if live[info.ChainID] || info.Refs > 0 {
			continue
		}
		size, _ := e.snaps.Usage(info.ChainID)
		if err := e.snaps.RemoveSnapshot(ctx, info.ChainID); err != nil {
			if errors.Is(err, snapshot.ErrInUse) {
				continue
			}
			e.log.Debug("hull: could not remove a dangling snapshot", "chainID", info.ChainID, "err", err)
			continue
		}
		res.SnapshotsDeleted = append(res.SnapshotsDeleted, info.ChainID)
		res.SpaceReclaimed += size
	}

	blobs, err := e.content.GC(ctx, e.images.Roots(), e.blobChildren)
	if err != nil {
		return res, fmt.Errorf("engine: collect unreferenced blobs: %w", err)
	}
	res.BlobsDeleted = blobs.Deleted
	res.SpaceReclaimed += blobs.FreedBytes
	return res, nil
}

// liveChainIDs is every overlay chain some image or container still needs,
// including the intermediate ones, because a snapshot's lower layers are as
// live as the top.
func (e *Engine) liveChainIDs() (map[string]bool, error) {
	out := map[string]bool{}
	for _, img := range e.images.List() {
		chains, err := snapshot.ChainIDs(img.DiffIDs)
		if err != nil {
			continue
		}
		for _, c := range chains {
			out[c] = true
		}
	}
	ctrs, err := e.state.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("engine: list containers: %w", err)
	}
	for _, c := range ctrs {
		if c.SnapshotID != "" {
			out[c.SnapshotID] = true
		}
	}
	return out, nil
}

// blobChildren answers the garbage collector's reachability question: which
// further digests does this blob name?
//
// Only manifests and indexes have children. A blob that is too large, or that
// is not JSON, is a layer and is reported as having none — never as an error,
// because an error abandons the whole pass.
func (e *Engine) blobChildren(dgst string) ([]string, error) {
	info, err := e.content.Stat(dgst)
	if err != nil || info.Size > maxManifestBlob {
		return nil, nil
	}
	body, err := e.content.ReadAll(dgst)
	if err != nil || len(body) == 0 || body[0] != '{' {
		return nil, nil
	}
	var doc struct {
		MediaType string             `json:"mediaType"`
		Config    *types.Descriptor  `json:"config"`
		Layers    []types.Descriptor `json:"layers"`
		Manifests []types.Descriptor `json:"manifests"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil
	}
	var out []string
	if doc.Config != nil && doc.Config.Digest != "" {
		out = append(out, doc.Config.Digest)
	}
	for _, l := range doc.Layers {
		if l.Digest != "" {
			out = append(out, l.Digest)
		}
	}
	for _, m := range doc.Manifests {
		if m.Digest != "" {
			out = append(out, m.Digest)
		}
	}
	for _, d := range out {
		if err := content.ValidateDigest(d); err != nil {
			// A malformed child reference means this blob is not a manifest
			// hull wrote; treat it as a leaf rather than risk the pass.
			return nil, nil
		}
	}
	return out, nil
}

// GC runs one garbage-collection pass on demand, which is what
// "hull engine gc" calls.
func (e *Engine) GC(ctx context.Context) (PruneResult, error) {
	var res PruneResult
	if err := e.checkOpen(); err != nil {
		return res, err
	}
	gc, err := e.collectGarbage(ctx)
	if err != nil {
		return res, err
	}
	res.SnapshotsDeleted = gc.SnapshotsDeleted
	res.SpaceReclaimed = gc.SpaceReclaimed
	return res, nil
}
