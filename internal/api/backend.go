package api

import (
	"context"
	"io"

	"github.com/rahuldhali/hull/internal/engine"
	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/logbuf"
	"github.com/rahuldhali/hull/internal/network"
	"github.com/rahuldhali/hull/internal/oci/registry"
	"github.com/rahuldhali/hull/internal/snapshot"
	"github.com/rahuldhali/hull/internal/types"
	"github.com/rahuldhali/hull/internal/volume"
)

// Backend is the subset of *engine.Engine this server drives.
//
// It exists so the HTTP surface — routing, version gating, filter parsing,
// error shapes, the chunked progress encoder and the hijack handshake — can be
// tested with httptest against a fake, with no kernel, no overlay mount, no
// bridge and no registry. *engine.Engine satisfies it as written; see the
// compile-time assertion at the bottom of this file.
type Backend interface {
	// --- containers ---

	// Create builds a container and leaves it in the "created" state.
	Create(ctx context.Context, name string, cfg types.ContainerConfig, host types.HostConfig, imageRef string) (*types.Container, error)
	// Inspect returns one container's full record.
	Inspect(ctx context.Context, idOrName string) (*types.Container, error)
	// List returns the containers matching opts, newest first.
	List(ctx context.Context, opts engine.ListOptions) ([]*types.Container, error)
	// Start runs a created or exited container, optionally attaching.
	Start(ctx context.Context, idOrName string, attach *engine.AttachConfig) error
	// Stop, Restart and Kill end or cycle a running container.
	Stop(ctx context.Context, idOrName string, timeout *int) error
	Restart(ctx context.Context, idOrName string, timeout *int) error
	Kill(ctx context.Context, idOrName, signal string) error
	// Pause and Unpause freeze and thaw the container's cgroup.
	Pause(ctx context.Context, idOrName string) error
	Unpause(ctx context.Context, idOrName string) error
	// Remove deletes a container, optionally forcing and taking its
	// anonymous volumes with it.
	Remove(ctx context.Context, idOrName string, force, removeVolumes bool) error
	// Rename changes a container's name.
	Rename(ctx context.Context, idOrName, newName string) error
	// Update applies resource limits and a restart policy in place.
	Update(ctx context.Context, idOrName string, r types.Resources, rp *types.RestartPolicy) error
	// Wait blocks until the container satisfies condition.
	Wait(ctx context.Context, idOrName, condition string) (int, error)
	// Resize sets the container's pty window size.
	Resize(ctx context.Context, idOrName string, h, w uint16) error
	// Top returns the container's process table.
	Top(ctx context.Context, idOrName, psArgs string) (engine.TopResult, error)
	// Logs writes the container's log to w.
	Logs(ctx context.Context, idOrName string, opts logbuf.ReadOptions, w io.Writer, framed bool) error
	// Attach connects a client's streams to a running container.
	Attach(ctx context.Context, idOrName string, opts engine.AttachConfig) error
	// Stats samples resource usage.
	Stats(ctx context.Context, idOrName string, stream bool, fn func(types.Stats) error) error
	// Diff reports what the writable layer changed.
	Diff(ctx context.Context, idOrName string) ([]snapshot.Change, error)
	// Export streams the container's filesystem as a tar archive.
	Export(ctx context.Context, idOrName string, w io.Writer) error
	// CopyFrom and CopyTo move a tar archive in or out of a container.
	CopyFrom(ctx context.Context, idOrName, srcPath string) (io.ReadCloser, engine.CopyStat, error)
	CopyTo(ctx context.Context, idOrName, dstPath string, r io.Reader, opts engine.CopyOptions) error
	// Commit turns a container's filesystem into an image.
	Commit(ctx context.Context, idOrName string, opts engine.CommitOptions) (*types.Image, error)
	// Prune reclaims space across every object kind.
	Prune(ctx context.Context, filters map[string][]string) (engine.PruneResult, error)
	// Warnings returns the limits this host could not enforce for a
	// container. They must reach the client or the user silently gets an
	// unlimited container.
	Warnings(ctx context.Context, idOrName string) ([]string, error)

	// --- exec ---

	// Exec registers a command and returns its exec id.
	Exec(ctx context.Context, idOrName string, cfg engine.ExecConfig) (string, error)
	// ExecStart runs a registered exec and streams it.
	ExecStart(ctx context.Context, execID string, opts engine.AttachConfig) error
	// ExecInspect reports an exec's state.
	ExecInspect(ctx context.Context, execID string) (*engine.ExecInspect, error)
	// ExecResize sets a running exec's pty window size.
	ExecResize(ctx context.Context, execID string, h, w uint16) error

	// --- images ---

	// Pull fetches an image and unpacks it.
	Pull(ctx context.Context, ref string, plat *types.Platform, progress func(registry.ProgressEvent)) (*types.Image, error)
	// Push uploads a local image.
	Push(ctx context.Context, ref string, progress func(registry.ProgressEvent)) error
	// Images lists local images.
	Images(ctx context.Context, opts engine.ImageListOptions) ([]*types.Image, error)
	// ImageInspect returns one image's record.
	ImageInspect(ctx context.Context, ref string) (*types.Image, error)
	// ImageRemove untags and deletes an image.
	ImageRemove(ctx context.Context, ref string, force, prune bool) ([]engine.ImageDelete, error)
	// ImageHistory returns an image's build history.
	ImageHistory(ctx context.Context, ref string) ([]engine.HistoryEntry, error)
	// Tag points a new reference at an existing image.
	Tag(ctx context.Context, src, target string) error
	// Save and Load move images through a tar archive.
	Save(ctx context.Context, refs []string, w io.Writer) error
	Load(ctx context.Context, r io.Reader, quiet bool, progress func(string)) error
	// Lockfile resolves references to manifest digests without pulling, which
	// is exactly what /distribution/{name}/json reports.
	Lockfile(ctx context.Context, refs []string) ([]engine.LockEntry, error)
	// Login verifies registry credentials.
	Login(ctx context.Context, registryHost, user, pass string) (string, error)

	// --- networks ---

	// NetworkCreate, NetworkRemove, NetworkList and NetworkInspect manage
	// networks.
	NetworkCreate(ctx context.Context, name string, cfg network.CreateConfig) (*types.Network, error)
	NetworkRemove(ctx context.Context, idOrName string) error
	NetworkList(ctx context.Context) ([]*types.Network, error)
	NetworkInspect(ctx context.Context, idOrName string) (*types.Network, error)
	// NetworkConnect and NetworkDisconnect attach and detach a container.
	NetworkConnect(ctx context.Context, netIDOrName, ctrIDOrName string, cfg network.EndpointConfig) error
	NetworkDisconnect(ctx context.Context, netIDOrName, ctrIDOrName string, force bool) error
	// NetworkPrune removes unused networks.
	NetworkPrune(ctx context.Context) ([]string, error)

	// --- volumes ---

	// VolumeCreate, VolumeInspect, VolumeList and VolumeRemove manage named
	// volumes.
	VolumeCreate(ctx context.Context, name, driver string, opts, labels map[string]string) (*types.Volume, error)
	VolumeInspect(ctx context.Context, name string) (*types.Volume, error)
	VolumeList(ctx context.Context, f volume.Filters) ([]*types.Volume, error)
	VolumeRemove(ctx context.Context, name string, force bool) error
	// VolumePrune removes unreferenced volumes.
	VolumePrune(ctx context.Context, f volume.Filters) ([]string, int64, error)

	// --- system ---

	// Info is the /info payload.
	Info(ctx context.Context) (engine.Info, error)
	// Events is the engine event bus /events subscribes to.
	Events() *events.Bus
	// DataRoot is hull's state directory, which the inspect document's
	// per-container file paths are derived from.
	DataRoot() string
	// ClientConnected and ClientDisconnected tell the scale-to-zero watcher
	// that somebody is using the daemon.
	ClientConnected()
	ClientDisconnected()
}

// Compile-time proof that the production engine satisfies the interface, so a
// change to either side fails the build rather than a deployment.
var _ Backend = (*engine.Engine)(nil)
