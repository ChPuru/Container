package engine

import (
	"context"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/network"
	"github.com/rahuldhali/hull/internal/oci/reference"
	"github.com/rahuldhali/hull/internal/oci/registry"
	"github.com/rahuldhali/hull/internal/snapshot"
	"github.com/rahuldhali/hull/internal/types"
	"github.com/rahuldhali/hull/internal/volume"
)

// The interfaces below are the exact subsets of the subsystem managers the
// engine uses. The production types satisfy them as they are; declaring them
// here is what lets the lifecycle, restart, health and unwind paths be tested
// without root, a bridge, an overlay mount or a registry.

// Snapshotter is the subset of *snapshot.Snapshotter the engine drives.
type Snapshotter interface {
	// Mount assembles the container's merged overlay and returns its path.
	Mount(ctx context.Context, containerID, chainID string, readonly bool) (string, error)
	// Unmount tears the merged overlay down, leaving the upperdir in place.
	Unmount(ctx context.Context, containerID string) error
	// Remove unmounts and deletes the container's upper, work and merged
	// directories.
	Remove(ctx context.Context, containerID string) error
	// IsMounted reports whether the container's merged overlay is live.
	IsMounted(containerID string) (bool, error)
	// MergedPath and UpperPath are the container's overlay paths.
	MergedPath(containerID string) (string, error)
	UpperPath(containerID string) (string, error)
	// Changes diffs the container's upperdir against its image.
	Changes(ctx context.Context, containerID string) ([]snapshot.Change, error)
	// Checkpoint captures the upperdir under a name, sharing inodes where the
	// filesystem allows it.
	Checkpoint(ctx context.Context, containerID, name string) (snapshot.Checkpoint, error)
	// CheckpointCopy captures the upperdir with a true byte copy, so the
	// result stays stable even if the container keeps running.
	CheckpointCopy(ctx context.Context, containerID, name string) (snapshot.Checkpoint, error)
	// ListCheckpoints, StatCheckpoint and DeleteCheckpoint manage them.
	ListCheckpoints(containerID string) ([]snapshot.Checkpoint, error)
	StatCheckpoint(containerID, name string) (snapshot.Checkpoint, error)
	DeleteCheckpoint(ctx context.Context, containerID, name string) error
	// Restore rolls the upperdir back to a checkpoint.
	Restore(ctx context.Context, containerID, name string) error
	// DiffCheckpoints compares two checkpoints of one container.
	DiffCheckpoints(ctx context.Context, containerID, a, b string) ([]snapshot.Change, error)
	// Unpack extracts an image's layers into the snapshot store.
	Unpack(ctx context.Context, img *types.Image, store *content.Store, layers []types.Descriptor, progress func(string, string)) error
	// Exists reports whether a chain ID is committed.
	Exists(chainID string) bool
	// Stat describes one committed snapshot.
	Stat(chainID string) (snapshot.Info, error)
	// List returns every snapshot with its live reference count.
	List() ([]snapshot.Info, error)
	// RemoveSnapshot deletes one committed layer.
	RemoveSnapshot(ctx context.Context, chainID string) error
	// Cleanup drops partial snapshots and stale short links.
	Cleanup(ctx context.Context) error
	// Usage reports a snapshot's on-disk size.
	Usage(chainID string) (int64, error)
}

// Networker is the subset of *network.Manager the engine drives.
type Networker interface {
	// Init brings kernel and netfilter state into line with the persisted
	// configuration. It is idempotent and is also the restart path.
	Init(ctx context.Context) error
	// Shutdown stops DNS and the port proxies, leaving bridges in place.
	Shutdown(ctx context.Context) error
	// Create, Remove, Get and List manage networks.
	Create(ctx context.Context, name string, cfg network.CreateConfig) (*types.Network, error)
	Remove(ctx context.Context, idOrName string) error
	Get(idOrName string) (*types.Network, error)
	List() []*types.Network
	// Connect attaches a container to a network. It needs a live network
	// namespace, so the container must already have a pid.
	Connect(ctx context.Context, netID string, c *types.Container, cfg network.EndpointConfig) (*types.EndpointSettings, error)
	// Disconnect detaches a container from a network.
	Disconnect(ctx context.Context, netID, containerID string, force bool) error
	// ConfigureSandbox writes the container's hostname, hosts and resolv.conf.
	ConfigureSandbox(ctx context.Context, pid int, c *types.Container) error
	// PublishPorts and UnpublishPorts manage the userland proxies and the
	// DNAT rules behind them.
	PublishPorts(ctx context.Context, c *types.Container, bindings map[string][]types.PortBinding) ([]network.PublishedPort, error)
	UnpublishPorts(ctx context.Context, containerID string) error
	// UsedPorts reports every published port across all containers.
	UsedPorts() []network.PublishedPort
}

// Volumes is the subset of *volume.Manager the engine drives.
type Volumes interface {
	// Resolve turns a container's mount requests into the final ordered list,
	// materialising every named and anonymous volume and taking references.
	Resolve(ctx context.Context, c *types.Container) ([]types.Mount, error)
	// Release drops this container's references, optionally deleting the
	// anonymous volumes nothing else uses.
	Release(ctx context.Context, c *types.Container, removeAnonymous bool) error
	// Create, Get, List and Remove manage named volumes.
	Create(ctx context.Context, name, driver string, opts, labels map[string]string) (*types.Volume, error)
	Get(name string) (*types.Volume, error)
	List(f volume.Filters) ([]*types.Volume, error)
	Remove(ctx context.Context, name string, force bool) error
	// Prune removes unreferenced volumes and reports what it freed.
	Prune(ctx context.Context, f volume.Filters) (removed []string, reclaimed int64, err error)
	// DataDir is a volume's host directory.
	DataDir(name string) (string, error)
	// Refs lists the containers referencing a volume.
	Refs(name string) ([]string, error)
	// Usage reports a volume's on-disk size.
	Usage(name string) (int64, error)
}

// Registry is the subset of *registry.Client the engine drives. A fresh client
// is built per call because progress delivery is configured at construction.
type Registry interface {
	// Pull fetches a reference into the content store and returns the image.
	Pull(ctx context.Context, ref reference.Reference, store *content.Store, plat *types.Platform) (*types.Image, error)
	// Push uploads an image already present in the content store.
	Push(ctx context.Context, ref reference.Reference, img *types.Image, store *content.Store) error
	// Resolve returns a reference's manifest descriptor and body without
	// downloading any layer.
	Resolve(ctx context.Context, ref reference.Reference, plat *types.Platform) (types.Descriptor, []byte, error)
	// Ping checks that a registry answers, which is how Login validates
	// credentials.
	Ping(ctx context.Context, registryHost string) error
}

// compile-time assertions that the production types satisfy the interfaces.
var (
	_ Snapshotter = (*snapshot.Snapshotter)(nil)
	_ Networker   = (*network.Manager)(nil)
	_ Volumes     = (*volume.Manager)(nil)
	_ Registry    = (*registry.Client)(nil)
)
