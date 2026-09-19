//go:build !linux

package snapshot

import (
	"context"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/types"
)

// This file keeps the package's API identical on every GOOS so the Windows
// build of the hull CLI links, while making it impossible to pretend a
// snapshotter works anywhere but Linux. Every entry point fails with
// ErrUnsupportedPlatform; none of them touches the filesystem.

// New reports that snapshotting requires Linux. The real implementation drives
// overlayfs, which exists only there; the Windows CLI talks to a daemon inside
// WSL instead of managing snapshots itself.
func New(root string, feat Features) (*Snapshotter, error) { return nil, ErrUnsupportedPlatform }

// Detect reports that overlayfs cannot be probed off Linux.
func Detect(ctx context.Context, probeDir string) (Features, error) {
	return Features{}, ErrUnsupportedPlatform
}

// Prepare is unavailable off Linux.
func (s *Snapshotter) Prepare(ctx context.Context, chainID string, parentChainID string) (string, error) {
	return "", ErrUnsupportedPlatform
}

// Commit is unavailable off Linux.
func (s *Snapshotter) Commit(ctx context.Context, chainID string, diffID string, size int64) error {
	return ErrUnsupportedPlatform
}

// Abort is unavailable off Linux.
func (s *Snapshotter) Abort(ctx context.Context, chainID string) error { return ErrUnsupportedPlatform }

// Unpack is unavailable off Linux.
func (s *Snapshotter) Unpack(ctx context.Context, img *types.Image, store *content.Store, layers []types.Descriptor, progress func(string, string)) error {
	return ErrUnsupportedPlatform
}

// Stat is unavailable off Linux.
func (s *Snapshotter) Stat(chainID string) (Info, error) { return Info{}, ErrUnsupportedPlatform }

// Chain is unavailable off Linux.
func (s *Snapshotter) Chain(chainID string) ([]string, error) { return nil, ErrUnsupportedPlatform }

// List is unavailable off Linux.
func (s *Snapshotter) List() ([]Info, error) { return nil, ErrUnsupportedPlatform }

// Usage is unavailable off Linux.
func (s *Snapshotter) Usage(chainID string) (int64, error) { return 0, ErrUnsupportedPlatform }

// RemoveSnapshot is unavailable off Linux.
func (s *Snapshotter) RemoveSnapshot(ctx context.Context, chainID string) error {
	return ErrUnsupportedPlatform
}

// Cleanup is unavailable off Linux.
func (s *Snapshotter) Cleanup(ctx context.Context) error { return ErrUnsupportedPlatform }

// Mount is unavailable off Linux.
func (s *Snapshotter) Mount(ctx context.Context, containerID string, chainID string, readonly bool) (string, error) {
	return "", ErrUnsupportedPlatform
}

// Unmount is unavailable off Linux.
func (s *Snapshotter) Unmount(ctx context.Context, containerID string) error {
	return ErrUnsupportedPlatform
}

// Remove is unavailable off Linux.
func (s *Snapshotter) Remove(ctx context.Context, containerID string) error {
	return ErrUnsupportedPlatform
}

// IsMounted is unavailable off Linux.
func (s *Snapshotter) IsMounted(containerID string) (bool, error) {
	return false, ErrUnsupportedPlatform
}

// Checkpoint is unavailable off Linux.
func (s *Snapshotter) Checkpoint(ctx context.Context, containerID string, name string) (Checkpoint, error) {
	return Checkpoint{}, ErrUnsupportedPlatform
}

// CheckpointCopy is unavailable off Linux.
func (s *Snapshotter) CheckpointCopy(ctx context.Context, containerID string, name string) (Checkpoint, error) {
	return Checkpoint{}, ErrUnsupportedPlatform
}

// ListCheckpoints is unavailable off Linux.
func (s *Snapshotter) ListCheckpoints(containerID string) ([]Checkpoint, error) {
	return nil, ErrUnsupportedPlatform
}

// StatCheckpoint is unavailable off Linux.
func (s *Snapshotter) StatCheckpoint(containerID string, name string) (Checkpoint, error) {
	return Checkpoint{}, ErrUnsupportedPlatform
}

// DeleteCheckpoint is unavailable off Linux.
func (s *Snapshotter) DeleteCheckpoint(ctx context.Context, containerID string, name string) error {
	return ErrUnsupportedPlatform
}

// Restore is unavailable off Linux.
func (s *Snapshotter) Restore(ctx context.Context, containerID string, name string) error {
	return ErrUnsupportedPlatform
}

// DiffCheckpoints is unavailable off Linux.
func (s *Snapshotter) DiffCheckpoints(ctx context.Context, containerID string, a string, b string) ([]Change, error) {
	return nil, ErrUnsupportedPlatform
}

// Changes is unavailable off Linux.
func (s *Snapshotter) Changes(ctx context.Context, containerID string) ([]Change, error) {
	return nil, ErrUnsupportedPlatform
}
