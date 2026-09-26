package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ChPuru/hull/internal/fsutil"
	"github.com/ChPuru/hull/internal/snapshot"
	"github.com/ChPuru/hull/internal/types"
)

// Snapshot captures a running container's writable layer under a name.
//
// A running container is frozen for the duration of the copy and thawed
// afterwards, so the checkpoint is a consistent point in time rather than a
// smear across whatever the process was doing. The copy is a true copy, not a
// hardlink share: a checkpoint of a container that keeps running has to stay
// stable, and a shared inode would be rewritten in place by the next write
// overlayfs makes.
func (e *Engine) Snapshot(ctx context.Context, idOrName, name string) (snapshot.Checkpoint, error) {
	var cp snapshot.Checkpoint
	if err := e.checkOpen(); err != nil {
		return cp, err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return cp, err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return cp, err
	}
	defer unlock()

	c, err := e.lookup(id)
	if err != nil {
		return cp, err
	}
	froze := false
	if c.State == types.StateRunning {
		if ferr := e.freeze(id); ferr != nil {
			// A host with no freezer can still take a checkpoint; it is just
			// not a consistent one, and saying so is better than refusing.
			e.log.Warn("hull: taking a checkpoint without freezing the container",
				"container", idShort(id), "err", ferr)
		} else {
			froze = true
		}
	}
	cp, err = e.snaps.CheckpointCopy(ctx, id, name)
	if froze {
		if terr := e.thaw(id); terr != nil {
			e.log.Error("hull: a container was left frozen after a checkpoint",
				"container", idShort(id), "err", terr)
		}
	}
	if err != nil {
		return snapshot.Checkpoint{}, mapSnapshotError(err)
	}
	e.emit("snapshot", c, map[string]string{"checkpoint": name})
	return cp, nil
}

// Checkpoints lists a container's checkpoints, oldest first.
func (e *Engine) Checkpoints(ctx context.Context, idOrName string) ([]snapshot.Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return nil, err
	}
	list, err := e.snaps.ListCheckpoints(id)
	if err != nil {
		return nil, mapSnapshotError(err)
	}
	return list, nil
}

// Revert rolls a container's writable layer back to a checkpoint.
//
// The overlay has to be unmounted for the upperdir to be replaced, so a
// running container is stopped, reverted and started again. That is
// deliberate: silently reverting under a live process would give it a
// filesystem that changed beneath its open file descriptors.
func (e *Engine) Revert(ctx context.Context, idOrName, name string) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()

	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	wasRunning := c.State == types.StateRunning || c.State == types.StatePaused
	if wasRunning {
		if err := e.stopLocked(ctx, id, nil, true); err != nil {
			return err
		}
	}
	if err := e.snaps.Unmount(ctx, id); err != nil {
		return fmt.Errorf("engine: unmount the rootfs of %s: %w", idShort(id), err)
	}
	if err := e.snaps.Restore(ctx, id, name); err != nil {
		// Put the container back the way it was found rather than leaving it
		// unmounted and unusable.
		if _, merr := e.snaps.Mount(ctx, id, c.SnapshotID, c.HostConfig.ReadonlyRootfs); merr != nil {
			e.log.Error("hull: could not remount a container after a failed revert",
				"container", idShort(id), "err", merr)
		}
		return mapSnapshotError(err)
	}
	if _, err := e.snaps.Mount(ctx, id, c.SnapshotID, c.HostConfig.ReadonlyRootfs); err != nil {
		return fmt.Errorf("engine: remount the rootfs of %s: %w", idShort(id), err)
	}
	e.emit("revert", c, map[string]string{"checkpoint": name})
	if wasRunning {
		_, serr := e.startLocked(ctx, id, nil)
		return serr
	}
	return nil
}

// Branch creates a new container from a checkpoint of an existing one.
//
// The new container starts from the same image and configuration as the
// original and has the checkpoint's writable layer as its own, so it is a
// fork of the original's state rather than a fresh instance of the image.
func (e *Engine) Branch(ctx context.Context, idOrName, name, newName string) (*types.Container, error) {
	if err := e.checkOpen(); err != nil {
		return nil, err
	}
	srcID, err := e.resolveID(idOrName)
	if err != nil {
		return nil, err
	}
	src, err := e.lookup(srcID)
	if err != nil {
		return nil, err
	}
	if _, err := e.snaps.StatCheckpoint(srcID, name); err != nil {
		return nil, mapSnapshotError(err)
	}

	clone, err := e.Create(ctx, newName, src.Config, src.HostConfig, src.ImageRef)
	if err != nil {
		return nil, err
	}
	unlock, err := e.locks.Lock(ctx, clone.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := e.copyCheckpointInto(ctx, srcID, name, clone); err != nil {
		// A branch that cannot be populated is not a branch; take the new
		// container away again rather than hand back an empty one.
		if rerr := e.removeLocked(ctx, clone.ID, true, true); rerr != nil {
			e.log.Warn("hull: could not clean up a failed branch", "container", idShort(clone.ID), "err", rerr)
		}
		return nil, err
	}
	e.emit("branch", clone, map[string]string{"from": idShort(srcID), "checkpoint": name})
	return e.Inspect(ctx, clone.ID)
}

// copyCheckpointInto replaces a freshly created container's upperdir with the
// contents of another container's checkpoint.
//
// The checkpoint path is derived from the snapshotter's exported layout
// constants rather than from an API call, because the snapshotter addresses a
// checkpoint by the container it came from and has no "restore into a
// different container" entry point.
func (e *Engine) copyCheckpointInto(ctx context.Context, srcID, name string, dst *types.Container) error {
	srcUpper := filepath.Join(e.cfg.DataRoot, snapshot.DirCheckpoints, srcID, name, snapshot.DirUpper)
	if !fsutil.IsDir(srcUpper) {
		return fmt.Errorf("%w: checkpoint %s of %s", ErrNotFound, name, idShort(srcID))
	}
	if err := e.snaps.Unmount(ctx, dst.ID); err != nil {
		return fmt.Errorf("engine: unmount the rootfs of %s: %w", idShort(dst.ID), err)
	}
	dstUpper, err := e.snaps.UpperPath(dst.ID)
	if err != nil {
		return mapSnapshotError(err)
	}
	if err := os.RemoveAll(dstUpper); err != nil {
		return fmt.Errorf("engine: clear the writable layer of %s: %w", idShort(dst.ID), err)
	}
	if err := copyTree(ctx, srcUpper, dstUpper, e.log.Warn); err != nil {
		return err
	}
	if _, err := e.snaps.Mount(ctx, dst.ID, dst.SnapshotID, dst.HostConfig.ReadonlyRootfs); err != nil {
		return fmt.Errorf("engine: remount the rootfs of %s: %w", idShort(dst.ID), err)
	}
	return nil
}

// SnapshotDiff reports what changed between two checkpoints of one container.
func (e *Engine) SnapshotDiff(ctx context.Context, idOrName, a, b string) ([]snapshot.Change, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return nil, err
	}
	changes, err := e.snaps.DiffCheckpoints(ctx, id, a, b)
	if err != nil {
		return nil, mapSnapshotError(err)
	}
	return changes, nil
}

// Diff reports what a container has changed in its filesystem since it was
// created from its image.
func (e *Engine) Diff(ctx context.Context, idOrName string) ([]snapshot.Change, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return nil, err
	}
	changes, err := e.snaps.Changes(ctx, id)
	if err != nil {
		return nil, mapSnapshotError(err)
	}
	return changes, nil
}

// CheckpointRemove deletes one of a container's checkpoints.
func (e *Engine) CheckpointRemove(ctx context.Context, idOrName, name string) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	if err := e.snaps.DeleteCheckpoint(ctx, id, name); err != nil {
		return mapSnapshotError(err)
	}
	if c, lerr := e.lookup(id); lerr == nil {
		e.emit("snapshot_delete", c, map[string]string{"checkpoint": name})
	}
	return nil
}

// mapSnapshotError translates the snapshotter's sentinels into the engine's.
func mapSnapshotError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, snapshot.ErrNotFound):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case errors.Is(err, snapshot.ErrExists), errors.Is(err, snapshot.ErrInUse), errors.Is(err, snapshot.ErrMounted):
		return fmt.Errorf("%w: %w", ErrConflict, err)
	case errors.Is(err, snapshot.ErrUnsupportedPlatform), errors.Is(err, snapshot.ErrOverlayUnsupported):
		return fmt.Errorf("%w: %w", ErrUnsupported, err)
	case errors.Is(err, snapshot.ErrInvalidChainID):
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	default:
		return err
	}
}

// copyTree copies a directory tree with the portable operations only:
// directories, regular files and symlinks. Anything else — a device node, a
// socket, a fifo — is reported through warn and skipped rather than silently
// turned into an empty file.
func copyTree(ctx context.Context, src, dst string, warn func(string, ...any)) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, info.Mode().Perm())
		case info.Mode()&os.ModeSymlink != 0:
			link, lerr := os.Readlink(p)
			if lerr != nil {
				return lerr
			}
			_ = os.Remove(target)
			return os.Symlink(link, target)
		case info.Mode().IsRegular():
			return fsutil.CopyFile(target, p, info.Mode().Perm())
		default:
			if warn != nil {
				warn("hull: skipping a special file while copying a checkpoint", "path", rel)
			}
			return nil
		}
	})
}
