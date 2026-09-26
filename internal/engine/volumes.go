package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/ChPuru/hull/internal/events"
	"github.com/ChPuru/hull/internal/types"
	"github.com/ChPuru/hull/internal/volume"
)

// VolumeCreate creates, or returns, a named volume. An empty name produces an
// anonymous one.
func (e *Engine) VolumeCreate(ctx context.Context, name, driver string, opts, labels map[string]string) (*types.Volume, error) {
	if err := e.checkOpen(); err != nil {
		return nil, err
	}
	if driver == "" {
		driver = volume.DriverLocal
	}
	v, err := e.vols.Create(ctx, name, driver, opts, labels)
	if err != nil {
		return nil, mapVolumeError(err)
	}
	e.bus.Publish(events.Volume(events.ActionCreate, v.Name, v.Labels))
	return v, nil
}

// VolumeInspect returns one volume by name.
func (e *Engine) VolumeInspect(ctx context.Context, name string) (*types.Volume, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v, err := e.vols.Get(name)
	if err != nil {
		return nil, mapVolumeError(err)
	}
	return v, nil
}

// VolumeList returns the volumes matching the filter.
func (e *Engine) VolumeList(ctx context.Context, f volume.Filters) ([]*types.Volume, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := e.vols.List(f)
	if err != nil {
		return nil, mapVolumeError(err)
	}
	return out, nil
}

// VolumeRemove deletes a volume and its data. It is refused while a container
// still references it, unless force is set.
func (e *Engine) VolumeRemove(ctx context.Context, name string, force bool) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	v, err := e.vols.Get(name)
	if err != nil {
		return mapVolumeError(err)
	}
	if err := e.vols.Remove(ctx, name, force); err != nil {
		return mapVolumeError(err)
	}
	e.bus.Publish(events.Volume(events.ActionDestroy, v.Name, v.Labels))
	return nil
}

// VolumePrune removes unreferenced volumes and reports what was freed.
func (e *Engine) VolumePrune(ctx context.Context, f volume.Filters) ([]string, int64, error) {
	if err := e.checkOpen(); err != nil {
		return nil, 0, err
	}
	removed, reclaimed, err := e.vols.Prune(ctx, f)
	if err != nil {
		return removed, reclaimed, mapVolumeError(err)
	}
	for _, name := range removed {
		e.bus.Publish(events.Volume(events.ActionDestroy, name, nil))
	}
	return removed, reclaimed, nil
}

// mapVolumeError translates the volume manager's sentinels into the engine's.
func mapVolumeError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, volume.ErrNotFound):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case errors.Is(err, volume.ErrInUse), errors.Is(err, volume.ErrConflict):
		return fmt.Errorf("%w: %w", ErrConflict, err)
	case errors.Is(err, volume.ErrInvalidName), errors.Is(err, volume.ErrInvalidMount),
		errors.Is(err, volume.ErrUNCPath), errors.Is(err, volume.ErrDriverUnsupported):
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	default:
		return err
	}
}
