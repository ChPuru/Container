package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/ChPuru/hull/internal/events"
	"github.com/ChPuru/hull/internal/network"
	"github.com/ChPuru/hull/internal/types"
)

// NetworkCreate defines a new bridge network.
func (e *Engine) NetworkCreate(ctx context.Context, name string, cfg network.CreateConfig) (*types.Network, error) {
	if err := e.checkOpen(); err != nil {
		return nil, err
	}
	n, err := e.nets.Create(ctx, name, cfg)
	if err != nil {
		return nil, mapNetworkError(err)
	}
	if err := e.state.PutNetwork(n); err != nil {
		return nil, fmt.Errorf("engine: persist network %s: %w", n.Name, err)
	}
	e.bus.Publish(events.Network(events.ActionCreate, n, ""))
	return n, nil
}

// NetworkRemove deletes a network. It is refused while a container is still
// attached, because tearing the bridge out would leave that container with a
// veth pointing nowhere.
func (e *Engine) NetworkRemove(ctx context.Context, idOrName string) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	n, err := e.nets.Get(idOrName)
	if err != nil {
		return mapNetworkError(err)
	}
	if err := e.nets.Remove(ctx, idOrName); err != nil {
		return mapNetworkError(err)
	}
	if err := e.state.DeleteNetwork(n.ID); err != nil {
		e.log.Debug("hull: could not drop a network from the index", "network", n.Name, "err", err)
	}
	e.bus.Publish(events.Network(events.ActionDestroy, n, ""))
	return nil
}

// NetworkList returns every network, sorted by name.
func (e *Engine) NetworkList(ctx context.Context) ([]*types.Network, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return e.nets.List(), nil
}

// NetworkInspect returns one network by id, id prefix or name.
func (e *Engine) NetworkInspect(ctx context.Context, idOrName string) (*types.Network, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n, err := e.nets.Get(idOrName)
	if err != nil {
		return nil, mapNetworkError(err)
	}
	return n, nil
}

// NetworkConnect attaches a running container to another network, creating the
// veth pair immediately. A container that is not running records the intent
// and is attached when it starts.
func (e *Engine) NetworkConnect(ctx context.Context, netIDOrName, ctrIDOrName string, cfg network.EndpointConfig) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(ctrIDOrName)
	if err != nil {
		return err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()

	n, err := e.nets.Get(netIDOrName)
	if err != nil {
		return mapNetworkError(err)
	}
	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	if _, already := c.NetworkSettings.Networks[n.Name]; already {
		return fmt.Errorf("%w: %s is already attached to %s", ErrConflict, idShort(id), n.Name)
	}

	ep := types.EndpointSettings{NetworkID: n.ID, Aliases: cfg.Aliases}
	if c.State == types.StateRunning {
		live, cerr := e.nets.Connect(ctx, n.ID, c, cfg)
		if cerr != nil {
			return fmt.Errorf("engine: attach %s to %s: %w", idShort(id), n.Name, mapNetworkError(cerr))
		}
		ep = *live
	}
	if err := e.update(id, func(cur *types.Container) error {
		if cur.NetworkSettings.Networks == nil {
			cur.NetworkSettings.Networks = map[string]types.EndpointSettings{}
		}
		cur.NetworkSettings.Networks[n.Name] = ep
		return nil
	}); err != nil {
		return err
	}
	e.bus.Publish(events.Network(events.ActionConnect, n, id))
	return nil
}

// NetworkDisconnect detaches a container from a network.
func (e *Engine) NetworkDisconnect(ctx context.Context, netIDOrName, ctrIDOrName string, force bool) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(ctrIDOrName)
	if err != nil {
		return err
	}
	unlock, err := e.locks.Lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()

	n, err := e.nets.Get(netIDOrName)
	if err != nil {
		return mapNetworkError(err)
	}
	if err := e.nets.Disconnect(ctx, n.ID, id, force); err != nil && !force {
		return mapNetworkError(err)
	}
	if err := e.update(id, func(cur *types.Container) error {
		delete(cur.NetworkSettings.Networks, n.Name)
		return nil
	}); err != nil {
		return err
	}
	e.bus.Publish(events.Network(events.ActionDisconnect, n, id))
	return nil
}

// NetworkPrune removes every unused network and reports what went.
func (e *Engine) NetworkPrune(ctx context.Context) ([]string, error) {
	if err := e.checkOpen(); err != nil {
		return nil, err
	}
	var removed []string
	for _, n := range e.nets.List() {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		if n.Name == network.DefaultNetworkName || len(n.Containers) > 0 {
			continue
		}
		if err := e.NetworkRemove(ctx, n.ID); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return removed, err
		}
		removed = append(removed, n.Name)
	}
	return removed, nil
}

// mapNetworkError translates the network manager's sentinels into the
// engine's, so the API layer has one vocabulary to map onto HTTP statuses.
func mapNetworkError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, network.ErrNotFound):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case errors.Is(err, network.ErrExists), errors.Is(err, network.ErrInUse):
		return fmt.Errorf("%w: %w", ErrConflict, err)
	case errors.Is(err, network.ErrInvalidConfig):
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	case errors.Is(err, network.ErrUnsupported):
		return fmt.Errorf("%w: %w", ErrUnsupported, err)
	default:
		return err
	}
}
