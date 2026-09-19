package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/idutil"
	"github.com/rahuldhali/hull/internal/network"
	"github.com/rahuldhali/hull/internal/state"
	"github.com/rahuldhali/hull/internal/types"
)

// unwinder collects the compensating actions of a partially built container so
// a failure anywhere can undo everything already done, in reverse order.
//
// A failed Create must leave nothing behind: no mounted snapshot, no volume
// reference, no reserved name, no allocated address, no half-written state.
// Doing that with defers alone gets unreadable fast, so the steps are pushed
// onto a stack and popped on failure.
type unwinder struct {
	steps []func()
	log   func(error)
}

// push adds a compensating action.
func (u *unwinder) push(fn func()) { u.steps = append(u.steps, fn) }

// unwind runs every compensating action in reverse order.
func (u *unwinder) unwind() {
	for i := len(u.steps) - 1; i >= 0; i-- {
		u.steps[i]()
	}
	u.steps = nil
}

// cancel discards the compensating actions; the object is now owned by the
// caller.
func (u *unwinder) cancel() { u.steps = nil }

// Create builds a container from an image and leaves it in the "created"
// state, with its rootfs mounted, its volumes resolved and its OCI bundle
// written, but nothing running.
//
// The image is pulled when it is not already present. An empty name is
// generated. On any failure every step already taken is undone in reverse
// order, so a failed Create leaves no snapshot mounted, no volume referenced,
// no name reserved and no address allocated.
func (e *Engine) Create(ctx context.Context, name string, cfg types.ContainerConfig, host types.HostConfig, imageRef string) (*types.Container, error) {
	if err := e.checkOpen(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(imageRef) == "" {
		return nil, fmt.Errorf("%w: no image was given", ErrInvalid)
	}

	img, err := e.resolveImageForCreate(ctx, imageRef, host)
	if err != nil {
		return nil, err
	}

	merged, err := MergeImageConfig(cfg, img)
	if err != nil {
		return nil, err
	}
	host = e.applyHostDefaults(host)

	id := idutil.NewID()
	un := &unwinder{log: func(err error) {
		e.log.Warn("hull: unwinding a failed create", "container", idShort(id), "err", err)
	}}
	defer func() {
		if err != nil {
			un.unwind()
		}
	}()

	// 1. Reserve the name. Doing it first means a duplicate name costs
	//    nothing: no directory, no mount, no volume.
	if name == "" {
		name = e.state.GenerateName()
	}
	if err = e.state.ReserveName(name, id); err != nil {
		if errors.Is(err, state.ErrNameInUse) {
			return nil, fmt.Errorf("%w: the name %q is already in use", ErrConflict, name)
		}
		if errors.Is(err, state.ErrInvalidName) {
			return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		return nil, fmt.Errorf("engine: reserve the name %q: %w", name, err)
	}
	reserved := name
	un.push(func() {
		if rerr := e.state.ReleaseName(reserved); rerr != nil {
			un.log(rerr)
		}
	})

	if merged.Hostname == "" {
		merged.Hostname = idShort(id)
	}
	c := &types.Container{
		ID:         id,
		Name:       name,
		Created:    e.now(),
		Image:      img.ID,
		ImageRef:   imageRef,
		Config:     merged,
		HostConfig: host,
		State:      types.StateCreated,
		NetworkSettings: types.NetworkSettings{
			Networks: map[string]types.EndpointSettings{},
			Ports:    map[string][]types.PortBinding{},
		},
	}

	// 2. The container directory holds the bundle, the log, the shim socket
	//    and the overlay dirs; every later step writes into it.
	dir := e.containerDir(id)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("engine: create %s: %w", dir, err)
	}
	un.push(func() {
		if rerr := os.RemoveAll(dir); rerr != nil {
			un.log(rerr)
		}
	})

	// 3. Mount the image's layers as the container's rootfs. Volume seeding
	//    reads through it, and bundle resolves --user against its
	//    /etc/passwd, so it has to be live before either.
	var rootfs string
	if rootfs, err = e.snaps.Mount(ctx, id, img.ChainID, host.ReadonlyRootfs); err != nil {
		return nil, fmt.Errorf("engine: mount the rootfs for %s: %w", idShort(id), err)
	}
	c.RootFS = rootfs
	c.SnapshotID = img.ChainID
	c.BundleDir = dir
	un.push(func() {
		if rerr := e.snaps.Remove(context.WithoutCancel(ctx), id); rerr != nil {
			un.log(rerr)
		}
	})

	// 4. Volumes. Resolve materialises every named and anonymous volume, takes
	//    a reference for this container and seeds a fresh one from the image.
	var mounts []types.Mount
	if mounts, err = e.vols.Resolve(ctx, c); err != nil {
		return nil, fmt.Errorf("engine: resolve mounts for %s: %w", idShort(id), err)
	}
	un.push(func() {
		if rerr := e.vols.Release(context.WithoutCancel(ctx), c, true); rerr != nil {
			un.log(rerr)
		}
	})
	c.HostConfig.Mounts = mounts
	c.HostConfig.Binds = nil
	c.HostConfig.Tmpfs = nil

	// 5. The sandbox files have to exist before the bundle binds them, and
	//    they are refreshed once the address is allocated at start.
	if err = e.nets.ConfigureSandbox(ctx, 0, c); err != nil {
		return nil, fmt.Errorf("engine: write the sandbox files for %s: %w", idShort(id), err)
	}
	if err = e.syncSandboxFiles(id); err != nil {
		return nil, err
	}

	// 6. The OCI bundle. Its warnings are the ones that say a resource limit
	//    could not be enforced here, so they are recorded rather than logged.
	var warnings []string
	warnings, err = e.generateBundle(c, img)
	if err != nil {
		return nil, err
	}
	e.setWarnings(id, warnings)
	for _, w := range warnings {
		e.log.Warn("hull: container warning", "container", idShort(id), "warning", w)
	}

	// 7. Network endpoints. The veth cannot be created yet: the manager needs
	//    a live network namespace and the container has no pid until its shim
	//    creates it, so Start does the attachment. What is recorded here is
	//    the intent, and it is validated now so a typo in --network fails at
	//    create time rather than at start.
	var planned []plannedEndpoint
	if planned, err = e.planEndpoints(c); err != nil {
		return nil, err
	}
	for _, p := range planned {
		c.NetworkSettings.Networks[p.name] = types.EndpointSettings{NetworkID: p.id, Aliases: p.cfg.Aliases}
	}

	// 8. Persist. Everything above is now recoverable from disk.
	if err = e.state.PutContainer(c); err != nil {
		return nil, fmt.Errorf("engine: persist container %s: %w", idShort(id), err)
	}
	un.push(func() {
		if rerr := e.state.DeleteContainer(id); rerr != nil {
			un.log(rerr)
		}
	})

	un.cancel()
	e.runtimeState(id)
	e.emit(events.ActionCreate, c, nil)
	return copyContainer(c), nil
}

// plannedEndpoint is one network attachment Create validated and Start will
// realise.
type plannedEndpoint struct {
	// id and name identify the network.
	id   string
	name string
	// cfg is the per-attachment configuration.
	cfg network.EndpointConfig
}

// planEndpoints resolves the container's network mode into the attachments
// Start must make. "host", "none" and "container:<id>" produce none, because
// they are handled by the runtime's namespace configuration rather than by a
// veth pair.
func (e *Engine) planEndpoints(c *types.Container) ([]plannedEndpoint, error) {
	mode := c.HostConfig.NetworkMode
	switch {
	case mode == "" || mode == "bridge" || mode == "default":
		mode = network.DefaultNetworkName
	case mode == "host" || mode == "none":
		return nil, nil
	case strings.HasPrefix(mode, "container:"):
		return nil, nil
	}
	n, err := e.nets.Get(mode)
	if err != nil {
		return nil, fmt.Errorf("%w: network %q: %w", ErrNotFound, mode, err)
	}
	aliases := []string{idShort(c.ID)}
	if c.Name != "" {
		aliases = append(aliases, c.Name)
	}
	return []plannedEndpoint{{
		id:   n.ID,
		name: n.Name,
		cfg:  network.EndpointConfig{Aliases: aliases},
	}}, nil
}

// resolveImageForCreate finds the image locally, pulling it when it is absent.
//
// hull's pull policy at create time is Docker's "missing": a reference already
// in the local store is used as it is, and only an absent one goes to the
// network. A digest reference is never re-pulled, because a digest cannot have
// changed.
func (e *Engine) resolveImageForCreate(ctx context.Context, ref string, host types.HostConfig) (*types.Image, error) {
	img, err := e.images.Get(ref)
	if err == nil {
		return img, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	pulled, perr := e.Pull(ctx, ref, platformFor(host), nil)
	if perr != nil {
		return nil, fmt.Errorf("engine: %s is not present locally and could not be pulled: %w", ref, perr)
	}
	return pulled, nil
}

// platformFor returns the platform a create should resolve its image for. hull
// has no per-container platform field yet, so this is always the host's; the
// hook exists so adding --platform later touches one place.
func platformFor(types.HostConfig) *types.Platform { return nil }

// Inspect returns the full record of one container.
func (e *Engine) Inspect(ctx context.Context, idOrName string) (*types.Container, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := e.lookup(idOrName)
	if err != nil {
		return nil, err
	}
	e.refreshHealthView(c)
	return copyContainer(c), nil
}

// refreshHealthView fills in a health record for a container that has a
// healthcheck configured but has never been probed, so inspect shows
// "starting" rather than nothing at all.
func (e *Engine) refreshHealthView(c *types.Container) {
	if c.Config.Healthcheck == nil || c.Health != nil {
		return
	}
	if c.State == types.StateRunning {
		c.Health = &types.HealthState{Status: HealthStarting}
	}
}

// Rename gives a container a new name, moving the reservation atomically
// enough that a failure leaves the old name in place.
func (e *Engine) Rename(ctx context.Context, idOrName, newName string) error {
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
	if c.Name == newName {
		return nil
	}
	if err := state.ValidateName(newName); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := e.state.ReserveName(newName, id); err != nil {
		if errors.Is(err, state.ErrNameInUse) {
			return fmt.Errorf("%w: the name %q is already in use", ErrConflict, newName)
		}
		return fmt.Errorf("engine: reserve the name %q: %w", newName, err)
	}
	old := c.Name
	if err := e.update(id, func(cur *types.Container) error {
		cur.Name = newName
		return nil
	}); err != nil {
		if rerr := e.state.ReleaseName(newName); rerr != nil {
			e.log.Warn("hull: could not release a name after a failed rename", "name", newName, "err", rerr)
		}
		return err
	}
	if err := e.state.ReleaseName(old); err != nil {
		e.log.Warn("hull: could not release the old name after a rename", "name", old, "err", err)
	}
	c.Name = newName
	e.emit(events.ActionRename, c, map[string]string{"oldName": old})
	return nil
}

// Update changes a running or stopped container's resource limits and restart
// policy in place.
//
// Limits that this host cannot enforce are reported rather than silently
// dropped: the cgroup write is attempted, and a refusal becomes a warning the
// caller can show, because a container quietly running without its memory cap
// is exactly the failure mode hull exists to avoid.
func (e *Engine) Update(ctx context.Context, idOrName string, r types.Resources, rp *types.RestartPolicy) error {
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

	if err := e.update(id, func(cur *types.Container) error {
		cur.HostConfig.Resources = r
		if rp != nil {
			cur.HostConfig.RestartPolicy = *rp
		}
		return nil
	}); err != nil {
		return err
	}

	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	if warn := e.applyResources(id, r); warn != "" {
		e.setWarnings(id, append(mustWarnings(e, ctx, id), warn))
		e.log.Warn("hull: resource update could not be enforced", "container", idShort(id), "warning", warn)
	}
	e.emit(events.ActionUpdate, c, nil)
	return nil
}

// mustWarnings reads the recorded warnings, ignoring a read failure: it is
// only used to append to them.
func mustWarnings(e *Engine, ctx context.Context, id string) []string {
	w, err := e.Warnings(ctx, id)
	if err != nil {
		return nil
	}
	return w
}

// stopTimeoutFor resolves the effective stop timeout in seconds.
func stopTimeoutFor(c *types.Container, override *int) time.Duration {
	secs := DefaultStopTimeout
	if c.Config.StopTimeout != nil && *c.Config.StopTimeout >= 0 {
		secs = *c.Config.StopTimeout
	}
	if override != nil && *override >= 0 {
		secs = *override
	}
	return time.Duration(secs) * time.Second
}
