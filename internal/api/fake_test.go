package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/rahuldhali/hull/internal/engine"
	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/logbuf"
	"github.com/rahuldhali/hull/internal/network"
	"github.com/rahuldhali/hull/internal/oci/registry"
	"github.com/rahuldhali/hull/internal/snapshot"
	"github.com/rahuldhali/hull/internal/types"
	"github.com/rahuldhali/hull/internal/volume"
)

// fakeBackend is an in-memory Backend. It exists so the whole HTTP surface can
// be exercised — routing, version gating, filters, error shapes, the progress
// encoder and the hijack handshake — without a kernel, an overlay mount, a
// bridge or a registry.
type fakeBackend struct {
	mu sync.Mutex

	containers map[string]*types.Container
	images     map[string]*types.Image
	networks   map[string]*types.Network
	volumes    map[string]*types.Volume
	execs      map[string]*engine.ExecInspect
	warnings   map[string][]string

	bus  *events.Bus
	root string

	clients int

	// Hooks that let one test bend one call without a whole new fake.
	pullFn   func(ctx context.Context, ref string, plat *types.Platform, progress func(registry.ProgressEvent)) (*types.Image, error)
	attachFn func(ctx context.Context, id string, opts engine.AttachConfig) error
	execFn   func(ctx context.Context, execID string, opts engine.AttachConfig) error
	logsFn   func(ctx context.Context, id string, opts logbuf.ReadOptions, w io.Writer, framed bool) error
	statsFn  func(ctx context.Context, id string, stream bool, fn func(types.Stats) error) error
	waitFn   func(ctx context.Context, id, condition string) (int, error)
}

// newFakeBackend returns an empty fake.
func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		containers: map[string]*types.Container{},
		images:     map[string]*types.Image{},
		networks:   map[string]*types.Network{},
		volumes:    map[string]*types.Volume{},
		execs:      map[string]*engine.ExecInspect{},
		warnings:   map[string][]string{},
		bus:        events.NewBus(16),
		root:       "/var/lib/hull",
	}
}

// addContainer registers a container with the fake.
func (f *fakeBackend) addContainer(c *types.Container) *types.Container {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.containers[c.ID] = c
	return c
}

// find resolves an id, id prefix or name.
func (f *fakeBackend) find(idOrName string) (*types.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.containers[idOrName]; ok {
		return c, nil
	}
	for _, c := range f.containers {
		if c.Name == idOrName || (len(idOrName) >= 3 && len(c.ID) >= len(idOrName) && c.ID[:len(idOrName)] == idOrName) {
			return c, nil
		}
	}
	return nil, fmt.Errorf("%w: container %s", engine.ErrNotFound, idOrName)
}

func (f *fakeBackend) Create(_ context.Context, name string, cfg types.ContainerConfig, host types.HostConfig, imageRef string) (*types.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.images[imageRef]; !ok {
		return nil, fmt.Errorf("%w: image %s", engine.ErrNotFound, imageRef)
	}
	for _, c := range f.containers {
		if c.Name == name && name != "" {
			return nil, fmt.Errorf("%w: the name %q is already in use", engine.ErrConflict, name)
		}
	}
	if name == "" {
		name = fmt.Sprintf("generated-%d", len(f.containers))
	}
	id := fmt.Sprintf("%064x", len(f.containers)+1)
	c := &types.Container{
		ID:         id,
		Name:       name,
		Created:    time.Unix(1700000000, 0).UTC(),
		Image:      "sha256:" + imageRef,
		ImageRef:   imageRef,
		Config:     cfg,
		HostConfig: host,
		State:      types.StateCreated,
		NetworkSettings: types.NetworkSettings{
			Networks: map[string]types.EndpointSettings{},
			Ports:    map[string][]types.PortBinding{},
		},
	}
	f.containers[id] = c
	return c, nil
}

func (f *fakeBackend) Inspect(_ context.Context, idOrName string) (*types.Container, error) {
	return f.find(idOrName)
}

func (f *fakeBackend) List(_ context.Context, opts engine.ListOptions) ([]*types.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*types.Container, 0, len(f.containers))
	for _, c := range f.containers {
		if !opts.All && c.State != types.StateRunning {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeBackend) Start(_ context.Context, idOrName string, _ *engine.AttachConfig) error {
	c, err := f.find(idOrName)
	if err != nil {
		return err
	}
	if c.State == types.StateRunning {
		return fmt.Errorf("%w: already running", engine.ErrRunning)
	}
	c.State = types.StateRunning
	c.Pid = 4242
	c.StartedAt = time.Unix(1700000100, 0).UTC()
	return nil
}

func (f *fakeBackend) Stop(_ context.Context, idOrName string, _ *int) error {
	c, err := f.find(idOrName)
	if err != nil {
		return err
	}
	if c.State != types.StateRunning {
		return fmt.Errorf("%w: not running", engine.ErrNotRunning)
	}
	c.State = types.StateExited
	return nil
}

func (f *fakeBackend) Restart(_ context.Context, idOrName string, _ *int) error {
	_, err := f.find(idOrName)
	return err
}

func (f *fakeBackend) Kill(_ context.Context, idOrName, _ string) error {
	_, err := f.find(idOrName)
	return err
}

func (f *fakeBackend) Pause(_ context.Context, idOrName string) error {
	c, err := f.find(idOrName)
	if err != nil {
		return err
	}
	c.State = types.StatePaused
	return nil
}

func (f *fakeBackend) Unpause(_ context.Context, idOrName string) error {
	c, err := f.find(idOrName)
	if err != nil {
		return err
	}
	c.State = types.StateRunning
	return nil
}

func (f *fakeBackend) Remove(_ context.Context, idOrName string, force, _ bool) error {
	c, err := f.find(idOrName)
	if err != nil {
		return err
	}
	if c.State == types.StateRunning && !force {
		return fmt.Errorf("%w: container is running", engine.ErrRunning)
	}
	f.mu.Lock()
	delete(f.containers, c.ID)
	f.mu.Unlock()
	return nil
}

func (f *fakeBackend) Rename(_ context.Context, idOrName, newName string) error {
	c, err := f.find(idOrName)
	if err != nil {
		return err
	}
	c.Name = newName
	return nil
}

func (f *fakeBackend) Update(_ context.Context, idOrName string, r types.Resources, _ *types.RestartPolicy) error {
	c, err := f.find(idOrName)
	if err != nil {
		return err
	}
	c.HostConfig.Resources = r
	return nil
}

func (f *fakeBackend) Wait(ctx context.Context, idOrName, condition string) (int, error) {
	if f.waitFn != nil {
		return f.waitFn(ctx, idOrName, condition)
	}
	c, err := f.find(idOrName)
	if err != nil {
		return 0, err
	}
	return c.ExitCode, nil
}

func (f *fakeBackend) Resize(_ context.Context, idOrName string, _, _ uint16) error {
	_, err := f.find(idOrName)
	return err
}

func (f *fakeBackend) Top(_ context.Context, idOrName, _ string) (engine.TopResult, error) {
	if _, err := f.find(idOrName); err != nil {
		return engine.TopResult{}, err
	}
	return engine.TopResult{
		Titles:    []string{"PID", "CMD"},
		Processes: [][]string{{"1", "/bin/sh"}},
	}, nil
}

func (f *fakeBackend) Logs(ctx context.Context, idOrName string, opts logbuf.ReadOptions, w io.Writer, framed bool) error {
	if f.logsFn != nil {
		return f.logsFn(ctx, idOrName, opts, w, framed)
	}
	if _, err := f.find(idOrName); err != nil {
		return err
	}
	_, err := w.Write([]byte("hello\n"))
	return err
}

func (f *fakeBackend) Attach(ctx context.Context, idOrName string, opts engine.AttachConfig) error {
	if f.attachFn != nil {
		return f.attachFn(ctx, idOrName, opts)
	}
	if opts.Stdout != nil {
		_, _ = opts.Stdout.Write([]byte("attached"))
	}
	return nil
}

func (f *fakeBackend) Stats(ctx context.Context, idOrName string, stream bool, fn func(types.Stats) error) error {
	if f.statsFn != nil {
		return f.statsFn(ctx, idOrName, stream, fn)
	}
	if _, err := f.find(idOrName); err != nil {
		return err
	}
	return fn(types.Stats{
		Read:        time.Unix(1700000200, 0).UTC(),
		CPUUsage:    1000,
		SystemUsage: 2000,
		MemoryUsage: 4096,
		MemoryLimit: 8192,
		OnlineCPUs:  4,
	})
}

func (f *fakeBackend) Diff(_ context.Context, idOrName string) ([]snapshot.Change, error) {
	if _, err := f.find(idOrName); err != nil {
		return nil, err
	}
	return []snapshot.Change{
		{Path: "/etc/hosts", Kind: snapshot.KindModified},
		{Path: "/new", Kind: snapshot.KindAdded},
		{Path: "/gone", Kind: snapshot.KindDeleted},
	}, nil
}

func (f *fakeBackend) Export(_ context.Context, idOrName string, w io.Writer) error {
	if _, err := f.find(idOrName); err != nil {
		return err
	}
	_, err := w.Write([]byte("tarbytes"))
	return err
}

func (f *fakeBackend) CopyFrom(_ context.Context, idOrName, srcPath string) (io.ReadCloser, engine.CopyStat, error) {
	if _, err := f.find(idOrName); err != nil {
		return nil, engine.CopyStat{}, err
	}
	stat := engine.CopyStat{Name: "file", Size: 3, Mode: 0o644, Mtime: time.Unix(1700000300, 0).UTC()}
	return io.NopCloser(stringReader("abc")), stat, nil
}

func (f *fakeBackend) CopyTo(_ context.Context, idOrName, _ string, r io.Reader, _ engine.CopyOptions) error {
	if _, err := f.find(idOrName); err != nil {
		return err
	}
	_, err := io.Copy(io.Discard, r)
	return err
}

func (f *fakeBackend) Commit(_ context.Context, idOrName string, _ engine.CommitOptions) (*types.Image, error) {
	if _, err := f.find(idOrName); err != nil {
		return nil, err
	}
	return &types.Image{ID: "sha256:committed"}, nil
}

func (f *fakeBackend) Prune(_ context.Context, _ map[string][]string) (engine.PruneResult, error) {
	return engine.PruneResult{}, nil
}

func (f *fakeBackend) Warnings(_ context.Context, idOrName string) ([]string, error) {
	c, err := f.find(idOrName)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.warnings[c.ID], nil
}

func (f *fakeBackend) Exec(_ context.Context, idOrName string, cfg engine.ExecConfig) (string, error) {
	c, err := f.find(idOrName)
	if err != nil {
		return "", err
	}
	if c.State != types.StateRunning {
		return "", fmt.Errorf("%w: not running", engine.ErrNotRunning)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	id := fmt.Sprintf("exec%d", len(f.execs)+1)
	f.execs[id] = &engine.ExecInspect{
		ID:           id,
		ContainerID:  c.ID,
		Cmd:          cfg.Cmd,
		Tty:          cfg.Tty,
		AttachStdin:  cfg.AttachStdin,
		AttachStdout: cfg.AttachStdout,
		AttachStderr: cfg.AttachStderr,
		User:         cfg.User,
	}
	return id, nil
}

func (f *fakeBackend) ExecStart(ctx context.Context, execID string, opts engine.AttachConfig) error {
	if f.execFn != nil {
		return f.execFn(ctx, execID, opts)
	}
	f.mu.Lock()
	_, ok := f.execs[execID]
	f.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: exec %s", engine.ErrNotFound, execID)
	}
	if opts.Stdout != nil {
		_, _ = opts.Stdout.Write([]byte("exec-output"))
	}
	return nil
}

func (f *fakeBackend) ExecInspect(_ context.Context, execID string) (*engine.ExecInspect, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.execs[execID]
	if !ok {
		return nil, fmt.Errorf("%w: exec %s", engine.ErrNotFound, execID)
	}
	return rec, nil
}

func (f *fakeBackend) ExecResize(_ context.Context, execID string, _, _ uint16) error {
	_, err := f.ExecInspect(context.Background(), execID)
	return err
}

func (f *fakeBackend) Pull(ctx context.Context, ref string, plat *types.Platform, progress func(registry.ProgressEvent)) (*types.Image, error) {
	if f.pullFn != nil {
		return f.pullFn(ctx, ref, plat, progress)
	}
	if progress != nil {
		progress(registry.ProgressEvent{Digest: "sha256:" + fmt.Sprintf("%064d", 1), Status: registry.StatusDownloading, Current: 5, Total: 10})
		progress(registry.ProgressEvent{Digest: "sha256:" + fmt.Sprintf("%064d", 1), Status: registry.StatusDone})
	}
	img := &types.Image{ID: "sha256:pulled", RepoTags: []string{ref}}
	f.mu.Lock()
	f.images[ref] = img
	f.mu.Unlock()
	return img, nil
}

func (f *fakeBackend) Push(_ context.Context, ref string, progress func(registry.ProgressEvent)) error {
	if progress != nil {
		progress(registry.ProgressEvent{Digest: "sha256:abc", Status: registry.StatusDone})
	}
	return nil
}

func (f *fakeBackend) Images(_ context.Context, _ engine.ImageListOptions) ([]*types.Image, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*types.Image, 0, len(f.images))
	seen := map[string]bool{}
	for _, img := range f.images {
		if seen[img.ID] {
			continue
		}
		seen[img.ID] = true
		out = append(out, img)
	}
	return out, nil
}

func (f *fakeBackend) ImageInspect(_ context.Context, ref string) (*types.Image, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if img, ok := f.images[ref]; ok {
		return img, nil
	}
	return nil, fmt.Errorf("%w: image %s", engine.ErrNotFound, ref)
}

func (f *fakeBackend) ImageRemove(_ context.Context, ref string, _, _ bool) ([]engine.ImageDelete, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	img, ok := f.images[ref]
	if !ok {
		return nil, fmt.Errorf("%w: image %s", engine.ErrNotFound, ref)
	}
	delete(f.images, ref)
	return []engine.ImageDelete{{Untagged: ref}, {Deleted: img.ID}}, nil
}

func (f *fakeBackend) ImageHistory(_ context.Context, ref string) ([]engine.HistoryEntry, error) {
	if _, err := f.ImageInspect(context.Background(), ref); err != nil {
		return nil, err
	}
	return []engine.HistoryEntry{{ID: "sha256:pulled", Created: time.Unix(1700000000, 0), CreatedBy: "CMD"}}, nil
}

func (f *fakeBackend) Tag(_ context.Context, src, target string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	img, ok := f.images[src]
	if !ok {
		return fmt.Errorf("%w: image %s", engine.ErrNotFound, src)
	}
	f.images[target] = img
	return nil
}

func (f *fakeBackend) Save(_ context.Context, _ []string, w io.Writer) error {
	_, err := w.Write([]byte("image-archive"))
	return err
}

func (f *fakeBackend) Load(_ context.Context, r io.Reader, _ bool, progress func(string)) error {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	if progress != nil {
		progress("Loaded image: alpine:3.20")
	}
	return nil
}

func (f *fakeBackend) Lockfile(_ context.Context, refs []string) ([]engine.LockEntry, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	f.mu.Lock()
	_, ok := f.images[refs[0]]
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: image %s", engine.ErrNotFound, refs[0])
	}
	return []engine.LockEntry{{
		Ref:       refs[0],
		Resolved:  "docker.io/library/" + refs[0],
		Digest:    "sha256:deadbeef",
		MediaType: "application/vnd.oci.image.index.v1+json",
		Size:      1234,
		Platform:  "linux/amd64",
	}}, nil
}

func (f *fakeBackend) Login(_ context.Context, _, user, pass string) (string, error) {
	if user == "" || pass == "" {
		return "", errors.New("unauthorized: bad credentials")
	}
	return "Login Succeeded", nil
}

func (f *fakeBackend) NetworkCreate(_ context.Context, name string, cfg network.CreateConfig) (*types.Network, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.networks {
		if n.Name == name {
			return nil, fmt.Errorf("%w: network %s exists", engine.ErrConflict, name)
		}
	}
	n := &types.Network{
		ID:      fmt.Sprintf("net%d", len(f.networks)+1),
		Name:    name,
		Driver:  cfg.Driver,
		Scope:   "local",
		Created: time.Unix(1700000000, 0).UTC(),
		IPAM:    types.IPAMConfig{Driver: "default", Subnet: cfg.Subnet, Gateway: cfg.Gateway},
		Labels:  cfg.Labels,
		Options: cfg.Options,
	}
	f.networks[n.ID] = n
	return n, nil
}

func (f *fakeBackend) NetworkRemove(_ context.Context, idOrName string) error {
	n, err := f.NetworkInspect(context.Background(), idOrName)
	if err != nil {
		return err
	}
	f.mu.Lock()
	delete(f.networks, n.ID)
	f.mu.Unlock()
	return nil
}

func (f *fakeBackend) NetworkList(_ context.Context) ([]*types.Network, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*types.Network, 0, len(f.networks))
	for _, n := range f.networks {
		out = append(out, n)
	}
	return out, nil
}

func (f *fakeBackend) NetworkInspect(_ context.Context, idOrName string) (*types.Network, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n, ok := f.networks[idOrName]; ok {
		return n, nil
	}
	for _, n := range f.networks {
		if n.Name == idOrName {
			return n, nil
		}
	}
	return nil, fmt.Errorf("%w: network %s", engine.ErrNotFound, idOrName)
}

func (f *fakeBackend) NetworkConnect(_ context.Context, netIDOrName, ctrIDOrName string, _ network.EndpointConfig) error {
	if _, err := f.NetworkInspect(context.Background(), netIDOrName); err != nil {
		return err
	}
	_, err := f.find(ctrIDOrName)
	return err
}

func (f *fakeBackend) NetworkDisconnect(_ context.Context, netIDOrName, ctrIDOrName string, _ bool) error {
	return f.NetworkConnect(context.Background(), netIDOrName, ctrIDOrName, network.EndpointConfig{})
}

func (f *fakeBackend) NetworkPrune(_ context.Context) ([]string, error) { return nil, nil }

func (f *fakeBackend) VolumeCreate(_ context.Context, name, driver string, opts, labels map[string]string) (*types.Volume, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if name == "" {
		name = fmt.Sprintf("vol%d", len(f.volumes)+1)
	}
	v := &types.Volume{
		Name:       name,
		Driver:     orDefault(driver, "local"),
		Mountpoint: "/var/lib/hull/volumes/" + name + "/_data",
		Created:    time.Unix(1700000000, 0).UTC(),
		Labels:     labels,
		Options:    opts,
		Scope:      "local",
	}
	f.volumes[name] = v
	return v, nil
}

func (f *fakeBackend) VolumeInspect(_ context.Context, name string) (*types.Volume, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.volumes[name]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("%w: volume %s", engine.ErrNotFound, name)
}

func (f *fakeBackend) VolumeList(_ context.Context, _ volume.Filters) ([]*types.Volume, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*types.Volume, 0, len(f.volumes))
	for _, v := range f.volumes {
		out = append(out, v)
	}
	return out, nil
}

func (f *fakeBackend) VolumeRemove(_ context.Context, name string, _ bool) error {
	if _, err := f.VolumeInspect(context.Background(), name); err != nil {
		return err
	}
	f.mu.Lock()
	delete(f.volumes, name)
	f.mu.Unlock()
	return nil
}

func (f *fakeBackend) VolumePrune(_ context.Context, _ volume.Filters) ([]string, int64, error) {
	return nil, 0, nil
}

func (f *fakeBackend) Info(_ context.Context) (engine.Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return engine.Info{
		ID:             "hull-test",
		Name:           "testhost",
		ServerVersion:  "0.1.0-test",
		Containers:     len(f.containers),
		Images:         len(f.images),
		Driver:         "overlay2",
		LoggingDriver:  "json-file",
		CgroupDriver:   "cgroupfs",
		CgroupVersion:  "1 (hybrid, no v2 controllers delegated)",
		OSType:         "linux",
		Architecture:   "amd64",
		KernelVersion:  "5.15.167.4",
		DataRoot:       f.root,
		DockerRootDir:  f.root,
		DefaultRuntime: "hull",
		Runtimes:       []string{"hull", "crun"},
		Warnings:       []string{"cgroup v2 controllers are not delegated; resource limits will not be enforced"},
		Plugins: engine.InfoPlugins{
			Volume:  []string{"local"},
			Network: []string{"bridge", "host", "none"},
			Log:     []string{"json-file", "none"},
		},
	}, nil
}

func (f *fakeBackend) Events() *events.Bus { return f.bus }

func (f *fakeBackend) DataRoot() string { return f.root }

func (f *fakeBackend) ClientConnected() {
	f.mu.Lock()
	f.clients++
	f.mu.Unlock()
}

func (f *fakeBackend) ClientDisconnected() {
	f.mu.Lock()
	f.clients--
	f.mu.Unlock()
}

// stringReader is a tiny io.Reader over a string, kept local so the fake does
// not pull in strings just for one call.
type stringReader string

// Read copies the string out once.
func (s stringReader) Read(p []byte) (int, error) {
	if len(s) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s)
	return n, io.EOF
}

// compile-time proof the fake really is a Backend.
var _ Backend = (*fakeBackend)(nil)
