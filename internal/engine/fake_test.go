package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/network"
	"github.com/rahuldhali/hull/internal/oci/reference"
	"github.com/rahuldhali/hull/internal/oci/registry"
	"github.com/rahuldhali/hull/internal/shim"
	"github.com/rahuldhali/hull/internal/snapshot"
	"github.com/rahuldhali/hull/internal/state"
	"github.com/rahuldhali/hull/internal/types"
	"github.com/rahuldhali/hull/internal/volume"
)

// The fakes below let the whole lifecycle be exercised without root, a kernel
// namespace, an overlay mount, a bridge or a registry. They are deliberately
// in-memory rather than "a smaller real thing": the point is to test the
// engine's orchestration, not the subsystems it orchestrates, which have their
// own tests.

// ---------- supervisor ----------

// fakeStream is an in-memory attach stream.
type fakeStream struct {
	terminal bool
	stdinW   io.WriteCloser
	stdout   io.Reader
	stderr   io.Reader
	outW     *io.PipeWriter
	errW     *io.PipeWriter

	once sync.Once
	done chan struct{}
	mu   sync.Mutex
	err  error
}

// newFakeStream builds a stream honouring the requested directions.
func newFakeStream(opts shim.AttachOptions, terminal bool) *fakeStream {
	s := &fakeStream{terminal: terminal, done: make(chan struct{})}
	if opts.Stdout || opts.Stderr || terminal {
		r, w := io.Pipe()
		s.stdout, s.outW = r, w
	}
	if opts.Stderr && !terminal {
		r, w := io.Pipe()
		s.stderr, s.errW = r, w
	}
	if opts.Stdin {
		s.stdinW = nopWriteCloser{io.Discard}
	}
	return s
}

// emit pushes bytes onto the stream's stdout, as a container would.
func (s *fakeStream) emit(b []byte) {
	if s.outW != nil {
		_, _ = s.outW.Write(b)
	}
}

func (s *fakeStream) Terminal() bool        { return s.terminal }
func (s *fakeStream) Stdin() io.WriteCloser { return s.stdinW }
func (s *fakeStream) Stdout() io.Reader     { return s.stdout }
func (s *fakeStream) Stderr() io.Reader     { return s.stderr }
func (s *fakeStream) Done() <-chan struct{} { return s.done }
func (s *fakeStream) Err() error            { s.mu.Lock(); defer s.mu.Unlock(); return s.err }

// Close ends the stream once.
func (s *fakeStream) Close() error {
	s.once.Do(func() {
		if s.outW != nil {
			_ = s.outW.Close()
		}
		if s.errW != nil {
			_ = s.errW.Close()
		}
		close(s.done)
	})
	return nil
}

// nopWriteCloser turns a writer into a WriteCloser.
type nopWriteCloser struct{ io.Writer }

// Close does nothing.
func (nopWriteCloser) Close() error { return nil }

// fakeExec is an in-memory exec handle.
type fakeExec struct {
	*fakeStream
	pid      int
	exitCode int
	waitErr  error
	resized  chan [2]uint16
}

func (e *fakeExec) Pid() int { return e.pid }

// Wait reports the configured exit code.
func (e *fakeExec) Wait(ctx context.Context) (int, error) {
	if e.waitErr != nil {
		return 0, e.waitErr
	}
	return e.exitCode, nil
}

// Resize records the requested size.
func (e *fakeExec) Resize(ctx context.Context, h, w uint16) error {
	select {
	case e.resized <- [2]uint16{h, w}:
	default:
	}
	return nil
}

// fakeSupervisor is an in-memory shim.
type fakeSupervisor struct {
	id string

	mu         sync.Mutex
	pid        int
	started    bool
	exited     bool
	exitCode   int
	oomKilled  bool
	signals    []syscall.Signal
	ignoreTerm bool
	acked      bool
	closed     bool
	stats      types.Stats
	streams    []*fakeStream

	startErr error
	execErr  error
	execCode int

	waitCh chan struct{}
}

// newFakeSupervisor builds a supervisor for a container id.
func newFakeSupervisor(id string, pid int) *fakeSupervisor {
	return &fakeSupervisor{id: id, pid: pid, waitCh: make(chan struct{})}
}

// Start releases the container.
func (f *fakeSupervisor) Start(ctx context.Context) error {
	if f.startErr != nil {
		return f.startErr
	}
	f.mu.Lock()
	f.started = true
	f.mu.Unlock()
	return nil
}

// State reports the container's state.
func (f *fakeSupervisor) State(ctx context.Context) (shim.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := shim.State{Pid: f.pid, ExitCode: f.exitCode, Exited: f.exited, OOMKilled: f.oomKilled}
	switch {
	case f.exited:
		st.Status = shim.StatusStopped
		st.Pid = 0
	case f.started:
		st.Status = shim.StatusRunning
	default:
		st.Status = shim.StatusCreated
	}
	return st, nil
}

// Kill records the signal and, unless the container is configured to ignore
// SIGTERM, exits.
func (f *fakeSupervisor) Kill(ctx context.Context, sig syscall.Signal, all bool) error {
	f.mu.Lock()
	f.signals = append(f.signals, sig)
	ignore := f.ignoreTerm && sig != sigKill
	f.mu.Unlock()
	if ignore {
		return nil
	}
	f.exit(128+int(sig), false)
	return nil
}

// exit marks the container exited exactly once.
func (f *fakeSupervisor) exit(code int, oom bool) {
	f.mu.Lock()
	if f.exited {
		f.mu.Unlock()
		return
	}
	f.exited, f.exitCode, f.oomKilled = true, code, oom
	f.mu.Unlock()
	close(f.waitCh)
}

// Wait blocks until the container exits.
func (f *fakeSupervisor) Wait(ctx context.Context) (int, error) {
	select {
	case <-f.waitCh:
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.exitCode, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// Resize is a no-op.
func (f *fakeSupervisor) Resize(ctx context.Context, h, w uint16) error { return nil }

// Stats returns the configured sample.
func (f *fakeSupervisor) Stats(ctx context.Context) (types.Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats, nil
}

// Ack records the daemon's acknowledgement.
func (f *fakeSupervisor) Ack(ctx context.Context) error {
	f.mu.Lock()
	f.acked = true
	f.mu.Unlock()
	return nil
}

// Shutdown stops the container.
func (f *fakeSupervisor) Shutdown(ctx context.Context) error {
	f.exit(143, false)
	return nil
}

// Attach opens an in-memory stream.
func (f *fakeSupervisor) Attach(ctx context.Context, opts shim.AttachOptions) (Stream, error) {
	s := newFakeStream(opts, false)
	f.mu.Lock()
	f.streams = append(f.streams, s)
	f.mu.Unlock()
	return s, nil
}

// Exec starts an in-memory process.
func (f *fakeSupervisor) Exec(ctx context.Context, execID string, spec []byte, opts shim.AttachOptions) (ExecHandle, error) {
	if f.execErr != nil {
		return nil, f.execErr
	}
	s := newFakeStream(opts, false)
	h := &fakeExec{fakeStream: s, pid: f.pid + 1, exitCode: f.execCode, resized: make(chan [2]uint16, 4)}
	// A probe that reads output must see EOF, so the stream is closed as soon
	// as it is handed over.
	go s.Close()
	return h, nil
}

// Close detaches without touching the container.
func (f *fakeSupervisor) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

// fakeSpawner hands out fakeSupervisors.
type fakeSpawner struct {
	mu        sync.Mutex
	sups      map[string]*fakeSupervisor
	spawned   int
	spawnErr  error
	exits     map[string]shim.ExitStatus
	reconnect map[string]Supervisor
	nextPid   int
}

// newFakeSpawner builds an empty spawner.
func newFakeSpawner() *fakeSpawner {
	return &fakeSpawner{
		sups:      map[string]*fakeSupervisor{},
		exits:     map[string]shim.ExitStatus{},
		reconnect: map[string]Supervisor{},
		nextPid:   1000,
	}
}

// Spawn creates a supervisor for cfg.ID.
func (s *fakeSpawner) Spawn(ctx context.Context, cfg shim.Config) (Supervisor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.spawnErr != nil {
		return nil, s.spawnErr
	}
	s.spawned++
	s.nextPid++
	sup := newFakeSupervisor(cfg.ID, s.nextPid)
	s.sups[cfg.ID] = sup
	return sup, nil
}

// Reconnect returns a pre-seeded supervisor, or reports that the shim is gone.
func (s *fakeSpawner) Reconnect(ctx context.Context, containerDir string) (Supervisor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sup, ok := s.reconnect[filepath.Base(containerDir)]; ok {
		return sup, nil
	}
	return nil, fmt.Errorf("%w: no shim in %s", shim.ErrShimGone, containerDir)
}

// ReadExit returns a pre-seeded exit status.
func (s *fakeSpawner) ReadExit(containerDir string) (shim.ExitStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.exits[filepath.Base(containerDir)]; ok {
		return st, nil
	}
	return shim.ExitStatus{}, os.ErrNotExist
}

// supervisor returns the supervisor for a container, failing the test when
// there is none.
func (s *fakeSpawner) supervisor(t *testing.T, id string) *fakeSupervisor {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	sup, ok := s.sups[id]
	if !ok {
		t.Fatalf("no supervisor was spawned for %s", idShort(id))
	}
	return sup
}

// ---------- snapshotter ----------

// fakeSnapshotter keeps container rootfs directories on disk so bundle
// generation, which reads /etc/passwd, has something real to look at.
type fakeSnapshotter struct {
	root string

	mu        sync.Mutex
	mounted   map[string]bool
	removed   []string
	mountErr  error
	unmounted []string
	snapshots []snapshot.Info
	changes   []snapshot.Change
	cps       map[string][]snapshot.Checkpoint
}

// newFakeSnapshotter builds one rooted at dir.
func newFakeSnapshotter(dir string) *fakeSnapshotter {
	return &fakeSnapshotter{
		root:    dir,
		mounted: map[string]bool{},
		cps:     map[string][]snapshot.Checkpoint{},
	}
}

// mergedDir is where a container's rootfs lives.
func (f *fakeSnapshotter) mergedDir(id string) string { return filepath.Join(f.root, id, "merged") }

// Mount materialises a minimal rootfs.
func (f *fakeSnapshotter) Mount(ctx context.Context, id, chainID string, ro bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mountErr != nil {
		return "", f.mountErr
	}
	dir := f.mergedDir(id)
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "etc", "passwd"),
		[]byte("root:x:0:0:root:/root:/bin/sh\n"), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "etc", "group"), []byte("root:x:0:\n"), 0o644); err != nil {
		return "", err
	}
	f.mounted[id] = true
	return dir, nil
}

// Unmount marks the rootfs unmounted.
func (f *fakeSnapshotter) Unmount(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.mounted, id)
	f.unmounted = append(f.unmounted, id)
	return nil
}

// Remove unmounts and deletes the container's directories.
func (f *fakeSnapshotter) Remove(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.mounted, id)
	f.removed = append(f.removed, id)
	return os.RemoveAll(filepath.Join(f.root, id))
}

// IsMounted reports the recorded state.
func (f *fakeSnapshotter) IsMounted(id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mounted[id], nil
}

func (f *fakeSnapshotter) MergedPath(id string) (string, error) { return f.mergedDir(id), nil }
func (f *fakeSnapshotter) UpperPath(id string) (string, error) {
	return filepath.Join(f.root, id, "upper"), nil
}

func (f *fakeSnapshotter) Changes(ctx context.Context, id string) ([]snapshot.Change, error) {
	return f.changes, nil
}

func (f *fakeSnapshotter) Checkpoint(ctx context.Context, id, name string) (snapshot.Checkpoint, error) {
	return f.CheckpointCopy(ctx, id, name)
}

func (f *fakeSnapshotter) CheckpointCopy(ctx context.Context, id, name string) (snapshot.Checkpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := snapshot.Checkpoint{Name: name, ContainerID: id, Created: time.Now().UTC()}
	f.cps[id] = append(f.cps[id], cp)
	return cp, nil
}

func (f *fakeSnapshotter) ListCheckpoints(id string) ([]snapshot.Checkpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cps[id], nil
}

func (f *fakeSnapshotter) StatCheckpoint(id, name string) (snapshot.Checkpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, cp := range f.cps[id] {
		if cp.Name == name {
			return cp, nil
		}
	}
	return snapshot.Checkpoint{}, fmt.Errorf("%w: %s", snapshot.ErrNotFound, name)
}

func (f *fakeSnapshotter) DeleteCheckpoint(ctx context.Context, id, name string) error { return nil }
func (f *fakeSnapshotter) Restore(ctx context.Context, id, name string) error          { return nil }

func (f *fakeSnapshotter) DiffCheckpoints(ctx context.Context, id, a, b string) ([]snapshot.Change, error) {
	return f.changes, nil
}

func (f *fakeSnapshotter) Unpack(ctx context.Context, img *types.Image, store *content.Store, layers []types.Descriptor, progress func(string, string)) error {
	return nil
}

func (f *fakeSnapshotter) Exists(chainID string) bool { return true }
func (f *fakeSnapshotter) Stat(chainID string) (snapshot.Info, error) {
	return snapshot.Info{ChainID: chainID}, nil
}
func (f *fakeSnapshotter) List() ([]snapshot.Info, error) { return f.snapshots, nil }
func (f *fakeSnapshotter) RemoveSnapshot(ctx context.Context, chainID string) error {
	return nil
}
func (f *fakeSnapshotter) Cleanup(ctx context.Context) error   { return nil }
func (f *fakeSnapshotter) Usage(chainID string) (int64, error) { return 0, nil }

// ---------- networker ----------

// fakeNetworker records what the engine asked the network layer to do.
type fakeNetworker struct {
	root string

	mu           sync.Mutex
	nets         map[string]*types.Network
	connected    []string
	disconnected []string
	published    map[string][]network.PublishedPort
	unpublished  []string
	connectErr   error
	nextIP       int
}

// newFakeNetworker builds one with the default bridge network present.
func newFakeNetworker(root string) *fakeNetworker {
	return &fakeNetworker{
		root: root,
		nets: map[string]*types.Network{
			network.DefaultNetworkName: {
				ID:         "net0000000000000000000000000000000000000000000000000000000000000",
				Name:       network.DefaultNetworkName,
				Driver:     "bridge",
				IPAM:       types.IPAMConfig{Subnet: "10.66.0.0/24", Gateway: "10.66.0.1"},
				Containers: map[string]types.EndpointSettings{},
			},
		},
		published: map[string][]network.PublishedPort{},
		nextIP:    2,
	}
}

func (f *fakeNetworker) Init(ctx context.Context) error     { return nil }
func (f *fakeNetworker) Shutdown(ctx context.Context) error { return nil }

func (f *fakeNetworker) Create(ctx context.Context, name string, cfg network.CreateConfig) (*types.Network, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.nets[name]; ok {
		return nil, fmt.Errorf("%w: %s", network.ErrExists, name)
	}
	n := &types.Network{ID: "net-" + name, Name: name, Driver: "bridge", Containers: map[string]types.EndpointSettings{}}
	f.nets[name] = n
	return n, nil
}

func (f *fakeNetworker) Remove(ctx context.Context, idOrName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nets[idOrName]
	if !ok {
		return fmt.Errorf("%w: %s", network.ErrNotFound, idOrName)
	}
	if len(n.Containers) > 0 {
		return fmt.Errorf("%w: %s", network.ErrInUse, idOrName)
	}
	delete(f.nets, idOrName)
	return nil
}

func (f *fakeNetworker) Get(idOrName string) (*types.Network, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.nets {
		if n.Name == idOrName || n.ID == idOrName {
			return n, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", network.ErrNotFound, idOrName)
}

func (f *fakeNetworker) List() []*types.Network {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*types.Network, 0, len(f.nets))
	for _, n := range f.nets {
		out = append(out, n)
	}
	return out
}

func (f *fakeNetworker) Connect(ctx context.Context, netID string, c *types.Container, cfg network.EndpointConfig) (*types.EndpointSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.connectErr != nil {
		return nil, f.connectErr
	}
	if c.Pid <= 0 {
		return nil, fmt.Errorf("%w: no pid", network.ErrInvalidConfig)
	}
	f.connected = append(f.connected, c.ID)
	ip := fmt.Sprintf("10.66.0.%d", f.nextIP)
	f.nextIP++
	return &types.EndpointSettings{
		NetworkID:   netID,
		EndpointID:  "ep-" + idShort(c.ID),
		IPAddress:   ip,
		IPPrefixLen: 24,
		Gateway:     "10.66.0.1",
		Aliases:     cfg.Aliases,
	}, nil
}

func (f *fakeNetworker) Disconnect(ctx context.Context, netID, containerID string, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnected = append(f.disconnected, containerID)
	return nil
}

// ConfigureSandbox writes the three files the bundle binds.
func (f *fakeNetworker) ConfigureSandbox(ctx context.Context, pid int, c *types.Container) error {
	dir := filepath.Join(f.root, "containers", c.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, body := range map[string]string{
		"hostname":    c.Config.Hostname + "\n",
		"hosts":       "127.0.0.1 localhost\n",
		"resolv.conf": "nameserver 10.66.0.1\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeNetworker) PublishPorts(ctx context.Context, c *types.Container, bindings map[string][]types.PortBinding) ([]network.PublishedPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []network.PublishedPort
	for spec := range bindings {
		port, proto, err := network.ParsePortSpec(spec)
		if err != nil {
			return nil, err
		}
		out = append(out, network.PublishedPort{
			Proto: proto, HostIP: "0.0.0.0", HostPort: port,
			ContainerPort: port, ContainerID: c.ID,
		})
	}
	f.published[c.ID] = out
	return out, nil
}

func (f *fakeNetworker) UnpublishPorts(ctx context.Context, containerID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.published, containerID)
	f.unpublished = append(f.unpublished, containerID)
	return nil
}

func (f *fakeNetworker) UsedPorts() []network.PublishedPort {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []network.PublishedPort
	for _, list := range f.published {
		out = append(out, list...)
	}
	return out
}

// ---------- volumes ----------

// fakeVolumes materialises volume mounts as real directories so bundle
// generation, which stats every bind source, is satisfied.
type fakeVolumes struct {
	root string

	mu         sync.Mutex
	resolveErr error
	released   []string
	refs       map[string][]string
	vols       map[string]*types.Volume
}

// newFakeVolumes builds one rooted at dir.
func newFakeVolumes(dir string) *fakeVolumes {
	return &fakeVolumes{root: dir, refs: map[string][]string{}, vols: map[string]*types.Volume{}}
}

func (f *fakeVolumes) Resolve(ctx context.Context, c *types.Container) ([]types.Mount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	var out []types.Mount
	for _, m := range c.HostConfig.Mounts {
		if m.Type == "volume" {
			name := m.Source
			if name == "" {
				name = "anon-" + idShort(c.ID)
			}
			data := filepath.Join(f.root, name, "_data")
			if err := os.MkdirAll(data, 0o755); err != nil {
				return nil, err
			}
			f.refs[name] = append(f.refs[name], c.ID)
			f.vols[name] = &types.Volume{Name: name, Driver: "local", Mountpoint: data}
			m.Source = data
		}
		out = append(out, m)
	}
	for target := range c.Config.Volumes {
		name := "img-" + idShort(c.ID)
		data := filepath.Join(f.root, name, "_data")
		if err := os.MkdirAll(data, 0o755); err != nil {
			return nil, err
		}
		f.refs[name] = append(f.refs[name], c.ID)
		f.vols[name] = &types.Volume{Name: name, Driver: "local", Mountpoint: data}
		out = append(out, types.Mount{Type: "volume", Source: data, Target: target})
	}
	return out, nil
}

func (f *fakeVolumes) Release(ctx context.Context, c *types.Container, removeAnonymous bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, c.ID)
	for name, ids := range f.refs {
		var keep []string
		for _, id := range ids {
			if id != c.ID {
				keep = append(keep, id)
			}
		}
		if len(keep) == 0 {
			delete(f.refs, name)
		} else {
			f.refs[name] = keep
		}
	}
	return nil
}

func (f *fakeVolumes) Create(ctx context.Context, name, driver string, opts, labels map[string]string) (*types.Volume, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := &types.Volume{Name: name, Driver: driver, Mountpoint: filepath.Join(f.root, name, "_data"), Labels: labels}
	f.vols[name] = v
	return v, nil
}

func (f *fakeVolumes) Get(name string) (*types.Volume, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vols[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", volume.ErrNotFound, name)
	}
	return v, nil
}

func (f *fakeVolumes) List(vf volume.Filters) ([]*types.Volume, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*types.Volume, 0, len(f.vols))
	for _, v := range f.vols {
		out = append(out, v)
	}
	return out, nil
}

func (f *fakeVolumes) Remove(ctx context.Context, name string, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.refs[name]) > 0 && !force {
		return fmt.Errorf("%w: %s", volume.ErrInUse, name)
	}
	delete(f.vols, name)
	return nil
}

func (f *fakeVolumes) Prune(ctx context.Context, vf volume.Filters) ([]string, int64, error) {
	return nil, 0, nil
}

func (f *fakeVolumes) DataDir(name string) (string, error) {
	return filepath.Join(f.root, name, "_data"), nil
}

func (f *fakeVolumes) Refs(name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refs[name], nil
}

func (f *fakeVolumes) Usage(name string) (int64, error) { return 0, nil }

// ---------- registry ----------

// fakeRegistry serves pre-seeded images without any network.
type fakeRegistry struct {
	pulls  []string
	images map[string]*types.Image
	err    error
}

func (f *fakeRegistry) Pull(ctx context.Context, ref reference.Reference, store *content.Store, plat *types.Platform) (*types.Image, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.pulls = append(f.pulls, ref.FamiliarString())
	img, ok := f.images[ref.FamiliarString()]
	if !ok {
		return nil, errors.New("fake registry: no such image")
	}
	return img, nil
}

func (f *fakeRegistry) Push(ctx context.Context, ref reference.Reference, img *types.Image, store *content.Store) error {
	return f.err
}

func (f *fakeRegistry) Resolve(ctx context.Context, ref reference.Reference, plat *types.Platform) (types.Descriptor, []byte, error) {
	if f.err != nil {
		return types.Descriptor{}, nil, f.err
	}
	return types.Descriptor{Digest: "sha256:" + fixedHex("resolve"), Size: 3}, []byte("{}"), nil
}

func (f *fakeRegistry) Ping(ctx context.Context, registryHost string) error { return f.err }

// ---------- harness ----------

// testEngine is an Engine wired to the fakes, plus handles on them.
type testEngine struct {
	*Engine
	root    string
	spawner *fakeSpawner
	snaps   *fakeSnapshotter
	nets    *fakeNetworker
	vols    *fakeVolumes
	reg     *fakeRegistry
}

// newTestEngine builds an engine over a temporary data root with every
// subsystem faked. It needs no root privileges and touches no kernel state.
func newTestEngine(t *testing.T) *testEngine {
	t.Helper()
	root := t.TempDir()

	st, err := state.Open(root)
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cs, err := content.NewStore(filepath.Join(root, "content"))
	if err != nil {
		t.Fatalf("open content store: %v", err)
	}
	imgs, err := openImageStore(root)
	if err != nil {
		t.Fatalf("open image store: %v", err)
	}

	te := &testEngine{
		root:    root,
		spawner: newFakeSpawner(),
		snaps:   newFakeSnapshotter(filepath.Join(root, "snapfs")),
		nets:    newFakeNetworker(root),
		vols:    newFakeVolumes(filepath.Join(root, "volumes")),
		reg:     &fakeRegistry{images: map[string]*types.Image{}},
	}

	e := &Engine{
		cfg: Config{
			DataRoot:           root,
			ShimBinary:         "/usr/local/bin/hull-shim",
			MaxConcurrentPulls: 2,
			LogConfig:          types.LogConfig{Type: "json-file"},
		},
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		state:         st,
		content:       cs,
		snaps:         te.snaps,
		vols:          te.vols,
		nets:          te.nets,
		images:        imgs,
		bus:           events.NewBus(64),
		runtimeName:   "crun",
		runtimeBinary: "/usr/bin/crun",
		specVersion:   "1.0.2",
		spawner:       te.spawner,
		locks:         newKeyedLock(),
		pullSem:       make(chan struct{}, 2),
		notify:        newNotifier(),
		rt:            map[string]*ctrState{},
		execs:         map[string]*execRecord{},
		now:           func() time.Time { return time.Now().UTC() },
	}
	e.newRegistry = func(func(registry.ProgressEvent)) Registry { return te.reg }
	e.ctx, e.cancel = context.WithCancel(context.Background())
	te.Engine = e

	t.Cleanup(func() {
		e.cancel()
		e.wg.Wait()
		e.bus.Close()
	})
	return te
}

// seedImage registers an image in the local store under a tag.
func (te *testEngine) seedImage(t *testing.T, tag string, cfg types.ImageConfig) *types.Image {
	t.Helper()
	img := &types.Image{
		ID:           "sha256:" + fixedHex(tag),
		Digest:       "sha256:" + fixedHex("manifest-"+tag),
		RepoTags:     []string{tag},
		Created:      time.Now().UTC().Add(-time.Hour),
		Architecture: "amd64",
		OS:           "linux",
		DiffIDs:      []string{"sha256:" + fixedHex("layer-"+tag)},
		ChainID:      "sha256:" + fixedHex("layer-"+tag),
		Config:       cfg,
		ManifestType: "application/vnd.oci.image.manifest.v1+json",
	}
	stored, err := te.images.Put(img)
	if err != nil {
		t.Fatalf("seed image %s: %v", tag, err)
	}
	return stored
}

// fixedHex turns a label into a deterministic 64-character hex string, so test
// image ids look like real digests without any hashing ceremony.
func fixedHex(seed string) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, 64)
	n := 0
	for _, r := range seed {
		n = n*31 + int(r)
	}
	if n < 0 {
		n = -n
	}
	for i := range out {
		n = (n*1103515245 + 12345) & 0x7fffffff
		out[i] = alphabet[n%16]
	}
	return string(out)
}

// createTestContainer creates a container from a seeded image with a command,
// which is the minimum bundle.Generate will accept.
func (te *testEngine) createTestContainer(t *testing.T, name string) *types.Container {
	t.Helper()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	c, err := te.Create(context.Background(), name, types.ContainerConfig{}, types.HostConfig{}, "test:latest")
	if err != nil {
		t.Fatalf("create container %q: %v", name, err)
	}
	return c
}

// waitForState polls until a container reaches one of the wanted states.
func (te *testEngine) waitForState(t *testing.T, id string, want ...types.State) *types.Container {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := te.lookup(id)
		if err == nil {
			for _, w := range want {
				if c.State == w {
					return c
				}
			}
		}
		if time.Now().After(deadline) {
			got := types.State("<missing>")
			if c != nil {
				got = c.State
			}
			t.Fatalf("container %s never reached %v (it is %s)", idShort(id), want, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
