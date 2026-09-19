package engine

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/shim"
	"github.com/rahuldhali/hull/internal/state"
	"github.com/rahuldhali/hull/internal/types"
)

// restart closes the engine's state store and opens a fresh engine over the
// same data root, which is exactly what a daemon restart looks like from the
// disk's point of view.
func (te *testEngine) restart(t *testing.T) *testEngine {
	t.Helper()
	if err := te.state.Close(); err != nil {
		t.Fatalf("close the state store: %v", err)
	}
	return newTestEngineAt(t, te.root)
}

func TestRecoverReadoptsALiveShim(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	c, err := te.Create(ctx, "survivor", types.ContainerConfig{}, types.HostConfig{
		PortBindings: map[string][]types.PortBinding{"80/tcp": {{HostPort: "8088"}}},
	}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	next := te.restart(t)
	// The container outlived the daemon: its shim is still there.
	live := newFakeSupervisor(c.ID, 4242)
	live.started = true
	next.spawner.reconnect[c.ID] = live

	if err := next.recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}

	got, err := next.Inspect(ctx, c.ID)
	if err != nil {
		t.Fatalf("Inspect after recovery: %v", err)
	}
	if got.State != types.StateRunning {
		t.Errorf("state = %q after recovery, want running", got.State)
	}
	if got.Pid != 4242 {
		t.Errorf("pid = %d after recovery, want the shim's answer 4242", got.Pid)
	}
	if _, err := next.supervisorFor(c.ID); err != nil {
		t.Errorf("the re-adopted container has no supervisor: %v", err)
	}
	if len(next.nets.published[c.ID]) == 0 {
		t.Error("the published port was not re-created after the restart")
	}
	// The veth is a kernel object and outlived the daemon, so the endpoint is
	// re-adopted rather than re-created: the address must be the one the
	// record already held.
	ep, ok := got.NetworkSettings.Networks["bridge"]
	if !ok || ep.IPAddress == "" {
		t.Errorf("the network endpoint was lost across the restart: %+v", got.NetworkSettings.Networks)
	}
	if len(next.nets.connected) != 0 {
		t.Errorf("a new veth was created for an endpoint that already existed: %v", next.nets.connected)
	}

	// And the re-adopted container is still supervised: its exit is noticed.
	live.exit(7, false)
	after := next.waitForState(t, c.ID, types.StateExited)
	if after.ExitCode != 7 {
		t.Errorf("exit code = %d, want 7", after.ExitCode)
	}
}

func TestRecoverMarksAVanishedContainerExited(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	c, err := te.Create(ctx, "vanished", types.ContainerConfig{}, types.HostConfig{}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	next := te.restart(t)
	// No live shim, but it left its exit status behind before it went.
	next.spawner.exits[c.ID] = shim.ExitStatus{
		ExitCode:   137,
		FinishedAt: time.Now().UTC(),
		OOMKilled:  true,
	}
	if err := next.recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}

	got, err := next.Inspect(ctx, c.ID)
	if err != nil {
		t.Fatalf("Inspect after recovery: %v", err)
	}
	if got.State != types.StateExited {
		t.Errorf("state = %q, want exited", got.State)
	}
	if got.ExitCode != 137 {
		t.Errorf("exit code = %d, want 137 from exit.json", got.ExitCode)
	}
	if !got.OOMKilled {
		t.Error("the recorded OOM kill was lost")
	}
	if got.Pid != 0 {
		t.Errorf("pid = %d, want 0", got.Pid)
	}
	if len(next.nets.unpublished) == 0 {
		t.Error("the ports of a vanished container were not released")
	}
}

func TestRecoverWithNoExitRecordUsesTheDisappearedCode(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	c, err := te.Create(ctx, "gone", types.ContainerConfig{}, types.HostConfig{}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	next := te.restart(t)
	if err := next.recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	got, err := next.Inspect(ctx, c.ID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.ExitCode != state.DisappearedExitCode {
		t.Errorf("exit code = %d, want %d", got.ExitCode, state.DisappearedExitCode)
	}
	if got.Error == "" {
		t.Error("no explanation was recorded for a container that disappeared")
	}
}

func TestRecoverRestartsAnUnlessStoppedContainer(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	c, err := te.Create(ctx, "persistent", types.ContainerConfig{}, types.HostConfig{
		RestartPolicy: types.RestartPolicy{Name: "unless-stopped"},
	}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	next := te.restart(t)
	if err := next.recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	next.waitForState(t, c.ID, types.StateRunning)
	next.spawner.mu.Lock()
	spawned := next.spawner.spawned
	next.spawner.mu.Unlock()
	if spawned != 1 {
		t.Errorf("%d shims were spawned during recovery, want 1", spawned)
	}
}

func TestRecoverDoesNotRestartAContainerTheUserStopped(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})
	c, err := te.Create(ctx, "stopped-on-purpose", types.ContainerConfig{}, types.HostConfig{
		RestartPolicy: types.RestartPolicy{Name: "unless-stopped"},
	}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := te.Stop(ctx, c.ID, nil); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	te.waitForState(t, c.ID, types.StateExited)

	next := te.restart(t)
	if err := next.recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	// The marker is on disk, which is the whole point of putting it there.
	if !next.manuallyStopped(c.ID) {
		t.Fatal("the manual-stop marker did not survive the daemon restart")
	}
	time.Sleep(300 * time.Millisecond)
	next.spawner.mu.Lock()
	spawned := next.spawner.spawned
	next.spawner.mu.Unlock()
	if spawned != 0 {
		t.Errorf("%d shims were spawned; a container the user stopped must stay stopped", spawned)
	}
	got, err := next.Inspect(ctx, c.ID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.State != types.StateExited {
		t.Errorf("state = %q after recovery, want exited", got.State)
	}
}

func TestCloseDetachesWithoutKillingContainers(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	c := te.createTestContainer(t, "outlives-me")
	if err := te.Start(ctx, c.ID, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	sup := te.spawner.supervisor(t, c.ID)

	if err := te.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	sup.mu.Lock()
	exited, closed := sup.exited, sup.closed
	signals := len(sup.signals)
	sup.mu.Unlock()

	if exited {
		t.Error("Close killed the container; containers must outlive the daemon")
	}
	if signals != 0 {
		t.Errorf("Close sent %d signals to the container, want 0", signals)
	}
	if !closed {
		t.Error("Close did not release the shim client")
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	img := seedRealImage(t, te, "round:trip")

	var archive bytes.Buffer
	if err := te.Save(ctx, []string{"round:trip"}, &archive); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if archive.Len() == 0 {
		t.Fatal("Save produced an empty archive")
	}

	// A completely separate engine must be able to read it.
	other := newTestEngine(t)
	var lines []string
	if err := other.Load(ctx, bytes.NewReader(archive.Bytes()), false, func(s string) {
		lines = append(lines, s)
	}); err != nil {
		t.Fatalf("Load: %v", err)
	}

	loaded, err := other.images.Get("round:trip")
	if err != nil {
		t.Fatalf("the loaded archive did not register the image: %v", err)
	}
	if loaded.ID != img.ID {
		t.Errorf("loaded image id = %s, want %s", idShort(loaded.ID), idShort(img.ID))
	}
	if len(loaded.DiffIDs) != len(img.DiffIDs) {
		t.Errorf("loaded diffIDs = %v, want %v", loaded.DiffIDs, img.DiffIDs)
	}
	if len(lines) == 0 {
		t.Error("Load reported no progress at all")
	}
}

func TestSaveRefusesAnUnknownImage(t *testing.T) {
	te := newTestEngine(t)
	var buf bytes.Buffer
	if err := te.Save(context.Background(), []string{"nope:latest"}, &buf); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Save of an unknown image = %v, want ErrNotFound", err)
	}
	if err := te.Save(context.Background(), nil, &buf); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Save with no references = %v, want ErrInvalid", err)
	}
}

// seedRealImage stores a genuine config, layer and manifest in the content
// store and registers the image, so archive round-trips have real bytes to
// move.
func seedRealImage(t *testing.T, te *testEngine, tag string) *types.Image {
	t.Helper()
	ctx := context.Background()

	layer := []byte("not really a tar, but it is a real blob\n")
	layerInfo, err := te.content.WriteBlob(ctx, bytes.NewReader(layer), "", int64(len(layer)))
	if err != nil {
		t.Fatalf("store a layer blob: %v", err)
	}

	cfg := []byte(`{"created":"2024-01-01T00:00:00Z","architecture":"amd64","os":"linux",` +
		`"config":{"Cmd":["/bin/sh"]},` +
		`"rootfs":{"type":"layers","diff_ids":["` + layerInfo.Digest + `"]},` +
		`"history":[{"created":"2024-01-01T00:00:00Z","created_by":"test"}]}`)
	cfgInfo, err := te.content.WriteBlob(ctx, bytes.NewReader(cfg), "", int64(len(cfg)))
	if err != nil {
		t.Fatalf("store a config blob: %v", err)
	}

	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",` +
		`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + cfgInfo.Digest +
		`","size":` + itoa(len(cfg)) + `},` +
		`"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"` + layerInfo.Digest +
		`","size":` + itoa(len(layer)) + `}]}`)
	manifestInfo, err := te.content.WriteBlob(ctx, bytes.NewReader(manifest), "", int64(len(manifest)))
	if err != nil {
		t.Fatalf("store a manifest blob: %v", err)
	}

	img, err := imageFromManifest(manifest, cfg, "application/vnd.oci.image.manifest.v1+json", nil)
	if err != nil {
		t.Fatalf("build the image record: %v", err)
	}
	img.Digest = manifestInfo.Digest
	img.RepoTags = []string{tag}
	stored, err := te.images.Put(img)
	if err != nil {
		t.Fatalf("register the image: %v", err)
	}
	return stored
}
