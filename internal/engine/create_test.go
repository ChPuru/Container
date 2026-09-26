package engine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ChPuru/hull/internal/state"
	"github.com/ChPuru/hull/internal/types"
)

func TestCreateBuildsEverythingAndPersists(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	img := te.seedImage(t, "test:latest", types.ImageConfig{
		Cmd:          []string{"/bin/sh"},
		Env:          []string{"FROM=image"},
		WorkingDir:   "/srv",
		ExposedPorts: map[string]struct{}{"80/tcp": {}},
		Labels:       map[string]string{"org": "hull"},
	})

	c, err := te.Create(ctx, "web", types.ContainerConfig{Env: []string{"EXTRA=1"}}, types.HostConfig{}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if c.Name != "web" {
		t.Errorf("name = %q, want web", c.Name)
	}
	if c.State != types.StateCreated {
		t.Errorf("state = %q, want created", c.State)
	}
	if c.Image != img.ID {
		t.Errorf("image = %s, want %s", c.Image, img.ID)
	}
	if c.ImageRef != "test:latest" {
		t.Errorf("imageRef = %q, want test:latest", c.ImageRef)
	}
	// The image config must have been merged into the record.
	if c.Config.WorkingDir != "/srv" {
		t.Errorf("workingDir = %q, want /srv (from the image)", c.Config.WorkingDir)
	}
	if len(c.Config.Cmd) != 1 || c.Config.Cmd[0] != "/bin/sh" {
		t.Errorf("cmd = %q, want [/bin/sh] (from the image)", c.Config.Cmd)
	}
	if _, ok := c.Config.ExposedPorts["80/tcp"]; !ok {
		t.Errorf("exposed ports = %v, want 80/tcp from the image", c.Config.ExposedPorts)
	}
	if c.Config.Labels["org"] != "hull" {
		t.Errorf("labels = %v, want the image label", c.Config.Labels)
	}
	if c.Config.Hostname == "" {
		t.Error("hostname was left empty; it should default to the short id")
	}
	// Host defaults.
	if c.HostConfig.NetworkMode != "bridge" {
		t.Errorf("networkMode = %q, want bridge", c.HostConfig.NetworkMode)
	}
	if c.HostConfig.LogConfig.Type != "json-file" {
		t.Errorf("log driver = %q, want json-file", c.HostConfig.LogConfig.Type)
	}

	// The rootfs is mounted and the bundle is on disk.
	if mounted, _ := te.snaps.IsMounted(c.ID); !mounted {
		t.Error("the container's rootfs was not mounted")
	}
	if _, err := os.Stat(filepath.Join(te.containerDir(c.ID), "config.json")); err != nil {
		t.Errorf("the OCI bundle was not written: %v", err)
	}
	for _, f := range sandboxFiles {
		if _, err := os.Stat(filepath.Join(te.containerDir(c.ID), f.mnt)); err != nil {
			t.Errorf("the sandbox file %s was not materialised: %v", f.mnt, err)
		}
	}

	// The record survives a reload from the store.
	loaded, err := te.state.GetContainer("web")
	if err != nil {
		t.Fatalf("reload the container by name: %v", err)
	}
	if loaded.ID != c.ID {
		t.Errorf("the name resolves to %s, want %s", idShort(loaded.ID), idShort(c.ID))
	}

	// The network endpoint is planned but not yet realised: there is no pid.
	if ep, ok := loaded.NetworkSettings.Networks["bridge"]; !ok {
		t.Error("no bridge endpoint was recorded at create time")
	} else if ep.IPAddress != "" {
		t.Errorf("an address was allocated before the container had a namespace: %q", ep.IPAddress)
	}
	if len(te.nets.connected) != 0 {
		t.Errorf("Connect was called at create time: %v", te.nets.connected)
	}
}

func TestCreateGeneratesANameWhenNoneIsGiven(t *testing.T) {
	te := newTestEngine(t)
	c := te.createTestContainer(t, "")
	if c.Name == "" {
		t.Fatal("Create left the container unnamed")
	}
	if _, err := te.state.GetContainer(c.Name); err != nil {
		t.Errorf("the generated name %q does not resolve: %v", c.Name, err)
	}
}

func TestCreateRefusesADuplicateName(t *testing.T) {
	te := newTestEngine(t)
	te.createTestContainer(t, "twice")
	_, err := te.Create(context.Background(), "twice", types.ContainerConfig{}, types.HostConfig{}, "test:latest")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("a duplicate name gave %v, want ErrConflict", err)
	}
}

func TestCreateRefusesAnUnknownImage(t *testing.T) {
	te := newTestEngine(t)
	_, err := te.Create(context.Background(), "x", types.ContainerConfig{}, types.HostConfig{}, "nosuch:tag")
	if err == nil {
		t.Fatal("Create with an unknown image should fail")
	}
}

func TestCreatePullsAnAbsentImage(t *testing.T) {
	te := newTestEngine(t)
	// The registry has it; the local store does not.
	te.reg.images["absent:latest"] = &types.Image{
		ID:       "sha256:" + fixedHex("absent"),
		Digest:   "sha256:" + fixedHex("absent-manifest"),
		RepoTags: []string{"absent:latest"},
		DiffIDs:  []string{"sha256:" + fixedHex("absent-layer")},
		ChainID:  "sha256:" + fixedHex("absent-layer"),
		Config:   types.ImageConfig{Cmd: []string{"/bin/sh"}},
	}
	// Pull reads the manifest back out of the content store to find the
	// layers, so give it one.
	writeManifestBlob(t, te, te.reg.images["absent:latest"])

	c, err := te.Create(context.Background(), "pulled", types.ContainerConfig{}, types.HostConfig{}, "absent:latest")
	if err != nil {
		t.Fatalf("Create with a pull: %v", err)
	}
	if len(te.reg.pulls) != 1 || te.reg.pulls[0] != "absent:latest" {
		t.Errorf("registry pulls = %v, want [absent:latest]", te.reg.pulls)
	}
	if c.Image != te.reg.images["absent:latest"].ID {
		t.Errorf("the created container does not use the pulled image")
	}
}

// writeManifestBlob stores a minimal manifest for an image so the engine can
// read its layer descriptors back.
func writeManifestBlob(t *testing.T, te *testEngine, img *types.Image) {
	t.Helper()
	body := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",` +
		`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + img.ID + `","size":2},` +
		`"layers":[]}`)
	info, err := te.content.WriteBlob(context.Background(), bytesReader(body), "", int64(len(body)))
	if err != nil {
		t.Fatalf("store a manifest blob: %v", err)
	}
	img.Digest = info.Digest
}

func TestCreateUnwindsEverythingOnFailure(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})

	// Fail at the mount step: nothing but the name has been taken yet.
	t.Run("mount failure releases the name", func(t *testing.T) {
		te.snaps.mountErr = errors.New("overlay refused")
		defer func() { te.snaps.mountErr = nil }()

		if _, err := te.Create(ctx, "doomed", types.ContainerConfig{}, types.HostConfig{}, "test:latest"); err == nil {
			t.Fatal("Create should have failed")
		}
		if _, err := te.state.Resolve("doomed"); !errors.Is(err, state.ErrNotFound) {
			t.Errorf("the name was left reserved: %v", err)
		}
		if _, err := os.Stat(filepath.Join(te.root, "containers", "doomed")); err == nil {
			t.Error("a container directory was left behind")
		}
	})

	// Fail at the volume step, after the snapshot is mounted.
	t.Run("volume failure unwinds the snapshot too", func(t *testing.T) {
		before := len(te.snaps.removed)
		te.vols.resolveErr = errors.New("volume refused")
		defer func() { te.vols.resolveErr = nil }()

		if _, err := te.Create(ctx, "doomed2", types.ContainerConfig{}, types.HostConfig{}, "test:latest"); err == nil {
			t.Fatal("Create should have failed")
		}
		if got := len(te.snaps.removed) - before; got != 1 {
			t.Errorf("%d snapshots were removed during the unwind, want 1", got)
		}
		if len(te.vols.released) == 0 {
			t.Error("volume references were not released during the unwind")
		}
		if _, err := te.state.Resolve("doomed2"); !errors.Is(err, state.ErrNotFound) {
			t.Errorf("the name was left reserved: %v", err)
		}
		ctrs, err := te.state.ListContainers()
		if err != nil {
			t.Fatalf("list containers: %v", err)
		}
		for _, c := range ctrs {
			if c.Name == "doomed2" {
				t.Error("a record was left behind for the failed container")
			}
		}
	})

	// After all that, a normal create still works: nothing was poisoned.
	if _, err := te.Create(ctx, "doomed", types.ContainerConfig{}, types.HostConfig{}, "test:latest"); err != nil {
		t.Fatalf("a create after two failures: %v", err)
	}
}

func TestCreateRecordsBundleWarnings(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	te.seedImage(t, "test:latest", types.ImageConfig{Cmd: []string{"/bin/sh"}})

	// This host has no delegated cgroup v2 controllers, which is the stock
	// WSL situation. bundle reports rather than refuses, and the engine must
	// carry that warning out to the caller.
	c, err := te.Create(ctx, "limited", types.ContainerConfig{}, types.HostConfig{
		Resources: types.Resources{Memory: 512 << 20},
	}, "test:latest")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	warnings, err := te.Warnings(ctx, c.ID)
	if err != nil {
		t.Fatalf("Warnings: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("a memory limit on a host with no cgroup v2 delegation produced no warning")
	}
	// And the warning survives a reload, because it is on disk.
	reloaded, err := te.Warnings(ctx, c.Name)
	if err != nil {
		t.Fatalf("Warnings by name: %v", err)
	}
	if len(reloaded) != len(warnings) {
		t.Errorf("warnings by name = %d entries, by id = %d", len(reloaded), len(warnings))
	}
}

func TestRenameMovesTheReservation(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	c := te.createTestContainer(t, "before")

	if err := te.Rename(ctx, "before", "after"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := te.state.Resolve("before"); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("the old name is still reserved: %v", err)
	}
	got, err := te.state.GetContainer("after")
	if err != nil {
		t.Fatalf("resolve the new name: %v", err)
	}
	if got.ID != c.ID {
		t.Errorf("the new name resolves to %s, want %s", idShort(got.ID), idShort(c.ID))
	}

	te.createTestContainer(t, "taken")
	if err := te.Rename(ctx, "after", "taken"); !errors.Is(err, ErrConflict) {
		t.Errorf("renaming onto a used name = %v, want ErrConflict", err)
	}
	// The failed rename must not have moved anything.
	if _, err := te.state.GetContainer("after"); err != nil {
		t.Errorf("the container lost its name after a failed rename: %v", err)
	}
}

func TestUpdateChangesResourcesAndPolicy(t *testing.T) {
	te := newTestEngine(t)
	ctx := context.Background()
	c := te.createTestContainer(t, "updatable")

	policy := types.RestartPolicy{Name: "on-failure", MaximumRetryCount: 3}
	if err := te.Update(ctx, c.ID, types.Resources{Memory: 1 << 30}, &policy); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := te.Inspect(ctx, c.ID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.HostConfig.Resources.Memory != 1<<30 {
		t.Errorf("memory = %d, want %d", got.HostConfig.Resources.Memory, int64(1)<<30)
	}
	if got.HostConfig.RestartPolicy != policy {
		t.Errorf("restart policy = %+v, want %+v", got.HostConfig.RestartPolicy, policy)
	}
	// The host cannot enforce the limit, and must say so rather than pretend.
	warnings, err := te.Warnings(ctx, c.ID)
	if err != nil {
		t.Fatalf("Warnings: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("an unenforceable resource update produced no warning")
	}
}

// bytesReader is a tiny helper so the tests can hand a byte slice to an
// io.Reader parameter without importing bytes everywhere.
func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
