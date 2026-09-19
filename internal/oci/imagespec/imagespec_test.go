package imagespec

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

func TestMediaTypePredicates(t *testing.T) {
	tests := []struct {
		mt         string
		list       bool
		manifest   bool
		layer      bool
		compressed bool
		schema1    bool
		config     bool
	}{
		{mt: MediaTypeImageIndex, list: true},
		{mt: MediaTypeDockerManifestList, list: true},
		{mt: MediaTypeImageManifest, manifest: true},
		{mt: MediaTypeDockerManifest, manifest: true},
		{mt: MediaTypeImageConfig, config: true},
		{mt: MediaTypeDockerConfig, config: true},
		{mt: MediaTypeImageLayer, layer: true},
		{mt: MediaTypeImageLayerGzip, layer: true, compressed: true},
		{mt: MediaTypeImageLayerZstd, layer: true, compressed: true},
		{mt: MediaTypeDockerLayerGzip, layer: true, compressed: true},
		{mt: MediaTypeDockerForeignLayer, layer: true, compressed: true},
		{mt: MediaTypeDockerManifestSchema1, schema1: true},
		{mt: MediaTypeDockerManifestSchema1Signed, schema1: true},
		{mt: MediaTypeEmptyJSON},
		{mt: "application/octet-stream"},
	}
	for _, tt := range tests {
		t.Run(tt.mt, func(t *testing.T) {
			if got := IsManifestList(tt.mt); got != tt.list {
				t.Errorf("IsManifestList = %v, want %v", got, tt.list)
			}
			if got := IsManifest(tt.mt); got != tt.manifest {
				t.Errorf("IsManifest = %v, want %v", got, tt.manifest)
			}
			if got := IsLayer(tt.mt); got != tt.layer {
				t.Errorf("IsLayer = %v, want %v", got, tt.layer)
			}
			if got := IsCompressedLayer(tt.mt); got != tt.compressed {
				t.Errorf("IsCompressedLayer = %v, want %v", got, tt.compressed)
			}
			if got := IsSchema1(tt.mt); got != tt.schema1 {
				t.Errorf("IsSchema1 = %v, want %v", got, tt.schema1)
			}
			if got := IsConfig(tt.mt); got != tt.config {
				t.Errorf("IsConfig = %v, want %v", got, tt.config)
			}
		})
	}
}

func TestMediaTypeStringsAreExact(t *testing.T) {
	want := map[string]string{
		"MediaTypeImageIndex":                  "application/vnd.oci.image.index.v1+json",
		"MediaTypeImageManifest":               "application/vnd.oci.image.manifest.v1+json",
		"MediaTypeImageConfig":                 "application/vnd.oci.image.config.v1+json",
		"MediaTypeImageLayer":                  "application/vnd.oci.image.layer.v1.tar",
		"MediaTypeImageLayerGzip":              "application/vnd.oci.image.layer.v1.tar+gzip",
		"MediaTypeImageLayerZstd":              "application/vnd.oci.image.layer.v1.tar+zstd",
		"MediaTypeEmptyJSON":                   "application/vnd.oci.empty.v1+json",
		"MediaTypeDockerManifestList":          "application/vnd.docker.distribution.manifest.list.v2+json",
		"MediaTypeDockerManifest":              "application/vnd.docker.distribution.manifest.v2+json",
		"MediaTypeDockerConfig":                "application/vnd.docker.container.image.v1+json",
		"MediaTypeDockerLayerGzip":             "application/vnd.docker.image.rootfs.diff.tar.gzip",
		"MediaTypeDockerForeignLayer":          "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
		"MediaTypeDockerManifestSchema1":       "application/vnd.docker.distribution.manifest.v1+json",
		"MediaTypeDockerManifestSchema1Signed": "application/vnd.docker.distribution.manifest.v1+prettyjws",
	}
	got := map[string]string{
		"MediaTypeImageIndex":                  MediaTypeImageIndex,
		"MediaTypeImageManifest":               MediaTypeImageManifest,
		"MediaTypeImageConfig":                 MediaTypeImageConfig,
		"MediaTypeImageLayer":                  MediaTypeImageLayer,
		"MediaTypeImageLayerGzip":              MediaTypeImageLayerGzip,
		"MediaTypeImageLayerZstd":              MediaTypeImageLayerZstd,
		"MediaTypeEmptyJSON":                   MediaTypeEmptyJSON,
		"MediaTypeDockerManifestList":          MediaTypeDockerManifestList,
		"MediaTypeDockerManifest":              MediaTypeDockerManifest,
		"MediaTypeDockerConfig":                MediaTypeDockerConfig,
		"MediaTypeDockerLayerGzip":             MediaTypeDockerLayerGzip,
		"MediaTypeDockerForeignLayer":          MediaTypeDockerForeignLayer,
		"MediaTypeDockerManifestSchema1":       MediaTypeDockerManifestSchema1,
		"MediaTypeDockerManifestSchema1Signed": MediaTypeDockerManifestSchema1Signed,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %q, want %q", k, got[k], w)
		}
	}
}

func TestAllManifestAccept(t *testing.T) {
	got := AllManifestAccept()
	parts := strings.Split(got, ",")
	want := []string{
		MediaTypeImageIndex,
		MediaTypeImageManifest,
		MediaTypeDockerManifestList,
		MediaTypeDockerManifest,
	}
	if len(parts) != len(want) {
		t.Fatalf("AllManifestAccept() = %q, want %d entries", got, len(want))
	}
	for i := range want {
		if parts[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, parts[i], want[i])
		}
	}
	if strings.Contains(got, " ") {
		t.Errorf("AllManifestAccept() = %q, want no spaces", got)
	}
}

const indexJSON = `{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:aaaa",
      "size": 1234,
      "platform": {"architecture": "amd64", "os": "linux"}
    }
  ],
  "annotations": {"org.opencontainers.image.ref.name": "3.20"}
}`

func TestIndexUnmarshal(t *testing.T) {
	var idx Index
	if err := json.Unmarshal([]byte(indexJSON), &idx); err != nil {
		t.Fatalf("unmarshal index: %v", err)
	}
	if idx.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", idx.SchemaVersion, SchemaVersion)
	}
	if !IsManifestList(idx.MediaType) {
		t.Errorf("MediaType %q is not recognised as a manifest list", idx.MediaType)
	}
	if len(idx.Manifests) != 1 {
		t.Fatalf("len(Manifests) = %d, want 1", len(idx.Manifests))
	}
	m := idx.Manifests[0]
	if m.Digest != "sha256:aaaa" || m.Size != 1234 {
		t.Errorf("descriptor = %+v", m)
	}
	if m.Platform == nil || m.Platform.Architecture != "amd64" || m.Platform.OS != "linux" {
		t.Errorf("platform = %+v", m.Platform)
	}
	if idx.Subject != nil {
		t.Errorf("Subject = %+v, want nil", idx.Subject)
	}
}

const manifestJSON = `{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {
    "mediaType": "application/vnd.docker.container.image.v1+json",
    "digest": "sha256:cccc",
    "size": 7
  },
  "layers": [
    {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": "sha256:dddd", "size": 99}
  ]
}`

func TestManifestUnmarshal(t *testing.T) {
	var m Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if !IsManifest(m.MediaType) {
		t.Errorf("MediaType %q is not recognised as a manifest", m.MediaType)
	}
	if !IsConfig(m.Config.MediaType) {
		t.Errorf("config MediaType %q is not recognised", m.Config.MediaType)
	}
	if len(m.Layers) != 1 || !IsCompressedLayer(m.Layers[0].MediaType) {
		t.Errorf("layers = %+v", m.Layers)
	}
}

const configJSON = `{
  "created": "2024-01-02T03:04:05Z",
  "architecture": "amd64",
  "os": "linux",
  "config": {
    "User": "1000:1000",
    "ExposedPorts": {"80/tcp": {}},
    "Env": ["PATH=/usr/bin"],
    "Entrypoint": ["/bin/sh"],
    "Cmd": ["-c", "true"],
    "Volumes": {"/data": {}},
    "WorkingDir": "/srv",
    "Labels": {"a": "b"},
    "StopSignal": "SIGTERM",
    "ArgsEscaped": true,
    "Memory": 1024,
    "MemorySwap": 2048,
    "CpuShares": 512,
    "Healthcheck": {"Test": ["CMD", "true"], "Interval": 1000000000, "Retries": 3},
    "OnBuild": ["RUN true"],
    "Shell": ["/bin/sh", "-c"]
  },
  "rootfs": {"type": "layers", "diff_ids": ["sha256:1111", "sha256:2222"]},
  "history": [{"created": "2024-01-02T03:04:05Z", "created_by": "RUN true", "empty_layer": true}]
}`

func TestImageConfigUnmarshal(t *testing.T) {
	var c ImageConfig
	if err := json.Unmarshal([]byte(configJSON), &c); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if c.Created == nil || !c.Created.Equal(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("Created = %v", c.Created)
	}
	if c.RootFS.Type != RootFSTypeLayers || len(c.RootFS.DiffIDs) != 2 {
		t.Errorf("RootFS = %+v", c.RootFS)
	}
	if len(c.History) != 1 || !c.History[0].EmptyLayer {
		t.Errorf("History = %+v", c.History)
	}
	if got, want := c.Platform(), (types.Platform{Architecture: "amd64", OS: "linux"}); got.Architecture != want.Architecture || got.OS != want.OS {
		t.Errorf("Platform() = %+v, want %+v", got, want)
	}

	cb := c.Config
	if cb.Memory != 1024 || cb.MemorySwap != 2048 || cb.CPUShares != 512 {
		t.Errorf("reserved keys not decoded: %+v", cb)
	}
	if !cb.ArgsEscaped {
		t.Error("ArgsEscaped = false, want true")
	}
	if len(cb.OnBuild) != 1 {
		t.Errorf("OnBuild = %v", cb.OnBuild)
	}
	if cb.Healthcheck == nil || cb.Healthcheck.Interval != time.Second || cb.Healthcheck.Retries != 3 {
		t.Errorf("Healthcheck = %+v", cb.Healthcheck)
	}
}

func TestToTypesConfig(t *testing.T) {
	hc := &types.Healthcheck{Test: []string{"CMD", "true"}, Retries: 2}
	in := ConfigBlock{
		User:         "root",
		ExposedPorts: map[string]struct{}{"80/tcp": {}},
		Env:          []string{"A=B"},
		Entrypoint:   []string{"/entry"},
		Cmd:          []string{"arg"},
		Volumes:      map[string]struct{}{"/v": {}},
		WorkingDir:   "/w",
		Labels:       map[string]string{"k": "v"},
		StopSignal:   "SIGQUIT",
		Memory:       1,
		CPUShares:    2,
		Healthcheck:  hc,
		OnBuild:      []string{"ignored"},
		Shell:        []string{"/bin/sh"},
	}
	out := ToTypesConfig(in)

	if out.User != "root" || out.WorkingDir != "/w" || out.StopSignal != "SIGQUIT" {
		t.Errorf("scalar fields not copied: %+v", out)
	}
	if _, ok := out.ExposedPorts["80/tcp"]; !ok {
		t.Errorf("ExposedPorts = %v", out.ExposedPorts)
	}
	if _, ok := out.Volumes["/v"]; !ok {
		t.Errorf("Volumes = %v", out.Volumes)
	}
	if out.Labels["k"] != "v" {
		t.Errorf("Labels = %v", out.Labels)
	}
	if out.Healthcheck == nil || out.Healthcheck.Retries != 2 {
		t.Fatalf("Healthcheck = %+v", out.Healthcheck)
	}

	// The result must not alias the input.
	out.Env[0] = "mutated"
	out.Labels["k"] = "mutated"
	out.ExposedPorts["9/tcp"] = struct{}{}
	out.Healthcheck.Retries = 99
	if in.Env[0] != "A=B" {
		t.Error("ToTypesConfig aliased Env")
	}
	if in.Labels["k"] != "v" {
		t.Error("ToTypesConfig aliased Labels")
	}
	if _, ok := in.ExposedPorts["9/tcp"]; ok {
		t.Error("ToTypesConfig aliased ExposedPorts")
	}
	if hc.Retries != 2 {
		t.Error("ToTypesConfig aliased Healthcheck")
	}
}

func TestToTypesConfigEmpty(t *testing.T) {
	out := ToTypesConfig(ConfigBlock{})
	if out.ExposedPorts != nil || out.Volumes != nil || out.Labels != nil ||
		out.Env != nil || out.Entrypoint != nil || out.Cmd != nil ||
		out.Shell != nil || out.Healthcheck != nil {
		t.Errorf("empty ConfigBlock produced non-nil fields: %+v", out)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{}" {
		t.Errorf("marshalled empty config = %s, want {}", b)
	}
}
