package imagespec

import (
	"time"

	"github.com/ChPuru/hull/internal/types"
)

// SchemaVersion is the only schemaVersion value OCI and Docker schema 2 use.
const SchemaVersion = 2

// Index is an OCI image index (or a Docker manifest list, which is
// structurally identical).
type Index struct {
	SchemaVersion int                `json:"schemaVersion"`
	MediaType     string             `json:"mediaType,omitempty"`
	ArtifactType  string             `json:"artifactType,omitempty"`
	Manifests     []types.Descriptor `json:"manifests"`
	Subject       *types.Descriptor  `json:"subject,omitempty"`
	Annotations   map[string]string  `json:"annotations,omitempty"`
}

// Manifest is an OCI image manifest (or a Docker schema 2 manifest).
type Manifest struct {
	SchemaVersion int                `json:"schemaVersion"`
	MediaType     string             `json:"mediaType,omitempty"`
	ArtifactType  string             `json:"artifactType,omitempty"`
	Config        types.Descriptor   `json:"config"`
	Layers        []types.Descriptor `json:"layers"`
	Subject       *types.Descriptor  `json:"subject,omitempty"`
	Annotations   map[string]string  `json:"annotations,omitempty"`
}

// ImageConfig is the JSON body of an image config blob. Its digest is the
// image ID.
type ImageConfig struct {
	Created      *time.Time  `json:"created,omitempty"`
	Author       string      `json:"author,omitempty"`
	Architecture string      `json:"architecture"`
	OS           string      `json:"os"`
	OSVersion    string      `json:"os.version,omitempty"`
	OSFeatures   []string    `json:"os.features,omitempty"`
	Variant      string      `json:"variant,omitempty"`
	Config       ConfigBlock `json:"config,omitempty"`
	RootFS       RootFS      `json:"rootfs"`
	History      []History   `json:"history,omitempty"`
}

// ConfigBlock is the "config" member of an image config: the execution
// parameters a runtime applies when the image is used as the base of a
// container. Field names use the exact capitalised OCI/Docker JSON keys.
type ConfigBlock struct {
	User         string              `json:"User,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	Env          []string            `json:"Env,omitempty"`
	Entrypoint   []string            `json:"Entrypoint,omitempty"`
	Cmd          []string            `json:"Cmd,omitempty"`
	Volumes      map[string]struct{} `json:"Volumes,omitempty"`
	WorkingDir   string              `json:"WorkingDir,omitempty"`
	Labels       map[string]string   `json:"Labels,omitempty"`
	StopSignal   string              `json:"StopSignal,omitempty"`
	ArgsEscaped  bool                `json:"ArgsEscaped,omitempty"`

	// Reserved keys. OCI reserves these names; Docker writes them. hull
	// preserves them on round-trip but does not act on Memory, MemorySwap
	// or CpuShares — container resources come from types.Resources.
	Memory      int64              `json:"Memory,omitempty"`
	MemorySwap  int64              `json:"MemorySwap,omitempty"`
	CPUShares   int64              `json:"CpuShares,omitempty"`
	Healthcheck *types.Healthcheck `json:"Healthcheck,omitempty"`

	// Docker-only keys, not part of the OCI image-spec.
	OnBuild []string `json:"OnBuild,omitempty"`
	Shell   []string `json:"Shell,omitempty"`
}

// RootFS lists the uncompressed layer digests (DiffIDs) of an image, base first.
type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

// History is one build step recorded in an image config.
type History struct {
	Created    *time.Time `json:"created,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	Author     string     `json:"author,omitempty"`
	Comment    string     `json:"comment,omitempty"`
	EmptyLayer bool       `json:"empty_layer,omitempty"`
}

// Platform returns the image config's platform as a types.Platform.
func (c ImageConfig) Platform() types.Platform {
	return types.Platform{
		Architecture: c.Architecture,
		OS:           c.OS,
		OSVersion:    c.OSVersion,
		OSFeatures:   c.OSFeatures,
		Variant:      c.Variant,
	}
}

// ToTypesConfig converts a wire-format ConfigBlock into hull's domain
// types.ImageConfig, dropping the keys hull does not act on. Maps and slices
// are copied so the result does not alias the decoded blob.
func ToTypesConfig(c ConfigBlock) types.ImageConfig {
	out := types.ImageConfig{
		User:       c.User,
		WorkingDir: c.WorkingDir,
		StopSignal: c.StopSignal,
	}
	if len(c.ExposedPorts) > 0 {
		out.ExposedPorts = make(map[string]struct{}, len(c.ExposedPorts))
		for k := range c.ExposedPorts {
			out.ExposedPorts[k] = struct{}{}
		}
	}
	if len(c.Volumes) > 0 {
		out.Volumes = make(map[string]struct{}, len(c.Volumes))
		for k := range c.Volumes {
			out.Volumes[k] = struct{}{}
		}
	}
	if len(c.Labels) > 0 {
		out.Labels = make(map[string]string, len(c.Labels))
		for k, v := range c.Labels {
			out.Labels[k] = v
		}
	}
	if len(c.Env) > 0 {
		out.Env = append([]string(nil), c.Env...)
	}
	if len(c.Entrypoint) > 0 {
		out.Entrypoint = append([]string(nil), c.Entrypoint...)
	}
	if len(c.Cmd) > 0 {
		out.Cmd = append([]string(nil), c.Cmd...)
	}
	if len(c.Shell) > 0 {
		out.Shell = append([]string(nil), c.Shell...)
	}
	if c.Healthcheck != nil {
		hc := *c.Healthcheck
		if len(c.Healthcheck.Test) > 0 {
			hc.Test = append([]string(nil), c.Healthcheck.Test...)
		}
		out.Healthcheck = &hc
	}
	return out
}
