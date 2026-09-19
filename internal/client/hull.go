package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/rahuldhali/hull/internal/hostinfo"
)

// The hull-only endpoints live under /hull/v1 rather than inside the Docker
// namespace, so that a Docker client never sees a path it does not recognise
// and hull never has to bend one of Docker's shapes around a verb Docker does
// not have. They are not API-version prefixed; /hull/v1 is their own version.

// Doctor returns the engine host's capability report: what this machine
// supports, and the exact fix for what it does not.
//
// kconfig asks for the full /proc/config.gz dump, which is thousands of lines
// and is deliberately off by default so the answer is not buried under it.
func (c *Client) Doctor(ctx context.Context, kconfig bool) (*hostinfo.Report, error) {
	q := url.Values{}
	boolQuery(q, "kconfig", kconfig)
	var out hostinfo.Report
	if err := c.get(ctx, "/hull/v1/doctor", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DoctorRaw returns the doctor report undecoded, for "hull doctor --json".
func (c *Client) DoctorRaw(ctx context.Context, kconfig bool) (json.RawMessage, error) {
	q := url.Values{}
	boolQuery(q, "kconfig", kconfig)
	return c.raw(ctx, "/hull/v1/doctor", q)
}

// Checkpoint is one named snapshot of a container's writable layer.
type Checkpoint struct {
	// Name is what the user called it.
	Name string `json:"name"`
	// Container is the container it was taken from.
	Container string `json:"container,omitempty"`
	// Created is when it was taken.
	Created time.Time `json:"created"`
	// Size is how many bytes the checkpoint holds.
	Size int64 `json:"size,omitempty"`
	// Parent is the checkpoint this one was taken on top of, when there is
	// one.
	Parent string `json:"parent,omitempty"`
}

// Change is one filesystem difference between two checkpoints, or between a
// container and its image. Kind matches Docker's numbering: 0 modified,
// 1 added, 2 deleted.
type Change struct {
	Path string `json:"path"`
	Kind int    `json:"kind"`
}

// CheckpointCreate commits a container's writable layer as a named checkpoint.
func (c *Client) CheckpointCreate(ctx context.Context, container, name string) (Checkpoint, error) {
	var out Checkpoint
	body := struct {
		Name string `json:"name"`
	}{Name: name}
	if err := c.post(ctx, "/hull/v1/containers/"+url.PathEscape(container)+"/checkpoints", nil, body, &out); err != nil {
		return Checkpoint{}, err
	}
	return out, nil
}

// CheckpointList lists a container's checkpoints.
func (c *Client) CheckpointList(ctx context.Context, container string) ([]Checkpoint, error) {
	var out []Checkpoint
	if err := c.get(ctx, "/hull/v1/containers/"+url.PathEscape(container)+"/checkpoints", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CheckpointRemove deletes one checkpoint.
func (c *Client) CheckpointRemove(ctx context.Context, container, name string) error {
	return c.del(ctx, "/hull/v1/containers/"+url.PathEscape(container)+"/checkpoints/"+url.PathEscape(name), nil, nil)
}

// CheckpointRevert rolls a container's writable layer back to a checkpoint.
func (c *Client) CheckpointRevert(ctx context.Context, container, name string) error {
	return c.post(ctx, "/hull/v1/containers/"+url.PathEscape(container)+"/revert", url.Values{"name": []string{name}}, nil, nil)
}

// CheckpointBranch starts a new container from a checkpoint of another one.
func (c *Client) CheckpointBranch(ctx context.Context, container, name, newName string) (ContainerCreateResponse, error) {
	q := url.Values{"name": []string{name}, "newName": []string{newName}}
	var out ContainerCreateResponse
	if err := c.post(ctx, "/hull/v1/containers/"+url.PathEscape(container)+"/branch", q, nil, &out); err != nil {
		return ContainerCreateResponse{}, err
	}
	return out, nil
}

// CheckpointDiff reports what changed between two checkpoints. An empty second
// name compares against the container's current state.
func (c *Client) CheckpointDiff(ctx context.Context, container, a, b string) ([]Change, error) {
	q := url.Values{"a": []string{a}}
	if b != "" {
		q.Set("b", b)
	}
	var out []Change
	if err := c.get(ctx, "/hull/v1/containers/"+url.PathEscape(container)+"/checkpoints/diff", q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ContainerWarnings returns the warnings the engine recorded when it built a
// container's bundle — chiefly the resource limits this host cannot enforce.
func (c *Client) ContainerWarnings(ctx context.Context, container string) ([]string, error) {
	var out []string
	if err := c.get(ctx, "/hull/v1/containers/"+url.PathEscape(container)+"/warnings", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SetIdleFreeze changes how long a container may be idle before the engine
// freezes it. A negative duration pins the container permanently awake.
func (c *Client) SetIdleFreeze(ctx context.Context, container string, after time.Duration) error {
	body := struct {
		FreezeAfter string `json:"freezeAfter"`
	}{FreezeAfter: after.String()}
	return c.post(ctx, "/hull/v1/containers/"+url.PathEscape(container)+"/idle", nil, body, nil)
}

// LockEntry is one line of hull.lock: a reference pinned to the exact digest
// it resolved to.
type LockEntry struct {
	// Ref is the reference as the user wrote it.
	Ref string `json:"ref"`
	// Resolved is the fully qualified reference.
	Resolved string `json:"resolved"`
	// Digest is the manifest digest the reference resolved to.
	Digest string `json:"digest"`
	// MediaType is the manifest's media type.
	MediaType string `json:"mediaType,omitempty"`
	// Size is the manifest size in bytes.
	Size int64 `json:"size,omitempty"`
	// Platform is the platform the digest was resolved for.
	Platform string `json:"platform,omitempty"`
}

// Lockfile resolves every reference to a digest, which is what "hull lock"
// writes into hull.lock so a project rebuilds byte-identically.
func (c *Client) Lockfile(ctx context.Context, refs []string) ([]LockEntry, error) {
	body := struct {
		Refs []string `json:"refs"`
	}{Refs: refs}
	var out []LockEntry
	if err := c.post(ctx, "/hull/v1/lock", nil, body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SyncOptions configures a folder sync between a Windows path and a volume.
type SyncOptions struct {
	// HostPath is the path as the engine can see it, e.g. /mnt/c/src/app.
	HostPath string `json:"hostPath"`
	// Volume is the named volume to keep in step with it.
	Volume string `json:"volume"`
	// Direction is "both", "to-volume" or "to-host".
	Direction string `json:"direction,omitempty"`
	// Once performs a single reconciliation instead of watching.
	Once bool `json:"once,omitempty"`
	// Exclude are path patterns to skip.
	Exclude []string `json:"exclude,omitempty"`
}

// SyncEvent is one line of a running sync.
type SyncEvent struct {
	// Kind is what happened, e.g. "copy", "delete", "conflict", "error".
	Kind string `json:"kind"`
	// Path is the relative path the event is about.
	Path string `json:"path,omitempty"`
	// Side is "host" or "volume".
	Side string `json:"side,omitempty"`
	// Bytes is how much moved, when anything did.
	Bytes int64 `json:"bytes,omitempty"`
	// Message is a human explanation, set for errors and conflicts.
	Message string `json:"message,omitempty"`
}

// Sync keeps a host folder and a volume in step, reporting each action through
// fn until the context is cancelled or a one-shot sync completes.
func (c *Client) Sync(ctx context.Context, opts SyncOptions, fn func(SyncEvent) error) error {
	resp, err := c.doStreamBody(ctx, http.MethodPost, "/hull/v1/sync", nil, opts)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	dec := json.NewDecoder(resp.Body)
	for {
		var ev SyncEvent
		if err := dec.Decode(&ev); err != nil {
			if isStreamEnd(err) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		if fn != nil {
			if err := fn(ev); err != nil {
				return err
			}
		}
	}
}

// EngineStatus is what "hull engine status" reports.
type EngineStatus struct {
	// Running reports that the daemon answered.
	Running bool `json:"running"`
	// Version is the daemon's version string.
	Version string `json:"version,omitempty"`
	// PID is the daemon's process id inside its distro.
	PID int `json:"pid,omitempty"`
	// Uptime is how long it has been up.
	Uptime time.Duration `json:"uptime,omitempty"`
	// DataRoot is the engine's data directory.
	DataRoot string `json:"dataRoot,omitempty"`
	// Distro is the WSL distro holding the engine.
	Distro string `json:"distro,omitempty"`
	// Containers and Images are the population it is managing.
	Containers int `json:"containers"`
	Images     int `json:"images"`
	// IdleFrozen is how many containers the idle watcher has frozen.
	IdleFrozen int `json:"idleFrozen,omitempty"`
}

// EngineStatus asks the daemon about itself. Unlike Info it is cheap and is
// meant to be called on a timer.
func (c *Client) EngineStatus(ctx context.Context) (EngineStatus, error) {
	var out EngineStatus
	if err := c.get(ctx, "/hull/v1/engine/status", nil, &out); err != nil {
		return EngineStatus{}, err
	}
	return out, nil
}

// EngineGC reclaims unreferenced blobs and snapshots. With dryRun set the
// engine reports what it would remove and removes nothing.
func (c *Client) EngineGC(ctx context.Context, dryRun bool) (PruneReport, error) {
	q := url.Values{}
	boolQuery(q, "dry-run", dryRun)
	var out PruneReport
	if err := c.post(ctx, "/hull/v1/engine/gc", q, nil, &out); err != nil {
		return PruneReport{}, err
	}
	return out, nil
}

// DebugOptions configures the toolbox shell attached to a container.
type DebugOptions struct {
	// Image is the toolbox image, empty for the engine's built-in busybox.
	Image string `json:"image,omitempty"`
	// Cmd is the command to run, empty for the toolbox's shell.
	Cmd []string `json:"cmd,omitempty"`
	// Tty allocates a pseudo-terminal.
	Tty bool `json:"tty"`
	// Namespaces selects which of the target's namespaces to join; empty
	// means all of them.
	Namespaces []string `json:"namespaces,omitempty"`
}

// Debug attaches a toolbox shell to a container's namespaces, which is the
// only way into a distroless container that has no shell of its own.
func (c *Client) Debug(ctx context.Context, container string, opts DebugOptions) (*HijackedResponse, error) {
	return c.hijack(ctx, http.MethodPost, "/hull/v1/containers/"+url.PathEscape(container)+"/debug", nil, opts, opts.Tty)
}

// doStreamBody performs a request with a JSON body and leaves the response
// body open for streaming.
func (c *Client) doStreamBody(ctx context.Context, method, path string, query url.Values, in any) (*http.Response, error) {
	buf, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	return c.do(ctx, method, path, query, bytes.NewReader(buf), headers)
}
