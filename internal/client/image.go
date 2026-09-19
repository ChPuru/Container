package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// registryAuthHeader carries a base64 AuthConfig on pull, push and build.
const registryAuthHeader = "X-Registry-Auth"

// EncodeAuth renders a credential into the header form the API expects:
// base64url of the JSON object, with no padding stripped.
func EncodeAuth(auth AuthConfig) (string, error) {
	buf, err := json.Marshal(auth)
	if err != nil {
		return "", fmt.Errorf("client: encode registry auth: %w", err)
	}
	return base64.URLEncoding.EncodeToString(buf), nil
}

// ProgressFunc receives one decoded object of a chunked JSON progress stream.
// Returning an error stops the stream and is reported to the caller.
type ProgressFunc func(ProgressMessage) error

// progressStream decodes a chunked JSON progress body.
//
// The endpoints that use it have already sent a 200 and their headers by the
// time anything can fail, so a failure arrives as a final object with "error"
// set rather than as a status code. Missing that is how a broken pull looks
// like a successful one.
func progressStream(ctx context.Context, body io.ReadCloser, fn ProgressFunc) error {
	defer func() { _ = body.Close() }()
	dec := json.NewDecoder(body)
	for {
		var msg ProgressMessage
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("client: decode progress stream: %w", err)
		}
		if msg.Error != "" || (msg.ErrorDetail != nil && msg.ErrorDetail.Message != "") {
			text := msg.Error
			if text == "" {
				text = msg.ErrorDetail.Message
			}
			return fmt.Errorf("%s", text)
		}
		if fn != nil {
			if err := fn(msg); err != nil {
				return err
			}
		}
	}
}

// ProgressDetail is the byte counter attached to a progress message.
type ProgressDetail struct {
	// Current is how many bytes have moved so far.
	Current int64 `json:"current,omitempty"`
	// Total is the size of the object, or zero when it is unknown.
	Total int64 `json:"total,omitempty"`
}

// ProgressMessage is one object of a chunked JSON progress stream, as
// /images/create, /images/load, /images/push and /build all emit.
//
// A failure arrives as a final message with Error set and a 200 status,
// because the headers went out long before anything failed.
type ProgressMessage struct {
	// ID identifies the layer or object the message is about.
	ID string `json:"id,omitempty"`
	// Status is the human phrase, e.g. "Downloading" or "Pull complete".
	Status string `json:"status,omitempty"`
	// Stream is build output, which arrives as raw text rather than status.
	Stream string `json:"stream,omitempty"`
	// Progress is the engine's own rendered progress bar, which hull ignores
	// in favour of ProgressDetail.
	Progress string `json:"progress,omitempty"`
	// ProgressDetail is the machine-readable byte counter.
	ProgressDetail *ProgressDetail `json:"progressDetail,omitempty"`
	// Error and ErrorDetail carry a mid-stream failure.
	Error       string `json:"error,omitempty"`
	ErrorDetail *struct {
		Code    int    `json:"code,omitempty"`
		Message string `json:"message"`
	} `json:"errorDetail,omitempty"`
	// Aux carries structured extras, such as the built image id.
	Aux json.RawMessage `json:"aux,omitempty"`
}

// RootFS lists an image's layer diff ids.
type RootFS struct {
	// Type is always "layers" for an OCI image.
	Type string `json:"Type"`
	// Layers are the uncompressed layer digests, base first.
	Layers []string `json:"Layers,omitempty"`
}

// ImageInspect is GET /images/{name}/json.
type ImageInspect struct {
	// ID is the config blob digest.
	ID string `json:"Id"`
	// RepoTags and RepoDigests are the references pointing at this image.
	RepoTags    []string `json:"RepoTags,omitempty"`
	RepoDigests []string `json:"RepoDigests,omitempty"`
	// Parent is the parent image id, empty for a pulled image.
	Parent string `json:"Parent,omitempty"`
	// Comment and Author come from the image history.
	Comment string `json:"Comment,omitempty"`
	Author  string `json:"Author,omitempty"`
	// Created is an RFC3339 timestamp.
	Created string `json:"Created"`
	// Architecture and Os are the image's platform.
	Architecture string `json:"Architecture"`
	Os           string `json:"Os"`
	// Size is the sum of the uncompressed layers.
	Size        int64 `json:"Size"`
	VirtualSize int64 `json:"VirtualSize,omitempty"`
	// Config is the image's runtime configuration.
	Config *Config `json:"Config,omitempty"`
	// RootFS lists the layers.
	RootFS RootFS `json:"RootFS,omitzero"`
	// Labels are the image labels, also present inside Config.
	Labels map[string]string `json:"Labels,omitempty"`
}

// ImageListOptions narrows GET /images/json.
type ImageListOptions struct {
	// All includes intermediate and untagged images.
	All bool
	// Filters are Docker filter terms such as "dangling" or "reference".
	Filters Filters
	// SharedSize asks for the shared-layer accounting.
	SharedSize bool
}

// ImageList lists local images.
func (c *Client) ImageList(ctx context.Context, opts ImageListOptions) ([]ImageSummary, error) {
	q := url.Values{}
	boolQuery(q, "all", opts.All)
	boolQuery(q, "shared-size", opts.SharedSize)
	opts.Filters.set(q)
	var out []ImageSummary
	if err := c.get(ctx, "/images/json", q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ImagePullOptions configures POST /images/create.
type ImagePullOptions struct {
	// Platform pins the image variant, e.g. "linux/amd64".
	Platform string
	// All pulls every tag of the repository.
	All bool
	// Auth is the registry credential, when one is needed.
	Auth *AuthConfig
}

// ImagePull fetches an image and reports progress through fn.
//
// The reference may carry a tag or a digest; without either, "latest" is
// assumed, exactly as Docker does.
func (c *Client) ImagePull(ctx context.Context, ref string, opts ImagePullOptions, fn ProgressFunc) error {
	name, tag := splitRef(ref)
	q := url.Values{"fromImage": []string{name}}
	if tag != "" && !opts.All {
		q.Set("tag", tag)
	}
	if opts.Platform != "" {
		q.Set("platform", opts.Platform)
	}
	headers := http.Header{}
	if opts.Auth != nil {
		enc, err := EncodeAuth(*opts.Auth)
		if err != nil {
			return err
		}
		headers.Set(registryAuthHeader, enc)
	}
	resp, err := c.do(ctx, http.MethodPost, "/images/create", q, nil, headers)
	if err != nil {
		return err
	}
	return progressStream(ctx, resp.Body, fn)
}

// ImagePushOptions configures POST /images/{name}/push.
type ImagePushOptions struct {
	// All pushes every tag of the repository.
	All bool
	// Auth is the registry credential.
	Auth *AuthConfig
}

// ImagePush uploads an image and reports progress through fn.
func (c *Client) ImagePush(ctx context.Context, ref string, opts ImagePushOptions, fn ProgressFunc) error {
	name, tag := splitRef(ref)
	q := url.Values{}
	if tag != "" && !opts.All {
		q.Set("tag", tag)
	}
	headers := http.Header{}
	if opts.Auth != nil {
		enc, err := EncodeAuth(*opts.Auth)
		if err != nil {
			return err
		}
		headers.Set(registryAuthHeader, enc)
	} else {
		// The endpoint insists on the header even for an anonymous push.
		enc, _ := EncodeAuth(AuthConfig{})
		headers.Set(registryAuthHeader, enc)
	}
	resp, err := c.do(ctx, http.MethodPost, "/images/"+escapeRef(name)+"/push", q, nil, headers)
	if err != nil {
		return err
	}
	return progressStream(ctx, resp.Body, fn)
}

// ImageInspect returns one image's metadata.
func (c *Client) ImageInspect(ctx context.Context, ref string) (*ImageInspect, error) {
	var out ImageInspect
	if err := c.get(ctx, "/images/"+escapeRef(ref)+"/json", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ImageInspectRaw returns the inspect payload undecoded.
func (c *Client) ImageInspectRaw(ctx context.Context, ref string) (json.RawMessage, error) {
	return c.raw(ctx, "/images/"+escapeRef(ref)+"/json", nil)
}

// ImageHistory lists an image's build steps.
func (c *Client) ImageHistory(ctx context.Context, ref string) ([]HistoryEntry, error) {
	var out []HistoryEntry
	if err := c.get(ctx, "/images/"+escapeRef(ref)+"/history", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ImageTag points a new reference at an existing image.
func (c *Client) ImageTag(ctx context.Context, source, target string) error {
	repo, tag := splitRef(target)
	q := url.Values{"repo": []string{repo}}
	if tag != "" {
		q.Set("tag", tag)
	}
	return c.post(ctx, "/images/"+escapeRef(source)+"/tag", q, nil, nil)
}

// ImageRemove deletes an image or one of its tags.
func (c *Client) ImageRemove(ctx context.Context, ref string, force, noPrune bool) ([]ImageDeleteResponse, error) {
	q := url.Values{}
	boolQuery(q, "force", force)
	boolQuery(q, "noprune", noPrune)
	var out []ImageDeleteResponse
	if err := c.del(ctx, "/images/"+escapeRef(ref), q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ImageSave streams one or more images as a tar archive.
func (c *Client) ImageSave(ctx context.Context, refs []string) (io.ReadCloser, error) {
	q := url.Values{}
	for _, r := range refs {
		q.Add("names", r)
	}
	resp, err := c.do(ctx, http.MethodGet, "/images/get", q, nil, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// ImageLoad reads a tar archive of images and reports progress through fn.
func (c *Client) ImageLoad(ctx context.Context, input io.Reader, quiet bool, fn ProgressFunc) error {
	q := url.Values{}
	boolQuery(q, "quiet", quiet)
	headers := http.Header{}
	headers.Set("Content-Type", "application/x-tar")
	resp, err := c.do(ctx, http.MethodPost, "/images/load", q, input, headers)
	if err != nil {
		return err
	}
	return progressStream(ctx, resp.Body, fn)
}

// ImagesPrune removes unused images.
func (c *Client) ImagesPrune(ctx context.Context, filters Filters) (PruneReport, error) {
	q := url.Values{}
	filters.set(q)
	var out PruneReport
	if err := c.post(ctx, "/images/prune", q, nil, &out); err != nil {
		return PruneReport{}, err
	}
	return out, nil
}

// ImageBuildOptions configures POST /build.
type ImageBuildOptions struct {
	// Tags are the references to apply to the built image.
	Tags []string
	// Dockerfile is the path to the build file inside the context.
	Dockerfile string
	// BuildArgs are ARG values; a nil entry unsets one.
	BuildArgs map[string]*string
	// Labels are applied to the resulting image.
	Labels map[string]string
	// NoCache disables layer reuse.
	NoCache bool
	// Pull always re-fetches the base image.
	Pull bool
	// Remove and ForceRemove control intermediate container cleanup.
	Remove      bool
	ForceRemove bool
	// Quiet suppresses the build output and prints only the image id.
	Quiet bool
	// Target selects one stage of a multi-stage build.
	Target string
	// Platform pins the build platform.
	Platform string
	// NetworkMode is the network intermediate containers get.
	NetworkMode string
	// Auth carries registry credentials, keyed by registry host.
	Auth map[string]AuthConfig
}

// ImageBuild sends a build context and streams the build output through fn.
//
// When the engine ships without a bundled builder this returns a 501 whose
// message names the fix; IsNotImplemented reports that case.
func (c *Client) ImageBuild(ctx context.Context, buildContext io.Reader, opts ImageBuildOptions, fn ProgressFunc) error {
	q := url.Values{}
	for _, t := range opts.Tags {
		q.Add("t", t)
	}
	if opts.Dockerfile != "" {
		q.Set("dockerfile", opts.Dockerfile)
	}
	if opts.Target != "" {
		q.Set("target", opts.Target)
	}
	if opts.Platform != "" {
		q.Set("platform", opts.Platform)
	}
	if opts.NetworkMode != "" {
		q.Set("networkmode", opts.NetworkMode)
	}
	boolQuery(q, "nocache", opts.NoCache)
	boolQuery(q, "pull", opts.Pull)
	boolQuery(q, "q", opts.Quiet)
	boolQuery(q, "forcerm", opts.ForceRemove)
	if opts.Remove {
		q.Set("rm", "1")
	} else {
		q.Set("rm", "0")
	}
	if len(opts.BuildArgs) > 0 {
		buf, err := json.Marshal(opts.BuildArgs)
		if err != nil {
			return fmt.Errorf("client: encode build args: %w", err)
		}
		q.Set("buildargs", string(buf))
	}
	if len(opts.Labels) > 0 {
		buf, err := json.Marshal(opts.Labels)
		if err != nil {
			return fmt.Errorf("client: encode build labels: %w", err)
		}
		q.Set("labels", string(buf))
	}
	headers := http.Header{}
	headers.Set("Content-Type", "application/x-tar")
	if len(opts.Auth) > 0 {
		buf, err := json.Marshal(opts.Auth)
		if err != nil {
			return fmt.Errorf("client: encode build auth: %w", err)
		}
		headers.Set("X-Registry-Config", base64.URLEncoding.EncodeToString(buf))
	}
	resp, err := c.do(ctx, http.MethodPost, "/build", q, buildContext, headers)
	if err != nil {
		return err
	}
	return progressStream(ctx, resp.Body, fn)
}

// BuildCachePrune removes the builder's cache.
func (c *Client) BuildCachePrune(ctx context.Context, all bool) (PruneReport, error) {
	q := url.Values{}
	boolQuery(q, "all", all)
	var out PruneReport
	if err := c.post(ctx, "/build/prune", q, nil, &out); err != nil {
		return PruneReport{}, err
	}
	return out, nil
}

// DistributionInspect resolves a reference against its registry without
// pulling it, which is what the lockfile and "pull --dry-run" need.
func (c *Client) DistributionInspect(ctx context.Context, ref string, auth *AuthConfig) (json.RawMessage, error) {
	headers := http.Header{}
	if auth != nil {
		enc, err := EncodeAuth(*auth)
		if err != nil {
			return nil, err
		}
		headers.Set(registryAuthHeader, enc)
	}
	resp, err := c.do(ctx, http.MethodGet, "/distribution/"+escapeRef(ref)+"/json", nil, nil, headers)
	if err != nil {
		return nil, err
	}
	defer closeBody(resp)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("client: read distribution inspect: %w", err)
	}
	return json.RawMessage(body), nil
}

// splitRef separates a reference's name from its tag or digest. A digest stays
// attached to the name the way the API expects on pull.
func splitRef(ref string) (name, tag string) {
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return ref, ""
	}
	// A colon inside the registry host's port is not a tag separator.
	if strings.Contains(ref[i+1:], "/") {
		return ref, ""
	}
	return ref[:i], ref[i+1:]
}

// escapeRef escapes a reference for use as one path segment while leaving the
// slashes that separate a repository's namespace intact, which is what the
// API's own routing expects.
func escapeRef(ref string) string {
	parts := strings.Split(ref, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}
