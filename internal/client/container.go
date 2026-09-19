package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Filters is the Docker filter map: different keys AND together, repeated
// values of one key OR together.
type Filters map[string][]string

// Add appends one value to a filter key.
func (f Filters) Add(key, value string) { f[key] = append(f[key], value) }

// Len reports how many filter terms are set.
func (f Filters) Len() int {
	n := 0
	for _, v := range f {
		n += len(v)
	}
	return n
}

// encode renders the filters as the JSON object the API expects, or "" when
// nothing is set.
func (f Filters) encode() string {
	if f.Len() == 0 {
		return ""
	}
	buf, err := json.Marshal(map[string][]string(f))
	if err != nil {
		return ""
	}
	return string(buf)
}

// set adds the filters to a query when there are any.
func (f Filters) set(q url.Values) {
	if s := f.encode(); s != "" {
		q.Set("filters", s)
	}
}

// ContainerListOptions narrows GET /containers/json.
type ContainerListOptions struct {
	// All includes containers that are not running.
	All bool
	// Limit returns only the most recently created n containers.
	Limit int
	// Size asks for the writable-layer size, which costs a filesystem walk.
	Size bool
	// Filters are the Docker filter terms, such as "status" or "label".
	Filters Filters
}

// ContainerList lists containers.
func (c *Client) ContainerList(ctx context.Context, opts ContainerListOptions) ([]ContainerSummary, error) {
	q := url.Values{}
	boolQuery(q, "all", opts.All)
	boolQuery(q, "size", opts.Size)
	if opts.Limit > 0 {
		q.Set("limit", strconv.Itoa(opts.Limit))
	}
	opts.Filters.set(q)
	var out []ContainerSummary
	if err := c.get(ctx, "/containers/json", q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ContainerCreate creates a container. An empty name lets the engine generate
// one, and an empty platform lets it pick the host's.
//
// The returned warnings are the engine's own, and must be shown: they are
// where a resource limit that cannot be enforced on this host's hybrid
// cgroups is reported, and a caller that drops them leaves the user with a
// silently unlimited container.
func (c *Client) ContainerCreate(ctx context.Context, name, platform string, req ContainerCreateRequest) (ContainerCreateResponse, error) {
	q := url.Values{}
	if name != "" {
		q.Set("name", name)
	}
	if platform != "" {
		q.Set("platform", platform)
	}
	var out ContainerCreateResponse
	if err := c.post(ctx, "/containers/create", q, req, &out); err != nil {
		return ContainerCreateResponse{}, err
	}
	return out, nil
}

// ContainerInspect returns the full state of one container.
func (c *Client) ContainerInspect(ctx context.Context, id string, size bool) (*ContainerJSON, error) {
	q := url.Values{}
	boolQuery(q, "size", size)
	var out ContainerJSON
	if err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ContainerInspectRaw returns the inspect payload undecoded, so "--format
// json" can print exactly what the engine said, including fields this client
// does not model.
func (c *Client) ContainerInspectRaw(ctx context.Context, id string, size bool) (json.RawMessage, error) {
	q := url.Values{}
	boolQuery(q, "size", size)
	return c.raw(ctx, "/containers/"+url.PathEscape(id)+"/json", q)
}

// raw performs a GET and returns the undecoded body.
func (c *Client) raw(ctx context.Context, path string, q url.Values) (json.RawMessage, error) {
	resp, err := c.do(ctx, http.MethodGet, path, q, nil, nil)
	if err != nil {
		return nil, err
	}
	defer closeBody(resp)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("client: read %s: %w", path, err)
	}
	return json.RawMessage(body), nil
}

// ContainerStart starts a created or stopped container.
func (c *Client) ContainerStart(ctx context.Context, id, detachKeys string) error {
	q := url.Values{}
	if detachKeys != "" {
		q.Set("detachKeys", detachKeys)
	}
	return c.post(ctx, "/containers/"+url.PathEscape(id)+"/start", q, nil, nil)
}

// ContainerStop sends the stop signal and escalates to SIGKILL after timeout
// seconds. A nil timeout uses the container's own stop timeout.
func (c *Client) ContainerStop(ctx context.Context, id string, timeout *int, signal string) error {
	q := url.Values{}
	if timeout != nil {
		q.Set("t", strconv.Itoa(*timeout))
	}
	if signal != "" {
		q.Set("signal", signal)
	}
	return c.post(ctx, "/containers/"+url.PathEscape(id)+"/stop", q, nil, nil)
}

// ContainerRestart stops and starts a container.
func (c *Client) ContainerRestart(ctx context.Context, id string, timeout *int) error {
	q := url.Values{}
	if timeout != nil {
		q.Set("t", strconv.Itoa(*timeout))
	}
	return c.post(ctx, "/containers/"+url.PathEscape(id)+"/restart", q, nil, nil)
}

// ContainerKill sends one signal to a container's main process.
func (c *Client) ContainerKill(ctx context.Context, id, signal string) error {
	q := url.Values{}
	if signal != "" {
		q.Set("signal", signal)
	}
	return c.post(ctx, "/containers/"+url.PathEscape(id)+"/kill", q, nil, nil)
}

// ContainerPause freezes every process in a container.
func (c *Client) ContainerPause(ctx context.Context, id string) error {
	return c.post(ctx, "/containers/"+url.PathEscape(id)+"/pause", nil, nil, nil)
}

// ContainerUnpause thaws a paused container.
func (c *Client) ContainerUnpause(ctx context.Context, id string) error {
	return c.post(ctx, "/containers/"+url.PathEscape(id)+"/unpause", nil, nil, nil)
}

// ContainerRemoveOptions configures DELETE /containers/{id}.
type ContainerRemoveOptions struct {
	// Force removes a running container.
	Force bool
	// RemoveVolumes removes anonymous volumes created with the container.
	RemoveVolumes bool
	// RemoveLinks is accepted for compatibility and is not implemented.
	RemoveLinks bool
}

// ContainerRemove deletes a container.
func (c *Client) ContainerRemove(ctx context.Context, id string, opts ContainerRemoveOptions) error {
	q := url.Values{}
	boolQuery(q, "force", opts.Force)
	boolQuery(q, "v", opts.RemoveVolumes)
	boolQuery(q, "link", opts.RemoveLinks)
	return c.del(ctx, "/containers/"+url.PathEscape(id), q, nil)
}

// ContainerRename gives a container a new name.
func (c *Client) ContainerRename(ctx context.Context, id, newName string) error {
	q := url.Values{"name": []string{newName}}
	return c.post(ctx, "/containers/"+url.PathEscape(id)+"/rename", q, nil, nil)
}

// ContainerUpdate changes a running container's resource limits. The returned
// warnings say which limits the host could not actually apply, and are as
// load-bearing here as they are on create.
func (c *Client) ContainerUpdate(ctx context.Context, id string, cfg ContainerUpdateRequest) ([]string, error) {
	var out ContainerUpdateResponse
	if err := c.post(ctx, "/containers/"+url.PathEscape(id)+"/update", nil, cfg, &out); err != nil {
		return nil, err
	}
	return out.Warnings, nil
}

// Wait conditions, as the API defines them.
const (
	// WaitConditionNotRunning returns as soon as the container is not
	// running, which is the default.
	WaitConditionNotRunning = "not-running"
	// WaitConditionNextExit waits for the next exit, ignoring the current
	// state.
	WaitConditionNextExit = "next-exit"
	// WaitConditionRemoved waits until the container has been removed.
	WaitConditionRemoved = "removed"
)

// ContainerWait blocks until the container reaches the condition and reports
// its exit code.
func (c *Client) ContainerWait(ctx context.Context, id, condition string) (ContainerWaitResponse, error) {
	q := url.Values{}
	if condition != "" {
		q.Set("condition", condition)
	}
	var out ContainerWaitResponse
	if err := c.post(ctx, "/containers/"+url.PathEscape(id)+"/wait", q, nil, &out); err != nil {
		return ContainerWaitResponse{}, err
	}
	return out, nil
}

// ContainerLogsOptions configures GET /containers/{id}/logs.
type ContainerLogsOptions struct {
	// ShowStdout and ShowStderr select the streams. With neither set the
	// engine returns nothing, so callers normally set both.
	ShowStdout bool
	ShowStderr bool
	// Since and Until bound the window. Both accept a unix timestamp or a
	// Go duration such as "10m".
	Since string
	Until string
	// Timestamps prefixes every line with its RFC3339Nano time.
	Timestamps bool
	// Follow keeps the stream open and delivers new lines as they arrive.
	Follow bool
	// Tail is a line count, or "all".
	Tail string
}

// ContainerLogs streams a container's logs.
//
// The reader carries Docker's 8-byte stream framing unless the container has
// a TTY; use logbuf.DemuxFramed, or HijackedResponse.Stream's logic, to split
// stdout from stderr.
func (c *Client) ContainerLogs(ctx context.Context, id string, opts ContainerLogsOptions) (io.ReadCloser, error) {
	q := url.Values{}
	boolQuery(q, "stdout", opts.ShowStdout)
	boolQuery(q, "stderr", opts.ShowStderr)
	boolQuery(q, "timestamps", opts.Timestamps)
	boolQuery(q, "follow", opts.Follow)
	if opts.Since != "" {
		q.Set("since", opts.Since)
	}
	if opts.Until != "" {
		q.Set("until", opts.Until)
	}
	if opts.Tail != "" {
		q.Set("tail", opts.Tail)
	}
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/logs", q, nil, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// ContainerAttachOptions configures POST /containers/{id}/attach.
type ContainerAttachOptions struct {
	// Stream asks for the live stream rather than only the replayed log.
	Stream bool
	// Stdin, Stdout and Stderr select the directions to attach.
	Stdin  bool
	Stdout bool
	Stderr bool
	// Logs replays what the container has already written.
	Logs bool
	// DetachKeys is the escape sequence, such as "ctrl-p,ctrl-q".
	DetachKeys string
	// TTY tells the client whether to expect framed output. It must match
	// the container's own Tty setting.
	TTY bool
}

// ContainerAttach attaches to a running container's streams.
func (c *Client) ContainerAttach(ctx context.Context, id string, opts ContainerAttachOptions) (*HijackedResponse, error) {
	q := url.Values{}
	boolQuery(q, "stream", opts.Stream)
	boolQuery(q, "stdin", opts.Stdin)
	boolQuery(q, "stdout", opts.Stdout)
	boolQuery(q, "stderr", opts.Stderr)
	boolQuery(q, "logs", opts.Logs)
	if opts.DetachKeys != "" {
		q.Set("detachKeys", opts.DetachKeys)
	}
	return c.hijack(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/attach", q, nil, opts.TTY)
}

// ContainerResize tells the engine the terminal is now h rows by w columns.
func (c *Client) ContainerResize(ctx context.Context, id string, height, width int) error {
	q := url.Values{
		"h": []string{strconv.Itoa(height)},
		"w": []string{strconv.Itoa(width)},
	}
	return c.post(ctx, "/containers/"+url.PathEscape(id)+"/resize", q, nil, nil)
}

// ContainerTop lists the processes running inside a container.
func (c *Client) ContainerTop(ctx context.Context, id, psArgs string) (ContainerTopResponse, error) {
	q := url.Values{}
	if psArgs != "" {
		q.Set("ps_args", psArgs)
	}
	var out ContainerTopResponse
	if err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/top", q, &out); err != nil {
		return ContainerTopResponse{}, err
	}
	return out, nil
}

// ContainerChanges reports what the container has changed in its filesystem
// relative to the image.
func (c *Client) ContainerChanges(ctx context.Context, id string) ([]ContainerChange, error) {
	var out []ContainerChange
	if err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/changes", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ContainerExport streams a container's filesystem as a tar archive.
func (c *Client) ContainerExport(ctx context.Context, id string) (io.ReadCloser, error) {
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/export", nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// CommitOptions configures POST /commit.
type CommitOptions struct {
	// Container is the container to commit.
	Container string
	// Repo and Tag name the resulting image.
	Repo string
	Tag  string
	// Comment and Author are recorded in the image history.
	Comment string
	Author  string
	// Pause freezes the container while its filesystem is captured.
	Pause bool
	// Changes are Dockerfile instructions applied to the committed config.
	Changes []string
	// Config overrides the committed image's configuration.
	Config *Config
}

// CommitResponse carries the id of the image a commit produced.
type CommitResponse struct {
	// ID is the new image id.
	ID string `json:"Id"`
}

// ContainerCommit turns a container's filesystem into an image.
func (c *Client) ContainerCommit(ctx context.Context, opts CommitOptions) (CommitResponse, error) {
	q := url.Values{"container": []string{opts.Container}}
	if opts.Repo != "" {
		q.Set("repo", opts.Repo)
	}
	if opts.Tag != "" {
		q.Set("tag", opts.Tag)
	}
	if opts.Comment != "" {
		q.Set("comment", opts.Comment)
	}
	if opts.Author != "" {
		q.Set("author", opts.Author)
	}
	if opts.Pause {
		q.Set("pause", "1")
	} else {
		q.Set("pause", "0")
	}
	for _, ch := range opts.Changes {
		q.Add("changes", ch)
	}
	var out CommitResponse
	if err := c.post(ctx, "/commit", q, opts.Config, &out); err != nil {
		return CommitResponse{}, err
	}
	return out, nil
}

// ContainerStats streams resource samples for one container. With stream set
// the reader stays open and yields one JSON object per interval; without it
// the engine sends a single sample and closes.
func (c *Client) ContainerStats(ctx context.Context, id string, stream bool) (io.ReadCloser, error) {
	q := url.Values{}
	if stream {
		q.Set("stream", "1")
	} else {
		q.Set("stream", "0")
		q.Set("one-shot", "1")
	}
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/stats", q, nil, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// ContainerStatsStream decodes the stats stream and hands each sample to fn.
// It returns when the stream ends, when fn returns an error, or when ctx is
// cancelled.
func (c *Client) ContainerStatsStream(ctx context.Context, id string, stream bool, fn func(StatsResponse) error) error {
	body, err := c.ContainerStats(ctx, id, stream)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()
	dec := json.NewDecoder(body)
	for {
		var s StatsResponse
		if err := dec.Decode(&s); err != nil {
			if isStreamEnd(err) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("client: decode stats for %s: %w", id, err)
		}
		if err := fn(s); err != nil {
			return err
		}
	}
}

// ContainersPrune removes stopped containers.
func (c *Client) ContainersPrune(ctx context.Context, filters Filters) (PruneReport, error) {
	q := url.Values{}
	filters.set(q)
	var out PruneReport
	if err := c.post(ctx, "/containers/prune", q, nil, &out); err != nil {
		return PruneReport{}, err
	}
	return out, nil
}

// ContainerPorts returns the published bindings for one container, which is
// what "hull port" prints. It is a convenience over inspect rather than an
// endpoint of its own, because the API reports ports in two different shapes
// and inspect's is the complete one.
func (c *Client) ContainerPorts(ctx context.Context, id string) (map[string][]PortBinding, error) {
	insp, err := c.ContainerInspect(ctx, id, false)
	if err != nil {
		return nil, err
	}
	if insp.NetworkSettings == nil {
		return map[string][]PortBinding{}, nil
	}
	return insp.NetworkSettings.Ports, nil
}

// ParsePort splits a "port/proto" key into its halves, defaulting the protocol
// to tcp the way every Docker surface does.
func ParsePort(spec string) (port, proto string) {
	port, proto, ok := strings.Cut(spec, "/")
	if !ok || proto == "" {
		return port, "tcp"
	}
	return port, proto
}
