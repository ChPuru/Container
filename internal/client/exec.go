package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// ExecCreateRequest is the body of POST /containers/{id}/exec.
type ExecCreateRequest struct {
	// AttachStdin, AttachStdout and AttachStderr select the streams the
	// caller will consume when it starts the exec.
	AttachStdin  bool `json:"AttachStdin"`
	AttachStdout bool `json:"AttachStdout"`
	AttachStderr bool `json:"AttachStderr"`
	// DetachKeys is the escape sequence for the exec's stream.
	DetachKeys string `json:"DetachKeys,omitempty"`
	// Tty allocates a pseudo-terminal for the exec process.
	Tty bool `json:"Tty"`
	// Env entries are merged over the container's environment.
	Env []string `json:"Env,omitempty"`
	// Cmd is the command to run, and must be non-empty.
	Cmd []string `json:"Cmd"`
	// Privileged gives the exec every capability.
	Privileged bool `json:"Privileged,omitempty"`
	// User overrides the container's user.
	User string `json:"User,omitempty"`
	// WorkingDir overrides the container's working directory.
	WorkingDir string `json:"WorkingDir,omitempty"`
}

// ExecCreateResponse carries the new exec's id.
type ExecCreateResponse struct {
	// ID identifies the exec for start, inspect and resize.
	ID string `json:"Id"`
}

// ExecStartRequest is the body of POST /exec/{id}/start.
type ExecStartRequest struct {
	// Detach runs the exec without attaching to it.
	Detach bool `json:"Detach"`
	// Tty must match the exec's own Tty setting.
	Tty bool `json:"Tty"`
}

// ExecInspectResponse is GET /exec/{id}/json.
type ExecInspectResponse struct {
	// ID is the exec id.
	ID string `json:"ID"`
	// Running reports that the exec process is alive.
	Running bool `json:"Running"`
	// ExitCode is meaningful once Running is false.
	ExitCode int `json:"ExitCode"`
	// ContainerID is the container the exec belongs to.
	ContainerID string `json:"ContainerID"`
	// Pid is the exec process's pid, zero before it starts.
	Pid int `json:"Pid"`
	// OpenStdin, OpenStdout and OpenStderr echo the attach request.
	OpenStdin  bool `json:"OpenStdin"`
	OpenStdout bool `json:"OpenStdout"`
	OpenStderr bool `json:"OpenStderr"`
	// ProcessConfig describes the command being run.
	ProcessConfig *struct {
		Privileged bool     `json:"privileged"`
		User       string   `json:"user,omitempty"`
		Tty        bool     `json:"tty"`
		Entrypoint string   `json:"entrypoint"`
		Arguments  []string `json:"arguments,omitempty"`
	} `json:"ProcessConfig,omitempty"`
}

// ExecCreate prepares a command to run inside a container. Nothing runs until
// ExecStart or ExecAttach is called.
func (c *Client) ExecCreate(ctx context.Context, container string, req ExecCreateRequest) (ExecCreateResponse, error) {
	var out ExecCreateResponse
	if err := c.post(ctx, "/containers/"+url.PathEscape(container)+"/exec", nil, req, &out); err != nil {
		return ExecCreateResponse{}, err
	}
	return out, nil
}

// ExecStart runs a prepared exec without attaching to its streams.
func (c *Client) ExecStart(ctx context.Context, execID string, tty bool) error {
	return c.post(ctx, "/exec/"+url.PathEscape(execID)+"/start", nil,
		ExecStartRequest{Detach: true, Tty: tty}, nil)
}

// ExecAttach runs a prepared exec and hijacks the connection so the caller can
// speak to it directly.
func (c *Client) ExecAttach(ctx context.Context, execID string, tty bool) (*HijackedResponse, error) {
	return c.hijack(ctx, http.MethodPost, "/exec/"+url.PathEscape(execID)+"/start", nil,
		ExecStartRequest{Detach: false, Tty: tty}, tty)
}

// ExecInspect reports an exec's state, which is how the CLI learns the exit
// code once the stream has closed.
func (c *Client) ExecInspect(ctx context.Context, execID string) (ExecInspectResponse, error) {
	var out ExecInspectResponse
	if err := c.get(ctx, "/exec/"+url.PathEscape(execID)+"/json", nil, &out); err != nil {
		return ExecInspectResponse{}, err
	}
	return out, nil
}

// ExecResize tells the engine the exec's terminal is now h rows by w columns.
func (c *Client) ExecResize(ctx context.Context, execID string, height, width int) error {
	q := url.Values{
		"h": []string{strconv.Itoa(height)},
		"w": []string{strconv.Itoa(width)},
	}
	return c.post(ctx, "/exec/"+url.PathEscape(execID)+"/resize", q, nil, nil)
}
