package client

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// EngineLogsOptions narrows GET /hull/v1/engine/logs.
type EngineLogsOptions struct {
	// Follow keeps the stream open and delivers new lines as they arrive.
	Follow bool
	// Tail is how many existing lines to replay; zero means a sensible
	// default and a negative value means all of them.
	Tail int
	// Since bounds the window, as a unix timestamp or a Go duration.
	Since string
}

// EngineLogs streams the daemon's own log.
//
// This is the one log a user cannot get any other way: on Windows the daemon
// lives inside a WSL distro they never shell into, so "hull engine logs" is
// the only path to the reason the engine would not start.
func (c *Client) EngineLogs(ctx context.Context, opts EngineLogsOptions) (io.ReadCloser, error) {
	q := url.Values{}
	boolQuery(q, "follow", opts.Follow)
	if opts.Tail != 0 {
		q.Set("tail", strconv.Itoa(opts.Tail))
	}
	if opts.Since != "" {
		q.Set("since", opts.Since)
	}
	resp, err := c.do(ctx, http.MethodGet, "/hull/v1/engine/logs", q, nil, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// EngineStop asks the daemon to shut itself down cleanly.
//
// It is best-effort by nature: the response may never arrive, because the
// daemon closes its listener as part of stopping. A transport failure after
// the request went out is therefore not reported as an error.
func (c *Client) EngineStop(ctx context.Context) error {
	err := c.post(ctx, "/hull/v1/engine/stop", nil, nil, nil)
	if err != nil && IsConnectionFailed(err) {
		return nil
	}
	return err
}
