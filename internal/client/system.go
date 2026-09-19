package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
)

// Version reports the engine's build identity and API range.
func (c *Client) Version(ctx context.Context) (VersionResponse, error) {
	var out VersionResponse
	if err := c.get(ctx, "/version", nil, &out); err != nil {
		return VersionResponse{}, err
	}
	return out, nil
}

// Info reports what this daemon is and what the host can do. Its Warnings are
// the host problems "hull doctor" would report, and the CLI prints them.
func (c *Client) Info(ctx context.Context) (Info, error) {
	var out Info
	if err := c.get(ctx, "/info", nil, &out); err != nil {
		return Info{}, err
	}
	return out, nil
}

// DiskUsage reports what the engine is holding on disk.
func (c *Client) DiskUsage(ctx context.Context) (DiskUsage, error) {
	var out DiskUsage
	if err := c.get(ctx, "/system/df", nil, &out); err != nil {
		return DiskUsage{}, err
	}
	return out, nil
}

// RegistryLogin checks a credential against a registry and returns the
// identity token when the registry issues one.
func (c *Client) RegistryLogin(ctx context.Context, auth AuthConfig) (AuthResponse, error) {
	var out AuthResponse
	if err := c.post(ctx, "/auth", nil, auth, &out); err != nil {
		return AuthResponse{}, err
	}
	return out, nil
}

// EventsOptions narrows GET /events.
type EventsOptions struct {
	// Since and Until bound the window; both accept a unix timestamp or a
	// duration. Since also replays what has already happened, which is what
	// compose relies on to see the container it just created.
	Since string
	Until string
	// Filters are Docker filter terms such as "type", "container" or "event".
	Filters Filters
}

// Events streams engine events.
//
// It returns as soon as the stream is open. The event channel is closed when
// the stream ends; the error channel carries at most one error and is the
// place a mid-stream failure surfaces. Cancelling ctx ends both.
func (c *Client) Events(ctx context.Context, opts EventsOptions) (<-chan Event, <-chan error) {
	events := make(chan Event)
	errs := make(chan error, 1)

	q := url.Values{}
	if opts.Since != "" {
		q.Set("since", opts.Since)
	}
	if opts.Until != "" {
		q.Set("until", opts.Until)
	}
	opts.Filters.set(q)

	go func() {
		defer close(events)
		resp, err := c.do(ctx, http.MethodGet, "/events", q, nil, nil)
		if err != nil {
			errs <- err
			return
		}
		defer func() { _ = resp.Body.Close() }()
		dec := json.NewDecoder(resp.Body)
		for {
			var ev Event
			if err := dec.Decode(&ev); err != nil {
				if errors.Is(err, io.EOF) || ctx.Err() != nil || isStreamEnd(err) {
					return
				}
				errs <- err
				return
			}
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return events, errs
}
