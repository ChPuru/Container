package client

import (
	"context"
	"net/url"
)

// VolumeList lists named volumes. The response carries warnings of its own,
// which the caller should print.
func (c *Client) VolumeList(ctx context.Context, filters Filters) (VolumeListResponse, error) {
	q := url.Values{}
	filters.set(q)
	var out VolumeListResponse
	if err := c.get(ctx, "/volumes", q, &out); err != nil {
		return VolumeListResponse{}, err
	}
	return out, nil
}

// VolumeInspect returns one volume.
func (c *Client) VolumeInspect(ctx context.Context, name string) (*Volume, error) {
	var out Volume
	if err := c.get(ctx, "/volumes/"+url.PathEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VolumeCreate makes a volume. An empty name asks the engine to generate one.
func (c *Client) VolumeCreate(ctx context.Context, req VolumeCreateRequest) (*Volume, error) {
	var out Volume
	if err := c.post(ctx, "/volumes/create", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VolumeRemove deletes a volume. Force also removes one the engine believes is
// still referenced.
func (c *Client) VolumeRemove(ctx context.Context, name string, force bool) error {
	q := url.Values{}
	boolQuery(q, "force", force)
	return c.del(ctx, "/volumes/"+url.PathEscape(name), q, nil)
}

// VolumesPrune removes volumes no container references.
func (c *Client) VolumesPrune(ctx context.Context, filters Filters) (PruneReport, error) {
	q := url.Values{}
	filters.set(q)
	var out PruneReport
	if err := c.post(ctx, "/volumes/prune", q, nil, &out); err != nil {
		return PruneReport{}, err
	}
	return out, nil
}
