package client

import (
	"context"
	"net/url"
)

// NetworkConnectRequest is the body of POST /networks/{id}/connect.
type NetworkConnectRequest struct {
	// Container is the container to attach, by id or name.
	Container string `json:"Container"`
	// EndpointConfig pins the address or aliases for the new endpoint.
	EndpointConfig *EndpointSettings `json:"EndpointConfig,omitempty"`
}

// NetworkDisconnectRequest is the body of POST /networks/{id}/disconnect.
type NetworkDisconnectRequest struct {
	// Container is the container to detach.
	Container string `json:"Container"`
	// Force detaches an endpoint whose container is gone.
	Force bool `json:"Force,omitempty"`
}

// NetworkListOptions narrows GET /networks.
type NetworkListOptions struct {
	// Filters are Docker filter terms such as "driver" or "label".
	Filters Filters
}

// NetworkList lists networks.
func (c *Client) NetworkList(ctx context.Context, opts NetworkListOptions) ([]NetworkResource, error) {
	q := url.Values{}
	opts.Filters.set(q)
	var out []NetworkResource
	if err := c.get(ctx, "/networks", q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// NetworkInspect returns one network with its attached containers.
func (c *Client) NetworkInspect(ctx context.Context, idOrName string, verbose bool) (*NetworkResource, error) {
	q := url.Values{}
	boolQuery(q, "verbose", verbose)
	var out NetworkResource
	if err := c.get(ctx, "/networks/"+url.PathEscape(idOrName), q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// NetworkCreate makes a new network.
func (c *Client) NetworkCreate(ctx context.Context, req NetworkCreateRequest) (NetworkCreateResponse, error) {
	var out NetworkCreateResponse
	if err := c.post(ctx, "/networks/create", nil, req, &out); err != nil {
		return NetworkCreateResponse{}, err
	}
	return out, nil
}

// NetworkRemove deletes a network.
func (c *Client) NetworkRemove(ctx context.Context, idOrName string) error {
	return c.del(ctx, "/networks/"+url.PathEscape(idOrName), nil, nil)
}

// NetworkConnect attaches a container to a network.
func (c *Client) NetworkConnect(ctx context.Context, network, container string, cfg *EndpointSettings) error {
	req := NetworkConnectRequest{Container: container, EndpointConfig: cfg}
	return c.post(ctx, "/networks/"+url.PathEscape(network)+"/connect", nil, req, nil)
}

// NetworkDisconnect detaches a container from a network.
func (c *Client) NetworkDisconnect(ctx context.Context, network, container string, force bool) error {
	req := NetworkDisconnectRequest{Container: container, Force: force}
	return c.post(ctx, "/networks/"+url.PathEscape(network)+"/disconnect", nil, req, nil)
}

// NetworksPrune removes unused networks.
func (c *Client) NetworksPrune(ctx context.Context, filters Filters) (PruneReport, error) {
	q := url.Values{}
	filters.set(q)
	var out PruneReport
	if err := c.post(ctx, "/networks/prune", q, nil, &out); err != nil {
		return PruneReport{}, err
	}
	return out, nil
}
