package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rahuldhali/hull/internal/engine"
	"github.com/rahuldhali/hull/internal/network"
	"github.com/rahuldhali/hull/internal/types"
)

// networkListFilters are the ?filters= keys GET /networks accepts.
var networkListFilters = []string{"driver", "id", "label", "name", "scope", "type", "dangling"}

// getNetworks answers GET /networks.
func (s *Server) getNetworks(w http.ResponseWriter, r *http.Request) error {
	raw, err := parseFilterArgs(r)
	if err != nil {
		return err
	}
	if err := filterKeysAllowed(raw, networkListFilters...); err != nil {
		return err
	}
	nets, err := s.backend.NetworkList(r.Context())
	if err != nil {
		return err
	}
	labels := parseLabelTerms(raw["label"])
	out := make([]*NetworkResource, 0, len(nets))
	for _, n := range nets {
		if !matchAnyExact(raw["driver"], n.Driver) ||
			!matchAnyPrefix(raw["id"], n.ID) ||
			!matchAnySubstring(raw["name"], n.Name) ||
			!matchAnyExact(raw["scope"], orDefault(n.Scope, "local")) {
			continue
		}
		if !matchLabelTerms(labels, n.Labels) {
			continue
		}
		if !matchNetworkType(raw["type"], n) {
			continue
		}
		out = append(out, networkResource(n, networkContainers(n)))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// builtinNetworks are the networks Docker calls "builtin" for the ?type
// filter; everything else is "custom".
var builtinNetworks = map[string]bool{"bridge": true, "host": true, "none": true}

// matchNetworkType applies the builtin/custom filter.
func matchNetworkType(values []string, n *types.Network) bool {
	if len(values) == 0 {
		return true
	}
	kind := "custom"
	if builtinNetworks[n.Name] {
		kind = "builtin"
	}
	return matchAnyExact(values, kind)
}

// matchAnyExact ORs an exact-match filter, vacuously true when unset.
func matchAnyExact(values []string, got string) bool {
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		if v == got {
			return true
		}
	}
	return false
}

// matchAnyPrefix ORs an id-prefix filter.
func matchAnyPrefix(values []string, got string) bool {
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		if strings.HasPrefix(got, v) {
			return true
		}
	}
	return false
}

// matchAnySubstring ORs a substring filter, which is how Docker matches names.
func matchAnySubstring(values []string, got string) bool {
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		if strings.Contains(got, v) {
			return true
		}
	}
	return false
}

// getNetwork answers GET /networks/{id}.
func (s *Server) getNetwork(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	n, err := s.backend.NetworkInspect(r.Context(), id)
	if err != nil {
		return networkError(err, id)
	}
	writeJSON(w, http.StatusOK, networkResource(n, networkContainers(n)))
	return nil
}

// networkError turns a not-found into the text Docker's clients match on.
func networkError(err error, id string) error {
	if errors.Is(err, engine.ErrNotFound) {
		return errNoSuchNetwork(id)
	}
	return err
}

// postNetworksCreate answers POST /networks/create.
func (s *Server) postNetworksCreate(w http.ResponseWriter, r *http.Request) error {
	var req NetworkCreateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Name) == "" {
		return errBadParameter("the Name field is required")
	}
	cfg := network.CreateConfig{
		Driver:     orDefault(req.Driver, "bridge"),
		Internal:   req.Internal,
		Attachable: req.Attachable,
		IPv6:       req.EnableIPv6,
		Options:    req.Options,
		Labels:     req.Labels,
	}
	if req.IPAM != nil && len(req.IPAM.Config) > 0 {
		first := req.IPAM.Config[0]
		cfg.Subnet = first.Subnet
		cfg.Gateway = first.Gateway
		cfg.IPRange = first.IPRange
	}
	warning := ""
	if req.IPAM != nil && len(req.IPAM.Config) > 1 {
		warning = "hull allocates one subnet per network; the extra IPAM entries were ignored"
	}

	n, err := s.backend.NetworkCreate(r.Context(), req.Name, cfg)
	if err != nil {
		if errors.Is(err, engine.ErrConflict) {
			return wrapStatus(http.StatusConflict, err,
				"network with name %s already exists", req.Name)
		}
		if errors.Is(err, engine.ErrInvalid) {
			return wrapStatus(http.StatusBadRequest, err, "%s", errorMessage(err))
		}
		return err
	}
	writeJSON(w, http.StatusCreated, NetworkCreateResponse{ID: n.ID, Warning: warning})
	return nil
}

// deleteNetwork answers DELETE /networks/{id}.
func (s *Server) deleteNetwork(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	if err := s.backend.NetworkRemove(r.Context(), id); err != nil {
		if errors.Is(err, engine.ErrConflict) {
			return wrapStatus(http.StatusForbidden, err, "%s", errorMessage(err))
		}
		return networkError(err, id)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// postNetworkConnect answers POST /networks/{id}/connect.
func (s *Server) postNetworkConnect(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	var req NetworkConnectRequest
	if err := decodeJSONBody(r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Container) == "" {
		return errBadParameter("the Container field is required")
	}
	var cfg network.EndpointConfig
	if req.EndpointConfig != nil {
		cfg.Aliases = req.EndpointConfig.Aliases
		cfg.DNSNames = req.EndpointConfig.DNSNames
		cfg.MacAddress = req.EndpointConfig.MacAddress
		if req.EndpointConfig.IPAMConfig != nil {
			cfg.IPv4Address = req.EndpointConfig.IPAMConfig.IPv4Address
		}
	}
	if err := s.backend.NetworkConnect(r.Context(), id, req.Container, cfg); err != nil {
		return connectError(err, id, req.Container)
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

// postNetworkDisconnect answers POST /networks/{id}/disconnect.
func (s *Server) postNetworkDisconnect(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	var req NetworkDisconnectRequest
	if err := decodeJSONBody(r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Container) == "" {
		return errBadParameter("the Container field is required")
	}
	if err := s.backend.NetworkDisconnect(r.Context(), id, req.Container, req.Force); err != nil {
		return connectError(err, id, req.Container)
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

// connectError disambiguates a connect or disconnect failure: a client needs
// to know whether the network or the container was the thing that was missing.
func connectError(err error, netID, ctrID string) error {
	if !errors.Is(err, engine.ErrNotFound) {
		return err
	}
	if strings.Contains(err.Error(), ctrID) {
		return errNoSuchContainer(ctrID)
	}
	return errNoSuchNetwork(netID)
}

// postNetworksPrune answers POST /networks/prune.
func (s *Server) postNetworksPrune(w http.ResponseWriter, r *http.Request) error {
	raw, err := parseFilterArgs(r)
	if err != nil {
		return err
	}
	if err := filterKeysAllowed(raw, "until", "label", "label!"); err != nil {
		return err
	}
	removed, err := s.backend.NetworkPrune(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, NetworkPruneResponse{NetworksDeleted: stringsOrEmpty(removed)})
	return nil
}
