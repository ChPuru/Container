package api

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/engine"
	"github.com/rahuldhali/hull/internal/types"
)

// containerListFilters are the ?filters= keys GET /containers/json accepts.
// Anything else is a 400 naming the key, which is how Docker answers and how a
// typo in a compose file gets reported instead of silently widening a result.
var containerListFilters = []string{
	"ancestor", "before", "expose", "exited", "health", "id", "isolation",
	"is-task", "label", "name", "network", "publish", "since", "status", "volume",
}

// getContainersJSON answers GET /containers/json.
func (s *Server) getContainersJSON(w http.ResponseWriter, r *http.Request) error {
	raw, err := parseFilterArgs(r)
	if err != nil {
		return err
	}
	if err := filterKeysAllowed(raw, containerListFilters...); err != nil {
		return err
	}
	limit, err := intValue(r, "limit", 0)
	if err != nil {
		return err
	}
	opts := engine.ListOptions{
		All:      boolValue(r, "all"),
		Limit:    limit,
		Size:     boolValue(r, "size"),
		Status:   raw["status"],
		Name:     raw["name"],
		ID:       raw["id"],
		Label:    raw["label"],
		Ancestor: raw["ancestor"],
		Network:  raw["network"],
		Volume:   raw["volume"],
		Before:   raw["before"],
		Since:    raw["since"],
		Health:   raw["health"],
	}
	for _, v := range raw["exited"] {
		code, cerr := strconv.Atoi(v)
		if cerr != nil {
			return errBadParameter("Invalid filter 'exited=%s': expected an exit code", v)
		}
		opts.Exited = append(opts.Exited, code)
	}

	ctrs, err := s.backend.List(r.Context(), opts)
	if err != nil {
		return err
	}
	now := time.Now()
	out := make([]*ContainerSummary, 0, len(ctrs))
	for _, c := range ctrs {
		if !matchPortFilters(c, raw["expose"], raw["publish"]) {
			continue
		}
		out = append(out, containerSummary(c, now))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// matchPortFilters applies Docker's "expose" and "publish" container filters,
// which the engine's ListOptions does not model because they are purely a
// view over data the API layer already renders.
func matchPortFilters(c *types.Container, expose, publish []string) bool {
	if len(expose) == 0 && len(publish) == 0 {
		return true
	}
	ports := summaryPorts(c)
	match := func(spec string, needPublic bool) bool {
		want, proto, err := splitPortSpec(strings.TrimSpace(spec))
		if err != nil {
			return false
		}
		for _, p := range ports {
			if p.PrivatePort != want || p.Type != proto {
				continue
			}
			if needPublic && p.PublicPort == 0 {
				continue
			}
			return true
		}
		return false
	}
	for _, spec := range expose {
		if !match(spec, false) {
			return false
		}
	}
	for _, spec := range publish {
		if !match(spec, true) {
			return false
		}
	}
	return true
}

// postContainersCreate answers POST /containers/create.
//
// The warnings the bundle generator produced — a memory cap this host's
// hybrid cgroups cannot enforce, for instance — are returned in the response.
// Dropping them would leave the user with a silently unlimited container,
// which is the failure mode the integration notes call out by name.
func (s *Server) postContainersCreate(w http.ResponseWriter, r *http.Request) error {
	var req ContainerCreateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Image) == "" {
		return errBadParameter("Config.Image is required")
	}
	name, _ := lookupQuery(r, "name")

	cfg, host := configFromCreate(&req)
	var warnings []string
	if req.NetworkingConfig != nil && len(req.NetworkingConfig.EndpointsConfig) > 0 {
		names := make([]string, 0, len(req.NetworkingConfig.EndpointsConfig))
		for n := range req.NetworkingConfig.EndpointsConfig {
			names = append(names, n)
		}
		sort.Strings(names)
		if host.NetworkMode == "" || host.NetworkMode == "default" || host.NetworkMode == "bridge" {
			host.NetworkMode = names[0]
		}
		if len(names) > 1 {
			warnings = append(warnings,
				"hull attaches a container to one network at create time; connect the rest with "+
					"POST /networks/{id}/connect once it is running: "+strings.Join(names[1:], ", "))
		}
	}

	c, err := s.backend.Create(r.Context(), name, cfg, host, req.Image)
	if err != nil {
		return createError(err, name, req.Image)
	}
	if got, werr := s.backend.Warnings(r.Context(), c.ID); werr == nil {
		warnings = append(warnings, got...)
	}
	writeJSON(w, http.StatusCreated, ContainerCreateResponse{
		ID:       c.ID,
		Warnings: stringsOrEmpty(warnings),
	})
	return nil
}

// createError maps a create failure onto the status and message Docker sends.
// Compose matches the conflict text, and the CLI prints the 404 verbatim when
// an image could not be resolved.
func createError(err error, name, image string) error {
	switch {
	case errors.Is(err, engine.ErrConflict):
		return wrapStatus(http.StatusConflict, err,
			"Conflict. The container name %q is already in use. You have to remove (or rename) that "+
				"container to be able to reuse that name.", "/"+name)
	case errors.Is(err, engine.ErrNotFound):
		return errNoSuchImage(image)
	default:
		return err
	}
}

// getContainerJSON answers GET /containers/{id}/json.
func (s *Server) getContainerJSON(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	c, err := s.backend.Inspect(r.Context(), id)
	if err != nil {
		return containerError(err, id)
	}
	warnings, _ := s.backend.Warnings(r.Context(), c.ID)
	doc := s.containerJSON(c, warnings, nil)
	if boolValue(r, "size") {
		var zero int64
		doc.SizeRw = &zero
		doc.SizeRootFs = &zero
	}
	writeJSON(w, http.StatusOK, doc)
	return nil
}

// containerError turns a not-found into the exact text compose matches on and
// leaves every other failure to the generic mapper.
func containerError(err error, id string) error {
	if errors.Is(err, engine.ErrNotFound) {
		return errNoSuchContainer(id)
	}
	return err
}

// getContainerTop answers GET /containers/{id}/top.
func (s *Server) getContainerTop(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	psArgs, _ := lookupQuery(r, "ps_args")
	if psArgs == "" {
		psArgs = "-ef"
	}
	res, err := s.backend.Top(r.Context(), id, psArgs)
	if err != nil {
		return containerError(err, id)
	}
	writeJSON(w, http.StatusOK, ContainerTopResponse{
		Titles:    stringsOrEmpty(res.Titles),
		Processes: res.Processes,
	})
	return nil
}

// getContainerChanges answers GET /containers/{id}/changes.
func (s *Server) getContainerChanges(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	changes, err := s.backend.Diff(r.Context(), id)
	if err != nil {
		return containerError(err, id)
	}
	out := make([]ContainerChange, 0, len(changes))
	for _, ch := range changes {
		kind := ChangeModify
		switch ch.Kind.Letter() {
		case "A":
			kind = ChangeAdd
		case "D":
			kind = ChangeDelete
		}
		out = append(out, ContainerChange{Path: ch.Path, Kind: kind})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// postContainerStart answers POST /containers/{id}/start.
func (s *Server) postContainerStart(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	if err := s.backend.Start(r.Context(), id, nil); err != nil {
		if errors.Is(err, engine.ErrRunning) {
			// Docker answers 304 for an already-running container, and
			// compose treats anything else as a failure to converge.
			w.WriteHeader(http.StatusNotModified)
			return nil
		}
		return containerError(err, id)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// postContainerStop answers POST /containers/{id}/stop.
func (s *Server) postContainerStop(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	timeout, err := optionalIntValue(r, "t")
	if err != nil {
		return err
	}
	if timeout == nil {
		if timeout, err = optionalIntValue(r, "timeout"); err != nil {
			return err
		}
	}
	if err := s.backend.Stop(r.Context(), id, timeout); err != nil {
		if errors.Is(err, engine.ErrNotRunning) {
			w.WriteHeader(http.StatusNotModified)
			return nil
		}
		return containerError(err, id)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// postContainerRestart answers POST /containers/{id}/restart.
func (s *Server) postContainerRestart(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	timeout, err := optionalIntValue(r, "t")
	if err != nil {
		return err
	}
	if err := s.backend.Restart(r.Context(), id, timeout); err != nil {
		return containerError(err, id)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// postContainerKill answers POST /containers/{id}/kill.
func (s *Server) postContainerKill(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	signal, _ := lookupQuery(r, "signal")
	if err := s.backend.Kill(r.Context(), id, signal); err != nil {
		return containerError(err, id)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ContainerUpdateRequest is the body of POST /containers/{id}/update: the
// resource knobs, plus an optional restart policy.
type ContainerUpdateRequest struct {
	HostConfig
	// RestartPolicy replaces the container's policy when its Name is set.
	RestartPolicy RestartPolicy `json:"RestartPolicy"`
}

// postContainerUpdate answers POST /containers/{id}/update.
func (s *Server) postContainerUpdate(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	var req ContainerUpdateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		return err
	}
	res := resourcesFromAPI(&req.HostConfig)
	var rp *types.RestartPolicy
	if req.RestartPolicy.Name != "" {
		rp = &types.RestartPolicy{
			Name:              req.RestartPolicy.Name,
			MaximumRetryCount: req.RestartPolicy.MaximumRetryCount,
		}
	}
	if err := s.backend.Update(r.Context(), id, res, rp); err != nil {
		return containerError(err, id)
	}
	warnings, _ := s.backend.Warnings(r.Context(), id)
	writeJSON(w, http.StatusOK, ContainerUpdateResponse{Warnings: stringsOrEmpty(warnings)})
	return nil
}

// postContainerRename answers POST /containers/{id}/rename.
func (s *Server) postContainerRename(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	name, ok := lookupQuery(r, "name")
	if !ok || strings.TrimSpace(name) == "" {
		return errBadParameter("the name parameter is required")
	}
	if err := s.backend.Rename(r.Context(), id, strings.TrimPrefix(name, "/")); err != nil {
		if errors.Is(err, engine.ErrConflict) {
			return wrapStatus(http.StatusConflict, err,
				"Conflict. The container name %q is already in use.", "/"+strings.TrimPrefix(name, "/"))
		}
		return containerError(err, id)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// postContainerPause answers POST /containers/{id}/pause.
func (s *Server) postContainerPause(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	if err := s.backend.Pause(r.Context(), id); err != nil {
		return containerError(err, id)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// postContainerUnpause answers POST /containers/{id}/unpause.
func (s *Server) postContainerUnpause(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	if err := s.backend.Unpause(r.Context(), id); err != nil {
		return containerError(err, id)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// postContainerWait answers POST /containers/{id}/wait.
func (s *Server) postContainerWait(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	condition, _ := lookupQuery(r, "condition")
	switch condition {
	case "", engine.WaitNotRunning, engine.WaitNextExit, engine.WaitRemoved:
	default:
		return errBadParameter("invalid condition %q: expected %s, %s or %s",
			condition, engine.WaitNotRunning, engine.WaitNextExit, engine.WaitRemoved)
	}
	code, err := s.backend.Wait(r.Context(), id, condition)
	if err != nil {
		if errors.Is(err, engine.ErrNotFound) {
			return errNoSuchContainer(id)
		}
		// The headers have not gone out yet, so a real HTTP error is still
		// possible; Docker nonetheless prefers the in-body Error field here
		// because a client's decoder is already waiting for this shape.
		writeJSON(w, http.StatusOK, ContainerWaitResponse{
			StatusCode: code,
			Error:      &ContainerWaitError{Message: errorMessage(err)},
		})
		return nil
	}
	writeJSON(w, http.StatusOK, ContainerWaitResponse{StatusCode: code})
	return nil
}

// postContainerResize answers POST /containers/{id}/resize.
func (s *Server) postContainerResize(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	h, wdt, err := resizeDimensions(r)
	if err != nil {
		return err
	}
	if err := s.backend.Resize(r.Context(), id, h, wdt); err != nil {
		return containerError(err, id)
	}
	writeJSON(w, http.StatusOK, nil)
	return nil
}

// resizeDimensions reads the h and w query parameters of a resize request.
func resizeDimensions(r *http.Request) (uint16, uint16, error) {
	height, err := intValue(r, "h", 0)
	if err != nil {
		return 0, 0, err
	}
	width, err := intValue(r, "w", 0)
	if err != nil {
		return 0, 0, err
	}
	if height <= 0 || width <= 0 || height > 65535 || width > 65535 {
		return 0, 0, errBadParameter("h and w must both be between 1 and 65535")
	}
	return uint16(height), uint16(width), nil
}

// deleteContainer answers DELETE /containers/{id}.
func (s *Server) deleteContainer(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	force := boolValue(r, "force")
	removeVolumes := boolValue(r, "v")
	if !removeVolumes {
		removeVolumes = boolValue(r, "volumes")
	}
	if err := s.backend.Remove(r.Context(), id, force, removeVolumes); err != nil {
		if errors.Is(err, engine.ErrRunning) || errors.Is(err, engine.ErrConflict) {
			return wrapStatus(http.StatusConflict, err,
				"You cannot remove a running container %s. Stop the container before attempting "+
					"removal or force remove", id)
		}
		return containerError(err, id)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// postContainersPrune answers POST /containers/prune.
//
// It is implemented here rather than delegated to the engine's own Prune,
// because that call is a whole-daemon sweep that also collects images,
// snapshots and blobs. This endpoint must remove stopped containers and
// nothing else, which is what a client asking for it expects.
func (s *Server) postContainersPrune(w http.ResponseWriter, r *http.Request) error {
	raw, err := parseFilterArgs(r)
	if err != nil {
		return err
	}
	if err := filterKeysAllowed(raw, "until", "label", "label!"); err != nil {
		return err
	}
	until, err := pruneUntil(raw["until"])
	if err != nil {
		return err
	}
	labels := parseLabelTerms(raw["label"])

	ctx := r.Context()
	ctrs, err := s.backend.List(ctx, engine.ListOptions{All: true})
	if err != nil {
		return err
	}
	resp := ContainerPruneResponse{ContainersDeleted: []string{}}
	for _, c := range ctrs {
		switch c.State {
		case types.StateExited, types.StateCreated, types.StateDead:
		default:
			continue
		}
		if until != nil && !c.Created.Before(*until) {
			continue
		}
		if !matchLabelTerms(labels, c.Config.Labels) {
			continue
		}
		if rerr := s.backend.Remove(ctx, c.ID, false, false); rerr != nil {
			if errors.Is(rerr, engine.ErrConflict) || errors.Is(rerr, engine.ErrNotFound) {
				continue
			}
			return rerr
		}
		resp.ContainersDeleted = append(resp.ContainersDeleted, c.ID)
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// pruneUntil reads the "until" prune filter, which Docker accepts as either an
// RFC3339 instant or a duration ago.
func pruneUntil(values []string) (*time.Time, error) {
	if len(values) == 0 {
		return nil, nil
	}
	v := strings.TrimSpace(values[0])
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return &t, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		t := time.Now().UTC().Add(-d)
		return &t, nil
	}
	return nil, errBadParameter("Invalid filter 'until=%s': expected an RFC3339 time or a duration", v)
}

// labelTerm is one parsed "key" or "key=value" label filter.
type labelTerm struct {
	key   string
	value string
	exact bool
}

// parseLabelTerms parses the label filter values.
func parseLabelTerms(values []string) []labelTerm {
	out := make([]labelTerm, 0, len(values))
	for _, v := range values {
		key, val, ok := strings.Cut(v, "=")
		out = append(out, labelTerm{key: key, value: val, exact: ok})
	}
	return out
}

// matchLabelTerms requires every term to hold, which is Docker's semantics for
// label filters even though other filter keys OR their values.
func matchLabelTerms(terms []labelTerm, labels map[string]string) bool {
	for _, t := range terms {
		got, ok := labels[t.key]
		if !ok {
			return false
		}
		if t.exact && got != t.value {
			return false
		}
	}
	return true
}
