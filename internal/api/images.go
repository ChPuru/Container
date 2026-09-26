package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/ChPuru/hull/internal/engine"
	"github.com/ChPuru/hull/internal/oci/registry"
	"github.com/ChPuru/hull/internal/types"
)

// imageListFilters are the ?filters= keys GET /images/json accepts.
var imageListFilters = []string{"before", "dangling", "label", "reference", "since", "until"}

// getImagesJSON answers GET /images/json.
func (s *Server) getImagesJSON(w http.ResponseWriter, r *http.Request) error {
	raw, err := parseFilterArgs(r)
	if err != nil {
		return err
	}
	if err := filterKeysAllowed(raw, imageListFilters...); err != nil {
		return err
	}
	opts := engine.ImageListOptions{
		All:       boolValue(r, "all"),
		Reference: raw["reference"],
		Label:     raw["label"],
		Before:    raw["before"],
		Since:     raw["since"],
	}
	for _, v := range raw["dangling"] {
		b, perr := strconv.ParseBool(v)
		if perr != nil {
			return errBadParameter("Invalid filter 'dangling=%s': expected true or false", v)
		}
		opts.Dangling = &b
	}

	imgs, err := s.backend.Images(r.Context(), opts)
	if err != nil {
		return err
	}
	out := make([]*ImageSummary, 0, len(imgs))
	for _, img := range imgs {
		out = append(out, imageSummary(img))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// getImageJSON answers GET /images/{name}/json.
func (s *Server) getImageJSON(w http.ResponseWriter, r *http.Request) error {
	name, err := pathVar(r, "name")
	if err != nil {
		return err
	}
	img, err := s.backend.ImageInspect(r.Context(), name)
	if err != nil {
		return imageError(err, name)
	}
	writeJSON(w, http.StatusOK, imageInspect(img))
	return nil
}

// imageError turns a not-found into the exact text Docker's clients match on.
func imageError(err error, ref string) error {
	if errors.Is(err, engine.ErrNotFound) {
		return errNoSuchImage(ref)
	}
	return err
}

// getImageHistory answers GET /images/{name}/history.
func (s *Server) getImageHistory(w http.ResponseWriter, r *http.Request) error {
	name, err := pathVar(r, "name")
	if err != nil {
		return err
	}
	hist, err := s.backend.ImageHistory(r.Context(), name)
	if err != nil {
		return imageError(err, name)
	}
	writeJSON(w, http.StatusOK, historyItems(hist))
	return nil
}

// postImageTag answers POST /images/{name}/tag.
func (s *Server) postImageTag(w http.ResponseWriter, r *http.Request) error {
	name, err := pathVar(r, "name")
	if err != nil {
		return err
	}
	repo, _ := lookupQuery(r, "repo")
	if strings.TrimSpace(repo) == "" {
		return errBadParameter("the repo parameter is required")
	}
	if tag, ok := lookupQuery(r, "tag"); ok && tag != "" {
		repo = repo + ":" + tag
	}
	if err := s.backend.Tag(r.Context(), name, repo); err != nil {
		if errors.Is(err, engine.ErrInvalid) {
			return wrapStatus(http.StatusBadRequest, err, "%s", errorMessage(err))
		}
		return imageError(err, name)
	}
	w.WriteHeader(http.StatusCreated)
	return nil
}

// deleteImage answers DELETE /images/{name}.
func (s *Server) deleteImage(w http.ResponseWriter, r *http.Request) error {
	name, err := pathVar(r, "name")
	if err != nil {
		return err
	}
	deleted, err := s.backend.ImageRemove(r.Context(), name,
		boolValue(r, "force"), !boolValue(r, "noprune"))
	if err != nil {
		if errors.Is(err, engine.ErrConflict) {
			return wrapStatus(http.StatusConflict, err,
				"conflict: unable to delete %s (must be forced) - image is being used by stopped container", name)
		}
		return imageError(err, name)
	}
	writeJSON(w, http.StatusOK, imageDeleteItems(deleted))
	return nil
}

// postImagesCreate answers POST /images/create: a pull, streamed as
// newline-delimited JSON progress objects.
//
// The status is 200 as soon as the first object goes out, so a later failure
// is reported inside the stream. Returning a 500 after the header would leave
// the client's progress display waiting forever.
func (s *Server) postImagesCreate(w http.ResponseWriter, r *http.Request) error {
	fromImage, _ := lookupQuery(r, "fromImage")
	fromSrc, _ := lookupQuery(r, "fromSrc")
	if fromSrc != "" {
		return errStatus(http.StatusNotImplemented,
			"hull cannot import a root filesystem yet; build an image or pull one instead")
	}
	if strings.TrimSpace(fromImage) == "" {
		return errBadParameter("the fromImage parameter is required")
	}
	ref := fromImage
	if tag, ok := lookupQuery(r, "tag"); ok && tag != "" {
		if strings.HasPrefix(tag, "sha256:") {
			ref = fromImage + "@" + tag
		} else if !strings.Contains(fromImage, "@") {
			ref = fromImage + ":" + tag
		}
	}
	plat, err := parsePlatformQuery(r)
	if err != nil {
		return err
	}
	// The credentials are accepted and validated so a malformed header is a
	// 400 before the stream starts; the registry client resolves the actual
	// credential from the keychain the CLI owns.
	if _, err := registryAuthFromHeader(r); err != nil {
		return err
	}

	pw := newProgressWriter(w)
	pw.Status("Pulling from %s", ref)
	if _, perr := s.backend.Pull(r.Context(), ref, plat, pullProgress(pw)); perr != nil {
		if _, ierr := s.backend.ImageInspect(r.Context(), ref); ierr == nil {
			// The layers are on disk; a late failure after a complete pull
			// would be a lie.
			pw.Status("Status: Image is up to date for %s", ref)
			return nil
		}
		pw.Fail(perr)
		return nil
	}
	pw.Status("Status: Downloaded newer image for %s", ref)
	return nil
}

// pullProgress adapts the registry client's per-blob events into the JSON
// progress objects Docker's clients draw bars from.
func pullProgress(pw *progressWriter) func(registry.ProgressEvent) {
	return func(ev registry.ProgressEvent) {
		msg := JSONMessage{ID: shortDigest(ev.Digest)}
		switch {
		case ev.Err != nil:
			msg.Status = "Error"
			msg.ErrorDetail = &JSONError{Message: ev.Err.Error()}
			msg.Error = ev.Err.Error()
		case ev.Status == registry.StatusExists:
			msg.Status = "Already exists"
		case ev.Status == registry.StatusDownloading:
			msg.Status = "Downloading"
			msg.ProgressDetail = &ProgressDetail{Current: ev.Current, Total: ev.Total}
			msg.Progress = progressBar(ev.Current, ev.Total)
		case ev.Status == registry.StatusExtracting:
			msg.Status = "Extracting"
			msg.ProgressDetail = &ProgressDetail{Current: ev.Current, Total: ev.Total}
			msg.Progress = progressBar(ev.Current, ev.Total)
		case ev.Status == registry.StatusDone:
			msg.Status = "Pull complete"
		default:
			msg.Status = ev.Status
		}
		pw.Write(msg)
	}
}

// shortDigest renders a digest the 12-character way Docker labels a layer.
func shortDigest(d string) string {
	hex := strings.TrimPrefix(d, "sha256:")
	if len(hex) > 12 {
		return hex[:12]
	}
	return hex
}

// parsePlatformQuery reads the ?platform=os/arch[/variant] parameter.
func parsePlatformQuery(r *http.Request) (*types.Platform, error) {
	raw, ok := lookupQuery(r, "platform")
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, errBadParameter("invalid platform %q: expected os/arch[/variant]", raw)
	}
	p := &types.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) > 2 {
		p.Variant = parts[2]
	}
	return p, nil
}

// postImagePush answers POST /images/{name}/push.
func (s *Server) postImagePush(w http.ResponseWriter, r *http.Request) error {
	name, err := pathVar(r, "name")
	if err != nil {
		return err
	}
	if tag, ok := lookupQuery(r, "tag"); ok && tag != "" && !strings.Contains(name, "@") {
		name = name + ":" + tag
	}
	if _, err := registryAuthFromHeader(r); err != nil {
		return err
	}
	// A reference that does not exist locally is knowable before the stream
	// starts, so it is a real 404 rather than an error buried in a 200.
	if _, err := s.backend.ImageInspect(r.Context(), name); err != nil {
		return imageError(err, name)
	}

	pw := newProgressWriter(w)
	pw.Status("The push refers to repository [%s]", name)
	if perr := s.backend.Push(r.Context(), name, pushProgress(pw)); perr != nil {
		pw.Fail(perr)
		return nil
	}
	pw.Status("%s: digest: pushed", name)
	return nil
}

// pushProgress adapts upload events into progress objects.
func pushProgress(pw *progressWriter) func(registry.ProgressEvent) {
	return func(ev registry.ProgressEvent) {
		msg := JSONMessage{ID: shortDigest(ev.Digest)}
		switch {
		case ev.Err != nil:
			msg.Status = "Error"
			msg.ErrorDetail = &JSONError{Message: ev.Err.Error()}
			msg.Error = ev.Err.Error()
		case ev.Status == registry.StatusExists:
			msg.Status = "Layer already exists"
		case ev.Status == registry.StatusDone:
			msg.Status = "Pushed"
		default:
			msg.Status = "Pushing"
			msg.ProgressDetail = &ProgressDetail{Current: ev.Current, Total: ev.Total}
			msg.Progress = progressBar(ev.Current, ev.Total)
		}
		pw.Write(msg)
	}
}

// getImagesGet answers GET /images/get, which saves one or more references
// named by repeated ?names= parameters.
func (s *Server) getImagesGet(w http.ResponseWriter, r *http.Request) error {
	names := r.URL.Query()["names"]
	if len(names) == 0 {
		return errBadParameter("the names parameter is required")
	}
	return s.saveImages(w, r, names)
}

// getImageGet answers GET /images/{name}/get, which saves one reference.
func (s *Server) getImageGet(w http.ResponseWriter, r *http.Request) error {
	name, err := pathVar(r, "name")
	if err != nil {
		return err
	}
	return s.saveImages(w, r, []string{name})
}

// saveImages streams an image archive.
func (s *Server) saveImages(w http.ResponseWriter, r *http.Request, refs []string) error {
	// Resolving every reference first turns a typo into a 404 rather than a
	// truncated tar the client has already started unpacking.
	for _, ref := range refs {
		if _, err := s.backend.ImageInspect(r.Context(), ref); err != nil {
			return imageError(err, ref)
		}
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.WriteHeader(http.StatusOK)
	if err := s.backend.Save(r.Context(), refs, w); err != nil && r.Context().Err() == nil {
		s.log.Warn("hull: image save ended early", "refs", strings.Join(refs, ","), "err", err)
	}
	return nil
}

// postImagesLoad answers POST /images/load.
func (s *Server) postImagesLoad(w http.ResponseWriter, r *http.Request) error {
	quiet := boolValue(r, "quiet")
	if r.Body == nil {
		return errBadParameter("the request body must be an image archive")
	}
	pw := newProgressWriter(w)
	err := s.backend.Load(r.Context(), r.Body, quiet, func(line string) {
		pw.Write(JSONMessage{Stream: line + "\n"})
	})
	if err != nil {
		pw.Fail(err)
	}
	return nil
}

// postImagesPrune answers POST /images/prune.
//
// Like the container prune, this is implemented here rather than delegated to
// the engine's whole-daemon sweep, because a client asking to prune images
// must not also lose its stopped containers.
func (s *Server) postImagesPrune(w http.ResponseWriter, r *http.Request) error {
	raw, err := parseFilterArgs(r)
	if err != nil {
		return err
	}
	if err := filterKeysAllowed(raw, "dangling", "until", "label", "label!"); err != nil {
		return err
	}
	until, err := pruneUntil(raw["until"])
	if err != nil {
		return err
	}
	labels := parseLabelTerms(raw["label"])

	// Docker's default is dangling-only; dangling=false widens it to every
	// unused image.
	danglingOnly := true
	for _, v := range raw["dangling"] {
		b, perr := strconv.ParseBool(v)
		if perr != nil {
			return errBadParameter("Invalid filter 'dangling=%s': expected true or false", v)
		}
		danglingOnly = b
	}

	ctx := r.Context()
	ctrs, err := s.backend.List(ctx, engine.ListOptions{All: true})
	if err != nil {
		return err
	}
	inUse := map[string]bool{}
	for _, c := range ctrs {
		inUse[c.Image] = true
	}

	imgs, err := s.backend.Images(ctx, engine.ImageListOptions{All: true})
	if err != nil {
		return err
	}
	resp := ImagePruneResponse{ImagesDeleted: []ImageDeleteResponseItem{}}
	for _, img := range imgs {
		if inUse[img.ID] {
			continue
		}
		if danglingOnly && len(img.RepoTags) > 0 {
			continue
		}
		if until != nil && !img.Created.Before(*until) {
			continue
		}
		if !matchLabelTerms(labels, img.Labels) {
			continue
		}
		deleted, derr := s.backend.ImageRemove(ctx, img.ID, false, true)
		if derr != nil {
			continue
		}
		resp.ImagesDeleted = append(resp.ImagesDeleted, imageDeleteItems(deleted)...)
		resp.SpaceReclaimed += img.Size
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// getImagesSearch answers GET /images/search.
//
// hull has no registry search: Docker Hub's search API is unauthenticated,
// rate-limited and returns results for a single registry only, so a partial
// implementation would mislead. The refusal names the alternative.
func (s *Server) getImagesSearch(_ http.ResponseWriter, _ *http.Request) error {
	return errStatus(http.StatusNotImplemented,
		"hull does not proxy registry search; search on the registry's own site or use "+
			"a reference directly with hull pull")
}

// postCommit answers POST /commit.
func (s *Server) postCommit(w http.ResponseWriter, r *http.Request) error {
	container, ok := lookupQuery(r, "container")
	if !ok || strings.TrimSpace(container) == "" {
		return errBadParameter("the container parameter is required")
	}
	repo, _ := lookupQuery(r, "repo")
	tag, _ := lookupQuery(r, "tag")
	comment, _ := lookupQuery(r, "comment")
	author, _ := lookupQuery(r, "author")

	opts := engine.CommitOptions{
		Repo:    repo,
		Tag:     tag,
		Comment: comment,
		Author:  author,
		Changes: r.URL.Query()["changes"],
	}
	if _, ok := lookupQuery(r, "pause"); ok {
		pause := boolValue(r, "pause")
		opts.Pause = &pause
	}

	img, err := s.backend.Commit(r.Context(), container, opts)
	if err != nil {
		return containerError(err, container)
	}
	writeJSON(w, http.StatusCreated, CommitResponse{ID: img.ID})
	return nil
}

// getDistributionJSON answers GET /distribution/{name}/json: resolve a
// reference in the registry without pulling a single layer.
func (s *Server) getDistributionJSON(w http.ResponseWriter, r *http.Request) error {
	name, err := pathVar(r, "name")
	if err != nil {
		return err
	}
	if _, err := registryAuthFromHeader(r); err != nil {
		return err
	}
	entries, err := s.backend.Lockfile(r.Context(), []string{name})
	if err != nil {
		return imageError(err, name)
	}
	if len(entries) == 0 {
		return errNoSuchImage(name)
	}
	e := entries[0]
	out := DistributionInspect{
		Descriptor: DistributionDescriptor{
			MediaType: e.MediaType,
			Digest:    e.Digest,
			Size:      e.Size,
		},
		Platforms: []DistributionPlatform{},
	}
	if e.Platform != "" {
		parts := strings.Split(e.Platform, "/")
		p := DistributionPlatform{OS: parts[0]}
		if len(parts) > 1 {
			p.Architecture = parts[1]
		}
		if len(parts) > 2 {
			p.Variant = parts[2]
		}
		out.Platforms = append(out.Platforms, p)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
