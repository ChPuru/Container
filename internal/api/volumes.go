package api

import (
	"errors"
	"net/http"

	"github.com/ChPuru/hull/internal/engine"
	"github.com/ChPuru/hull/internal/volume"
)

// volumeFiltersAll is the filter that selects every volume, used by
// /system/df, which reports the whole store.
func volumeFiltersAll() volume.Filters { return volume.Filters{} }

// getVolumes answers GET /volumes.
func (s *Server) getVolumes(w http.ResponseWriter, r *http.Request) error {
	raw, err := parseFilterArgs(r)
	if err != nil {
		return err
	}
	f, err := volume.ParseFilters(raw)
	if err != nil {
		return wrapStatus(http.StatusBadRequest, err, "%s", err.Error())
	}
	vols, err := s.backend.VolumeList(r.Context(), f)
	if err != nil {
		return err
	}
	resp := VolumeListResponse{Volumes: make([]*Volume, 0, len(vols)), Warnings: []string{}}
	for _, v := range vols {
		resp.Volumes = append(resp.Volumes, volumeToAPI(v))
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// getVolume answers GET /volumes/{name}.
func (s *Server) getVolume(w http.ResponseWriter, r *http.Request) error {
	name, err := pathVar(r, "name")
	if err != nil {
		return err
	}
	v, err := s.backend.VolumeInspect(r.Context(), name)
	if err != nil {
		return volumeError(err, name)
	}
	writeJSON(w, http.StatusOK, volumeToAPI(v))
	return nil
}

// volumeError turns a not-found into the text Docker's clients match on.
func volumeError(err error, name string) error {
	if errors.Is(err, engine.ErrNotFound) || errors.Is(err, volume.ErrNotFound) {
		return errNoSuchVolume(name)
	}
	return err
}

// postVolumesCreate answers POST /volumes/create.
func (s *Server) postVolumesCreate(w http.ResponseWriter, r *http.Request) error {
	var req VolumeCreateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		return err
	}
	v, err := s.backend.VolumeCreate(r.Context(), req.Name, req.Driver, req.DriverOpts, req.Labels)
	if err != nil {
		if errors.Is(err, engine.ErrInvalid) {
			return wrapStatus(http.StatusBadRequest, err, "%s", errorMessage(err))
		}
		if errors.Is(err, volume.ErrDriverUnsupported) {
			return wrapStatus(http.StatusNotFound, err,
				"error looking up volume plugin %s: plugin not found", req.Driver)
		}
		return err
	}
	writeJSON(w, http.StatusCreated, volumeToAPI(v))
	return nil
}

// deleteVolume answers DELETE /volumes/{name}.
func (s *Server) deleteVolume(w http.ResponseWriter, r *http.Request) error {
	name, err := pathVar(r, "name")
	if err != nil {
		return err
	}
	if err := s.backend.VolumeRemove(r.Context(), name, boolValue(r, "force")); err != nil {
		if errors.Is(err, volume.ErrInUse) || errors.Is(err, engine.ErrConflict) {
			return wrapStatus(http.StatusConflict, err,
				"remove %s: volume is in use", name)
		}
		return volumeError(err, name)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// postVolumesPrune answers POST /volumes/prune.
func (s *Server) postVolumesPrune(w http.ResponseWriter, r *http.Request) error {
	raw, err := parseFilterArgs(r)
	if err != nil {
		return err
	}
	if err := filterKeysAllowed(raw, "label", "label!", "all"); err != nil {
		return err
	}
	f, err := volume.ParseFilters(raw)
	if err != nil {
		return wrapStatus(http.StatusBadRequest, err, "%s", err.Error())
	}
	removed, reclaimed, err := s.backend.VolumePrune(r.Context(), f)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, VolumePruneResponse{
		VolumesDeleted: stringsOrEmpty(removed),
		SpaceReclaimed: reclaimed,
	})
	return nil
}
