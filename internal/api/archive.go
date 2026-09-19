package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/rahuldhali/hull/internal/engine"
)

// pathStatHeader is where Docker puts the stat of the path a /archive request
// names: a base64-encoded JSON object. The CLI reads it before it reads a
// single byte of the tar stream, and `docker cp` refuses to overwrite a
// directory with a file based on what it finds here.
const pathStatHeader = "X-Docker-Container-Path-Stat"

// setPathStat encodes a stat into the header.
func setPathStat(w http.ResponseWriter, stat engine.CopyStat) error {
	body, err := json.Marshal(stat)
	if err != nil {
		return err
	}
	w.Header().Set(pathStatHeader, base64.StdEncoding.EncodeToString(body))
	return nil
}

// archivePath reads and validates the required ?path= parameter.
func archivePath(r *http.Request) (string, error) {
	p, ok := lookupQuery(r, "path")
	if !ok || strings.TrimSpace(p) == "" {
		return "", errBadParameter("Bad parameters: the path parameter is required")
	}
	return p, nil
}

// headContainerArchive answers HEAD /containers/{id}/archive: the stat header
// and nothing else.
func (s *Server) headContainerArchive(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	p, err := archivePath(r)
	if err != nil {
		return err
	}
	rc, stat, err := s.backend.CopyFrom(r.Context(), id, p)
	if err != nil {
		return archiveError(err, id, p)
	}
	_ = rc.Close()
	if err := setPathStat(w, stat); err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

// getContainerArchive answers GET /containers/{id}/archive: the stat header
// followed by a tar stream.
func (s *Server) getContainerArchive(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	p, err := archivePath(r)
	if err != nil {
		return err
	}
	rc, stat, err := s.backend.CopyFrom(r.Context(), id, p)
	if err != nil {
		return archiveError(err, id, p)
	}
	defer func() { _ = rc.Close() }()

	if err := setPathStat(w, stat); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.WriteHeader(http.StatusOK)
	if _, cerr := io.Copy(w, rc); cerr != nil && r.Context().Err() == nil {
		s.log.Warn("hull: archive stream ended early", "container", id, "path", p, "err", cerr)
	}
	return nil
}

// putContainerArchive answers PUT /containers/{id}/archive.
func (s *Server) putContainerArchive(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	p, err := archivePath(r)
	if err != nil {
		return err
	}
	// Docker's parameter is the negative one: noOverwriteDirNonDir=true means
	// refuse to replace a directory with a file or the other way round. hull's
	// engine takes the positive form, so the sense is inverted here rather
	// than in two places.
	opts := engine.CopyOptions{
		AllowOverwriteDirWithFile: !boolValue(r, "noOverwriteDirNonDir"),
		CopyUIDGID:                boolValue(r, "copyUIDGID"),
	}
	if r.Body == nil {
		return errBadParameter("Bad parameters: the request body must be a tar archive")
	}
	if err := s.backend.CopyTo(r.Context(), id, p, r.Body, opts); err != nil {
		return archiveError(err, id, p)
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

// archiveError maps a copy failure onto Docker's status and message. A
// missing path inside a container is a 404 about the path, not about the
// container, and `docker cp` says so.
func archiveError(err error, id, p string) error {
	switch {
	case errors.Is(err, engine.ErrNotFound):
		if strings.Contains(err.Error(), p) {
			return wrapStatus(http.StatusNotFound, err,
				"Could not find the file %s in container %s", p, id)
		}
		return errNoSuchContainer(id)
	case errors.Is(err, engine.ErrInvalid):
		return wrapStatus(http.StatusBadRequest, err, "%s", errorMessage(err))
	default:
		return err
	}
}
