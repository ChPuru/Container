package api

import "net/http"

// registerRoutes binds every endpoint hull serves.
//
// Order matters only where two patterns could match the same path: the router
// returns the first match, so the more specific pattern is registered first.
// The image routes are the only place this comes up, because an image
// reference may itself contain slashes.
func (s *Server) registerRoutes() {
	rt := s.router

	// --- system ---
	rt.handle(http.MethodGet, "/_ping", s.getPing)
	rt.handle(http.MethodHead, "/_ping", s.headPing)
	rt.handle(http.MethodGet, "/version", s.getVersion)
	rt.handle(http.MethodGet, "/info", s.getInfo)
	rt.handle(http.MethodGet, "/events", s.getEvents)
	rt.handle(http.MethodGet, "/system/df", s.getSystemDF)
	rt.handle(http.MethodPost, "/auth", s.postAuth)

	// --- containers ---
	rt.handle(http.MethodGet, "/containers/json", s.getContainersJSON)
	rt.handle(http.MethodPost, "/containers/create", s.postContainersCreate)
	rt.handle(http.MethodPost, "/containers/prune", s.postContainersPrune)
	rt.handle(http.MethodGet, "/containers/{id}/json", s.getContainerJSON)
	rt.handle(http.MethodGet, "/containers/{id}/top", s.getContainerTop)
	rt.handle(http.MethodGet, "/containers/{id}/logs", s.getContainerLogs)
	rt.handle(http.MethodGet, "/containers/{id}/changes", s.getContainerChanges)
	rt.handle(http.MethodGet, "/containers/{id}/export", s.getContainerExport)
	rt.handle(http.MethodGet, "/containers/{id}/stats", s.getContainerStats)
	rt.handle(http.MethodGet, "/containers/{id}/attach/ws", s.getContainerAttachWS)
	rt.handle(http.MethodGet, "/containers/{id}/archive", s.getContainerArchive)
	rt.handle(http.MethodHead, "/containers/{id}/archive", s.headContainerArchive)
	rt.handle(http.MethodPut, "/containers/{id}/archive", s.putContainerArchive)
	rt.handle(http.MethodPost, "/containers/{id}/start", s.postContainerStart)
	rt.handle(http.MethodPost, "/containers/{id}/stop", s.postContainerStop)
	rt.handle(http.MethodPost, "/containers/{id}/restart", s.postContainerRestart)
	rt.handle(http.MethodPost, "/containers/{id}/kill", s.postContainerKill)
	rt.handle(http.MethodPost, "/containers/{id}/update", s.postContainerUpdate)
	rt.handle(http.MethodPost, "/containers/{id}/rename", s.postContainerRename)
	rt.handle(http.MethodPost, "/containers/{id}/pause", s.postContainerPause)
	rt.handle(http.MethodPost, "/containers/{id}/unpause", s.postContainerUnpause)
	rt.handle(http.MethodPost, "/containers/{id}/attach", s.postContainerAttach)
	rt.handle(http.MethodPost, "/containers/{id}/wait", s.postContainerWait)
	rt.handle(http.MethodPost, "/containers/{id}/resize", s.postContainerResize)
	rt.handle(http.MethodPost, "/containers/{id}/exec", s.postContainerExec)
	rt.handle(http.MethodDelete, "/containers/{id}", s.deleteContainer)

	// --- exec ---
	rt.handle(http.MethodPost, "/exec/{id}/start", s.postExecStart)
	rt.handle(http.MethodPost, "/exec/{id}/resize", s.postExecResize)
	rt.handle(http.MethodGet, "/exec/{id}/json", s.getExecJSON)

	// --- images ---
	// The fixed-path routes come first so "json", "create", "load", "prune"
	// and "get" are never mistaken for an image reference.
	rt.handle(http.MethodGet, "/images/json", s.getImagesJSON)
	rt.handle(http.MethodPost, "/images/create", s.postImagesCreate)
	rt.handle(http.MethodPost, "/images/load", s.postImagesLoad)
	rt.handle(http.MethodPost, "/images/prune", s.postImagesPrune)
	rt.handle(http.MethodGet, "/images/get", s.getImagesGet)
	rt.handle(http.MethodGet, "/images/search", s.getImagesSearch)
	rt.handle(http.MethodGet, "/images/{name...}/json", s.getImageJSON)
	rt.handle(http.MethodGet, "/images/{name...}/history", s.getImageHistory)
	rt.handle(http.MethodGet, "/images/{name...}/get", s.getImageGet)
	rt.handle(http.MethodPost, "/images/{name...}/push", s.postImagePush)
	rt.handle(http.MethodPost, "/images/{name...}/tag", s.postImageTag)
	rt.handle(http.MethodDelete, "/images/{name...}", s.deleteImage)
	rt.handle(http.MethodPost, "/commit", s.postCommit)
	rt.handle(http.MethodPost, "/build", s.postBuild)
	rt.handle(http.MethodPost, "/build/prune", s.postBuildPrune)

	// --- buildkit, when one is bundled ---
	rt.handle(http.MethodPost, "/grpc", s.postGRPC)
	rt.handle(http.MethodPost, "/session", s.postSession)

	// --- distribution ---
	rt.handle(http.MethodGet, "/distribution/{name...}/json", s.getDistributionJSON)

	// --- networks ---
	rt.handle(http.MethodGet, "/networks", s.getNetworks)
	rt.handle(http.MethodPost, "/networks/create", s.postNetworksCreate)
	rt.handle(http.MethodPost, "/networks/prune", s.postNetworksPrune)
	rt.handle(http.MethodGet, "/networks/{id}", s.getNetwork)
	rt.handle(http.MethodDelete, "/networks/{id}", s.deleteNetwork)
	rt.handle(http.MethodPost, "/networks/{id}/connect", s.postNetworkConnect)
	rt.handle(http.MethodPost, "/networks/{id}/disconnect", s.postNetworkDisconnect)

	// --- volumes ---
	rt.handle(http.MethodGet, "/volumes", s.getVolumes)
	rt.handle(http.MethodPost, "/volumes/create", s.postVolumesCreate)
	rt.handle(http.MethodPost, "/volumes/prune", s.postVolumesPrune)
	rt.handle(http.MethodGet, "/volumes/{name}", s.getVolume)
	rt.handle(http.MethodDelete, "/volumes/{name}", s.deleteVolume)
}
