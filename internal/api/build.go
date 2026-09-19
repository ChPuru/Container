package api

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// buildKitProbeTTL is how long a buildkitd reachability answer is trusted.
// Short enough that `hull engine install-buildkit` takes effect without a
// daemon restart, long enough that /_ping does not dial a socket per call.
const buildKitProbeTTL = 30 * time.Second

// buildKitDialTimeout bounds a reachability probe.
const buildKitDialTimeout = 750 * time.Millisecond

// defaultBuildKitSockets are the places a bundled buildkitd is expected to
// listen, most specific first.
var defaultBuildKitSockets = []string{
	"/run/buildkit/buildkitd.sock",
	"/var/run/buildkit/buildkitd.sock",
}

// buildKitEndpoints returns the addresses to probe, in order.
func (s *Server) buildKitEndpoints() []string {
	if s.opts.BuildKitAddr != "" {
		return []string{s.opts.BuildKitAddr}
	}
	out := []string{filepath.Join(s.dataRoot, "buildkit", "buildkitd.sock")}
	return append(out, defaultBuildKitSockets...)
}

// splitEndpoint turns "unix:///run/x.sock", "tcp://127.0.0.1:1234" or a bare
// path into a net.Dial network and address.
func splitEndpoint(addr string) (string, string) {
	switch {
	case strings.HasPrefix(addr, "unix://"):
		return "unix", strings.TrimPrefix(addr, "unix://")
	case strings.HasPrefix(addr, "tcp://"):
		return "tcp", strings.TrimPrefix(addr, "tcp://")
	case strings.Contains(addr, "://"):
		net, rest, _ := strings.Cut(addr, "://")
		return net, rest
	default:
		return "unix", addr
	}
}

// buildKitAvailable reports whether a buildkitd answers, caching the answer
// for buildKitProbeTTL.
func (s *Server) buildKitAvailable() bool {
	s.buildkitMu.Lock()
	defer s.buildkitMu.Unlock()
	if time.Since(s.buildkitChecked) < buildKitProbeTTL {
		return s.buildkitUp
	}
	s.buildkitChecked = time.Now()
	s.buildkitUp, s.buildkitAddr = false, ""
	for _, ep := range s.buildKitEndpoints() {
		network, address := splitEndpoint(ep)
		if network == "unix" {
			if fi, err := os.Stat(address); err != nil || fi.Mode()&os.ModeSocket == 0 {
				continue
			}
		}
		conn, err := net.DialTimeout(network, address, buildKitDialTimeout)
		if err != nil {
			continue
		}
		_ = conn.Close()
		s.buildkitUp, s.buildkitAddr = true, ep
		return true
	}
	return false
}

// installBuildKitHint is the message every builder refusal ends with. It names
// the exact command rather than saying "buildkit is not available", because a
// user who hits this needs the next step, not a diagnosis.
const installBuildKitHint = "run 'hull engine install-buildkit' to install and start the bundled " +
	"buildkitd, then retry the build"

// postBuild answers POST /build.
//
// The tar context is accepted and drained either way: a client that is still
// writing its context when the daemon answers sees a broken pipe instead of
// the message, and then reports something unrelated.
func (s *Server) postBuild(w http.ResponseWriter, r *http.Request) error {
	drainBody(r)
	if !s.buildKitAvailable() {
		return errStatus(http.StatusNotImplemented,
			"hull has no built-in image builder yet and no buildkitd is reachable: %s",
			installBuildKitHint)
	}
	return errStatus(http.StatusNotImplemented,
		"hull routes BuildKit builds through the /grpc and /session endpoints, which a buildx "+
			"client drives directly; run 'docker buildx build' (or 'hull build', which does the "+
			"same) rather than the legacy /build endpoint")
}

// postBuildPrune answers POST /build/prune. With no native builder there is
// no build cache to reclaim, and saying so with a zero is more useful than a
// 404 that a client will retry.
func (s *Server) postBuildPrune(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, http.StatusOK, struct {
		CachesDeleted  []string `json:"CachesDeleted"`
		SpaceReclaimed int64    `json:"SpaceReclaimed"`
	}{CachesDeleted: []string{}, SpaceReclaimed: 0})
	return nil
}

// postGRPC answers POST /grpc: hijack and proxy the connection to buildkitd.
func (s *Server) postGRPC(w http.ResponseWriter, r *http.Request) error {
	return s.proxyToBuildKit(w, r, "/grpc")
}

// postSession answers POST /session: hijack and proxy the connection to
// buildkitd, which is how buildx ships the build context and credentials.
func (s *Server) postSession(w http.ResponseWriter, r *http.Request) error {
	return s.proxyToBuildKit(w, r, "/session")
}

// proxyToBuildKit hijacks the client connection and splices it onto a fresh
// connection to buildkitd.
//
// Both endpoints are opaque byte streams once the upgrade completes — gRPC
// over h2c in one direction and a session multiplexer in the other — so the
// proxy deliberately understands nothing about the payload. It only has to not
// corrupt it: the upgrade response is written verbatim, and neither direction
// is buffered past a copy.
func (s *Server) proxyToBuildKit(w http.ResponseWriter, r *http.Request, endpoint string) error {
	if !s.buildKitAvailable() {
		drainBody(r)
		return errStatus(http.StatusNotImplemented,
			"hull cannot serve %s: no buildkitd is reachable. %s", endpoint, installBuildKitHint)
	}
	s.buildkitMu.Lock()
	addr := s.buildkitAddr
	s.buildkitMu.Unlock()

	network, address := splitEndpoint(addr)
	upstream, err := net.DialTimeout(network, address, 5*time.Second)
	if err != nil {
		drainBody(r)
		return errStatus(http.StatusServiceUnavailable,
			"hull could not reach buildkitd at %s: %v. %s", addr, err, installBuildKitHint)
	}
	defer func() { _ = upstream.Close() }()

	rc := http.NewResponseController(w)
	conn, brw, err := rc.Hijack()
	if err != nil {
		return errStatus(http.StatusInternalServerError,
			"hull could not hijack the connection for %s: %v", endpoint, err)
	}
	defer func() { _ = conn.Close() }()

	proto := r.Header.Get("Upgrade")
	if proto == "" {
		proto = "h2c"
	}
	handshake := "HTTP/1.1 101 UPGRADED\r\n" +
		"Content-Type: application/vnd.docker.raw-stream\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: " + proto + "\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(handshake)); err != nil {
		return nil
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, brw)
		if cw, ok := upstream.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		_ = closeWrite(conn)
		done <- struct{}{}
	}()
	<-done
	return nil
}

// drainBody reads and discards a request body so the client's write side
// completes before it reads the response. The cap keeps a hostile or runaway
// build context from being read forever.
func drainBody(r *http.Request) {
	if r.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxDrainBytes))
	_ = r.Body.Close()
}

// maxDrainBytes bounds how much of an abandoned request body is consumed.
const maxDrainBytes = 64 << 20
