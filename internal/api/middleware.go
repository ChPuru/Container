package api

import (
	"bufio"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

// recordingWriter tracks the status and byte count of a response so the access
// log can report them.
//
// It deliberately implements http.Hijacker by delegation and exposes
// Unwrap, so http.NewResponseController can still reach the underlying
// connection. A logging wrapper that swallows Hijack is the classic way to
// break `docker attach` without breaking anything a curl test would notice.
type recordingWriter struct {
	http.ResponseWriter
	status   int
	written  int64
	hijacked bool
}

// WriteHeader records the status before passing it on.
func (w *recordingWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

// Write records the byte count before passing the data on.
func (w *recordingWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.written += int64(n)
	return n, err
}

// Unwrap exposes the wrapped writer to http.ResponseController, which is how
// Flush and Hijack keep working through this wrapper.
func (w *recordingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack takes over the connection, which is what the attach, exec and raw
// stream endpoints need.
func (w *recordingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errNotHijackable
	}
	conn, rw, err := h.Hijack()
	if err == nil {
		w.hijacked = true
		if w.status == 0 {
			w.status = http.StatusSwitchingProtocols
		}
	}
	return conn, rw, err
}

// Flush pushes buffered bytes to the client, which every streaming endpoint
// depends on.
func (w *recordingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// middleware wraps the dispatcher with CORS, panic recovery, client
// accounting and the optional access log.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recordingWriter{ResponseWriter: w}

		if s.opts.CORS != "" {
			h := rec.Header()
			h.Set("Access-Control-Allow-Origin", s.opts.CORS)
			h.Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, X-Registry-Auth, Authorization")
			h.Set("Access-Control-Allow-Methods", "HEAD, GET, POST, DELETE, PUT, OPTIONS")
			if r.Method == http.MethodOptions {
				rec.WriteHeader(http.StatusOK)
				return
			}
		}

		// The scale-to-zero watcher must not freeze a container or shut the
		// daemon down while a client is mid-request.
		s.backend.ClientConnected()
		defer s.backend.ClientDisconnected()

		defer func() {
			if rv := recover(); rv != nil {
				s.log.Error("hull: API handler panicked",
					"method", r.Method, "path", r.URL.Path, "panic", rv,
					"stack", string(debug.Stack()))
				if rec.status == 0 && !rec.hijacked {
					writeError(rec, errStatus(http.StatusInternalServerError,
						"the daemon hit an internal error handling %s %s", r.Method, r.URL.Path))
				}
			}
			if s.opts.AccessLog {
				attrs := []any{
					"method", r.Method,
					"path", r.URL.Path,
					"status", rec.status,
					"bytes", rec.written,
				}
				if s.opts.Debug {
					attrs = append(attrs, "duration", time.Since(start).String(),
						"remote", r.RemoteAddr, "ua", r.Header.Get("User-Agent"))
				}
				s.log.Debug("hull: api", attrs...)
			}
		}()

		next.ServeHTTP(rec, r)
	})
}

// dispatch parses the version prefix, gates on it, and runs the matched
// handler.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) {
	path, rawVersion, _ := splitVersionPrefix(r.URL.Path)
	ver, err := s.negotiate(rawVersion)
	if err != nil {
		writeError(w, err)
		return
	}

	h, v, matched := s.router.lookup(r.Method, path)
	if h == nil {
		if matched {
			w.Header().Set("Allow", strings.Join(s.allowedMethods(path), ", "))
			writeError(w, errStatus(http.StatusMethodNotAllowed,
				"page not found: %s is not allowed on %s", r.Method, path))
			return
		}
		writeError(w, errStatus(http.StatusNotFound, "page not found"))
		return
	}

	if err := h(w, withVars(r, v, ver)); err != nil {
		writeError(w, err)
	}
}

// allowedMethods lists the methods registered for a path, for the Allow header
// of a 405.
func (s *Server) allowedMethods(path string) []string {
	parts := splitPath(path)
	var out []string
	seen := map[string]bool{}
	for i := range s.router.routes {
		if _, ok := matchSegments(s.router.routes[i].segments, parts); !ok {
			continue
		}
		if m := s.router.routes[i].method; !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}
