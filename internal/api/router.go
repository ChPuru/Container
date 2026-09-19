package api

import (
	"context"
	"net/http"
	"strings"
)

// ctxKey is the private key type for values this package puts on a request
// context.
type ctxKey int

const (
	// ctxKeyVars carries the matched path parameters.
	ctxKeyVars ctxKey = iota
	// ctxKeyVersion carries the negotiated API version.
	ctxKeyVersion
)

// handlerFunc is one endpoint. Returning an error is how a handler that has
// not yet written anything reports a failure: the dispatcher turns it into
// Docker's {"message": "..."} body with the right status. A handler that has
// already started streaming reports failures inside the stream and returns
// nil.
type handlerFunc func(w http.ResponseWriter, r *http.Request) error

// segment is one component of a route pattern.
type segment struct {
	// literal is the exact text to match when name is empty.
	literal string
	// name is the parameter to bind when non-empty.
	name string
	// greedy makes the parameter consume as many path segments as the fixed
	// tail allows, which is what an image reference needs: "foo/bar:tag" is
	// two path segments and one name.
	greedy bool
}

// route is one method-and-pattern to handler binding.
type route struct {
	method   string
	pattern  string
	segments []segment
	handler  handlerFunc
}

// router matches a method and path onto a handler, binding path parameters.
//
// It is hand-rolled rather than built on http.ServeMux because Docker's image
// endpoints put a value containing slashes in the middle of a path
// (/images/registry.example.com/team/app:1.0/json) and no stdlib pattern can
// express that.
type router struct {
	routes []route
}

// parsePattern compiles "/containers/{id}/json" or "/images/{name...}/json"
// into segments. "{x}" matches one path segment; "{x...}" matches one or more.
func parsePattern(pattern string) []segment {
	parts := strings.Split(strings.Trim(pattern, "/"), "/")
	segs := make([]segment, 0, len(parts))
	for _, p := range parts {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			name := p[1 : len(p)-1]
			greedy := strings.HasSuffix(name, "...")
			segs = append(segs, segment{name: strings.TrimSuffix(name, "..."), greedy: greedy})
			continue
		}
		segs = append(segs, segment{literal: p})
	}
	return segs
}

// handle registers a handler for one method and pattern.
func (rt *router) handle(method, pattern string, h handlerFunc) {
	rt.routes = append(rt.routes, route{
		method:   method,
		pattern:  pattern,
		segments: parsePattern(pattern),
		handler:  h,
	})
}

// lookup finds the handler for a method and path.
//
// It reports pathMatched separately so the dispatcher can answer a known path
// with the wrong method as 405 rather than 404, which is what a client needs
// in order to tell "this endpoint does not exist" from "you asked for it
// wrongly".
func (rt *router) lookup(method, path string) (handlerFunc, map[string]string, bool) {
	parts := splitPath(path)
	pathMatched := false
	for i := range rt.routes {
		vars, ok := matchSegments(rt.routes[i].segments, parts)
		if !ok {
			continue
		}
		pathMatched = true
		if rt.routes[i].method != method {
			continue
		}
		return rt.routes[i].handler, vars, true
	}
	return nil, nil, pathMatched
}

// splitPath breaks a request path into its non-empty segments.
func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// matchSegments matches a compiled pattern against a split path, binding any
// parameters it finds.
func matchSegments(segs []segment, parts []string) (map[string]string, bool) {
	greedyAt := -1
	for i := range segs {
		if segs[i].greedy {
			greedyAt = i
			break
		}
	}
	if greedyAt < 0 {
		if len(segs) != len(parts) {
			return nil, false
		}
		vars := map[string]string{}
		for i := range segs {
			if segs[i].name != "" {
				vars[segs[i].name] = parts[i]
				continue
			}
			if segs[i].literal != parts[i] {
				return nil, false
			}
		}
		return vars, true
	}

	head, tail := segs[:greedyAt], segs[greedyAt+1:]
	// The greedy segment must swallow at least one path component.
	if len(parts) < len(head)+len(tail)+1 {
		return nil, false
	}
	vars := map[string]string{}
	for i := range head {
		if head[i].name != "" {
			vars[head[i].name] = parts[i]
			continue
		}
		if head[i].literal != parts[i] {
			return nil, false
		}
	}
	tailStart := len(parts) - len(tail)
	for i := range tail {
		p := parts[tailStart+i]
		if tail[i].name != "" {
			vars[tail[i].name] = p
			continue
		}
		if tail[i].literal != p {
			return nil, false
		}
	}
	vars[segs[greedyAt].name] = strings.Join(parts[len(head):tailStart], "/")
	return vars, true
}

// vars returns the path parameters bound by the matched route.
func vars(r *http.Request) map[string]string {
	if m, ok := r.Context().Value(ctxKeyVars).(map[string]string); ok {
		return m
	}
	return map[string]string{}
}

// pathVar returns one bound path parameter, URL-unescaped.
func pathVar(r *http.Request, name string) (string, error) {
	return pathUnescape(vars(r)[name])
}

// withVars returns r carrying the matched path parameters and the negotiated
// API version.
func withVars(r *http.Request, v map[string]string, ver Version) *http.Request {
	ctx := context.WithValue(r.Context(), ctxKeyVars, v)
	ctx = context.WithValue(ctx, ctxKeyVersion, ver)
	return r.WithContext(ctx)
}
