package localproxy

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

// Register publishes name at target, plus any aliases.
//
// target may be "127.0.0.1:32769", "10.66.2.2:80", "http://host:port/prefix"
// or an https:// URL; a bare host:port is assumed to be http. name is normally
// the container name: it answers for "<name>.<Domain>". An alias containing a
// dot is taken as a fully qualified hostname and matched verbatim, so a
// compose service can also claim "api.internal"; an alias without a dot gets
// the Domain appended like the name does.
//
// Registering a name that already exists replaces it, which is what a container
// restart on a new published port needs. Claiming a hostname that a *different*
// route already answers for fails with [ErrConflict] and changes nothing.
func (p *Proxy) Register(name string, target string, aliases ...string) error {
	key := normalizeHost(name)
	if key == "" {
		return fmt.Errorf("localproxy: register: %w: empty name", ErrBadName)
	}
	u, err := parseTarget(target)
	if err != nil {
		return fmt.Errorf("localproxy: register %q: %w", name, err)
	}

	primary, err := p.qualify(name)
	if err != nil {
		return fmt.Errorf("localproxy: register %q: %w", name, err)
	}
	hostnames := []string{primary}
	seen := map[string]struct{}{primary: {}}
	for _, a := range aliases {
		h, err := p.qualify(a)
		if err != nil {
			return fmt.Errorf("localproxy: register %q: alias %q: %w", name, a, err)
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		hostnames = append(hostnames, h)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for _, h := range hostnames {
		if owner, ok := p.index[h]; ok && owner.name != key {
			return fmt.Errorf("localproxy: register %q: %w: %q belongs to %q",
				name, ErrConflict, h, owner.name)
		}
	}
	if old, ok := p.routes[key]; ok {
		for _, h := range old.hostnames {
			delete(p.index, h)
		}
	}
	r := &route{
		name:      key,
		url:       u,
		aliases:   append([]string(nil), aliases...),
		hostnames: hostnames,
	}
	p.routes[key] = r
	for _, h := range hostnames {
		p.index[h] = r
	}
	return nil
}

// Unregister removes the route registered under name. It returns [ErrNoRoute]
// if there is none, which callers tearing down a container may ignore with
// errors.Is.
func (p *Proxy) Unregister(name string) error {
	key := normalizeHost(name)
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.routes[key]
	if !ok {
		return fmt.Errorf("localproxy: unregister %q: %w", name, ErrNoRoute)
	}
	delete(p.routes, key)
	for _, h := range r.hostnames {
		if p.index[h] == r {
			delete(p.index, h)
		}
	}
	return nil
}

// Routes returns every registered route, sorted by name. The result is a copy;
// mutating it does not affect the proxy.
func (p *Proxy) Routes() []Route {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Route, 0, len(p.routes))
	for _, r := range p.routes {
		out = append(out, r.public())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup resolves a Host header to a target URL exactly as a request would be
// routed: static table first, then [Config.Resolve]. It exists so 'hull doctor'
// and the TUI can answer "where would api.localhost go?" without issuing a
// request.
func (p *Proxy) Lookup(host string) (target string, ok bool) {
	u, ok := p.resolveTarget(normalizeHost(host))
	if !ok {
		return "", false
	}
	return u.String(), true
}

// resolveTarget is the request path's lookup. host must already be normalised.
func (p *Proxy) resolveTarget(host string) (*url.URL, bool) {
	if host == "" {
		return nil, false
	}
	p.mu.RLock()
	r, ok := p.index[host]
	p.mu.RUnlock()
	if ok {
		return r.url, true
	}
	if p.resolve == nil {
		return nil, false
	}
	target, ok := p.resolve(host)
	if !ok {
		return nil, false
	}
	u, err := parseTarget(target)
	if err != nil {
		p.logf("localproxy: Resolve(%q) returned unusable target %q: %v", host, target, err)
		return nil, false
	}
	return u, true
}

// qualify turns a name or alias into the hostname it answers for: a bare label
// gets the Domain appended, anything already containing a dot is taken as
// given, and a name that already ends in the Domain is not suffixed twice.
func (p *Proxy) qualify(s string) (string, error) {
	n := normalizeHost(s)
	if n == "" {
		return "", fmt.Errorf("%w: %q", ErrBadName, s)
	}
	if !strings.Contains(n, ".") {
		n += "." + p.domain
	}
	if !validHostname(n) {
		return "", fmt.Errorf("%w: %q", ErrBadName, s)
	}
	return n, nil
}

// normalizeHost reduces a Host header or a configured name to the form the
// route index is keyed by: no port, no IPv6 brackets, lowercase, no trailing
// root dot.
//
// This is the whole of hull's host matching, so it is deliberately boring:
// "API.localhost:8080", "api.localhost." and "api.LOCALHOST" all key the same
// route, and "[::1]:443" keys "::1".
func normalizeHost(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return ""
	}
	// SplitHostPort handles "[::1]:443" and "api.localhost:8080"; it fails on
	// a bare IPv6 literal or a name with no port, both of which are already
	// in the form we want.
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	h = strings.ToLower(h)
	for strings.HasSuffix(h, ".") {
		h = strings.TrimSuffix(h, ".")
	}
	return h
}

// validHostname reports whether h is a hostname hull will route. Underscores
// are allowed because Docker container names allow them.
func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			switch {
			case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '-', ch == '_':
			default:
				return false
			}
		}
	}
	return true
}

// parseTarget accepts "host:port", "http://host:port" or "https://host:port",
// optionally with a path prefix, and returns the normalised upstream URL.
func parseTarget(target string) (*url.URL, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return nil, fmt.Errorf("%w: empty target", ErrBadTarget)
	}
	if !strings.Contains(t, "://") {
		// "127.0.0.1:32769" would otherwise parse as scheme "127.0.0.1".
		t = "http://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return nil, fmt.Errorf("%w %q: %w", ErrBadTarget, target, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("%w %q: scheme %q is not http or https", ErrBadTarget, target, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w %q: no host", ErrBadTarget, target)
	}
	if h, _, err := net.SplitHostPort(u.Host); err == nil && h == "" {
		return nil, fmt.Errorf("%w %q: no host", ErrBadTarget, target)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	return u, nil
}
