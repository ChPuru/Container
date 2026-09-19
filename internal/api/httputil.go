package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxJSONBody bounds how much of a request body the JSON decoders will read.
// Every JSON body this API takes is a configuration blob measured in
// kilobytes; anything larger is a mistake or an attack.
const maxJSONBody = 4 << 20

// writeJSON sends v as an application/json response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSONBody reads a JSON request body into v.
//
// An empty body is accepted and leaves v untouched, because Docker's clients
// routinely POST with no body at all to endpoints that take optional
// parameters.
func decodeJSONBody(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil {
		return errBadParameter("read request body: %v", err)
	}
	if int64(len(body)) > maxJSONBody {
		return errBadParameter("request body is larger than the %d byte limit", maxJSONBody)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		return errBadParameter("invalid JSON body: %v", err)
	}
	return nil
}

// boolValue reads a query parameter the way Docker does: present-but-empty is
// true, "0"/"false"/"no"/"none" are false, everything else is true.
func boolValue(r *http.Request, name string) bool {
	s, ok := lookupQuery(r, name)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "false", "no", "none":
		return false
	default:
		return true
	}
}

// boolValueOrDefault is boolValue with a fallback for an absent parameter.
func boolValueOrDefault(r *http.Request, name string, def bool) bool {
	if _, ok := lookupQuery(r, name); !ok {
		return def
	}
	return boolValue(r, name)
}

// lookupQuery returns a query parameter and whether it was present at all.
func lookupQuery(r *http.Request, name string) (string, bool) {
	q := r.URL.Query()
	if vs, ok := q[name]; ok && len(vs) > 0 {
		return vs[0], true
	}
	return "", false
}

// intValue reads an integer query parameter, returning def when absent and an
// error when present but unparseable.
func intValue(r *http.Request, name string, def int) (int, error) {
	s, ok := lookupQuery(r, name)
	if !ok || s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, errBadParameter("invalid value for %s: %q", name, s)
	}
	return n, nil
}

// int64Value reads a 64-bit integer query parameter.
func int64Value(r *http.Request, name string, def int64) (int64, error) {
	s, ok := lookupQuery(r, name)
	if !ok || s == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, errBadParameter("invalid value for %s: %q", name, s)
	}
	return n, nil
}

// optionalIntValue reads an integer query parameter as a pointer, so "absent"
// and "explicitly zero" stay distinguishable — which matters for a stop
// timeout, where zero means "kill immediately".
func optionalIntValue(r *http.Request, name string) (*int, error) {
	s, ok := lookupQuery(r, name)
	if !ok || s == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil, errBadParameter("invalid value for %s: %q", name, s)
	}
	return &n, nil
}

// parseFilterArgs decodes the ?filters= query parameter, which is a JSON
// object of string to []string. Docker also accepts the older map[string]bool
// encoding, so both are handled: a client from 2016 should still get an
// answer, not a parse error.
func parseFilterArgs(r *http.Request) (map[string][]string, error) {
	raw, ok := lookupQuery(r, "filters")
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out map[string][]string
	if err := json.Unmarshal([]byte(raw), &out); err == nil {
		return out, nil
	}
	var legacy map[string]map[string]bool
	if err := json.Unmarshal([]byte(raw), &legacy); err != nil {
		return nil, errBadParameter("invalid filters: %v", err)
	}
	out = make(map[string][]string, len(legacy))
	for k, set := range legacy {
		for v, on := range set {
			if on {
				out[k] = append(out[k], v)
			}
		}
	}
	return out, nil
}

// filterKeysAllowed rejects a filter key this endpoint does not implement, the
// way Docker rejects it: by name, with a 400, rather than by quietly widening
// the result set.
func filterKeysAllowed(f map[string][]string, allowed ...string) error {
	if len(f) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	for k := range f {
		if _, ok := set[k]; !ok {
			return errBadParameter("Invalid filter '%s'", k)
		}
	}
	return nil
}

// parseSinceUntil reads the /events and /logs time bounds. Docker accepts a
// unix timestamp with an optional fractional part, and an RFC3339 instant.
func parseTimestamp(s string, def time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	if secs, frac, ok := strings.Cut(s, "."); ok {
		if n, err := strconv.ParseInt(secs, 10, 64); err == nil {
			nanos, ferr := parseFraction(frac)
			if ferr != nil {
				return time.Time{}, ferr
			}
			return time.Unix(n, nanos), nil
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, errBadParameter("invalid time %q: expected a unix timestamp or an RFC3339 instant", s)
	}
	return t, nil
}

// parseFraction turns the fractional part of a unix timestamp into nanoseconds.
func parseFraction(frac string) (int64, error) {
	if frac == "" {
		return 0, nil
	}
	if len(frac) > 9 {
		frac = frac[:9]
	}
	for len(frac) < 9 {
		frac += "0"
	}
	n, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return 0, errBadParameter("invalid fractional timestamp %q", frac)
	}
	return n, nil
}

// registryAuthFromHeader decodes the X-Registry-Auth header, which is a
// base64url-encoded AuthConfig. An absent header is not an error: most pulls
// are anonymous.
func registryAuthFromHeader(r *http.Request) (AuthConfig, error) {
	var cfg AuthConfig
	raw := r.Header.Get("X-Registry-Auth")
	if raw == "" {
		return cfg, nil
	}
	dec, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(strings.TrimRight(raw, "="))
	if err != nil {
		if dec, err = base64.StdEncoding.DecodeString(raw); err != nil {
			return cfg, errBadParameter("invalid X-Registry-Auth header: %v", err)
		}
	}
	if err := json.Unmarshal(dec, &cfg); err != nil {
		return cfg, errBadParameter("invalid X-Registry-Auth header: %v", err)
	}
	return cfg, nil
}

// credentials resolves an AuthConfig into a username and password, expanding
// the legacy base64 "user:pass" form when that is all the client sent.
func (a AuthConfig) credentials() (string, string, error) {
	if a.Username != "" || a.Password != "" {
		return a.Username, a.Password, nil
	}
	if a.Auth == "" {
		return "", "", nil
	}
	dec, err := base64.StdEncoding.DecodeString(a.Auth)
	if err != nil {
		return "", "", errBadParameter("invalid auth token: %v", err)
	}
	user, pass, ok := strings.Cut(string(dec), ":")
	if !ok {
		return "", "", errBadParameter("invalid auth token: expected user:password")
	}
	return user, pass, nil
}

// pathUnescape is url.PathUnescape with a clearer error, used for the {name}
// segment of the image endpoints, where a reference may contain a slash.
func pathUnescape(s string) (string, error) {
	out, err := url.PathUnescape(s)
	if err != nil {
		return "", errBadParameter("invalid path segment %q: %v", s, err)
	}
	return out, nil
}

// errNotHijackable is returned when the underlying ResponseWriter cannot be
// hijacked, which in practice means a test server or a proxy that buffers.
var errNotHijackable = errors.New("api: this connection cannot be hijacked")

// stringsOrNil returns s, or nil when it is empty, so an omitempty JSON field
// serialises as null rather than [] where Docker sends null.
func stringsOrNil(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// stringsOrEmpty returns s, or an empty non-nil slice, so a JSON field
// serialises as [] rather than null where Docker sends [].
func stringsOrEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// mapOrEmpty returns m, or an empty non-nil map, so a JSON field serialises as
// {} rather than null.
func mapOrEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// queryValues is r.URL.Query() with the "filters" key removed, used by the
// endpoints that accept both named parameters and a filters blob.
func queryValues(r *http.Request) url.Values {
	q := r.URL.Query()
	delete(q, "filters")
	return q
}

// formatDuration renders a duration the way Docker's units.HumanDuration does,
// which is what the container list's Status column is built from.
func formatDuration(d time.Duration) string {
	seconds := int(d.Seconds())
	switch {
	case seconds < 1:
		return "Less than a second"
	case seconds == 1:
		return "1 second"
	case seconds < 60:
		return fmt.Sprintf("%d seconds", seconds)
	}
	minutes := seconds / 60
	switch {
	case minutes == 1:
		return "About a minute"
	case minutes < 60:
		return fmt.Sprintf("%d minutes", minutes)
	}
	hours := int(float64(minutes)/60 + 0.5)
	switch {
	case hours == 1:
		return "About an hour"
	case hours < 48:
		return fmt.Sprintf("%d hours", hours)
	case hours < 24*7*2:
		return fmt.Sprintf("%d days", hours/24)
	case hours < 24*30*2:
		return fmt.Sprintf("%d weeks", hours/24/7)
	case hours < 24*365*2:
		return fmt.Sprintf("%d months", hours/24/30)
	}
	return fmt.Sprintf("%d years", hours/24/365)
}
