// Package registry implements an OCI distribution-spec v1.1.1 client: manifest
// resolution across image indexes, blob transfer with digest verification,
// pushes, tag and catalog listing, and the full Bearer token dance registries
// authenticate with.
//
// It uses nothing but the Go standard library and hull's own lower layers, and
// it is deliberately strict:
//
//   - Content is dispatched on the response Content-Type, never on what the
//     client asked for in Accept, because Docker Hub serves whatever was pushed.
//   - Every byte that is stored is verified against the digest that names it.
//   - The Authorization header is stripped whenever a registry redirects a blob
//     download to a different host, because a presigned CDN URL both rejects it
//     and would leak the token to a third party.
//   - Only idempotent requests are retried. A PUT or POST that may have partly
//     applied is never replayed.
package registry

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ChPuru/hull/internal/oci/reference"
)

// Defaults applied by NewClient when Options leaves a field zero.
const (
	// DefaultConcurrency is how many layer downloads run at once.
	DefaultConcurrency = 3
	// DefaultUserAgent identifies hull to registries.
	DefaultUserAgent = "hull/1.0 (+https://github.com/ChPuru/hull)"
	// DockerHubEndpoint is the host that actually serves the Docker Hub
	// distribution API; docker.io itself does not.
	DockerHubEndpoint = "registry-1.docker.io"
)

// Internal limits. These exist so that a hostile or broken registry cannot make
// the daemon allocate without bound.
const (
	// maxManifestSize caps a manifest or image index body at 8 MiB. Real ones
	// are kilobytes.
	maxManifestSize = 8 << 20
	// maxErrorBody caps how much of an error response is read back.
	maxErrorBody = 64 << 10
	// maxListBody caps a tag or catalog listing page.
	maxListBody = 4 << 20
	// defaultMaxRetries is how many times an idempotent request is retried.
	defaultMaxRetries = 3
	// defaultBaseBackoff is the first retry delay; it doubles each attempt.
	defaultBaseBackoff = 200 * time.Millisecond
	// maxRetryAfterWait is the longest Retry-After hull will honour inline.
	// Anything longer is reported to the user instead of silently stalling.
	maxRetryAfterWait = 30 * time.Second
	// maxRedirects bounds a redirect chain.
	maxRedirects = 10
)

// Options configures a Client. The zero value is usable: it produces an
// anonymous client with sane timeouts.
type Options struct {
	// UserAgent is sent on every request. Empty means DefaultUserAgent.
	UserAgent string
	// HTTPClient is the transport to use. Nil means a client with hull's
	// default timeouts. A supplied client is shallow-copied, never mutated,
	// and its redirect policy is replaced so that Authorization is stripped on
	// cross-host redirects.
	HTTPClient *http.Client
	// Insecure talks plain HTTP to registries and skips TLS verification when
	// https is used anyway. It is an explicit opt-in for local registries.
	Insecure bool
	// Auth supplies credentials. Nil means fully anonymous, which still works
	// for public images because the anonymous token dance needs no secrets.
	Auth Authenticator
	// Concurrency bounds simultaneous layer downloads. Zero means
	// DefaultConcurrency.
	Concurrency int
	// Progress, when non-nil, receives one event per layer state change. It is
	// called serially, never concurrently, so it may touch shared state.
	Progress func(ProgressEvent)
}

// rateLimit is the last rate-limit state a registry reported.
type rateLimit struct {
	limit     int
	remaining int
	window    time.Duration
	seen      bool
}

// Client is an OCI distribution-spec v1.1.1 registry client. It is safe for
// concurrent use by multiple goroutines.
type Client struct {
	http        *http.Client
	userAgent   string
	insecure    bool
	auth        Authenticator
	concurrency int

	progressMu sync.Mutex
	progress   func(ProgressEvent)

	mu         sync.Mutex
	challenges map[string]Challenge
	rl         rateLimit

	// Tunables, lowered by tests.
	maxRetries    int
	baseBackoff   time.Duration
	pushChunkSize int64
}

// NewClient returns a Client configured by opts.
func NewClient(opts Options) *Client {
	hc := opts.HTTPClient
	if hc == nil {
		hc = defaultHTTPClient(opts.Insecure)
	} else {
		cp := *hc
		hc = &cp
		if hc.Transport == nil && opts.Insecure {
			hc.Transport = insecureTransport()
		}
	}
	hc.CheckRedirect = stripAuthOnCrossHostRedirect

	c := &Client{
		http:          hc,
		userAgent:     opts.UserAgent,
		insecure:      opts.Insecure,
		auth:          opts.Auth,
		concurrency:   opts.Concurrency,
		progress:      opts.Progress,
		challenges:    map[string]Challenge{},
		maxRetries:    defaultMaxRetries,
		baseBackoff:   defaultBaseBackoff,
		pushChunkSize: DefaultPushChunkSize,
	}
	if c.userAgent == "" {
		c.userAgent = DefaultUserAgent
	}
	if c.concurrency <= 0 {
		c.concurrency = DefaultConcurrency
	}
	if setter, ok := c.auth.(HTTPClientSetter); ok {
		setter.SetHTTPClient(hc)
	}
	return c
}

// baseTransport returns hull's default transport settings.
func baseTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
}

func insecureTransport() *http.Transport {
	t := baseTransport()
	// Explicitly requested by Options.Insecure, for local registries with
	// self-signed certificates.
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in
	return t
}

// defaultHTTPClient builds the transport used when the caller supplies none.
// There is deliberately no Client.Timeout: a layer download may legitimately
// take minutes, and cancellation is the context's job.
func defaultHTTPClient(insecure bool) *http.Client {
	if insecure {
		return &http.Client{Transport: insecureTransport()}
	}
	return &http.Client{Transport: baseTransport()}
}

// canonicalHost renders a URL's host with its default port elided, so that
// https://example.com and https://example.com:443 compare equal.
func canonicalHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	switch {
	case port == "":
	case u.Scheme == "https" && port == "443":
		port = ""
	case u.Scheme == "http" && port == "80":
		port = ""
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

// stripAuthOnCrossHostRedirect removes credentials when a registry redirects to
// another host.
//
// Registries answer a blob GET with a 307 to a CDN — S3, CloudFront, GCS — and
// those presigned URLs reject a request that also carries an Authorization
// header, as well as making the registry token visible to a third party. Go's
// own redirect logic compares hostnames only, so it would happily forward the
// header to a different port on the same host; this policy compares host and
// port and is therefore strictly tighter.
func stripAuthOnCrossHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("registry: stopped after %d redirects", maxRedirects)
	}
	prev := via[len(via)-1]
	if canonicalHost(prev.URL) != canonicalHost(req.URL) {
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
		req.Header.Del("Www-Authenticate")
	}
	return nil
}

// Endpoint returns the scheme and host that serve the distribution API for a
// registry domain. docker.io is mapped to registry-1.docker.io, and
// Options.Insecure selects plain HTTP.
func (c *Client) Endpoint(domain string) (scheme, host string) {
	host = domain
	if normalizeAuthKey(domain) == "docker.io" {
		host = DockerHubEndpoint
	}
	if c.insecure {
		return "http", host
	}
	return "https", host
}

// repoURL builds a /v2/<name>/... URL for a repository.
func (c *Client) repoURL(ref reference.Reference, parts ...string) string {
	scheme, host := c.Endpoint(ref.Domain)
	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	b.WriteString("/v2/")
	b.WriteString(ref.Name())
	for _, p := range parts {
		b.WriteByte('/')
		b.WriteString(p)
	}
	return b.String()
}

// registryURL builds a /v2/... URL that is not scoped to a repository.
func (c *Client) registryURL(domain string, parts ...string) string {
	scheme, host := c.Endpoint(domain)
	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	b.WriteString("/v2/")
	b.WriteString(strings.Join(parts, "/"))
	return b.String()
}

// repoScope builds the token scope for a repository and a set of actions.
func repoScope(ref reference.Reference, actions ...string) string {
	return "repository:" + ref.Name() + ":" + strings.Join(actions, ",")
}

// pullScope is the scope for reading from a repository.
func pullScope(ref reference.Reference) string { return repoScope(ref, "pull") }

// pushScope is the scope for writing to a repository.
func pushScope(ref reference.Reference) string { return repoScope(ref, "pull", "push") }

func (c *Client) cachedChallenge(host string) (Challenge, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.challenges[host]
	return ch, ok
}

func (c *Client) cacheChallenge(host string, ch Challenge) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.challenges[host] = ch
}

// newRequest builds a request with hull's standard headers.
func (c *Client) newRequest(ctx context.Context, method, rawurl string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawurl, body)
	if err != nil {
		return nil, fmt.Errorf("registry: building %s %s: %w", method, rawurl, err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	return req, nil
}

// do sends req, performing the token dance on a 401 and retrying idempotent
// requests on transient failures.
//
// fallbackScope is used when the registry's challenge does not name one. The
// returned response's body is open and belongs to the caller; a non-nil error
// means nothing is left to close.
func (c *Client) do(ctx context.Context, req *http.Request, fallbackScope string) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	host := canonicalHost(req.URL)

	if c.auth != nil {
		if ch, ok := c.cachedChallenge(host); ok {
			scope := fallbackScope
			if ch.IsBasic() {
				scope = ""
			}
			if err := c.auth.Authorize(ctx, req, ch.Realm(), ch.Service(), scope); err != nil {
				return nil, err
			}
		}
	}

	resp, err := c.attempt(ctx, req)
	if err != nil {
		return nil, err
	}
	c.recordRateLimit(resp)

	if resp.StatusCode == http.StatusUnauthorized && c.auth != nil {
		chs := ParseChallenges(resp.Header.Get("WWW-Authenticate"))
		if ch, ok := pickChallenge(chs); ok {
			drain(resp)
			c.cacheChallenge(host, ch)
			scope := ch.Scope()
			if scope == "" && !ch.IsBasic() {
				scope = fallbackScope
			}
			retry, err := cloneRequest(ctx, req)
			if err != nil {
				return nil, err
			}
			retry.Header.Del("Authorization")
			if err := c.auth.Authorize(ctx, retry, ch.Realm(), ch.Service(), scope); err != nil {
				return nil, err
			}
			resp, err = c.attempt(ctx, retry)
			if err != nil {
				return nil, err
			}
			c.recordRateLimit(resp)
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		err := c.rateLimitError(resp)
		drain(resp)
		return nil, err
	}
	return resp, nil
}

// cloneRequest copies a request so it can be sent again, rewinding its body.
func cloneRequest(ctx context.Context, req *http.Request) (*http.Request, error) {
	clone := req.Clone(ctx)
	if req.Body == nil || req.Body == http.NoBody {
		return clone, nil
	}
	if req.GetBody == nil {
		return nil, fmt.Errorf("registry: cannot resend %s %s: the request body is not rewindable", req.Method, req.URL)
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("registry: rewinding request body: %w", err)
	}
	clone.Body = body
	return clone, nil
}

// idempotent reports whether a request may be replayed. A PUT, POST or PATCH
// that may have partly applied is never retried.
func idempotent(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
	}
	return false
}

// retryableStatus reports whether a status code is worth another attempt.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// attempt sends a request, retrying transient failures with exponential
// backoff plus jitter when the request is idempotent.
func (c *Client) attempt(ctx context.Context, req *http.Request) (*http.Response, error) {
	canRetry := idempotent(req)
	var lastErr error
	for i := 0; ; i++ {
		send := req
		if i > 0 {
			var err error
			send, err = cloneRequest(ctx, req)
			if err != nil {
				return nil, err
			}
		}
		resp, err := c.http.Do(send)
		switch {
		case err == nil && !retryableStatus(resp.StatusCode):
			return resp, nil
		case err != nil:
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, fmt.Errorf("registry: %s %s: %w", req.Method, req.URL, ctxErr)
			}
			lastErr = fmt.Errorf("registry: %s %s: %w", req.Method, req.URL, err)
		default:
			lastErr = nil
		}

		if !canRetry || i >= c.maxRetries {
			if err != nil {
				return nil, lastErr
			}
			return resp, nil
		}

		wait := c.backoff(i)
		if resp != nil {
			if ra, ok := retryAfter(resp); ok {
				if ra > maxRetryAfterWait {
					// Honouring this inline would stall the caller for
					// minutes; report it instead.
					return resp, nil
				}
				wait = ra
			}
			drain(resp)
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("registry: %s %s: %w", req.Method, req.URL, ctx.Err())
		case <-time.After(wait):
		}
	}
}

// backoff returns the delay before retry number i, with up to 50% jitter so
// that a fleet of pullers does not synchronise on a struggling registry.
func (c *Client) backoff(i int) time.Duration {
	base := c.baseBackoff
	if base <= 0 {
		base = defaultBaseBackoff
	}
	if i > 6 {
		i = 6
	}
	d := base << uint(i)
	jitter := time.Duration(rand.Int64N(int64(d/2) + 1))
	return d + jitter
}

// retryAfter reads a Retry-After header in either of its two legal forms.
func retryAfter(resp *http.Response) (time.Duration, bool) {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

// drain consumes and closes a response body so the connection can be reused.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
	_ = resp.Body.Close()
}

// parseRateLimitValue parses the "100;w=3600" form used by RateLimit-Limit and
// RateLimit-Remaining, tolerating a bare number.
func parseRateLimitValue(v string) (int, time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, 0, false
	}
	// Some registries list several policies, comma-separated; the first is the
	// one in force.
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	num, rest, _ := strings.Cut(v, ";")
	n, err := strconv.Atoi(strings.TrimSpace(num))
	if err != nil {
		return 0, 0, false
	}
	var window time.Duration
	for _, part := range strings.Split(rest, ";") {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.TrimSpace(k) != "w" {
			continue
		}
		if secs, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && secs > 0 {
			window = time.Duration(secs) * time.Second
		}
	}
	return n, window, true
}

// headerAny returns the first non-empty value among several header spellings.
func headerAny(h http.Header, names ...string) string {
	for _, n := range names {
		if v := h.Get(n); v != "" {
			return v
		}
	}
	return ""
}

// recordRateLimit captures the rate-limit headers of every response.
func (c *Client) recordRateLimit(resp *http.Response) {
	if resp == nil {
		return
	}
	limitHdr := headerAny(resp.Header, "RateLimit-Limit", "X-RateLimit-Limit")
	remainHdr := headerAny(resp.Header, "RateLimit-Remaining", "X-RateLimit-Remaining")
	if limitHdr == "" && remainHdr == "" {
		return
	}
	var rl rateLimit
	rl.remaining = -1
	if n, w, ok := parseRateLimitValue(limitHdr); ok {
		rl.limit, rl.window, rl.seen = n, w, true
	}
	if n, w, ok := parseRateLimitValue(remainHdr); ok {
		rl.remaining, rl.seen = n, true
		if rl.window == 0 {
			rl.window = w
		}
	}
	if !rl.seen {
		return
	}
	c.mu.Lock()
	c.rl = rl
	c.mu.Unlock()
}

// RateLimit reports the registry's most recently advertised rate limit.
//
// ok is false until a response carrying RateLimit-Limit or RateLimit-Remaining
// has been seen; remaining is -1 when the registry sent only a limit. window is
// the period the limit applies over, taken from the ";w=" parameter — on Docker
// Hub that is 3600 seconds, i.e. the documented "100 pulls per 6 hours" is not
// what the live headers actually say, so hull always reads the header.
func (c *Client) RateLimit() (limit, remaining int, window time.Duration, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rl.limit, c.rl.remaining, c.rl.window, c.rl.seen
}

// rateLimitError builds the typed error for a 429.
func (c *Client) rateLimitError(resp *http.Response) error {
	e := &RateLimitError{
		Registry:  canonicalHost(resp.Request.URL),
		Remaining: -1,
	}
	if d, ok := retryAfter(resp); ok {
		e.RetryAfter = d
		e.Reset = time.Now().Add(d)
	}
	if n, _, ok := parseRateLimitValue(headerAny(resp.Header, "RateLimit-Limit", "X-RateLimit-Limit")); ok {
		e.Limit = n
	}
	if n, _, ok := parseRateLimitValue(headerAny(resp.Header, "RateLimit-Remaining", "X-RateLimit-Remaining")); ok {
		e.Remaining = n
	}
	if e.Reset.IsZero() {
		if v := headerAny(resp.Header, "RateLimit-Reset", "X-RateLimit-Reset"); v != "" {
			if secs, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				// Both the delta-seconds and the unix-timestamp forms are in
				// the wild; a value that looks like a timestamp is treated as
				// one.
				if secs > 1_000_000_000 {
					e.Reset = time.Unix(secs, 0)
				} else if secs > 0 {
					e.RetryAfter = time.Duration(secs) * time.Second
					e.Reset = time.Now().Add(e.RetryAfter)
				}
			}
		}
	}
	return e
}

// errorBody is the distribution-spec error document.
type errorBody struct {
	Errors []APIError `json:"errors"`
}

// statusError turns a non-2xx response into a *StatusError and closes its body.
func statusError(resp *http.Response) error {
	e := &StatusError{
		Method:     resp.Request.Method,
		URL:        resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	_ = resp.Body.Close()

	var eb errorBody
	if err := json.Unmarshal(body, &eb); err == nil && len(eb.Errors) > 0 {
		e.Errors = eb.Errors
	} else {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 512 {
			msg = msg[:512] + "..."
		}
		e.Body = msg
	}
	return e
}

// success reports whether a status code is 2xx.
func success(code int) bool { return code >= 200 && code < 300 }

// checkResponse returns nil for a 2xx response and a *StatusError otherwise,
// consuming the body in the error case.
func checkResponse(resp *http.Response) error {
	if success(resp.StatusCode) {
		return nil
	}
	return statusError(resp)
}

// contentType returns the response's media type with parameters stripped and
// lower-cased.
func contentType(resp *http.Response) string {
	ct := resp.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// errIsTemporary reports whether err looks like a transport-level failure that
// a retry might survive, as opposed to a context cancellation.
func errIsTemporary(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}
