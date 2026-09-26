package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ChPuru/hull/internal/version"
)

// placeholderHost is the authority hull puts in request URLs for transports
// that are not TCP. net/http insists on a host; the dialler ignores it.
const placeholderHost = "hull"

// Options configures a Client.
type Options struct {
	// Host is the engine address. Empty means the documented resolution
	// order: $HULL_HOST, then $DOCKER_HOST, then the platform default.
	Host string
	// Version pins the Docker Engine API version used in request paths. Empty
	// means hull's own version.APIVersion, which Ping may then negotiate down
	// to whatever the engine actually serves.
	Version string
	// HTTPClient replaces the transport hull would build. It is for tests and
	// for callers with their own TLS or proxy policy; the hijacking endpoints
	// still dial the host directly, because a hijacked stream cannot go
	// through an http.Client.
	HTTPClient *http.Client
	// Token is a bearer token sent on every request, for a TCP endpoint
	// guarded by a shared secret.
	Token string
	// UserAgent overrides the default "hull/<version>".
	UserAgent string
	// RelayCommand overrides the argv the wsl:// transport runs inside the
	// engine distro.
	RelayCommand []string
}

// Client talks to one hull engine.
//
// It is safe for concurrent use. Streaming calls return a reader or a channel
// that the caller must drain and close; everything else is a plain
// request/response round trip.
type Client struct {
	host   Host
	scheme string
	addr   string
	hc     *http.Client
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	token  string
	ua     string

	mu         sync.Mutex
	version    string
	pinned     bool
	negotiated bool
}

// New builds a client for the engine named by opts.
func New(opts Options) (*Client, error) {
	host, err := ResolveHost(opts.Host)
	if err != nil {
		return nil, err
	}
	dial, err := dialerFor(host, opts.RelayCommand)
	if err != nil {
		return nil, err
	}
	scheme := "http"
	if host.TLS {
		scheme = "https"
	}
	addr := placeholderHost
	if host.Scheme == SchemeTCP {
		addr = host.Addr
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Transport: &http.Transport{
				DialContext:           dial,
				DisableCompression:    true,
				MaxIdleConns:          8,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: 0,
				ExpectContinueTimeout: time.Second,
			},
		}
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "hull/" + version.Version
	}
	ver := strings.TrimPrefix(opts.Version, "v")
	pinned := ver != ""
	if ver == "" {
		ver = version.APIVersion
	}
	return &Client{
		host:    host,
		scheme:  scheme,
		addr:    addr,
		hc:      hc,
		dial:    dial,
		token:   opts.Token,
		ua:      ua,
		version: ver,
		pinned:  pinned,
	}, nil
}

// Host returns the endpoint this client talks to.
func (c *Client) Host() Host { return c.host }

// ClientVersion returns the API version currently used in request paths.
func (c *Client) ClientVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

// Close releases pooled connections. A client stays usable afterwards; this
// only tears down idle transports, which for the wsl:// transport means idle
// relay processes.
func (c *Client) Close() error {
	if tr, ok := c.hc.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
	return nil
}

// Ping is what /_ping reports about the engine.
type Ping struct {
	// APIVersion is the newest Docker Engine API version the engine serves.
	APIVersion string `json:"apiVersion"`
	// OSType is the engine's operating system, always "linux" for hull.
	OSType string `json:"osType"`
	// Experimental reports whether experimental features are on.
	Experimental bool `json:"experimental"`
	// BuilderVersion is "1" for the classic builder and "2" for BuildKit.
	BuilderVersion string `json:"builderVersion"`
	// SwarmStatus is empty for hull, which is single-host by design.
	SwarmStatus string `json:"swarmStatus"`
}

// Ping asks the engine what it is, and is the call every other client uses to
// negotiate an API version before doing anything else.
func (c *Client) Ping(ctx context.Context) (Ping, error) {
	resp, err := c.do(ctx, http.MethodGet, "/_ping", nil, nil, nil)
	if err != nil {
		return Ping{}, err
	}
	defer closeBody(resp)
	p := pingFromHeader(resp.Header)
	if p.APIVersion == "" {
		// A daemon too old to send the header still answers the body.
		if body, _ := io.ReadAll(io.LimitReader(resp.Body, 512)); len(body) > 0 {
			var fromBody Ping
			if json.Unmarshal(body, &fromBody) == nil && fromBody.APIVersion != "" {
				p = fromBody
			}
		}
	}
	return p, nil
}

// pingFromHeader reads the headers Docker clients gate on before anything
// else. Cache-Control and the rest are deliberately ignored.
func pingFromHeader(h http.Header) Ping {
	p := Ping{
		APIVersion:     h.Get("Api-Version"),
		OSType:         h.Get("Ostype"),
		BuilderVersion: h.Get("Builder-Version"),
		SwarmStatus:    h.Get("Swarm"),
	}
	if v, err := strconv.ParseBool(h.Get("Docker-Experimental")); err == nil {
		p.Experimental = v
	}
	return p
}

// NegotiateAPIVersion lowers this client's API version to the engine's when
// the engine is older, which is what makes an old daemon usable rather than
// confusing. A pinned version, or an unreachable engine, leaves it alone.
func (c *Client) NegotiateAPIVersion(ctx context.Context) {
	c.mu.Lock()
	if c.pinned || c.negotiated {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	p, err := c.Ping(ctx)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.negotiated = true
	if p.APIVersion == "" {
		return
	}
	if CompareAPIVersions(p.APIVersion, c.version) < 0 {
		c.version = p.APIVersion
	}
}

// CompareAPIVersions orders two dotted API versions such as "1.43" and "1.24".
// It returns -1 when a is older, 1 when a is newer and 0 when they match.
func CompareAPIVersions(a, b string) int {
	as := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bs := strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := 0, 0
		if i < len(as) {
			av, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(bs[i])
		}
		switch {
		case av < bv:
			return -1
		case av > bv:
			return 1
		}
	}
	return 0
}

// requestPath prefixes a Docker endpoint with the negotiated API version, the
// way every Docker client does. hull's own /hull/v1 endpoints are versioned by
// their own path and are passed through untouched.
func (c *Client) requestPath(path string) string {
	if strings.HasPrefix(path, "/hull/") {
		return path
	}
	// /_ping is what negotiation is made of, so it cannot carry the version
	// it is trying to discover: an engine whose ceiling is below ours must
	// reject a version prefix outside its range, and would then reject the
	// very request that would have told us to ask for less.
	if path == "/_ping" {
		return path
	}
	v := c.ClientVersion()
	if v == "" {
		return path
	}
	return "/v" + v + path
}

// url builds the absolute request URL.
func (c *Client) url(path string, query url.Values) string {
	u := url.URL{Scheme: c.scheme, Host: c.addr, Path: c.requestPath(path)}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

// newRequest builds a request with hull's standard headers attached.
func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.url(path, query), body)
	if err != nil {
		return nil, fmt.Errorf("client: build %s %s: %w", method, path, err)
	}
	req.Header.Set("User-Agent", c.ua)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return req, nil
}

// do performs one request and returns the response with its body still open.
// A non-2xx status is turned into an *Error and the body is drained.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Response, error) {
	req, err := c.newRequest(ctx, method, path, query, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("client: %s %s: %w", method, path, ctx.Err())
		}
		return nil, &ConnectionError{Host: c.host, Err: err}
	}
	if err := checkResponse(resp, method, path); err != nil {
		return nil, err
	}
	return resp, nil
}

// doJSON sends an optional JSON body and decodes an optional JSON response.
func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body io.Reader
	headers := http.Header{}
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("client: encode %s %s body: %w", method, path, err)
		}
		body = bytes.NewReader(buf)
		headers.Set("Content-Type", "application/json")
	}
	resp, err := c.do(ctx, method, path, query, body, headers)
	if err != nil {
		return err
	}
	defer closeBody(resp)
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("client: decode %s %s response: %w", method, path, err)
	}
	return nil
}

// get performs a GET and decodes the JSON response.
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	return c.doJSON(ctx, http.MethodGet, path, query, nil, out)
}

// post performs a POST with an optional JSON body and response.
func (c *Client) post(ctx context.Context, path string, query url.Values, in, out any) error {
	return c.doJSON(ctx, http.MethodPost, path, query, in, out)
}

// put performs a PUT with an optional JSON body and response.
func (c *Client) put(ctx context.Context, path string, query url.Values, in, out any) error {
	return c.doJSON(ctx, http.MethodPut, path, query, in, out)
}

// del performs a DELETE with an optional JSON response.
func (c *Client) del(ctx context.Context, path string, query url.Values, out any) error {
	return c.doJSON(ctx, http.MethodDelete, path, query, nil, out)
}

// checkResponse converts a non-2xx response into an *Error, preserving the
// engine's own message text because clients match on it.
func checkResponse(resp *http.Response, method, path string) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	closeBody(resp)
	msg := strings.TrimSpace(string(body))
	var payload struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Message != "" {
		msg = payload.Message
	}
	return &Error{StatusCode: resp.StatusCode, Message: msg, Method: method, Path: path}
}

// closeBody drains and closes a response body so the connection can be reused.
func closeBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
}

// boolQuery adds a query parameter only when the flag is set, matching how
// Docker's own clients build their requests.
func boolQuery(q url.Values, key string, v bool) {
	if v {
		q.Set(key, "1")
	}
}
