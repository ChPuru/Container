// Package localproxy gives every container a name instead of a port number.
//
// A container that publishes an HTTP port is reachable at
// http://<name>.localhost/ and https://<name>.localhost/ rather than at
// http://localhost:32769/, which nobody can remember and which changes every
// time the container is recreated. The proxy listens once on :80 and :443,
// matches the Host header against its route table, and reverse-proxies to the
// container's published address. TLS is served from a local root managed by
// [github.com/ChPuru/hull/internal/localca].
//
// The routing rules, in order:
//
//  1. The Host header is normalised: port stripped, IPv6 brackets stripped,
//     lowercased, trailing root dot removed.
//  2. The result is looked up in the static table built by [Proxy.Register].
//     A name registered as "api" answers for "api.<Domain>"; an alias
//     containing a dot is taken verbatim, one without gets the Domain appended.
//  3. Failing that, [Config.Resolve] is consulted, so the engine can answer for
//     containers that were never explicitly registered.
//  4. Failing that, the request gets a 404 that *lists the routes that do
//     exist*. A wrong-hostname 404 saying only "not found" is the worst
//     possible failure here: the user cannot tell whether the proxy is down,
//     the container is down, or they typed the name wrong.
//
// Upgrades and streaming work: FlushInterval is -1 so nothing is buffered,
// which is what server-sent events need, and [net/http/httputil.ReverseProxy]
// hands a 101 response straight through to a raw bidirectional copy, which is
// what WebSockets need.
//
// # Name resolution on Windows
//
// This is the part that bites, and hull says so up front rather than shipping a
// feature that silently does not work.
//
// On Linux, systemd-resolved (and glibc, per RFC 6761) special-case the
// .localhost TLD: every name under it resolves to 127.0.0.1 without any
// configuration, so api.localhost just works. Windows' own resolver does not do
// this. It resolves the bare name "localhost" from a built-in rule, but
// "api.localhost" goes to DNS like any other name and comes back NXDOMAIN
// (Chrome and Edge resolve *.localhost internally, so a browser may work while
// curl, PowerShell and every other client fails — which is worse than a clean
// failure, because it looks like hull is broken only sometimes).
//
// Therefore 'hull doctor' must actually check whether <name>.localhost
// resolves on the Windows side, and when it does not, tell the user to either
// add the names to %SystemRoot%\System32\drivers\etc\hosts:
//
//	127.0.0.1 api.localhost
//	127.0.0.1 web.localhost
//
// (one line per container name, as Administrator), or to skip name resolution
// and use the 127.0.0.1 route directly with an explicit Host header, which this
// proxy routes identically:
//
//	curl -H 'Host: api.localhost' http://127.0.0.1/
//
// The certificates minted for these names carry 127.0.0.1 and ::1 as SANs
// precisely so that the second route works over HTTPS too.
package localproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ChPuru/hull/internal/localca"
)

// Defaults applied by [New] when a [Config] field is left zero.
const (
	// DefaultHTTPAddr is the plain-HTTP listen address.
	DefaultHTTPAddr = ":80"
	// DefaultHTTPSAddr is the TLS listen address.
	DefaultHTTPSAddr = ":443"
	// DefaultDomain is the suffix appended to a bare container name.
	DefaultDomain = "localhost"
	// DefaultShutdownGrace is how long Run waits for in-flight requests when
	// its context is cancelled.
	DefaultShutdownGrace = 5 * time.Second
)

// Transport tunables. Targets are containers on the far end of a veth pair in
// the same VM, so these are tight on purpose: a dead container should produce a
// 502 with an explanation, not a hung browser tab.
const (
	dialTimeout           = 5 * time.Second
	keepAlive             = 30 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
	responseHeaderTimeout = 60 * time.Second
	idleConnTimeout       = 90 * time.Second
	maxIdleConnsPerHost   = 32
)

// Sentinel errors returned by this package.
var (
	// ErrNoRoute means the name is not registered.
	ErrNoRoute = errors.New("no such route")
	// ErrConflict means a hostname is already claimed by a different route.
	ErrConflict = errors.New("hostname already routed")
	// ErrBadName means a route name or alias is not a usable hostname label.
	ErrBadName = errors.New("invalid route name")
	// ErrBadTarget means a target is not a usable host:port or URL.
	ErrBadTarget = errors.New("invalid route target")
	// ErrAlreadyRunning means Run was called twice on the same Proxy.
	ErrAlreadyRunning = errors.New("proxy is already running")
	// ErrNoListeners means both listen addresses were empty.
	ErrNoListeners = errors.New("no listen address configured")
)

// Config configures a [Proxy]. The zero value is usable: it listens on :80 and
// :443 for *.localhost with an empty route table.
type Config struct {
	// HTTPAddr is the plain-HTTP listen address, ":80" by default. Set it to
	// "-" to disable the plain listener entirely.
	HTTPAddr string
	// HTTPSAddr is the TLS listen address, ":443" by default. Set it to "-"
	// to disable TLS, in which case no CA is created.
	HTTPSAddr string
	// CADir is where the local root lives. Empty means "hull-ca" beside the
	// process working directory is *not* assumed — it is required whenever
	// HTTPS is enabled, and New fails without it.
	CADir string
	// Domain is the suffix bare names are qualified with, "localhost" by
	// default. It is matched, never resolved: hull does not run a DNS server
	// for it (see the package documentation on Windows resolution).
	Domain string
	// Resolve, if set, is consulted for a Host that matches no static route.
	// It is called with the already-normalised hostname (lowercased, port and
	// trailing dot stripped), e.g. "api.localhost", and returns the target in
	// the same forms Register accepts. It must be safe for concurrent use and
	// must not block: it is on the request path.
	Resolve func(host string) (target string, ok bool)
	// ShutdownGrace bounds the graceful shutdown when Run's context is
	// cancelled. Zero means DefaultShutdownGrace.
	ShutdownGrace time.Duration
	// ErrorLog, if set, receives listener and proxy errors.
	ErrorLog interface{ Printf(format string, v ...any) }
}

// Route is one registered destination, as [Proxy.Routes] reports it.
type Route struct {
	// Name is the registration key, normally the container name.
	Name string
	// Target is the normalised absolute URL requests are forwarded to.
	Target string
	// Aliases are the extra names given at registration, as given.
	Aliases []string
	// Hostnames is every Host header that reaches this route, primary first.
	Hostnames []string
}

// route is the internal form: a Route plus the parsed target.
type route struct {
	name      string
	url       *url.URL
	aliases   []string
	hostnames []string
}

func (r *route) public() Route {
	out := Route{
		Name:      r.name,
		Target:    r.url.String(),
		Aliases:   append([]string(nil), r.aliases...),
		Hostnames: append([]string(nil), r.hostnames...),
	}
	return out
}

// targetKey carries the chosen upstream from ServeHTTP into the single shared
// ReverseProxy's Rewrite hook, so the proxy needs no per-route object and no
// cache that could diverge from the route table.
type targetKey struct{}

// Proxy is the <name>.localhost reverse proxy. It is safe for concurrent use,
// and routes may be registered and unregistered while it is serving.
type Proxy struct {
	httpAddr  string
	httpsAddr string
	domain    string
	grace     time.Duration
	resolve   func(host string) (target string, ok bool)
	errorLog  interface{ Printf(format string, v ...any) }

	ca *localca.CA
	rp *httputil.ReverseProxy

	mu     sync.RWMutex
	routes map[string]*route // by name
	index  map[string]*route // by hostname

	running atomic.Bool

	readyOnce sync.Once
	ready     chan struct{}

	addrMu     sync.Mutex
	boundHTTP  string
	boundHTTPS string
}

// New builds a Proxy from cfg, creating or loading the local CA when HTTPS is
// enabled. It binds nothing; call [Proxy.Run] for that.
func New(cfg Config) (*Proxy, error) {
	p := &Proxy{
		httpAddr:  firstNonEmpty(cfg.HTTPAddr, DefaultHTTPAddr),
		httpsAddr: firstNonEmpty(cfg.HTTPSAddr, DefaultHTTPSAddr),
		domain:    normalizeHost(firstNonEmpty(cfg.Domain, DefaultDomain)),
		grace:     cfg.ShutdownGrace,
		resolve:   cfg.Resolve,
		errorLog:  cfg.ErrorLog,
		routes:    make(map[string]*route),
		index:     make(map[string]*route),
		ready:     make(chan struct{}),
	}
	if p.httpAddr == disabled {
		p.httpAddr = ""
	}
	if p.httpsAddr == disabled {
		p.httpsAddr = ""
	}
	if p.grace <= 0 {
		p.grace = DefaultShutdownGrace
	}
	if p.domain == "" || !validHostname(p.domain) {
		return nil, fmt.Errorf("localproxy: new: %w: domain %q", ErrBadName, cfg.Domain)
	}
	if p.httpsAddr != "" {
		if cfg.CADir == "" {
			return nil, errors.New("localproxy: new: CADir is required when HTTPS is enabled")
		}
		ca, err := localca.EnsureCA(cfg.CADir)
		if err != nil {
			return nil, fmt.Errorf("localproxy: new: %w", err)
		}
		p.ca = ca
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite:       p.rewrite,
		Transport:     newTransport(),
		FlushInterval: -1, // never buffer: SSE and long polls must stream
		ErrorHandler:  p.proxyError,
	}
	return p, nil
}

// disabled is the sentinel a caller passes to switch a listener off.
const disabled = "-"

// CA returns the local certificate authority backing HTTPS, or nil when the
// TLS listener is disabled. Callers use it for [localca.CA.InstallHint].
func (p *Proxy) CA() *localca.CA { return p.ca }

// Domain returns the suffix bare names are qualified with.
func (p *Proxy) Domain() string { return p.domain }

// Handler returns the routing handler, for embedding the proxy in another
// server or for testing it without binding a privileged port.
func (p *Proxy) Handler() http.Handler { return p }

// Ready returns a channel closed once Run has bound its listeners, or has
// failed trying. [Proxy.Addrs] is meaningful after it closes.
func (p *Proxy) Ready() <-chan struct{} { return p.ready }

// Addrs returns the actually-bound HTTP and HTTPS addresses, which differ from
// the configured ones when port 0 was requested. Either is empty when that
// listener is disabled or not yet bound.
func (p *Proxy) Addrs() (httpAddr, httpsAddr string) {
	p.addrMu.Lock()
	defer p.addrMu.Unlock()
	return p.boundHTTP, p.boundHTTPS
}

func (p *Proxy) logf(format string, args ...any) {
	if p.errorLog != nil {
		p.errorLog.Printf(format, args...)
	}
}

func newTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil, // never honour HTTP_PROXY for a loopback container hop
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: keepAlive,
		}).DialContext,
		// HTTP/2 to the upstream would break the Upgrade path, and every
		// upstream here is a container on the other side of a veth.
		ForceAttemptHTTP2:     false,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// contextWithTarget returns ctx carrying u as the upstream for one request.
func contextWithTarget(ctx context.Context, u *url.URL) context.Context {
	return context.WithValue(ctx, targetKey{}, u)
}

// targetFromContext returns the upstream stored by contextWithTarget.
func targetFromContext(ctx context.Context) (*url.URL, bool) {
	u, ok := ctx.Value(targetKey{}).(*url.URL)
	return u, ok
}
