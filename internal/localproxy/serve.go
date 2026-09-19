package localproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

// Run binds the configured listeners and serves until ctx is cancelled or a
// listener fails, then shuts both down gracefully within the configured grace
// period. It returns nil on a clean context-cancelled shutdown.
//
// Binding :80 and :443 needs CAP_NET_BIND_SERVICE or root inside the engine
// distro; hull runs the proxy in the same process as the daemon, which already
// has it. Run may only be called once per Proxy.
func (p *Proxy) Run(ctx context.Context) error {
	if !p.running.CompareAndSwap(false, true) {
		return fmt.Errorf("localproxy: run: %w", ErrAlreadyRunning)
	}
	defer p.readyOnce.Do(func() { close(p.ready) })

	if p.httpAddr == "" && p.httpsAddr == "" {
		return fmt.Errorf("localproxy: run: %w", ErrNoListeners)
	}

	type server struct {
		srv  *http.Server
		ln   net.Listener
		addr string
	}
	var servers []server
	closeAll := func() {
		for _, s := range servers {
			_ = s.ln.Close()
		}
	}

	if p.httpAddr != "" {
		ln, err := net.Listen("tcp", p.httpAddr)
		if err != nil {
			return fmt.Errorf("localproxy: listen http on %s: %w", p.httpAddr, err)
		}
		p.setBound(false, ln.Addr().String())
		servers = append(servers, server{srv: p.newServer(ctx, nil), ln: ln, addr: ln.Addr().String()})
	}
	if p.httpsAddr != "" {
		ln, err := net.Listen("tcp", p.httpsAddr)
		if err != nil {
			closeAll()
			return fmt.Errorf("localproxy: listen https on %s: %w", p.httpsAddr, err)
		}
		tlsCfg := p.ca.TLSConfig()
		p.setBound(true, ln.Addr().String())
		servers = append(servers, server{
			srv:  p.newServer(ctx, tlsCfg),
			ln:   tls.NewListener(ln, tlsCfg),
			addr: ln.Addr().String(),
		})
	}
	p.readyOnce.Do(func() { close(p.ready) })

	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func(s server) {
			err := s.srv.Serve(s.ln)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errc <- err
		}(s)
	}

	var serveErr error
	remaining := len(servers)
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
		remaining--
		if serveErr != nil {
			serveErr = fmt.Errorf("localproxy: serve: %w", serveErr)
		}
	}

	shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.grace)
	defer cancel()
	errs := []error{serveErr}
	for _, s := range servers {
		if err := s.srv.Shutdown(shutCtx); err != nil {
			errs = append(errs, fmt.Errorf("localproxy: shutdown %s: %w", s.addr, err))
		}
	}
	// Drain the goroutines that have not reported yet, so Run never leaks one.
	for i := 0; i < remaining; i++ {
		select {
		case err := <-errc:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, fmt.Errorf("localproxy: serve: %w", err))
			}
		case <-time.After(p.grace):
		}
	}
	return errors.Join(errs...)
}

func (p *Proxy) newServer(ctx context.Context, tlsCfg *tls.Config) *http.Server {
	return &http.Server{
		Handler:   p,
		TLSConfig: tlsCfg,
		// No WriteTimeout: it would cut off server-sent events and long-lived
		// WebSocket connections, which is the opposite of the point.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}
}

func (p *Proxy) setBound(https bool, addr string) {
	p.addrMu.Lock()
	defer p.addrMu.Unlock()
	if https {
		p.boundHTTPS = addr
	} else {
		p.boundHTTP = addr
	}
}

// ServeHTTP routes one request. See the package documentation for the order of
// the rules.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := normalizeHost(r.Host)
	if u, ok := p.resolveTarget(host); ok {
		p.rp.ServeHTTP(w, r.WithContext(contextWithTarget(r.Context(), u)))
		return
	}
	// A request to the bare domain ("http://localhost/") is not a mistake
	// worth a 404: it is somebody asking what hull is serving. Answer it.
	if host == p.domain {
		p.writeIndex(w, r)
		return
	}
	p.writeNotFound(w, r, host)
}

// rewrite is the ReverseProxy hook. It preserves the client's Host header so
// the upstream generates correct absolute URLs and virtual-host routing inside
// the container still works, and sets the standard forwarding headers.
func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	u, ok := targetFromContext(pr.In.Context())
	if !ok {
		// Unreachable: ServeHTTP is the only caller and it always sets the
		// target. Fail closed rather than proxying to nowhere.
		return
	}
	pr.SetURL(u)
	// SetXForwarded overwrites any inbound X-Forwarded-* rather than appending
	// to it, which is correct here: this proxy is the trust boundary, and a
	// client-supplied chain is a spoofing vector.
	pr.SetXForwarded()
	pr.Out.Host = pr.In.Host
	if pr.In.TLS != nil {
		pr.Out.Header.Set("X-Forwarded-Proto", "https")
	}
}

// proxyError turns an upstream failure into a page that says which name was
// asked for, which container address it resolved to, and what usually causes it.
func (p *Proxy) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	// A cancelled client is not an error worth a page.
	if errors.Is(err, context.Canceled) {
		return
	}
	host := normalizeHost(r.Host)
	target := "(unresolved)"
	if u, ok := targetFromContext(r.Context()); ok {
		target = u.String()
	}
	p.logf("localproxy: %s -> %s: %v", host, target, err)
	p.writeGatewayError(w, r, host, target, err)
}
