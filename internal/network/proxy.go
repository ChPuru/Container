package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Tunables for the userland proxy.
const (
	// UDPSessionIdle is how long a UDP flow may sit silent before its relay
	// socket is reclaimed.
	UDPSessionIdle = 60 * time.Second
	// udpReapInterval is how often idle UDP sessions are swept.
	udpReapInterval = 10 * time.Second
	// udpBufSize is the largest datagram the relay forwards. 64 KiB is the
	// maximum an IPv4 datagram can carry.
	udpBufSize = 65535
	// dialTimeout bounds the connection to the container.
	dialTimeout = 10 * time.Second
)

// PublishedPort is one host port hull has published for a container.
//
// hull always backs a published port with a *real listening socket in the root
// network namespace*, because WSL's NAT-mode localhost forwarding discovers
// ports by polling sock_diag for TCP sockets in LISTEN state there. A port
// published only with a DNAT rule is invisible from Windows. The nftables DNAT
// rule installed alongside covers LAN-originated traffic, which never reaches
// the userland listener.
type PublishedPort struct {
	// Proto is "tcp" or "udp".
	Proto string
	// HostIP is the address the proxy listens on, "0.0.0.0" for all.
	HostIP string
	// HostPort is the port actually bound, never 0 — an ephemeral request is
	// resolved to the port the kernel picked.
	HostPort int
	// ContainerPort is the port traffic is forwarded to.
	ContainerPort int
	// ContainerIP is the address traffic is forwarded to.
	ContainerIP string
	// ContainerID owns the publication.
	ContainerID string

	closer func() error
}

// String renders the publication the way `hull ps` prints it.
func (p PublishedPort) String() string {
	return fmt.Sprintf("%s:%d->%d/%s", p.HostIP, p.HostPort, p.ContainerPort, p.Proto)
}

// Close tears down the listening socket and every relayed connection. It is
// safe to call more than once.
func (p PublishedPort) Close() error {
	if p.closer == nil {
		return nil
	}
	return p.closer()
}

// listenAddr renders the socket address the proxy binds.
func listenAddr(hostIP string, port int) string {
	if hostIP == "" {
		hostIP = "0.0.0.0"
	}
	return net.JoinHostPort(hostIP, strconv.Itoa(port))
}

// ---------- TCP ----------

// tcpProxy accepts connections on a host port and relays each one to the
// container, full duplex, propagating a half-close in either direction so
// protocols that signal end-of-request with a FIN (HTTP/1.0, many RPCs) work.
type tcpProxy struct {
	ln     net.Listener
	target string

	closeOnce sync.Once
	closeErr  error
	done      chan struct{}

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

// newTCPProxy binds hostIP:hostPort and relays to target. A hostPort of 0 asks
// the kernel for an ephemeral port; Port reports what it got.
func newTCPProxy(ctx context.Context, hostIP string, hostPort int, target string) (*tcpProxy, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listenAddr(hostIP, hostPort))
	if err != nil {
		return nil, fmt.Errorf("network: listen tcp %s: %w", listenAddr(hostIP, hostPort), err)
	}
	p := &tcpProxy{
		ln:     ln,
		target: target,
		done:   make(chan struct{}),
		conns:  make(map[net.Conn]struct{}),
	}
	p.wg.Add(1)
	go func() { defer p.wg.Done(); p.serve() }()
	return p, nil
}

// Port returns the bound host port.
func (p *tcpProxy) Port() int {
	if a, ok := p.ln.Addr().(*net.TCPAddr); ok {
		return a.Port
	}
	return 0
}

// serve accepts until the listener is closed.
func (p *tcpProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.track(c)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.untrack(c)
			p.handle(c)
		}()
	}
}

// track records a live connection so Close can tear it down.
func (p *tcpProxy) track(c net.Conn) {
	p.mu.Lock()
	p.conns[c] = struct{}{}
	p.mu.Unlock()
}

// untrack forgets a connection that has finished.
func (p *tcpProxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

// handle relays one accepted connection to the container.
func (p *tcpProxy) handle(client net.Conn) {
	defer client.Close()
	d := net.Dialer{Timeout: dialTimeout}
	server, err := d.Dial("tcp", p.target)
	if err != nil {
		return
	}
	defer server.Close()
	p.track(server)
	defer p.untrack(server)
	pipeConns(client, server)
}

// Close stops accepting, drops every relayed connection and waits for the
// goroutines to exit.
func (p *tcpProxy) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)
		p.closeErr = p.ln.Close()
		p.mu.Lock()
		for c := range p.conns {
			_ = c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p.closeErr
}

// pipeConns copies bytes between two connections in both directions and returns
// once both halves are done.
//
// The half-close is the point: when the client stops sending, the container
// must see EOF on its socket while still being able to write its reply, so each
// direction ends with CloseWrite rather than a full Close. Connections that
// cannot half-close (net.Pipe, for example) are closed outright, which is the
// only correct approximation.
func pipeConns(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	wg.Wait()
}

// halfCloser is implemented by *net.TCPConn and *net.UnixConn.
type halfCloser interface{ CloseWrite() error }

// closeWrite shuts down the write half of c, falling back to a full close.
func closeWrite(c net.Conn) {
	if hc, ok := c.(halfCloser); ok {
		if err := hc.CloseWrite(); err == nil {
			return
		}
	}
	_ = c.Close()
}

// ---------- UDP ----------

// udpProxy relays datagrams between a host port and the container. UDP has no
// connections, so the relay keeps one socket per source address and reclaims it
// after UDPSessionIdle of silence; replies from the container are written back
// to the source that last used the session.
type udpProxy struct {
	pc     net.PacketConn
	target string
	idle   time.Duration

	closeOnce sync.Once
	closeErr  error
	done      chan struct{}

	mu       sync.Mutex
	sessions map[string]*udpSession
	wg       sync.WaitGroup
}

// udpSession is one source address's flow to the container.
type udpSession struct {
	conn net.Conn
	from net.Addr

	mu   sync.Mutex
	last time.Time
}

// touch records activity on a session.
func (s *udpSession) touch() {
	s.mu.Lock()
	s.last = time.Now()
	s.mu.Unlock()
}

// idleFor reports how long the session has been silent.
func (s *udpSession) idleFor(now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Sub(s.last)
}

// newUDPProxy binds hostIP:hostPort and relays datagrams to target.
func newUDPProxy(ctx context.Context, hostIP string, hostPort int, target string) (*udpProxy, error) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", listenAddr(hostIP, hostPort))
	if err != nil {
		return nil, fmt.Errorf("network: listen udp %s: %w", listenAddr(hostIP, hostPort), err)
	}
	p := &udpProxy{
		pc:       pc,
		target:   target,
		idle:     UDPSessionIdle,
		done:     make(chan struct{}),
		sessions: make(map[string]*udpSession),
	}
	p.wg.Add(2)
	go func() { defer p.wg.Done(); p.serve() }()
	go func() { defer p.wg.Done(); p.reap() }()
	return p, nil
}

// Port returns the bound host port.
func (p *udpProxy) Port() int {
	if a, ok := p.pc.LocalAddr().(*net.UDPAddr); ok {
		return a.Port
	}
	return 0
}

// serve reads datagrams from the host side until the socket closes.
func (p *udpProxy) serve() {
	buf := make([]byte, udpBufSize)
	for {
		n, from, err := p.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		s, err := p.session(from)
		if err != nil {
			continue
		}
		s.touch()
		if _, err := s.conn.Write(buf[:n]); err != nil {
			p.drop(from.String())
		}
	}
}

// session returns the relay socket for a source address, creating it on first
// sight and starting the reply pump.
func (p *udpProxy) session(from net.Addr) (*udpSession, error) {
	key := from.String()
	p.mu.Lock()
	if s, ok := p.sessions[key]; ok {
		p.mu.Unlock()
		return s, nil
	}
	p.mu.Unlock()

	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.Dial("udp", p.target)
	if err != nil {
		return nil, fmt.Errorf("network: udp relay dial %s: %w", p.target, err)
	}
	s := &udpSession{conn: conn, from: from, last: time.Now()}

	p.mu.Lock()
	if existing, ok := p.sessions[key]; ok { // lost the race
		p.mu.Unlock()
		conn.Close()
		return existing, nil
	}
	p.sessions[key] = s
	p.mu.Unlock()

	p.wg.Add(1)
	go func() { defer p.wg.Done(); p.pump(key, s) }()
	return s, nil
}

// pump copies replies from the container back to the originating address.
func (p *udpProxy) pump(key string, s *udpSession) {
	buf := make([]byte, udpBufSize)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(p.idle))
		n, err := s.conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && s.idleFor(time.Now()) < p.idle {
				continue
			}
			p.drop(key)
			return
		}
		s.touch()
		if _, err := p.pc.WriteTo(buf[:n], s.from); err != nil {
			p.drop(key)
			return
		}
	}
}

// drop closes and forgets one session.
func (p *udpProxy) drop(key string) {
	p.mu.Lock()
	s, ok := p.sessions[key]
	delete(p.sessions, key)
	p.mu.Unlock()
	if ok {
		_ = s.conn.Close()
	}
}

// reap closes sessions that have been silent for longer than the idle timeout.
func (p *udpProxy) reap() {
	t := time.NewTicker(udpReapInterval)
	defer t.Stop()
	for {
		select {
		case <-p.done:
			return
		case now := <-t.C:
			var stale []string
			p.mu.Lock()
			for k, s := range p.sessions {
				if s.idleFor(now) > p.idle {
					stale = append(stale, k)
				}
			}
			p.mu.Unlock()
			for _, k := range stale {
				p.drop(k)
			}
		}
	}
}

// Close stops the relay and closes every session socket.
func (p *udpProxy) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)
		p.closeErr = p.pc.Close()
		p.mu.Lock()
		for k, s := range p.sessions {
			_ = s.conn.Close()
			delete(p.sessions, k)
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p.closeErr
}

// startProxy binds a host port for one protocol and returns the bound port
// together with a closer. It is the single place that knows both transports.
func startProxy(ctx context.Context, proto, hostIP string, hostPort int, containerIP string, containerPort int) (int, func() error, error) {
	target := net.JoinHostPort(containerIP, strconv.Itoa(containerPort))
	switch proto {
	case "tcp":
		p, err := newTCPProxy(ctx, hostIP, hostPort, target)
		if err != nil {
			return 0, nil, err
		}
		return p.Port(), p.Close, nil
	case "udp":
		p, err := newUDPProxy(ctx, hostIP, hostPort, target)
		if err != nil {
			return 0, nil, err
		}
		return p.Port(), p.Close, nil
	case "sctp":
		return 0, nil, fmt.Errorf("%w: publishing sctp ports is not implemented; "+
			"the WSL localhost relay only tracks tcp sockets anyway", ErrUnsupported)
	default:
		return 0, nil, fmt.Errorf("%w: unknown protocol %q", ErrInvalidConfig, proto)
	}
}
