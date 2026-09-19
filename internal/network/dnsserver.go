package network

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defaults for the embedded DNS server.
const (
	// DefaultDNSTTL is the TTL hull puts on the records it generates itself.
	// It is short because a container's address changes whenever it restarts.
	DefaultDNSTTL uint32 = 30
	// DefaultUpstreamTimeout bounds a single forwarded query.
	DefaultUpstreamTimeout = 5 * time.Second
	// DefaultMaxUpstreams is how many upstream resolvers are queried in
	// parallel. Racing three covers a dead resolver without amplifying load.
	DefaultMaxUpstreams = 3

	minCacheTTL     = 5 * time.Second
	maxCacheTTL     = time.Hour
	negativeTTL     = 30 * time.Second
	maxNegativeTTL  = 5 * time.Minute
	tcpQueryTimeout = 10 * time.Second
	maxUDPRead      = 4096
	maxTCPMessage   = 65535
)

// hostGatewayNames are the pseudo-names that resolve to the bridge gateway,
// which on WSL is also the route to the Windows host. The docker.internal
// spellings are included because published images and dev-container templates
// hard-code them.
var hostGatewayNames = []string{
	"host." + InternalDomain,
	"gateway." + InternalDomain,
	"host.docker.internal",
	"gateway.docker.internal",
	"host-gateway",
}

// Registry is the endpoint table the DNS server answers from. Manager
// implements it; tests substitute a fake.
type Registry interface {
	// NetworksForSource returns the IDs of the networks the querying address is
	// attached to and the gateway address serving it. An unknown source yields
	// no networks and a nil gateway, which makes the server answer only the
	// host pseudo-names and forward everything else.
	NetworksForSource(src net.IP) (networks []string, gateway net.IP)

	// LookupName returns every address registered for name (a bare, lowercase
	// name with no trailing dot) within the given networks, in a stable order.
	LookupName(name string, networks []string) []net.IP

	// LookupAddr returns the canonical bare name registered for addr, or "".
	LookupAddr(addr net.IP) string
}

// DNSOptions configures a DNSServer. The zero value is valid and uses the
// documented defaults.
type DNSOptions struct {
	// Port is the UDP and TCP port to bind on each gateway address.
	Port int
	// Domain is the internal search domain, defaulting to InternalDomain.
	Domain string
	// Search is the list of suffixes stripped before an internal lookup, so a
	// resolver that appends a search domain still finds a container.
	Search []string
	// Upstreams are "ip:port" resolvers for names hull does not own. When
	// empty they are read from ResolvConfPath.
	Upstreams []string
	// ResolvConfPath is where the host's resolvers are read from.
	ResolvConfPath string
	// Timeout bounds one forwarded query.
	Timeout time.Duration
	// MaxUpstreams caps how many resolvers are raced.
	MaxUpstreams int
	// TTL is the TTL of locally generated records.
	TTL uint32
}

// DNSServer is hull's embedded resolver. It binds UDP and TCP on each bridge
// gateway address — never on 0.0.0.0, because Docker Desktop may already hold
// :53 on other addresses in the shared WSL VM — answers for container names,
// aliases and the host pseudo-names, and forwards everything else to the host's
// upstream resolvers with a small TTL-honouring cache.
//
// A DNSServer is safe for concurrent use.
type DNSServer struct {
	opts DNSOptions
	reg  Registry

	mu        sync.RWMutex
	listeners map[string]*dnsListener
	selfAddrs map[string]struct{}
	upstreams []string

	cache *dnsCache
}

// dnsListener is one bound gateway address.
type dnsListener struct {
	addr   string
	pc     net.PacketConn
	ln     net.Listener
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDNSServer builds a resolver over reg. It does not bind anything; call
// Listen once per bridge gateway.
func NewDNSServer(reg Registry, opts DNSOptions) *DNSServer {
	if opts.Port == 0 {
		opts.Port = DefaultDNSPort
	}
	if opts.Domain == "" {
		opts.Domain = InternalDomain
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultUpstreamTimeout
	}
	if opts.MaxUpstreams <= 0 {
		opts.MaxUpstreams = DefaultMaxUpstreams
	}
	if opts.TTL == 0 {
		opts.TTL = DefaultDNSTTL
	}
	if opts.ResolvConfPath == "" {
		opts.ResolvConfPath = "/etc/resolv.conf"
	}
	s := &DNSServer{
		opts:      opts,
		reg:       reg,
		listeners: make(map[string]*dnsListener),
		selfAddrs: make(map[string]struct{}),
		cache:     newDNSCache(),
	}
	s.upstreams = normaliseUpstreams(opts.Upstreams)
	return s
}

// Port returns the port the server binds on every gateway address.
func (s *DNSServer) Port() int { return s.opts.Port }

// Upstreams returns the resolvers hull forwards to.
func (s *DNSServer) Upstreams() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.upstreams...)
}

// SetUpstreams replaces the forwarding resolvers. Addresses without a port get
// :53. Any address hull is itself listening on is dropped, because forwarding
// to ourselves is an infinite loop, not a fallback.
func (s *DNSServer) SetUpstreams(list []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstreams = normaliseUpstreams(list)
}

// LoadUpstreamsFromResolvConf reads the host's resolvers and installs them. It
// is how hull picks up WSL's 10.255.255.254 without hard-coding it.
func (s *DNSServer) LoadUpstreamsFromResolvConf() error {
	rc, err := ParseResolvConf(s.opts.ResolvConfPath)
	if err != nil {
		return err
	}
	if len(rc.Nameservers) == 0 {
		return fmt.Errorf("network: %s lists no nameserver: hull cannot forward DNS. "+
			"Set generateResolvConf=true in /etc/wsl.conf or pass --dns", s.opts.ResolvConfPath)
	}
	s.SetUpstreams(rc.Nameservers)
	return nil
}

// Addrs returns the gateway addresses the server is currently bound to.
func (s *DNSServer) Addrs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.listeners))
	for a := range s.listeners {
		out = append(out, a)
	}
	return out
}

// Listen binds UDP and TCP on ip:Port and serves until Stop or Shutdown. It is
// idempotent: binding an address that is already served is a no-op.
func (s *DNSServer) Listen(ctx context.Context, ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("%w: nil DNS listen address", ErrInvalidConfig)
	}
	key := ip.String()
	s.mu.Lock()
	if _, ok := s.listeners[key]; ok {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	addr := net.JoinHostPort(key, strconv.Itoa(s.opts.Port))
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return fmt.Errorf("network: bind DNS udp %s: %w", addr, err)
	}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		pc.Close()
		return fmt.Errorf("network: bind DNS tcp %s: %w", addr, err)
	}

	lctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	l := &dnsListener{addr: key, pc: pc, ln: ln, cancel: cancel}

	s.mu.Lock()
	s.listeners[key] = l
	s.selfAddrs[key] = struct{}{}
	s.upstreams = s.filterSelfLocked(s.upstreams)
	s.mu.Unlock()

	l.wg.Add(2)
	go func() { defer l.wg.Done(); s.serveUDP(lctx, pc) }()
	go func() { defer l.wg.Done(); s.serveTCP(lctx, ln) }()
	return nil
}

// Stop unbinds one gateway address and waits for its handlers to finish.
func (s *DNSServer) Stop(ip net.IP) error {
	if ip == nil {
		return nil
	}
	key := ip.String()
	s.mu.Lock()
	l, ok := s.listeners[key]
	delete(s.listeners, key)
	delete(s.selfAddrs, key)
	s.mu.Unlock()
	if !ok {
		return nil
	}
	return l.close()
}

// Shutdown unbinds every address.
func (s *DNSServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	ls := make([]*dnsListener, 0, len(s.listeners))
	for k, l := range s.listeners {
		ls = append(ls, l)
		delete(s.listeners, k)
		delete(s.selfAddrs, k)
	}
	s.mu.Unlock()
	var firstErr error
	for _, l := range ls {
		if err := l.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// close shuts one listener down and waits for its goroutines.
func (l *dnsListener) close() error {
	l.cancel()
	err1 := l.pc.Close()
	err2 := l.ln.Close()
	l.wg.Wait()
	if err1 != nil {
		return fmt.Errorf("network: close DNS udp %s: %w", l.addr, err1)
	}
	if err2 != nil {
		return fmt.Errorf("network: close DNS tcp %s: %w", l.addr, err2)
	}
	return nil
}

// filterSelfLocked drops upstreams that point at one of our own listeners.
// The caller must hold s.mu.
func (s *DNSServer) filterSelfLocked(list []string) []string {
	out := list[:0:0]
	for _, u := range list {
		host, _, err := net.SplitHostPort(u)
		if err != nil {
			continue
		}
		if _, self := s.selfAddrs[host]; self {
			continue
		}
		out = append(out, u)
	}
	return out
}

// serveUDP reads queries until the connection is closed.
func (s *DNSServer) serveUDP(ctx context.Context, pc net.PacketConn) {
	buf := make([]byte, maxUDPRead)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		src := addrIP(from)
		go func() {
			limit := MinUDPSize
			if m, perr := ParseMessage(q); perr == nil {
				if opt := findOPT(m.Additional); opt != nil && int(opt.Class) > limit {
					limit = min(int(opt.Class), maxUDPRead)
				}
			}
			resp, err := s.Exchange(ctx, q, src, limit)
			if err != nil || len(resp) == 0 {
				return
			}
			_ = pc.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = pc.WriteTo(resp, from)
		}()
	}
}

// serveTCP accepts length-prefixed queries until the listener is closed.
func (s *DNSServer) serveTCP(ctx context.Context, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleTCP(ctx, c)
	}
}

// handleTCP serves one TCP connection, which may carry several queries.
func (s *DNSServer) handleTCP(ctx context.Context, c net.Conn) {
	defer c.Close()
	src := addrIP(c.RemoteAddr())
	var lenBuf [2]byte
	for {
		if err := c.SetDeadline(time.Now().Add(tcpQueryTimeout)); err != nil {
			return
		}
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		q := make([]byte, n)
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp, err := s.Exchange(ctx, q, src, 0)
		if err != nil || len(resp) == 0 {
			return
		}
		out := make([]byte, 2, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		out = append(out, resp...)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

// Exchange answers one raw DNS query on behalf of src and returns the raw
// response. udpLimit, when positive, is the largest response the transport can
// carry: a longer answer is emptied and marked truncated so the client retries
// over TCP. It is exported because it is the whole server logic with no
// sockets, which is what the unit tests drive.
func (s *DNSServer) Exchange(ctx context.Context, query []byte, src net.IP, udpLimit int) ([]byte, error) {
	m, err := ParseMessage(query)
	if err != nil {
		if len(query) >= 2 {
			return s.errorResponse(binary.BigEndian.Uint16(query[0:2]), Question{}, RcodeFormatError, nil)
		}
		return nil, err
	}
	if m.Header.Response {
		return nil, fmt.Errorf("%w: query has the response bit set", ErrBadMessage)
	}

	reqOPT := findOPT(m.Additional)
	if m.Header.Opcode != 0 || len(m.Questions) != 1 {
		return s.errorResponse(m.Header.ID, Question{}, RcodeNotImplemented, reqOPT)
	}
	q := m.Questions[0]
	if q.Class != ClassINET && q.Class != TypeANY {
		return s.errorResponse(m.Header.ID, q, RcodeRefused, reqOPT)
	}

	resp := &Message{
		Header: Header{
			ID:                 m.Header.ID,
			Response:           true,
			RecursionDesired:   m.Header.RecursionDesired,
			RecursionAvailable: true,
			Rcode:              RcodeSuccess,
		},
		Questions: []Question{q},
	}

	answers, known := s.localAnswer(q, src)
	switch {
	case known:
		resp.Header.Authoritative = true
		resp.Answers = answers
	default:
		fwd, err := s.forward(ctx, q)
		switch {
		case err != nil:
			resp.Header.Rcode = RcodeServerFailure
		default:
			resp.Header.Rcode = fwd.Header.Rcode
			resp.Answers = fwd.Answers
			resp.Authority = fwd.Authority
			resp.Additional = filterOPT(fwd.Additional)
		}
	}

	if reqOPT != nil {
		resp.Additional = append(resp.Additional, optRecord(EDNSUDPSize))
	}
	return packLimited(resp, udpLimit)
}

// packLimited packs a response, degrading to a truncated empty answer when it
// does not fit the transport's limit.
func packLimited(resp *Message, udpLimit int) ([]byte, error) {
	out, err := resp.Pack()
	if err != nil {
		return nil, err
	}
	if udpLimit <= 0 || len(out) <= udpLimit {
		return out, nil
	}
	trunc := &Message{Header: resp.Header, Questions: resp.Questions}
	trunc.Header.Truncated = true
	if opt := findOPT(resp.Additional); opt != nil {
		trunc.Additional = []ResourceRecord{*opt}
	}
	return trunc.Pack()
}

// errorResponse packs a bare response carrying only an rcode.
func (s *DNSServer) errorResponse(id uint16, q Question, rcode uint8, reqOPT *ResourceRecord) ([]byte, error) {
	resp := &Message{Header: Header{
		ID: id, Response: true, RecursionAvailable: true, Rcode: rcode,
	}}
	if q.Name != "" {
		resp.Questions = []Question{q}
	}
	if reqOPT != nil {
		resp.Additional = append(resp.Additional, optRecord(EDNSUDPSize))
	}
	return resp.Pack()
}

// localAnswer resolves a question against the endpoint table and the host
// pseudo-names. It reports known=true when hull owns the name, even if that
// means returning an empty answer set for the wrong record type — an existing
// name with no AAAA is NOERROR, not NXDOMAIN.
func (s *DNSServer) localAnswer(q Question, src net.IP) (rrs []ResourceRecord, known bool) {
	name := canonicalName(q.Name)
	bare := strings.ToLower(trimName(name))

	networks, gateway := s.reg.NetworksForSource(src)

	// PTR for an address hull handed out, or for the gateway itself.
	if q.Type == TypePTR || q.Type == TypeANY {
		if ip := parseReverseName(bare); ip != nil {
			if gateway != nil && ip.Equal(gateway) {
				if rr, err := ptrRecord(name, s.opts.TTL, canonicalName("host."+s.opts.Domain)); err == nil {
					return []ResourceRecord{rr}, true
				}
			}
			if target := s.reg.LookupAddr(ip); target != "" {
				if rr, err := ptrRecord(name, s.opts.TTL, canonicalName(target+"."+s.opts.Domain)); err == nil {
					return []ResourceRecord{rr}, true
				}
			}
			return nil, false
		}
	}

	if isHostGatewayName(bare) {
		if gateway == nil {
			return nil, false
		}
		return s.addrAnswers(name, q.Type, []net.IP{gateway}), true
	}

	for _, cand := range s.candidates(bare) {
		if ips := s.reg.LookupName(cand, networks); len(ips) > 0 {
			return s.addrAnswers(name, q.Type, ips), true
		}
	}
	return nil, false
}

// candidates returns the names to try for a query, in order: the name as asked
// and then the name with any configured search suffix removed, so a resolver
// that appended "svc.example.com" still finds the container "web".
func (s *DNSServer) candidates(bare string) []string {
	if bare == "" {
		return nil
	}
	out := []string{bare}
	suffixes := append([]string{s.opts.Domain}, s.opts.Search...)
	for _, suf := range suffixes {
		suf = strings.ToLower(strings.Trim(suf, "."))
		if suf == "" {
			continue
		}
		if strings.HasSuffix(bare, "."+suf) {
			if stripped := strings.TrimSuffix(bare, "."+suf); stripped != "" {
				out = append(out, stripped)
			}
		}
	}
	return out
}

// addrAnswers renders addresses as A or AAAA records for the asked type.
func (s *DNSServer) addrAnswers(name string, qtype uint16, ips []net.IP) []ResourceRecord {
	var out []ResourceRecord
	for _, ip := range ips {
		isV4 := ip.To4() != nil
		switch {
		case isV4 && (qtype == TypeA || qtype == TypeANY):
			if rr, err := aRecord(name, s.opts.TTL, ip); err == nil {
				out = append(out, rr)
			}
		case !isV4 && (qtype == TypeAAAA || qtype == TypeANY):
			if rr, err := aaaaRecord(name, s.opts.TTL, ip); err == nil {
				out = append(out, rr)
			}
		}
	}
	return out
}

// isHostGatewayName reports whether a bare name is one of the pseudo-names that
// point at the bridge gateway.
func isHostGatewayName(bare string) bool {
	for _, n := range hostGatewayNames {
		if bare == n {
			return true
		}
	}
	return false
}

// filterOPT strips OPT records from a section; hull emits its own.
func filterOPT(rrs []ResourceRecord) []ResourceRecord {
	var out []ResourceRecord
	for _, rr := range rrs {
		if rr.Type != TypeOPT {
			out = append(out, rr)
		}
	}
	return out
}

// forward resolves a question through the upstream resolvers, consulting and
// populating the cache. Up to MaxUpstreams resolvers are queried in parallel
// and the first usable answer wins.
func (s *DNSServer) forward(ctx context.Context, q Question) (*Message, error) {
	if hit, ok := s.cache.get(q); ok {
		return hit, nil
	}
	s.mu.RLock()
	ups := append([]string(nil), s.upstreams...)
	s.mu.RUnlock()
	if len(ups) == 0 {
		return nil, fmt.Errorf("network: no upstream DNS resolver configured for %s", q.Name)
	}
	if len(ups) > s.opts.MaxUpstreams {
		ups = ups[:s.opts.MaxUpstreams]
	}

	ctx, cancel := context.WithTimeout(ctx, s.opts.Timeout)
	defer cancel()

	type result struct {
		server string
		msg    *Message
		err    error
	}
	results := make(chan result, len(ups))
	for _, up := range ups {
		go func(up string) {
			m, err := queryUpstream(ctx, up, q)
			results <- result{up, m, err}
		}(up)
	}

	var lastErr error
	for i := 0; i < len(ups); i++ {
		select {
		case r := <-results:
			if r.err != nil {
				lastErr = r.err
				continue
			}
			if r.msg.Header.Rcode == RcodeSuccess || r.msg.Header.Rcode == RcodeNameError {
				s.cache.put(q, r.msg)
				return r.msg, nil
			}
			lastErr = fmt.Errorf("network: upstream %s returned rcode %d for %s", r.server, r.msg.Header.Rcode, q.Name)
		case <-ctx.Done():
			return nil, fmt.Errorf("network: upstream DNS for %s: %w", q.Name, ctx.Err())
		}
	}
	if lastErr == nil {
		lastErr = errors.New("network: no upstream answered")
	}
	return nil, lastErr
}

// queryUpstream sends one question to one resolver over UDP, retrying over TCP
// when the answer comes back truncated.
func queryUpstream(ctx context.Context, server string, q Question) (*Message, error) {
	req := &Message{
		Header:    Header{ID: randomID(), RecursionDesired: true},
		Questions: []Question{q},
		Additional: []ResourceRecord{
			optRecord(EDNSUDPSize),
		},
	}
	wire, err := req.Pack()
	if err != nil {
		return nil, err
	}

	resp, err := exchangeUpstream(ctx, "udp", server, wire, maxUDPRead)
	if err != nil {
		return nil, err
	}
	if resp.Header.Truncated {
		if tcpResp, tcpErr := exchangeUpstream(ctx, "tcp", server, wire, maxTCPMessage); tcpErr == nil {
			resp = tcpResp
		}
	}
	if resp.Header.ID != req.Header.ID {
		return nil, fmt.Errorf("network: upstream %s replied with id %d, wanted %d",
			server, resp.Header.ID, req.Header.ID)
	}
	return resp, nil
}

// exchangeUpstream performs one transport-level exchange with a resolver.
func exchangeUpstream(ctx context.Context, network, server string, wire []byte, limit int) (*Message, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, fmt.Errorf("network: dial %s %s: %w", network, server, err)
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}

	if network == "tcp" {
		out := make([]byte, 2, 2+len(wire))
		binary.BigEndian.PutUint16(out, uint16(len(wire)))
		out = append(out, wire...)
		if _, err := c.Write(out); err != nil {
			return nil, fmt.Errorf("network: write to %s: %w", server, err)
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			return nil, fmt.Errorf("network: read from %s: %w", server, err)
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		buf := make([]byte, n)
		if _, err := io.ReadFull(c, buf); err != nil {
			return nil, fmt.Errorf("network: read from %s: %w", server, err)
		}
		return ParseMessage(buf)
	}

	if _, err := c.Write(wire); err != nil {
		return nil, fmt.Errorf("network: write to %s: %w", server, err)
	}
	buf := make([]byte, limit)
	n, err := c.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("network: read from %s: %w", server, err)
	}
	return ParseMessage(buf[:n])
}

// randomID draws a query identifier from crypto/rand, falling back to a
// nanosecond timestamp if the entropy source fails.
func randomID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}

// addrIP extracts the IP from a net.Addr, returning nil for anything else.
func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// ---------- cache ----------

// dnsCache is a small TTL-honouring cache of forwarded answers, positive and
// negative. It is intentionally unbounded in time but bounded in size: DNS
// answers are tiny and a container host asks for very few distinct names.
type dnsCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	maxSize int
}

type cacheEntry struct {
	msg     *Message
	stored  time.Time
	expires time.Time
}

// newDNSCache builds an empty cache.
func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[string]*cacheEntry), maxSize: 2048}
}

// cacheKey identifies a question.
func cacheKey(q Question) string {
	return strings.ToLower(canonicalName(q.Name)) + "|" +
		strconv.Itoa(int(q.Type)) + "|" + strconv.Itoa(int(q.Class))
}

// get returns a cached answer with TTLs aged by the time it has been held.
func (c *dnsCache) get(q Question) (*Message, bool) {
	key := cacheKey(q)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	now := time.Now()
	if now.After(e.expires) {
		delete(c.entries, key)
		return nil, false
	}
	aged := uint32(now.Sub(e.stored) / time.Second)
	return copyMessageAged(e.msg, aged), true
}

// put stores an answer for the smaller of its TTLs, clamped into a sane range.
func (c *dnsCache) put(q Question, m *Message) {
	ttl := messageTTL(m)
	if ttl <= 0 {
		return
	}
	key := cacheKey(q)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		for k, e := range c.entries {
			if now.After(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.maxSize {
			for k := range c.entries { // drop an arbitrary entry to make room
				delete(c.entries, k)
				break
			}
		}
	}
	c.entries[key] = &cacheEntry{msg: copyMessageAged(m, 0), stored: now, expires: now.Add(ttl)}
}

// messageTTL returns how long an answer may be cached: the smallest record TTL
// for a positive answer, the SOA minimum for a negative one.
func messageTTL(m *Message) time.Duration {
	if m.Header.Rcode == RcodeNameError || len(m.Answers) == 0 {
		ttl := negativeTTL
		for _, rr := range m.Authority {
			if rr.Type == TypeSOA && len(rr.Data) >= 4 {
				min := time.Duration(binary.BigEndian.Uint32(rr.Data[len(rr.Data)-4:])) * time.Second
				if min > 0 && min < ttl {
					ttl = min
				}
			}
		}
		if ttl > maxNegativeTTL {
			ttl = maxNegativeTTL
		}
		return ttl
	}
	best := time.Duration(1<<62 - 1)
	for _, section := range [][]ResourceRecord{m.Answers, m.Authority} {
		for _, rr := range section {
			if rr.Type == TypeOPT {
				continue
			}
			d := time.Duration(rr.TTL) * time.Second
			if d < best {
				best = d
			}
		}
	}
	if best < minCacheTTL {
		best = minCacheTTL
	}
	if best > maxCacheTTL {
		best = maxCacheTTL
	}
	return best
}

// copyMessageAged deep-copies a message, subtracting aged seconds from every
// TTL so a cached answer does not keep resetting a client's own timers.
func copyMessageAged(m *Message, aged uint32) *Message {
	out := &Message{Header: m.Header, Questions: append([]Question(nil), m.Questions...)}
	cp := func(in []ResourceRecord) []ResourceRecord {
		if len(in) == 0 {
			return nil
		}
		o := make([]ResourceRecord, len(in))
		for i, rr := range in {
			rr.Data = append([]byte(nil), rr.Data...)
			if rr.Type != TypeOPT {
				if rr.TTL > aged {
					rr.TTL -= aged
				} else {
					rr.TTL = 1
				}
			}
			o[i] = rr
		}
		return o
	}
	out.Answers = cp(m.Answers)
	out.Authority = cp(m.Authority)
	out.Additional = cp(m.Additional)
	return out
}

// ---------- resolv.conf ----------

// ResolvConf is the subset of resolver configuration hull reads and writes.
type ResolvConf struct {
	// Nameservers are "ip:port" upstream resolvers, in file order.
	Nameservers []string
	// Search is the search domain list.
	Search []string
	// NDots is the ndots option, or 0 when unset.
	NDots int
	// Options are the remaining resolver options, verbatim.
	Options []string
}

// ParseResolvConf reads a resolv.conf-formatted file. On WSL the generated file
// names the VM's NAT gateway, usually 10.255.255.254.
func ParseResolvConf(path string) (*ResolvConf, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("network: open %s: %w", path, err)
	}
	defer f.Close()
	return parseResolvConf(f), nil
}

// parseResolvConf does the parsing, split out so tests need no file.
func parseResolvConf(r io.Reader) *ResolvConf {
	rc := &ResolvConf{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "nameserver":
			if ip := net.ParseIP(fields[1]); ip != nil {
				rc.Nameservers = append(rc.Nameservers, net.JoinHostPort(ip.String(), "53"))
			}
		case "search", "domain":
			rc.Search = append(rc.Search, fields[1:]...)
		case "options":
			for _, o := range fields[1:] {
				if v, ok := strings.CutPrefix(o, "ndots:"); ok {
					if n, err := strconv.Atoi(v); err == nil {
						rc.NDots = n
						continue
					}
				}
				rc.Options = append(rc.Options, o)
			}
		}
	}
	return rc
}

// normaliseUpstreams adds the default port to bare addresses and drops anything
// unparsable, so a mangled resolv.conf degrades to "fewer resolvers" rather
// than a dial to a nonsense address on every query.
func normaliseUpstreams(list []string) []string {
	out := make([]string, 0, len(list))
	seen := make(map[string]struct{}, len(list))
	for _, u := range list {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(u); err != nil {
			if ip := net.ParseIP(u); ip != nil {
				u = net.JoinHostPort(ip.String(), strconv.Itoa(DefaultDNSPort))
			} else {
				continue
			}
		}
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}
