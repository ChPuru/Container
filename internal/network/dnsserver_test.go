package network

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRegistry is a stand-in endpoint table for the resolver tests.
type fakeRegistry struct {
	// sources maps a querying address to the networks it can resolve on.
	sources map[string][]string
	// gateways maps a querying address to the gateway serving it.
	gateways map[string]string
	// names maps "network|name" to the addresses registered for it.
	names map[string][]string
	// ptr maps an address to its canonical name.
	ptr map[string]string
}

func (f *fakeRegistry) NetworksForSource(src net.IP) ([]string, net.IP) {
	if src == nil {
		return nil, nil
	}
	return f.sources[src.String()], net.ParseIP(f.gateways[src.String()])
}

func (f *fakeRegistry) LookupName(name string, networks []string) []net.IP {
	var out []net.IP
	for _, n := range networks {
		for _, s := range f.names[n+"|"+name] {
			out = append(out, net.ParseIP(s))
		}
	}
	return out
}

func (f *fakeRegistry) LookupAddr(addr net.IP) string {
	if addr == nil {
		return ""
	}
	return f.ptr[addr.String()]
}

// testRegistry builds a two-network table: "frontend" holds web and db,
// "isolated" holds a container that shares the name "web".
func testRegistry() *fakeRegistry {
	return &fakeRegistry{
		sources: map[string][]string{
			"10.66.0.2": {"frontend"},
			"10.66.0.3": {"frontend"},
			"10.66.1.2": {"isolated"},
		},
		gateways: map[string]string{
			"10.66.0.2": "10.66.0.1",
			"10.66.0.3": "10.66.0.1",
			"10.66.1.2": "10.66.1.1",
		},
		names: map[string][]string{
			"frontend|web":          {"10.66.0.2"},
			"frontend|web.frontend": {"10.66.0.2"},
			"frontend|api":          {"10.66.0.2"}, // an alias for the same container
			"frontend|db":           {"10.66.0.3"},
			"frontend|a1b2c3d4e5f6": {"10.66.0.3"},
			"isolated|web":          {"10.66.1.2"},
			"frontend|v6":           {"fd00::2"},
		},
		ptr: map[string]string{
			"10.66.0.2": "web",
			"10.66.0.3": "db",
		},
	}
}

// ask packs a query, runs it through the server and parses the reply.
func ask(t *testing.T, s *DNSServer, src, name string, qtype uint16, edns bool) *Message {
	t.Helper()
	q := &Message{
		Header:    Header{ID: 0x4242, RecursionDesired: true},
		Questions: []Question{{Name: canonicalName(name), Type: qtype, Class: ClassINET}},
	}
	if edns {
		q.Additional = append(q.Additional, optRecord(4096))
	}
	wire, err := q.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	raw, err := s.Exchange(context.Background(), wire, net.ParseIP(src), 0)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	resp, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Header.ID != q.Header.ID {
		t.Fatalf("response id = %#x, want %#x", resp.Header.ID, q.Header.ID)
	}
	if !resp.Header.Response {
		t.Fatal("QR bit not set on the response")
	}
	if !resp.Header.RecursionAvailable {
		t.Fatal("RA bit must be set: musl and glibc both look at it")
	}
	return resp
}

// answerIPs extracts the addresses from an answer section.
func answerIPs(m *Message) []string {
	var out []string
	for _, rr := range m.Answers {
		if ip := rdataIP(rr); ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

func newTestDNS(t *testing.T, reg Registry) *DNSServer {
	t.Helper()
	return NewDNSServer(reg, DNSOptions{Port: 0, TTL: 30, Timeout: 100 * time.Millisecond})
}

func TestDNSResolvesContainerNamesScopedToTheSourceNetwork(t *testing.T) {
	s := newTestDNS(t, testRegistry())

	tests := []struct {
		name  string
		src   string
		query string
		qtype uint16
		want  []string
	}{
		{"container name", "10.66.0.2", "db", TypeA, []string{"10.66.0.3"}},
		{"alias", "10.66.0.3", "api", TypeA, []string{"10.66.0.2"}},
		{"network-qualified name", "10.66.0.3", "web.frontend", TypeA, []string{"10.66.0.2"}},
		{"short container id", "10.66.0.2", "a1b2c3d4e5f6", TypeA, []string{"10.66.0.3"}},
		{"case insensitive", "10.66.0.2", "DB", TypeA, []string{"10.66.0.3"}},
		{"same name on another network", "10.66.1.2", "web", TypeA, []string{"10.66.1.2"}},
		{"host pseudo-name", "10.66.0.2", "host.hull.internal", TypeA, []string{"10.66.0.1"}},
		{"docker pseudo-name", "10.66.0.2", "host.docker.internal", TypeA, []string{"10.66.0.1"}},
		{"gateway pseudo-name", "10.66.1.2", "gateway.hull.internal", TypeA, []string{"10.66.1.1"}},
		{"ipv6 record", "10.66.0.2", "v6", TypeAAAA, []string{"fd00::2"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := ask(t, s, tc.src, tc.query, tc.qtype, false)
			if resp.Header.Rcode != RcodeSuccess {
				t.Fatalf("rcode = %d, want NOERROR", resp.Header.Rcode)
			}
			if !resp.Header.Authoritative {
				t.Fatal("a locally owned name must be answered authoritatively")
			}
			got := answerIPs(resp)
			if len(got) != len(tc.want) {
				t.Fatalf("answers = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("answers = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestDNSDoesNotLeakNamesAcrossNetworks(t *testing.T) {
	s := newTestDNS(t, testRegistry())
	// "db" only exists on frontend; a container on "isolated" must not see it.
	// With no upstreams configured the forward fails, which is SERVFAIL, but
	// the important part is that no address leaks.
	resp := ask(t, s, "10.66.1.2", "db", TypeA, false)
	if len(resp.Answers) != 0 {
		t.Fatalf("db leaked across networks: %v", answerIPs(resp))
	}
}

func TestDNSReturnsNXDOMAINNotEmptyNOERROR(t *testing.T) {
	// musl retries forever against an empty NOERROR, so an unknown name that
	// the upstream says does not exist must come back as NXDOMAIN.
	up := startFakeUpstream(t, func(q *Message) *Message {
		resp := &Message{
			Header:    Header{ID: q.Header.ID, Response: true, RecursionAvailable: true, Rcode: RcodeNameError},
			Questions: q.Questions,
		}
		return resp
	})
	s := NewDNSServer(testRegistry(), DNSOptions{
		Port: 0, TTL: 30, Upstreams: []string{up}, Timeout: 2 * time.Second,
	})
	resp := ask(t, s, "10.66.0.2", "nope.example.com", TypeA, false)
	if resp.Header.Rcode != RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN (%d)", resp.Header.Rcode, RcodeNameError)
	}
}

func TestDNSForwardsAndCachesUpstreamAnswers(t *testing.T) {
	var calls atomic.Int32
	up := startFakeUpstream(t, func(q *Message) *Message {
		calls.Add(1)
		rr, _ := aRecord(q.Questions[0].Name, 300, net.ParseIP("93.184.216.34"))
		return &Message{
			Header:    Header{ID: q.Header.ID, Response: true, RecursionAvailable: true},
			Questions: q.Questions,
			Answers:   []ResourceRecord{rr},
		}
	})
	s := NewDNSServer(testRegistry(), DNSOptions{
		Port: 0, TTL: 30, Upstreams: []string{up}, Timeout: 2 * time.Second,
	})
	for i := 0; i < 3; i++ {
		resp := ask(t, s, "10.66.0.2", "example.com", TypeA, false)
		if got := answerIPs(resp); len(got) != 1 || got[0] != "93.184.216.34" {
			t.Fatalf("answers = %v", got)
		}
		if resp.Header.Authoritative {
			t.Fatal("a forwarded answer must not claim authority")
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("upstream called %d times, want 1 (the cache should have served the rest)", n)
	}
}

func TestDNSEchoesEDNS0(t *testing.T) {
	s := newTestDNS(t, testRegistry())
	resp := ask(t, s, "10.66.0.2", "db", TypeA, true)
	opt := findOPT(resp.Additional)
	if opt == nil {
		t.Fatal("no OPT record in the response to an EDNS0 query")
	}
	if opt.Class != EDNSUDPSize {
		t.Fatalf("advertised buffer = %d, want %d", opt.Class, EDNSUDPSize)
	}

	plain := ask(t, s, "10.66.0.2", "db", TypeA, false)
	if findOPT(plain.Additional) != nil {
		t.Fatal("a non-EDNS query must not get an OPT record back")
	}
}

func TestDNSReverseLookup(t *testing.T) {
	s := newTestDNS(t, testRegistry())
	resp := ask(t, s, "10.66.0.2", "3.0.66.10.in-addr.arpa", TypePTR, false)
	if resp.Header.Rcode != RcodeSuccess || len(resp.Answers) != 1 {
		t.Fatalf("PTR lookup failed: rcode %d, %d answers", resp.Header.Rcode, len(resp.Answers))
	}
	want, err := packName(nil, "db.hull.internal.")
	if err != nil {
		t.Fatalf("packName: %v", err)
	}
	if string(resp.Answers[0].Data) != string(want) {
		t.Fatalf("PTR target = % x, want % x", resp.Answers[0].Data, want)
	}

	gw := ask(t, s, "10.66.0.2", "1.0.66.10.in-addr.arpa", TypePTR, false)
	if len(gw.Answers) != 1 {
		t.Fatalf("the gateway should reverse to host.hull.internal, got %d answers", len(gw.Answers))
	}
}

func TestDNSExistingNameWithWrongTypeIsNOERROR(t *testing.T) {
	s := newTestDNS(t, testRegistry())
	// "db" exists but has no AAAA. That is NOERROR with no answers, not
	// NXDOMAIN: the name exists.
	resp := ask(t, s, "10.66.0.2", "db", TypeAAAA, false)
	if resp.Header.Rcode != RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", resp.Header.Rcode)
	}
	if len(resp.Answers) != 0 {
		t.Fatalf("answers = %v, want none", answerIPs(resp))
	}
}

func TestDNSRejectsMalformedAndUnsupportedQueries(t *testing.T) {
	s := newTestDNS(t, testRegistry())

	// A truncated message still gets a FORMERR with the right ID.
	raw, err := s.Exchange(context.Background(), []byte{0xab, 0xcd, 0x01}, net.ParseIP("10.66.0.2"), 0)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	resp, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Header.ID != 0xabcd || resp.Header.Rcode != RcodeFormatError {
		t.Fatalf("got id %#x rcode %d, want 0xabcd FORMERR", resp.Header.ID, resp.Header.Rcode)
	}

	// An unsupported opcode is NOTIMP.
	q := &Message{Header: Header{ID: 1, Opcode: 5}, Questions: []Question{{Name: "web.", Type: TypeA, Class: ClassINET}}}
	wire, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	raw, err = s.Exchange(context.Background(), wire, net.ParseIP("10.66.0.2"), 0)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	resp, _ = ParseMessage(raw)
	if resp.Header.Rcode != RcodeNotImplemented {
		t.Fatalf("rcode = %d, want NOTIMP", resp.Header.Rcode)
	}
}

func TestDNSTruncatesOversizedUDPAnswers(t *testing.T) {
	reg := testRegistry()
	// Register many addresses so the answer cannot fit in 512 bytes.
	var ips []string
	for i := 2; i < 80; i++ {
		ips = append(ips, net.IPv4(10, 66, 9, byte(i)).String())
	}
	reg.names["frontend|many"] = ips
	s := newTestDNS(t, reg)

	q := &Message{Header: Header{ID: 7, RecursionDesired: true},
		Questions: []Question{{Name: "many.", Type: TypeA, Class: ClassINET}}}
	wire, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	raw, err := s.Exchange(context.Background(), wire, net.ParseIP("10.66.0.2"), MinUDPSize)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(raw) > MinUDPSize {
		t.Fatalf("response is %d bytes, over the %d-byte UDP limit", len(raw), MinUDPSize)
	}
	resp, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !resp.Header.Truncated {
		t.Fatal("TC bit not set on an oversized answer")
	}

	// Over TCP (no limit) the whole answer comes back.
	raw, err = s.Exchange(context.Background(), wire, net.ParseIP("10.66.0.2"), 0)
	if err != nil {
		t.Fatalf("Exchange over tcp: %v", err)
	}
	resp, err = ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Header.Truncated || len(resp.Answers) != len(ips) {
		t.Fatalf("tcp answer truncated=%v answers=%d want %d", resp.Header.Truncated, len(resp.Answers), len(ips))
	}
}

func TestDNSListenAndServeOverUDPAndTCP(t *testing.T) {
	s := NewDNSServer(testRegistry(), DNSOptions{Port: freePort(t), TTL: 30, Timeout: time.Second})
	// 127.x.x.x is entirely local on Linux, so this needs no bridge and no root.
	gw := net.ParseIP("127.66.0.1")
	ctx := context.Background()
	if err := s.Listen(ctx, gw); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	if err := s.Listen(ctx, gw); err != nil {
		t.Fatalf("Listen must be idempotent: %v", err)
	}
	if addrs := s.Addrs(); len(addrs) != 1 || addrs[0] != "127.66.0.1" {
		t.Fatalf("Addrs = %v", addrs)
	}

	q := &Message{Header: Header{ID: 0x1111, RecursionDesired: true},
		Questions: []Question{{Name: "host.hull.internal.", Type: TypeA, Class: ClassINET}}}
	wire, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	addr := net.JoinHostPort(gw.String(), itoa(s.Port()))

	// The registry does not know 127.66.0.1 as a source, so the pseudo-name has
	// no gateway and is forwarded; what this test proves is that both listeners
	// accept, parse and answer, which is the transport contract.
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(wire); err != nil {
		t.Fatalf("write udp: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read udp: %v", err)
	}
	resp, err := ParseMessage(buf[:n])
	if err != nil {
		t.Fatalf("parse udp response: %v", err)
	}
	if resp.Header.ID != 0x1111 || !resp.Header.Response {
		t.Fatalf("udp response header = %+v", resp.Header)
	}

	tc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
	framed := append([]byte{byte(len(wire) >> 8), byte(len(wire))}, wire...)
	if _, err := tc.Write(framed); err != nil {
		t.Fatalf("write tcp: %v", err)
	}
	hdr := make([]byte, 2)
	if _, err := readFull(tc, hdr); err != nil {
		t.Fatalf("read tcp length: %v", err)
	}
	body := make([]byte, int(hdr[0])<<8|int(hdr[1]))
	if _, err := readFull(tc, body); err != nil {
		t.Fatalf("read tcp body: %v", err)
	}
	resp, err = ParseMessage(body)
	if err != nil {
		t.Fatalf("parse tcp response: %v", err)
	}
	if resp.Header.ID != 0x1111 {
		t.Fatalf("tcp response id = %#x", resp.Header.ID)
	}
}

func TestParseResolvConf(t *testing.T) {
	const sample = `# generated by WSL
nameserver 10.255.255.254
nameserver 8.8.8.8  ; trailing comment
search hull.internal example.com
options ndots:2 edns0
nameserver not-an-ip
`
	rc := parseResolvConf(strings.NewReader(sample))
	want := []string{"10.255.255.254:53", "8.8.8.8:53"}
	if len(rc.Nameservers) != len(want) {
		t.Fatalf("nameservers = %v, want %v", rc.Nameservers, want)
	}
	for i := range want {
		if rc.Nameservers[i] != want[i] {
			t.Fatalf("nameservers = %v, want %v", rc.Nameservers, want)
		}
	}
	if len(rc.Search) != 2 || rc.Search[0] != "hull.internal" {
		t.Fatalf("search = %v", rc.Search)
	}
	if rc.NDots != 2 {
		t.Fatalf("ndots = %d", rc.NDots)
	}
	if len(rc.Options) != 1 || rc.Options[0] != "edns0" {
		t.Fatalf("options = %v", rc.Options)
	}
}

func TestNormaliseUpstreams(t *testing.T) {
	got := normaliseUpstreams([]string{"1.1.1.1", "8.8.8.8:5353", "1.1.1.1", "garbage", "", "  9.9.9.9  "})
	want := []string{"1.1.1.1:53", "8.8.8.8:5353", "9.9.9.9:53"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestSetUpstreamsDropsSelf(t *testing.T) {
	s := NewDNSServer(testRegistry(), DNSOptions{Port: freePort(t)})
	gw := net.ParseIP("127.66.0.2")
	if err := s.Listen(context.Background(), gw); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	s.SetUpstreams([]string{"127.66.0.2", "1.1.1.1"})
	// SetUpstreams stores the list; Listen is what filters self, so re-listening
	// on the same address must remove the loop.
	if err := s.Listen(context.Background(), net.ParseIP("127.66.0.3")); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	for _, u := range s.Upstreams() {
		if strings.HasPrefix(u, "127.66.0.2:") {
			t.Fatalf("forwarding to ourselves: %v", s.Upstreams())
		}
	}
}

// startFakeUpstream runs a UDP DNS server that answers with handler, and
// returns its address.
func startFakeUpstream(t *testing.T, handler func(*Message) *Message) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake upstream: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := ParseMessage(buf[:n])
			if err != nil {
				continue
			}
			resp := handler(q)
			out, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

// freePort grabs an unused high port so tests never need CAP_NET_BIND_SERVICE.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// itoa avoids importing strconv for one call in the transport test.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// readFull fills p from c.
func readFull(c net.Conn, p []byte) (int, error) {
	n := 0
	for n < len(p) {
		m, err := c.Read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
