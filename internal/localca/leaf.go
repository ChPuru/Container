package localca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// loopbackV4 and loopbackV6 are added to the SANs of every leaf, so a client
// that reaches the proxy by address — the documented fallback when Windows'
// resolver refuses to answer for <name>.localhost — still gets a certificate
// that matches what it dialled.
var (
	loopbackV4 = net.IPv4(127, 0, 0, 1)
	loopbackV6 = net.IPv6loopback
)

// LeafFor returns a server certificate valid for the given DNS names, minting
// and caching one if needed.
//
// Every leaf also carries 127.0.0.1 and ::1 as IP SANs. A name that parses as
// an IP address is added as an IP SAN rather than a DNS SAN. Leaves are valid
// for [LeafValidity] and are cached per *set* of names, so the order the names
// are passed in does not matter and a cached leaf near expiry is re-minted.
func (c *CA) LeafFor(names []string) (*tls.Certificate, error) {
	dnsNames, ips, err := splitNames(names)
	if err != nil {
		return nil, err
	}
	if len(dnsNames) == 0 && len(ips) == 0 {
		return nil, fmt.Errorf("localca: leaf: %w: no names given", ErrBadName)
	}
	key := cacheKey(dnsNames, ips)

	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf, ok := c.leaves[key]; ok {
		if leaf.Leaf != nil && c.clock().Add(leafRenewBefore).Before(leaf.Leaf.NotAfter) {
			return leaf, nil
		}
		delete(c.leaves, key)
	}
	leaf, err := c.mint(dnsNames, ips)
	if err != nil {
		return nil, err
	}
	if len(c.leaves) >= maxCachedLeaves {
		c.leaves = make(map[string]*tls.Certificate, 1)
	}
	c.leaves[key] = leaf
	return leaf, nil
}

// mint signs a fresh leaf. The caller holds c.mu.
func (c *CA) mint(dnsNames []string, ips []net.IP) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("localca: generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	cn := "hull local service"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	if len(cn) > 64 { // CommonName is an UTF8String of at most 64 characters.
		cn = cn[:64]
	}
	now := c.clock()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"hull"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(LeafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		return nil, fmt.Errorf("localca: sign leaf for %v: %w", dnsNames, err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("localca: parse minted leaf: %w", err)
	}
	// Only the leaf goes on the wire. The root is a trust anchor the peer
	// either has or does not; sending it saves nobody anything.
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        parsed,
	}, nil
}

// TLSConfig returns a server TLS config that mints a leaf per SNI name on
// demand. A handshake with no SNI — a client that dialled 127.0.0.1 directly —
// gets a certificate for "localhost", which still matches thanks to the
// loopback IP SANs.
//
// ALPN advertises http/1.1 only, deliberately: hull's proxy carries WebSocket
// upgrades, and HTTP/2 has no plain Upgrade mechanism, so negotiating h2 here
// would break exactly the feature <name>.localhost exists to make pleasant.
func (c *CA) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := normalizeName(hello.ServerName)
			if name == "" {
				name = "localhost"
			}
			leaf, err := c.LeafFor([]string{name})
			if err != nil {
				return nil, fmt.Errorf("localca: certificate for %q: %w", hello.ServerName, err)
			}
			return leaf, nil
		},
	}
}

// splitNames normalises the requested names into sorted, de-duplicated DNS
// names and IP addresses, and always appends the loopback addresses.
func splitNames(names []string) ([]string, []net.IP, error) {
	seenDNS := make(map[string]struct{}, len(names))
	seenIP := make(map[string]struct{}, len(names)+2)
	var dnsNames []string
	var ips []net.IP

	addIP := func(a netip.Addr) {
		a = a.Unmap()
		if _, dup := seenIP[a.String()]; dup {
			return
		}
		seenIP[a.String()] = struct{}{}
		ips = append(ips, net.IP(a.AsSlice()))
	}

	for _, raw := range names {
		n := normalizeName(raw)
		if n == "" {
			continue
		}
		if addr, err := netip.ParseAddr(n); err == nil {
			addIP(addr)
			continue
		}
		if !validDNSName(n) {
			return nil, nil, fmt.Errorf("localca: %w: %q", ErrBadName, raw)
		}
		if _, dup := seenDNS[n]; dup {
			continue
		}
		seenDNS[n] = struct{}{}
		dnsNames = append(dnsNames, n)
	}
	v4, _ := netip.AddrFromSlice(loopbackV4.To4())
	addIP(v4)
	v6, _ := netip.AddrFromSlice(loopbackV6)
	addIP(v6)

	sort.Strings(dnsNames)
	return dnsNames, ips, nil
}

// cacheKey is a stable identity for a name set.
func cacheKey(dnsNames []string, ips []net.IP) string {
	var b strings.Builder
	for _, n := range dnsNames {
		b.WriteString(n)
		b.WriteByte(',')
	}
	b.WriteByte('|')
	strs := make([]string, 0, len(ips))
	for _, ip := range ips {
		strs = append(strs, ip.String())
	}
	sort.Strings(strs)
	for _, s := range strs {
		b.WriteString(s)
		b.WriteByte(',')
	}
	return b.String()
}

// normalizeName lowercases a name and strips surrounding whitespace, the
// trailing root dot and IPv6 brackets.
func normalizeName(s string) string {
	n := strings.ToLower(strings.TrimSpace(s))
	n = strings.TrimSuffix(n, ".")
	if len(n) > 1 && n[0] == '[' && n[len(n)-1] == ']' {
		n = n[1 : len(n)-1]
	}
	return n
}

// validDNSName reports whether n is a hostname hull will put in a SAN.
//
// Underscores are permitted because Docker container names allow them and a
// user who called their container my_app should still get a certificate;
// browsers may refuse to resolve such a name, which is a naming problem rather
// than a certificate problem.
func validDNSName(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for _, label := range strings.Split(n, ".") {
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

// errNoLeaf is returned by verification helpers that were handed a nil leaf.
var errNoLeaf = errors.New("certificate has no parsed leaf")

// Verify checks that leaf chains to this root and is valid for name at t. It is
// the same check a browser performs once the root is trusted, and hull uses it
// in tests and in 'hull doctor' rather than asserting that certificate
// generation "probably worked".
func (c *CA) Verify(leaf *tls.Certificate, name string, t time.Time) error {
	if leaf == nil || leaf.Leaf == nil {
		return fmt.Errorf("localca: verify: %w", errNoLeaf)
	}
	_, err := leaf.Leaf.Verify(x509.VerifyOptions{
		DNSName:     normalizeName(name),
		Roots:       c.Pool(),
		CurrentTime: t,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("localca: verify %q: %w", name, err)
	}
	return nil
}
