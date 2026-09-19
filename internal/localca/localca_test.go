package localca

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEnsureCAGenerates(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	if got, want := ca.CertPath(), filepath.Join(dir, CertFileName); got != want {
		t.Errorf("CertPath = %q, want %q", got, want)
	}
	if got, want := ca.KeyPath(), filepath.Join(dir, KeyFileName); got != want {
		t.Errorf("KeyPath = %q, want %q", got, want)
	}

	cert := ca.Certificate()
	if !cert.IsCA {
		t.Error("root is not marked as a CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("root cannot sign certificates")
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("public key algorithm = %v, want ECDSA", cert.PublicKeyAlgorithm)
	}
	life := cert.NotAfter.Sub(cert.NotBefore)
	if want := CAValidity + clockSkew; absDur(life-want) > 48*time.Hour {
		t.Errorf("root validity = %v, want about %v", life, want)
	}
	if !strings.Contains(string(ca.CertPEM()), "BEGIN CERTIFICATE") {
		t.Error("CertPEM is not PEM")
	}

	if runtime.GOOS != "windows" {
		for _, p := range []string{ca.CertPath(), ca.KeyPath()} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatalf("stat %s: %v", p, err)
			}
			if got := fi.Mode().Perm(); got != FileMode {
				t.Errorf("%s mode = %04o, want %04o", p, got, FileMode)
			}
		}
	}
}

func TestEnsureCAReusesExisting(t *testing.T) {
	dir := t.TempDir()
	first, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA (first): %v", err)
	}
	second, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA (second): %v", err)
	}
	if first.Certificate().SerialNumber.Cmp(second.Certificate().SerialNumber) != 0 {
		t.Fatal("second EnsureCA generated a new root instead of reusing the stored one")
	}
	if !first.Certificate().Equal(second.Certificate()) {
		t.Error("reloaded root differs from the generated one")
	}
}

func TestEnsureCAErrors(t *testing.T) {
	t.Run("empty dir", func(t *testing.T) {
		if _, err := EnsureCA(""); err == nil {
			t.Fatal("EnsureCA(\"\") succeeded, want error")
		}
	})

	t.Run("missing key", func(t *testing.T) {
		dir := t.TempDir()
		ca, err := EnsureCA(dir)
		if err != nil {
			t.Fatalf("EnsureCA: %v", err)
		}
		if err := os.Remove(ca.KeyPath()); err != nil {
			t.Fatal(err)
		}
		_, err = EnsureCA(dir)
		if !errors.Is(err, ErrIncompleteCA) {
			t.Fatalf("err = %v, want ErrIncompleteCA", err)
		}
	})

	t.Run("key mismatch", func(t *testing.T) {
		dir := t.TempDir()
		ca, err := EnsureCA(dir)
		if err != nil {
			t.Fatalf("EnsureCA: %v", err)
		}
		other, err := EnsureCA(t.TempDir())
		if err != nil {
			t.Fatalf("EnsureCA (other): %v", err)
		}
		keyPEM, err := os.ReadFile(other.KeyPath())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ca.KeyPath(), keyPEM, FileMode); err != nil {
			t.Fatal(err)
		}
		_, err = EnsureCA(dir)
		if !errors.Is(err, ErrKeyMismatch) {
			t.Fatalf("err = %v, want ErrKeyMismatch", err)
		}
	})

	t.Run("garbage certificate", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, CertFileName), []byte("not a pem"), FileMode); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, KeyFileName), []byte("not a pem"), FileMode); err != nil {
			t.Fatal(err)
		}
		if _, err := EnsureCA(dir); err == nil {
			t.Fatal("EnsureCA accepted a garbage root")
		}
	})
}

func TestEnsureCARejectsExpiredRoot(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	// Rewrite the stored root with one that expired two days ago, keeping the key.
	expired := selfSignedAt(t, ca, time.Now().Add(-2*24*time.Hour))
	if err := os.WriteFile(ca.CertPath(), expired, FileMode); err != nil {
		t.Fatal(err)
	}
	_, err = EnsureCA(dir)
	if !errors.Is(err, ErrExpiredCA) {
		t.Fatalf("err = %v, want ErrExpiredCA", err)
	}
}

func TestLeafForSANs(t *testing.T) {
	ca := testCA(t)

	tests := []struct {
		name     string
		names    []string
		wantDNS  []string
		wantIPs  []string
		verify   []string // names the chain must be valid for
		mustFail []string // names the chain must be invalid for
		wantErr  bool
	}{
		{
			name:    "single name",
			names:   []string{"api.localhost"},
			wantDNS: []string{"api.localhost"},
			wantIPs: []string{"127.0.0.1", "::1"},
			verify:  []string{"api.localhost"},
			// Case and the trailing root dot are normalised away.
			mustFail: []string{"web.localhost"},
		},
		{
			name:    "several names sorted",
			names:   []string{"web.localhost", "api.localhost"},
			wantDNS: []string{"api.localhost", "web.localhost"},
			wantIPs: []string{"127.0.0.1", "::1"},
			verify:  []string{"api.localhost", "web.localhost"},
		},
		{
			name:    "normalises case and trailing dot",
			names:   []string{"API.Localhost.", " api.localhost "},
			wantDNS: []string{"api.localhost"},
			wantIPs: []string{"127.0.0.1", "::1"},
			verify:  []string{"api.localhost"},
		},
		{
			name:    "explicit ip becomes an ip san",
			names:   []string{"10.66.2.2", "api.localhost"},
			wantDNS: []string{"api.localhost"},
			wantIPs: []string{"10.66.2.2", "127.0.0.1", "::1"},
			verify:  []string{"api.localhost"},
		},
		{
			name:    "no names at all",
			names:   nil,
			wantErr: true,
		},
		{
			name:    "unusable name",
			names:   []string{"not a hostname"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf, err := ca.LeafFor(tc.names)
			if tc.wantErr {
				if !errors.Is(err, ErrBadName) {
					t.Fatalf("err = %v, want ErrBadName", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LeafFor(%v): %v", tc.names, err)
			}
			if got := leaf.Leaf.DNSNames; !equalStrings(got, tc.wantDNS) {
				t.Errorf("DNSNames = %v, want %v", got, tc.wantDNS)
			}
			var gotIPs []string
			for _, ip := range leaf.Leaf.IPAddresses {
				gotIPs = append(gotIPs, ip.String())
			}
			for _, want := range tc.wantIPs {
				if !contains(gotIPs, want) {
					t.Errorf("IP SANs = %v, missing %s", gotIPs, want)
				}
			}
			if leaf.Leaf.IsCA {
				t.Error("leaf is marked as a CA")
			}
			if len(leaf.Leaf.ExtKeyUsage) != 1 || leaf.Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
				t.Errorf("ExtKeyUsage = %v, want [ServerAuth]", leaf.Leaf.ExtKeyUsage)
			}
			life := leaf.Leaf.NotAfter.Sub(leaf.Leaf.NotBefore)
			if want := LeafValidity + clockSkew; absDur(life-want) > time.Minute {
				t.Errorf("leaf validity = %v, want about %v", life, want)
			}
			for _, name := range tc.verify {
				if err := ca.Verify(leaf, name, time.Now()); err != nil {
					t.Errorf("chain does not verify for %s: %v", name, err)
				}
			}
			for _, name := range tc.mustFail {
				if err := ca.Verify(leaf, name, time.Now()); err == nil {
					t.Errorf("chain unexpectedly verified for %s", name)
				}
			}
		})
	}
}

func TestLeafChainVerifiesOnlyAgainstItsOwnRoot(t *testing.T) {
	ca := testCA(t)
	other := testCA(t)

	leaf, err := ca.LeafFor([]string{"api.localhost"})
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	if err := ca.Verify(leaf, "api.localhost", time.Now()); err != nil {
		t.Fatalf("verify against own root: %v", err)
	}
	if err := other.Verify(leaf, "api.localhost", time.Now()); err == nil {
		t.Fatal("leaf verified against an unrelated root")
	}
	if err := ca.Verify(leaf, "api.localhost", time.Now().Add(LeafValidity+48*time.Hour)); err == nil {
		t.Fatal("expired leaf verified")
	}
}

func TestLeafForCaches(t *testing.T) {
	ca := testCA(t)

	a, err := ca.LeafFor([]string{"api.localhost", "web.localhost"})
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	b, err := ca.LeafFor([]string{"web.localhost", "API.localhost."})
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	if a != b {
		t.Error("same name set in a different order minted a second leaf")
	}
	c, err := ca.LeafFor([]string{"api.localhost"})
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	if a == c {
		t.Error("a different name set reused a cached leaf")
	}

	// A cached leaf close to expiry is re-minted rather than served.
	ca.now = func() time.Time { return time.Now().Add(LeafValidity - leafRenewBefore/2) }
	d, err := ca.LeafFor([]string{"api.localhost"})
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	if c == d {
		t.Error("a leaf inside the renewal window was served from the cache")
	}
}

func TestLeafCacheIsBounded(t *testing.T) {
	ca := testCA(t)
	for i := 0; i < maxCachedLeaves+5; i++ {
		if _, err := ca.LeafFor([]string{namef(i)}); err != nil {
			t.Fatalf("LeafFor: %v", err)
		}
	}
	ca.mu.Lock()
	n := len(ca.leaves)
	ca.mu.Unlock()
	if n > maxCachedLeaves {
		t.Fatalf("leaf cache holds %d entries, want at most %d", n, maxCachedLeaves)
	}
}

func TestTLSConfigHandshake(t *testing.T) {
	ca := testCA(t)

	tests := []struct {
		name       string
		serverName string
		wantCN     string
	}{
		{name: "sni name", serverName: "api.localhost", wantCN: "api.localhost"},
		{name: "sni case folded", serverName: "API.Localhost", wantCN: "api.localhost"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := handshake(t, ca, tc.serverName)
			if len(state.PeerCertificates) == 0 {
				t.Fatal("no peer certificate")
			}
			if got := state.PeerCertificates[0].Subject.CommonName; got != tc.wantCN {
				t.Errorf("CommonName = %q, want %q", got, tc.wantCN)
			}
			if got := state.NegotiatedProtocol; got != "" && got != "http/1.1" {
				t.Errorf("ALPN = %q, want http/1.1 (HTTP/2 would break WebSocket upgrades)", got)
			}
		})
	}
}

func TestInstallHint(t *testing.T) {
	ca := testCA(t)
	hint := ca.InstallHint()

	for _, want := range []string{
		`certutil -addstore -user Root ` + WindowsCertPath,
		"update-ca-certificates",
		"update-ca-trust extract",
		".mozilla/firefox",
		ca.CertPath(),
		"--cacert",
	} {
		if !strings.Contains(hint, want) {
			t.Errorf("InstallHint is missing %q\n---\n%s", want, hint)
		}
	}
	if strings.Contains(hint, "\n\n\n") {
		t.Error("InstallHint has a triple newline")
	}
	if hint != ca.InstallHint() {
		t.Error("InstallHint is not deterministic")
	}
}

// ---- helpers ----

func testCA(t *testing.T) *CA {
	t.Helper()
	ca, err := EnsureCA(t.TempDir())
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	return ca
}

// handshake runs a real TLS handshake over an in-memory pipe and returns the
// client's connection state, so the certificate path is exercised exactly as a
// browser would exercise it, without binding a port.
func handshake(t *testing.T, ca *CA, serverName string) tls.ConnectionState {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errc := make(chan error, 1)
	go func() {
		s := tls.Server(serverConn, ca.TLSConfig())
		errc <- s.Handshake()
	}()

	c := tls.Client(clientConn, &tls.Config{
		ServerName: serverName,
		RootCAs:    ca.Pool(),
		MinVersion: tls.VersionTLS12,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return c.ConnectionState()
}

// selfSignedAt re-signs ca's root with a NotAfter in the past, so the expiry
// path can be tested without waiting ten years.
func selfSignedAt(t *testing.T, ca *CA, notAfter time.Time) []byte {
	t.Helper()
	tmpl := *ca.Certificate()
	tmpl.NotBefore = notAfter.Add(-CAValidity)
	tmpl.NotAfter = notAfter
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, ca.key.Public(), ca.key)
	if err != nil {
		t.Fatalf("re-sign root: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func namef(i int) string {
	return "svc" + strconv.Itoa(i) + ".localhost"
}
