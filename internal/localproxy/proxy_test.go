package localproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// echoBackend is a stand-in for a container: it reports the Host header and the
// forwarding headers it was given, so the test can assert what the proxy sent.
func echoBackend(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "path=%s\nhost=%s\nxff=%s\nxfh=%s\nxfp=%s\n",
			r.URL.Path,
			r.Host,
			r.Header.Get("X-Forwarded-For"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Forwarded-Proto"),
		)
	}))
	t.Cleanup(s.Close)
	return s
}

// get issues a request through the proxy with an explicit Host header, which is
// exactly what 'curl -H Host:' does and what a browser does after resolution.
func get(t *testing.T, frontend *httptest.Server, host, path string, hdr http.Header) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, frontend.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = host
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := frontend.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

func TestRoutingMatchesHostHeader(t *testing.T) {
	backend := echoBackend(t)
	p := newTestProxy(t, Config{
		Resolve: func(host string) (string, bool) {
			if host == "dynamic.localhost" {
				return backend.Listener.Addr().String(), true
			}
			return "", false
		},
	})
	if err := p.Register("myapp", backend.Listener.Addr().String(), "www", "myapp.internal"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	frontend := httptest.NewServer(p.Handler())
	defer frontend.Close()

	tests := []struct {
		name       string
		host       string
		wantStatus int
	}{
		{"exact", "myapp.localhost", http.StatusOK},
		{"uppercase", "MYAPP.LOCALHOST", http.StatusOK},
		{"mixed case", "MyApp.LocalHost", http.StatusOK},
		{"with port", "myapp.localhost:80", http.StatusOK},
		{"with odd port", "myapp.localhost:8080", http.StatusOK},
		{"trailing root dot", "myapp.localhost.", http.StatusOK},
		{"bare alias", "www.localhost", http.StatusOK},
		{"qualified alias", "myapp.internal", http.StatusOK},
		{"qualified alias with port", "myapp.internal:443", http.StatusOK},
		{"resolve fallback", "dynamic.localhost", http.StatusOK},
		{"unknown name", "other.localhost", http.StatusNotFound},
		{"unknown domain", "myapp.example.com", http.StatusNotFound},
		{"partial name", "myap.localhost", http.StatusNotFound},
		{"bare label", "myapp", http.StatusNotFound},
		{"bare domain is the index", "localhost", http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := get(t, frontend, tc.host, "/hello", nil)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d\n%s", resp.StatusCode, tc.wantStatus, body)
			}
			if tc.wantStatus == http.StatusOK && tc.host != "localhost" {
				if !strings.Contains(body, "path=/hello") {
					t.Errorf("request did not reach the backend:\n%s", body)
				}
			}
		})
	}
}

func TestReverseProxyPreservesHostAndSetsForwarded(t *testing.T) {
	backend := echoBackend(t)
	p := newTestProxy(t, Config{})
	if err := p.Register("myapp", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	frontend := httptest.NewServer(p.Handler())
	defer frontend.Close()

	hdr := http.Header{}
	// A client-supplied chain must not be trusted through the boundary.
	hdr.Set("X-Forwarded-For", "203.0.113.9")
	hdr.Set("X-Forwarded-Proto", "https")
	resp, body := get(t, frontend, "myapp.localhost", "/a/b", hdr)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d\n%s", resp.StatusCode, body)
	}
	fields := parseFields(body)
	if fields["host"] != "myapp.localhost" {
		t.Errorf("upstream saw Host %q, want the client's myapp.localhost", fields["host"])
	}
	if fields["xfh"] != "myapp.localhost" {
		t.Errorf("X-Forwarded-Host = %q, want myapp.localhost", fields["xfh"])
	}
	if fields["xfp"] != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want http (the client's claim of https must not survive)", fields["xfp"])
	}
	if fields["xff"] == "" || strings.Contains(fields["xff"], "203.0.113.9") {
		t.Errorf("X-Forwarded-For = %q, want the real client address and not the spoofed one", fields["xff"])
	}
	if fields["path"] != "/a/b" {
		t.Errorf("path = %q, want /a/b", fields["path"])
	}
}

func TestReverseProxyJoinsTargetPathPrefix(t *testing.T) {
	backend := echoBackend(t)
	p := newTestProxy(t, Config{})
	if err := p.Register("myapp", "http://"+backend.Listener.Addr().String()+"/prefix"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	frontend := httptest.NewServer(p.Handler())
	defer frontend.Close()

	_, body := get(t, frontend, "myapp.localhost", "/thing", nil)
	if got := parseFields(body)["path"]; got != "/prefix/thing" {
		t.Errorf("upstream path = %q, want /prefix/thing", got)
	}
}

func TestNotFoundListsExistingRoutes(t *testing.T) {
	backend := echoBackend(t)
	p := newTestProxy(t, Config{})
	if err := p.Register("myapp", backend.Listener.Addr().String(), "www"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := p.Register("postgres", "10.66.2.3:5432"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	frontend := httptest.NewServer(p.Handler())
	defer frontend.Close()

	t.Run("plain text for curl", func(t *testing.T) {
		resp, body := get(t, frontend, "myap.localhost", "/", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("Content-Type = %q, want text/plain for a non-HTML client", ct)
		}
		for _, want := range []string{
			"myap.localhost",     // what was asked for
			"myapp.localhost",    // the routes that do exist
			"www.localhost",      // including aliases
			"postgres.localhost", //
			"10.66.2.3:5432",     // and where they go
			"Did you mean",       // the typo is one edit away
			"hosts",              // the Windows resolution note
		} {
			if !strings.Contains(body, want) {
				t.Errorf("404 body is missing %q\n---\n%s", want, body)
			}
		}
	})

	t.Run("html for a browser", func(t *testing.T) {
		hdr := http.Header{"Accept": []string{"text/html,application/xhtml+xml,*/*;q=0.8"}}
		resp, body := get(t, frontend, "myap.localhost", "/", hdr)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("Content-Type = %q, want text/html", ct)
		}
		for _, want := range []string{"<!doctype html>", "myapp.localhost", "postgres.localhost", "drivers\\etc\\hosts"} {
			if !strings.Contains(body, want) {
				t.Errorf("404 page is missing %q", want)
			}
		}
		if strings.Contains(body, "<script") {
			t.Error("the 404 page must not need scripts")
		}
	})

	t.Run("hostile host is escaped", func(t *testing.T) {
		hdr := http.Header{"Accept": []string{"text/html"}}
		// The Host header reaches the page, so it must be escaped. Go's
		// http.Client refuses control characters, so use a plain injection.
		resp, body := get(t, frontend, "a<script>x.localhost", "/", hdr)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		if strings.Contains(body, "<script>x") {
			t.Errorf("the requested host was not escaped:\n%s", body)
		}
	})

	t.Run("no routes at all", func(t *testing.T) {
		empty := newTestProxy(t, Config{})
		srv := httptest.NewServer(empty.Handler())
		defer srv.Close()
		resp, body := get(t, srv, "anything.localhost", "/", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		if !strings.Contains(body, "not routing any names yet") {
			t.Errorf("empty 404 does not explain itself:\n%s", body)
		}
	})
}

func TestIndexAtBareDomain(t *testing.T) {
	p := newTestProxy(t, Config{})
	if err := p.Register("myapp", "10.66.2.2:80"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	frontend := httptest.NewServer(p.Handler())
	defer frontend.Close()

	resp, body := get(t, frontend, "localhost", "/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "myapp.localhost") {
		t.Errorf("index does not list the routes:\n%s", body)
	}
}

func TestGatewayErrorExplains(t *testing.T) {
	// Bind and immediately release a port so the target is certainly dead.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	p := newTestProxy(t, Config{})
	if err := p.Register("myapp", dead); err != nil {
		t.Fatalf("Register: %v", err)
	}
	frontend := httptest.NewServer(p.Handler())
	defer frontend.Close()

	resp, body := get(t, frontend, "myapp.localhost", "/", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502\n%s", resp.StatusCode, body)
	}
	for _, want := range []string{"myapp.localhost", dead, "stopped"} {
		if !strings.Contains(body, want) {
			t.Errorf("502 body is missing %q\n---\n%s", want, body)
		}
	}
}

func TestServerSentEventsAreNotBuffered(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("backend ResponseWriter is not a Flusher")
			return
		}
		io.WriteString(w, "data: first\n\n")
		fl.Flush()
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		io.WriteString(w, "data: second\n\n")
		fl.Flush()
	}))
	defer backend.Close()

	p := newTestProxy(t, Config{})
	if err := p.Register("sse", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	frontend := httptest.NewServer(p.Handler())
	defer frontend.Close()

	req, _ := http.NewRequest(http.MethodGet, frontend.URL+"/events", nil)
	req.Host = "sse.localhost"
	resp, err := frontend.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	first := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		first <- string(buf[:n])
	}()
	select {
	case got := <-first:
		if !strings.Contains(got, "first") {
			t.Fatalf("first chunk = %q, want the first event", got)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("no event arrived while the handler was still running: the response was buffered")
	}
	close(release)

	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if !strings.Contains(string(rest), "second") {
		t.Errorf("rest = %q, want the second event", rest)
	}
}

// websocketMagic is the GUID from RFC 6455 used to derive Sec-WebSocket-Accept.
const websocketMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func TestWebSocketUpgrade(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "not an upgrade: "+r.Header.Get("Upgrade"), http.StatusBadRequest)
			return
		}
		if r.Host != "ws.localhost" {
			http.Error(w, "upgrade lost the Host header: "+r.Host, http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijacker", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		accept := wsAccept(r.Header.Get("Sec-WebSocket-Key"))
		fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		if err := buf.Flush(); err != nil {
			t.Errorf("flush 101: %v", err)
			return
		}
		// Echo whatever the client sends down the raw connection.
		_, _ = io.Copy(conn, buf)
	}))
	defer backend.Close()

	p := newTestProxy(t, Config{})
	if err := p.Register("ws", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	frontend := httptest.NewServer(p.Handler())
	defer frontend.Close()

	conn, err := net.Dial("tcp", frontend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: ws.localhost\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", key)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read 101: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != wsAccept(key) {
		t.Errorf("Sec-WebSocket-Accept = %q, want %q", got, wsAccept(key))
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Errorf("Upgrade = %q, want websocket", resp.Header.Get("Upgrade"))
	}

	// The tunnel must now carry bytes in both directions.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write through the tunnel: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read through the tunnel: %v", err)
	}
	if string(got) != "ping" {
		t.Errorf("echoed %q, want %q", got, "ping")
	}
}

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + websocketMagic))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func TestRunServesHTTPAndHTTPS(t *testing.T) {
	backend := echoBackend(t)
	p, err := New(Config{
		HTTPAddr:  "127.0.0.1:0",
		HTTPSAddr: "127.0.0.1:0",
		CADir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Register("myapp", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	select {
	case <-p.Ready():
	case err := <-done:
		t.Fatalf("Run returned before binding: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("Run never became ready")
	}

	httpAddr, httpsAddr := p.Addrs()
	if httpAddr == "" || httpsAddr == "" {
		cancel()
		t.Fatalf("Addrs() = %q, %q; want both bound", httpAddr, httpsAddr)
	}

	t.Run("plain", func(t *testing.T) {
		c := &http.Client{Transport: &http.Transport{
			DialContext: dialFixed(httpAddr),
		}}
		resp, err := c.Get("http://myapp.localhost/plain")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d\n%s", resp.StatusCode, body)
		}
		if got := parseFields(string(body))["host"]; got != "myapp.localhost" {
			t.Errorf("upstream Host = %q", got)
		}
	})

	t.Run("tls with the local ca", func(t *testing.T) {
		c := &http.Client{Transport: &http.Transport{
			DialContext:     dialFixed(httpsAddr),
			TLSClientConfig: &tls.Config{RootCAs: p.CA().Pool(), MinVersion: tls.VersionTLS12},
		}}
		resp, err := c.Get("https://myapp.localhost/secure")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d\n%s", resp.StatusCode, body)
		}
		fields := parseFields(string(body))
		if fields["path"] != "/secure" {
			t.Errorf("path = %q", fields["path"])
		}
		if fields["xfp"] != "https" {
			t.Errorf("X-Forwarded-Proto = %q, want https", fields["xfp"])
		}
	})

	t.Run("untrusted without the root", func(t *testing.T) {
		c := &http.Client{Transport: &http.Transport{DialContext: dialFixed(httpsAddr)}}
		if _, err := c.Get("https://myapp.localhost/"); err == nil {
			t.Fatal("the leaf verified against the system roots; it must not")
		}
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil after a cancelled context", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

func TestRunTwiceFails(t *testing.T) {
	p, err := New(Config{HTTPAddr: "127.0.0.1:0", HTTPSAddr: disabled})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	<-p.Ready()

	if err := p.Run(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Run err = %v, want ErrAlreadyRunning", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestRunWithNoListeners(t *testing.T) {
	p, err := New(Config{HTTPAddr: disabled, HTTPSAddr: disabled})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Run(context.Background()); !errors.Is(err, ErrNoListeners) {
		t.Fatalf("err = %v, want ErrNoListeners", err)
	}
}

// TestRunOnPrivilegedPorts is the real thing: :80 and :443, which is where the
// proxy actually lives inside the engine distro. It needs root, and it is
// skipped when something else already owns those ports (Docker Desktop and
// friends share one port space with hull in WSL).
func TestRunOnPrivilegedPorts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("binding :80 and :443 needs root")
	}
	for _, addr := range []string{"127.0.0.1:80", "127.0.0.1:443"} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Skipf("%s is already in use: %v", addr, err)
		}
		ln.Close()
	}
	backend := echoBackend(t)
	p, err := New(Config{HTTPAddr: "127.0.0.1:80", HTTPSAddr: "127.0.0.1:443", CADir: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Register("myapp", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	<-p.Ready()

	c := &http.Client{Transport: &http.Transport{DialContext: dialFixed("127.0.0.1:80")}}
	resp, err := c.Get("http://myapp.localhost/")
	if err != nil {
		cancel()
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}
}

// dialFixed sends every connection to addr regardless of the name in the URL,
// which is how these tests reach the proxy without touching a resolver — the
// same trick a user applies with 'curl --resolve' or a hosts-file entry.
func dialFixed(addr string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
}

func parseFields(body string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			out[k] = v
		}
	}
	return out
}
