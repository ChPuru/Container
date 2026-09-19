package network

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// echoUpperServer accepts one connection at a time, upper-cases everything it
// reads and writes it back, then half-closes so the client sees EOF.
func echoUpperServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				// Read until the client half-closes, then reply and half-close.
				b, _ := io.ReadAll(c)
				_, _ = c.Write([]byte(strings.ToUpper(string(b))))
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			}()
		}
	}()
	return ln.Addr().String(), func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	}
}

func TestTCPProxyMovesBytesBothWaysAndPropagatesHalfClose(t *testing.T) {
	target, stopTarget := echoUpperServer(t)
	defer stopTarget()

	p, err := newTCPProxy(context.Background(), "127.0.0.1", 0, target)
	if err != nil {
		t.Fatalf("newTCPProxy: %v", err)
	}
	defer p.Close()
	if p.Port() == 0 {
		t.Fatal("ephemeral port was not resolved")
	}

	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(p.Port())))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	payload := "hello from the host side"
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Half-close: the server only replies once it sees EOF, so this test fails
	// outright if the proxy does not propagate the FIN.
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != strings.ToUpper(payload) {
		t.Fatalf("got %q, want %q", got, strings.ToUpper(payload))
	}
}

func TestTCPProxyHandlesConcurrentConnections(t *testing.T) {
	target, stopTarget := echoUpperServer(t)
	defer stopTarget()

	p, err := newTCPProxy(context.Background(), "127.0.0.1", 0, target)
	if err != nil {
		t.Fatalf("newTCPProxy: %v", err)
	}
	defer p.Close()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(p.Port())))
			if err != nil {
				t.Errorf("dial: %v", err)
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			msg := "conn" + itoa(i)
			if _, err := c.Write([]byte(msg)); err != nil {
				t.Errorf("write: %v", err)
				return
			}
			_ = c.(*net.TCPConn).CloseWrite()
			got, err := io.ReadAll(c)
			if err != nil {
				t.Errorf("read: %v", err)
				return
			}
			if string(got) != strings.ToUpper(msg) {
				t.Errorf("got %q, want %q", got, strings.ToUpper(msg))
			}
		}(i)
	}
	wg.Wait()
}

func TestTCPProxyCloseStopsAccepting(t *testing.T) {
	target, stopTarget := echoUpperServer(t)
	defer stopTarget()
	p, err := newTCPProxy(context.Background(), "127.0.0.1", 0, target)
	if err != nil {
		t.Fatalf("newTCPProxy: %v", err)
	}
	port := p.Port()
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close must be idempotent: %v", err)
	}
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), time.Second); err == nil {
		c.Close()
		t.Fatal("proxy still accepting after Close")
	}
}

func TestPipeConnsCopiesBothDirections(t *testing.T) {
	// net.Pipe has no half-close, so pipeConns must fall back to a full close
	// and still deliver every byte first.
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()

	go pipeConns(a2, b1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 5)
		if _, err := io.ReadFull(b2, buf); err != nil {
			t.Errorf("read on b2: %v", err)
			return
		}
		if string(buf) != "ping!" {
			t.Errorf("b2 got %q", buf)
			return
		}
		if _, err := b2.Write([]byte("pong!")); err != nil {
			t.Errorf("write on b2: %v", err)
		}
	}()

	if _, err := a1.Write([]byte("ping!")); err != nil {
		t.Fatalf("write on a1: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(a1, buf); err != nil {
		t.Fatalf("read on a1: %v", err)
	}
	if string(buf) != "pong!" {
		t.Fatalf("a1 got %q", buf)
	}
	<-done
	a1.Close()
	b2.Close()
}

func TestCloseWriteFallsBackToClose(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	closeWrite(a) // net.Pipe is not a halfCloser
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("connection should be closed")
	}
}

func TestUDPProxyRelaysDatagramsBothWays(t *testing.T) {
	// A UDP echo server standing in for the container.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(bytes.ToUpper(buf[:n]), from)
		}
	}()

	p, err := newUDPProxy(context.Background(), "127.0.0.1", 0, pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("newUDPProxy: %v", err)
	}
	defer p.Close()
	if p.Port() == 0 {
		t.Fatal("ephemeral udp port was not resolved")
	}

	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(p.Port())))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	for i := 0; i < 3; i++ {
		msg := "datagram" + itoa(i)
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 2048)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf[:n]) != strings.ToUpper(msg) {
			t.Fatalf("got %q, want %q", buf[:n], strings.ToUpper(msg))
		}
	}

	// One source address means exactly one relay session.
	p.mu.Lock()
	sessions := len(p.sessions)
	p.mu.Unlock()
	if sessions != 1 {
		t.Fatalf("sessions = %d, want 1", sessions)
	}
}

func TestUDPProxyReapsIdleSessions(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	p, err := newUDPProxy(context.Background(), "127.0.0.1", 0, pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("newUDPProxy: %v", err)
	}
	defer p.Close()
	p.idle = 20 * time.Millisecond

	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(p.Port())))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		n := len(p.sessions)
		p.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The reply pump's own read deadline drops the session once it goes quiet.
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		n := len(p.sessions)
		p.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("idle udp session was never reclaimed")
}

func TestStartProxyRejectsUnsupportedProtocols(t *testing.T) {
	if _, _, err := startProxy(context.Background(), "sctp", "127.0.0.1", 0, "10.66.0.2", 80); err == nil {
		t.Fatal("sctp should be refused with a clear message")
	}
	if _, _, err := startProxy(context.Background(), "nonsense", "127.0.0.1", 0, "10.66.0.2", 80); err == nil {
		t.Fatal("an unknown protocol should be refused")
	}
}

func TestPublishedPortStringAndClose(t *testing.T) {
	closed := false
	p := PublishedPort{
		Proto: "tcp", HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80,
		closer: func() error { closed = true; return nil },
	}
	if got := p.String(); got != "0.0.0.0:8080->80/tcp" {
		t.Fatalf("String = %q", got)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !closed {
		t.Fatal("closer not invoked")
	}
	var zero PublishedPort
	if err := zero.Close(); err != nil {
		t.Fatalf("closing a zero PublishedPort must be safe: %v", err)
	}
}
