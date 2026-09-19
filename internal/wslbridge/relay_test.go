package wslbridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- relay mode detection ----------

// TestSniffRelayModePushesTheByteBack is the property the whole auto-detection
// rests on: the byte used to decide is still the first byte the protocol sees.
func TestSniffRelayModePushesTheByteBack(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want byte
	}{
		{name: "a multiplexed session opens with a control frame", in: "\x00\x00\x00\x00\x00\x00\x00\x09rest", want: muxFirstByte},
		{name: "a raw client opens with an HTTP method", in: "GET /_ping HTTP/1.1\r\n\r\n", want: 'G'},
		{name: "a raw POST", in: "POST /containers/create HTTP/1.1\r\n", want: 'P'},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			first, rest, err := sniffRelayMode(strings.NewReader(tt.in))
			if err != nil {
				t.Fatalf("sniffRelayMode: %v", err)
			}
			if first != tt.want {
				t.Errorf("first byte = %#x, want %#x", first, tt.want)
			}
			all, err := io.ReadAll(rest)
			if err != nil {
				t.Fatalf("read the pushed-back stream: %v", err)
			}
			if string(all) != tt.in {
				t.Errorf("stream after the sniff = %q, want %q", all, tt.in)
			}
		})
	}
}

// TestRunRelayOnAnEmptyStream covers the dial that was cancelled before it sent
// anything: the relay must exit quietly rather than report a failure.
func TestRunRelayOnAnEmptyStream(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var out bytes.Buffer
	err := RunRelay(ctx, RelayOptions{
		Config: Config{SocketPath: "/nonexistent/hull.sock"},
		In:     bytes.NewReader(nil),
		Out:    &out,
	})
	if err != nil {
		t.Fatalf("RunRelay on an empty stream = %v, want nil", err)
	}
	if out.Len() != 0 {
		t.Errorf("relay wrote %q to a peer that said nothing", out.Bytes())
	}
}

// startRequestEngine runs a unix-socket server that reads a whole HTTP request
// head before answering with exactly what it received.
//
// Reading to the blank line rather than answering the first Read is what makes
// the raw-relay test an assertion about bytes rather than about scheduling: the
// relay legitimately writes the sniffed byte and the remainder as two writes,
// and a unix socket may deliver them as one read or two.
func startRequestEngine(t *testing.T) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "hull.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var got []byte
				buf := make([]byte, 256)
				for !bytes.Contains(got, []byte("\r\n\r\n")) {
					n, err := c.Read(buf)
					got = append(got, buf[:n]...)
					if err != nil {
						break
					}
				}
				_, _ = fmt.Fprintf(c, "engine saw %q", got)
			}(conn)
		}
	}()
	return socket
}

// TestRelayServesARawClient is the compatibility case: hull's own client dials
// one `wsl.exe --exec hull __relay` per connection and writes raw HTTP into it,
// with no framing at all. The same subcommand has to answer that as well as the
// Windows bridge's multiplexed session.
func TestRelayServesARawClient(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	socket := startRequestEngine(t)
	client, relaySide := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		defer relaySide.Close()
		done <- RunRelay(ctx, RelayOptions{
			Config: Config{SocketPath: socket},
			In:     relaySide,
			Out:    relaySide,
		})
	}()

	request := "GET /_ping HTTP/1.1\r\n\r\n"
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatalf("write the request: %v", err)
	}
	buf := make([]byte, 256)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read the response: %v", err)
	}
	if want := fmt.Sprintf("engine saw %q", request); string(buf[:n]) != want {
		t.Fatalf("response = %q, want %q", buf[:n], want)
	}

	_ = client.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.ErrClosedPipe) && !isExpectedClose(err) {
			t.Errorf("RunRelay = %v, want a clean end", err)
		}
	case <-ctx.Done():
		t.Fatal("RunRelay did not return after the client went away")
	}
}

// TestRelayRawModeReportsADialFailure keeps the raw path as diagnosable as the
// multiplexed one: there is no reset frame to carry a reason here, so the error
// has to come back from RunRelay itself and name the socket.
func TestRelayRawModeReportsADialFailure(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	missing := "/nonexistent/hull.sock"
	err := RunRelay(ctx, RelayOptions{
		Config: Config{SocketPath: missing, DialTimeout: time.Second},
		Mode:   RelayModeRaw,
		In:     strings.NewReader("GET /_ping HTTP/1.1\r\n\r\n"),
		Out:    io.Discard,
	})
	if err == nil {
		t.Fatal("RunRelay succeeded with no engine listening")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error = %v, want it to name %s", err, missing)
	}
}

// TestRelayModeString keeps the log field readable.
func TestRelayModeString(t *testing.T) {
	t.Parallel()
	for mode, want := range map[RelayMode]string{
		RelayModeAuto: "auto",
		RelayModeMux:  "mux",
		RelayModeRaw:  "raw",
		RelayMode(42): "auto",
	} {
		if got := mode.String(); got != want {
			t.Errorf("RelayMode(%d).String() = %q, want %q", mode, got, want)
		}
	}
}

// ---------- the TCP handshake must not read ahead ----------

// chunkConn is a net.Conn whose Read hands back everything it holds in one go,
// which is what a loopback socket does when the peer's handshake reply and the
// first API bytes arrive in the same segment.
type chunkConn struct {
	net.Conn
	r *bytes.Reader
	w bytes.Buffer
}

// Read implements net.Conn.
func (c *chunkConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Write implements net.Conn.
func (c *chunkConn) Write(p []byte) (int, error) { return c.w.Write(p) }

// SetDeadline implements net.Conn.
func (c *chunkConn) SetDeadline(time.Time) error { return nil }

// TestReadHandshakeLineLeavesTheRestOfTheStream is a regression test for a
// buffered reader: the connection is handed on raw once the handshake
// succeeds, so any byte the handshake consumed past the newline is a byte the
// Docker API never sees.
func TestReadHandshakeLineLeavesTheRestOfTheStream(t *testing.T) {
	t.Parallel()
	const payload = "GET /_ping HTTP/1.1\r\nHost: hull\r\n\r\n"
	conn := &chunkConn{r: bytes.NewReader([]byte(TCPHandshakeOK + "\n" + payload))}

	line, err := readHandshakeLine(conn)
	if err != nil {
		t.Fatalf("readHandshakeLine: %v", err)
	}
	if line != TCPHandshakeOK {
		t.Fatalf("line = %q, want %q", line, TCPHandshakeOK)
	}
	rest, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read the rest: %v", err)
	}
	if string(rest) != payload {
		t.Errorf("stream after the handshake = %q, want %q", rest, payload)
	}
}

// TestReadHandshakeLineBounds refuses a peer that never sends a newline.
func TestReadHandshakeLineBounds(t *testing.T) {
	t.Parallel()
	conn := &chunkConn{r: bytes.NewReader(bytes.Repeat([]byte("x"), tcpHandshakeMaxLine*2))}
	if _, err := readHandshakeLine(conn); err == nil {
		t.Fatal("readHandshakeLine accepted an unterminated line")
	}
}

// TestTCPHandshakeRejectsAWrongSecret checks the refusal is reported to the
// peer rather than dropped, so the client can print something better than
// "connection reset".
func TestTCPHandshakeRejectsAWrongSecret(t *testing.T) {
	t.Parallel()
	conn := &chunkConn{r: bytes.NewReader([]byte(TCPHandshakeMagic + " wrong-secret\n"))}
	err := TCPServerHandshake(conn, "the-real-secret")
	if !errors.Is(err, ErrHandshakeRejected) {
		t.Fatalf("TCPServerHandshake = %v, want ErrHandshakeRejected", err)
	}
	if got := strings.TrimSpace(conn.w.String()); got != TCPHandshakeDenied {
		t.Errorf("server said %q, want %q", got, TCPHandshakeDenied)
	}
}

// ---------- distro list parsing and the missing-distro error ----------

func TestParseDistroList(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []byte
		want []string
	}{
		{
			name: "utf-8 with CRLF, what WSL_UTF8=1 gives",
			in:   []byte("hull-engine\r\nUbuntu\r\n"),
			want: []string{"hull-engine", "Ubuntu"},
		},
		{
			name: "utf-16le with a byte-order mark, what an older wsl.exe gives",
			in:   withBOM(utf16leBytes("hull-engine\r\nUbuntu\r\ndocker-desktop\r\n")),
			want: []string{"hull-engine", "Ubuntu", "docker-desktop"},
		},
		{
			name: "the (Default) marker is stripped when --quiet was not honoured",
			in:   []byte("hull-engine (Default)\nUbuntu\n"),
			want: []string{"hull-engine", "Ubuntu"},
		},
		{
			name: "stray NULs from a truncated UTF-16 read do not become part of a name",
			in:   []byte("hull-engine\x00\nUbuntu\x00\n"),
			want: []string{"hull-engine", "Ubuntu"},
		},
		{
			name: "blank lines and trailing whitespace are dropped",
			in:   []byte("\n  hull-engine  \n\n\n"),
			want: []string{"hull-engine"},
		},
		{
			name: "no distros at all",
			in:   []byte("\r\n"),
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ParseDistroList(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("ParseDistroList = %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("ParseDistroList = %q, want %q", got, tt.want)
				}
			}
		})
	}
}

// TestEnsureDistroNamesTheInstaller is the error a first-run user sees, so it
// has to say what to run rather than just what is wrong.
func TestEnsureDistroNamesTheInstaller(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{handler: func(string, []string) ([]byte, error) {
		return withBOM(utf16leBytes("Ubuntu\r\ndocker-desktop\r\n")), nil
	}}
	err := EnsureDistroWith(context.Background(), Config{Distro: "hull-engine", Runner: runner})
	if err == nil {
		t.Fatal("EnsureDistroWith succeeded with the engine distro unregistered")
	}
	if !errors.Is(err, ErrDistroMissing) {
		t.Errorf("error does not wrap ErrDistroMissing: %v", err)
	}
	for _, want := range []string{"hull-engine", "install.ps1", "Ubuntu"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestEnsureDistroAcceptsARegisteredDistro is the other half: no error, and no
// installer advice, when it is there.
func TestEnsureDistroAcceptsARegisteredDistro(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{handler: func(string, []string) ([]byte, error) {
		return []byte("hull-engine\nUbuntu\n"), nil
	}}
	if err := EnsureDistroWith(context.Background(), Config{Distro: "hull-engine", Runner: runner}); err != nil {
		t.Fatalf("EnsureDistroWith: %v", err)
	}
}

// TestStartEngineWithBootsWhenTheSocketIsAbsent checks the boot command and the
// polling, using a runner that reports the socket missing until hull-boot runs.
func TestStartEngineWithBootsWhenTheSocketIsAbsent(t *testing.T) {
	t.Parallel()

	var (
		mu     sync.Mutex
		booted bool
	)
	runner := &fakeRunner{handler: func(_ string, args []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.Contains(joined, BootBinary):
			booted = true
			return nil, nil
		case strings.Contains(joined, "test -S"):
			if booted {
				return nil, nil
			}
			return nil, errors.New("exit status 1")
		}
		return nil, nil
	}}

	cfg := Config{Runner: runner, EngineStartTimeout: 5 * time.Second}
	if err := StartEngineWith(context.Background(), cfg); err != nil {
		t.Fatalf("StartEngineWith: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !booted {
		t.Fatal("StartEngineWith never ran hull-boot")
	}
}
