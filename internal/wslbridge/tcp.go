package wslbridge

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The loopback TCP transport exists because WSL's NAT-mode localhost forwarding
// makes a listener inside the VM reachable at 127.0.0.1 on Windows, which is by
// far the simplest fast path. It is off by default and guarded by a shared
// secret because loopback is not a security boundary on Windows: any process
// running as the user can connect to it, and the Docker Engine API is root
// inside the distro.

// TCP handshake wire format. The client sends one line and the server answers
// with one line, both plain ASCII, before any API bytes flow.
const (
	// TCPHandshakeMagic prefixes the client's line.
	TCPHandshakeMagic = "HULL-BRIDGE/1"

	// TCPHandshakeOK is the server's acceptance.
	TCPHandshakeOK = "OK"

	// TCPHandshakeDenied is the server's refusal.
	TCPHandshakeDenied = "DENIED"

	// tcpHandshakeMaxLine bounds a handshake line, so a wrong-protocol client
	// cannot make the server read forever.
	tcpHandshakeMaxLine = 512

	// tcpHandshakeTimeout bounds the whole handshake.
	tcpHandshakeTimeout = 5 * time.Second
)

// ErrTokenMissing means the shared-secret file does not exist.
var ErrTokenMissing = errors.New("wslbridge: shared secret file does not exist")

// ErrHandshakeRejected means the peer refused the shared secret.
var ErrHandshakeRejected = errors.New("wslbridge: shared secret rejected")

// LoadToken reads the shared secret used by the TCP transport.
func LoadToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s", ErrTokenMissing, path)
		}
		return "", fmt.Errorf("wslbridge: read shared secret %s: %w", path, err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("wslbridge: shared secret %s is empty", path)
	}
	return token, nil
}

// EnsureToken returns the shared secret at path, creating a fresh 256-bit one
// if the file does not exist. The file is written 0600 -- on Windows that maps
// onto an ACL that still admits anything running as the user, which is exactly
// why this transport is opt-in.
func EnsureToken(path string) (string, error) {
	if token, err := LoadToken(path); err == nil {
		return token, nil
	} else if !errors.Is(err, ErrTokenMissing) {
		return "", err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("wslbridge: generate shared secret: %w", err)
	}
	token := hex.EncodeToString(raw[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("wslbridge: create shared secret directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("wslbridge: write shared secret %s: %w", path, err)
	}
	return token, nil
}

// TCPClientHandshake presents the shared secret and waits for acceptance. It is
// exported so the engine's TCP listener and this transport cannot drift apart.
func TCPClientHandshake(conn net.Conn, token string) error {
	_ = conn.SetDeadline(time.Now().Add(tcpHandshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	if _, err := fmt.Fprintf(conn, "%s %s\n", TCPHandshakeMagic, token); err != nil {
		return fmt.Errorf("wslbridge: send handshake: %w", err)
	}
	line, err := readHandshakeLine(conn)
	if err != nil {
		return fmt.Errorf("wslbridge: read handshake reply: %w", err)
	}
	if line != TCPHandshakeOK {
		return fmt.Errorf("%w: %s", ErrHandshakeRejected, line)
	}
	return nil
}

// TCPServerHandshake checks the shared secret a client presented. The comparison
// is constant-time, and a refusal is reported to the peer before the connection
// is dropped so the client can print something better than "connection reset".
func TCPServerHandshake(conn net.Conn, token string) error {
	_ = conn.SetDeadline(time.Now().Add(tcpHandshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	line, err := readHandshakeLine(conn)
	if err != nil {
		return fmt.Errorf("wslbridge: read handshake: %w", err)
	}
	magic, presented, ok := strings.Cut(line, " ")
	if !ok || magic != TCPHandshakeMagic ||
		subtle.ConstantTimeCompare([]byte(presented), []byte(token)) != 1 {
		_, _ = fmt.Fprintf(conn, "%s\n", TCPHandshakeDenied)
		return ErrHandshakeRejected
	}
	if _, err := fmt.Fprintf(conn, "%s\n", TCPHandshakeOK); err != nil {
		return fmt.Errorf("wslbridge: send handshake reply: %w", err)
	}
	return nil
}

// readHandshakeLine reads one bounded, newline-terminated line straight from
// conn, one byte at a time.
//
// A bufio.Reader here would be faster and wrong. It reads ahead, so any API
// bytes that arrive in the same segment as the handshake line land in a buffer
// the caller never sees again -- the connection is handed on raw once the
// handshake succeeds. That loses the first bytes of a request whenever the peer
// pipelines, which is exactly what a Docker client does. The handshake is a few
// hundred bytes once per connection, so a syscall per byte is the cheaper
// mistake to avoid.
func readHandshakeLine(conn net.Conn) (string, error) {
	var (
		b    [1]byte
		line []byte
	)
	for len(line) <= tcpHandshakeMaxLine {
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", err
		}
		if b[0] == '\n' {
			return strings.TrimRight(string(line), "\r"), nil
		}
		line = append(line, b[0])
	}
	return "", errors.New("wslbridge: handshake line is longer than the maximum")
}

// TCPTransport reaches the engine over loopback TCP, authenticated with the
// shared secret in the token file. Unlike the multiplexed stdio transport it
// opens one real connection per Dial, so there is no framing at all.
type TCPTransport struct {
	address string
	token   string
	cfg     Config
}

var _ Transport = (*TCPTransport)(nil)

// NewTCPTransport returns a TCP transport, loading the shared secret. It fails
// if the secret is missing rather than falling back to an unauthenticated
// connection.
func NewTCPTransport(cfg Config) (*TCPTransport, error) {
	cfg = cfg.WithDefaults()
	token, err := LoadToken(cfg.TokenPath)
	if err != nil {
		return nil, err
	}
	return &TCPTransport{address: cfg.TCPAddress, token: token, cfg: cfg}, nil
}

// Name implements Transport.
func (t *TCPTransport) Name() string { return "tcp" }

// Dial implements Transport.
func (t *TCPTransport) Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", t.address)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: dial %s: %w", t.address, err)
	}
	if err := TCPClientHandshake(conn, t.token); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// Probe implements Transport.
func (t *TCPTransport) Probe(ctx context.Context) error {
	conn, err := t.Dial(ctx)
	if err != nil {
		return err
	}
	return conn.Close()
}
