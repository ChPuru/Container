package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rahuldhali/hull/internal/logbuf"
)

// rawStreamMediaType is the content type the engine answers a hijack with.
const rawStreamMediaType = "application/vnd.docker.raw-stream"

// HijackedResponse is a connection that has stopped being HTTP and is now a
// bidirectional byte stream: attach, exec start and the debug shell all end up
// here.
//
// The caller owns the connection and must Close it. Reader is where the
// response bytes are, not Conn, because the HTTP response headers were read
// through a buffer that may already hold stream bytes.
type HijackedResponse struct {
	// Conn is the raw connection, for writing and for half-closing.
	Conn net.Conn
	// Reader carries everything the engine sends after the handshake.
	Reader *bufio.Reader
	// TTY reports that the stream is unframed because the container has a
	// pseudo-terminal. Without it, output is multiplexed with Docker's
	// 8-byte stream header and must be demultiplexed.
	TTY bool

	closeOnce sync.Once
}

// Close tears the connection down. It is safe to call more than once.
func (h *HijackedResponse) Close() error {
	var err error
	h.closeOnce.Do(func() { err = h.Conn.Close() })
	return err
}

// CloseWrite half-closes the connection so the container sees EOF on stdin
// while its output keeps flowing. Transports that cannot half-close — a named
// pipe, a relay process — report no error, because the alternative is losing
// the rest of the output.
func (h *HijackedResponse) CloseWrite() error {
	if cw, ok := h.Conn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("client: half-close stream: %w", err)
		}
	}
	return nil
}

// Stream pumps a hijacked connection until the output side ends.
//
// stdin is copied into the container in the background and its end
// half-closes the connection; output is demultiplexed into stdout and stderr
// unless the stream is a TTY, in which case it is copied through byte for
// byte. A nil writer discards that stream.
func (h *HijackedResponse) Stream(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	inDone := make(chan struct{})
	if stdin != nil {
		go func() {
			defer close(inDone)
			_, _ = io.Copy(h.Conn, stdin)
			_ = h.CloseWrite()
		}()
	} else {
		close(inDone)
	}

	outErr := make(chan error, 1)
	go func() {
		if h.TTY {
			_, err := io.Copy(stdout, h.Reader)
			outErr <- err
			return
		}
		outErr <- logbuf.DemuxFramed(h.Reader, stdout, stderr)
	}()

	select {
	case err := <-outErr:
		if err != nil && !isStreamEnd(err) {
			return fmt.Errorf("client: stream: %w", err)
		}
		return nil
	case <-ctx.Done():
		_ = h.Close()
		return ctx.Err()
	}
}

// isStreamEnd reports whether an error is just the far end going away, which
// is the normal way an attached container finishes.
func isStreamEnd(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrUnexpectedEOF)
}

// hijack performs a request that upgrades into a raw stream.
//
// It cannot go through http.Client: the response is not a response any more
// once the handshake completes, so the request is written onto a connection
// dialled straight from the host's transport.
func (c *Client) hijack(ctx context.Context, method, path string, query url.Values, body any, tty bool) (*HijackedResponse, error) {
	var payload io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("client: encode %s %s body: %w", method, path, err)
		}
		payload = bytes.NewReader(buf)
	}
	req, err := c.newRequest(ctx, method, path, query, payload)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	req.Host = c.addr

	conn, err := c.dial(ctx, "tcp", c.addr)
	if err != nil {
		return nil, &ConnectionError{Host: c.host, Err: err}
	}
	if c.host.TLS {
		host, _, splitErr := net.SplitHostPort(c.addr)
		if splitErr != nil {
			host = c.addr
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, &ConnectionError{Host: c.host, Err: err}
		}
		conn = tlsConn
	}
	// A hijacked stream lives as long as the container talks; any deadline
	// the transport set while dialling has to go.
	_ = conn.SetDeadline(time.Time{})

	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("client: write %s %s: %w", method, path, err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("client: read %s %s response: %w", method, path, err)
	}
	switch {
	case resp.StatusCode == http.StatusSwitchingProtocols:
	case resp.StatusCode == http.StatusOK &&
		strings.HasPrefix(resp.Header.Get("Content-Type"), rawStreamMediaType):
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// A 200 without the raw-stream content type still carries the
		// stream; older daemons answer this way.
	default:
		defer func() { _ = conn.Close() }()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		text := strings.TrimSpace(string(msg))
		var payload struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(msg, &payload) == nil && payload.Message != "" {
			text = payload.Message
		}
		return nil, &Error{StatusCode: resp.StatusCode, Message: text, Method: method, Path: path}
	}
	return &HijackedResponse{Conn: conn, Reader: br, TTY: tty}, nil
}
