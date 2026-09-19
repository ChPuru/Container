package api

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// Content types for a hijacked stream. Docker 24 and later also understand
// the "multiplexed" spelling, but every client understands the raw one, so
// that is what hull sends.
const (
	// RawStreamContentType marks a hijacked attach or exec stream.
	RawStreamContentType = "application/vnd.docker.raw-stream"
	// MultiplexedStreamContentType is the newer spelling for a framed stream.
	MultiplexedStreamContentType = "application/vnd.docker.multiplexed-stream"
)

// The two handshakes a hijacking endpoint may send, byte for byte. Clients
// parse these with a hand-written reader rather than a real HTTP parser, so
// the spelling — "101 UPGRADED", not "101 Switching Protocols" — matters.
var (
	upgradeHandshake = []byte("HTTP/1.1 101 UPGRADED\r\n" +
		"Content-Type: " + RawStreamContentType + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: tcp\r\n" +
		"\r\n")

	plainHandshake = []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: " + RawStreamContentType + "\r\n" +
		"\r\n")
)

// wantsUpgrade reports whether the client asked to upgrade the connection.
// Docker's CLI does; a plain curl does not, and then the handshake is a 200
// with the raw-stream content type instead.
func wantsUpgrade(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "tcp")
}

// handshakeFor returns the exact bytes to send for this request.
func handshakeFor(r *http.Request) []byte {
	if wantsUpgrade(r) {
		return upgradeHandshake
	}
	return plainHandshake
}

// hijackConn takes over the connection and writes the handshake.
//
// The returned bufio.ReadWriter must be used for reading: the HTTP server may
// already have buffered the first bytes the client sent after its headers, and
// reading the raw net.Conn would lose them.
func hijackConn(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	rc := http.NewResponseController(w)
	conn, brw, err := rc.Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errNotHijackable, err)
	}
	// Anything the server buffered as a "response so far" is not ours.
	if _, err := conn.Write(handshakeFor(r)); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("api: write the stream handshake: %w", err)
	}
	return conn, brw, nil
}

// closeWriter is a connection half that can signal EOF without tearing the
// whole connection down, which is what lets a piped `docker run -i` give the
// container's stdin an end of file.
type closeWriter interface {
	CloseWrite() error
}

// closeWrite half-closes a connection where the transport supports it and
// falls back to a full close where it does not.
func closeWrite(c net.Conn) error {
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// hijackedStdin adapts the hijacked connection into the reader the engine
// wants for a container's standard input.
type hijackedStdin struct {
	r io.Reader
}

// Read forwards the client's bytes.
func (h hijackedStdin) Read(p []byte) (int, error) { return h.r.Read(p) }

// hijackedStdout adapts the hijacked connection into the writer the engine
// wants for a container's output, flushing the bufio writer after every chunk
// so an interactive shell feels interactive.
type hijackedStdout struct {
	w *bufio.ReadWriter
}

// Write forwards and flushes.
func (h hijackedStdout) Write(p []byte) (int, error) {
	n, err := h.w.Write(p)
	if err != nil {
		return n, err
	}
	return n, h.w.Flush()
}
