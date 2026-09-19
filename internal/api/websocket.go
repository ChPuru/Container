package api

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// wsGUID is RFC 6455's magic string, concatenated with the client's key to
// prove the server understood the handshake rather than merely echoing it.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WebSocket frame opcodes, from RFC 6455 section 5.2.
const (
	wsOpContinuation byte = 0x0
	wsOpText         byte = 0x1
	wsOpBinary       byte = 0x2
	wsOpClose        byte = 0x8
	wsOpPing         byte = 0x9
	wsOpPong         byte = 0xA
)

// wsMaxPayload bounds a single frame's payload.
//
// The length field is 63 bits wide, so without a cap a client could announce
// an exabyte and have the daemon try to allocate it. Attach traffic is
// keystrokes and terminal output; 8 MiB is already generous.
const wsMaxPayload = 8 << 20

// wsMaxControlPayload is the spec's own limit on a control frame.
const wsMaxControlPayload = 125

// wsAcceptKey computes the Sec-WebSocket-Accept value for a client key.
func wsAcceptKey(key string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(key) + wsGUID)) //nolint:gosec // RFC 6455 mandates SHA-1 here.
	return base64.StdEncoding.EncodeToString(sum[:])
}

// headerHasToken reports whether a comma-separated header names a token,
// case-insensitively. "Connection: keep-alive, Upgrade" is legal and common,
// so a plain equality check on the header would reject real clients.
func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// wsSubprotocol picks a subprotocol to echo back.
//
// Only "binary" is selected, because that is the only one hull speaks and RFC
// 6455 requires the server to choose from what the client offered or to stay
// silent. Staying silent is what x/net/websocket's default handshake does, so
// a client that offers nothing keeps working unchanged.
func wsSubprotocol(r *http.Request) string {
	for _, v := range r.Header.Values("Sec-Websocket-Protocol") {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "binary") {
				return "binary"
			}
		}
	}
	return ""
}

// wsUpgrade validates the handshake, hijacks the connection and writes the 101.
//
// It returns a [statusError] rather than a bare error for every client-side
// mistake, so a browser or a curl that stumbles into this endpoint gets
// Docker's {"message": …} shape and not a hung socket.
func wsUpgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !headerHasToken(r.Header, "Connection", "upgrade") ||
		!strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return nil, errBadParameter("this endpoint requires a WebSocket upgrade: " +
			"send Connection: Upgrade and Upgrade: websocket")
	}
	if v := strings.TrimSpace(r.Header.Get("Sec-Websocket-Version")); v != "13" {
		return nil, errBadParameter(
			"unsupported WebSocket version %q: hull speaks version 13", v)
	}
	key := strings.TrimSpace(r.Header.Get("Sec-Websocket-Key"))
	if key == "" {
		return nil, errBadParameter("the WebSocket handshake is missing Sec-WebSocket-Key")
	}

	rc := http.NewResponseController(w)
	conn, brw, err := rc.Hijack()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNotHijackable, err)
	}

	var b strings.Builder
	b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Accept: " + wsAcceptKey(key) + "\r\n")
	if proto := wsSubprotocol(r); proto != "" {
		b.WriteString("Sec-WebSocket-Protocol: " + proto + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("api: write the WebSocket handshake: %w", err)
	}
	return &wsConn{conn: conn, br: brw.Reader}, nil
}

// wsConn is a server-side WebSocket connection presented as an io.ReadWriter.
//
// Read yields the payload of data frames with control frames handled
// transparently; Write sends one binary frame per call. That is exactly the
// shape the engine's attach path wants, so the same code that drives a raw
// hijack drives this with no special cases.
type wsConn struct {
	conn net.Conn
	br   *bufio.Reader

	// pending is the unread remainder of the last data frame.
	pending []byte
	// readErr latches the first read failure so a second Read does not
	// resurrect a dead connection.
	readErr error

	// mu serialises writes: the engine may write stdout and stderr from two
	// goroutines, and a WebSocket frame must not be interleaved.
	mu     sync.Mutex
	closed bool
}

// Read returns payload bytes from the client's data frames.
//
// Control frames never reach the caller: a ping is answered, a pong is
// dropped, and a close ends the stream with io.EOF — which is what tells the
// container's stdin that the client is finished.
func (c *wsConn) Read(p []byte) (int, error) {
	for {
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}
		if c.readErr != nil {
			return 0, c.readErr
		}
		opcode, payload, err := c.readFrame()
		if err != nil {
			c.readErr = err
			return 0, err
		}
		switch opcode {
		case wsOpText, wsOpBinary, wsOpContinuation:
			if len(payload) == 0 {
				continue
			}
			c.pending = payload
		case wsOpPing:
			if err := c.writeFrame(wsOpPong, payload); err != nil {
				c.readErr = err
				return 0, err
			}
		case wsOpPong:
			// Nothing to do; an unsolicited pong is legal.
		case wsOpClose:
			_ = c.writeFrame(wsOpClose, closePayload(payload))
			c.readErr = io.EOF
			return 0, io.EOF
		default:
			c.readErr = fmt.Errorf("api: websocket opcode %#x is not supported", opcode)
			return 0, c.readErr
		}
	}
}

// closePayload echoes a close frame's status code back, which is what the
// spec asks a server to do, while dropping any reason text.
func closePayload(in []byte) []byte {
	if len(in) < 2 {
		return nil
	}
	return in[:2]
}

// Write sends p as one binary frame.
func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeFrame(wsOpBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close sends a normal-closure frame and closes the connection.
func (c *wsConn) Close() error {
	c.mu.Lock()
	already := c.closed
	c.closed = true
	c.mu.Unlock()
	if already {
		return nil
	}
	var normal [2]byte
	binary.BigEndian.PutUint16(normal[:], 1000)
	_ = c.writeFrame(wsOpClose, normal[:])
	return c.conn.Close()
}

// readFrame reads one frame, unmasking its payload.
//
// Fragmentation is handled by the caller: a continuation frame is delivered
// like any other data frame, which is correct for a byte stream where the
// message boundaries carry no meaning.
func (c *wsConn) readFrame() (byte, []byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(c.br, head[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF
		}
		return 0, nil, err
	}
	opcode := head[0] & 0x0F
	masked := head[1]&0x80 != 0
	length := int64(head[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		v := binary.BigEndian.Uint64(ext[:])
		if v > uint64(wsMaxPayload) {
			return 0, nil, fmt.Errorf("api: websocket frame of %d bytes exceeds the %d byte limit",
				v, wsMaxPayload)
		}
		length = int64(v)
	}
	if length > wsMaxPayload {
		return 0, nil, fmt.Errorf("api: websocket frame of %d bytes exceeds the %d byte limit",
			length, wsMaxPayload)
	}
	if opcode >= wsOpClose && length > wsMaxControlPayload {
		return 0, nil, fmt.Errorf("api: websocket control frame of %d bytes exceeds %d",
			length, wsMaxControlPayload)
	}
	// RFC 6455 requires every client-to-server frame to be masked. Accepting
	// an unmasked one would let a crafted HTTP request from a browser be
	// replayed as WebSocket traffic, which is the whole reason masking
	// exists.
	if !masked {
		return 0, nil, errors.New("api: the client sent an unmasked WebSocket frame")
	}

	var mask [4]byte
	if _, err := io.ReadFull(c.br, mask[:]); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return opcode, payload, nil
}

// writeFrame sends one unmasked frame. A server must never mask.
func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	header := make([]byte, 0, 10)
	header = append(header, 0x80|opcode) // FIN set: hull never fragments.
	switch n := len(payload); {
	case n < 126:
		header = append(header, byte(n))
	case n <= 0xFFFF:
		header = append(header, 126, byte(n>>8), byte(n))
	default:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		header = append(header, 127)
		header = append(header, ext[:]...)
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := c.conn.Write(payload)
	return err
}
