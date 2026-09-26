package api

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ChPuru/hull/internal/engine"
	"github.com/ChPuru/hull/internal/types"
)

func TestWSAcceptKey(t *testing.T) {
	t.Parallel()
	// The example from RFC 6455 section 1.3, which is the only way to be sure
	// the concatenation and the digest are both right.
	if got, want := wsAcceptKey("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="; got != want {
		t.Errorf("wsAcceptKey = %q, want %q", got, want)
	}
	// Surrounding whitespace is trimmed, not hashed.
	if got := wsAcceptKey("  dGhlIHNhbXBsZSBub25jZQ==  "); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Errorf("wsAcceptKey did not trim its input: %q", got)
	}
}

func TestHeaderHasToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		values []string
		token  string
		want   bool
	}{
		{name: "exact", values: []string{"Upgrade"}, token: "upgrade", want: true},
		{name: "in a list", values: []string{"keep-alive, Upgrade"}, token: "upgrade", want: true},
		{name: "repeated header", values: []string{"keep-alive", "Upgrade"}, token: "upgrade", want: true},
		{name: "absent", values: []string{"keep-alive"}, token: "upgrade"},
		{name: "no header at all", token: "upgrade"},
		{name: "substring is not a token", values: []string{"upgraded"}, token: "upgrade"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := http.Header{}
			for _, v := range tc.values {
				h.Add("Connection", v)
			}
			if got := headerHasToken(h, "Connection", tc.token); got != tc.want {
				t.Errorf("headerHasToken(%v) = %v, want %v", tc.values, got, tc.want)
			}
		})
	}
}

func TestWSSubprotocol(t *testing.T) {
	t.Parallel()
	tests := []struct {
		offer string
		want  string
	}{
		{offer: "", want: ""},
		{offer: "binary", want: "binary"},
		{offer: "chat, BINARY", want: "binary"},
		{offer: "chat, superchat", want: ""},
	}
	for _, tc := range tests {
		t.Run("offer="+tc.offer, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/containers/x/attach/ws", nil)
			if tc.offer != "" {
				r.Header.Set("Sec-WebSocket-Protocol", tc.offer)
			}
			if got := wsSubprotocol(r); got != tc.want {
				t.Errorf("wsSubprotocol(%q) = %q, want %q", tc.offer, got, tc.want)
			}
		})
	}
}

func TestAttachWSRejectsANonWebSocketRequest(t *testing.T) {
	t.Parallel()
	s, be := newTestServer(t)
	be.addContainer(&types.Container{
		ID:              "d00d000000000000000000000000000000000000000000000000000000000000",
		Name:            "web",
		State:           types.StateRunning,
		NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{}},
	})

	tests := []struct {
		name    string
		headers map[string]string
		want    int
		body    string
	}{
		{
			name: "no upgrade at all",
			want: http.StatusBadRequest,
			body: "requires a WebSocket upgrade",
		},
		{
			name: "wrong version",
			headers: map[string]string{
				"Connection": "Upgrade", "Upgrade": "websocket",
				"Sec-WebSocket-Version": "8", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
			},
			want: http.StatusBadRequest,
			body: "version 13",
		},
		{
			name: "missing key",
			headers: map[string]string{
				"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
			},
			want: http.StatusBadRequest,
			body: "Sec-WebSocket-Key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/v1.43/containers/web/attach/ws?stdout=1", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.body) {
				t.Errorf("body = %q, want it to mention %q", rec.Body.String(), tc.body)
			}
		})
	}
}

func TestAttachWSMissingContainerIs404(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	rec := do(t, s, http.MethodGet, "/v1.43/containers/ghost/attach/ws", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No such container") {
		t.Errorf("body = %q, want \"No such container\"", rec.Body.String())
	}
}

func TestAttachWSStoppedContainerIs409(t *testing.T) {
	t.Parallel()
	s, be := newTestServer(t)
	be.addContainer(&types.Container{
		ID:              "dead000000000000000000000000000000000000000000000000000000000000",
		Name:            "stopped",
		State:           types.StateExited,
		NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{}},
	})
	rec := do(t, s, http.MethodGet, "/v1.43/containers/stopped/attach/ws?stdout=1", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (%s)", rec.Code, rec.Body.String())
	}
}

// TestAttachWSHandshakeAndFrames drives the whole transport over a real
// socket: the 101, the computed accept key, a masked client frame arriving as
// container stdin, and the container's output coming back as binary frames.
func TestAttachWSHandshakeAndFrames(t *testing.T) {
	t.Parallel()
	s, be := newTestServer(t)
	be.addContainer(&types.Container{
		ID:              "beef000000000000000000000000000000000000000000000000000000000000",
		Name:            "web",
		State:           types.StateRunning,
		NetworkSettings: types.NetworkSettings{Networks: map[string]types.EndpointSettings{}},
	})

	got := make(chan string, 1)
	be.attachFn = func(_ context.Context, _ string, opts engine.AttachConfig) error {
		buf := make([]byte, len("hello"))
		n, err := io.ReadFull(opts.Stdin, buf)
		if err != nil {
			return err
		}
		got <- string(buf[:n])
		_, err = opts.Stdout.Write([]byte("pong-from-container"))
		return err
	}

	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(hs.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	req := "GET /v1.43/containers/web/attach/ws?stream=1&stdin=1&stdout=1 HTTP/1.1\r\n" +
		"Host: hull\r\n" +
		"Connection: keep-alive, Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: binary\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if strings.TrimRight(line, "\r\n") != "HTTP/1.1 101 Switching Protocols" {
		t.Fatalf("status line = %q", strings.TrimRight(line, "\r\n"))
	}
	headers := map[string]string{}
	for {
		h, herr := br.ReadString('\n')
		if herr != nil {
			t.Fatalf("read header: %v", herr)
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break
		}
		k, v, _ := strings.Cut(h, ": ")
		headers[http.CanonicalHeaderKey(k)] = v
	}
	if want := wsAcceptKey(key); headers["Sec-Websocket-Accept"] != want {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q", headers["Sec-Websocket-Accept"], want)
	}
	if !strings.EqualFold(headers["Upgrade"], "websocket") {
		t.Errorf("Upgrade = %q, want websocket", headers["Upgrade"])
	}
	if headers["Sec-Websocket-Protocol"] != "binary" {
		t.Errorf("Sec-WebSocket-Protocol = %q, want binary", headers["Sec-Websocket-Protocol"])
	}

	if _, err := conn.Write(clientFrame(wsOpBinary, []byte("hello"))); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	select {
	case in := <-got:
		if in != "hello" {
			t.Errorf("container stdin = %q, want %q", in, "hello")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the container never received the client's frame")
	}

	opcode, payload, err := readServerFrame(br)
	if err != nil {
		t.Fatalf("read server frame: %v", err)
	}
	if opcode != wsOpBinary {
		t.Errorf("opcode = %#x, want binary", opcode)
	}
	if string(payload) != "pong-from-container" {
		t.Errorf("payload = %q, want %q", payload, "pong-from-container")
	}
}

func TestWSFrameRoundTrip(t *testing.T) {
	t.Parallel()
	sizes := []int{0, 1, 125, 126, 1000, 70000}
	for _, size := range sizes {
		t.Run("size="+itoa(size), func(t *testing.T) {
			t.Parallel()
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()

			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i % 251)
			}

			ws := &wsConn{conn: server, br: bufio.NewReader(server)}
			go func() {
				_, _ = ws.Write(payload)
			}()

			opcode, got, err := readServerFrame(bufio.NewReader(client))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if opcode != wsOpBinary {
				t.Fatalf("opcode = %#x", opcode)
			}
			if len(got) != size || string(got) != string(payload) {
				t.Fatalf("payload round trip failed at size %d", size)
			}
		})
	}
}

func TestWSReadHandlesControlFrames(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	ws := &wsConn{conn: server, br: bufio.NewReader(server)}
	go func() {
		_, _ = client.Write(clientFrame(wsOpPing, []byte("are you there")))
		_, _ = client.Write(clientFrame(wsOpBinary, []byte("data")))
		var normal [2]byte
		binary.BigEndian.PutUint16(normal[:], 1000)
		_, _ = client.Write(clientFrame(wsOpClose, normal[:]))
	}()

	// The pong goes out before the data arrives, so it is read first.
	cr := bufio.NewReader(client)
	done := make(chan struct{})
	var pongOp byte
	var pongPayload []byte
	go func() {
		defer close(done)
		pongOp, pongPayload, _ = readServerFrame(cr)
	}()

	buf := make([]byte, 16)
	n, err := ws.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "data" {
		t.Fatalf("Read = %q, want %q", buf[:n], "data")
	}
	<-done
	if pongOp != wsOpPong || string(pongPayload) != "are you there" {
		t.Errorf("pong = %#x %q, want an echoed ping payload", pongOp, pongPayload)
	}

	// Draining the close frame ends the stream with EOF, which is what gives
	// a container's stdin its end of file.
	go func() { _, _, _ = readServerFrame(cr) }()
	if _, err := ws.Read(buf); err != io.EOF {
		t.Errorf("Read after close = %v, want io.EOF", err)
	}
	// A second read must not resurrect the connection.
	if _, err := ws.Read(buf); err != io.EOF {
		t.Errorf("second Read = %v, want io.EOF", err)
	}
}

func TestWSRejectsAnUnmaskedClientFrame(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	ws := &wsConn{conn: server, br: bufio.NewReader(server)}
	go func() {
		// A server-shaped (unmasked) frame from the client side: exactly what
		// a replayed browser request would look like.
		_, _ = client.Write([]byte{0x80 | wsOpBinary, 4, 'd', 'a', 't', 'a'})
	}()
	if _, err := ws.Read(make([]byte, 8)); err == nil {
		t.Fatal("an unmasked client frame was accepted")
	}
}

func TestWSRejectsAnOversizedFrame(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	ws := &wsConn{conn: server, br: bufio.NewReader(server)}
	go func() {
		head := []byte{0x80 | wsOpBinary, 0x80 | 127}
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(wsMaxPayload)+1)
		_, _ = client.Write(append(head, ext[:]...))
	}()
	if _, err := ws.Read(make([]byte, 8)); err == nil {
		t.Fatal("a frame larger than the limit was accepted")
	}
}

// --- helpers ---

// clientFrame builds a masked frame, the way a conforming client must.
func clientFrame(opcode byte, payload []byte) []byte {
	out := []byte{0x80 | opcode}
	switch n := len(payload); {
	case n < 126:
		out = append(out, 0x80|byte(n))
	case n <= 0xFFFF:
		out = append(out, 0x80|126, byte(n>>8), byte(n))
	default:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		out = append(out, 0x80|127)
		out = append(out, ext[:]...)
	}
	mask := [4]byte{0x37, 0xfa, 0x21, 0x3d}
	out = append(out, mask[:]...)
	for i, b := range payload {
		out = append(out, b^mask[i%4])
	}
	return out
}

// readServerFrame reads one unmasked server frame.
func readServerFrame(br *bufio.Reader) (byte, []byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return 0, nil, err
	}
	opcode := head[0] & 0x0F
	length := int(head[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = int(binary.BigEndian.Uint64(ext[:]))
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		return 0, nil, err
	}
	return opcode, payload, nil
}

// itoa avoids importing strconv for one call in a subtest name.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
