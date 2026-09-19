package wslbridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// testTimeout bounds anything in this file that waits, so a protocol bug shows
// up as a failed test rather than a hung CI run.
const testTimeout = 10 * time.Second

// sessionPair wires a client and a server session together over net.Pipe and
// tears both down when the test ends.
func sessionPair(t *testing.T, window, maxFrame int) (client, server *Session) {
	t.Helper()
	a, b := net.Pipe()
	client = NewSession(a, SessionOptions{Window: window, MaxFrame: maxFrame, OpenTimeout: testTimeout})
	server = NewSession(b, SessionOptions{Server: true, Window: window, MaxFrame: maxFrame, OpenTimeout: testTimeout})
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// readRawFrame reads one frame off the wire, header first.
func readRawFrame(t *testing.T, r io.Reader) (uint32, []byte) {
	t.Helper()
	var hdr [FrameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	id := binary.BigEndian.Uint32(hdr[0:4])
	n := binary.BigEndian.Uint32(hdr[4:8])
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			t.Fatalf("read frame payload: %v", err)
		}
	}
	return id, payload
}

// writeRawControl writes one control frame by hand, so the test encodes the
// wire format independently of the code under test.
func writeRawControl(t *testing.T, w io.Writer, kind frameKind, id uint32, extra []byte) {
	t.Helper()
	payload := make([]byte, controlHeaderSize+len(extra))
	payload[0] = byte(kind)
	binary.BigEndian.PutUint32(payload[1:5], id)
	copy(payload[controlHeaderSize:], extra)
	writeRawFrame(t, w, ControlStream, payload)
}

// writeRawFrame writes one frame by hand.
func writeRawFrame(t *testing.T, w io.Writer, id uint32, payload []byte) {
	t.Helper()
	var hdr [FrameHeaderSize]byte
	binary.BigEndian.PutUint32(hdr[0:4], id)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
	if _, err := w.Write(append(hdr[:], payload...)); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func TestParseControl(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		payload []byte
		want    control
		wantErr bool
	}{
		{
			name:    "open with a window",
			payload: append([]byte{byte(kindOpen), 0, 0, 0, 7}, 0, 1, 0, 0),
			want:    control{kind: kindOpen, id: 7, extra: []byte{0, 1, 0, 0}},
		},
		{
			name:    "close with no extra",
			payload: []byte{byte(kindClose), 0, 0, 0, 3},
			want:    control{kind: kindClose, id: 3, extra: []byte{}},
		},
		{
			name:    "reset carries a reason",
			payload: append([]byte{byte(kindReset), 0, 0, 0, 9}, []byte("dial failed")...),
			want:    control{kind: kindReset, id: 9, extra: []byte("dial failed")},
		},
		{
			name:    "truncated header",
			payload: []byte{byte(kindOpen), 0, 0},
			wantErr: true,
		},
		{
			name:    "empty payload",
			payload: nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseControl(tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseControl(%v) = %+v, want an error", tt.payload, got)
				}
				if !errors.Is(err, ErrProtocol) {
					t.Fatalf("error %v does not wrap ErrProtocol", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseControl: %v", err)
			}
			if got.kind != tt.want.kind || got.id != tt.want.id || !bytes.Equal(got.extra, tt.want.extra) {
				t.Fatalf("parseControl = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestFrameKindString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind frameKind
		want string
	}{
		{kindOpen, "open"},
		{kindAck, "ack"},
		{kindClose, "close"},
		{kindReset, "reset"},
		{kindWindow, "window"},
		{frameKind(99), "kind(99)"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("frameKind(%d).String() = %q, want %q", uint8(tt.kind), got, tt.want)
		}
	}
}

// TestCodecRoundTripOnTheWire drives a real session against hand-written frames,
// so the encoder and the decoder are checked against the documented layout
// rather than against each other.
func TestCodecRoundTripOnTheWire(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	sess := NewSession(a, SessionOptions{Window: 4096, MaxFrame: 128, OpenTimeout: testTimeout})
	defer sess.Close()

	type opened struct {
		stream *Stream
		err    error
	}
	opens := make(chan opened, 1)
	go func() {
		st, err := sess.Open(context.Background())
		opens <- opened{st, err}
	}()

	// The open frame: control stream, kind open, first client id, and the
	// advertised receive window.
	id, payload := readRawFrame(t, b)
	if id != ControlStream {
		t.Fatalf("open arrived on stream %d, want the control stream", id)
	}
	c, err := parseControl(payload)
	if err != nil {
		t.Fatalf("parse open: %v", err)
	}
	if c.kind != kindOpen {
		t.Fatalf("first frame is %s, want open", c.kind)
	}
	if c.id != 1 {
		t.Fatalf("first client stream id is %d, want 1 (odd ids are the client's)", c.id)
	}
	if got := binary.BigEndian.Uint32(c.extra); got != 4096 {
		t.Fatalf("open advertised a window of %d, want 4096", got)
	}

	// Acknowledge it, advertising a small window of our own.
	writeRawControl(t, b, kindAck, c.id, beUint32(64))
	got := <-opens
	if got.err != nil {
		t.Fatalf("Open: %v", got.err)
	}
	stream := got.stream

	// Data frames carry no kind byte at all.
	done := make(chan error, 1)
	go func() {
		_, err := stream.Write([]byte("hello engine"))
		done <- err
	}()
	id, payload = readRawFrame(t, b)
	if id != c.id {
		t.Fatalf("data arrived on stream %d, want %d", id, c.id)
	}
	if string(payload) != "hello engine" {
		t.Fatalf("payload = %q, want %q", payload, "hello engine")
	}
	if err := <-done; err != nil {
		t.Fatalf("Write: %v", err)
	}

	// A data frame in the other direction. The Read happens in a goroutine
	// because consuming bytes returns credit to the peer, and on an unbuffered
	// pipe that window frame has to be collected before Read can return.
	writeRawFrame(t, b, c.id, []byte("hello client"))
	type readResult struct {
		n   int
		err error
	}
	reads := make(chan readResult, 1)
	buf := make([]byte, 64)
	go func() {
		n, err := stream.Read(buf)
		reads <- readResult{n, err}
	}()

	id, payload = readRawFrame(t, b)
	if id != ControlStream {
		t.Fatalf("expected a window frame on the control stream, got stream %d", id)
	}
	credit, err := parseControl(payload)
	if err != nil {
		t.Fatalf("parse window: %v", err)
	}
	if credit.kind != kindWindow || credit.id != c.id {
		t.Fatalf("got %s for stream %d, want a window frame for stream %d", credit.kind, credit.id, c.id)
	}
	if got := binary.BigEndian.Uint32(credit.extra); got != uint32(len("hello client")) {
		t.Fatalf("window credit = %d, want %d", got, len("hello client"))
	}

	r := <-reads
	if r.err != nil {
		t.Fatalf("Read: %v", r.err)
	}
	if string(buf[:r.n]) != "hello client" {
		t.Fatalf("Read = %q, want %q", buf[:r.n], "hello client")
	}
	writeRawControl(t, b, kindClose, c.id, nil)
	if _, err := stream.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after a close frame = %v, want io.EOF", err)
	}
}

// TestSessionInterleavedStreams checks that concurrent streams do not leak bytes
// into one another, which is the one failure a byte relay must never have.
func TestSessionInterleavedStreams(t *testing.T) {
	t.Parallel()
	client, server := sessionPair(t, 8*1024, 256)

	// The server echoes every stream, prefixed with its own id, until EOF.
	go func() {
		for {
			st, err := server.Accept(context.Background())
			if err != nil {
				return
			}
			go func(st *Stream) {
				defer st.Close()
				if err := st.Confirm(); err != nil {
					return
				}
				body, err := io.ReadAll(st)
				if err != nil {
					return
				}
				_, _ = st.Write(append([]byte("echo:"), body...))
				_ = st.CloseWrite()
			}(st)
		}
	}()

	const streams = 8
	payloads := make([]string, streams)
	for i := range payloads {
		payloads[i] = strings.Repeat(string(rune('a'+i)), 900)
	}

	var wg sync.WaitGroup
	errs := make(chan error, streams)
	for i := range streams {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			st, err := client.Open(ctx)
			if err != nil {
				errs <- err
				return
			}
			defer st.Close()
			if _, err := io.WriteString(st, payloads[i]); err != nil {
				errs <- err
				return
			}
			if err := st.CloseWrite(); err != nil {
				errs <- err
				return
			}
			got, err := io.ReadAll(st)
			if err != nil {
				errs <- err
				return
			}
			if want := "echo:" + payloads[i]; string(got) != want {
				errs <- errors.New("stream " + st.LocalAddr().String() + " got the wrong body")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("stream failed: %v", err)
	}
}

// TestStreamBackpressure checks that a writer stops when the peer's window is
// full and resumes when the reader drains it. Without this a slow "docker logs"
// consumer would let the relay buffer without limit.
func TestStreamBackpressure(t *testing.T) {
	t.Parallel()
	const window = 64
	client, server := sessionPair(t, window, 16)

	accepted := make(chan *Stream, 1)
	go func() {
		st, err := server.Accept(context.Background())
		if err != nil {
			return
		}
		_ = st.Confirm()
		accepted <- st
	}()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var peer *Stream
	select {
	case peer = <-accepted:
	case <-time.After(testTimeout):
		t.Fatal("server never accepted the stream")
	}

	const total = window * 4
	written := make(chan error, 1)
	go func() {
		_, err := stream.Write(bytes.Repeat([]byte{'x'}, total))
		written <- err
	}()

	// The writer must not be able to finish: only a window's worth can be in
	// flight while the reader is idle.
	select {
	case err := <-written:
		t.Fatalf("Write of %d bytes finished with a %d byte window (err=%v); there is no backpressure", total, window, err)
	case <-time.After(150 * time.Millisecond):
	}

	// Draining the receive buffer returns credit and lets the writer continue.
	got, err := io.ReadFull(peer, make([]byte, total))
	if err != nil {
		t.Fatalf("read %d bytes: %v", got, err)
	}
	select {
	case err := <-written:
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Write never completed after the reader drained the window")
	}
}

// TestStreamResetOnOpen is the relay's failure path: the engine socket cannot be
// dialled, and the reason has to reach the Windows client.
func TestStreamResetOnOpen(t *testing.T) {
	t.Parallel()
	client, server := sessionPair(t, 4096, 256)

	go func() {
		st, err := server.Accept(context.Background())
		if err != nil {
			return
		}
		_ = st.Reset(errors.New("dial /run/hull/hull.sock: no such file or directory"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	_, err := client.Open(ctx)
	if err == nil {
		t.Fatal("Open succeeded against a stream the peer reset")
	}
	var reset *ResetError
	if !errors.As(err, &reset) {
		t.Fatalf("Open error %v is not a *ResetError", err)
	}
	if !strings.Contains(reset.Reason, "no such file") {
		t.Fatalf("reset reason %q lost the peer's explanation", reset.Reason)
	}
}

// TestStreamResetMidStream checks that a reset after the stream is running
// reaches both a blocked reader and a later writer.
func TestStreamResetMidStream(t *testing.T) {
	t.Parallel()
	client, server := sessionPair(t, 4096, 256)

	accepted := make(chan *Stream, 1)
	go func() {
		st, err := server.Accept(context.Background())
		if err != nil {
			return
		}
		_ = st.Confirm()
		accepted <- st
	}()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	peer := <-accepted

	readErr := make(chan error, 1)
	go func() {
		_, err := stream.Read(make([]byte, 16))
		readErr <- err
	}()
	_ = peer.Reset(errors.New("engine went away"))

	select {
	case err := <-readErr:
		var reset *ResetError
		if !errors.As(err, &reset) {
			t.Fatalf("Read error %v is not a *ResetError", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("a blocked Read did not notice the reset")
	}
	if _, err := stream.Write([]byte("more")); err == nil {
		t.Fatal("Write succeeded on a reset stream")
	}
}

// TestStreamHalfClose is the shape every HTTP request has: the client finishes
// its body, the server answers, and neither direction may cut the other off.
func TestStreamHalfClose(t *testing.T) {
	t.Parallel()
	client, server := sessionPair(t, 4096, 256)

	go func() {
		st, err := server.Accept(context.Background())
		if err != nil {
			return
		}
		_ = st.Confirm()
		body, err := io.ReadAll(st)
		if err != nil {
			return
		}
		_, _ = st.Write([]byte("got " + string(body)))
		_ = st.CloseWrite()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := io.WriteString(stream, "request"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if _, err := stream.Write([]byte("late")); err == nil {
		t.Fatal("Write succeeded after CloseWrite")
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "got request" {
		t.Fatalf("response = %q, want %q", got, "got request")
	}
}

func TestStreamReadDeadline(t *testing.T) {
	t.Parallel()
	client, server := sessionPair(t, 4096, 256)

	go func() {
		st, err := server.Accept(context.Background())
		if err != nil {
			return
		}
		_ = st.Confirm()
		<-server.Done()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	if _, err := stream.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > testTimeout/2 {
		t.Fatalf("Read took %s to hit a 50ms deadline", elapsed)
	}
	// Clearing the deadline must make the stream usable again.
	if err := stream.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("re-arm deadline: %v", err)
	}
	if _, err := stream.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read after re-arming = %v, want os.ErrDeadlineExceeded", err)
	}
}

// TestSessionCloseFailsStreams checks that a dead relay child surfaces on every
// stream instead of hanging them.
func TestSessionCloseFailsStreams(t *testing.T) {
	t.Parallel()
	client, server := sessionPair(t, 4096, 256)

	go func() {
		st, err := server.Accept(context.Background())
		if err != nil {
			return
		}
		_ = st.Confirm()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := stream.Read(make([]byte, 8))
		readErr <- err
	}()
	_ = client.Close()

	select {
	case err := <-readErr:
		if !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("Read after session close = %v, want ErrSessionClosed", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("a blocked Read did not notice the session closing")
	}
	if _, err := client.Open(ctx); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Open on a closed session = %v, want ErrSessionClosed", err)
	}
}

// TestSessionRejectsOversizedFrame checks the guard that stops a peer naming a
// frame larger than the agreed maximum.
func TestSessionRejectsOversizedFrame(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	sess := NewSession(a, SessionOptions{Window: 1024, MaxFrame: 64})
	defer sess.Close()

	var hdr [FrameHeaderSize]byte
	binary.BigEndian.PutUint32(hdr[0:4], 3)
	binary.BigEndian.PutUint32(hdr[4:8], 1<<20)
	go func() { _, _ = b.Write(hdr[:]) }()

	select {
	case <-sess.Done():
		if err := sess.Err(); !errors.Is(err, ErrProtocol) {
			t.Fatalf("session ended with %v, want ErrProtocol", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("session accepted a frame larger than its maximum")
	}
}

// TestServerSessionRefusesOpen keeps the id-parity rule honest.
func TestServerSessionRefusesOpen(t *testing.T) {
	t.Parallel()
	_, server := sessionPair(t, 1024, 64)
	if _, err := server.Open(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("server Open = %v, want ErrProtocol", err)
	}
}
