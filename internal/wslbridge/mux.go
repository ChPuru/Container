package wslbridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// The multiplexer exists because a "wsl.exe --exec" child gives hull exactly one
// byte stream -- the child's stdin and stdout -- while the Docker API needs many
// concurrent connections: a "docker logs -f" holds one open for hours while
// "docker ps" comes and goes. Spawning one wsl.exe per API connection would be
// both slow and a lifecycle hazard, so every connection instead becomes a stream
// inside one long-lived relay process.
//
// Wire format, big-endian throughout:
//
//	[4-byte stream id][4-byte payload length][payload]
//
// Stream id 0 is the control stream. Its payload is
//
//	[1-byte kind][4-byte stream id][kind-specific extra]
//
// which keeps the frame header uniform while still giving open/close/reset a
// place to live. Data frames carry no kind byte at all, so the relay's hot path
// copies bytes and nothing else.

const (
	// FrameHeaderSize is the fixed frame header: a 4-byte big-endian stream id
	// followed by a 4-byte big-endian payload length.
	FrameHeaderSize = 8

	// ControlStream is the stream id reserved for control frames. No data
	// stream is ever allocated this id.
	ControlStream uint32 = 0

	// DefaultMaxFrame is the largest data payload a single frame carries. 32 KiB
	// is comfortably above a pipe read and well below the point where a single
	// stream would monopolise the shared link.
	DefaultMaxFrame = 32 * 1024

	// DefaultWindow is the per-stream receive window: how many bytes a peer may
	// send before it must wait for the reader to consume them. This is what
	// stops one idle "docker logs" consumer from stalling every other stream,
	// and what stops the relay buffering an unbounded image pull in memory.
	DefaultWindow = 256 * 1024

	// controlHeaderSize is the kind byte plus the 4-byte stream id that every
	// control payload starts with.
	controlHeaderSize = 5

	// maxResetReason bounds the reason text carried by a reset frame, so a
	// hostile or buggy peer cannot make a control frame arbitrarily large.
	maxResetReason = 512

	// acceptBacklog is how many peer-opened streams may wait for Accept before
	// further opens are refused with a reset.
	acceptBacklog = 64
)

// frameKind identifies a control frame.
type frameKind uint8

const (
	kindOpen   frameKind = 1 // open a stream
	kindAck    frameKind = 2 // the acceptor took the stream and it is usable
	kindClose  frameKind = 3 // half-close: the sender will send no more data
	kindReset  frameKind = 4 // abort the stream, with an optional reason
	kindWindow frameKind = 5 // grant the peer more send credit
)

// String names a control frame kind, for errors and debug logs.
func (k frameKind) String() string {
	switch k {
	case kindOpen:
		return "open"
	case kindAck:
		return "ack"
	case kindClose:
		return "close"
	case kindReset:
		return "reset"
	case kindWindow:
		return "window"
	default:
		return fmt.Sprintf("kind(%d)", uint8(k))
	}
}

// Errors returned by the multiplexer.
var (
	// ErrSessionClosed is returned once the session's underlying connection is
	// gone: the relay child exited, the pipe broke, or Close was called.
	ErrSessionClosed = errors.New("wslbridge: session closed")

	// ErrStreamClosed is returned by operations on a stream this side closed.
	ErrStreamClosed = errors.New("wslbridge: stream closed")

	// ErrProtocol reports a frame the peer should never have sent. It always
	// tears the whole session down: a desynchronised byte stream cannot be
	// resynchronised.
	ErrProtocol = errors.New("wslbridge: protocol error")
)

// ResetError is the error a stream's Read and Write return after the peer reset
// it. Reason carries the peer's explanation -- for the relay that is usually the
// unix-socket dial failure, which is exactly what the Windows side needs to show
// the user.
type ResetError struct {
	// StreamID is the stream the peer reset.
	StreamID uint32
	// Reason is the peer's text, which may be empty.
	Reason string
}

// Error implements error.
func (e *ResetError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("wslbridge: stream %d reset by peer", e.StreamID)
	}
	return fmt.Sprintf("wslbridge: stream %d reset by peer: %s", e.StreamID, e.Reason)
}

// SessionOptions configures a Session.
type SessionOptions struct {
	// Server makes this side the acceptor: it never allocates stream ids of its
	// own and delivers peer-opened streams through Accept. The relay inside WSL
	// is the server; hull.exe on Windows is the client.
	Server bool
	// Window is the per-stream receive window in bytes. Zero means DefaultWindow.
	Window int
	// MaxFrame is the largest data payload per frame. Zero means DefaultMaxFrame.
	MaxFrame int
	// OpenTimeout bounds how long Open waits for the peer to acknowledge a new
	// stream. Zero means 30s.
	OpenTimeout time.Duration
	// Logger receives protocol-level diagnostics. Zero means a discarding logger.
	Logger *slog.Logger
}

// withDefaults fills in the zero values.
func (o SessionOptions) withDefaults() SessionOptions {
	if o.Window <= 0 {
		o.Window = DefaultWindow
	}
	if o.MaxFrame <= 0 {
		o.MaxFrame = DefaultMaxFrame
	}
	if o.OpenTimeout <= 0 {
		o.OpenTimeout = 30 * time.Second
	}
	if o.Logger == nil {
		o.Logger = discardLogger()
	}
	return o
}

// Session multiplexes many streams over one duplex byte connection.
//
// It is safe for concurrent use. Exactly one goroutine reads the underlying
// connection; writes are serialised by a mutex, so one frame never interleaves
// with another.
type Session struct {
	conn io.ReadWriteCloser
	opts SessionOptions

	wmu  sync.Mutex // serialises whole frames onto conn
	wbuf []byte

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	err     error

	accept    chan *Stream
	done      chan struct{}
	closeOnce sync.Once
}

// NewSession starts a multiplexer over conn and begins reading frames from it
// immediately. Closing the Session closes conn.
func NewSession(conn io.ReadWriteCloser, opts SessionOptions) *Session {
	opts = opts.withDefaults()
	s := &Session{
		conn:    conn,
		opts:    opts,
		streams: make(map[uint32]*Stream),
		// Client streams are odd and server streams even, so both ends could
		// open streams without ever colliding.
		nextID: 1,
		accept: make(chan *Stream, acceptBacklog),
		done:   make(chan struct{}),
	}
	if opts.Server {
		s.nextID = 2
	}
	go s.readLoop()
	return s
}

// Done is closed when the session ends, for any reason.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err reports why the session ended, or nil while it is still running.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close tears the session down and closes the underlying connection. Every
// stream fails with the session's error afterwards.
func (s *Session) Close() error {
	s.closeWithError(ErrSessionClosed)
	return nil
}

// closeWithError ends the session once, recording the first cause.
func (s *Session) closeWithError(cause error) {
	s.closeOnce.Do(func() {
		if cause == nil {
			cause = ErrSessionClosed
		}
		s.mu.Lock()
		s.err = cause
		streams := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.streams = map[uint32]*Stream{}
		s.mu.Unlock()

		close(s.done)
		for _, st := range streams {
			st.fail(cause)
		}
		_ = s.conn.Close()
	})
}

// Open allocates a stream and waits for the peer to acknowledge it. The wait is
// what turns a failed unix-socket dial inside WSL into an error on the very
// first Dial, instead of an unexplained EOF several hundred bytes into an HTTP
// request.
func (s *Session) Open(ctx context.Context) (*Stream, error) {
	if s.opts.Server {
		// Nothing in the protocol stops a server opening streams, but hull's
		// relay never does, and refusing keeps the id parity scheme honest.
		return nil, fmt.Errorf("wslbridge: open on a server session: %w", ErrProtocol)
	}

	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return nil, err
	}
	id := s.nextID
	s.nextID += 2
	st := newStream(s, id, false)
	s.streams[id] = st
	s.mu.Unlock()

	if err := s.writeControl(kindOpen, id, beUint32(uint32(s.opts.Window))); err != nil {
		s.removeStream(id)
		return nil, err
	}

	timer := time.NewTimer(s.opts.OpenTimeout)
	defer timer.Stop()
	select {
	case <-st.acked:
		if err := st.openError(); err != nil {
			s.removeStream(id)
			return nil, err
		}
		return st, nil
	case <-ctx.Done():
		_ = st.resetLocal("open cancelled")
		return nil, fmt.Errorf("wslbridge: open stream %d: %w", id, ctx.Err())
	case <-timer.C:
		_ = st.resetLocal("open timed out")
		return nil, fmt.Errorf("wslbridge: open stream %d: peer did not acknowledge within %s", id, s.opts.OpenTimeout)
	case <-s.done:
		return nil, s.wrapClosed()
	}
}

// Accept returns the next stream the peer opened. The returned stream is not yet
// acknowledged: the caller must call Confirm once it is ready to carry bytes, or
// Reset to refuse it. That ordering is deliberate -- it lets the relay dial the
// engine socket first and report a failure as a reset the client can print.
func (s *Session) Accept(ctx context.Context) (*Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.wrapClosed()
	}
}

// wrapClosed returns the session's recorded error, or ErrSessionClosed.
func (s *Session) wrapClosed() error {
	if err := s.Err(); err != nil {
		return err
	}
	return ErrSessionClosed
}

// removeStream forgets a finished stream.
func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// lookup finds a live stream by id.
func (s *Session) lookup(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

// writeFrame emits one frame. Header and payload go out in a single Write so a
// concurrent frame can never be interleaved by a partial write underneath.
func (s *Session) writeFrame(id uint32, payload []byte) error {
	select {
	case <-s.done:
		return s.wrapClosed()
	default:
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	need := FrameHeaderSize + len(payload)
	if cap(s.wbuf) < need {
		s.wbuf = make([]byte, 0, need)
	}
	buf := s.wbuf[:FrameHeaderSize]
	binary.BigEndian.PutUint32(buf[0:4], id)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(payload)))
	buf = append(buf, payload...)
	s.wbuf = buf[:0]
	if _, err := s.conn.Write(buf); err != nil {
		err = fmt.Errorf("wslbridge: write frame for stream %d: %w", id, err)
		s.closeWithError(err)
		return err
	}
	return nil
}

// writeControl emits a control frame on stream 0.
func (s *Session) writeControl(k frameKind, id uint32, extra []byte) error {
	payload := make([]byte, controlHeaderSize+len(extra))
	payload[0] = byte(k)
	binary.BigEndian.PutUint32(payload[1:5], id)
	copy(payload[controlHeaderSize:], extra)
	return s.writeFrame(ControlStream, payload)
}

// control is a decoded control frame.
type control struct {
	kind  frameKind
	id    uint32
	extra []byte
}

// parseControl decodes a control payload. The returned extra aliases payload.
func parseControl(payload []byte) (control, error) {
	if len(payload) < controlHeaderSize {
		return control{}, fmt.Errorf("%w: control frame of %d bytes", ErrProtocol, len(payload))
	}
	return control{
		kind:  frameKind(payload[0]),
		id:    binary.BigEndian.Uint32(payload[1:5]),
		extra: payload[controlHeaderSize:],
	}, nil
}

// readLoop is the session's single reader. It exits, closing the session, on the
// first read error or protocol violation.
func (s *Session) readLoop() {
	var hdr [FrameHeaderSize]byte
	buf := make([]byte, s.opts.MaxFrame)
	for {
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			s.closeWithError(readError(err))
			return
		}
		id := binary.BigEndian.Uint32(hdr[0:4])
		n := binary.BigEndian.Uint32(hdr[4:8])
		if int(n) > cap(buf) {
			s.closeWithError(fmt.Errorf("%w: frame of %d bytes exceeds the %d byte maximum", ErrProtocol, n, cap(buf)))
			return
		}
		payload := buf[:n]
		if n > 0 {
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				s.closeWithError(readError(err))
				return
			}
		}
		if id == ControlStream {
			if err := s.handleControl(payload); err != nil {
				s.closeWithError(err)
				return
			}
			continue
		}
		if err := s.handleData(id, payload); err != nil {
			s.closeWithError(err)
			return
		}
	}
}

// readError normalises the end of the underlying connection.
func readError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("wslbridge: peer closed the link: %w", ErrSessionClosed)
	}
	return fmt.Errorf("wslbridge: read frame: %w", err)
}

// handleControl dispatches one control frame.
func (s *Session) handleControl(payload []byte) error {
	c, err := parseControl(payload)
	if err != nil {
		return err
	}
	switch c.kind {
	case kindOpen:
		return s.handleOpen(c.id, c.extra)
	case kindAck:
		if st := s.lookup(c.id); st != nil {
			st.peerAcked(c.extra)
		}
	case kindClose:
		if st := s.lookup(c.id); st != nil {
			st.peerClosed()
		}
	case kindReset:
		reason := string(c.extra)
		if len(reason) > maxResetReason {
			reason = reason[:maxResetReason]
		}
		if st := s.lookup(c.id); st != nil {
			st.peerReset(reason)
			s.removeStream(c.id)
		}
	case kindWindow:
		if len(c.extra) != 4 {
			return fmt.Errorf("%w: window frame with %d bytes of credit", ErrProtocol, len(c.extra))
		}
		if st := s.lookup(c.id); st != nil {
			st.addSendWindow(int32(binary.BigEndian.Uint32(c.extra)))
		}
	default:
		// Unknown kinds are ignored so a newer peer can add frames without
		// breaking an older one. Data framing is unaffected either way.
		s.opts.Logger.Debug("wslbridge: ignoring unknown control frame", "kind", uint8(c.kind), "stream", c.id)
	}
	return nil
}

// handleOpen registers a peer-opened stream and queues it for Accept. extra
// carries the opener's receive window when it sent one.
func (s *Session) handleOpen(id uint32, extra []byte) error {
	if id == ControlStream {
		return fmt.Errorf("%w: peer opened the control stream", ErrProtocol)
	}
	s.mu.Lock()
	if _, dup := s.streams[id]; dup {
		s.mu.Unlock()
		return fmt.Errorf("%w: peer reopened live stream %d", ErrProtocol, id)
	}
	if s.err != nil {
		s.mu.Unlock()
		return nil
	}
	st := newStream(s, id, true)
	s.streams[id] = st
	s.mu.Unlock()
	st.adoptPeerWindow(extra)

	select {
	case s.accept <- st:
		return nil
	default:
		s.removeStream(id)
		// Off the read loop, for the same reason as the window credit above.
		go func() { _ = s.writeControl(kindReset, id, []byte("accept backlog full")) }()
		return nil
	}
}

// handleData delivers a data frame to its stream.
func (s *Session) handleData(id uint32, payload []byte) error {
	st := s.lookup(id)
	if st == nil {
		// A stream this side already finished with. Dropping late data is
		// correct: the peer will see the close or reset we already sent.
		return nil
	}
	return st.push(payload)
}

// Stream is one multiplexed connection. It implements net.Conn so the rest of
// hull can treat a relayed Docker API connection exactly like a socket.
type Stream struct {
	sess     *Session
	id       uint32
	accepted bool // opened by the peer rather than by us

	mu sync.Mutex
	// receive side
	rbuf     bytes.Buffer
	rerr     error         // io.EOF on peer half-close, or a hard error
	readable chan struct{} // closed and replaced on every receive-side change
	pending  int32         // consumed bytes not yet credited back to the peer
	winLeft  int32         // credit the peer still holds
	rclosed  bool
	// send side
	sendWin  int32
	writable chan struct{} // closed and replaced on every send-side change
	werr     error
	wclosed  bool

	confirmed bool          // acceptor: ack already sent
	acked     chan struct{} // opener: closed when the peer acked or reset
	ackErr    error
	ackOnce   sync.Once
	closeOnce sync.Once

	rdl deadline
	wdl deadline
}

// newStream registers a stream with its session's initial window.
func newStream(s *Session, id uint32, accepted bool) *Stream {
	win := int32(s.opts.Window)
	return &Stream{
		sess:     s,
		id:       id,
		accepted: accepted,
		readable: make(chan struct{}),
		writable: make(chan struct{}),
		winLeft:  win,
		sendWin:  win,
		acked:    make(chan struct{}),
		rdl:      deadline{cancel: make(chan struct{})},
		wdl:      deadline{cancel: make(chan struct{})},
	}
}

// ID reports the stream's id on the wire, which is what lets a log follow one
// Docker API connection through the relay.
func (st *Stream) ID() uint32 { return st.id }

// signalRead wakes every reader. Callers hold st.mu.
func (st *Stream) signalRead() {
	close(st.readable)
	st.readable = make(chan struct{})
}

// signalWrite wakes every writer. Callers hold st.mu.
func (st *Stream) signalWrite() {
	close(st.writable)
	st.writable = make(chan struct{})
}

// Confirm acknowledges an accepted stream, telling the opener it may send. It is
// a no-op on a stream this side opened, and on one already confirmed.
func (st *Stream) Confirm() error {
	if !st.accepted {
		return nil
	}
	st.mu.Lock()
	if st.confirmed {
		st.mu.Unlock()
		return nil
	}
	st.confirmed = true
	st.mu.Unlock()
	return st.sess.writeControl(kindAck, st.id, beUint32(uint32(st.sess.opts.Window)))
}

// Reset aborts the stream and tells the peer why. The reason reaches the other
// end as a ResetError, which is how a failed engine-socket dial inside WSL is
// reported to the Windows client.
func (st *Stream) Reset(reason error) error {
	text := ""
	if reason != nil {
		text = reason.Error()
	}
	return st.resetLocal(text)
}

// resetLocal is Reset with a plain string, used internally for open failures.
func (st *Stream) resetLocal(reason string) error {
	if len(reason) > maxResetReason {
		reason = reason[:maxResetReason]
	}
	st.mu.Lock()
	already := st.rclosed && st.wclosed
	st.rclosed, st.wclosed = true, true
	if st.rerr == nil {
		st.rerr = ErrStreamClosed
	}
	if st.werr == nil {
		st.werr = ErrStreamClosed
	}
	st.rbuf.Reset()
	st.signalRead()
	st.signalWrite()
	st.mu.Unlock()

	st.ackOnce.Do(func() {
		st.mu.Lock()
		st.ackErr = &ResetError{StreamID: st.id, Reason: reason}
		st.mu.Unlock()
		close(st.acked)
	})
	st.sess.removeStream(st.id)
	if already {
		return nil
	}
	return st.sess.writeControl(kindReset, st.id, []byte(reason))
}

// peerAcked records the peer's acknowledgement of an open, adopting the receive
// window it advertised.
func (st *Stream) peerAcked(extra []byte) {
	st.adoptPeerWindow(extra)
	st.ackOnce.Do(func() { close(st.acked) })
}

// adoptPeerWindow sets how many bytes this side may send before waiting for
// credit, from the window the peer advertised on open or ack.
//
// Without this exchange each end would assume its own configured window applied
// to the other, and a bridge configured with a larger window than its relay
// would overrun the relay's receive window on the first large request -- a
// protocol error that kills the session, and one that would only ever show up
// on a user who had tuned the setting.
func (st *Stream) adoptPeerWindow(extra []byte) {
	if len(extra) != 4 {
		return
	}
	window := int32(binary.BigEndian.Uint32(extra))
	if window <= 0 {
		return
	}
	st.mu.Lock()
	st.sendWin = window
	st.signalWrite()
	st.mu.Unlock()
}

// beUint32 renders n as the 4 big-endian bytes a control frame carries.
func beUint32(n uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return b[:]
}

// openError reports why an open failed, if it did.
func (st *Stream) openError() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.ackErr
}

// peerClosed handles a half-close: no more data will arrive, but this side may
// still write.
func (st *Stream) peerClosed() {
	st.mu.Lock()
	if st.rerr == nil {
		st.rerr = io.EOF
	}
	st.signalRead()
	st.mu.Unlock()
}

// peerReset handles an abort from the other end.
func (st *Stream) peerReset(reason string) {
	err := &ResetError{StreamID: st.id, Reason: reason}
	st.mu.Lock()
	st.rbuf.Reset()
	st.rerr = err
	st.werr = err
	st.rclosed, st.wclosed = true, true
	st.ackErr = err
	st.signalRead()
	st.signalWrite()
	st.mu.Unlock()
	st.ackOnce.Do(func() { close(st.acked) })
}

// fail ends the stream because the whole session ended.
func (st *Stream) fail(cause error) {
	st.mu.Lock()
	if st.rerr == nil {
		st.rerr = cause
	}
	if st.werr == nil {
		st.werr = cause
	}
	if st.ackErr == nil {
		st.ackErr = cause
	}
	st.signalRead()
	st.signalWrite()
	st.mu.Unlock()
	st.ackOnce.Do(func() { close(st.acked) })
}

// push delivers a received data frame, enforcing the receive window. A peer that
// overruns its window is a protocol error and kills the session, because the
// alternative is unbounded memory growth driven by the other end.
func (st *Stream) push(payload []byte) error {
	st.mu.Lock()
	if int32(len(payload)) > st.winLeft {
		left := st.winLeft
		st.mu.Unlock()
		return fmt.Errorf("%w: stream %d sent %d bytes with %d of window left", ErrProtocol, st.id, len(payload), left)
	}
	st.winLeft -= int32(len(payload))
	if st.rclosed {
		// Nobody will read these bytes, but the peer still deserves its credit
		// back so it does not wedge waiting for a window that never opens.
		st.pending += int32(len(payload))
		credit := st.takeCreditLocked(true)
		st.mu.Unlock()
		if credit > 0 {
			// Sent from a goroutine, never inline: this runs on the session's
			// read loop, and a blocking write here would stop reading — which
			// is half of a deadlock if the peer is blocked writing to us.
			go func() { _ = st.sendWindow(credit) }()
		}
		return nil
	}
	st.rbuf.Write(payload)
	st.signalRead()
	st.mu.Unlock()
	return nil
}

// takeCreditLocked decides whether to return consumed bytes to the peer now.
// Credit is batched at half a window to keep control frames rare, but an empty
// receive buffer always flushes, so a reader that consumes in small sips can
// never deadlock against a writer waiting for window.
func (st *Stream) takeCreditLocked(bufferEmpty bool) int32 {
	if st.pending <= 0 {
		return 0
	}
	if !bufferEmpty && st.pending*2 < int32(st.sess.opts.Window) {
		return 0
	}
	credit := st.pending
	st.pending = 0
	st.winLeft += credit
	return credit
}

// sendWindow grants the peer more credit.
func (st *Stream) sendWindow(credit int32) error {
	var extra [4]byte
	binary.BigEndian.PutUint32(extra[:], uint32(credit))
	return st.sess.writeControl(kindWindow, st.id, extra[:])
}

// addSendWindow grants this side more credit to send.
func (st *Stream) addSendWindow(credit int32) {
	st.mu.Lock()
	st.sendWin += credit
	st.signalWrite()
	st.mu.Unlock()
}

// Read implements io.Reader. It returns io.EOF after the peer half-closes and
// every buffered byte has been consumed.
func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		st.mu.Lock()
		if st.rbuf.Len() > 0 {
			n, _ := st.rbuf.Read(p)
			st.pending += int32(n)
			credit := st.takeCreditLocked(st.rbuf.Len() == 0)
			st.mu.Unlock()
			if credit > 0 {
				// A failed window update means the session is gone; the bytes
				// in hand are still real, so return them and let the next call
				// report the error.
				_ = st.sendWindow(credit)
			}
			return n, nil
		}
		if st.rerr != nil {
			err := st.rerr
			st.mu.Unlock()
			return 0, err
		}
		if st.rclosed {
			st.mu.Unlock()
			return 0, ErrStreamClosed
		}
		ready := st.readable
		st.mu.Unlock()

		select {
		case <-ready:
		case <-st.rdl.wait():
			return 0, os.ErrDeadlineExceeded
		case <-st.sess.done:
			// Loop once more: data that arrived before the session ended is
			// still worth delivering.
			st.mu.Lock()
			buffered := st.rbuf.Len() > 0
			st.mu.Unlock()
			if !buffered {
				return 0, st.sess.wrapClosed()
			}
		}
	}
}

// Write implements io.Writer. It blocks while the peer's receive window is full,
// which is the backpressure that keeps one slow consumer from consuming memory
// on behalf of every other stream.
func (st *Stream) Write(p []byte) (int, error) {
	if st.accepted {
		if err := st.Confirm(); err != nil {
			return 0, err
		}
	}
	total := 0
	for len(p) > 0 {
		st.mu.Lock()
		if st.werr != nil {
			err := st.werr
			st.mu.Unlock()
			return total, err
		}
		if st.wclosed {
			st.mu.Unlock()
			return total, ErrStreamClosed
		}
		win := st.sendWin
		if win <= 0 {
			ready := st.writable
			st.mu.Unlock()
			select {
			case <-ready:
			case <-st.wdl.wait():
				return total, os.ErrDeadlineExceeded
			case <-st.sess.done:
				return total, st.sess.wrapClosed()
			}
			continue
		}
		n := len(p)
		if int(win) < n {
			n = int(win)
		}
		if n > st.sess.opts.MaxFrame {
			n = st.sess.opts.MaxFrame
		}
		st.sendWin -= int32(n)
		st.mu.Unlock()

		if err := st.sess.writeFrame(st.id, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// CloseWrite half-closes the stream: the peer's Read returns io.EOF once it has
// drained what is already in flight, while this side keeps reading. A Docker API
// client that finishes its request body and waits for the response depends on
// exactly this.
func (st *Stream) CloseWrite() error {
	st.mu.Lock()
	if st.wclosed {
		st.mu.Unlock()
		return nil
	}
	st.wclosed = true
	st.signalWrite()
	st.mu.Unlock()
	return st.sess.writeControl(kindClose, st.id, nil)
}

// Close shuts the stream down in both directions. When the peer has already
// half-closed this is a graceful close; otherwise it is an abort, so the peer
// stops writing into a stream nobody will read.
func (st *Stream) Close() error {
	var err error
	st.closeOnce.Do(func() {
		st.mu.Lock()
		peerDone := st.rerr != nil
		wasClosed := st.wclosed
		st.rclosed = true
		st.wclosed = true
		if st.rerr == nil {
			st.rerr = ErrStreamClosed
		}
		if st.werr == nil {
			st.werr = ErrStreamClosed
		}
		st.rbuf.Reset()
		st.signalRead()
		st.signalWrite()
		st.mu.Unlock()

		if peerDone {
			if !wasClosed {
				err = st.sess.writeControl(kindClose, st.id, nil)
			}
			st.sess.removeStream(st.id)
			return
		}
		err = st.sess.writeControl(kindReset, st.id, []byte("closed"))
		st.sess.removeStream(st.id)
	})
	return err
}

// streamAddr is the net.Addr a Stream reports.
type streamAddr struct {
	id   uint32
	role string
}

// Network implements net.Addr.
func (a streamAddr) Network() string { return "hullmux" }

// String implements net.Addr.
func (a streamAddr) String() string { return fmt.Sprintf("hullmux/%s/%d", a.role, a.id) }

// LocalAddr implements net.Conn.
func (st *Stream) LocalAddr() net.Addr { return streamAddr{id: st.id, role: "local"} }

// RemoteAddr implements net.Conn.
func (st *Stream) RemoteAddr() net.Addr { return streamAddr{id: st.id, role: "peer"} }

// SetDeadline implements net.Conn.
func (st *Stream) SetDeadline(t time.Time) error {
	st.rdl.set(t)
	st.wdl.set(t)
	return nil
}

// SetReadDeadline implements net.Conn.
func (st *Stream) SetReadDeadline(t time.Time) error {
	st.rdl.set(t)
	return nil
}

// SetWriteDeadline implements net.Conn.
func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.wdl.set(t)
	return nil
}

var _ net.Conn = (*Stream)(nil)

// deadline is the net.Pipe deadline pattern: a channel closed when the deadline
// expires, replaced whenever the deadline is moved.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

// set arms, moves or clears the deadline. A zero time clears it.
func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cancel == nil {
		d.cancel = make(chan struct{})
	}
	if d.timer != nil && !d.timer.Stop() {
		// The timer is firing: wait for its callback to close the channel, so
		// the channel this method replaces is never closed twice.
		<-d.cancel
	}
	d.timer = nil

	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

// wait returns a channel closed when the deadline expires. A cleared deadline
// yields a channel that is never closed.
func (d *deadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cancel == nil {
		d.cancel = make(chan struct{})
	}
	return d.cancel
}

// isClosedChan reports whether c has been closed, without blocking.
func isClosedChan(c chan struct{}) bool {
	if c == nil {
		return false
	}
	select {
	case <-c:
		return true
	default:
		return false
	}
}
