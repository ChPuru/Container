package shim

import (
	"errors"
	"io"
	"sync"
)

// attacherQueue is how many Chunks may be in flight to one attacher before it
// is considered stalled. Container output must never block on a wedged client,
// so an attacher that fills its queue is disconnected instead.
const attacherQueue = 256

// Hub fans one container's output out to the json-file log and to every live
// attacher, and funnels the one attacher that holds stdin back into the
// container.
//
// Output ordering is preserved per stream and across streams: Write appends to
// the ring and enqueues to every attacher under one lock, so two attachers
// always see the same byte order.
type Hub struct {
	ring *RingBuffer

	mu         sync.Mutex
	attachers  map[*Attacher]struct{}
	stdinOwner *Attacher
	closed     bool

	stdinMu sync.Mutex
	stdin   io.WriteCloser
}

// NewHub returns a Hub. stdin is the container's input sink — the pty master
// or the write end of its stdin pipe — and may be nil for a container created
// without stdin, in which case attachers asking for stdin get
// ErrStdinUnavailable. ringSize is the replay buffer in bytes; zero uses
// DefaultRingSize.
func NewHub(stdin io.WriteCloser, ringSize int) *Hub {
	return &Hub{
		ring:      NewRingBuffer(ringSize),
		attachers: make(map[*Attacher]struct{}),
		stdin:     stdin,
	}
}

// Write records p on the given stream (KindStdout or KindStderr) and delivers
// it to every attacher subscribed to that stream. It copies p once and shares
// the copy, so the caller may reuse its buffer.
//
// Write never blocks on an attacher and never fails: it returns len(p), nil.
func (h *Hub) Write(stream byte, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	data := make([]byte, len(p))
	copy(data, p)
	chunk := Chunk{Stream: stream, Data: data}

	h.mu.Lock()
	h.ring.Add(stream, data)
	var stalled []*Attacher
	for a := range h.attachers {
		if !a.wants(stream) {
			continue
		}
		if !a.enqueue(chunk) {
			stalled = append(stalled, a)
		}
	}
	for _, a := range stalled {
		h.removeLocked(a, errAttacherStalled)
	}
	h.mu.Unlock()
	return len(p), nil
}

// errAttacherStalled ends an attach stream that could not keep up.
var errAttacherStalled = errors.New("shim: attach stream fell too far behind and was disconnected")

// Attach registers a. If a asked for stdin it is granted only when no other
// attacher holds it and the container has an input sink. On success the ring
// buffer is replayed to a before any new output, so a late attacher sees
// recent output immediately.
func (h *Hub) Attach(a *Attacher) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return ErrNotRunning
	}
	if a.opts.Stdin {
		if !h.HasStdin() {
			return ErrStdinUnavailable
		}
		if h.stdinOwner != nil {
			return ErrStdinInUse
		}
		h.stdinOwner = a
		a.stdinGranted = true
	}
	a.hub = h
	// Replay under the lock so no concurrent Write can slot in ahead of the
	// snapshot and be delivered out of order.
	for _, c := range h.ring.Snapshot() {
		if a.wants(c.Stream) {
			a.enqueue(c)
		}
	}
	h.attachers[a] = struct{}{}
	return nil
}

// Detach removes a and releases stdin if it held it, so the next attacher may
// take over the keyboard.
func (h *Hub) Detach(a *Attacher) {
	h.mu.Lock()
	h.removeLocked(a, nil)
	h.mu.Unlock()
}

// removeLocked drops a and closes its queue with the given cause. The caller
// holds h.mu.
func (h *Hub) removeLocked(a *Attacher, cause error) {
	if _, ok := h.attachers[a]; !ok {
		return
	}
	delete(h.attachers, a)
	if h.stdinOwner == a {
		h.stdinOwner = nil
		a.stdinGranted = false
	}
	a.finish(cause)
}

// Count reports how many attachers are live.
func (h *Hub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.attachers)
}

// HasStdin reports whether the hub has a container input sink at all.
func (h *Hub) HasStdin() bool {
	h.stdinMu.Lock()
	defer h.stdinMu.Unlock()
	return h.stdin != nil
}

// WriteStdin forwards p to the container on behalf of a, which must hold
// stdin. It is serialised so two writes never interleave mid-escape-sequence.
func (h *Hub) WriteStdin(a *Attacher, p []byte) (int, error) {
	h.mu.Lock()
	granted := h.stdinOwner == a
	h.mu.Unlock()
	if !granted {
		return 0, ErrStdinInUse
	}
	h.stdinMu.Lock()
	defer h.stdinMu.Unlock()
	if h.stdin == nil {
		return 0, ErrStdinUnavailable
	}
	return h.stdin.Write(p)
}

// CloseStdin closes the container's stdin on behalf of a, which must hold it.
// This is how `docker attach` with a closed stdin lets `cat` see EOF.
func (h *Hub) CloseStdin(a *Attacher) error {
	h.mu.Lock()
	granted := h.stdinOwner == a
	h.mu.Unlock()
	if !granted {
		return ErrStdinInUse
	}
	h.stdinMu.Lock()
	defer h.stdinMu.Unlock()
	if h.stdin == nil {
		return nil
	}
	err := h.stdin.Close()
	h.stdin = nil
	return err
}

// Close ends every attach stream. It is called once the container's output has
// reached EOF, so attachers see a clean end rather than hanging.
func (h *Hub) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	for a := range h.attachers {
		delete(h.attachers, a)
		a.finish(nil)
	}
	h.stdinOwner = nil
	h.mu.Unlock()

	h.stdinMu.Lock()
	defer h.stdinMu.Unlock()
	if h.stdin != nil {
		err := h.stdin.Close()
		h.stdin = nil
		return err
	}
	return nil
}

// Attacher is one client's subscription to the container's streams.
type Attacher struct {
	opts AttachOptions

	ch   chan Chunk
	done chan struct{}

	once sync.Once
	mu   sync.Mutex
	err  error

	hub          *Hub
	stdinGranted bool
}

// NewAttacher returns an attacher for the given options. A container with a
// terminal has only one output stream, reported as KindStdout; asking for
// either Stdout or Stderr subscribes to it.
func NewAttacher(opts AttachOptions) *Attacher {
	return &Attacher{
		opts: opts,
		ch:   make(chan Chunk, attacherQueue),
		done: make(chan struct{}),
	}
}

// Options returns the options the attacher was created with.
func (a *Attacher) Options() AttachOptions { return a.opts }

// StdinGranted reports whether this attacher holds the container's stdin.
func (a *Attacher) StdinGranted() bool {
	if a.hub == nil {
		return false
	}
	a.hub.mu.Lock()
	defer a.hub.mu.Unlock()
	return a.hub.stdinOwner == a
}

// Chunks is the stream of output destined for this attacher. It is closed when
// the attacher is detached or the container's output ends.
func (a *Attacher) Chunks() <-chan Chunk { return a.ch }

// Done is closed when the attacher is finished; Err then reports why.
func (a *Attacher) Done() <-chan struct{} { return a.done }

// Err reports why the attacher ended: nil for a clean end, errAttacherStalled
// for a client that could not keep up, ErrDetached for the detach sequence.
func (a *Attacher) Err() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

// Write forwards p to the container's stdin. It implements io.Writer so the
// server can copy an attach connection straight into the container.
func (a *Attacher) Write(p []byte) (int, error) {
	if a.hub == nil {
		return 0, ErrStdinUnavailable
	}
	return a.hub.WriteStdin(a, p)
}

// CloseStdin closes the container's stdin if this attacher holds it.
func (a *Attacher) CloseStdin() error {
	if a.hub == nil {
		return ErrStdinUnavailable
	}
	return a.hub.CloseStdin(a)
}

// Detach removes the attacher from its hub with the given cause, which may be
// nil or ErrDetached. The container is unaffected.
func (a *Attacher) Detach(cause error) {
	if a.hub == nil {
		a.finish(cause)
		return
	}
	a.mu.Lock()
	if a.err == nil {
		a.err = cause
	}
	a.mu.Unlock()
	a.hub.Detach(a)
}

// wants reports whether the attacher subscribes to the given stream.
func (a *Attacher) wants(stream byte) bool {
	switch stream {
	case KindStdout:
		return a.opts.Stdout || a.opts.Stderr
	case KindStderr:
		return a.opts.Stderr
	}
	return false
}

// enqueue offers c to the attacher without blocking, reporting false when the
// queue is full and the attacher must be dropped.
func (a *Attacher) enqueue(c Chunk) bool {
	select {
	case <-a.done:
		return true // already finished; nothing to deliver, not a stall
	case a.ch <- c:
		return true
	default:
		return false
	}
}

// finish closes the attacher exactly once, recording the first cause seen.
func (a *Attacher) finish(cause error) {
	a.once.Do(func() {
		a.mu.Lock()
		if a.err == nil {
			a.err = cause
		}
		a.mu.Unlock()
		close(a.ch)
		close(a.done)
	})
}
