// Package shim implements hull's per-container supervisor: the long-lived
// process that outlives the daemon.
//
// hulld spawns exactly one hull-shim per container, double-forked and setsid'd
// so it is reparented to PID 1 and survives a hulld restart or crash. The shim
// owns everything that must not be lost when the daemon goes away:
//
//   - the container init's pidfd, so every signal is delivered to *that*
//     process and a recycled pid can never be hit;
//   - the pty master (or the three stdio pipes) and the attach multiplexer;
//   - the json-file log writer;
//   - the container's exit status, persisted to exit.json before the shim
//     exits and served over the control socket for a grace period so a
//     restarting daemon cannot lose it.
//
// # Control protocol
//
// The shim serves a small framed protocol on a unix socket at
// <containerDir>/shim.sock. Every frame is:
//
//	+--------+------------------+-------------------+
//	| kind   | length (4 bytes, | body (length      |
//	| 1 byte | big endian)      | bytes)            |
//	+--------+------------------+-------------------+
//
// The body of a KindRequest, KindResponse or KindEvent frame is JSON; the body
// of a KindStdin, KindStdout or KindStderr frame is raw container bytes.
// KindEOF has an empty body.
//
// A connection starts in RPC mode: the client writes one KindRequest frame and
// reads one KindResponse frame. For most operations that ends the exchange and
// the client closes the connection — every RPC uses a fresh connection, so a
// blocking Wait can never stall an unrelated State.
//
// Three operations upgrade the connection to a stream after their response:
//
//	attach  the connection carries KindStdin frames client->shim and
//	        KindStdout/KindStderr frames shim->client until either side closes
//	        or the detach key sequence is seen in the stdin bytes;
//	exec    the same, for a newly exec'd process;
//	events  the shim writes KindEvent frames until the client goes away.
//
// The framing is deliberately tiny: it has to be decodable by a daemon that
// was restarted and knows nothing about the shim beyond shim.json.
package shim

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

// Frame kinds. The kind is the first byte of every frame.
const (
	// KindRequest carries a JSON-encoded Request, client to shim.
	KindRequest byte = 0x01
	// KindResponse carries a JSON-encoded Response, shim to client.
	KindResponse byte = 0x02
	// KindEvent carries a JSON-encoded Event, shim to client.
	KindEvent byte = 0x03
	// KindStdin carries raw bytes destined for the container's stdin.
	KindStdin byte = 0x04
	// KindStdout carries raw bytes from the container's stdout, or from the
	// pty master when the container has a terminal.
	KindStdout byte = 0x05
	// KindStderr carries raw bytes from the container's stderr. It is never
	// sent for a container with a terminal, whose streams are merged.
	KindStderr byte = 0x06
	// KindEOF marks the end of a stream. Its body is empty. Sent by a client
	// to half-close the container's stdin, and by the shim when the container
	// output ends.
	KindEOF byte = 0x07
)

// MaxFrameSize caps a frame body. It bounds what a peer can make the other
// side allocate; an exec spec or a burst of container output is far smaller.
const MaxFrameSize = 4 << 20

// Operations carried in Request.Op.
const (
	// OpStart starts the created container.
	OpStart = "start"
	// OpState reports the container's current State.
	OpState = "state"
	// OpKill sends one signal to the container.
	OpKill = "kill"
	// OpWait blocks until the container exits and reports its exit code.
	OpWait = "wait"
	// OpAttach upgrades the connection to an attach stream.
	OpAttach = "attach"
	// OpResize sets the pty window size.
	OpResize = "resize"
	// OpExec starts an additional process and upgrades the connection to its
	// attach stream.
	OpExec = "exec"
	// OpExecWait blocks until a previously started exec process exits.
	OpExecWait = "exec-wait"
	// OpExecResize resizes one exec process's pty.
	OpExecResize = "exec-resize"
	// OpStats samples the container's cgroup.
	OpStats = "stats"
	// OpEvents upgrades the connection to an event stream.
	OpEvents = "events"
	// OpAck tells the shim the daemon has durably recorded the exit status, so
	// the shim may stop serving and exit without waiting out its grace period.
	OpAck = "ack"
	// OpShutdown asks the shim to stop the container and exit.
	OpShutdown = "shutdown"
	// OpPing is a liveness probe used by Connect.
	OpPing = "ping"
)

// Event types carried in Event.Type.
const (
	// EventExit is emitted once, when the container's init exits.
	EventExit = "exit"
	// EventOOM is emitted when the cgroup reports a new OOM kill.
	EventOOM = "oom"
	// EventExecExit is emitted when an exec'd process exits.
	EventExecExit = "exec-exit"
)

// Sentinel errors returned by a Client. The shim sends the matching Code on
// the wire so the client can rebuild them with errors.Is.
var (
	// ErrStdinInUse is returned when a second attacher asks for stdin. Stdin
	// is granted to the first attacher and refused to the rest, because
	// interleaving two keyboards into one pty produces garbage.
	ErrStdinInUse = errors.New("shim: container stdin is already attached by another client")
	// ErrStdinUnavailable is returned when stdin is requested for a container
	// that was created without an open stdin.
	ErrStdinUnavailable = errors.New("shim: container was created without stdin: rerun it with -i")
	// ErrNotRunning is returned by operations that need a live container.
	ErrNotRunning = errors.New("shim: container is not running")
	// ErrAlreadyStarted is returned by a second Start.
	ErrAlreadyStarted = errors.New("shim: container has already been started")
	// ErrNoTerminal is returned by Resize for a container without a pty.
	ErrNoTerminal = errors.New("shim: container was created without a terminal")
	// ErrClosed is returned by a Client after Close.
	ErrClosed = errors.New("shim: client is closed")
	// ErrShimGone is returned when the shim socket is not there, or the
	// process recorded in shim.json is not the shim any more.
	ErrShimGone = errors.New("shim: shim process is gone")
	// ErrDetached is reported on an attach stream that ended because the
	// detach key sequence was typed. The container keeps running.
	ErrDetached = errors.New("shim: detached")
	// ErrNoSuchExec is returned for an unknown exec id.
	ErrNoSuchExec = errors.New("shim: no such exec")
	// ErrProtocol is returned for a malformed or unexpected frame.
	ErrProtocol = errors.New("shim: protocol error")
)

// Error codes put on the wire for the sentinels above.
const (
	codeStdinInUse       = "stdin-in-use"
	codeStdinUnavailable = "stdin-unavailable"
	codeNotRunning       = "not-running"
	codeAlreadyStarted   = "already-started"
	codeNoTerminal       = "no-terminal"
	codeNoSuchExec       = "no-such-exec"
	codeDetached         = "detached"
)

// Request is the JSON body of a KindRequest frame. Only the fields an
// operation needs are populated.
type Request struct {
	Op string `json:"op"`

	// Signal and All belong to OpKill. All asks for every process in the
	// container's cgroup, not just its init.
	Signal int  `json:"signal,omitempty"`
	All    bool `json:"all,omitempty"`

	// Height and Width belong to OpResize and OpExecResize.
	Height uint16 `json:"h,omitempty"`
	Width  uint16 `json:"w,omitempty"`

	// ExecID identifies an exec process for OpExec, OpExecWait and
	// OpExecResize.
	ExecID string `json:"execId,omitempty"`
	// Spec is the OCI process spec for OpExec, verbatim.
	Spec []byte `json:"spec,omitempty"`

	// Attach configures OpAttach and OpExec.
	Attach *AttachOptions `json:"attach,omitempty"`
}

// Response is the JSON body of a KindResponse frame. Error is empty on
// success; Code carries a sentinel identifier when one applies.
type Response struct {
	Error string `json:"error,omitempty"`
	Code  string `json:"code,omitempty"`

	State    *State       `json:"state,omitempty"`
	ExitCode *int         `json:"exitCode,omitempty"`
	Stats    *types.Stats `json:"stats,omitempty"`
	Pid      int          `json:"pid,omitempty"`
	// Terminal reports whether the upgraded stream is a single merged pty
	// stream rather than separate stdout and stderr.
	Terminal bool `json:"terminal,omitempty"`
}

// State is the shim's view of the container's lifecycle.
type State struct {
	// Pid is the container init's pid in the shim's pid namespace, or 0 once
	// it has exited.
	Pid int `json:"pid"`
	// Status is one of "created", "running", "stopped".
	Status string `json:"status"`
	// ExitCode is meaningful only once Exited is true. A process killed by
	// signal N reports 128+N, as Docker does.
	ExitCode int `json:"exitCode"`
	// Exited is true once the container init has been reaped.
	Exited bool `json:"exited"`
	// OOMKilled reports that the container's cgroup recorded an OOM kill.
	OOMKilled bool `json:"oomKilled"`
	// Error carries a supervision failure, e.g. the runtime refusing to start.
	Error string `json:"error,omitempty"`

	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
}

// Container status values reported in State.Status.
const (
	// StatusCreated means the runtime has created the container but its init
	// is still blocked waiting for start.
	StatusCreated = "created"
	// StatusRunning means the container init is alive.
	StatusRunning = "running"
	// StatusStopped means the container init has exited.
	StatusStopped = "stopped"
)

// Event is one entry on the shim's event stream.
type Event struct {
	// Type is EventExit, EventOOM or EventExecExit.
	Type string `json:"type"`
	// ID is the container id, or the exec id for EventExecExit.
	ID string `json:"id"`
	// ExitCode is set for EventExit and EventExecExit.
	ExitCode int `json:"exitCode,omitempty"`
	// OOMKilled is set on EventExit when the cgroup recorded an OOM kill.
	OOMKilled bool      `json:"oomKilled,omitempty"`
	Time      time.Time `json:"time"`
}

// AttachOptions selects which streams an attacher wants and how it detaches.
type AttachOptions struct {
	// Stdin asks for the container's stdin. It is granted to the first
	// attacher that asks; later attachers get ErrStdinInUse.
	Stdin bool `json:"stdin,omitempty"`
	// Stdout and Stderr select output streams. For a container with a
	// terminal the two are merged and either flag delivers the merged stream.
	Stdout bool `json:"stdout,omitempty"`
	Stderr bool `json:"stderr,omitempty"`
	// DetachKeys is a comma-separated key sequence such as "ctrl-p,ctrl-q"
	// that detaches the attacher without signalling the container. Empty means
	// DefaultDetachKeys.
	DetachKeys string `json:"detachKeys,omitempty"`
}

// WriteFrame writes one frame: the kind byte, a 4-byte big-endian body length
// and the body. It performs a single Write so a frame is never interleaved
// with another goroutine's frame on the same connection.
func WriteFrame(w io.Writer, kind byte, body []byte) error {
	if len(body) > MaxFrameSize {
		return fmt.Errorf("shim: frame body of %d bytes exceeds the %d byte limit", len(body), MaxFrameSize)
	}
	buf := make([]byte, 5+len(body))
	buf[0] = kind
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(body)))
	copy(buf[5:], body)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("shim: write frame: %w", err)
	}
	return nil
}

// ReadFrame reads one frame. It returns io.EOF when the peer closed cleanly
// between frames, and io.ErrUnexpectedEOF when it closed mid-frame.
func ReadFrame(r io.Reader) (kind byte, body []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:5])
	if n > MaxFrameSize {
		return 0, nil, fmt.Errorf("%w: frame declares %d bytes, over the %d byte limit", ErrProtocol, n, MaxFrameSize)
	}
	if n == 0 {
		return hdr[0], nil, nil
	}
	body = make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, io.ErrUnexpectedEOF
	}
	return hdr[0], body, nil
}

// WriteJSONFrame marshals v and writes it as a frame of the given kind.
func WriteJSONFrame(w io.Writer, kind byte, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("shim: marshal frame body: %w", err)
	}
	return WriteFrame(w, kind, body)
}

// ReadRequest reads one frame and decodes it as a Request. A frame of any
// other kind is a protocol error.
func ReadRequest(r io.Reader) (Request, error) {
	kind, body, err := ReadFrame(r)
	if err != nil {
		return Request{}, err
	}
	if kind != KindRequest {
		return Request{}, fmt.Errorf("%w: expected a request frame, got kind 0x%02x", ErrProtocol, kind)
	}
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		return Request{}, fmt.Errorf("%w: malformed request body: %v", ErrProtocol, err)
	}
	if req.Op == "" {
		return Request{}, fmt.Errorf("%w: request has no op", ErrProtocol)
	}
	return req, nil
}

// ReadResponse reads one frame and decodes it as a Response. A frame of any
// other kind is a protocol error.
func ReadResponse(r io.Reader) (Response, error) {
	kind, body, err := ReadFrame(r)
	if err != nil {
		return Response{}, err
	}
	if kind != KindResponse {
		return Response{}, fmt.Errorf("%w: expected a response frame, got kind 0x%02x", ErrProtocol, kind)
	}
	var resp Response
	if err := json.Unmarshal(body, &resp); err != nil {
		return Response{}, fmt.Errorf("%w: malformed response body: %v", ErrProtocol, err)
	}
	return resp, nil
}

// unmarshalJSON decodes a frame body, reporting a malformed body as a
// protocol error rather than as a bare json error.
func unmarshalJSON(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%w: malformed frame body: %v", ErrProtocol, err)
	}
	return nil
}

// errorResponse turns err into a Response, mapping the package sentinels onto
// stable wire codes so the client can rebuild them.
func errorResponse(err error) Response {
	if err == nil {
		return Response{}
	}
	resp := Response{Error: err.Error()}
	switch {
	case errors.Is(err, ErrStdinInUse):
		resp.Code = codeStdinInUse
	case errors.Is(err, ErrStdinUnavailable):
		resp.Code = codeStdinUnavailable
	case errors.Is(err, ErrNotRunning):
		resp.Code = codeNotRunning
	case errors.Is(err, ErrAlreadyStarted):
		resp.Code = codeAlreadyStarted
	case errors.Is(err, ErrNoTerminal):
		resp.Code = codeNoTerminal
	case errors.Is(err, ErrNoSuchExec):
		resp.Code = codeNoSuchExec
	case errors.Is(err, ErrDetached):
		resp.Code = codeDetached
	}
	return resp
}

// responseError rebuilds an error from a Response, preserving the sentinel so
// callers can use errors.Is across the socket.
func responseError(resp Response) error {
	if resp.Error == "" && resp.Code == "" {
		return nil
	}
	var sentinel error
	switch resp.Code {
	case codeStdinInUse:
		sentinel = ErrStdinInUse
	case codeStdinUnavailable:
		sentinel = ErrStdinUnavailable
	case codeNotRunning:
		sentinel = ErrNotRunning
	case codeAlreadyStarted:
		sentinel = ErrAlreadyStarted
	case codeNoTerminal:
		sentinel = ErrNoTerminal
	case codeNoSuchExec:
		sentinel = ErrNoSuchExec
	case codeDetached:
		sentinel = ErrDetached
	}
	if sentinel == nil {
		if resp.Error == "" {
			return fmt.Errorf("shim: request failed with code %q", resp.Code)
		}
		return errors.New(resp.Error)
	}
	if resp.Error == "" || resp.Error == sentinel.Error() {
		return sentinel
	}
	return fmt.Errorf("%w: %s", sentinel, resp.Error)
}
