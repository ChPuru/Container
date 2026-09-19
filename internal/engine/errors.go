// Package engine is hull's orchestration core.
//
// Everything else in hull is a surface over this package: the Docker Engine
// API server, the hull CLI and the TUI all drive an [Engine]. It owns the
// container lifecycle, the image service, healthchecks, restart policy, stats,
// the event bus wiring and the background workers that keep the on-disk state
// and the kernel in agreement.
//
// # Concurrency
//
// There is no global lock. Every operation that mutates one container takes
// that container's own mutex from a keyed lock map, so pulling a multi-gigabyte
// image can never block `hull ps`. The map itself is guarded by an RWMutex.
// Every exported method takes a context and abandons its work cleanly when the
// context is cancelled.
//
// # Recovery
//
// A hull daemon is not the owner of its containers' lifetimes: each container
// is supervised by a shim that is reparented to PID 1, so containers outlive
// the daemon. [New] therefore reconciles every persisted container against
// reality before it returns, reconnecting to live shims, marking vanished ones
// exited, re-applying restart policies and re-publishing ports. [Engine.Close]
// detaches from the shims without killing anything.
package engine

import "errors"

// Errors the engine returns. Callers should test them with errors.Is rather
// than matching on message text; the API layer maps them onto HTTP statuses.
var (
	// ErrNotFound means no container, image, network, volume or exec with
	// that identifier exists.
	ErrNotFound = errors.New("engine: no such object")
	// ErrConflict means the object exists but is in the wrong state for the
	// operation, e.g. removing a running container without force.
	ErrConflict = errors.New("engine: conflict")
	// ErrNotRunning means the operation needs a running container.
	ErrNotRunning = errors.New("engine: container is not running")
	// ErrRunning means the operation needs a stopped container.
	ErrRunning = errors.New("engine: container is running")
	// ErrPaused means the operation cannot be performed while the container
	// is frozen.
	ErrPaused = errors.New("engine: container is paused")
	// ErrInvalid means the request itself is malformed: a bad filter, an
	// impossible resource limit, a relative path where an absolute one is
	// required.
	ErrInvalid = errors.New("engine: invalid request")
	// ErrClosed means the engine is shutting down and is no longer accepting
	// work.
	ErrClosed = errors.New("engine: daemon is shutting down")
	// ErrUnsupported means this host, kernel or build cannot do it. The
	// wrapped message always names the missing feature and the remedy.
	ErrUnsupported = errors.New("engine: operation not supported here")
	// ErrNoRuntimeBinary means no OCI runtime binary could be resolved, so
	// the per-container shim has nothing to drive.
	ErrNoRuntimeBinary = errors.New("engine: no OCI runtime binary available")
)
