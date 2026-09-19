package client

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is a failure the engine reported over HTTP. The engine's message text
// matters as much as the status code: compose and Testcontainers match on
// strings like "No such container: x", so the message is carried verbatim.
type Error struct {
	// StatusCode is the HTTP status the engine returned.
	StatusCode int
	// Message is the engine's own error text, unwrapped from its JSON body.
	Message string
	// Method and Path name the request that failed.
	Method string
	Path   string
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("engine returned %s for %s %s", http.StatusText(e.StatusCode), e.Method, e.Path)
	}
	return e.Message
}

// NotFound reports whether the engine said the object does not exist.
func (e *Error) NotFound() bool { return e.StatusCode == http.StatusNotFound }

// Conflict reports whether the engine refused because of a conflicting state,
// such as a name already in use or a running container being removed.
func (e *Error) Conflict() bool { return e.StatusCode == http.StatusConflict }

// NotModified reports a no-op, which the engine uses for starting an already
// running container.
func (e *Error) NotModified() bool { return e.StatusCode == http.StatusNotModified }

// Unauthorized reports a credentials problem.
func (e *Error) Unauthorized() bool {
	return e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden
}

// NotImplemented reports that this engine build does not offer the endpoint,
// which is how a missing bundled buildkit surfaces.
func (e *Error) NotImplemented() bool { return e.StatusCode == http.StatusNotImplemented }

// IsNotFound reports whether err is an engine 404.
func IsNotFound(err error) bool { return statusIs(err, (*Error).NotFound) }

// IsConflict reports whether err is an engine 409.
func IsConflict(err error) bool { return statusIs(err, (*Error).Conflict) }

// IsNotModified reports whether err is an engine 304.
func IsNotModified(err error) bool { return statusIs(err, (*Error).NotModified) }

// IsUnauthorized reports whether err is an engine 401 or 403.
func IsUnauthorized(err error) bool { return statusIs(err, (*Error).Unauthorized) }

// IsNotImplemented reports whether err is an engine 501.
func IsNotImplemented(err error) bool { return statusIs(err, (*Error).NotImplemented) }

// statusIs unwraps err to an *Error and applies pred.
func statusIs(err error, pred func(*Error) bool) bool {
	var e *Error
	if errors.As(err, &e) {
		return pred(e)
	}
	return false
}

// ErrConnectionFailed is wrapped into every failure to reach the engine at
// all, so the CLI can tell "the daemon is not running" apart from "the daemon
// said no".
var ErrConnectionFailed = errors.New("cannot connect to the hull engine")

// ConnectionError wraps a transport failure with the address that was tried.
type ConnectionError struct {
	// Host is the address the client attempted.
	Host Host
	// Err is the underlying dial or protocol failure.
	Err error
}

// Error implements the error interface.
func (e *ConnectionError) Error() string {
	return fmt.Sprintf("%v at %s: %v", ErrConnectionFailed, e.Host.String(), e.Err)
}

// Unwrap exposes the underlying failure.
func (e *ConnectionError) Unwrap() error { return e.Err }

// Is lets errors.Is match ErrConnectionFailed.
func (e *ConnectionError) Is(target error) bool { return target == ErrConnectionFailed }

// IsConnectionFailed reports whether err is a failure to reach the engine.
func IsConnectionFailed(err error) bool { return errors.Is(err, ErrConnectionFailed) }
