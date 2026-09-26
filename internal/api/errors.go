package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ChPuru/hull/internal/engine"
	"github.com/ChPuru/hull/internal/events"
	"github.com/ChPuru/hull/internal/volume"
)

// statusError carries an HTTP status alongside a message, so a handler can say
// exactly what it means without the mapper having to guess.
type statusError struct {
	// status is the HTTP status to send.
	status int
	// msg is the body's "message" field, verbatim.
	msg string
	// err is the wrapped cause, kept so errors.Is still works through it.
	err error
}

// Error implements error.
func (e *statusError) Error() string { return e.msg }

// Unwrap exposes the cause.
func (e *statusError) Unwrap() error { return e.err }

// errStatus builds an error carrying an explicit HTTP status and message.
func errStatus(status int, format string, args ...any) error {
	return &statusError{status: status, msg: fmt.Sprintf(format, args...)}
}

// wrapStatus builds an error carrying an explicit status, message and cause.
func wrapStatus(status int, cause error, format string, args ...any) error {
	return &statusError{status: status, msg: fmt.Sprintf(format, args...), err: cause}
}

// errBadParameter is the 400 every malformed request gets.
func errBadParameter(format string, args ...any) error {
	return errStatus(http.StatusBadRequest, format, args...)
}

// errNoSuchContainer produces the exact text compose matches on. Do not
// reword it: "No such container" is a string comparison in more than one
// client library.
func errNoSuchContainer(id string) error {
	return wrapStatus(http.StatusNotFound, engine.ErrNotFound, "No such container: %s", id)
}

// errNoSuchImage produces the text Docker's clients match on.
func errNoSuchImage(ref string) error {
	return wrapStatus(http.StatusNotFound, engine.ErrNotFound, "No such image: %s", ref)
}

// errNoSuchNetwork produces the text Docker's clients match on.
func errNoSuchNetwork(id string) error {
	return wrapStatus(http.StatusNotFound, engine.ErrNotFound, "network %s not found", id)
}

// errNoSuchVolume produces the text Docker's clients match on.
func errNoSuchVolume(name string) error {
	return wrapStatus(http.StatusNotFound, engine.ErrNotFound, "get %s: no such volume", name)
}

// errNoSuchExec produces the text Docker's clients match on.
func errNoSuchExec(id string) error {
	return wrapStatus(http.StatusNotFound, engine.ErrNotFound, "No such exec instance '%s' found in daemon", id)
}

// httpStatusOf maps an error onto the status Docker would send.
//
// A handler-supplied [statusError] wins outright. Otherwise the engine's
// sentinel errors decide: not-found is 404, conflict and the wrong-state
// errors are 409, a malformed request is 400, an unsupported host feature is
// 501, and anything else is 500. A cancelled context is 499, the status the
// Docker daemon itself uses for a client that hung up.
func httpStatusOf(err error) int {
	var se *statusError
	if errors.As(err, &se) && se.status != 0 {
		return se.status
	}
	var fe *events.InvalidFilterError
	if errors.As(err, &fe) {
		return http.StatusBadRequest
	}
	switch {
	case errors.Is(err, engine.ErrNotFound), errors.Is(err, volume.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, engine.ErrConflict), errors.Is(err, volume.ErrInUse),
		errors.Is(err, engine.ErrRunning), errors.Is(err, engine.ErrNotRunning),
		errors.Is(err, engine.ErrPaused):
		return http.StatusConflict
	case errors.Is(err, engine.ErrInvalid):
		return http.StatusBadRequest
	case errors.Is(err, engine.ErrUnsupported), errors.Is(err, volume.ErrDriverUnsupported):
		return http.StatusNotImplemented
	case errors.Is(err, engine.ErrClosed):
		return http.StatusServiceUnavailable
	case errors.Is(err, context.Canceled):
		return statusClientClosedRequest
	default:
		return http.StatusInternalServerError
	}
}

// statusClientClosedRequest is nginx's 499, which the Docker daemon also uses
// for a client that disconnected mid-request. It is never sent on the wire
// when the connection is already gone; it exists so the access log tells the
// truth about why a handler stopped.
const statusClientClosedRequest = 499

// errorMessage renders an error the way Docker phrases it in a response body.
//
// The engine's own messages are prefixed "engine: " and often carry a sentinel
// prefix like "engine: conflict: ", which is noise to a client. Those prefixes
// are stripped so the text a user sees is the text that explains the problem.
func errorMessage(err error) string {
	var se *statusError
	if errors.As(err, &se) && se.msg != "" {
		return se.msg
	}
	msg := err.Error()
	for _, p := range []string{
		"engine: no such object: ",
		"engine: conflict: ",
		"engine: container is not running: ",
		"engine: container is running: ",
		"engine: container is paused: ",
		"engine: invalid request: ",
		"engine: operation not supported here: ",
	} {
		msg = strings.ReplaceAll(msg, p, "")
	}
	msg = strings.TrimPrefix(msg, "engine: ")
	if msg == "" {
		return "unknown error"
	}
	return msg
}

// writeError sends an error as Docker's {"message": "..."} body with the right
// status. It is a no-op once the response has been hijacked or the headers
// have already gone out, which is why streaming handlers report failures
// inside the stream instead.
func writeError(w http.ResponseWriter, err error) {
	status := httpStatusOf(err)
	if status == statusClientClosedRequest {
		// The client is gone; writing would only log a broken pipe.
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Message: errorMessage(err)})
}
