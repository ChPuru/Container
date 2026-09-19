package state

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors returned (usually wrapped) by the store. Callers should test
// them with errors.Is rather than comparing error values directly, because the
// store wraps them in richer types that carry the offending identifier.
var (
	// ErrNotFound means no container, network or volume matched the reference.
	ErrNotFound = errors.New("no such object")

	// ErrAmbiguous means an ID prefix matched more than one object.
	ErrAmbiguous = errors.New("ambiguous reference")

	// ErrNameInUse means a name reservation collided with an existing one.
	ErrNameInUse = errors.New("name already in use")

	// ErrAlreadyLocked means another hull daemon already holds the store lock.
	ErrAlreadyLocked = errors.New("state directory is locked by another daemon")

	// ErrInvalidName means a name failed ValidateName.
	ErrInvalidName = errors.New("invalid name")

	// ErrInvalidID means an ID or ID prefix was not lowercase hex, or a full ID
	// was not exactly 64 characters.
	ErrInvalidID = errors.New("invalid id")

	// ErrClosed means the store has already been closed.
	ErrClosed = errors.New("state store is closed")
)

// NotFoundError reports which reference of which kind could not be resolved.
type NotFoundError struct {
	Kind string // "container", "network" or "volume"
	Ref  string
}

// Error implements error.
func (e *NotFoundError) Error() string {
	return fmt.Sprintf("no such %s: %s", e.Kind, e.Ref)
}

// Unwrap makes errors.Is(err, ErrNotFound) true.
func (e *NotFoundError) Unwrap() error { return ErrNotFound }

// AmbiguousError reports an ID prefix that matched several objects, and lists
// every match so the CLI can print an actionable message.
type AmbiguousError struct {
	Kind    string
	Prefix  string
	Matches []string
}

// Error implements error.
func (e *AmbiguousError) Error() string {
	show := e.Matches
	const max = 8
	suffix := ""
	if len(show) > max {
		suffix = fmt.Sprintf(" (and %d more)", len(show)-max)
		show = show[:max]
	}
	return fmt.Sprintf("%s prefix %q is ambiguous, it matches %d objects: %s%s",
		e.Kind, e.Prefix, len(e.Matches), strings.Join(show, ", "), suffix)
}

// Unwrap makes errors.Is(err, ErrAmbiguous) true.
func (e *AmbiguousError) Unwrap() error { return ErrAmbiguous }

// NameInUseError reports the name that was taken and the ID that holds it.
type NameInUseError struct {
	Name  string
	Owner string // container ID currently holding the name
}

// Error implements error.
func (e *NameInUseError) Error() string {
	if e.Owner == "" {
		return fmt.Sprintf("the name %q is already in use", e.Name)
	}
	return fmt.Sprintf("the name %q is already in use by container %s", e.Name, e.Owner)
}

// Unwrap makes errors.Is(err, ErrNameInUse) true.
func (e *NameInUseError) Unwrap() error { return ErrNameInUse }

// LockedError reports that the store lock is held, and by which pid if the pid
// file could be read.
type LockedError struct {
	Path string // path of the lock file
	Pid  int    // 0 when <root>/run/hull.pid was missing or unreadable
}

// Error implements error.
func (e *LockedError) Error() string {
	if e.Pid > 0 {
		return fmt.Sprintf("another hull daemon (pid %d) already holds %s; "+
			"stop it before starting a second daemon", e.Pid, e.Path)
	}
	return fmt.Sprintf("another hull daemon already holds %s "+
		"(its pid file is missing or unreadable); stop it before starting a second daemon", e.Path)
}

// Unwrap makes errors.Is(err, ErrAlreadyLocked) true.
func (e *LockedError) Unwrap() error { return ErrAlreadyLocked }

// InvalidNameError reports a name that failed validation and why.
type InvalidNameError struct {
	Name   string
	Reason string
}

// Error implements error.
func (e *InvalidNameError) Error() string {
	return fmt.Sprintf("invalid name %q: %s", e.Name, e.Reason)
}

// Unwrap makes errors.Is(err, ErrInvalidName) true.
func (e *InvalidNameError) Unwrap() error { return ErrInvalidName }
