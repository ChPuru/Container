// Package volume implements hull's named volumes, bind mounts and the Windows
// path story: the part of the engine a user notices immediately when
// "docker run -v C:\Users\me\proj:/app" either works or does not.
//
// The package owns three related jobs.
//
// Parsing. ParseBind understands every shape of the short -v flag, including
// the Windows drive-letter forms whose colon must not be mistaken for the field
// separator, and ParseMount understands the long --mount CSV form with proper
// quoting. Both produce a types.Mount.
//
// Bookkeeping. Manager creates, lists, reference-counts and removes named
// volumes under /var/lib/hull/volumes, persisting the volume records through
// internal/state and the reference counts in <root>/refs.json.
//
// Materialisation. Manager.Resolve turns a container's Binds, Mounts, Tmpfs and
// the image's VOLUME set into one ordered, de-duplicated mount list with volume
// sources replaced by their real _data directories, seeding a fresh volume from
// the image's content at that path first. Manager.Release undoes the references
// when the container goes away.
//
// Only the "local" driver exists. Anything else is refused loudly rather than
// quietly degraded.
package volume

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors. Callers should test them with errors.Is; the richer error
// types below wrap them and carry the offending identifier.
var (
	// ErrNotFound means no volume with that name is recorded.
	ErrNotFound = errors.New("no such volume")

	// ErrDriverUnsupported means a volume driver other than "local" was asked
	// for. hull ships no volume plugin host, so there is nothing to delegate to.
	ErrDriverUnsupported = errors.New("volume driver not supported")

	// ErrInUse means a volume still has at least one container referencing it.
	ErrInUse = errors.New("volume is in use")

	// ErrInvalidName means a volume name failed validation.
	ErrInvalidName = errors.New("invalid volume name")

	// ErrInvalidMount means a -v or --mount specification could not be parsed,
	// or parsed into something hull refuses to mount.
	ErrInvalidMount = errors.New("invalid mount specification")

	// ErrConflict means two mount requests claimed the same container target.
	ErrConflict = errors.New("duplicate mount target")

	// ErrUNCPath means a bind source was a Windows UNC path such as \wsl$\...,
	// which hull deliberately refuses; see TranslateWindowsPath.
	ErrUNCPath = errors.New("windows UNC path cannot be used as a bind source")
)

// NotFoundError reports the volume name that could not be resolved.
type NotFoundError struct {
	Name string
}

// Error implements error.
func (e *NotFoundError) Error() string {
	return fmt.Sprintf("no such volume: %s", e.Name)
}

// Unwrap lets errors.Is(err, ErrNotFound) succeed.
func (e *NotFoundError) Unwrap() error { return ErrNotFound }

// InUseError reports which containers still reference a volume, so the operator
// is told what to stop rather than just that the removal failed.
type InUseError struct {
	Name       string
	Containers []string
}

// Error implements error.
func (e *InUseError) Error() string {
	if len(e.Containers) == 0 {
		return fmt.Sprintf("volume %s is in use", e.Name)
	}
	short := make([]string, 0, len(e.Containers))
	for _, id := range e.Containers {
		if len(id) > 12 {
			id = id[:12]
		}
		short = append(short, id)
	}
	return fmt.Sprintf("volume %s is in use by %d container(s): %s (use force to remove anyway)",
		e.Name, len(e.Containers), strings.Join(short, ", "))
}

// Unwrap lets errors.Is(err, ErrInUse) succeed.
func (e *InUseError) Unwrap() error { return ErrInUse }

// DriverError reports an unsupported volume driver by name.
type DriverError struct {
	Driver string
}

// Error implements error.
func (e *DriverError) Error() string {
	return fmt.Sprintf("volume driver %q is not supported; hull only implements the built-in %q driver", e.Driver, DriverLocal)
}

// Unwrap lets errors.Is(err, ErrDriverUnsupported) succeed.
func (e *DriverError) Unwrap() error { return ErrDriverUnsupported }
