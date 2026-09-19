package state

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// nameRE is the name grammar hull accepts, matching Docker's:
// an optional leading slash, then an alphanumeric, then at least one more
// alphanumeric, underscore, dot or dash.
var nameRE = regexp.MustCompile(`^/?[a-zA-Z0-9][a-zA-Z0-9_.-]+$`)

// maxNameLen bounds a name so a reservation always fits in one path component
// on every filesystem hull may be installed on.
const maxNameLen = 128

// ValidateName reports whether name is a legal hull container name. A valid
// name matches ^/?[a-zA-Z0-9][a-zA-Z0-9_.-]+$ — which, by construction, can
// never contain a path separator or "..", so a validated name is safe to join
// onto the names directory.
func ValidateName(name string) error {
	if name == "" {
		return &InvalidNameError{Name: name, Reason: "name is empty"}
	}
	if len(name) > maxNameLen {
		return &InvalidNameError{Name: name, Reason: fmt.Sprintf("name is longer than %d characters", maxNameLen)}
	}
	if !nameRE.MatchString(name) {
		return &InvalidNameError{
			Name:   name,
			Reason: "must start with a letter or digit and contain only letters, digits, '_', '.' and '-' (at least 2 characters)",
		}
	}
	return nil
}

// normalizeName strips Docker's leading slash after validating the name.
func normalizeName(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	return strings.TrimPrefix(name, "/"), nil
}

// NewID returns a fresh container/network/endpoint identifier: 32 bytes from
// the system CSPRNG, hex encoded to 64 characters.
func NewID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read on Linux is getrandom(2) and only fails if the
		// kernel is broken; there is no safe way to continue without entropy.
		panic(fmt.Sprintf("hull: cannot read from the system CSPRNG: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// nameLinkPath returns the reservation path for an already-normalized name.
func (s *Store) nameLinkPath(name string) string {
	return filepath.Join(s.namesDir(), name)
}

// nameTarget is the relative symlink body a reservation stores. Keeping it
// relative means the whole state tree can be moved or bind-mounted elsewhere
// without invalidating every name.
func nameTarget(id string) string { return "../containers/" + id }

// idFromTarget extracts the container ID out of a reservation symlink body.
func idFromTarget(target string) string {
	target = strings.ReplaceAll(target, `\`, "/")
	if i := strings.LastIndexByte(target, '/'); i >= 0 {
		return target[i+1:]
	}
	return target
}

// lookupName resolves a name reservation to a container ID. A missing link, a
// malformed link, or a link that points at a container directory which no
// longer exists all report a *NotFoundError, because none of them names a live
// container.
func (s *Store) lookupName(name string) (string, error) {
	norm, err := normalizeName(name)
	if err != nil {
		return "", err
	}
	target, err := os.Readlink(s.nameLinkPath(norm))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", &NotFoundError{Kind: "container", Ref: name}
		}
		if errors.Is(err, fs.ErrInvalid) || isNotSymlink(err) {
			s.logger.Warn("hull: name entry is not a symlink", "name", norm)
			return "", &NotFoundError{Kind: "container", Ref: name}
		}
		return "", fmt.Errorf("read name reservation %s: %w", norm, err)
	}
	id := idFromTarget(target)
	if validateFullID(id) != nil {
		s.logger.Warn("hull: name reservation points somewhere unexpected", "name", norm, "target", target)
		return "", &NotFoundError{Kind: "container", Ref: name}
	}
	if fi, err := os.Stat(s.ContainerDir(id)); err != nil || !fi.IsDir() {
		// Dangling: the daemon died between removing the container directory
		// and removing the name. Recover sweeps these up.
		return "", &NotFoundError{Kind: "container", Ref: name}
	}
	return id, nil
}

// ReserveName atomically claims name for container id.
//
// The reservation is a symlink <root>/names/<name> -> ../containers/<id>.
// symlink(2) fails with EEXIST if the name is taken, so the claim is atomic
// with no lock and it survives a crash: on restart the link is either fully
// there or not there at all.
//
// It returns a *NameInUseError (errors.Is ErrNameInUse) when another container
// holds the name, and nil when id already holds it, so retrying a half-finished
// create is safe. A reservation left dangling by a crash is reclaimed.
func (s *Store) ReserveName(name, id string) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	norm, err := normalizeName(name)
	if err != nil {
		return err
	}
	if err := validateFullID(id); err != nil {
		return err
	}
	link := s.nameLinkPath(norm)

	for attempt := 0; attempt < 2; attempt++ {
		err := os.Symlink(nameTarget(id), link)
		if err == nil {
			if err := syncDir(s.namesDir()); err != nil {
				return fmt.Errorf("fsync names dir: %w", err)
			}
			return nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("reserve name %q: %w", norm, err)
		}

		owner := ""
		if target, rerr := os.Readlink(link); rerr == nil {
			owner = idFromTarget(target)
		}
		if owner == id {
			return nil // already ours
		}
		if owner != "" && validateFullID(owner) == nil {
			if fi, serr := os.Stat(s.ContainerDir(owner)); serr == nil && fi.IsDir() {
				return &NameInUseError{Name: norm, Owner: owner}
			}
		}
		// The existing entry is dangling or malformed. Drop it and try once
		// more; if someone else wins the race we report ErrNameInUse below.
		if rerr := os.Remove(link); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			return &NameInUseError{Name: norm, Owner: owner}
		}
	}
	return &NameInUseError{Name: norm}
}

// ReleaseName removes a name reservation. Releasing a name that is not
// reserved is not an error, so cleanup paths can call it unconditionally.
func (s *Store) ReleaseName(name string) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	norm, err := normalizeName(name)
	if err != nil {
		return err
	}
	if err := os.Remove(s.nameLinkPath(norm)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("release name %q: %w", norm, err)
	}
	if err := syncDir(s.namesDir()); err != nil {
		return fmt.Errorf("fsync names dir: %w", err)
	}
	return nil
}

// releaseNameIfOwnedBy removes a reservation only when it still points at id,
// so deleting container A can never steal the name of container B that reused
// it after A was renamed.
func (s *Store) releaseNameIfOwnedBy(name, id string) error {
	norm, err := normalizeName(name)
	if err != nil {
		return err
	}
	target, err := os.Readlink(s.nameLinkPath(norm))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read name reservation %s: %w", norm, err)
	}
	if idFromTarget(target) != id {
		return nil
	}
	return s.ReleaseName(norm)
}

// GenerateName returns an unused Docker-style "adjective_scientist" name.
//
// It retries on collision with the reservations already on disk, and after
// enough collisions falls back to appending a numeric suffix so it always
// terminates. The name is not reserved by this call; pass it to ReserveName,
// and on ErrNameInUse (someone raced you) call GenerateName again.
func (s *Store) GenerateName() string {
	const plainAttempts = 12
	for i := 0; ; i++ {
		s.rndMu.Lock()
		adj := adjectives[s.rnd.IntN(len(adjectives))]
		sci := scientists[s.rnd.IntN(len(scientists))]
		suffix := 0
		if i >= plainAttempts {
			suffix = s.rnd.IntN(1_000_000)
		}
		s.rndMu.Unlock()

		// Steve Wozniak is not boring. (Docker's own joke, kept for parity.)
		if adj == "boring" && sci == "wozniak" {
			continue
		}
		candidate := adj + "_" + sci
		if i >= plainAttempts {
			candidate = fmt.Sprintf("%s_%d", candidate, suffix)
		}
		if s.nameAvailable(candidate) {
			return candidate
		}
	}
}

// nameAvailable reports whether no reservation exists for candidate.
func (s *Store) nameAvailable(candidate string) bool {
	_, err := os.Lstat(s.nameLinkPath(candidate))
	return errors.Is(err, fs.ErrNotExist)
}
