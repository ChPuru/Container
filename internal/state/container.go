package state

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rahuldhali/hull/internal/types"
)

const (
	// stateFile is the per-container record inside <root>/containers/<id>.
	stateFile = "state.json"
	// containerLockFile serialises read-modify-write cycles on stateFile
	// across processes (daemon vs. shim).
	containerLockFile = "state.lock"
	// minPrefixLen is the shortest ID prefix Resolve will consider. Anything
	// shorter matches far too much to be a safe shorthand for "docker rm".
	minPrefixLen = 3
	// idLen is the length of a hull container ID in hex characters.
	idLen = 64
)

// isHexString reports whether s is non-empty and made only of lowercase hex
// digits. Every hull ID is generated that way, so this doubles as the guard
// that keeps a container-controlled reference from ever containing a path
// separator or "..".
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

// validateFullID checks that id is exactly 64 lowercase hex characters.
func validateFullID(id string) error {
	if len(id) != idLen || !isHexString(id) {
		return fmt.Errorf("%w: %q is not a 64-character lowercase hex id", ErrInvalidID, id)
	}
	return nil
}

// PutContainer writes c's record to <root>/containers/<id>/state.json
// atomically: the JSON is staged in state.json.tmp, fsynced, renamed over
// state.json and the directory is fsynced. A reader concurrent with this call
// sees either the old record or the new one.
func (s *Store) PutContainer(c *types.Container) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if c == nil {
		return errors.New("state: PutContainer called with a nil container")
	}
	if err := validateFullID(c.ID); err != nil {
		return err
	}
	dir := s.ContainerDir(c.ID)
	if err := mkdirAll(dir, dirPerm); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(dir, stateFile), c, filePerm); err != nil {
		return fmt.Errorf("persist container %s: %w", c.ID, err)
	}
	return nil
}

// readContainerAt loads one container record from an already-known directory.
func readContainerAt(dir string) (*types.Container, error) {
	var c types.Container
	if err := readJSON(filepath.Join(dir, stateFile), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// GetContainer returns the record for a container named by an exact ID, a
// unique ID prefix of at least three characters, or an exact name. It returns a
// *NotFoundError (errors.Is ErrNotFound) or a *AmbiguousError (errors.Is
// ErrAmbiguous) when the reference does not identify exactly one container.
func (s *Store) GetContainer(idOrName string) (*types.Container, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	id, err := s.Resolve(idOrName)
	if err != nil {
		return nil, err
	}
	c, err := readContainerAt(s.ContainerDir(id))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, &NotFoundError{Kind: "container", Ref: idOrName}
		}
		return nil, fmt.Errorf("load container %s: %w", id, err)
	}
	return c, nil
}

// ListContainers returns every readable container record, sorted newest first.
//
// A container directory whose state.json is missing, truncated or corrupt is
// logged and skipped rather than failing the whole listing: one bad record must
// never make "hull ps" stop working.
func (s *Store) ListContainers() ([]*types.Container, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.containersDir())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("list containers: %w", err)
	}
	out := make([]*types.Container, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if validateFullID(id) != nil {
			s.logger.Warn("hull: ignoring unexpected entry in containers directory", "name", id)
			continue
		}
		c, err := readContainerAt(s.ContainerDir(id))
		if err != nil {
			s.logger.Warn("hull: skipping unreadable container record", "id", id, "err", err)
			continue
		}
		if c.ID != id {
			s.logger.Warn("hull: skipping container record with mismatched id",
				"dir", id, "record", c.ID)
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Created.Equal(out[j].Created) {
			return out[i].ID < out[j].ID
		}
		return out[i].Created.After(out[j].Created)
	})
	return out, nil
}

// DeleteContainer removes a container's whole directory, together with the name
// reservation pointing at it. It returns a *NotFoundError if the container does
// not exist.
func (s *Store) DeleteContainer(id string) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := validateFullID(id); err != nil {
		return err
	}
	dir := s.ContainerDir(id)
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &NotFoundError{Kind: "container", Ref: id}
		}
		return fmt.Errorf("stat container %s: %w", id, err)
	}

	// Release the name first. If we are killed between the two steps the name
	// link is merely dangling, which Recover cleans up; the reverse order would
	// leave a name permanently reserved by a container that no longer exists.
	if c, err := readContainerAt(dir); err == nil && c.Name != "" {
		if err := s.releaseNameIfOwnedBy(c.Name, id); err != nil {
			s.logger.Warn("hull: could not release container name", "name", c.Name, "id", id, "err", err)
		}
	}

	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove container %s: %w", id, err)
	}
	if err := syncDir(s.containersDir()); err != nil {
		return fmt.Errorf("fsync containers dir: %w", err)
	}
	s.forgetContainerMutex(id)
	return nil
}

// UpdateContainer reads a container's record, applies fn to it and writes the
// result back atomically.
//
// The whole read-modify-write runs under a process-local mutex for this
// container *and* an exclusive advisory lock on
// <root>/containers/<id>/state.lock, so neither two daemon goroutines nor the
// daemon and a container's shim can interleave and lose an update. If fn
// returns an error, nothing is written and that error is returned unchanged.
func (s *Store) UpdateContainer(id string, fn func(*types.Container) error) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if fn == nil {
		return errors.New("state: UpdateContainer called with a nil function")
	}
	resolved, err := s.Resolve(id)
	if err != nil {
		return err
	}
	dir := s.ContainerDir(resolved)

	mu := s.containerMutex(resolved)
	mu.Lock()
	defer mu.Unlock()

	lk, err := acquireFileLock(filepath.Join(dir, containerLockFile))
	if err != nil {
		return err
	}
	defer lk.release()

	c, err := readContainerAt(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &NotFoundError{Kind: "container", Ref: id}
		}
		return fmt.Errorf("load container %s: %w", resolved, err)
	}
	if err := fn(c); err != nil {
		return err
	}
	if c.ID != resolved {
		return fmt.Errorf("state: UpdateContainer callback changed the id from %s to %s", resolved, c.ID)
	}
	if err := writeJSONAtomic(filepath.Join(dir, stateFile), c, filePerm); err != nil {
		return fmt.Errorf("persist container %s: %w", resolved, err)
	}
	return nil
}

// Resolve turns a user-supplied reference into a full container ID.
//
// It accepts, in order: an exact 64-character ID, an exact container name (with
// or without Docker's leading slash), and a unique ID prefix of at least
// minPrefixLen characters. It returns a *NotFoundError when nothing matches and
// a *AmbiguousError listing every candidate when a prefix matches more than one
// container.
//
// References come straight from the API and may be attacker-controlled, so
// Resolve never joins a reference onto a path before proving it is either pure
// lowercase hex or a valid hull name; neither can contain a separator or "..".
func (s *Store) Resolve(prefixOrName string) (string, error) {
	if err := s.checkOpen(); err != nil {
		return "", err
	}
	ref := strings.TrimPrefix(prefixOrName, "/")
	if ref == "" {
		return "", &NotFoundError{Kind: "container", Ref: prefixOrName}
	}

	// 1. Exact ID.
	if len(ref) == idLen && isHexString(ref) {
		if fi, err := os.Stat(s.ContainerDir(ref)); err == nil && fi.IsDir() {
			return ref, nil
		}
	}

	// 2. Exact name.
	if ValidateName(ref) == nil {
		id, err := s.lookupName(ref)
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return "", err
		}
	}

	// 3. Unique ID prefix.
	if len(ref) >= minPrefixLen && len(ref) < idLen && isHexString(ref) {
		matches, err := s.matchIDPrefix(ref)
		if err != nil {
			return "", err
		}
		switch len(matches) {
		case 0:
		case 1:
			return matches[0], nil
		default:
			sort.Strings(matches)
			return "", &AmbiguousError{Kind: "container", Prefix: ref, Matches: matches}
		}
	}

	return "", &NotFoundError{Kind: "container", Ref: prefixOrName}
}

// matchIDPrefix lists the container IDs starting with prefix.
func (s *Store) matchIDPrefix(prefix string) ([]string, error) {
	entries, err := os.ReadDir(s.containersDir())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan containers: %w", err)
	}
	var matches []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if validateFullID(name) != nil {
			continue
		}
		if strings.HasPrefix(name, prefix) {
			matches = append(matches, name)
		}
	}
	return matches, nil
}
