package volume

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/ChPuru/hull/internal/fsutil"
)

const (
	// refsFileName is the reference index inside the volumes root.
	refsFileName = "refs.json"
	// refsLockName guards the reference index against other processes.
	refsLockName = "refs.lock"
	// refsVersion is stamped into the file so a future hull can migrate it
	// instead of guessing at the shape.
	refsVersion = 1
)

// refIndex is the on-disk shape of <root>/refs.json: which containers currently
// reference which volume. The length of a volume's slice is its reference
// count, and a volume with no entry is unused ("dangling").
//
// Container IDs rather than a bare integer are kept deliberately: a plain count
// cannot survive a crash between Unref and the container record being deleted,
// whereas a set can be reconciled against the container index.
type refIndex struct {
	Version int                 `json:"version"`
	Refs    map[string][]string `json:"refs"`
}

func (m *Manager) refsPath() string     { return filepath.Join(m.root, refsFileName) }
func (m *Manager) refsLockPath() string { return filepath.Join(m.root, refsLockName) }

// loadRefs reads the reference index. A missing file is an empty index; a
// corrupt one is an error, because the file is only ever replaced by an atomic
// rename and treating a corrupt one as empty would silently free live volumes.
func (m *Manager) loadRefs() (*refIndex, error) {
	idx := &refIndex{Version: refsVersion, Refs: map[string][]string{}}
	if err := fsutil.ReadJSON(m.refsPath(), idx); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &refIndex{Version: refsVersion, Refs: map[string][]string{}}, nil
		}
		return nil, fmt.Errorf("volume: read reference index: %w", err)
	}
	if idx.Refs == nil {
		idx.Refs = map[string][]string{}
	}
	return idx, nil
}

// storeRefs replaces the reference index atomically.
func (m *Manager) storeRefs(idx *refIndex) error {
	idx.Version = refsVersion
	for name, ids := range idx.Refs {
		if len(ids) == 0 {
			delete(idx.Refs, name)
		}
	}
	if err := fsutil.WriteJSONAtomic(m.refsPath(), idx, 0o600); err != nil {
		return fmt.Errorf("volume: persist reference index: %w", err)
	}
	return nil
}

// withRefs runs fn under the in-process mutex and the cross-process reference
// lock, persisting the index if fn reports it changed.
//
// On platforms without flock (Windows, where only the CLI runs) the file lock
// is skipped: the manager is a daemon-side object and the daemon only ever runs
// inside the engine distro.
func (m *Manager) withRefs(fn func(*refIndex) (bool, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.withRefsLocked(fn)
}

// withRefsLocked is withRefs for callers that already hold m.mu.
func (m *Manager) withRefsLocked(fn func(*refIndex) (bool, error)) error {
	lk, err := fsutil.FileLock(m.refsLockPath())
	if err != nil && !errors.Is(err, fsutil.ErrUnsupported) {
		return fmt.Errorf("volume: lock reference index: %w", err)
	}
	if lk != nil {
		defer func() { _ = lk.Unlock() }()
	}
	idx, err := m.loadRefs()
	if err != nil {
		return err
	}
	dirty, err := fn(idx)
	if err != nil {
		return err
	}
	if !dirty {
		return nil
	}
	return m.storeRefs(idx)
}

// addRef inserts id into the volume's reference set, reporting whether the set
// changed.
func addRef(idx *refIndex, name, id string) bool {
	for _, have := range idx.Refs[name] {
		if have == id {
			return false
		}
	}
	ids := append(idx.Refs[name], id)
	sort.Strings(ids)
	idx.Refs[name] = ids
	return true
}

// removeRef deletes id from the volume's reference set, reporting whether the
// set changed.
func removeRef(idx *refIndex, name, id string) bool {
	ids := idx.Refs[name]
	out := ids[:0:0]
	changed := false
	for _, have := range ids {
		if have == id {
			changed = true
			continue
		}
		out = append(out, have)
	}
	if !changed {
		return false
	}
	if len(out) == 0 {
		delete(idx.Refs, name)
	} else {
		idx.Refs[name] = out
	}
	return true
}

// Ref records that containerID uses the named volume. It is idempotent: a
// second Ref by the same container is a no-op, which matters because a
// container that is started, stopped and started again must not leak a count.
func (m *Manager) Ref(name, containerID string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if containerID == "" {
		return fmt.Errorf("volume: Ref %s: empty container id", name)
	}
	if _, err := m.Get(name); err != nil {
		return err
	}
	return m.withRefs(func(idx *refIndex) (bool, error) {
		return addRef(idx, name, containerID), nil
	})
}

// Unref drops containerID's reference to the named volume. Unreferencing a
// volume that was never referenced is not an error, so cleanup paths can run
// unconditionally.
func (m *Manager) Unref(name, containerID string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if containerID == "" {
		return fmt.Errorf("volume: Unref %s: empty container id", name)
	}
	return m.withRefs(func(idx *refIndex) (bool, error) {
		return removeRef(idx, name, containerID), nil
	})
}

// Refs returns the container IDs currently referencing the named volume, sorted.
// An unused volume yields an empty slice, not an error.
func (m *Manager) Refs(name string) ([]string, error) {
	var out []string
	err := m.withRefs(func(idx *refIndex) (bool, error) {
		out = append(out, idx.Refs[name]...)
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RefCount returns how many containers reference the named volume.
func (m *Manager) RefCount(name string) (int, error) {
	ids, err := m.Refs(name)
	if err != nil {
		return 0, err
	}
	return len(ids), nil
}
