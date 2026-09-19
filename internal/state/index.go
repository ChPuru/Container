package state

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rahuldhali/hull/internal/types"
)

// indexVersion is stamped into the on-disk index files so a future hull can
// migrate them instead of guessing at the shape.
const indexVersion = 1

// networkIndex is the on-disk shape of <root>/networks/networks.json.
type networkIndex struct {
	Version  int                       `json:"version"`
	Networks map[string]*types.Network `json:"networks"`
}

// volumeIndex is the on-disk shape of <root>/volumes/volumes.json.
type volumeIndex struct {
	Version int                      `json:"version"`
	Volumes map[string]*types.Volume `json:"volumes"`
}

func (s *Store) networkIndexPath() string {
	return filepath.Join(s.root, "networks", "networks.json")
}

func (s *Store) networkLockPath() string {
	return filepath.Join(s.root, "networks", "networks.lock")
}

func (s *Store) volumeIndexPath() string {
	return filepath.Join(s.root, "volumes", "volumes.json")
}

func (s *Store) volumeLockPath() string {
	return filepath.Join(s.root, "volumes", "volumes.lock")
}

// loadNetworkIndex reads the network index. A missing file is an empty index;
// a corrupt one is an error, because the index is only ever replaced by an
// atomic rename and losing it silently would lose every network.
func (s *Store) loadNetworkIndex() (*networkIndex, error) {
	idx := &networkIndex{Version: indexVersion, Networks: map[string]*types.Network{}}
	if err := readJSON(s.networkIndexPath(), idx); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &networkIndex{Version: indexVersion, Networks: map[string]*types.Network{}}, nil
		}
		return nil, err
	}
	if idx.Networks == nil {
		idx.Networks = map[string]*types.Network{}
	}
	return idx, nil
}

func (s *Store) storeNetworkIndex(idx *networkIndex) error {
	idx.Version = indexVersion
	return writeJSONAtomic(s.networkIndexPath(), idx, filePerm)
}

func (s *Store) loadVolumeIndex() (*volumeIndex, error) {
	idx := &volumeIndex{Version: indexVersion, Volumes: map[string]*types.Volume{}}
	if err := readJSON(s.volumeIndexPath(), idx); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &volumeIndex{Version: indexVersion, Volumes: map[string]*types.Volume{}}, nil
		}
		return nil, err
	}
	if idx.Volumes == nil {
		idx.Volumes = map[string]*types.Volume{}
	}
	return idx, nil
}

func (s *Store) storeVolumeIndex(idx *volumeIndex) error {
	idx.Version = indexVersion
	return writeJSONAtomic(s.volumeIndexPath(), idx, filePerm)
}

// ---------- networks ----------

// PutNetwork inserts or replaces a network in the index.
//
// The index is one JSON file, so the whole read-modify-write runs under the
// store's network RWMutex (in-process) and an exclusive advisory lock on
// networks/networks.lock (cross-process), and the file is replaced by the same
// tmp + fsync + rename sequence used for container records.
func (s *Store) PutNetwork(n *types.Network) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if n == nil {
		return errors.New("state: PutNetwork called with a nil network")
	}
	if n.ID == "" {
		return fmt.Errorf("%w: network id is empty", ErrInvalidID)
	}
	if err := ValidateName(n.Name); err != nil {
		return err
	}

	s.netMu.Lock()
	defer s.netMu.Unlock()
	lk, err := acquireFileLock(s.networkLockPath())
	if err != nil {
		return err
	}
	defer lk.release()

	idx, err := s.loadNetworkIndex()
	if err != nil {
		return err
	}
	for id, other := range idx.Networks {
		if id != n.ID && other != nil && other.Name == n.Name {
			return &NameInUseError{Name: n.Name, Owner: id}
		}
	}
	idx.Networks[n.ID] = n
	if err := s.storeNetworkIndex(idx); err != nil {
		return fmt.Errorf("persist network %s: %w", n.ID, err)
	}
	return nil
}

// GetNetwork returns a network by exact ID, exact name, or unique ID prefix of
// at least three characters.
func (s *Store) GetNetwork(idOrName string) (*types.Network, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	s.netMu.RLock()
	defer s.netMu.RUnlock()
	lk, err := acquireFileLock(s.networkLockPath())
	if err != nil {
		return nil, err
	}
	defer lk.release()

	idx, err := s.loadNetworkIndex()
	if err != nil {
		return nil, err
	}
	ref := strings.TrimPrefix(idOrName, "/")
	if ref == "" {
		return nil, &NotFoundError{Kind: "network", Ref: idOrName}
	}
	if n, ok := idx.Networks[ref]; ok && n != nil {
		return n, nil
	}
	for _, n := range idx.Networks {
		if n != nil && n.Name == ref {
			return n, nil
		}
	}
	if len(ref) >= minPrefixLen {
		var matches []string
		for id, n := range idx.Networks {
			if n != nil && strings.HasPrefix(id, ref) {
				matches = append(matches, id)
			}
		}
		switch len(matches) {
		case 0:
		case 1:
			return idx.Networks[matches[0]], nil
		default:
			sort.Strings(matches)
			return nil, &AmbiguousError{Kind: "network", Prefix: ref, Matches: matches}
		}
	}
	return nil, &NotFoundError{Kind: "network", Ref: idOrName}
}

// ListNetworks returns every network in the index, sorted by name.
func (s *Store) ListNetworks() ([]*types.Network, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	s.netMu.RLock()
	defer s.netMu.RUnlock()
	lk, err := acquireFileLock(s.networkLockPath())
	if err != nil {
		return nil, err
	}
	defer lk.release()

	idx, err := s.loadNetworkIndex()
	if err != nil {
		return nil, err
	}
	out := make([]*types.Network, 0, len(idx.Networks))
	for _, n := range idx.Networks {
		if n != nil {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].ID < out[j].ID
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// DeleteNetwork removes a network from the index by exact ID. It returns a
// *NotFoundError if no such network is recorded.
func (s *Store) DeleteNetwork(id string) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if id == "" {
		return &NotFoundError{Kind: "network", Ref: id}
	}
	s.netMu.Lock()
	defer s.netMu.Unlock()
	lk, err := acquireFileLock(s.networkLockPath())
	if err != nil {
		return err
	}
	defer lk.release()

	idx, err := s.loadNetworkIndex()
	if err != nil {
		return err
	}
	if _, ok := idx.Networks[id]; !ok {
		return &NotFoundError{Kind: "network", Ref: id}
	}
	delete(idx.Networks, id)
	if err := s.storeNetworkIndex(idx); err != nil {
		return fmt.Errorf("persist network index: %w", err)
	}
	return nil
}

// ---------- volumes ----------

// PutVolume inserts or replaces a volume in the index, under the same
// mutex + flock + atomic-rename discipline as PutNetwork.
func (s *Store) PutVolume(v *types.Volume) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if v == nil {
		return errors.New("state: PutVolume called with a nil volume")
	}
	if err := ValidateName(v.Name); err != nil {
		return err
	}

	s.volMu.Lock()
	defer s.volMu.Unlock()
	lk, err := acquireFileLock(s.volumeLockPath())
	if err != nil {
		return err
	}
	defer lk.release()

	idx, err := s.loadVolumeIndex()
	if err != nil {
		return err
	}
	idx.Volumes[v.Name] = v
	if err := s.storeVolumeIndex(idx); err != nil {
		return fmt.Errorf("persist volume %s: %w", v.Name, err)
	}
	return nil
}

// GetVolume returns a volume by its exact name.
func (s *Store) GetVolume(name string) (*types.Volume, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	s.volMu.RLock()
	defer s.volMu.RUnlock()
	lk, err := acquireFileLock(s.volumeLockPath())
	if err != nil {
		return nil, err
	}
	defer lk.release()

	idx, err := s.loadVolumeIndex()
	if err != nil {
		return nil, err
	}
	if v, ok := idx.Volumes[name]; ok && v != nil {
		return v, nil
	}
	return nil, &NotFoundError{Kind: "volume", Ref: name}
}

// ListVolumes returns every volume in the index, sorted by name.
func (s *Store) ListVolumes() ([]*types.Volume, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	s.volMu.RLock()
	defer s.volMu.RUnlock()
	lk, err := acquireFileLock(s.volumeLockPath())
	if err != nil {
		return nil, err
	}
	defer lk.release()

	idx, err := s.loadVolumeIndex()
	if err != nil {
		return nil, err
	}
	out := make([]*types.Volume, 0, len(idx.Volumes))
	for _, v := range idx.Volumes {
		if v != nil {
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteVolume removes a volume from the index by name. It returns a
// *NotFoundError if no such volume is recorded. It does not touch the volume's
// data directory; that is the engine's job, after it has checked that no
// container still refers to the volume.
func (s *Store) DeleteVolume(name string) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	s.volMu.Lock()
	defer s.volMu.Unlock()
	lk, err := acquireFileLock(s.volumeLockPath())
	if err != nil {
		return err
	}
	defer lk.release()

	idx, err := s.loadVolumeIndex()
	if err != nil {
		return err
	}
	if _, ok := idx.Volumes[name]; !ok {
		return &NotFoundError{Kind: "volume", Ref: name}
	}
	delete(idx.Volumes, name)
	if err := s.storeVolumeIndex(idx); err != nil {
		return fmt.Errorf("persist volume index: %w", err)
	}
	return nil
}

// VolumeDir returns the directory that holds a named volume's data
// (<root>/volumes/<name>/_data). The name must have passed ValidateName, which
// guarantees it cannot escape the volumes directory.
func (s *Store) VolumeDir(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	return filepath.Join(s.root, "volumes", name, "_data"), nil
}
