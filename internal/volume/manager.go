package volume

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ChPuru/hull/internal/fsutil"
	"github.com/ChPuru/hull/internal/idutil"
	"github.com/ChPuru/hull/internal/state"
	"github.com/ChPuru/hull/internal/types"
)

const (
	// DriverLocal is the only volume driver hull implements. There is no
	// plugin host, so any other driver is an error rather than a fallback.
	DriverLocal = "local"

	// AnonymousLabel marks a volume hull created implicitly for a container,
	// rather than one the user named. This is the exact label both docker and
	// docker compose look for when deciding what `docker volume prune` and
	// `docker rm -v` may throw away, so it must not be spelled differently.
	AnonymousLabel = "com.docker.volume.anonymous"

	// ScopeLocal is the only scope hull has; there is no cluster.
	ScopeLocal = "local"

	// dataDirName is the subdirectory of a volume that holds its contents.
	// Keeping the data one level down leaves room for per-volume metadata
	// beside it without it ever appearing inside the container.
	dataDirName = "_data"

	// dataDirPerm is the mode of <root>/<name> and <root>/<name>/_data.
	// 0755 matches Docker, so an image that runs as a non-root user can still
	// traverse into a volume it does not own.
	dataDirPerm fs.FileMode = 0o755
)

// localOptKeys are the options the built-in local driver understands. They are
// recorded on the volume at Create time and consumed at mount time: "type" and
// "o" describe a filesystem to mount (tmpfs is the useful case), and "device"
// names what to mount (a block device, or a host path for a bind-style volume).
var localOptKeys = map[string]struct{}{
	"type":   {},
	"device": {},
	"o":      {},
}

// Manager owns the volumes tree under <state root>/volumes: the _data
// directories, the volume records in the state index, and the reference counts
// that decide when a volume may be removed.
//
// A Manager is safe for concurrent use. Cross-process safety comes from the
// state store's own locks plus an advisory lock on the reference index.
type Manager struct {
	root   string
	store  *state.Store
	logger *slog.Logger

	// mu serialises the read-modify-write of the reference index within this
	// process; the flock in withRefsLocked handles other processes.
	mu sync.Mutex
}

// New opens the volume manager rooted at root, which is normally
// /var/lib/hull/volumes. An empty root is derived from the store.
//
// The directory is created if it does not exist. store must be an open
// *state.Store: it holds the volume index that survives a daemon restart.
func New(root string, store *state.Store) (*Manager, error) {
	if store == nil {
		return nil, errors.New("volume: New requires an open state store")
	}
	if root == "" {
		root = filepath.Join(store.Root(), "volumes")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("volume: resolve root %q: %w", root, err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("volume: create root %s: %w", abs, err)
	}
	return &Manager{root: abs, store: store, logger: slog.Default()}, nil
}

// SetLogger replaces the logger used for the non-fatal warnings the manager
// emits (a seeded attribute it could not preserve, a stale reference it
// dropped). A nil logger restores the default.
func (m *Manager) SetLogger(l *slog.Logger) {
	if l == nil {
		l = slog.Default()
	}
	m.logger = l
}

// Root returns the directory the manager owns.
func (m *Manager) Root() string { return m.root }

// dir returns <root>/<name> for a name that has already been validated.
func (m *Manager) dir(name string) string { return filepath.Join(m.root, name) }

// DataDir returns the directory that is bind-mounted into containers for the
// named volume, <root>/<name>/_data. It does not check that the volume exists.
func (m *Manager) DataDir(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	d := filepath.Join(m.dir(name), dataDirName)
	if fsutil.IsEscape(m.root, d) {
		// Unreachable while ValidateName rejects separators; kept as a second
		// barrier so a future loosening of the name rules cannot turn into a
		// path traversal out of the volumes root.
		return "", fmt.Errorf("%w: %q escapes %s", ErrInvalidName, name, m.root)
	}
	return d, nil
}

// Create creates (or returns) a named volume.
//
// An empty name produces an anonymous volume: a fresh 64-hex name carrying the
// AnonymousLabel label, which is what marks it as hull's to reclaim.
//
// driver may be empty or "local"; anything else fails with ErrDriverUnsupported,
// because hull ships no volume plugin host and pretending otherwise would leave
// the user with a volume that silently is not what they asked for.
//
// opts are the local driver's options ("type", "device", "o"). They are
// recorded on the volume and consumed at mount time rather than now, so a
// tmpfs- or device-backed volume can be created while nothing is running.
//
// Creating a volume that already exists is not an error: the existing record is
// returned, as long as the requested driver matches.
func (m *Manager) Create(ctx context.Context, name string, driver string, opts, labels map[string]string) (*types.Volume, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if driver == "" {
		driver = DriverLocal
	}
	if driver != DriverLocal {
		return nil, &DriverError{Driver: driver}
	}
	if err := validateLocalOpts(opts); err != nil {
		return nil, err
	}

	anonymous := false
	if name == "" {
		name = idutil.NewID()
		anonymous = true
	}
	if err := ValidateName(name); err != nil {
		return nil, err
	}

	lbls := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		lbls[k] = v
	}
	if anonymous {
		lbls[AnonymousLabel] = ""
	}

	if existing, err := m.store.GetVolume(name); err == nil {
		if existing.Driver != "" && existing.Driver != driver {
			return nil, fmt.Errorf("volume %s already exists with driver %q, cannot recreate it with driver %q", name, existing.Driver, driver)
		}
		// Make sure the data directory is still there: a half-removed volume
		// must heal rather than hand back a mountpoint that does not exist.
		if err := m.makeDataDir(name); err != nil {
			return nil, err
		}
		return existing, nil
	} else if !errors.Is(err, state.ErrNotFound) {
		return nil, fmt.Errorf("volume: look up %s: %w", name, err)
	}

	if err := m.makeDataDir(name); err != nil {
		return nil, err
	}
	data, err := m.DataDir(name)
	if err != nil {
		return nil, err
	}

	v := &types.Volume{
		Name:       name,
		Driver:     driver,
		Mountpoint: data,
		Created:    time.Now().UTC(),
		Labels:     lbls,
		Options:    copyMap(opts),
		Scope:      ScopeLocal,
	}
	if len(v.Labels) == 0 {
		v.Labels = nil
	}
	if err := m.store.PutVolume(v); err != nil {
		// Roll the directory back so a failed create leaves no orphan.
		_ = os.RemoveAll(m.dir(name))
		return nil, fmt.Errorf("volume: record %s: %w", name, err)
	}
	return v, nil
}

// makeDataDir materialises <root>/<name>/_data with mode 0755.
func (m *Manager) makeDataDir(name string) error {
	data, err := m.DataDir(name)
	if err != nil {
		return err
	}
	if err := fsutil.MkdirAllChown(data, dataDirPerm, -1, -1); err != nil {
		return fmt.Errorf("volume: create data dir for %s: %w", name, err)
	}
	// MkdirAllChown only chmods directories it created; force the mode on an
	// existing one too so a volume restored from a backup is still traversable.
	if err := os.Chmod(data, dataDirPerm); err != nil {
		return fmt.Errorf("volume: chmod data dir for %s: %w", name, err)
	}
	return nil
}

// Get returns the volume record for name.
func (m *Manager) Get(name string) (*types.Volume, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	v, err := m.store.GetVolume(name)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return nil, &NotFoundError{Name: name}
		}
		return nil, fmt.Errorf("volume: look up %s: %w", name, err)
	}
	return v, nil
}

// List returns every volume matching f, sorted by name.
func (m *Manager) List(filters Filters) ([]*types.Volume, error) {
	all, err := m.store.ListVolumes()
	if err != nil {
		return nil, fmt.Errorf("volume: list: %w", err)
	}
	var refs map[string][]string
	if err := m.withRefs(func(idx *refIndex) (bool, error) {
		refs = idx.Refs
		return false, nil
	}); err != nil {
		return nil, err
	}
	out := make([]*types.Volume, 0, len(all))
	for _, v := range all {
		if v == nil {
			continue
		}
		if filters.Matches(v, len(refs[v.Name]) > 0) {
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Remove deletes a volume and its data.
//
// It refuses while any container still references it, naming the containers,
// unless force is set. Removing a volume that does not exist is an error unless
// force is set, matching `docker volume rm -f`.
func (m *Manager) Remove(ctx context.Context, name string, force bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateName(name); err != nil {
		return err
	}
	if _, err := m.Get(name); err != nil {
		if force && errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.withRefsLocked(func(idx *refIndex) (bool, error) {
		if users := idx.Refs[name]; len(users) > 0 && !force {
			return false, &InUseError{Name: name, Containers: append([]string(nil), users...)}
		}
		if _, ok := idx.Refs[name]; !ok {
			return false, nil
		}
		delete(idx.Refs, name)
		return true, nil
	}); err != nil {
		return err
	}

	dir := m.dir(name)
	if fsutil.IsEscape(m.root, dir) {
		return fmt.Errorf("%w: %q escapes %s", ErrInvalidName, name, m.root)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("volume: remove data of %s: %w", name, err)
	}
	if err := m.store.DeleteVolume(name); err != nil && !errors.Is(err, state.ErrNotFound) {
		return fmt.Errorf("volume: delete record %s: %w", name, err)
	}
	return nil
}

// Prune removes unused volumes and reports what it freed.
//
// By default only anonymous volumes are eligible, which is what `docker volume
// prune` does: a volume the user bothered to name is not thrown away on a
// cleanup command. Set Filters.All to include named volumes too. A volume that
// gains a reference between the survey and the removal is skipped rather than
// torn out from under the container that just claimed it.
func (m *Manager) Prune(ctx context.Context, filters Filters) (removed []string, reclaimed int64, err error) {
	candidates, err := m.List(filters)
	if err != nil {
		return nil, 0, err
	}
	for _, v := range candidates {
		if err := ctx.Err(); err != nil {
			return removed, reclaimed, err
		}
		n, cerr := m.RefCount(v.Name)
		if cerr != nil {
			return removed, reclaimed, cerr
		}
		if n > 0 {
			continue
		}
		if !filters.All && !IsAnonymous(v) {
			continue
		}
		size, uerr := m.Usage(v.Name)
		if uerr != nil && !errors.Is(uerr, fs.ErrNotExist) {
			return removed, reclaimed, uerr
		}
		if rerr := m.Remove(ctx, v.Name, false); rerr != nil {
			if errors.Is(rerr, ErrInUse) || errors.Is(rerr, ErrNotFound) {
				continue // raced with a start or another prune
			}
			return removed, reclaimed, rerr
		}
		removed = append(removed, v.Name)
		reclaimed += size
	}
	return removed, reclaimed, nil
}

// Usage returns the number of bytes the named volume's data occupies. Symlinks
// are counted by their own size and never followed, so a link pointing out of
// the volume cannot make hull walk the host filesystem.
func (m *Manager) Usage(name string) (int64, error) {
	if _, err := m.Get(name); err != nil {
		return 0, err
	}
	data, err := m.DataDir(name)
	if err != nil {
		return 0, err
	}
	var total int64
	walkErr := filepath.WalkDir(data, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // raced with a delete
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		fi, ierr := d.Info()
		if ierr != nil {
			if errors.Is(ierr, fs.ErrNotExist) {
				return nil
			}
			return ierr
		}
		total += fi.Size()
		return nil
	})
	if walkErr != nil {
		if errors.Is(walkErr, fs.ErrNotExist) {
			return 0, &NotFoundError{Name: name}
		}
		return 0, fmt.Errorf("volume: measure %s: %w", name, walkErr)
	}
	return total, nil
}

// IsAnonymous reports whether a volume was created implicitly by hull rather
// than named by the user.
func IsAnonymous(v *types.Volume) bool {
	if v == nil {
		return false
	}
	_, ok := v.Labels[AnonymousLabel]
	return ok
}

// validateLocalOpts rejects options the local driver does not implement, rather
// than storing them and ignoring them at mount time.
func validateLocalOpts(opts map[string]string) error {
	if len(opts) == 0 {
		return nil
	}
	var bad []string
	for k := range opts {
		if _, ok := localOptKeys[strings.ToLower(k)]; !ok {
			bad = append(bad, k)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("%w: the %q driver does not understand the option(s) %s (it accepts type, device and o)",
		ErrDriverUnsupported, DriverLocal, strings.Join(bad, ", "))
}

// copyMap returns a defensive copy, or nil for an empty input so the JSON
// record stays free of empty objects.
func copyMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
