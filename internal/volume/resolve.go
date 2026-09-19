package volume

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/rahuldhali/hull/internal/types"
)

// tmpfsNoOpFlags are tmpfs mount flags hull already applies to every container
// tmpfs, so seeing them in HostConfig.Tmpfs changes nothing.
var tmpfsNoOpFlags = map[string]struct{}{
	"rw":          {},
	"nosuid":      {},
	"nodev":       {},
	"noexec":      {},
	"noatime":     {},
	"strictatime": {},
	"nodiratime":  {},
}

// tmpfsRefusedFlags are tmpfs mount flags hull cannot honour, because
// types.TmpfsOptions carries only a size and a mode and hull's runtime always
// mounts a container tmpfs nosuid,nodev,noexec. Refusing is deliberate: a
// container that silently got an exec-able tmpfs it did not ask for, or failed
// to get one it did, is worse than a clear error.
var tmpfsRefusedFlags = map[string]struct{}{
	"exec": {},
	"suid": {},
	"dev":  {},
}

// Resolve turns a container's mount requests into the final, ordered,
// de-duplicated list the runtime will apply.
//
// The inputs, in precedence order, are HostConfig.Binds (-v), HostConfig.Mounts
// (--mount), HostConfig.Tmpfs (--tmpfs) and finally the image's VOLUME set,
// which only supplies targets none of the explicit requests already claimed.
// Two explicit requests for the same target are an error, not a silent
// last-one-wins.
//
// Every volume mount is materialised: a named volume is created if it does not
// exist, an empty source becomes a fresh anonymous volume, the container takes
// a reference on each, and Source is replaced by the volume's real _data path.
//
// Image-volume seeding: when a volume is fresh (its _data is empty) and the
// image has content at the mount target, that content is copied into the volume
// before first use, preserving ownership and modes. This is what makes
//
//	hull run -v db:/var/lib/postgresql/data postgres
//
// come up with an initialised database directory instead of an empty one. It is
// skipped for a volume that already has content, and for a mount that asked for
// "nocopy".
//
// The result is sorted parent-before-child so the runtime can apply it in order
// without a nested mount landing before the directory it lives in.
func (m *Manager) Resolve(ctx context.Context, c *types.Container) ([]types.Mount, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("volume: Resolve called with a nil container")
	}
	if c.ID == "" {
		return nil, errors.New("volume: Resolve requires a container id to take references with")
	}

	type entry struct {
		mount  types.Mount
		origin string
	}
	var list []entry
	byTarget := map[string]int{}

	add := func(mnt types.Mount, origin string) error {
		if i, dup := byTarget[mnt.Target]; dup {
			return fmt.Errorf("%w: %s is claimed by both %s and %s", ErrConflict, mnt.Target, list[i].origin, origin)
		}
		byTarget[mnt.Target] = len(list)
		list = append(list, entry{mount: mnt, origin: origin})
		return nil
	}

	for _, b := range c.HostConfig.Binds {
		mnt, err := ParseBind(b)
		if err != nil {
			return nil, err
		}
		if err := add(mnt, "-v "+b); err != nil {
			return nil, err
		}
	}

	for i, raw := range c.HostConfig.Mounts {
		mnt, err := normalizeMount(raw)
		if err != nil {
			return nil, fmt.Errorf("mount #%d: %w", i, err)
		}
		if err := add(mnt, "--mount "+mnt.Target); err != nil {
			return nil, err
		}
	}

	for _, target := range sortedKeys(c.HostConfig.Tmpfs) {
		mnt, err := tmpfsMount(target, c.HostConfig.Tmpfs[target])
		if err != nil {
			return nil, err
		}
		if err := add(mnt, "--tmpfs "+target); err != nil {
			return nil, err
		}
	}

	// The image's VOLUME set. These are the lowest precedence: an explicit
	// request for the same target simply wins, without an error.
	for _, target := range sortedKeys(c.Config.Volumes) {
		clean, err := validateTarget(target)
		if err != nil {
			return nil, fmt.Errorf("image VOLUME %q: %w", target, err)
		}
		if _, taken := byTarget[clean]; taken {
			continue
		}
		if err := add(types.Mount{Type: TypeVolume, Target: clean}, "image VOLUME "+target); err != nil {
			return nil, err
		}
	}

	out := make([]types.Mount, 0, len(list))
	for _, e := range list {
		mnt := e.mount
		if mnt.Type == TypeVolume {
			resolved, err := m.materialise(ctx, c, mnt)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", e.origin, err)
			}
			mnt = resolved
		}
		out = append(out, mnt)
	}

	sort.SliceStable(out, func(i, j int) bool {
		di, dj := depth(out[i].Target), depth(out[j].Target)
		if di != dj {
			return di < dj
		}
		return out[i].Target < out[j].Target
	})
	return out, nil
}

// materialise creates or finds the volume behind one volume mount, takes a
// reference for the container, seeds it from the image if it is fresh, and
// returns the mount with Source pointing at the volume's _data directory.
func (m *Manager) materialise(ctx context.Context, c *types.Container, mnt types.Mount) (types.Mount, error) {
	name := mnt.Source
	v, err := m.Create(ctx, name, DriverLocal, nil, nil)
	if err != nil {
		return types.Mount{}, err
	}
	if err := m.Ref(v.Name, c.ID); err != nil {
		return types.Mount{}, err
	}

	data, err := m.DataDir(v.Name)
	if err != nil {
		return types.Mount{}, err
	}

	if mnt.Consistency != ConsistencyNoCopy {
		if _, err := m.seed(ctx, v.Name, data, c.RootFS, mnt.Target); err != nil {
			return types.Mount{}, err
		}
	}

	mnt.Source = data
	// Consistency has done its job as the nocopy carrier; the runtime has no
	// use for it and it should not leak into the container's inspect output.
	mnt.Consistency = ""
	return mnt, nil
}

// seed copies the image's content at target into a fresh volume. It reports
// whether anything was copied.
//
// Nothing is copied when the volume already has content, when the container has
// no rootfs mounted yet, or when the image has nothing at that path. The copy
// itself never resolves a container-controlled path with filepath.Join: see
// copyImageContent, which walks the rootfs fd-relative and refuses to follow a
// symlink out of it.
func (m *Manager) seed(ctx context.Context, name, data, rootfs, target string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if rootfs == "" {
		return false, nil
	}
	empty, err := dirIsEmpty(data)
	if err != nil {
		return false, err
	}
	if !empty {
		return false, nil
	}
	if fi, err := os.Stat(rootfs); err != nil || !fi.IsDir() {
		// No rootfs on disk yet: there is genuinely nothing to copy from, and
		// this is not the engine quietly skipping work it could have done.
		return false, nil
	}
	rel := strings.TrimPrefix(path.Clean(target), "/")
	if rel == "" || rel == "." {
		return false, nil
	}
	copied, err := copyImageContent(data, rootfs, rel)
	if err != nil {
		return false, fmt.Errorf("seed volume %s from image content at %s: %w", name, target, err)
	}
	if copied {
		m.logger.Debug("seeded volume from image", "volume", name, "target", target)
	}
	return copied, nil
}

// Release drops every reference this container holds on a volume.
//
// The references are found in the reference index rather than by re-parsing the
// container's mount requests, so the anonymous volumes hull generated at Resolve
// time are released too even though their generated names appear nowhere in
// HostConfig.
//
// With removeAnonymous set (the `docker rm -v` behaviour), an anonymous volume
// that no other container references is then deleted along with its data. A
// named volume is never deleted here: the user named it, so it outlives the
// container.
func (m *Manager) Release(ctx context.Context, c *types.Container, removeAnonymous bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil {
		return errors.New("volume: Release called with a nil container")
	}
	if c.ID == "" {
		return errors.New("volume: Release requires a container id")
	}

	var touched []string
	if err := m.withRefs(func(idx *refIndex) (bool, error) {
		dirty := false
		for name := range idx.Refs {
			if removeRef(idx, name, c.ID) {
				touched = append(touched, name)
				dirty = true
			}
		}
		return dirty, nil
	}); err != nil {
		return err
	}
	sort.Strings(touched)

	if !removeAnonymous {
		return nil
	}
	var errs []error
	for _, name := range touched {
		v, err := m.Get(name)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			errs = append(errs, err)
			continue
		}
		if !IsAnonymous(v) {
			continue
		}
		if err := m.Remove(ctx, name, false); err != nil {
			if errors.Is(err, ErrInUse) || errors.Is(err, ErrNotFound) {
				continue // another container claimed it in the meantime
			}
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// normalizeMount validates and canonicalises a types.Mount that arrived from
// the API rather than from ParseMount, so a hand-built HostConfig is held to
// exactly the same rules as a command line.
func normalizeMount(in types.Mount) (types.Mount, error) {
	out := in
	target, err := validateTarget(in.Target)
	if err != nil {
		return types.Mount{}, err
	}
	out.Target = target

	switch in.Type {
	case TypeBind:
		if in.Source == "" {
			return types.Mount{}, fmt.Errorf("%w: a bind mount of %s requires a source", ErrInvalidMount, target)
		}
		src, terr := TranslateWindowsPath(in.Source)
		if terr != nil {
			return types.Mount{}, terr
		}
		out.Source = src
		if in.BindOptions != nil && in.BindOptions.Propagation != "" {
			if _, ok := validPropagations[in.BindOptions.Propagation]; !ok {
				return types.Mount{}, fmt.Errorf("%w: invalid propagation %q on %s", ErrInvalidMount, in.BindOptions.Propagation, target)
			}
		}

	case TypeVolume:
		if in.Source != "" {
			if err := ValidateName(in.Source); err != nil {
				return types.Mount{}, err
			}
		}
		if in.BindOptions != nil {
			return types.Mount{}, fmt.Errorf("%w: bind options are not valid on the volume mount at %s", ErrInvalidMount, target)
		}
		if in.Consistency != "" && in.Consistency != ConsistencyNoCopy {
			return types.Mount{}, fmt.Errorf("%w: unknown consistency %q on %s", ErrInvalidMount, in.Consistency, target)
		}

	case TypeTmpfs:
		if in.Source != "" {
			return types.Mount{}, fmt.Errorf("%w: the tmpfs mount at %s must not have a source", ErrInvalidMount, target)
		}
		if in.BindOptions != nil {
			return types.Mount{}, fmt.Errorf("%w: bind options are not valid on the tmpfs mount at %s", ErrInvalidMount, target)
		}

	case "":
		return types.Mount{}, fmt.Errorf("%w: the mount at %s has no type (want %s, %s or %s)", ErrInvalidMount, target, TypeBind, TypeVolume, TypeTmpfs)

	default:
		return types.Mount{}, fmt.Errorf("%w: unknown mount type %q at %s", ErrInvalidMount, in.Type, target)
	}
	return out, nil
}

// tmpfsMount builds the mount for one HostConfig.Tmpfs entry, whose value is a
// comma-separated mount option string such as "rw,size=64m,mode=1777".
func tmpfsMount(target, opts string) (types.Mount, error) {
	clean, err := validateTarget(target)
	if err != nil {
		return types.Mount{}, err
	}
	m := types.Mount{Type: TypeTmpfs, Target: clean}
	var (
		size int64
		mode uint32
		have bool
	)
	for _, tok := range strings.Split(opts, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		key, val, hasVal := strings.Cut(tok, "=")
		key = strings.ToLower(key)
		switch {
		case key == "size" && hasVal:
			n, perr := ParseSize(val)
			if perr != nil {
				return types.Mount{}, fmt.Errorf("tmpfs %s: %w", clean, perr)
			}
			size, have = n, true
		case key == "mode" && hasVal:
			n, perr := strconv.ParseUint(val, 8, 32)
			if perr != nil {
				return types.Mount{}, fmt.Errorf("%w: tmpfs %s: invalid mode %q, expected an octal mode such as 1777", ErrInvalidMount, clean, val)
			}
			mode, have = uint32(n), true
		case key == "ro" || key == "readonly":
			m.ReadOnly = true
		default:
			if _, ok := tmpfsNoOpFlags[key]; ok {
				continue
			}
			if _, ok := tmpfsRefusedFlags[key]; ok {
				return types.Mount{}, fmt.Errorf("%w: tmpfs %s: hull always mounts a container tmpfs nosuid,nodev,noexec and cannot honour %q", ErrInvalidMount, clean, tok)
			}
			return types.Mount{}, fmt.Errorf("%w: tmpfs %s: unknown option %q", ErrInvalidMount, clean, tok)
		}
	}
	if have {
		m.TmpfsOptions = &types.TmpfsOptions{SizeBytes: size, Mode: mode}
	}
	return m, nil
}

// sortedKeys returns a map's keys in a stable order, so a resolved mount list
// does not change between two runs of the same container.
func sortedKeys[V any](in map[string]V) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// depth counts the path components of a cleaned absolute target.
func depth(p string) int { return strings.Count(strings.TrimSuffix(p, "/"), "/") }

// dirIsEmpty reports whether dir has no entries. A missing directory counts as
// empty, because a volume whose data dir has not been created yet is certainly
// fresh.
func dirIsEmpty(dir string) (bool, error) {
	f, err := os.Open(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("volume: open %s: %w", dir, err)
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("volume: read %s: %w", dir, err)
	}
	return len(names) == 0, nil
}
