package volume

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/rahuldhali/hull/internal/types"
)

// Mount types, matching the strings Docker puts on the wire.
const (
	// TypeBind is a host path bind-mounted into the container.
	TypeBind = "bind"
	// TypeVolume is a hull-managed named or anonymous volume.
	TypeVolume = "volume"
	// TypeTmpfs is an in-memory filesystem private to the container.
	TypeTmpfs = "tmpfs"
)

// ConsistencyNoCopy is stored in types.Mount.Consistency to carry the volume
// "nocopy" option, which suppresses image-volume seeding for that mount.
//
// types.Mount has no VolumeOptions field, and hull must not silently drop a
// flag the user set. Consistency is otherwise unused on Linux (it only ever
// meant anything to Docker Desktop for macOS), so it is the one field free to
// carry this. Resolve is the only reader.
const ConsistencyNoCopy = "nocopy"

// validPropagations is the set of mount propagation modes the kernel accepts.
var validPropagations = map[string]struct{}{
	"private":     {},
	"rprivate":    {},
	"shared":      {},
	"rshared":     {},
	"slave":       {},
	"rslave":      {},
	"unbindable":  {},
	"runbindable": {},
}

// Spec is a fully parsed --mount request: a types.Mount plus the volume-level
// options that types.Mount has no field for. ParseMountSpec returns one;
// ParseMount returns just the types.Mount half and refuses anything that would
// otherwise be silently lost.
type Spec struct {
	// Mount is the portable half of the request.
	Mount types.Mount
	// VolumeDriver is the requested driver for a type=volume mount ("" means
	// the default, which is DriverLocal).
	VolumeDriver string
	// VolumeOptions are local-driver options (type, device, o) for a volume
	// created on demand by this mount.
	VolumeOptions map[string]string
	// VolumeLabels are labels applied to a volume created on demand.
	VolumeLabels map[string]string
	// NoCopy suppresses image-volume seeding. It is mirrored into
	// Mount.Consistency as ConsistencyNoCopy.
	NoCopy bool
	// BindNonRecursive asks for a non-recursive bind (MS_BIND without MS_REC).
	BindNonRecursive bool
}

// ParseBind parses one short-form -v/--volume specification.
//
// Accepted shapes:
//
//	/ctr                                anonymous volume at /ctr
//	/host:/ctr                          bind mount
//	/host:/ctr:ro                       read-only bind mount
//	name:/ctr:rw,z                      named volume with options
//	C:\Users\me\proj:/app               Windows bind mount
//	c:/Users/me/proj:/app:ro            Windows bind mount, forward slashes
//
// The drive-letter colon is never mistaken for the field separator: a leading
// [A-Za-z]: followed by a slash or backslash is re-joined onto the source field
// before the fields are interpreted.
//
// A \\wsl$ (or \\wsl.localhost) source is refused with actionable advice; see
// TranslateWindowsPath. The container target must be absolute and must not be
// "/".
func ParseBind(s string) (types.Mount, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return types.Mount{}, fmt.Errorf("%w: empty -v value", ErrInvalidMount)
	}
	if strings.ContainsRune(raw, 0) {
		return types.Mount{}, fmt.Errorf("%w: %q contains a NUL byte", ErrInvalidMount, s)
	}
	// A UNC source has to be caught before splitting: its leading backslashes
	// carry no colon to split on, and the advice hull owes the user is specific.
	if IsUNCPath(raw) {
		if _, err := TranslateWindowsPath(firstBindField(raw)); err != nil {
			return types.Mount{}, err
		}
	}

	fields := splitBindFields(raw)
	var src, target, opts string
	switch len(fields) {
	case 1:
		target = fields[0]
	case 2:
		src, target = fields[0], fields[1]
	case 3:
		src, target, opts = fields[0], fields[1], fields[2]
	default:
		return types.Mount{}, fmt.Errorf("%w: %q has %d colon-separated fields, expected at most 3 (source:target:options)", ErrInvalidMount, s, len(fields))
	}

	m := types.Mount{}
	cleanTarget, err := validateTarget(target)
	if err != nil {
		return types.Mount{}, fmt.Errorf("%w (in %q)", err, s)
	}
	m.Target = cleanTarget

	switch {
	case src == "":
		// "-v /ctr": an anonymous volume, created on demand by Resolve.
		m.Type = TypeVolume

	case LooksLikeVolumeName(src):
		if err := ValidateName(src); err != nil {
			return types.Mount{}, fmt.Errorf("%w (in %q)", err, s)
		}
		m.Type = TypeVolume
		m.Source = src

	default:
		hostPath, terr := TranslateWindowsPath(src)
		if terr != nil {
			return types.Mount{}, fmt.Errorf("%w (in %q)", terr, s)
		}
		m.Type = TypeBind
		m.Source = hostPath
	}

	if err := applyShortOptions(&m, opts); err != nil {
		return types.Mount{}, fmt.Errorf("%w (in %q)", err, s)
	}
	return m, nil
}

// firstBindField returns the source field of a UNC-prefixed spec. It is used
// only to build the rejection message.
func firstBindField(s string) string {
	if i := strings.Index(s, ":"); i >= 0 {
		return s[:i]
	}
	return s
}

// splitBindFields splits a -v value on ":" while keeping a Windows drive letter
// attached to its path. It is the whole trick behind parsing "C:\x:/app".
func splitBindFields(s string) []string {
	parts := strings.Split(s, ":")
	if len(parts) >= 2 && len(parts[0]) == 1 && isDriveLetter(parts[0][0]) &&
		parts[1] != "" && (parts[1][0] == '\\' || parts[1][0] == '/') {
		out := make([]string, 0, len(parts)-1)
		out = append(out, parts[0]+":"+parts[1])
		out = append(out, parts[2:]...)
		return out
	}
	return parts
}

// isDriveLetter reports whether b is an ASCII letter, i.e. a Windows drive.
func isDriveLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// validateTarget checks a container-side mount target and returns it cleaned.
func validateTarget(t string) (string, error) {
	t = strings.TrimSpace(t)
	switch {
	case t == "":
		return "", fmt.Errorf("%w: mount target is empty", ErrInvalidMount)
	case strings.ContainsRune(t, 0):
		return "", fmt.Errorf("%w: mount target contains a NUL byte", ErrInvalidMount)
	case IsWindowsPath(t):
		return "", fmt.Errorf("%w: mount target %q is a Windows path; the target is a path inside the container and must be a Linux absolute path", ErrInvalidMount, t)
	case !strings.HasPrefix(t, "/"):
		return "", fmt.Errorf("%w: mount target %q must be an absolute path", ErrInvalidMount, t)
	}
	c := path.Clean(t)
	if c == "/" {
		return "", fmt.Errorf("%w: cannot mount over the container root %q", ErrInvalidMount, t)
	}
	return c, nil
}

// applyShortOptions applies the comma-separated option list of a -v value.
func applyShortOptions(m *types.Mount, opts string) error {
	if strings.TrimSpace(opts) == "" {
		return nil
	}
	for _, tok := range strings.Split(opts, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		switch tok {
		case "ro", "readonly":
			m.ReadOnly = true
		case "rw":
			m.ReadOnly = false
		case "z", "Z":
			// SELinux relabelling. WSL2 has no SELinux (and no AppArmor), so
			// there is nothing to relabel; accepting the flag keeps compose
			// files written for Fedora hosts working unchanged.
		case "consistent", "cached", "delegated":
			// Docker Desktop for macOS cache hints; meaningless on Linux.
		case "nocopy":
			if m.Type != TypeVolume {
				return fmt.Errorf("%w: option %q is only valid on a volume mount", ErrInvalidMount, tok)
			}
			m.Consistency = ConsistencyNoCopy
		default:
			if _, ok := validPropagations[tok]; ok {
				if m.Type != TypeBind {
					return fmt.Errorf("%w: propagation %q is only valid on a bind mount", ErrInvalidMount, tok)
				}
				if m.BindOptions == nil {
					m.BindOptions = &types.BindOptions{}
				}
				m.BindOptions.Propagation = tok
				continue
			}
			return fmt.Errorf("%w: unknown option %q (valid: ro, rw, z, Z, nocopy, %s)", ErrInvalidMount, tok, strings.Join(sortedPropagations(), ", "))
		}
	}
	return nil
}

// sortedPropagations returns the propagation modes in a stable order so error
// messages do not change between runs.
func sortedPropagations() []string {
	out := make([]string, 0, len(validPropagations))
	for p := range validPropagations {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
