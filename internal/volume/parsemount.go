package volume

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/rahuldhali/hull/internal/types"
)

// ParseMount parses one long-form --mount specification and returns the
// portable types.Mount it describes.
//
// The value is comma-separated key=value CSV, so a value containing a comma
// works as long as it is quoted:
//
//	type=bind,source=/host,target=/ctr,readonly
//	type=volume,src=db,dst=/var/lib/postgresql/data
//	type=tmpfs,target=/run,tmpfs-size=64m,tmpfs-mode=1777
//	type=bind,source=C:\Users\me\proj,target=/app,bind-propagation=rslave
//	type=volume,src=cache,dst=/c,volume-opt=o="size=64m,uid=1000"
//
// Options that types.Mount cannot represent (a non-local volume-driver, any
// volume-opt or volume-label) are refused with a clear error rather than
// dropped; use ParseMountSpec if you need them, or create the volume up front
// with Manager.Create, which records local-driver options for mount time.
func ParseMount(s string) (types.Mount, error) {
	sp, err := ParseMountSpec(s)
	if err != nil {
		return types.Mount{}, err
	}
	if sp.VolumeDriver != "" && sp.VolumeDriver != DriverLocal {
		return types.Mount{}, fmt.Errorf("%w (in %q)", &DriverError{Driver: sp.VolumeDriver}, s)
	}
	if len(sp.VolumeOptions) > 0 {
		return types.Mount{}, fmt.Errorf("%w: volume-opt cannot be carried on a container mount record; create the volume first with its options (hull volume create --opt ...) and reference it by name (in %q)", ErrInvalidMount, s)
	}
	if len(sp.VolumeLabels) > 0 {
		return types.Mount{}, fmt.Errorf("%w: volume-label cannot be carried on a container mount record; create the volume first with its labels and reference it by name (in %q)", ErrInvalidMount, s)
	}
	if sp.BindNonRecursive {
		return types.Mount{}, fmt.Errorf("%w: bind-nonrecursive cannot be carried on a container mount record (in %q)", ErrInvalidMount, s)
	}
	return sp.Mount, nil
}

// ParseMountSpec parses one long-form --mount specification into a Spec, which
// keeps the volume-level options that types.Mount has no field for. It is the
// full-fidelity form of ParseMount.
func ParseMountSpec(s string) (Spec, error) {
	fields, err := csvFields(s)
	if err != nil {
		return Spec{}, err
	}

	sp := Spec{}
	m := &sp.Mount
	var (
		mountType   string
		source      string
		haveTarget  bool
		haveSrcKey  bool
		tmpfsSize   int64
		tmpfsMode   uint32
		haveTmpfsSz bool
		haveTmpfsMd bool
	)

	for _, f := range fields {
		rawKey, rawVal, hasVal := strings.Cut(f, "=")
		key := strings.ToLower(strings.TrimSpace(rawKey))
		val := strings.TrimSpace(rawVal)
		if key == "" {
			return Spec{}, fmt.Errorf("%w: empty field in %q", ErrInvalidMount, s)
		}

		switch key {
		case "type":
			mountType = strings.ToLower(val)

		case "source", "src":
			source, haveSrcKey = val, true

		case "target", "dst", "destination":
			t, verr := validateTarget(val)
			if verr != nil {
				return Spec{}, fmt.Errorf("%w (in %q)", verr, s)
			}
			m.Target, haveTarget = t, true

		case "readonly", "ro", "read-only":
			b, berr := optionalBool(key, val, hasVal)
			if berr != nil {
				return Spec{}, fmt.Errorf("%w (in %q)", berr, s)
			}
			m.ReadOnly = b

		case "rw", "readwrite", "read-write":
			b, berr := optionalBool(key, val, hasVal)
			if berr != nil {
				return Spec{}, fmt.Errorf("%w (in %q)", berr, s)
			}
			m.ReadOnly = !b

		case "bind-propagation":
			p := strings.ToLower(val)
			if _, ok := validPropagations[p]; !ok {
				return Spec{}, fmt.Errorf("%w: invalid bind-propagation %q (valid: %s) (in %q)", ErrInvalidMount, val, strings.Join(sortedPropagations(), ", "), s)
			}
			if m.BindOptions == nil {
				m.BindOptions = &types.BindOptions{}
			}
			m.BindOptions.Propagation = p

		case "bind-nonrecursive":
			b, berr := optionalBool(key, val, hasVal)
			if berr != nil {
				return Spec{}, fmt.Errorf("%w (in %q)", berr, s)
			}
			sp.BindNonRecursive = b

		case "bind-create-mountpoint", "create-mountpoint":
			b, berr := optionalBool(key, val, hasVal)
			if berr != nil {
				return Spec{}, fmt.Errorf("%w (in %q)", berr, s)
			}
			if m.BindOptions == nil {
				m.BindOptions = &types.BindOptions{}
			}
			m.BindOptions.CreateMountpoint = b

		case "volume-driver":
			sp.VolumeDriver = strings.ToLower(val)

		case "volume-nocopy":
			b, berr := optionalBool(key, val, hasVal)
			if berr != nil {
				return Spec{}, fmt.Errorf("%w (in %q)", berr, s)
			}
			sp.NoCopy = b

		case "volume-opt":
			k, v, ok := strings.Cut(val, "=")
			if !ok || strings.TrimSpace(k) == "" {
				return Spec{}, fmt.Errorf("%w: volume-opt needs a key=value value, got %q (in %q)", ErrInvalidMount, val, s)
			}
			if sp.VolumeOptions == nil {
				sp.VolumeOptions = map[string]string{}
			}
			sp.VolumeOptions[strings.TrimSpace(k)] = v

		case "volume-label":
			k, v, ok := strings.Cut(val, "=")
			if !ok || strings.TrimSpace(k) == "" {
				return Spec{}, fmt.Errorf("%w: volume-label needs a key=value value, got %q (in %q)", ErrInvalidMount, val, s)
			}
			if sp.VolumeLabels == nil {
				sp.VolumeLabels = map[string]string{}
			}
			sp.VolumeLabels[strings.TrimSpace(k)] = v

		case "tmpfs-size":
			n, serr := ParseSize(val)
			if serr != nil {
				return Spec{}, fmt.Errorf("%w (in %q)", serr, s)
			}
			tmpfsSize, haveTmpfsSz = n, true

		case "tmpfs-mode":
			mode, merr := strconv.ParseUint(val, 8, 32)
			if merr != nil {
				return Spec{}, fmt.Errorf("%w: invalid tmpfs-mode %q, expected an octal mode such as 1777 (in %q)", ErrInvalidMount, val, s)
			}
			tmpfsMode, haveTmpfsMd = uint32(mode), true

		case "consistency":
			// Docker Desktop for macOS cache hint; it has no meaning on Linux,
			// and hull keeps Consistency for the nocopy flag.

		default:
			return Spec{}, fmt.Errorf("%w: unknown --mount field %q (in %q)", ErrInvalidMount, rawKey, s)
		}
	}

	if mountType == "" {
		// Docker's default, and the safe one: an unnamed source becomes a
		// managed volume rather than an accidental host bind.
		mountType = TypeVolume
	}
	switch mountType {
	case TypeBind, TypeVolume, TypeTmpfs:
	default:
		return Spec{}, fmt.Errorf("%w: unknown mount type %q (valid: %s, %s, %s) (in %q)", ErrInvalidMount, mountType, TypeBind, TypeVolume, TypeTmpfs, s)
	}
	m.Type = mountType

	if !haveTarget {
		return Spec{}, fmt.Errorf("%w: --mount requires target= (in %q)", ErrInvalidMount, s)
	}

	switch mountType {
	case TypeBind:
		if !haveSrcKey || source == "" {
			return Spec{}, fmt.Errorf("%w: a bind mount requires source= (in %q)", ErrInvalidMount, s)
		}
		hostPath, terr := TranslateWindowsPath(source)
		if terr != nil {
			return Spec{}, fmt.Errorf("%w (in %q)", terr, s)
		}
		m.Source = hostPath
		if sp.NoCopy {
			return Spec{}, fmt.Errorf("%w: volume-nocopy is only valid on a volume mount (in %q)", ErrInvalidMount, s)
		}

	case TypeVolume:
		if source != "" {
			if err := ValidateName(source); err != nil {
				return Spec{}, fmt.Errorf("%w (in %q)", err, s)
			}
			m.Source = source
		}
		if m.BindOptions != nil {
			return Spec{}, fmt.Errorf("%w: bind-* options are only valid on a bind mount (in %q)", ErrInvalidMount, s)
		}
		if sp.NoCopy {
			m.Consistency = ConsistencyNoCopy
		}

	case TypeTmpfs:
		if source != "" {
			return Spec{}, fmt.Errorf("%w: a tmpfs mount must not have a source (in %q)", ErrInvalidMount, s)
		}
		if m.BindOptions != nil {
			return Spec{}, fmt.Errorf("%w: bind-* options are only valid on a bind mount (in %q)", ErrInvalidMount, s)
		}
		if sp.VolumeDriver != "" || len(sp.VolumeOptions) > 0 || len(sp.VolumeLabels) > 0 || sp.NoCopy {
			return Spec{}, fmt.Errorf("%w: volume-* options are only valid on a volume mount (in %q)", ErrInvalidMount, s)
		}
		if haveTmpfsSz || haveTmpfsMd {
			m.TmpfsOptions = &types.TmpfsOptions{SizeBytes: tmpfsSize, Mode: tmpfsMode}
		}
	}

	if mountType != TypeTmpfs && (haveTmpfsSz || haveTmpfsMd) {
		return Spec{}, fmt.Errorf("%w: tmpfs-* options are only valid on a tmpfs mount (in %q)", ErrInvalidMount, s)
	}
	return sp, nil
}

// csvFields splits one --mount value into its comma-separated fields using a
// real CSV reader, so a quoted value containing a comma survives intact.
func csvFields(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("%w: empty --mount value", ErrInvalidMount)
	}
	if strings.ContainsRune(s, 0) {
		return nil, fmt.Errorf("%w: %q contains a NUL byte", ErrInvalidMount, s)
	}
	r := csv.NewReader(strings.NewReader(s))
	r.Comma = ','
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	rec, err := r.Read()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("%w: empty --mount value", ErrInvalidMount)
		}
		return nil, fmt.Errorf("%w: cannot parse %q as CSV: %w", ErrInvalidMount, s, err)
	}
	if _, err := r.Read(); err != io.EOF {
		return nil, fmt.Errorf("%w: %q spans more than one line", ErrInvalidMount, s)
	}
	out := make([]string, 0, len(rec))
	for _, f := range rec {
		if strings.TrimSpace(f) == "" {
			continue
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: empty --mount value", ErrInvalidMount)
	}
	return out, nil
}

// optionalBool interprets a flag field that may be bare ("readonly") or carry a
// value ("readonly=false"). A bare flag means true.
func optionalBool(key, val string, hasVal bool) (bool, error) {
	if !hasVal || val == "" {
		return true, nil
	}
	switch strings.ToLower(val) {
	case "1", "t", "true", "yes", "y":
		return true, nil
	case "0", "f", "false", "no", "n":
		return false, nil
	}
	return false, fmt.Errorf("%w: %s=%q is not a boolean", ErrInvalidMount, key, val)
}

// ParseSize converts a human byte size such as "64m", "1.5g" or "1048576" into
// a byte count. Suffixes are binary (1k == 1024), matching Docker.
func ParseSize(s string) (int64, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, fmt.Errorf("%w: empty size", ErrInvalidMount)
	}
	lower := strings.ToLower(t)
	// Strip the byte suffix first so "1kb", "1kib" and "1k" all agree.
	switch {
	case strings.HasSuffix(lower, "ib"):
		lower = lower[:len(lower)-2]
	case strings.HasSuffix(lower, "b"):
		lower = lower[:len(lower)-1]
	}
	mult := int64(1)
	if n := len(lower); n > 0 {
		switch lower[n-1] {
		case 'k':
			mult, lower = 1<<10, lower[:n-1]
		case 'm':
			mult, lower = 1<<20, lower[:n-1]
		case 'g':
			mult, lower = 1<<30, lower[:n-1]
		case 't':
			mult, lower = 1<<40, lower[:n-1]
		}
	}
	lower = strings.TrimSpace(lower)
	if lower == "" {
		return 0, fmt.Errorf("%w: %q has no numeric part", ErrInvalidMount, s)
	}
	f, err := strconv.ParseFloat(lower, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q is not a byte size (try 64m, 1g or a plain byte count)", ErrInvalidMount, s)
	}
	if f < 0 {
		return 0, fmt.Errorf("%w: size %q is negative", ErrInvalidMount, s)
	}
	return int64(f * float64(mult)), nil
}
