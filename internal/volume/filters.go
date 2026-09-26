package volume

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ChPuru/hull/internal/types"
)

// Filters narrows a volume listing or a prune. A zero Filters matches every
// volume.
type Filters struct {
	// Names matches volumes whose name contains any of these substrings,
	// which is how Docker's "name" filter behaves for volumes.
	Names []string
	// Drivers matches volumes with any of these exact driver names.
	Drivers []string
	// Labels are "key" or "key=value" terms, all of which must match.
	Labels []string
	// Dangling, when set, selects volumes that are (true) or are not (false)
	// free of container references.
	Dangling *bool
	// All lets Prune consider named volumes and not only anonymous ones. It
	// has no effect on List.
	All bool
}

// Matches reports whether v satisfies the filter. inUse says whether any
// container currently references the volume, which is what the "dangling"
// filter turns on.
func (f Filters) Matches(v *types.Volume, inUse bool) bool {
	if v == nil {
		return false
	}
	if len(f.Names) > 0 {
		hit := false
		for _, n := range f.Names {
			if n != "" && strings.Contains(v.Name, n) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(f.Drivers) > 0 {
		hit := false
		for _, d := range f.Drivers {
			if v.Driver == d || (d == DriverLocal && v.Driver == "") {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	for _, term := range f.Labels {
		key, want, hasVal := strings.Cut(term, "=")
		got, ok := v.Labels[key]
		if !ok {
			return false
		}
		if hasVal && got != want {
			return false
		}
	}
	if f.Dangling != nil && *f.Dangling == inUse {
		return false
	}
	return true
}

// ParseFilters converts the Docker API's filter map into a Filters. It exists
// so the API layer does not have to re-derive the key names, and it rejects an
// unknown key rather than ignoring it, so a typo in a compose file or a CLI
// flag is reported instead of silently widening the result.
func ParseFilters(in map[string][]string) (Filters, error) {
	var f Filters
	for key, vals := range in {
		switch strings.ToLower(key) {
		case "name":
			f.Names = append(f.Names, vals...)
		case "driver":
			f.Drivers = append(f.Drivers, vals...)
		case "label":
			f.Labels = append(f.Labels, vals...)
		case "dangling":
			for _, v := range vals {
				b, err := strconv.ParseBool(v)
				if err != nil {
					return Filters{}, fmt.Errorf("volume: invalid dangling filter %q: want true or false", v)
				}
				f.Dangling = &b
			}
		case "all":
			for _, v := range vals {
				b, err := strconv.ParseBool(v)
				if err != nil {
					return Filters{}, fmt.Errorf("volume: invalid all filter %q: want true or false", v)
				}
				f.All = b
			}
		default:
			return Filters{}, fmt.Errorf("volume: unsupported filter %q (supported: name, driver, label, dangling, all)", key)
		}
	}
	return f, nil
}
