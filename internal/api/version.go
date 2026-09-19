package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Version is one Docker Engine API version, e.g. 1.43. Only the major and
// minor parts exist; Docker has never used a patch level here.
type Version struct {
	// Major and Minor are the two halves of the version.
	Major int
	// Minor is the second half.
	Minor int
}

// ParseVersion parses "1.43" or "v1.43" into a [Version].
func ParseVersion(s string) (Version, error) {
	raw := strings.TrimPrefix(strings.TrimSpace(s), "v")
	majorStr, minorStr, ok := strings.Cut(raw, ".")
	if !ok {
		return Version{}, fmt.Errorf("api: %q is not a Docker API version (want major.minor)", s)
	}
	major, err := strconv.Atoi(majorStr)
	if err != nil || major < 0 {
		return Version{}, fmt.Errorf("api: %q has an invalid major version", s)
	}
	minor, err := strconv.Atoi(minorStr)
	if err != nil || minor < 0 {
		return Version{}, fmt.Errorf("api: %q has an invalid minor version", s)
	}
	return Version{Major: major, Minor: minor}, nil
}

// String renders the version as Docker writes it, without a leading "v".
func (v Version) String() string { return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) }

// Compare orders two versions: -1 when v is older, 0 when equal, 1 when newer.
func (v Version) Compare(o Version) int {
	switch {
	case v.Major != o.Major:
		if v.Major < o.Major {
			return -1
		}
		return 1
	case v.Minor != o.Minor:
		if v.Minor < o.Minor {
			return -1
		}
		return 1
	default:
		return 0
	}
}

// LessThan reports whether v is older than o. It is the readable form of the
// comparison the version-gated handlers do.
func (v Version) LessThan(o Version) bool { return v.Compare(o) < 0 }

// AtLeast reports whether v is o or newer.
func (v Version) AtLeast(o Version) bool { return v.Compare(o) >= 0 }

// splitVersionPrefix strips a leading "/v<major>.<minor>" from a request path.
//
// It returns the remaining path and the version as written. Docker's clients
// prefix nearly every request this way, and a few still do not, so an absent
// prefix is not an error: the server then assumes its own version.
func splitVersionPrefix(path string) (rest string, version string, hadPrefix bool) {
	if !strings.HasPrefix(path, "/v") {
		return path, "", false
	}
	seg := path[1:]
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg, rest = seg[:i], seg[i:]
	} else {
		rest = "/"
	}
	// "v1.43" is a version prefix; "volumes" is not.
	body := seg[1:]
	if body == "" {
		return path, "", false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if (c < '0' || c > '9') && c != '.' {
			return path, "", false
		}
	}
	if !strings.Contains(body, ".") {
		return path, "", false
	}
	return rest, body, true
}

// negotiate checks a client-declared version against the range this server
// serves, returning the version to gate behaviour on.
//
// The refusal messages are Docker's, word for word, because a user who
// searches for the text should find Docker's own troubleshooting.
func (s *Server) negotiate(raw string) (Version, error) {
	if raw == "" {
		return s.version, nil
	}
	v, err := ParseVersion(raw)
	if err != nil {
		return Version{}, errBadParameter("client version %s is not a valid API version", raw)
	}
	if v.Compare(s.version) > 0 {
		return Version{}, errBadParameter(
			"client version %s is too new. Maximum supported API version is %s", v, s.version)
	}
	if v.Compare(s.minVersion) < 0 {
		return Version{}, errBadParameter(
			"client version %s is too old. Minimum supported API version is %s, "+
				"please upgrade your client to a newer version", v, s.minVersion)
	}
	return v, nil
}

// clientVersion returns the API version the current request negotiated. It is
// the server's own version when the client sent no prefix.
func clientVersion(r *http.Request) Version {
	if v, ok := r.Context().Value(ctxKeyVersion).(Version); ok {
		return v
	}
	return Version{Major: 1, Minor: 43}
}
