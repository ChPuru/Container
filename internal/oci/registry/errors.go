package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ChPuru/hull/internal/types"
)

// Sentinel errors returned by the registry client. Match them with errors.Is;
// the typed errors below all satisfy the sentinel they belong to.
var (
	// ErrNotFound means the registry answered 404 for a manifest, blob, tag
	// list or repository.
	ErrNotFound = errors.New("registry: not found")

	// ErrUnauthorized means the registry answered 401 and no usable
	// credentials were available.
	ErrUnauthorized = errors.New("registry: unauthorized")

	// ErrDenied means the registry answered 403: the credentials are valid but
	// do not grant the requested scope.
	ErrDenied = errors.New("registry: access denied")

	// ErrSchema1 means the registry served an obsolete Docker schema1
	// manifest. hull never parses these. SchemaOneError carries the reference.
	ErrSchema1 = errors.New("registry: Docker schema1 manifest")

	// ErrPlatformNotFound means an image index had no entry for the requested
	// platform. PlatformNotFoundError lists the platforms that are present.
	ErrPlatformNotFound = errors.New("registry: no image for the requested platform")

	// ErrRateLimited means the registry answered 429. RateLimitError carries
	// the reset time.
	ErrRateLimited = errors.New("registry: rate limited")

	// ErrUnsupported means the registry does not implement the requested
	// operation (for example manifest deletion, which most registries disable).
	ErrUnsupported = errors.New("registry: operation not supported by this registry")

	// ErrDigestMismatch means content did not hash to the digest that named it.
	// DigestMismatchError carries both digests.
	ErrDigestMismatch = errors.New("registry: digest mismatch")

	// ErrIndexTooDeep means an image index nested indexes more deeply than the
	// spec allows a client to follow.
	ErrIndexTooDeep = errors.New("registry: image index nested too deeply")

	// ErrMalformed means a response was syntactically valid HTTP but not a
	// usable distribution-spec payload.
	ErrMalformed = errors.New("registry: malformed registry response")
)

// APIError is one entry of a distribution-spec error body.
type APIError struct {
	// Code is the upper-case error code, e.g. MANIFEST_UNKNOWN.
	Code string `json:"code"`
	// Message is the registry's human-readable message.
	Message string `json:"message"`
	// Detail is the registry-specific detail object, left as raw JSON.
	Detail json.RawMessage `json:"detail,omitempty"`
}

// String renders one API error as "CODE: message".
func (e APIError) String() string {
	switch {
	case e.Code != "" && e.Message != "":
		return e.Code + ": " + e.Message
	case e.Code != "":
		return e.Code
	default:
		return e.Message
	}
}

// StatusError is a non-2xx HTTP response from a registry, with the
// distribution-spec error body decoded when the registry sent one.
//
// It matches ErrNotFound, ErrUnauthorized, ErrDenied, ErrUnsupported and
// ErrRateLimited under errors.Is according to its status code.
type StatusError struct {
	// Method is the HTTP method of the failed request.
	Method string
	// URL is the request URL, with any query string preserved.
	URL string
	// StatusCode is the HTTP status code.
	StatusCode int
	// Status is the HTTP status line.
	Status string
	// Errors holds the decoded distribution-spec error entries, if any.
	Errors []APIError
	// Body is the first few kilobytes of the response body, kept when it was
	// not a decodable error document.
	Body string
}

// Error implements error.
func (e *StatusError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "registry: %s %s: %s", e.Method, e.URL, e.statusText())
	if len(e.Errors) > 0 {
		parts := make([]string, 0, len(e.Errors))
		for _, ae := range e.Errors {
			parts = append(parts, ae.String())
		}
		b.WriteString(": ")
		b.WriteString(strings.Join(parts, "; "))
	} else if e.Body != "" {
		b.WriteString(": ")
		b.WriteString(e.Body)
	}
	return b.String()
}

func (e *StatusError) statusText() string {
	if e.Status != "" {
		return e.Status
	}
	return fmt.Sprintf("HTTP %d", e.StatusCode)
}

// Is maps HTTP status codes onto the package sentinels.
func (e *StatusError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.StatusCode == 404
	case ErrUnauthorized:
		return e.StatusCode == 401
	case ErrDenied:
		return e.StatusCode == 403
	case ErrRateLimited:
		return e.StatusCode == 429
	case ErrUnsupported:
		return e.StatusCode == 405 || e.StatusCode == 501
	}
	return false
}

// SchemaOneError reports a Docker schema1 manifest, which was removed from the
// ecosystem in 2025 and which hull deliberately refuses to parse. It matches
// ErrSchema1 under errors.Is.
type SchemaOneError struct {
	// Ref is the reference that resolved to a schema1 manifest.
	Ref string
	// MediaType is the schema1 media type the registry returned.
	MediaType string
}

// Error implements error.
func (e *SchemaOneError) Error() string {
	return fmt.Sprintf("registry: %s is a Docker schema1 image, which was removed from the ecosystem in 2025. "+
		"Re-push it as OCI or use a newer tag.", e.Ref)
}

// Is makes errors.Is(err, ErrSchema1) true.
func (e *SchemaOneError) Is(target error) bool { return target == ErrSchema1 }

// PlatformNotFoundError reports that an image index carried no entry for the
// requested platform, and lists the platforms it does carry. It matches
// ErrPlatformNotFound under errors.Is.
type PlatformNotFoundError struct {
	// Ref is the reference that was resolved.
	Ref string
	// Want is the platform that was asked for.
	Want types.Platform
	// Have lists every platform the index actually offers, in index order.
	Have []types.Platform
}

// Error implements error.
func (e *PlatformNotFoundError) Error() string {
	have := make([]string, 0, len(e.Have))
	for _, p := range e.Have {
		have = append(have, PlatformString(p))
	}
	if len(have) == 0 {
		return fmt.Sprintf("registry: %s has no image for platform %s; the index lists no platforms at all",
			e.Ref, PlatformString(e.Want))
	}
	return fmt.Sprintf("registry: %s has no image for platform %s; the index offers %s",
		e.Ref, PlatformString(e.Want), strings.Join(have, ", "))
}

// Is makes errors.Is(err, ErrPlatformNotFound) true.
func (e *PlatformNotFoundError) Is(target error) bool { return target == ErrPlatformNotFound }

// RateLimitError reports a 429 from a registry. It matches ErrRateLimited
// under errors.Is.
type RateLimitError struct {
	// Registry is the host that rate-limited the request.
	Registry string
	// Reset is when the caller may retry, derived from Retry-After or from the
	// RateLimit-Reset header. It is the zero time when the registry said
	// nothing useful.
	Reset time.Time
	// RetryAfter is the delay the registry asked for, or zero when unknown.
	RetryAfter time.Duration
	// Limit and Remaining are the RateLimit-Limit / RateLimit-Remaining values
	// when the registry sent them.
	Limit     int
	Remaining int
}

// Error implements error.
func (e *RateLimitError) Error() string {
	var b strings.Builder
	if IsDockerHub(e.Registry) {
		b.WriteString("registry: Docker Hub rate limit reached. 'hull login' raises the limit substantially.")
	} else {
		fmt.Fprintf(&b, "registry: %s rate limit reached.", e.Registry)
	}
	if e.Limit > 0 {
		fmt.Fprintf(&b, " Limit %d", e.Limit)
		if e.Remaining >= 0 {
			fmt.Fprintf(&b, ", %d remaining", e.Remaining)
		}
		b.WriteByte('.')
	}
	if !e.Reset.IsZero() {
		fmt.Fprintf(&b, " Retry after %s.", e.Reset.UTC().Format(time.RFC3339))
	} else if e.RetryAfter > 0 {
		fmt.Fprintf(&b, " Retry in %s.", e.RetryAfter)
	}
	return b.String()
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// DigestMismatchError reports content whose bytes did not hash to the digest
// that named them. It matches ErrDigestMismatch under errors.Is.
type DigestMismatchError struct {
	// Ref names what was being fetched, for the message.
	Ref string
	// Expected is the digest the registry or the reference promised.
	Expected string
	// Actual is the digest of the bytes that arrived.
	Actual string
}

// Error implements error.
func (e *DigestMismatchError) Error() string {
	return fmt.Sprintf("registry: %s: content digest mismatch: expected %s, got %s", e.Ref, e.Expected, e.Actual)
}

// Is makes errors.Is(err, ErrDigestMismatch) true.
func (e *DigestMismatchError) Is(target error) bool { return target == ErrDigestMismatch }

// PlatformString renders a platform as os/arch[/variant], the form users type
// and the CLI prints.
func PlatformString(p types.Platform) string {
	var b strings.Builder
	if p.OS == "" {
		b.WriteString("unknown")
	} else {
		b.WriteString(p.OS)
	}
	b.WriteByte('/')
	if p.Architecture == "" {
		b.WriteString("unknown")
	} else {
		b.WriteString(p.Architecture)
	}
	if p.Variant != "" {
		b.WriteByte('/')
		b.WriteString(p.Variant)
	}
	if p.OSVersion != "" {
		b.WriteByte(':')
		b.WriteString(p.OSVersion)
	}
	return b.String()
}
