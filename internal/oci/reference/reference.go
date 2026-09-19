// Package reference parses and normalises Docker/OCI image references using
// the distribution reference grammar.
//
// A reference is domain/path[:tag][@digest]. Parse always returns a fully
// normalised Reference — docker.io as the domain, a library/ prefix on
// single-component Docker Hub paths, and tag "latest" when neither a tag nor a
// digest was given — so every other hull package can compare references by
// String() without repeating the normalisation rules.
package reference

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Default domain and repository conventions of Docker Hub.
const (
	// DefaultDomain is the registry assumed when a reference has no domain.
	DefaultDomain = "docker.io"
	// LegacyDefaultDomain is the older spelling of DefaultDomain, which
	// Parse normalises away.
	LegacyDefaultDomain = "index.docker.io"
	// OfficialRepoPrefix is prepended to single-component Docker Hub paths.
	OfficialRepoPrefix = "library/"
	// DefaultTag is used when a reference names neither a tag nor a digest.
	DefaultTag = "latest"
	// MaxTagLength is the longest tag the grammar allows.
	MaxTagLength = 128
)

// Errors returned by Parse and ParseDigest. Callers use errors.Is to tell a
// malformed reference from a malformed digest.
var (
	// ErrEmptyReference is returned when the reference string is empty.
	ErrEmptyReference = errors.New("reference: empty image reference")
	// ErrInvalidReference is returned when a reference does not match the
	// distribution grammar.
	ErrInvalidReference = errors.New("reference: invalid image reference")
	// ErrInvalidDigest is returned when a digest is not sha256 plus 64
	// lowercase hex characters.
	ErrInvalidDigest = errors.New("reference: invalid digest")
)

var (
	domainRe = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?))*(?::[0-9]+)?$`)
	ipv6DomainRe = regexp.MustCompile(`^\[[0-9a-fA-F:.]+\](?::[0-9]+)?$`)
	pathRe = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
	tagRe  = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)
	sha256Re = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Reference is a parsed, normalised image reference.
//
// Domain and Path are always populated after a successful Parse. Exactly one
// of Tag and Digest is guaranteed to be set, and both may be set when the
// caller wrote name:tag@digest.
type Reference struct {
	Domain string // e.g. docker.io, ghcr.io, localhost:5000
	Path   string // e.g. library/alpine, foo/bar
	Tag    string // e.g. 3.20; empty for a digest-only reference
	Digest string // e.g. sha256:<64 hex>; empty when untagged by digest
}

// String returns the canonical, fully qualified form of the reference, for
// example docker.io/library/alpine:3.20.
func (r Reference) String() string {
	var b strings.Builder
	if r.Domain != "" {
		b.WriteString(r.Domain)
		b.WriteByte('/')
	}
	b.WriteString(r.Path)
	if r.Tag != "" {
		b.WriteByte(':')
		b.WriteString(r.Tag)
	}
	if r.Digest != "" {
		b.WriteByte('@')
		b.WriteString(r.Digest)
	}
	return b.String()
}

// FamiliarString returns the short form a user would type: the docker.io
// domain and the library/ prefix are dropped, so docker.io/library/alpine:3.20
// becomes alpine:3.20.
func (r Reference) FamiliarString() string {
	domain, path := r.Domain, r.Path
	if domain == DefaultDomain {
		domain = ""
		if strings.HasPrefix(path, OfficialRepoPrefix) &&
			!strings.Contains(strings.TrimPrefix(path, OfficialRepoPrefix), "/") {
			path = strings.TrimPrefix(path, OfficialRepoPrefix)
		}
	}
	short := Reference{Domain: domain, Path: path, Tag: r.Tag, Digest: r.Digest}
	return short.String()
}

// Repository returns domain/path with no tag or digest.
func (r Reference) Repository() string {
	if r.Domain == "" {
		return r.Path
	}
	return r.Domain + "/" + r.Path
}

// Name returns the path component alone, which is what a registry API URL
// uses after /v2/ (for example library/alpine).
func (r Reference) Name() string { return r.Path }

// IsDigest reports whether the reference pins a content digest.
func (r Reference) IsDigest() bool { return r.Digest != "" }

// IsTagged reports whether the reference carries a tag.
func (r Reference) IsTagged() bool { return r.Tag != "" }

// WithDigest returns a copy of the reference pinned to digest d. The caller is
// responsible for validating d with ParseDigest; WithDigest does not, so it
// can be used in a fluent chain.
func (r Reference) WithDigest(d string) Reference {
	r.Digest = d
	return r
}

// WithTag returns a copy of the reference carrying tag t.
func (r Reference) WithTag(t string) Reference {
	r.Tag = t
	return r
}

// ParseDigest validates a content digest. hull only accepts sha256 with 64
// lowercase hex characters: uppercase hex would break the content store's
// filename-is-the-digest invariant, and no registry hull talks to serves it.
func ParseDigest(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty digest", ErrInvalidDigest)
	}
	if sha256Re.MatchString(s) {
		return nil
	}
	algo, hex, ok := strings.Cut(s, ":")
	switch {
	case !ok:
		return fmt.Errorf("%w: %q has no algorithm prefix, want sha256:<64 hex>", ErrInvalidDigest, s)
	case algo != "sha256":
		return fmt.Errorf("%w: %q uses algorithm %q; hull only supports sha256", ErrInvalidDigest, s, algo)
	case len(hex) != 64:
		return fmt.Errorf("%w: %q has a %d-character hex part, want 64", ErrInvalidDigest, s, len(hex))
	default:
		return fmt.Errorf("%w: %q must be 64 lowercase hex characters", ErrInvalidDigest, s)
	}
}

// Parse parses and normalises an image reference.
//
// Normalisation: a missing domain becomes docker.io; a docker.io path with no
// slash gains the library/ prefix; index.docker.io becomes docker.io; and a
// reference with neither tag nor digest gets tag "latest". A first component
// that contains "." or ":", or equals "localhost", is treated as the registry
// domain rather than a path element.
func Parse(s string) (Reference, error) {
	if s == "" {
		return Reference{}, ErrEmptyReference
	}
	if strings.ContainsAny(s, " \t\r\n\x00") {
		return Reference{}, fmt.Errorf("%w: %q contains whitespace or a NUL byte", ErrInvalidReference, s)
	}

	rest := s
	var digest string
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		digest = rest[i+1:]
		rest = rest[:i]
		if err := ParseDigest(digest); err != nil {
			return Reference{}, err
		}
		if rest == "" {
			return Reference{}, fmt.Errorf("%w: %q has a digest but no name", ErrInvalidReference, s)
		}
	}

	// A colon is a tag separator only when nothing after it contains a slash;
	// otherwise it is a registry port in the domain component.
	var tag string
	if i := strings.LastIndexByte(rest, ':'); i >= 0 && !strings.ContainsRune(rest[i+1:], '/') {
		tag, rest = rest[i+1:], rest[:i]
		if tag == "" {
			return Reference{}, fmt.Errorf("%w: %q has an empty tag", ErrInvalidReference, s)
		}
		if len(tag) > MaxTagLength {
			return Reference{}, fmt.Errorf("%w: tag %q is %d characters, the maximum is %d", ErrInvalidReference, tag, len(tag), MaxTagLength)
		}
		if !tagRe.MatchString(tag) {
			return Reference{}, fmt.Errorf("%w: tag %q is not valid; tags match [A-Za-z0-9_][A-Za-z0-9._-]*", ErrInvalidReference, tag)
		}
	}
	if rest == "" {
		return Reference{}, fmt.Errorf("%w: %q has no repository name", ErrInvalidReference, s)
	}

	domain, path := splitDomain(rest)
	if domain == LegacyDefaultDomain {
		domain = DefaultDomain
	}
	if domain != DefaultDomain && !domainRe.MatchString(domain) && !ipv6DomainRe.MatchString(domain) {
		return Reference{}, fmt.Errorf("%w: registry domain %q is not a valid host[:port]", ErrInvalidReference, domain)
	}
	if path == "" {
		return Reference{}, fmt.Errorf("%w: %q has no repository name", ErrInvalidReference, s)
	}
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return Reference{}, fmt.Errorf("%w: repository path %q has an empty component", ErrInvalidReference, path)
	}
	if path != strings.ToLower(path) {
		return Reference{}, fmt.Errorf("%w: repository path %q must be lowercase", ErrInvalidReference, path)
	}
	if !pathRe.MatchString(path) {
		return Reference{}, fmt.Errorf("%w: repository path %q is not valid; components match [a-z0-9]+ separated by . _ __ or -", ErrInvalidReference, path)
	}
	if domain == DefaultDomain && !strings.ContainsRune(path, '/') {
		path = OfficialRepoPrefix + path
	}

	ref := Reference{Domain: domain, Path: path, Tag: tag, Digest: digest}
	if ref.Tag == "" && ref.Digest == "" {
		ref.Tag = DefaultTag
	}
	return ref, nil
}

// splitDomain separates an optional registry domain from the repository path.
// The first slash-separated component is the domain only when it looks like a
// host: it contains "." or ":", or it is exactly "localhost".
func splitDomain(name string) (domain, path string) {
	i := strings.IndexByte(name, '/')
	if i == -1 {
		return DefaultDomain, name
	}
	head := name[:i]
	if !strings.ContainsAny(head, ".:") && head != "localhost" {
		return DefaultDomain, name
	}
	return head, name[i+1:]
}
