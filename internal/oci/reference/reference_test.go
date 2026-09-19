package reference

import (
	"errors"
	"strings"
	"testing"
)

const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseValid(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		domain   string
		path     string
		tag      string
		digest   string
		canon    string
		familiar string
	}{
		{
			name: "bare name", in: "alpine",
			domain: "docker.io", path: "library/alpine", tag: "latest",
			canon: "docker.io/library/alpine:latest", familiar: "alpine:latest",
		},
		{
			name: "bare name with tag", in: "alpine:3.20",
			domain: "docker.io", path: "library/alpine", tag: "3.20",
			canon: "docker.io/library/alpine:3.20", familiar: "alpine:3.20",
		},
		{
			name: "explicit library", in: "library/alpine",
			domain: "docker.io", path: "library/alpine", tag: "latest",
			canon: "docker.io/library/alpine:latest", familiar: "alpine:latest",
		},
		{
			name: "fully qualified hub", in: "docker.io/library/alpine",
			domain: "docker.io", path: "library/alpine", tag: "latest",
			canon: "docker.io/library/alpine:latest", familiar: "alpine:latest",
		},
		{
			name: "legacy hub domain", in: "index.docker.io/library/alpine:3.20",
			domain: "docker.io", path: "library/alpine", tag: "3.20",
			canon: "docker.io/library/alpine:3.20", familiar: "alpine:3.20",
		},
		{
			name: "hub user repo", in: "rahuldhali/hull:v1",
			domain: "docker.io", path: "rahuldhali/hull", tag: "v1",
			canon: "docker.io/rahuldhali/hull:v1", familiar: "rahuldhali/hull:v1",
		},
		{
			name: "ghcr", in: "ghcr.io/foo/bar:v1",
			domain: "ghcr.io", path: "foo/bar", tag: "v1",
			canon: "ghcr.io/foo/bar:v1", familiar: "ghcr.io/foo/bar:v1",
		},
		{
			name: "localhost with port", in: "localhost:5000/x",
			domain: "localhost:5000", path: "x", tag: "latest",
			canon: "localhost:5000/x:latest", familiar: "localhost:5000/x:latest",
		},
		{
			name: "localhost no port", in: "localhost/x",
			domain: "localhost", path: "x", tag: "latest",
			canon: "localhost/x:latest", familiar: "localhost/x:latest",
		},
		{
			name: "registry port and digest", in: "registry.example.com:5000/a/b@sha256:" + hex64,
			domain: "registry.example.com:5000", path: "a/b", digest: "sha256:" + hex64,
			canon:    "registry.example.com:5000/a/b@sha256:" + hex64,
			familiar: "registry.example.com:5000/a/b@sha256:" + hex64,
		},
		{
			name: "digest on bare name", in: "alpine@sha256:" + hex64,
			domain: "docker.io", path: "library/alpine", digest: "sha256:" + hex64,
			canon:    "docker.io/library/alpine@sha256:" + hex64,
			familiar: "alpine@sha256:" + hex64,
		},
		{
			name: "tag and digest", in: "alpine:3.20@sha256:" + hex64,
			domain: "docker.io", path: "library/alpine", tag: "3.20", digest: "sha256:" + hex64,
			canon:    "docker.io/library/alpine:3.20@sha256:" + hex64,
			familiar: "alpine:3.20@sha256:" + hex64,
		},
		{
			name: "deep path", in: "registry.example.com/a/b/c/d:tag",
			domain: "registry.example.com", path: "a/b/c/d", tag: "tag",
			canon: "registry.example.com/a/b/c/d:tag", familiar: "registry.example.com/a/b/c/d:tag",
		},
		{
			name: "separators in component", in: "quay.io/some_org/my-app.v2:1.0",
			domain: "quay.io", path: "some_org/my-app.v2", tag: "1.0",
			canon: "quay.io/some_org/my-app.v2:1.0", familiar: "quay.io/some_org/my-app.v2:1.0",
		},
		{
			name: "double underscore", in: "foo__bar/baz",
			domain: "docker.io", path: "foo__bar/baz", tag: "latest",
			canon: "docker.io/foo__bar/baz:latest", familiar: "foo__bar/baz:latest",
		},
		{
			name: "hub path named like host is not a domain", in: "library/alpine:3.20",
			domain: "docker.io", path: "library/alpine", tag: "3.20",
			canon: "docker.io/library/alpine:3.20", familiar: "alpine:3.20",
		},
		{
			name: "multi-level hub path keeps library prefix meaning", in: "docker.io/library/nested/thing",
			domain: "docker.io", path: "library/nested/thing", tag: "latest",
			canon:    "docker.io/library/nested/thing:latest",
			familiar: "library/nested/thing:latest",
		},
		{
			name: "ipv6 registry", in: "[::1]:5000/x:v1",
			domain: "[::1]:5000", path: "x", tag: "v1",
			canon: "[::1]:5000/x:v1", familiar: "[::1]:5000/x:v1",
		},
		{
			name: "max length tag", in: "alpine:" + strings.Repeat("a", 128),
			domain: "docker.io", path: "library/alpine", tag: strings.Repeat("a", 128),
			canon:    "docker.io/library/alpine:" + strings.Repeat("a", 128),
			familiar: "alpine:" + strings.Repeat("a", 128),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q) = error %v, want success", tt.in, err)
			}
			if ref.Domain != tt.domain {
				t.Errorf("Domain = %q, want %q", ref.Domain, tt.domain)
			}
			if ref.Path != tt.path {
				t.Errorf("Path = %q, want %q", ref.Path, tt.path)
			}
			if ref.Tag != tt.tag {
				t.Errorf("Tag = %q, want %q", ref.Tag, tt.tag)
			}
			if ref.Digest != tt.digest {
				t.Errorf("Digest = %q, want %q", ref.Digest, tt.digest)
			}
			if got := ref.String(); got != tt.canon {
				t.Errorf("String() = %q, want %q", got, tt.canon)
			}
			if got := ref.FamiliarString(); got != tt.familiar {
				t.Errorf("FamiliarString() = %q, want %q", got, tt.familiar)
			}
			if got, want := ref.IsTagged(), tt.tag != ""; got != want {
				t.Errorf("IsTagged() = %v, want %v", got, want)
			}
			if got, want := ref.IsDigest(), tt.digest != ""; got != want {
				t.Errorf("IsDigest() = %v, want %v", got, want)
			}
			if got, want := ref.Repository(), tt.domain+"/"+tt.path; got != want {
				t.Errorf("Repository() = %q, want %q", got, want)
			}
			if got := ref.Name(); got != tt.path {
				t.Errorf("Name() = %q, want %q", got, tt.path)
			}
		})
	}
}

func TestParseRoundTripsCanonical(t *testing.T) {
	inputs := []string{
		"alpine",
		"alpine:3.20",
		"ghcr.io/foo/bar:v1",
		"localhost:5000/x",
		"registry.example.com:5000/a/b@sha256:" + hex64,
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			first, err := Parse(in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", in, err)
			}
			second, err := Parse(first.String())
			if err != nil {
				t.Fatalf("Parse(%q): %v", first.String(), err)
			}
			if first != second {
				t.Errorf("round trip changed reference: %+v -> %+v", first, second)
			}
			third, err := Parse(first.FamiliarString())
			if err != nil {
				t.Fatalf("Parse(familiar %q): %v", first.FamiliarString(), err)
			}
			if first != third {
				t.Errorf("familiar round trip changed reference: %+v -> %+v", first, third)
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrEmptyReference},
		{"uppercase path", "Alpine", ErrInvalidReference},
		{"uppercase nested path", "ghcr.io/Foo/bar", ErrInvalidReference},
		{"empty tag", "alpine:", ErrInvalidReference},
		{"empty component", "foo//bar", ErrInvalidReference},
		{"leading slash", "/alpine", ErrInvalidReference},
		{"trailing slash", "ghcr.io/foo/", ErrInvalidReference},
		{"tag too long", "alpine:" + strings.Repeat("a", 129), ErrInvalidReference},
		{"tag bad first char", "alpine:.bad", ErrInvalidReference},
		{"whitespace", "alpine 3.20", ErrInvalidReference},
		{"digest no name", "@sha256:" + hex64, ErrInvalidReference},
		{"bad digest algo", "alpine@md5:" + hex64, ErrInvalidDigest},
		{"short digest", "alpine@sha256:abcd", ErrInvalidDigest},
		{"uppercase digest", "alpine@sha256:" + strings.ToUpper(hex64), ErrInvalidDigest},
		{"no digest prefix", "alpine@" + hex64, ErrInvalidDigest},
		{"bad separator run", "foo_/bar", ErrInvalidReference},
		{"component starts with dash", "-foo/bar", ErrInvalidReference},
		{"nul byte", "alpine\x00", ErrInvalidReference},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := Parse(tt.in)
			if err == nil {
				t.Fatalf("Parse(%q) = %+v, want error", tt.in, ref)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("Parse(%q) error = %v, want errors.Is(_, %v)", tt.in, err, tt.want)
			}
		})
	}
}

func TestParseDigest(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid", "sha256:" + hex64, true},
		{"empty", "", false},
		{"no colon", "sha256" + hex64, false},
		{"wrong algo", "sha512:" + hex64, false},
		{"short", "sha256:abc", false},
		{"long", "sha256:" + hex64 + "ab", false},
		{"uppercase", "sha256:" + strings.ToUpper(hex64), false},
		{"non hex", "sha256:" + strings.Repeat("z", 64), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ParseDigest(tt.in)
			if tt.ok && err != nil {
				t.Fatalf("ParseDigest(%q) = %v, want nil", tt.in, err)
			}
			if !tt.ok {
				if err == nil {
					t.Fatalf("ParseDigest(%q) = nil, want error", tt.in)
				}
				if !errors.Is(err, ErrInvalidDigest) {
					t.Errorf("ParseDigest(%q) error = %v, want ErrInvalidDigest", tt.in, err)
				}
			}
		})
	}
}

func TestWithTagAndDigest(t *testing.T) {
	base, err := Parse("alpine")
	if err != nil {
		t.Fatal(err)
	}
	d := base.WithDigest("sha256:" + hex64)
	if !d.IsDigest() || d.Digest != "sha256:"+hex64 {
		t.Errorf("WithDigest did not set the digest: %+v", d)
	}
	if base.IsDigest() {
		t.Errorf("WithDigest mutated the receiver: %+v", base)
	}
	tagged := base.WithTag("3.20")
	if tagged.Tag != "3.20" {
		t.Errorf("WithTag = %q, want 3.20", tagged.Tag)
	}
	if base.Tag != "latest" {
		t.Errorf("WithTag mutated the receiver: %+v", base)
	}
	if got, want := tagged.String(), "docker.io/library/alpine:3.20"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
