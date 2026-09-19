package registry

import (
	"reflect"
	"testing"
)

func TestParseChallenges(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   []Challenge
	}{
		{
			name:   "empty",
			header: "",
			want:   nil,
		},
		{
			name:   "docker hub",
			header: `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"`,
			want: []Challenge{{Scheme: "bearer", Params: map[string]string{
				"realm":   "https://auth.docker.io/token",
				"service": "registry.docker.io",
				"scope":   "repository:library/alpine:pull",
			}}},
		},
		{
			name:   "ghcr",
			header: `Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:user/image:pull"`,
			want: []Challenge{{Scheme: "bearer", Params: map[string]string{
				"realm":   "https://ghcr.io/token",
				"service": "ghcr.io",
				"scope":   "repository:user/image:pull",
			}}},
		},
		{
			name:   "quay no scope",
			header: `Bearer realm="https://quay.io/v2/auth",service="quay.io"`,
			want: []Challenge{{Scheme: "bearer", Params: map[string]string{
				"realm":   "https://quay.io/v2/auth",
				"service": "quay.io",
			}}},
		},
		{
			name:   "gitlab",
			header: `Bearer realm="https://gitlab.com/jwt/auth",service="container_registry",scope="repository:group/proj/img:pull"`,
			want: []Challenge{{Scheme: "bearer", Params: map[string]string{
				"realm":   "https://gitlab.com/jwt/auth",
				"service": "container_registry",
				"scope":   "repository:group/proj/img:pull",
			}}},
		},
		{
			name:   "ecr basic",
			header: `Basic realm="https://123456789012.dkr.ecr.us-east-1.amazonaws.com/",service="ecr.amazonaws.com"`,
			want: []Challenge{{Scheme: "basic", Params: map[string]string{
				"realm":   "https://123456789012.dkr.ecr.us-east-1.amazonaws.com/",
				"service": "ecr.amazonaws.com",
			}}},
		},
		{
			name:   "push scope with comma inside quotes",
			header: `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:me/img:pull,push"`,
			want: []Challenge{{Scheme: "bearer", Params: map[string]string{
				"realm":   "https://auth.docker.io/token",
				"service": "registry.docker.io",
				"scope":   "repository:me/img:pull,push",
			}}},
		},
		{
			name:   "unquoted values with padding spaces",
			header: `Bearer realm=https://auth.example.com/token ,  service=example.com , scope=repository:foo/bar:pull`,
			want: []Challenge{{Scheme: "bearer", Params: map[string]string{
				"realm":   "https://auth.example.com/token",
				"service": "example.com",
				"scope":   "repository:foo/bar:pull",
			}}},
		},
		{
			name:   "two challenges basic then bearer",
			header: `Basic realm="registry", Bearer realm="https://auth.example.com/token",service="example"`,
			want: []Challenge{
				{Scheme: "basic", Params: map[string]string{"realm": "registry"}},
				{Scheme: "bearer", Params: map[string]string{
					"realm":   "https://auth.example.com/token",
					"service": "example",
				}},
			},
		},
		{
			name:   "bare negotiate before bearer",
			header: `Negotiate, Bearer realm="https://auth.example.com/token"`,
			want: []Challenge{
				{Scheme: "negotiate", Params: map[string]string{}},
				{Scheme: "bearer", Params: map[string]string{"realm": "https://auth.example.com/token"}},
			},
		},
		{
			name:   "negotiate token68",
			header: `Negotiate YIIFvwYGKwYBBQUCoIIFszCC==, Bearer realm="https://auth.example.com/token"`,
			want: []Challenge{
				{Scheme: "negotiate", Params: map[string]string{}, Token68: "YIIFvwYGKwYBBQUCoIIFszCC=="},
				{Scheme: "bearer", Params: map[string]string{"realm": "https://auth.example.com/token"}},
			},
		},
		{
			name:   "escaped quote in value",
			header: `Bearer realm="https://auth.example.com/to\"ken",service="x"`,
			want: []Challenge{{Scheme: "bearer", Params: map[string]string{
				"realm":   `https://auth.example.com/to"ken`,
				"service": "x",
			}}},
		},
		{
			name:   "lowercase scheme and mixed-case keys",
			header: `bearer Realm="https://auth.example.com/token",SERVICE="example"`,
			want: []Challenge{{Scheme: "bearer", Params: map[string]string{
				"realm":   "https://auth.example.com/token",
				"service": "example",
			}}},
		},
		{
			name:   "insufficient scope error parameter",
			header: `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:x/y:pull",error="insufficient_scope"`,
			want: []Challenge{{Scheme: "bearer", Params: map[string]string{
				"realm":   "https://auth.docker.io/token",
				"service": "registry.docker.io",
				"scope":   "repository:x/y:pull",
				"error":   "insufficient_scope",
			}}},
		},
		{
			name:   "no parameters at all",
			header: `Bearer`,
			want:   []Challenge{{Scheme: "bearer", Params: map[string]string{}}},
		},
		{
			name:   "garbage does not wedge the parser",
			header: `""" Bearer realm="https://auth.example.com/token"`,
			want: []Challenge{{Scheme: "bearer", Params: map[string]string{
				"realm": "https://auth.example.com/token",
			}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseChallenges(tt.header)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseChallenges(%q)\n got = %#v\nwant = %#v", tt.header, got, tt.want)
			}
		})
	}
}

func TestChallengeAccessors(t *testing.T) {
	chs := ParseChallenges(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:a/b:pull repository:c/d:pull"`)
	if len(chs) != 1 {
		t.Fatalf("got %d challenges, want 1", len(chs))
	}
	ch := chs[0]
	if !ch.IsBearer() || ch.IsBasic() {
		t.Errorf("scheme predicates wrong for %+v", ch)
	}
	if ch.Realm() != "https://auth.docker.io/token" {
		t.Errorf("Realm() = %q", ch.Realm())
	}
	if ch.Service() != "registry.docker.io" {
		t.Errorf("Service() = %q", ch.Service())
	}
	if got := ch.Scopes(); !reflect.DeepEqual(got, []string{"repository:a/b:pull", "repository:c/d:pull"}) {
		t.Errorf("Scopes() = %v", got)
	}
}

func TestPickChallenge(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantScheme string
		wantOK     bool
	}{
		{"bearer preferred", `Basic realm="r", Bearer realm="https://t"`, "bearer", true},
		{"basic only", `Basic realm="r"`, "basic", true},
		{"bearer without realm is unusable", `Bearer`, "", false},
		{"unknown scheme only", `Negotiate`, "", false},
		{"empty", ``, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, ok := pickChallenge(ParseChallenges(tt.header))
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (challenge %+v)", ok, tt.wantOK, ch)
			}
			if ok && ch.Scheme != tt.wantScheme {
				t.Errorf("scheme = %q, want %q", ch.Scheme, tt.wantScheme)
			}
		})
	}
}
