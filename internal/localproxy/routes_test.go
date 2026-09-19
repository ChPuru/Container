package localproxy

import (
	"errors"
	"strings"
	"testing"
)

// newTestProxy builds a Proxy with both listeners disabled, so no CA is
// created and no port is bound. Handler-level tests need nothing else.
func newTestProxy(t *testing.T, cfg Config) *Proxy {
	t.Helper()
	cfg.HTTPAddr = disabled
	cfg.HTTPSAddr = disabled
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "api.localhost", "api.localhost"},
		{"uppercase", "API.LOCALHOST", "api.localhost"},
		{"mixed case with port", "Api.Localhost:8080", "api.localhost"},
		{"default port", "api.localhost:80", "api.localhost"},
		{"tls port", "api.localhost:443", "api.localhost"},
		{"trailing root dot", "api.localhost.", "api.localhost"},
		{"trailing dot and port", "api.localhost.:443", "api.localhost"},
		{"several trailing dots", "api.localhost..", "api.localhost"},
		{"surrounding space", "  api.localhost  ", "api.localhost"},
		{"bare label", "api", "api"},
		{"ipv4", "127.0.0.1", "127.0.0.1"},
		{"ipv4 with port", "127.0.0.1:32769", "127.0.0.1"},
		{"ipv6 bracketed with port", "[::1]:443", "::1"},
		{"ipv6 bracketed", "[::1]", "::1"},
		{"ipv6 bare", "::1", "::1"},
		{"empty", "", ""},
		{"only spaces", "   ", ""},
		{"empty port", "api.localhost:", "api.localhost"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeHost(tc.in); got != tc.want {
				t.Errorf("normalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidHostname(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"simple", "api.localhost", true},
		{"single label", "api", true},
		{"digits", "app2.localhost", true},
		{"inner hyphen", "my-app.localhost", true},
		{"underscore (docker names allow it)", "my_app.localhost", true},
		{"empty", "", false},
		{"empty label", "api..localhost", false},
		{"leading hyphen", "-api.localhost", false},
		{"trailing hyphen", "api-.localhost", false},
		{"space", "my app.localhost", false},
		{"slash", "api/v1.localhost", false},
		{"uppercase (must be normalised first)", "API.localhost", false},
		{"long label", strings.Repeat("a", 64) + ".localhost", false},
		{"max label", strings.Repeat("a", 63) + ".localhost", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := validHostname(tc.in); got != tc.want {
				t.Errorf("validHostname(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "host port", in: "127.0.0.1:32769", want: "http://127.0.0.1:32769"},
		{name: "container ip", in: "10.66.2.2:8080", want: "http://10.66.2.2:8080"},
		{name: "explicit http", in: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{name: "https", in: "https://127.0.0.1:8443", want: "https://127.0.0.1:8443"},
		{name: "path prefix kept", in: "http://127.0.0.1:8080/api", want: "http://127.0.0.1:8080/api"},
		{name: "trailing slash trimmed", in: "http://127.0.0.1:8080/", want: "http://127.0.0.1:8080"},
		{name: "query dropped", in: "http://127.0.0.1:8080/?a=b", want: "http://127.0.0.1:8080"},
		{name: "spaces trimmed", in: "  127.0.0.1:8080 ", want: "http://127.0.0.1:8080"},
		{name: "empty", in: "", wantErr: true},
		{name: "wrong scheme", in: "tcp://127.0.0.1:8080", wantErr: true},
		{name: "no host", in: "http://", wantErr: true},
		{name: "port only", in: "http://:8080", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := parseTarget(tc.in)
			if tc.wantErr {
				if !errors.Is(err, ErrBadTarget) {
					t.Fatalf("parseTarget(%q) err = %v, want ErrBadTarget", tc.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTarget(%q): %v", tc.in, err)
			}
			if got := u.String(); got != tc.want {
				t.Errorf("parseTarget(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRegisterQualifiesNames(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		regName string
		aliases []string
		want    []string
	}{
		{
			name: "bare name gets the domain", regName: "api",
			want: []string{"api.localhost"},
		},
		{
			name: "name already qualified is not doubled", regName: "api.localhost",
			want: []string{"api.localhost"},
		},
		{
			name: "case folded", regName: "API",
			want: []string{"api.localhost"},
		},
		{
			name: "bare aliases get the domain", regName: "api", aliases: []string{"backend", "v1"},
			want: []string{"api.localhost", "backend.localhost", "v1.localhost"},
		},
		{
			name: "dotted alias is verbatim", regName: "api", aliases: []string{"api.internal"},
			want: []string{"api.localhost", "api.internal"},
		},
		{
			name: "duplicate alias collapses", regName: "api", aliases: []string{"api", "api.localhost"},
			want: []string{"api.localhost"},
		},
		{
			name: "custom domain", domain: "hull.test", regName: "api",
			want: []string{"api.hull.test"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProxy(t, Config{Domain: tc.domain})
			if err := p.Register(tc.regName, "127.0.0.1:8080", tc.aliases...); err != nil {
				t.Fatalf("Register: %v", err)
			}
			routes := p.Routes()
			if len(routes) != 1 {
				t.Fatalf("Routes() = %d entries, want 1", len(routes))
			}
			got := routes[0].Hostnames
			if len(got) != len(tc.want) {
				t.Fatalf("hostnames = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("hostnames = %v, want %v", got, tc.want)
				}
			}
			for _, h := range tc.want {
				if target, ok := p.Lookup(h); !ok || target != "http://127.0.0.1:8080" {
					t.Errorf("Lookup(%q) = %q, %v; want the registered target", h, target, ok)
				}
			}
		})
	}
}

func TestRegisterErrors(t *testing.T) {
	tests := []struct {
		name    string
		regName string
		target  string
		aliases []string
		want    error
	}{
		{name: "empty name", regName: "", target: "127.0.0.1:8080", want: ErrBadName},
		{name: "space in name", regName: "my app", target: "127.0.0.1:8080", want: ErrBadName},
		{name: "bad alias", regName: "api", target: "127.0.0.1:8080", aliases: []string{"nope!"}, want: ErrBadName},
		{name: "empty target", regName: "api", target: "", want: ErrBadTarget},
		{name: "bad scheme", regName: "api", target: "ftp://x:21", want: ErrBadTarget},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProxy(t, Config{})
			err := p.Register(tc.regName, tc.target, tc.aliases...)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Register err = %v, want %v", err, tc.want)
			}
			if n := len(p.Routes()); n != 0 {
				t.Fatalf("a failed Register left %d routes behind", n)
			}
		})
	}
}

func TestRegisterConflict(t *testing.T) {
	p := newTestProxy(t, Config{})
	if err := p.Register("api", "127.0.0.1:1"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	err := p.Register("web", "127.0.0.1:2", "api")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	if n := len(p.Routes()); n != 1 {
		t.Fatalf("Routes() = %d, want 1: a conflicting Register must change nothing", n)
	}
	if target, _ := p.Lookup("api.localhost"); target != "http://127.0.0.1:1" {
		t.Errorf("api.localhost = %q, want the original target", target)
	}
}

func TestRegisterReplacesAndDropsStaleAliases(t *testing.T) {
	p := newTestProxy(t, Config{})
	if err := p.Register("api", "127.0.0.1:1", "old"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// A restarted container comes back on a new port with a different alias.
	if err := p.Register("api", "127.0.0.1:2", "new"); err != nil {
		t.Fatalf("Register (replace): %v", err)
	}
	if n := len(p.Routes()); n != 1 {
		t.Fatalf("Routes() = %d, want 1", n)
	}
	if target, _ := p.Lookup("api.localhost"); target != "http://127.0.0.1:2" {
		t.Errorf("api.localhost = %q, want the new target", target)
	}
	if _, ok := p.Lookup("old.localhost"); ok {
		t.Error("the stale alias old.localhost still routes")
	}
	if target, ok := p.Lookup("new.localhost"); !ok || target != "http://127.0.0.1:2" {
		t.Errorf("new.localhost = %q, %v; want the new target", target, ok)
	}
}

func TestUnregister(t *testing.T) {
	p := newTestProxy(t, Config{})
	if err := p.Register("api", "127.0.0.1:1", "backend"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := p.Unregister("API"); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if n := len(p.Routes()); n != 0 {
		t.Fatalf("Routes() = %d, want 0", n)
	}
	for _, h := range []string{"api.localhost", "backend.localhost"} {
		if _, ok := p.Lookup(h); ok {
			t.Errorf("%s still routes after Unregister", h)
		}
	}
	err := p.Unregister("api")
	if !errors.Is(err, ErrNoRoute) {
		t.Fatalf("second Unregister err = %v, want ErrNoRoute", err)
	}
}

func TestRoutesSortedAndCopied(t *testing.T) {
	p := newTestProxy(t, Config{})
	for _, n := range []string{"web", "api", "db"} {
		if err := p.Register(n, "127.0.0.1:8080"); err != nil {
			t.Fatalf("Register(%s): %v", n, err)
		}
	}
	routes := p.Routes()
	want := []string{"api", "db", "web"}
	for i, w := range want {
		if routes[i].Name != w {
			t.Fatalf("Routes() = %v, want sorted %v", routes, want)
		}
	}
	// Mutating the result must not reach the proxy.
	routes[0].Hostnames[0] = "tampered"
	if target, ok := p.Lookup("api.localhost"); !ok || target == "" {
		t.Error("mutating the Routes() result changed the route table")
	}
}

func TestLookupFallsBackToResolve(t *testing.T) {
	var asked []string
	p := newTestProxy(t, Config{
		Resolve: func(host string) (string, bool) {
			asked = append(asked, host)
			if host == "dynamic.localhost" {
				return "10.66.2.9:8080", true
			}
			if host == "broken.localhost" {
				return "not a target", true
			}
			return "", false
		},
	})
	if err := p.Register("static", "127.0.0.1:1"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if target, ok := p.Lookup("static.localhost"); !ok || target != "http://127.0.0.1:1" {
		t.Errorf("static route = %q, %v", target, ok)
	}
	if len(asked) != 0 {
		t.Errorf("Resolve was consulted for a static route: %v", asked)
	}
	if target, ok := p.Lookup("DYNAMIC.localhost:8080"); !ok || target != "http://10.66.2.9:8080" {
		t.Errorf("dynamic route = %q, %v, want the resolved target", target, ok)
	}
	if len(asked) == 0 || asked[0] != "dynamic.localhost" {
		t.Errorf("Resolve was called with %v, want the normalised host", asked)
	}
	if _, ok := p.Lookup("broken.localhost"); ok {
		t.Error("an unparseable Resolve target was accepted")
	}
	if _, ok := p.Lookup("missing.localhost"); ok {
		t.Error("an unresolved host routed anyway")
	}
}

func TestNewRejectsBadDomain(t *testing.T) {
	if _, err := New(Config{HTTPAddr: disabled, HTTPSAddr: disabled, Domain: "not a domain"}); !errors.Is(err, ErrBadName) {
		t.Fatalf("err = %v, want ErrBadName", err)
	}
}

func TestNewRequiresCADirForHTTPS(t *testing.T) {
	if _, err := New(Config{HTTPAddr: disabled, HTTPSAddr: "127.0.0.1:0"}); err == nil {
		t.Fatal("New accepted HTTPS with no CADir")
	}
}

func TestSuggest(t *testing.T) {
	routes := []Route{
		{Name: "myapp", Hostnames: []string{"myapp.localhost"}},
		{Name: "postgres", Hostnames: []string{"postgres.localhost", "db.localhost"}},
	}
	tests := []struct {
		name string
		host string
		want string
	}{
		{"typo", "myap.localhost", "myapp.localhost"},
		{"transposition", "myapp.localhost", "myapp.localhost"},
		{"alias typo", "dbb.localhost", "postgres.localhost"},
		{"nothing close", "elasticsearch.localhost", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := suggest(tc.host, routes)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("suggest(%q) = %v, want none", tc.host, got)
				}
				return
			}
			if len(got) == 0 || got[0] != tc.want {
				t.Fatalf("suggest(%q) = %v, want %q first", tc.host, got, tc.want)
			}
		})
	}
}
