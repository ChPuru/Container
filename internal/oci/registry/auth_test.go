package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/oci/imagespec"
)

func TestNormalizeAuthKey(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://index.docker.io/v1/", "docker.io"},
		{"index.docker.io", "docker.io"},
		{"docker.io", "docker.io"},
		{"registry-1.docker.io", "docker.io"},
		{"registry.hub.docker.com", "docker.io"},
		{"https://ghcr.io", "ghcr.io"},
		{"ghcr.io", "ghcr.io"},
		{"GHCR.IO", "ghcr.io"},
		{"localhost:5000", "localhost:5000"},
		{"https://harbor.example.com/v2/", "harbor.example.com"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalizeAuthKey(tt.in); got != tt.want {
				t.Errorf("normalizeAuthKey(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsDockerHub(t *testing.T) {
	for _, host := range []string{"docker.io", "index.docker.io", "registry-1.docker.io"} {
		if !IsDockerHub(host) {
			t.Errorf("IsDockerHub(%q) = false", host)
		}
	}
	for _, host := range []string{"ghcr.io", "quay.io", "localhost:5000", ""} {
		if IsDockerHub(host) {
			t.Errorf("IsDockerHub(%q) = true", host)
		}
	}
}

func TestDecodeAuth(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantUser string
		wantPass string
		wantErr  bool
	}{
		{"standard", base64.StdEncoding.EncodeToString([]byte("alice:hunter2")), "alice", "hunter2", false},
		{"password with colons", base64.StdEncoding.EncodeToString([]byte("bob:a:b:c")), "bob", "a:b:c", false},
		{"empty password", base64.StdEncoding.EncodeToString([]byte("carol:")), "carol", "", false},
		{"no colon", base64.StdEncoding.EncodeToString([]byte("nocolon")), "", "", true},
		{"not base64", "!!!!", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, pass, err := decodeAuth(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decodeAuth = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && (user != tt.wantUser || pass != tt.wantPass) {
				t.Errorf("decodeAuth = %q/%q, want %q/%q", user, pass, tt.wantUser, tt.wantPass)
			}
		})
	}
}

// writeConfig writes a docker-style config.json into a temp dir.
func writeConfig(t *testing.T, cfg map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigAuthResolve(t *testing.T) {
	path := writeConfig(t, map[string]any{
		"auths": map[string]any{
			"https://index.docker.io/v1/": map[string]any{
				"auth": base64.StdEncoding.EncodeToString([]byte("hubuser:hubpass")),
			},
			"ghcr.io": map[string]any{
				"username": "ghuser",
				"password": "ghpass",
			},
			"tokenreg.example.com": map[string]any{
				"auth":          base64.StdEncoding.EncodeToString([]byte("<token>:")),
				"identitytoken": "refresh-me",
			},
		},
	})
	a := &ConfigAuth{Path: path}

	tests := []struct {
		name     string
		host     string
		wantUser string
		wantPass string
		wantID   string
		wantErr  error
	}{
		{"docker hub via its api host", "registry-1.docker.io", "hubuser", "hubpass", "", nil},
		{"docker hub via docker.io", "docker.io", "hubuser", "hubpass", "", nil},
		{"explicit host", "ghcr.io", "ghuser", "ghpass", "", nil},
		{"identity token", "tokenreg.example.com", "<token>", "", "refresh-me", nil},
		{"unknown registry", "quay.io", "", "", "", ErrNoCredentials},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := a.Resolve(context.Background(), tt.host)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if creds.Username != tt.wantUser || creds.Password != tt.wantPass || creds.IdentityToken != tt.wantID {
				t.Errorf("creds = %+v, want %q/%q/%q", creds, tt.wantUser, tt.wantPass, tt.wantID)
			}
		})
	}
}

func TestConfigAuthMissingFileIsNotAnError(t *testing.T) {
	a := &ConfigAuth{Path: filepath.Join(t.TempDir(), "nope.json")}
	_, err := a.Resolve(context.Background(), "ghcr.io")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestConfigAuthMissingCredsStoreWarnsAndFallsBack(t *testing.T) {
	path := writeConfig(t, map[string]any{
		"credsStore": "desktop.exe",
		"auths": map[string]any{
			"ghcr.io": map[string]any{
				"auth": base64.StdEncoding.EncodeToString([]byte("fallback:secret")),
			},
		},
	})
	var warnings []string
	a := &ConfigAuth{
		Path:  path,
		Warnf: func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) },
	}
	// Make sure no such helper is reachable.
	t.Setenv("PATH", t.TempDir())

	creds, err := a.Resolve(context.Background(), "ghcr.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if creds.Username != "fallback" || creds.Password != "secret" {
		t.Errorf("creds = %+v, want the config.json entry", creds)
	}
	if len(warnings) == 0 {
		t.Fatal("no warning was emitted for the missing credential store")
	}
	if !strings.Contains(warnings[0], "desktop.exe") {
		t.Errorf("warning %q does not name the missing helper", warnings[0])
	}

	// The warning must be emitted once, not once per request.
	if _, err := a.Resolve(context.Background(), "ghcr.io"); err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Errorf("emitted %d warnings, want 1", len(warnings))
	}
}

func TestConfigAuthMissingCredsStoreFallsBackToAnonymous(t *testing.T) {
	path := writeConfig(t, map[string]any{"credsStore": "desktop.exe"})
	var warnings []string
	a := &ConfigAuth{
		Path:  path,
		Warnf: func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) },
	}
	t.Setenv("PATH", t.TempDir())

	_, err := a.Resolve(context.Background(), "docker.io")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials so the pull continues anonymously", err)
	}
	if len(warnings) == 0 {
		t.Error("the missing helper was not reported to the user")
	}

	// And a pull of a public image must still work.
	f := newFakeRegistry(t)
	f.RequireAuth = true
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 16)
	dgst := f.AddImage(img)
	f.Tag("library/public", "1", dgst)

	c := f.Client(Options{Auth: a})
	if _, err := c.Pull(context.Background(), f.Ref("library/public:1"), newStore(t), nil); err != nil {
		t.Fatalf("anonymous pull with a broken credsStore: %v", err)
	}
}

// installHelper writes an executable docker-credential-<name> onto PATH.
func installHelper(t *testing.T, name, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("credential helpers are shell scripts in this test")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-credential-"+name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestConfigAuthCredHelper(t *testing.T) {
	installHelper(t, "hulltest", `#!/bin/sh
read -r server
printf '{"ServerURL":"%s","Username":"helperuser","Secret":"helpersecret"}' "$server"
`)
	path := writeConfig(t, map[string]any{
		"credHelpers": map[string]any{"ghcr.io": "hulltest"},
	})
	a := &ConfigAuth{Path: path}
	creds, err := a.Resolve(context.Background(), "ghcr.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if creds.Username != "helperuser" || creds.Password != "helpersecret" {
		t.Errorf("creds = %+v", creds)
	}
}

func TestConfigAuthCredHelperIdentityToken(t *testing.T) {
	installHelper(t, "hulltoken", `#!/bin/sh
read -r server
printf '{"ServerURL":"%s","Username":"<token>","Secret":"an-identity-token"}' "$server"
`)
	path := writeConfig(t, map[string]any{"credsStore": "hulltoken"})
	a := &ConfigAuth{Path: path}
	creds, err := a.Resolve(context.Background(), "docker.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if creds.IdentityToken != "an-identity-token" || creds.Username != "" {
		t.Errorf("creds = %+v, want an identity token", creds)
	}
}

func TestConfigAuthCredHelperNotFoundFallsBack(t *testing.T) {
	installHelper(t, "hullempty", `#!/bin/sh
read -r server
echo "credentials not found in native keychain" >&2
exit 1
`)
	path := writeConfig(t, map[string]any{
		"credsStore": "hullempty",
		"auths": map[string]any{
			"quay.io": map[string]any{"auth": base64.StdEncoding.EncodeToString([]byte("q:qq"))},
		},
	})
	var warnings []string
	a := &ConfigAuth{Path: path, Warnf: func(f string, a ...any) { warnings = append(warnings, fmt.Sprintf(f, a...)) }}
	creds, err := a.Resolve(context.Background(), "quay.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if creds.Username != "q" {
		t.Errorf("creds = %+v, want the config.json fallback", creds)
	}
	if len(warnings) != 0 {
		t.Errorf("a normal 'not found' from a helper produced warnings: %v", warnings)
	}
}

func TestConfigAuthHelperServerURL(t *testing.T) {
	if got := helperServerURL("registry-1.docker.io"); got != DockerHubConfigKey {
		t.Errorf("helperServerURL(docker hub) = %q, want %q", got, DockerHubConfigKey)
	}
	if got := helperServerURL("ghcr.io"); got != "ghcr.io" {
		t.Errorf("helperServerURL(ghcr.io) = %q", got)
	}
}

func TestNewKeychainPrefersTheFirstSourceWithCredentials(t *testing.T) {
	hull := writeConfig(t, map[string]any{
		"auths": map[string]any{"ghcr.io": map[string]any{"auth": base64.StdEncoding.EncodeToString([]byte("hull:one"))}},
	})
	docker := writeConfig(t, map[string]any{
		"auths": map[string]any{
			"ghcr.io": map[string]any{"auth": base64.StdEncoding.EncodeToString([]byte("docker:two"))},
			"quay.io": map[string]any{"auth": base64.StdEncoding.EncodeToString([]byte("quay:three"))},
		},
	})
	k, ok := NewKeychain(hull, docker).(*Keychain)
	if !ok {
		t.Fatal("NewKeychain did not return a *Keychain")
	}

	creds, err := k.Resolve(context.Background(), "ghcr.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if creds.Username != "hull" {
		t.Errorf("creds = %+v, want the first file to win", creds)
	}

	creds, err = k.Resolve(context.Background(), "quay.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if creds.Username != "quay" {
		t.Errorf("creds = %+v, want the second file to supply what the first lacks", creds)
	}

	if _, err := k.Resolve(context.Background(), "example.com"); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("err = %v, want ErrNoCredentials", err)
	}
}

func TestNewKeychainWithNoPathsUsesTheDefaults(t *testing.T) {
	if NewKeychain() == nil {
		t.Fatal("NewKeychain() returned nil")
	}
	// The defaults must not panic even when the home directory has neither file.
	a := NewKeychain(filepath.Join(t.TempDir(), "a.json"), filepath.Join(t.TempDir(), "b.json"))
	req, err := http.NewRequest(http.MethodGet, "https://ghcr.io/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Authorize(context.Background(), req, "", "", ""); err != nil {
		t.Fatalf("Authorize with no credentials: %v", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Error("an Authorization header was set without credentials for a Basic challenge")
	}
}

// tokenServer is a minimal bearer-token endpoint for the unit tests below.
type tokenServer struct {
	srv       *httptest.Server
	mu        sync.Mutex
	requests  []url.Values
	methods   []string
	expiresIn int
}

func newTokenServer(t *testing.T, expiresIn int) *tokenServer {
	ts := &tokenServer{expiresIn: expiresIn}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		ts.mu.Lock()
		ts.requests = append(ts.requests, r.Form)
		ts.methods = append(ts.methods, r.Method)
		n := len(ts.requests)
		ts.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":"tok-%d","expires_in":%d}`, n, ts.expiresIn)
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func (ts *tokenServer) count() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return len(ts.requests)
}

func TestTokenSourceCachesPerScope(t *testing.T) {
	ts := newTokenServer(t, 300)
	src := newTokenSource()
	src.setHTTPClient(ts.srv.Client())

	authorize := func(scope string) string {
		req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := src.authorize(context.Background(), req, ts.srv.URL, "svc", scope, Credentials{}); err != nil {
			t.Fatalf("authorize: %v", err)
		}
		return req.Header.Get("Authorization")
	}

	first := authorize("repository:a/b:pull")
	second := authorize("repository:a/b:pull")
	if first != second {
		t.Errorf("the token was not reused: %q then %q", first, second)
	}
	if ts.count() != 1 {
		t.Errorf("the token server was hit %d times for one scope, want 1", ts.count())
	}
	other := authorize("repository:c/d:pull")
	if other == first {
		t.Error("a different scope reused the previous scope's token")
	}
	if ts.count() != 2 {
		t.Errorf("token requests = %d, want 2", ts.count())
	}
}

func TestTokenSourceRefreshesAtEightyPercentOfLifetime(t *testing.T) {
	ts := newTokenServer(t, 100)
	src := newTokenSource()
	src.setHTTPClient(ts.srv.Client())

	now := time.Now()
	src.now = func() time.Time { return now }

	authorize := func() string {
		req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := src.authorize(context.Background(), req, ts.srv.URL, "svc", "s", Credentials{}); err != nil {
			t.Fatalf("authorize: %v", err)
		}
		return req.Header.Get("Authorization")
	}

	authorize()
	if ts.count() != 1 {
		t.Fatalf("token requests = %d, want 1", ts.count())
	}
	now = now.Add(79 * time.Second)
	authorize()
	if ts.count() != 1 {
		t.Errorf("the token was refreshed at 79%% of its lifetime (requests = %d)", ts.count())
	}
	now = now.Add(2 * time.Second) // 81s of a 100s lifetime
	authorize()
	if ts.count() != 2 {
		t.Errorf("the token was not refreshed at 81%% of its lifetime (requests = %d)", ts.count())
	}
}

func TestTokenSourceUsesAccessTokenWhenTokenIsAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"oauth-token","expires_in":300}`)
	}))
	t.Cleanup(srv.Close)

	src := newTokenSource()
	src.setHTTPClient(srv.Client())
	req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.authorize(context.Background(), req, srv.URL, "svc", "s", Credentials{}); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer oauth-token" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestTokenSourceIdentityTokenUsesOAuthPost(t *testing.T) {
	ts := newTokenServer(t, 300)
	src := newTokenSource()
	src.setHTTPClient(ts.srv.Client())

	req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = src.authorize(context.Background(), req, ts.srv.URL, "svc", "repository:a/b:pull",
		Credentials{IdentityToken: "refresh-me"})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.methods[0] != http.MethodPost {
		t.Errorf("method = %s, want POST for the OAuth2 refresh flow", ts.methods[0])
	}
	form := ts.requests[0]
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "refresh-me" {
		t.Errorf("form = %v", form)
	}
	if form.Get("service") != "svc" || form.Get("scope") != "repository:a/b:pull" {
		t.Errorf("form = %v", form)
	}
}

func TestTokenSourceBasicChallengeSetsBasicAuth(t *testing.T) {
	src := newTokenSource()
	req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	// An empty realm is the plain Basic-auth case: no token server exists.
	if err := src.authorize(context.Background(), req, "", "", "", Credentials{Username: "u", Password: "p"}); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	user, pass, ok := req.BasicAuth()
	if !ok || user != "u" || pass != "p" {
		t.Errorf("BasicAuth = %q/%q/%v", user, pass, ok)
	}
}

func TestTokenSourceRegistryTokenIsUsedVerbatim(t *testing.T) {
	src := newTokenSource()
	req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.authorize(context.Background(), req, "https://unused", "s", "sc",
		Credentials{RegistryToken: "preissued"}); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer preissued" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestTokenSourceRejectedCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED","message":"bad password"}]}`)
	}))
	t.Cleanup(srv.Close)

	src := newTokenSource()
	src.setHTTPClient(srv.Client())
	req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = src.authorize(context.Background(), req, srv.URL, "svc", "s", Credentials{Username: "u", Password: "bad"})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if !strings.Contains(err.Error(), "hull login") {
		t.Errorf("error %q does not tell the user what to do", err)
	}
}

func TestTokenSourceEmptyTokenIsMalformed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"expires_in":300}`)
	}))
	t.Cleanup(srv.Close)

	src := newTokenSource()
	src.setHTTPClient(srv.Client())
	req, _ := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/", nil)
	err := src.authorize(context.Background(), req, srv.URL, "svc", "s", Credentials{})
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestClientReusesTokensAcrossRequests(t *testing.T) {
	f := newFakeRegistry(t)
	f.RequireAuth = true
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 64)
	dgst := f.AddImage(img)
	f.Tag("library/alpine", "3.20", dgst)

	c := f.Client(Options{})
	ref := f.Ref("library/alpine:3.20")
	for i := 0; i < 3; i++ {
		if _, _, err := c.Resolve(context.Background(), ref, nil); err != nil {
			t.Fatalf("Resolve %d: %v", i, err)
		}
	}
	f.mu.Lock()
	tokenRequests := len(f.TokenQueries)
	f.mu.Unlock()
	if tokenRequests != 1 {
		t.Errorf("the token server was contacted %d times for three requests in one scope, want 1", tokenRequests)
	}
	// Only the first registry request should have been answered with a 401.
	if n := f.countRequests("GET /v2/library/alpine/manifests/3.20"); n != 4 {
		t.Errorf("manifest requests = %d, want 4 (one 401 plus three authenticated)", n)
	}
}

func TestStaticAuthImplementsAuthenticator(t *testing.T) {
	var _ Authenticator = &StaticAuth{}
	var _ Authenticator = &ConfigAuth{}
	var _ Authenticator = &Keychain{}
	var _ HTTPClientSetter = &StaticAuth{}
	var _ HTTPClientSetter = &ConfigAuth{}
	var _ HTTPClientSetter = &Keychain{}
	if NewStaticAuth("u", "p").Username != "u" {
		t.Error("NewStaticAuth did not keep the username")
	}
	if NewConfigAuth("/x").Path != "/x" {
		t.Error("NewConfigAuth did not keep the path")
	}
}

func TestDefaultConfigPaths(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", filepath.Join("some", "dir"))
	if got, want := DefaultDockerConfigPath(), filepath.Join("some", "dir", "config.json"); got != want {
		t.Errorf("DefaultDockerConfigPath() = %q, want %q", got, want)
	}
	t.Setenv("DOCKER_CONFIG", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory in this environment")
	}
	if got, want := DefaultHullConfigPath(), filepath.Join(home, ".hull", "config.json"); got != want {
		t.Errorf("DefaultHullConfigPath() = %q, want %q", got, want)
	}
}

func TestCredentialsIsEmpty(t *testing.T) {
	tests := []struct {
		name  string
		creds Credentials
		want  bool
	}{
		{"zero", Credentials{}, true},
		{"username only", Credentials{Username: "u"}, false},
		{"password only", Credentials{Password: "p"}, false},
		{"identity token", Credentials{IdentityToken: "t"}, false},
		{"registry token", Credentials{RegistryToken: "t"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.creds.IsEmpty(); got != tt.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}
