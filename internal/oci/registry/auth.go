package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Authenticator decides what Authorization header a registry request carries.
//
// Authorize is called with the parameters of the WWW-Authenticate challenge the
// registry answered with — realm, service and scope, any of which may be empty
// — and must set (or deliberately leave unset) req.Header["Authorization"].
// It is called once before the request is retried, and may be called
// concurrently from several goroutines, so implementations must be safe for
// concurrent use.
//
// A Bearer challenge (realm non-empty) means the token dance: exchange
// credentials at realm for a short-lived token. An empty realm means the
// registry asked for plain HTTP Basic.
type Authenticator interface {
	Authorize(ctx context.Context, req *http.Request, realm, service, scope string) error
}

// HTTPClientSetter is implemented by Authenticators that make their own HTTP
// requests — the token dance — and are willing to share the registry Client's
// transport. NewClient calls SetHTTPClient on an Authenticator that implements
// it so that Options.Insecure and any custom transport also apply to token
// requests.
type HTTPClientSetter interface {
	SetHTTPClient(*http.Client)
}

// Credentials are the secrets for one registry.
//
// Either Username plus Password (the classic form), or IdentityToken alone (an
// OAuth2 refresh token, which is what `docker login` stores for Docker Hub when
// it uses an identity token), or RegistryToken alone (a pre-issued bearer token
// used verbatim).
type Credentials struct {
	// Username is the account name, used for HTTP Basic and as the token
	// server's "account" parameter.
	Username string
	// Password is the password or personal access token.
	Password string
	// IdentityToken is an OAuth2 refresh token exchanged at the token server.
	IdentityToken string
	// RegistryToken is a bearer token to send verbatim, skipping the dance.
	RegistryToken string
}

// IsEmpty reports whether no credential material is present, i.e. the request
// must go out anonymously.
func (c Credentials) IsEmpty() bool {
	return c.Username == "" && c.Password == "" && c.IdentityToken == "" && c.RegistryToken == ""
}

// tokenResponse is the JSON body of a token-server reply. Docker's original
// endpoint returns "token"; the OAuth2 endpoint returns "access_token". Both
// are accepted, as the distribution spec requires.
type tokenResponse struct {
	Token        string    `json:"token"`
	AccessToken  string    `json:"access_token"`
	ExpiresIn    int       `json:"expires_in"`
	IssuedAt     time.Time `json:"issued_at"`
	RefreshToken string    `json:"refresh_token"`
}

func (t tokenResponse) value() string {
	if t.Token != "" {
		return t.Token
	}
	return t.AccessToken
}

// DefaultTokenLifetime is the lifetime assumed when a token server does not
// send expires_in, as the distribution spec prescribes.
const DefaultTokenLifetime = 60 * time.Second

// tokenRefreshFraction is the fraction of a token's lifetime after which the
// cache treats it as stale, so a long pull never fails on an expiring token.
const tokenRefreshFraction = 0.8

// maxTokenBody caps how much of a token-server reply is read, so a hostile or
// broken auth endpoint cannot make the daemon allocate without bound.
const maxTokenBody = 1 << 20

// cachedToken is one token plus the instant it should be refreshed.
type cachedToken struct {
	token   string
	refresh time.Time
}

// tokenSource performs and caches the Bearer token dance.
//
// Tokens are cached under (realm, service, scope), which is effectively
// (registry, scope) because a registry has exactly one realm and service.
type tokenSource struct {
	mu     sync.Mutex
	client *http.Client
	tokens map[string]cachedToken
	// now is overridable in tests.
	now func() time.Time
}

func newTokenSource() *tokenSource {
	return &tokenSource{tokens: map[string]cachedToken{}, now: time.Now}
}

func (t *tokenSource) setHTTPClient(hc *http.Client) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.client = hc
}

func (t *tokenSource) httpClient() *http.Client {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client == nil {
		t.client = &http.Client{Timeout: 30 * time.Second}
	}
	return t.client
}

func (t *tokenSource) clock() time.Time {
	if t.now == nil {
		return time.Now()
	}
	return t.now()
}

func (t *tokenSource) lookup(key string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ct, ok := t.tokens[key]
	if !ok {
		return "", false
	}
	if !t.clock().Before(ct.refresh) {
		delete(t.tokens, key)
		return "", false
	}
	return ct.token, true
}

func (t *tokenSource) store(key, token string, lifetime time.Duration) {
	if lifetime <= 0 {
		lifetime = DefaultTokenLifetime
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tokens[key] = cachedToken{
		token:   token,
		refresh: t.clock().Add(time.Duration(float64(lifetime) * tokenRefreshFraction)),
	}
}

// authorize applies credentials to req for the given challenge, doing and
// caching the token dance when the challenge is a Bearer one.
func (t *tokenSource) authorize(ctx context.Context, req *http.Request, realm, service, scope string, creds Credentials) error {
	if creds.RegistryToken != "" {
		req.Header.Set("Authorization", "Bearer "+creds.RegistryToken)
		return nil
	}
	if realm == "" {
		// Plain Basic-auth registry: no token server to talk to.
		if creds.Username != "" || creds.Password != "" {
			req.SetBasicAuth(creds.Username, creds.Password)
		}
		return nil
	}

	key := realm + "\x00" + service + "\x00" + scope
	if creds.Username != "" {
		key += "\x00" + creds.Username
	}
	if tok, ok := t.lookup(key); ok {
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil
	}

	tok, lifetime, err := t.fetch(ctx, realm, service, scope, creds)
	if err != nil {
		return err
	}
	t.store(key, tok, lifetime)
	req.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

// fetch performs one token request against realm.
func (t *tokenSource) fetch(ctx context.Context, realm, service, scope string, creds Credentials) (string, time.Duration, error) {
	u, err := url.Parse(realm)
	if err != nil {
		return "", 0, fmt.Errorf("registry: auth realm %q is not a URL: %w", realm, err)
	}

	var req *http.Request
	if creds.IdentityToken != "" {
		form := url.Values{}
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", creds.IdentityToken)
		form.Set("client_id", "hull")
		if service != "" {
			form.Set("service", service)
		}
		for _, s := range strings.Fields(scope) {
			form.Add("scope", s)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
		if err != nil {
			return "", 0, fmt.Errorf("registry: building token request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		q := u.Query()
		if service != "" {
			q.Set("service", service)
		}
		q.Del("scope")
		for _, s := range strings.Fields(scope) {
			q.Add("scope", s)
		}
		if creds.Username != "" {
			q.Set("account", creds.Username)
		}
		u.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", 0, fmt.Errorf("registry: building token request: %w", err)
		}
		if creds.Username != "" || creds.Password != "" {
			req.SetBasicAuth(creds.Username, creds.Password)
		}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := t.httpClient().Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("registry: requesting auth token from %s: %w", realm, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		hint := ""
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			if creds.IsEmpty() {
				hint = "; this repository needs credentials — run 'hull login'"
			} else {
				hint = "; the stored credentials were rejected — run 'hull login' again"
			}
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		msg := strings.TrimSpace(string(body))
		if len(msg) > 512 {
			msg = msg[:512]
		}
		err := fmt.Errorf("registry: auth token request to %s failed: %s%s: %s", realm, resp.Status, hint, msg)
		if resp.StatusCode == http.StatusUnauthorized {
			return "", 0, fmt.Errorf("%w: %w", ErrUnauthorized, err)
		}
		if resp.StatusCode == http.StatusForbidden {
			return "", 0, fmt.Errorf("%w: %w", ErrDenied, err)
		}
		return "", 0, err
	}

	var tr tokenResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxTokenBody))
	if err := dec.Decode(&tr); err != nil {
		return "", 0, fmt.Errorf("registry: decoding auth token from %s: %w", realm, err)
	}
	tok := tr.value()
	if tok == "" {
		return "", 0, fmt.Errorf("registry: auth token response from %s carried neither \"token\" nor \"access_token\": %w", realm, ErrMalformed)
	}
	lifetime := DefaultTokenLifetime
	if tr.ExpiresIn > 0 {
		lifetime = time.Duration(tr.ExpiresIn) * time.Second
	}
	return tok, lifetime, nil
}

// ---------- StaticAuth ----------

// StaticAuth authenticates every registry with one fixed username and password.
// Use it via a pointer: (&StaticAuth{Username: u, Password: p}).
//
// It performs and caches the Bearer token dance, and falls back to HTTP Basic
// when a registry issues a Basic challenge.
type StaticAuth struct {
	// Username is the account name. It may be empty for token-only registries.
	Username string
	// Password is the password or personal access token.
	Password string

	once sync.Once
	ts   *tokenSource
}

// NewStaticAuth returns a StaticAuth for the given credentials. Passing two
// empty strings yields an authenticator that still performs the anonymous token
// dance, which Docker Hub requires even for public images.
func NewStaticAuth(username, password string) *StaticAuth {
	return &StaticAuth{Username: username, Password: password}
}

func (a *StaticAuth) source() *tokenSource {
	a.once.Do(func() {
		if a.ts == nil {
			a.ts = newTokenSource()
		}
	})
	return a.ts
}

// SetHTTPClient makes the token dance use hc. It implements HTTPClientSetter.
func (a *StaticAuth) SetHTTPClient(hc *http.Client) { a.source().setHTTPClient(hc) }

// Authorize implements Authenticator.
func (a *StaticAuth) Authorize(ctx context.Context, req *http.Request, realm, service, scope string) error {
	return a.source().authorize(ctx, req, realm, service, scope, Credentials{
		Username: a.Username,
		Password: a.Password,
	})
}

// ---------- docker config.json ----------

// dockerConfig is the subset of ~/.docker/config.json hull reads.
type dockerConfig struct {
	Auths       map[string]dockerAuthEntry `json:"auths"`
	CredsStore  string                     `json:"credsStore"`
	CredHelpers map[string]string          `json:"credHelpers"`
}

// dockerAuthEntry is one entry of the "auths" map.
type dockerAuthEntry struct {
	Auth          string `json:"auth"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identitytoken"`
	RegistryToken string `json:"registrytoken"`
}

// hubHosts are all the spellings of Docker Hub that appear as registry domains
// or as config.json keys.
var hubHosts = map[string]bool{
	"docker.io":               true,
	"index.docker.io":         true,
	"registry-1.docker.io":    true,
	"registry.hub.docker.com": true,
}

// IsDockerHub reports whether host is any spelling of Docker Hub.
func IsDockerHub(host string) bool {
	return hubHosts[strings.ToLower(strings.TrimSuffix(host, "/"))]
}

// DockerHubConfigKey is the key `docker login` writes into config.json for
// Docker Hub, and the server URL its credential helpers expect.
const DockerHubConfigKey = "https://index.docker.io/v1/"

// normalizeAuthKey reduces a config.json auths/credHelpers key, or a registry
// domain, to a bare comparable host. Scheme and path are stripped and every
// spelling of Docker Hub collapses to docker.io.
func normalizeAuthKey(key string) string {
	k := strings.TrimSpace(key)
	if k == "" {
		return ""
	}
	if i := strings.Index(k, "://"); i >= 0 {
		k = k[i+3:]
	}
	if i := strings.IndexByte(k, '/'); i >= 0 {
		k = k[:i]
	}
	k = strings.ToLower(k)
	if hubHosts[k] {
		return "docker.io"
	}
	return k
}

// helperServerURL is the string handed to a credential helper on stdin.
func helperServerURL(host string) string {
	if IsDockerHub(host) {
		return DockerHubConfigKey
	}
	return host
}

// ErrNoCredentials means no credential source had anything for a registry, so
// the request must proceed anonymously. It is not usually fatal.
var ErrNoCredentials = errors.New("registry: no credentials for this registry")

// ConfigAuth reads credentials from a Docker-style config.json.
//
// It understands the "auths" map (base64 "user:pass" plus "identitytoken"),
// the "credsStore" credential helper and the per-registry "credHelpers" map.
// For a helper it executes "docker-credential-<name>" with "get" on stdin and
// parses {"Username","Secret"} from its output.
//
// Docker Desktop on WSL writes credsStore "desktop.exe", whose binary is not on
// PATH inside a plain WSL distro. When the helper binary is missing ConfigAuth
// warns once and falls back to the auths map and then to anonymous access,
// rather than failing a pull of a public image.
type ConfigAuth struct {
	// Path is the config.json to read. Empty means the Docker default:
	// $DOCKER_CONFIG/config.json, else ~/.docker/config.json.
	Path string

	// Warnf receives non-fatal warnings, such as a missing credential helper.
	// Nil means write to standard error.
	Warnf func(format string, args ...any)

	once sync.Once
	ts   *tokenSource

	mu      sync.Mutex
	loaded  bool
	cfg     dockerConfig
	loadErr error
	warned  map[string]bool
}

// NewConfigAuth returns a ConfigAuth reading path. An empty path selects the
// Docker default location.
func NewConfigAuth(path string) *ConfigAuth { return &ConfigAuth{Path: path} }

func (a *ConfigAuth) source() *tokenSource {
	a.once.Do(func() {
		if a.ts == nil {
			a.ts = newTokenSource()
		}
	})
	return a.ts
}

// SetHTTPClient makes the token dance use hc. It implements HTTPClientSetter.
func (a *ConfigAuth) SetHTTPClient(hc *http.Client) { a.source().setHTTPClient(hc) }

func (a *ConfigAuth) warn(format string, args ...any) {
	if a.Warnf != nil {
		a.Warnf(format, args...)
		return
	}
	fmt.Fprintf(os.Stderr, "hull: warning: "+format+"\n", args...)
}

// warnOnce emits a warning at most once per key for the life of the ConfigAuth.
func (a *ConfigAuth) warnOnce(key, format string, args ...any) {
	a.mu.Lock()
	if a.warned == nil {
		a.warned = map[string]bool{}
	}
	if a.warned[key] {
		a.mu.Unlock()
		return
	}
	a.warned[key] = true
	a.mu.Unlock()
	a.warn(format, args...)
}

// DefaultDockerConfigPath returns the config.json path Docker would use:
// $DOCKER_CONFIG/config.json if set, else ~/.docker/config.json.
func DefaultDockerConfigPath() string {
	if dir := os.Getenv("DOCKER_CONFIG"); dir != "" {
		return filepath.Join(dir, "config.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".docker", "config.json")
}

// DefaultHullConfigPath returns ~/.hull/config.json, hull's own credential file.
func DefaultHullConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".hull", "config.json")
}

// load reads and caches the config file. A missing file is not an error: it
// simply means no credentials.
func (a *ConfigAuth) load() (dockerConfig, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loaded {
		return a.cfg, a.loadErr
	}
	a.loaded = true

	path := a.Path
	if path == "" {
		path = DefaultDockerConfigPath()
	}
	if path == "" {
		return a.cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return a.cfg, nil
		}
		a.loadErr = fmt.Errorf("registry: reading %s: %w", path, err)
		return a.cfg, a.loadErr
	}
	if err := json.Unmarshal(b, &a.cfg); err != nil {
		a.loadErr = fmt.Errorf("registry: parsing %s: %w", path, err)
		return a.cfg, a.loadErr
	}
	return a.cfg, nil
}

// Resolve returns the credentials configured for a registry host, or an error
// wrapping ErrNoCredentials when there are none.
func (a *ConfigAuth) Resolve(ctx context.Context, host string) (Credentials, error) {
	cfg, err := a.load()
	if err != nil {
		return Credentials{}, err
	}
	want := normalizeAuthKey(host)

	// A per-registry helper wins over the global store.
	if name := matchKey(cfg.CredHelpers, want); name != "" {
		creds, err := a.runHelper(ctx, name, host)
		if err == nil {
			return creds, nil
		}
		if !errors.Is(err, ErrNoCredentials) {
			a.warnOnce("helper:"+name, "credential helper %q failed for %s: %v; continuing without credentials", name, host, err)
		}
	}
	if cfg.CredsStore != "" {
		creds, err := a.runHelper(ctx, cfg.CredsStore, host)
		if err == nil {
			return creds, nil
		}
		if !errors.Is(err, ErrNoCredentials) {
			a.warnOnce("store:"+cfg.CredsStore,
				"credential store %q is not usable (%v); falling back to config.json and then anonymous access",
				cfg.CredsStore, err)
		}
	}

	for key, entry := range cfg.Auths {
		if normalizeAuthKey(key) != want {
			continue
		}
		creds := Credentials{
			Username:      entry.Username,
			Password:      entry.Password,
			IdentityToken: entry.IdentityToken,
			RegistryToken: entry.RegistryToken,
		}
		if entry.Auth != "" {
			user, pass, err := decodeAuth(entry.Auth)
			if err != nil {
				return Credentials{}, fmt.Errorf("registry: auth entry for %q: %w", key, err)
			}
			if user != "" {
				creds.Username = user
			}
			if pass != "" {
				creds.Password = pass
			}
		}
		if creds.IsEmpty() {
			continue
		}
		return creds, nil
	}
	return Credentials{}, fmt.Errorf("%w: %s", ErrNoCredentials, host)
}

// matchKey finds the map key whose normalised form equals want.
func matchKey(m map[string]string, want string) string {
	for k, v := range m {
		if normalizeAuthKey(k) == want {
			return v
		}
	}
	return ""
}

// decodeAuth splits a base64 "user:password" auth entry.
func decodeAuth(enc string) (string, string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(strings.TrimSpace(enc))
		if err != nil {
			return "", "", fmt.Errorf("auth field is not valid base64: %w", err)
		}
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return "", "", errors.New("auth field does not decode to user:password")
	}
	return user, pass, nil
}

// helperOutput is the JSON a docker credential helper writes on "get".
type helperOutput struct {
	ServerURL string `json:"ServerURL"`
	Username  string `json:"Username"`
	Secret    string `json:"Secret"`
}

// identityTokenUsername is the sentinel username a credential helper returns
// when Secret is an OAuth2 identity token rather than a password.
const identityTokenUsername = "<token>"

// helperTimeout bounds a credential helper execution; desktop.exe in particular
// can hang when Docker Desktop is not running.
const helperTimeout = 15 * time.Second

// runHelper executes docker-credential-<name> get for host.
func (a *ConfigAuth) runHelper(ctx context.Context, name, host string) (Credentials, error) {
	bin := "docker-credential-" + name
	path, err := exec.LookPath(bin)
	if err != nil {
		return Credentials{}, fmt.Errorf("credential helper %q is not on PATH: %w", bin, err)
	}

	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "get")
	cmd.Stdin = strings.NewReader(helperServerURL(host))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if isCredentialsNotFound(msg) || isCredentialsNotFound(string(out)) {
			return Credentials{}, fmt.Errorf("%w: %s", ErrNoCredentials, host)
		}
		if msg != "" {
			return Credentials{}, fmt.Errorf("%s get: %w: %s", bin, err, msg)
		}
		return Credentials{}, fmt.Errorf("%s get: %w", bin, err)
	}

	var ho helperOutput
	if err := json.Unmarshal(out, &ho); err != nil {
		return Credentials{}, fmt.Errorf("%s get: parsing output: %w", bin, err)
	}
	if ho.Username == identityTokenUsername {
		if ho.Secret == "" {
			return Credentials{}, fmt.Errorf("%w: %s", ErrNoCredentials, host)
		}
		return Credentials{IdentityToken: ho.Secret}, nil
	}
	if ho.Username == "" && ho.Secret == "" {
		return Credentials{}, fmt.Errorf("%w: %s", ErrNoCredentials, host)
	}
	return Credentials{Username: ho.Username, Password: ho.Secret}, nil
}

// isCredentialsNotFound recognises the "not found" message every docker
// credential helper prints, which is a normal outcome rather than a failure.
func isCredentialsNotFound(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "credentials not found") ||
		strings.Contains(l, "no credentials") ||
		strings.Contains(l, "not found in native keychain")
}

// Authorize implements Authenticator.
func (a *ConfigAuth) Authorize(ctx context.Context, req *http.Request, realm, service, scope string) error {
	creds, err := a.Resolve(ctx, req.URL.Hostname())
	if err != nil && !errors.Is(err, ErrNoCredentials) {
		// A broken config must not stop a public pull.
		a.warnOnce("resolve:"+req.URL.Hostname(), "%v; continuing anonymously", err)
		creds = Credentials{}
	}
	return a.source().authorize(ctx, req, realm, service, scope, creds)
}

// ---------- keychain ----------

// Keychain tries several credential files in order and uses the first that has
// credentials for the registry being contacted. When none does, it still
// performs the anonymous token dance, which Docker Hub requires even for
// public images.
type Keychain struct {
	sources []*ConfigAuth
	once    sync.Once
	ts      *tokenSource
}

// NewKeychain returns an Authenticator that reads the given config.json paths
// in order. With no arguments it tries ~/.hull/config.json and then
// ~/.docker/config.json. Paths that do not exist are skipped silently.
func NewKeychain(paths ...string) Authenticator {
	if len(paths) == 0 {
		paths = []string{DefaultHullConfigPath(), DefaultDockerConfigPath()}
	}
	k := &Keychain{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		k.sources = append(k.sources, &ConfigAuth{Path: p})
	}
	return k
}

func (k *Keychain) source() *tokenSource {
	k.once.Do(func() {
		if k.ts == nil {
			k.ts = newTokenSource()
		}
	})
	return k.ts
}

// SetHTTPClient makes the token dance, and every underlying config source, use
// hc. It implements HTTPClientSetter.
func (k *Keychain) SetHTTPClient(hc *http.Client) {
	k.source().setHTTPClient(hc)
	for _, s := range k.sources {
		s.SetHTTPClient(hc)
	}
}

// Resolve returns the first credentials any source has for host, or an error
// wrapping ErrNoCredentials.
func (k *Keychain) Resolve(ctx context.Context, host string) (Credentials, error) {
	for _, s := range k.sources {
		creds, err := s.Resolve(ctx, host)
		if err == nil && !creds.IsEmpty() {
			return creds, nil
		}
	}
	return Credentials{}, fmt.Errorf("%w: %s", ErrNoCredentials, host)
}

// Authorize implements Authenticator.
func (k *Keychain) Authorize(ctx context.Context, req *http.Request, realm, service, scope string) error {
	creds, err := k.Resolve(ctx, req.URL.Hostname())
	if err != nil && !errors.Is(err, ErrNoCredentials) {
		return err
	}
	return k.source().authorize(ctx, req, realm, service, scope, creds)
}
