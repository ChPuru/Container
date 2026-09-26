package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ChPuru/hull/internal/content"
	"github.com/ChPuru/hull/internal/oci/imagespec"
	"github.com/ChPuru/hull/internal/oci/reference"
	"github.com/ChPuru/hull/internal/types"
)

// ---------- image fixtures ----------

// imageFixture is a complete, self-consistent single-platform image.
type imageFixture struct {
	Platform     types.Platform
	ConfigJSON   []byte
	ConfigDesc   types.Descriptor
	LayerData    [][]byte
	Layers       []types.Descriptor
	ManifestJSON []byte
	ManifestDesc types.Descriptor
	DiffIDs      []string
}

// buildImage constructs an image with one layer per entry of sizes. Layer
// bodies are deterministic, so a digest mismatch in a test is always a bug in
// the client rather than in the fixture.
func buildImage(t *testing.T, plat types.Platform, mediaType string, sizes ...int) imageFixture {
	t.Helper()
	if len(sizes) == 0 {
		sizes = []int{64, 128}
	}
	f := imageFixture{Platform: plat}

	layerMT := imagespec.MediaTypeImageLayerGzip
	configMT := imagespec.MediaTypeImageConfig
	if mediaType == imagespec.MediaTypeDockerManifest {
		layerMT = imagespec.MediaTypeDockerLayerGzip
		configMT = imagespec.MediaTypeDockerConfig
	}

	for i, n := range sizes {
		body := make([]byte, n)
		for j := range body {
			body[j] = byte((i*31 + j*7) % 251)
		}
		f.LayerData = append(f.LayerData, body)
		f.Layers = append(f.Layers, types.Descriptor{
			MediaType: layerMT,
			Digest:    content.DigestBytes(body),
			Size:      int64(len(body)),
		})
		// The diff ID of a fixture layer is just a distinct digest; nothing in
		// this package decompresses layers, so it only has to be well formed.
		f.DiffIDs = append(f.DiffIDs, content.DigestBytes(append([]byte("diff"), body...)))
	}

	created := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	cfg := imagespec.ImageConfig{
		Created:      &created,
		Architecture: plat.Architecture,
		OS:           plat.OS,
		Variant:      plat.Variant,
		Config: imagespec.ConfigBlock{
			Env:        []string{"PATH=/usr/bin"},
			Entrypoint: []string{"/bin/sh"},
			Cmd:        []string{"-c", "true"},
			Labels:     map[string]string{"org.opencontainers.image.title": "fixture"},
		},
		RootFS: imagespec.RootFS{Type: imagespec.RootFSTypeLayers, DiffIDs: f.DiffIDs},
	}
	var err error
	f.ConfigJSON, err = json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	f.ConfigDesc = types.Descriptor{
		MediaType: configMT,
		Digest:    content.DigestBytes(f.ConfigJSON),
		Size:      int64(len(f.ConfigJSON)),
	}

	manifestMT := mediaType
	if manifestMT == "" {
		manifestMT = imagespec.MediaTypeImageManifest
	}
	m := imagespec.Manifest{
		SchemaVersion: imagespec.SchemaVersion,
		MediaType:     manifestMT,
		Config:        f.ConfigDesc,
		Layers:        f.Layers,
	}
	f.ManifestJSON, err = json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	f.ManifestDesc = types.Descriptor{
		MediaType: manifestMT,
		Digest:    content.DigestBytes(f.ManifestJSON),
		Size:      int64(len(f.ManifestJSON)),
		Platform:  &f.Platform,
	}
	return f
}

// buildIndex assembles an image index over the given manifest descriptors and
// appends a buildx-style attestation entry, which a correct client must skip.
func buildIndex(t *testing.T, mediaType string, descs ...types.Descriptor) (types.Descriptor, []byte) {
	t.Helper()
	if mediaType == "" {
		mediaType = imagespec.MediaTypeImageIndex
	}
	entryMT := imagespec.MediaTypeImageManifest
	if mediaType == imagespec.MediaTypeDockerManifestList {
		entryMT = imagespec.MediaTypeDockerManifest
	}
	idx := imagespec.Index{SchemaVersion: imagespec.SchemaVersion, MediaType: mediaType}
	for _, d := range descs {
		if d.MediaType == "" {
			d.MediaType = entryMT
		}
		idx.Manifests = append(idx.Manifests, d)
	}
	idx.Manifests = append(idx.Manifests, types.Descriptor{
		MediaType:   entryMT,
		Digest:      content.DigestBytes([]byte("attestation")),
		Size:        11,
		Platform:    &types.Platform{OS: unknownPlatform, Architecture: unknownPlatform},
		Annotations: map[string]string{attestationRefTypeAnnotation: "attestation-manifest"},
	})
	body, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	return types.Descriptor{
		MediaType: mediaType,
		Digest:    content.DigestBytes(body),
		Size:      int64(len(body)),
	}, body
}

// ---------- in-process registry ----------

type storedManifest struct {
	mediaType string
	body      []byte
	// sendDigest, when non-empty, overrides the Docker-Content-Digest header,
	// which is how the digest-mismatch test lies to the client.
	sendDigest string
}

// fakeRegistry is an in-process OCI distribution registry with enough
// behaviour to exercise every path of the client: the token dance, a blob CDN
// on a different host, Range resumption, rate limits and transient failures.
type fakeRegistry struct {
	t *testing.T

	Server *httptest.Server
	CDN    *httptest.Server
	Token  *httptest.Server

	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string]storedManifest
	tags      map[string]string
	uploads   map[string][]byte
	nextID    int

	// Behaviour switches, set before the client runs.
	RequireAuth    bool
	Username       string
	Password       string
	RedirectBlobs  bool
	BreakBlobAt    map[string]int
	FailNTimes     map[string]int
	Send429        int
	RetryAfter     string
	RateLimitLimit string
	RateLimitLeft  string
	ContentTypeFor map[string]string
	DeleteDenied   bool
	TagPageSize    int
	BlobDelay      time.Duration

	// Concurrency observation.
	inFlight    int
	MaxInFlight int

	// Observations.
	Requests       []string
	CDNAuthHeaders []string
	TokenQueries   []url.Values
	TokenAuths     []string
	BlobRanges     []string
	ManifestAccept []string
	PutManifests   map[string][]byte
	PutBlobs       map[string][]byte
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{
		t:              t,
		blobs:          map[string][]byte{},
		manifests:      map[string]storedManifest{},
		tags:           map[string]string{},
		uploads:        map[string][]byte{},
		BreakBlobAt:    map[string]int{},
		FailNTimes:     map[string]int{},
		ContentTypeFor: map[string]string{},
		PutManifests:   map[string][]byte{},
		PutBlobs:       map[string][]byte{},
	}
	f.Token = httptest.NewServer(http.HandlerFunc(f.serveToken))
	f.CDN = httptest.NewServer(http.HandlerFunc(f.serveCDN))
	f.Server = httptest.NewServer(http.HandlerFunc(f.serveRegistry))
	t.Cleanup(func() {
		f.Server.Close()
		f.CDN.Close()
		f.Token.Close()
	})
	return f
}

// Host is the registry's host:port, usable as a reference domain.
func (f *fakeRegistry) Host() string { return strings.TrimPrefix(f.Server.URL, "http://") }

// Ref parses a reference against this registry.
func (f *fakeRegistry) Ref(name string) reference.Reference {
	f.t.Helper()
	ref, err := reference.Parse(f.Host() + "/" + name)
	if err != nil {
		f.t.Fatalf("parse reference: %v", err)
	}
	return ref
}

// Client returns a client wired to this registry with fast retries.
func (f *fakeRegistry) Client(opts Options) *Client {
	opts.Insecure = true
	if opts.Auth == nil {
		opts.Auth = &StaticAuth{Username: f.Username, Password: f.Password}
	}
	c := NewClient(opts)
	c.baseBackoff = time.Millisecond
	return c
}

func (f *fakeRegistry) AddBlob(b []byte) string {
	dgst := content.DigestBytes(b)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blobs[dgst] = b
	return dgst
}

// PutBlobAt stores bytes under a digest they do not actually hash to, so a
// test can check that the client catches corrupted content.
func (f *fakeRegistry) PutBlobAt(digest string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blobs[digest] = body
}

func (f *fakeRegistry) AddManifest(mediaType string, body []byte) string {
	dgst := content.DigestBytes(body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.manifests[dgst] = storedManifest{mediaType: mediaType, body: body}
	return dgst
}

func (f *fakeRegistry) AddRawManifest(mediaType string, body []byte, sendDigest string) string {
	dgst := content.DigestBytes(body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.manifests[dgst] = storedManifest{mediaType: mediaType, body: body, sendDigest: sendDigest}
	return dgst
}

// PutManifestAt stores a manifest under an arbitrary key, which is how the
// tests make the registry lie about what a digest resolves to.
func (f *fakeRegistry) PutManifestAt(key, mediaType string, body []byte, sendDigest string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.manifests[key] = storedManifest{mediaType: mediaType, body: body, sendDigest: sendDigest}
}

func (f *fakeRegistry) Tag(repo, tag, digest string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tags[repo+":"+tag] = digest
}

// AddImage registers every blob and the manifest of a fixture.
func (f *fakeRegistry) AddImage(img imageFixture) string {
	for _, b := range img.LayerData {
		f.AddBlob(b)
	}
	f.AddBlob(img.ConfigJSON)
	return f.AddManifest(img.ManifestDesc.MediaType, img.ManifestJSON)
}

func (f *fakeRegistry) record(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Requests = append(f.Requests, fmt.Sprintf(format, args...))
}

// countRequests returns how many recorded requests contain substr.
func (f *fakeRegistry) countRequests(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.Requests {
		if strings.Contains(r, substr) {
			n++
		}
	}
	return n
}

// ---------- token server ----------

func (f *fakeRegistry) serveToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.TokenQueries = append(f.TokenQueries, r.Form)
	f.TokenAuths = append(f.TokenAuths, r.Header.Get("Authorization"))
	user, pass := f.Username, f.Password
	f.mu.Unlock()

	if user != "" {
		gotUser, gotPass, ok := r.BasicAuth()
		if !ok || gotUser != user || gotPass != pass {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED","message":"bad credentials"}]}`)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token":%q,"expires_in":300,"issued_at":%q}`,
		"tok-"+strconv.Itoa(len(r.Form["scope"])), time.Now().UTC().Format(time.RFC3339))
}

// ---------- CDN ----------

func (f *fakeRegistry) serveCDN(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.CDNAuthHeaders = append(f.CDNAuthHeaders, r.Header.Get("Authorization"))
	f.mu.Unlock()
	f.record("CDN %s %s", r.Method, r.URL.Path)

	dgst := content.Algorithm + ":" + strings.TrimPrefix(r.URL.Path, "/blob/")
	f.mu.Lock()
	body, ok := f.blobs[dgst]
	f.mu.Unlock()
	if !ok {
		http.Error(w, "no such blob", http.StatusNotFound)
		return
	}
	f.writeBlob(w, r, dgst, body)
}

// ---------- registry ----------

func (f *fakeRegistry) authorized(w http.ResponseWriter, r *http.Request) bool {
	if !f.RequireAuth {
		return true
	}
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok-") {
		return true
	}
	scope := ""
	if name, kind, _, ok := parseV2Path(r.URL.Path); ok && kind != "" {
		scope = "repository:" + name + ":pull"
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			scope = "repository:" + name + ":pull,push"
		}
	}
	ch := fmt.Sprintf(`Bearer realm="%s/token",service="fake-registry"`, f.Token.URL)
	if scope != "" {
		ch += fmt.Sprintf(`,scope=%q`, scope)
	}
	w.Header().Set("WWW-Authenticate", ch)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`)
	return false
}

func (f *fakeRegistry) serveRegistry(w http.ResponseWriter, r *http.Request) {
	f.record("%s %s", r.Method, r.URL.RequestURI())
	f.setRateLimitHeaders(w)

	f.mu.Lock()
	if f.Send429 > 0 {
		f.Send429--
		f.mu.Unlock()
		if f.RetryAfter != "" {
			w.Header().Set("Retry-After", f.RetryAfter)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"errors":[{"code":"TOOMANYREQUESTS","message":"too many requests"}]}`)
		return
	}
	if n := f.FailNTimes[r.URL.Path]; n > 0 {
		f.FailNTimes[r.URL.Path] = n - 1
		f.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	f.mu.Unlock()

	if !f.authorized(w, r) {
		return
	}

	if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path == "/v2/_catalog" {
		f.serveCatalog(w, r)
		return
	}

	name, kind, rest, ok := parseV2Path(r.URL.Path)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	switch kind {
	case "manifests":
		f.serveManifests(w, r, name, rest)
	case "blobs":
		f.serveBlobs(w, r, name, rest)
	case "tags":
		f.serveTags(w, r, name)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (f *fakeRegistry) setRateLimitHeaders(w http.ResponseWriter) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.RateLimitLimit != "" {
		w.Header().Set("RateLimit-Limit", f.RateLimitLimit)
	}
	if f.RateLimitLeft != "" {
		w.Header().Set("RateLimit-Remaining", f.RateLimitLeft)
	}
}

// parseV2Path splits /v2/<name>/<kind>/<rest> keeping slashes inside <name>.
func parseV2Path(p string) (name, kind, rest string, ok bool) {
	if !strings.HasPrefix(p, "/v2/") {
		return "", "", "", false
	}
	p = strings.TrimPrefix(p, "/v2/")
	for _, k := range []string{"manifests", "blobs", "tags"} {
		marker := "/" + k + "/"
		if i := strings.LastIndex(p, marker); i >= 0 {
			return p[:i], k, p[i+len(marker):], true
		}
		if strings.HasSuffix(p, "/"+k) {
			return strings.TrimSuffix(p, "/"+k), k, "", true
		}
	}
	return p, "", "", true
}

func (f *fakeRegistry) serveManifests(w http.ResponseWriter, r *http.Request, name, ref string) {
	if r.Method == http.MethodPut {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		dgst := content.DigestBytes(body)
		f.mu.Lock()
		f.manifests[dgst] = storedManifest{mediaType: r.Header.Get("Content-Type"), body: body}
		if !strings.HasPrefix(ref, content.Algorithm+":") {
			f.tags[name+":"+ref] = dgst
		}
		f.PutManifests[name+":"+ref] = body
		f.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", dgst)
		w.Header().Set("Location", "/v2/"+name+"/manifests/"+dgst)
		w.WriteHeader(http.StatusCreated)
		return
	}

	f.mu.Lock()
	dgst := ref
	if !strings.HasPrefix(ref, content.Algorithm+":") {
		dgst = f.tags[name+":"+ref]
	}
	sm, ok := f.manifests[dgst]
	f.mu.Unlock()
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}`)
		return
	}

	if r.Method == http.MethodDelete {
		if f.DeleteDenied {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f.mu.Lock()
		delete(f.manifests, dgst)
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		return
	}

	f.mu.Lock()
	f.ManifestAccept = append(f.ManifestAccept, r.Header.Get("Accept"))
	override := f.ContentTypeFor[dgst]
	f.mu.Unlock()

	ct := sm.mediaType
	if override != "" {
		ct = override
	}
	sent := dgst
	if sm.sendDigest != "" {
		sent = sm.sendDigest
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Docker-Content-Digest", sent)
	w.Header().Set("Content-Length", strconv.Itoa(len(sm.body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sm.body)
}

func (f *fakeRegistry) serveBlobs(w http.ResponseWriter, r *http.Request, name, rest string) {
	// Upload endpoints: /v2/<name>/blobs/uploads/[id]
	if rest == "uploads" || strings.HasPrefix(rest, "uploads/") {
		f.serveUploads(w, r, name, strings.TrimPrefix(strings.TrimPrefix(rest, "uploads"), "/"))
		return
	}

	dgst := rest
	f.mu.Lock()
	body, ok := f.blobs[dgst]
	redirect := f.RedirectBlobs
	f.mu.Unlock()
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"errors":[{"code":"BLOB_UNKNOWN","message":"blob unknown"}]}`)
		return
	}
	if r.Method == http.MethodHead {
		w.Header().Set("Docker-Content-Digest", dgst)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		return
	}
	if redirect {
		http.Redirect(w, r, f.CDN.URL+"/blob/"+strings.TrimPrefix(dgst, content.Algorithm+":"), http.StatusTemporaryRedirect)
		return
	}
	f.writeBlob(w, r, dgst, body)
}

// writeBlob serves a blob with Range support and optional mid-stream abort.
func (f *fakeRegistry) writeBlob(w http.ResponseWriter, r *http.Request, dgst string, body []byte) {
	f.mu.Lock()
	f.inFlight++
	if f.inFlight > f.MaxInFlight {
		f.MaxInFlight = f.inFlight
	}
	delay := f.BlobDelay
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()
	if delay > 0 {
		time.Sleep(delay)
	}

	start := 0
	partial := false
	if rng := r.Header.Get("Range"); rng != "" {
		f.mu.Lock()
		f.BlobRanges = append(f.BlobRanges, rng)
		f.mu.Unlock()
		if spec, ok := strings.CutPrefix(rng, "bytes="); ok {
			s, _, _ := strings.Cut(spec, "-")
			if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= len(body) {
				start, partial = n, true
			}
		}
	}
	chunk := body[start:]

	f.mu.Lock()
	breakAt, shouldBreak := f.BreakBlobAt[dgst]
	if shouldBreak {
		delete(f.BreakBlobAt, dgst)
	}
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", dgst)
	if partial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(body)-1, len(body)))
		w.Header().Set("Content-Length", strconv.Itoa(len(chunk)))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.Header().Set("Content-Length", strconv.Itoa(len(chunk)))
		w.WriteHeader(http.StatusOK)
	}

	if shouldBreak && breakAt < len(chunk) {
		_, _ = w.Write(chunk[:breakAt])
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		// Kill the connection mid-body; the client must resume with a Range.
		panic(http.ErrAbortHandler)
	}
	_, _ = w.Write(chunk)
}

func (f *fakeRegistry) serveUploads(w http.ResponseWriter, r *http.Request, name, id string) {
	switch r.Method {
	case http.MethodPost:
		f.mu.Lock()
		f.nextID++
		id := strconv.Itoa(f.nextID)
		f.uploads[id] = nil
		f.mu.Unlock()
		w.Header().Set("Location", "/v2/"+name+"/blobs/uploads/"+id)
		w.Header().Set("Range", "0-0")
		w.WriteHeader(http.StatusAccepted)

	case http.MethodPatch:
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.uploads[id] = append(f.uploads[id], body...)
		n := len(f.uploads[id])
		f.mu.Unlock()
		w.Header().Set("Location", "/v2/"+name+"/blobs/uploads/"+id)
		w.Header().Set("Range", "0-"+strconv.Itoa(n-1))
		w.WriteHeader(http.StatusAccepted)

	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		want := r.URL.Query().Get("digest")
		f.mu.Lock()
		full := append(f.uploads[id], body...)
		delete(f.uploads, id)
		f.mu.Unlock()
		if got := content.DigestBytes(full); got != want {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"errors":[{"code":"DIGEST_INVALID","message":"expected %s got %s"}]}`, want, got)
			return
		}
		f.mu.Lock()
		f.blobs[want] = full
		f.PutBlobs[want] = full
		f.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", want)
		w.Header().Set("Location", "/v2/"+name+"/blobs/"+want)
		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (f *fakeRegistry) serveTags(w http.ResponseWriter, r *http.Request, name string) {
	var tags []string
	f.mu.Lock()
	for k, v := range f.tags {
		repo, tag, _ := strings.Cut(k, ":")
		if repo == name && v != "" {
			tags = append(tags, tag)
		}
	}
	pageSize := f.TagPageSize
	f.mu.Unlock()
	sortStrings(tags)

	last := r.URL.Query().Get("last")
	if last != "" {
		for i, t := range tags {
			if t == last {
				tags = tags[i+1:]
				break
			}
		}
	}
	if pageSize > 0 && len(tags) > pageSize {
		tags = tags[:pageSize]
		w.Header().Set("Link", fmt.Sprintf(`</v2/%s/tags/list?n=%d&last=%s>; rel="next"`, name, pageSize, tags[len(tags)-1]))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tagList{Name: name, Tags: tags})
}

func (f *fakeRegistry) serveCatalog(w http.ResponseWriter, r *http.Request) {
	repos := map[string]bool{}
	f.mu.Lock()
	for k := range f.tags {
		repo, _, _ := strings.Cut(k, ":")
		repos[repo] = true
	}
	f.mu.Unlock()
	var names []string
	for r := range repos {
		names = append(names, r)
	}
	sortStrings(names)

	last := r.URL.Query().Get("last")
	if last != "" {
		for i, n := range names {
			if n == last {
				names = names[i+1:]
				break
			}
		}
	}
	if n, err := strconv.Atoi(r.URL.Query().Get("n")); err == nil && n > 0 && len(names) > n {
		names = names[:n]
		w.Header().Set("Link", fmt.Sprintf(`</v2/_catalog?n=%d&last=%s>; rel="next"`, n, names[len(names)-1]))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(catalogList{Repositories: names})
}

// sortStrings is a tiny insertion sort so the harness does not drag in sort
// semantics that could mask an ordering bug in the code under test.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// countRequestsLocked is countRequests for callers that already hold f.mu.
func (f *fakeRegistry) countRequestsLocked(substr string) int {
	n := 0
	for _, r := range f.Requests {
		if strings.Contains(r, substr) {
			n++
		}
	}
	return n
}
