package registry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/oci/imagespec"
	"github.com/rahuldhali/hull/internal/types"
)

func TestNewClientDefaults(t *testing.T) {
	c := NewClient(Options{})
	if c.concurrency != DefaultConcurrency {
		t.Errorf("concurrency = %d, want %d", c.concurrency, DefaultConcurrency)
	}
	if c.userAgent != DefaultUserAgent {
		t.Errorf("userAgent = %q, want %q", c.userAgent, DefaultUserAgent)
	}
	if c.http.CheckRedirect == nil {
		t.Error("the client has no redirect policy, so Authorization would leak to a CDN")
	}
}

func TestNewClientDoesNotMutateTheSuppliedHTTPClient(t *testing.T) {
	supplied := &http.Client{}
	c := NewClient(Options{HTTPClient: supplied})
	if supplied.CheckRedirect != nil {
		t.Error("NewClient mutated the caller's http.Client")
	}
	if c.http == supplied {
		t.Error("NewClient kept the caller's http.Client instead of copying it")
	}
}

func TestEndpoint(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		insecure   bool
		wantScheme string
		wantHost   string
	}{
		{"docker hub", "docker.io", false, "https", DockerHubEndpoint},
		{"legacy docker hub", "index.docker.io", false, "https", DockerHubEndpoint},
		{"ghcr", "ghcr.io", false, "https", "ghcr.io"},
		{"local insecure", "localhost:5000", true, "http", "localhost:5000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(Options{Insecure: tt.insecure})
			scheme, host := c.Endpoint(tt.domain)
			if scheme != tt.wantScheme || host != tt.wantHost {
				t.Errorf("Endpoint(%q) = %s://%s, want %s://%s", tt.domain, scheme, host, tt.wantScheme, tt.wantHost)
			}
		})
	}
}

func TestStripAuthOnCrossHostRedirect(t *testing.T) {
	tests := []struct {
		name      string
		from      string
		to        string
		wantStrip bool
	}{
		{"same host", "https://registry.example.com/v2/x/blobs/y", "https://registry.example.com/other", false},
		{"default port elided", "https://registry.example.com/v2/x", "https://registry.example.com:443/other", false},
		{"different port", "http://127.0.0.1:1111/v2/x", "http://127.0.0.1:2222/blob", true},
		{"different host", "https://registry-1.docker.io/v2/x", "https://cdn.example.com/blob?sig=1", true},
		{"subdomain", "https://example.com/v2/x", "https://cdn.example.com/blob", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, err := url.Parse(tt.from)
			if err != nil {
				t.Fatal(err)
			}
			to, err := url.Parse(tt.to)
			if err != nil {
				t.Fatal(err)
			}
			next := &http.Request{URL: to, Header: http.Header{}}
			next.Header.Set("Authorization", "Bearer secret")
			next.Header.Set("Cookie", "session=1")
			prev := &http.Request{URL: from, Header: http.Header{}}
			if err := stripAuthOnCrossHostRedirect(next, []*http.Request{prev}); err != nil {
				t.Fatalf("policy returned an error: %v", err)
			}
			stripped := next.Header.Get("Authorization") == ""
			if stripped != tt.wantStrip {
				t.Errorf("stripped = %v, want %v", stripped, tt.wantStrip)
			}
			if tt.wantStrip && next.Header.Get("Cookie") != "" {
				t.Error("Cookie survived a cross-host redirect")
			}
		})
	}
}

func TestStripAuthOnCrossHostRedirectStopsLoops(t *testing.T) {
	u, _ := url.Parse("https://example.com/")
	via := make([]*http.Request, maxRedirects)
	for i := range via {
		via[i] = &http.Request{URL: u, Header: http.Header{}}
	}
	err := stripAuthOnCrossHostRedirect(&http.Request{URL: u, Header: http.Header{}}, via)
	if err == nil {
		t.Fatal("a chain of 10 redirects was allowed to continue")
	}
}

func TestFetchBlobCrossHostRedirectStripsAuthorization(t *testing.T) {
	f := newFakeRegistry(t)
	f.RequireAuth = true
	f.RedirectBlobs = true

	body := bytes.Repeat([]byte("payload"), 300)
	dgst := f.AddBlob(body)

	c := f.Client(Options{})
	rc, err := c.FetchBlob(context.Background(), f.Ref("library/alpine:3.20"), types.Descriptor{
		MediaType: imagespec.MediaTypeImageLayerGzip,
		Digest:    dgst,
		Size:      int64(len(body)),
	})
	if err != nil {
		t.Fatalf("FetchBlob: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading blob: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("blob body is wrong: got %d bytes, want %d", len(got), len(body))
	}

	f.mu.Lock()
	cdnAuth := append([]string(nil), f.CDNAuthHeaders...)
	f.mu.Unlock()
	if len(cdnAuth) == 0 {
		t.Fatal("the CDN was never contacted, so the redirect was not followed")
	}
	for i, h := range cdnAuth {
		if h != "" {
			t.Errorf("CDN request %d carried Authorization %q; the registry token leaked across hosts", i, h)
		}
	}
}

func TestFetchBlobRangeResumption(t *testing.T) {
	f := newFakeRegistry(t)
	body := make([]byte, 8192)
	for i := range body {
		body[i] = byte(i % 253)
	}
	dgst := f.AddBlob(body)
	f.mu.Lock()
	f.BreakBlobAt[dgst] = 3000
	f.mu.Unlock()

	c := f.Client(Options{})
	rc, err := c.FetchBlob(context.Background(), f.Ref("library/alpine:3.20"), types.Descriptor{
		MediaType: imagespec.MediaTypeImageLayerGzip,
		Digest:    dgst,
		Size:      int64(len(body)),
	})
	if err != nil {
		t.Fatalf("FetchBlob: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading a blob that was cut short: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("resumed blob is %d bytes and does not match the original (%d bytes)", len(got), len(body))
	}
	if content.DigestBytes(got) != dgst {
		t.Error("the resumed blob does not hash to its digest, so resumption duplicated or lost bytes")
	}

	f.mu.Lock()
	ranges := append([]string(nil), f.BlobRanges...)
	f.mu.Unlock()
	if len(ranges) == 0 {
		t.Fatal("no Range request was made; the client restarted the download instead of resuming")
	}
	if !strings.HasPrefix(ranges[0], "bytes=") || !strings.HasSuffix(ranges[0], "-") {
		t.Errorf("Range header = %q, want bytes=<n>-", ranges[0])
	}
}

func TestFetchBlobResumptionSurvivesIntoTheContentStore(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 4096, 4096)
	dgst := f.AddImage(img)
	f.Tag("library/flaky", "1", dgst)
	f.mu.Lock()
	f.BreakBlobAt[img.Layers[0].Digest] = 1500
	f.BreakBlobAt[img.Layers[1].Digest] = 2500
	f.mu.Unlock()

	c := f.Client(Options{Concurrency: 2})
	store := newStore(t)
	if _, err := c.Pull(context.Background(), f.Ref("library/flaky:1"), store, nil); err != nil {
		t.Fatalf("Pull over a flaky connection: %v", err)
	}
	for _, l := range img.Layers {
		if !store.Exists(l.Digest) {
			t.Errorf("layer %s did not make it into the store", content.ShortDigest(l.Digest))
		}
	}
}

func TestFetchBlobNotFound(t *testing.T) {
	f := newFakeRegistry(t)
	c := f.Client(Options{})
	_, err := c.FetchBlob(context.Background(), f.Ref("library/alpine:3.20"), types.Descriptor{
		Digest: content.DigestBytes([]byte("absent")),
		Size:   6,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFetchBlobRejectsAnInvalidDigest(t *testing.T) {
	f := newFakeRegistry(t)
	c := f.Client(Options{})
	_, err := c.FetchBlob(context.Background(), f.Ref("library/alpine:3.20"), types.Descriptor{
		Digest: "sha256:../../etc/passwd",
	})
	if err == nil {
		t.Fatal("an invalid digest was accepted")
	}
	if !errors.Is(err, content.ErrInvalidDigest) {
		t.Errorf("err = %v, want content.ErrInvalidDigest", err)
	}
}

func TestRetriesIdempotentRequests(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	dgst := f.AddImage(img)
	f.Tag("library/flappy", "1", dgst)
	f.mu.Lock()
	f.FailNTimes["/v2/library/flappy/manifests/1"] = 2
	f.mu.Unlock()

	c := f.Client(Options{})
	if _, _, err := c.Resolve(context.Background(), f.Ref("library/flappy:1"), nil); err != nil {
		t.Fatalf("Resolve did not survive two 503s: %v", err)
	}
	if n := f.countRequests("/v2/library/flappy/manifests/1"); n < 3 {
		t.Errorf("the manifest was requested %d times, want 3 (two failures plus the success)", n)
	}
}

func TestGivesUpAfterMaxRetries(t *testing.T) {
	f := newFakeRegistry(t)
	f.mu.Lock()
	f.FailNTimes["/v2/library/dead/manifests/1"] = 99
	f.mu.Unlock()

	c := f.Client(Options{})
	_, _, err := c.Resolve(context.Background(), f.Ref("library/dead:1"), nil)
	if err == nil {
		t.Fatal("Resolve succeeded against a registry that always fails")
	}
	var se *StatusError
	if !errors.As(err, &se) || se.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("err = %v, want a 503 StatusError", err)
	}
	if n := f.countRequests("/v2/library/dead/manifests/1"); n != defaultMaxRetries+1 {
		t.Errorf("made %d attempts, want %d", n, defaultMaxRetries+1)
	}
}

func TestUploadsAreNeverRetried(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	store := newStore(t)
	seedStore(t, store, img)
	f.mu.Lock()
	f.FailNTimes["/v2/library/target/blobs/uploads/"] = 99
	f.mu.Unlock()

	c := f.Client(Options{})
	typedImg := &types.Image{Digest: img.ManifestDesc.Digest, ManifestType: img.ManifestDesc.MediaType}
	err := c.Push(context.Background(), f.Ref("library/target:1"), typedImg, store)
	if err == nil {
		t.Fatal("Push succeeded against a failing registry")
	}
	if n := f.countRequests("POST /v2/library/target/blobs/uploads/"); n != 1 {
		t.Errorf("the upload POST was sent %d times; a non-idempotent request must never be replayed", n)
	}
}

func TestRateLimitHeadersAreRecorded(t *testing.T) {
	f := newFakeRegistry(t)
	f.RateLimitLimit = "100;w=3600"
	f.RateLimitLeft = "76;w=3600"

	c := f.Client(Options{})
	if _, _, _, ok := c.RateLimit(); ok {
		t.Error("RateLimit reported data before any request was made")
	}
	if err := c.Ping(context.Background(), f.Host()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	limit, remaining, window, ok := c.RateLimit()
	if !ok {
		t.Fatal("RateLimit reported no data after a response carrying the headers")
	}
	if limit != 100 || remaining != 76 || window != time.Hour {
		t.Errorf("RateLimit() = %d, %d, %v", limit, remaining, window)
	}
}

func TestParseRateLimitValue(t *testing.T) {
	tests := []struct {
		in         string
		wantN      int
		wantWindow time.Duration
		wantOK     bool
	}{
		{"100;w=3600", 100, time.Hour, true},
		{"76;w=21600", 76, 6 * time.Hour, true},
		{"100", 100, 0, true},
		{" 42 ; w=60 ", 42, time.Minute, true},
		{"100;w=3600, 5000;w=86400", 100, time.Hour, true},
		{"", 0, 0, false},
		{"unlimited", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			n, w, ok := parseRateLimitValue(tt.in)
			if ok != tt.wantOK || n != tt.wantN || w != tt.wantWindow {
				t.Errorf("parseRateLimitValue(%q) = %d, %v, %v; want %d, %v, %v",
					tt.in, n, w, ok, tt.wantN, tt.wantWindow, tt.wantOK)
			}
		})
	}
}

func TestRateLimited429(t *testing.T) {
	f := newFakeRegistry(t)
	f.Send429 = 99
	f.RateLimitLimit = "100;w=3600"
	f.RateLimitLeft = "0;w=3600"

	c := f.Client(Options{})
	err := c.Ping(context.Background(), f.Host())
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err is not *RateLimitError: %T", err)
	}
	if rl.Limit != 100 || rl.Remaining != 0 {
		t.Errorf("RateLimitError = %+v", rl)
	}
}

func TestRateLimitRetryAfterIsHonouredButBounded(t *testing.T) {
	f := newFakeRegistry(t)
	f.Send429 = 1
	f.RetryAfter = "0"
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	dgst := f.AddImage(img)
	f.Tag("library/limited", "1", dgst)

	c := f.Client(Options{})
	if _, _, err := c.Resolve(context.Background(), f.Ref("library/limited:1"), nil); err != nil {
		t.Fatalf("a 429 with Retry-After: 0 was not retried: %v", err)
	}

	// A Retry-After far beyond the inline budget must be reported, not slept on.
	f2 := newFakeRegistry(t)
	f2.Send429 = 99
	f2.RetryAfter = "3600"
	c2 := f2.Client(Options{})
	start := time.Now()
	err := c2.Ping(context.Background(), f2.Host())
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("the client waited %v for a one-hour Retry-After", elapsed)
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	var rl *RateLimitError
	if errors.As(err, &rl) {
		if rl.RetryAfter != time.Hour {
			t.Errorf("RetryAfter = %v, want 1h", rl.RetryAfter)
		}
		if rl.Reset.IsZero() {
			t.Error("Reset is zero even though Retry-After was sent")
		}
	}
}

func TestRateLimitErrorMessage(t *testing.T) {
	hub := &RateLimitError{Registry: DockerHubEndpoint, Limit: 100, Remaining: 0, Reset: time.Unix(1_800_000_000, 0)}
	msg := hub.Error()
	if !strings.Contains(msg, "Docker Hub rate limit reached. 'hull login' raises the limit substantially.") {
		t.Errorf("Docker Hub message = %q", msg)
	}
	if !strings.Contains(msg, "Retry after") {
		t.Errorf("message %q does not carry the reset time", msg)
	}
	other := &RateLimitError{Registry: "ghcr.io", Remaining: -1}
	if strings.Contains(other.Error(), "hull login") {
		t.Errorf("non-hub message mentions Docker Hub: %q", other.Error())
	}
}

func TestRetryAfterParsing(t *testing.T) {
	future := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
	tests := []struct {
		name   string
		header string
		wantOK bool
		check  func(time.Duration) bool
	}{
		{"seconds", "30", true, func(d time.Duration) bool { return d == 30*time.Second }},
		{"zero", "0", true, func(d time.Duration) bool { return d == 0 }},
		{"http date", future, true, func(d time.Duration) bool { return d > 60*time.Second && d <= 90*time.Second }},
		{"past date", "Mon, 02 Jan 2006 15:04:05 GMT", true, func(d time.Duration) bool { return d == 0 }},
		{"garbage", "soon", false, nil},
		{"absent", "", false, nil},
		{"negative", "-5", false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			if tt.header != "" {
				resp.Header.Set("Retry-After", tt.header)
			}
			d, ok := retryAfter(resp)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && !tt.check(d) {
				t.Errorf("duration = %v", d)
			}
		})
	}
}

func TestIdempotent(t *testing.T) {
	body := strings.NewReader("x")
	tests := []struct {
		method string
		want   bool
	}{
		{http.MethodGet, true},
		{http.MethodHead, true},
		{http.MethodPost, false},
		{http.MethodPut, false},
		{http.MethodPatch, false},
		{http.MethodDelete, false},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, "https://example.com/v2/", body)
			if err != nil {
				t.Fatal(err)
			}
			if got := idempotent(req); got != tt.want {
				t.Errorf("idempotent(%s) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

func TestBackoffGrowsAndJitters(t *testing.T) {
	c := NewClient(Options{})
	c.baseBackoff = 100 * time.Millisecond
	prevMin := time.Duration(0)
	for i := 0; i < 4; i++ {
		base := c.baseBackoff << uint(i)
		var sawJitter bool
		for j := 0; j < 50; j++ {
			d := c.backoff(i)
			if d < base || d > base+base/2 {
				t.Fatalf("backoff(%d) = %v, want between %v and %v", i, d, base, base+base/2)
			}
			if d != base {
				sawJitter = true
			}
		}
		if !sawJitter {
			t.Errorf("backoff(%d) never jittered", i)
		}
		if base <= prevMin {
			t.Errorf("backoff did not grow at attempt %d", i)
		}
		prevMin = base
	}
}

func TestUnauthorizedWithoutAnAuthenticator(t *testing.T) {
	f := newFakeRegistry(t)
	f.RequireAuth = true
	c := NewClient(Options{Insecure: true})
	c.baseBackoff = time.Millisecond
	_, _, err := c.Resolve(context.Background(), f.Ref("library/alpine:3.20"), nil)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestVerifyContentRange(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    int64
		wantErr bool
	}{
		{"exact", "bytes 100-199/200", 100, false},
		{"unknown total", "bytes 100-199/*", 100, false},
		{"wrong start", "bytes 50-199/200", 100, true},
		{"missing", "", 100, true},
		{"wrong unit", "items 100-199/200", 100, true},
		{"garbage", "bytes abc", 100, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyContentRange(tt.header, tt.want)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyContentRange(%q, %d) = %v, wantErr %v", tt.header, tt.want, err, tt.wantErr)
			}
		})
	}
}

func TestPlatformStringRendering(t *testing.T) {
	tests := []struct {
		in   types.Platform
		want string
	}{
		{types.Platform{OS: "linux", Architecture: "amd64"}, "linux/amd64"},
		{types.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, "linux/arm64/v8"},
		{types.Platform{OS: "windows", Architecture: "amd64", OSVersion: "10.0.20348"}, "windows/amd64:10.0.20348"},
		{types.Platform{}, "unknown/unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := PlatformString(tt.in); got != tt.want {
				t.Errorf("PlatformString(%+v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFetchForeignLayerUsesDescriptorURLsWithoutCredentials(t *testing.T) {
	f := newFakeRegistry(t)
	f.RequireAuth = true

	body := bytes.Repeat([]byte("foreign"), 100)
	dgst := f.AddBlob(body)
	hexPart := strings.TrimPrefix(dgst, content.Algorithm+":")

	c := f.Client(Options{})
	rc, err := c.FetchBlob(context.Background(), f.Ref("library/windows:1"), types.Descriptor{
		MediaType: imagespec.MediaTypeDockerForeignLayer,
		Digest:    dgst,
		Size:      int64(len(body)),
		URLs:      []string{f.CDN.URL + "/blob/" + hexPart},
	})
	if err != nil {
		t.Fatalf("FetchBlob: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading foreign layer: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Error("the foreign layer body is wrong")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, h := range f.CDNAuthHeaders {
		if h != "" {
			t.Errorf("a foreign-layer host received Authorization %q", h)
		}
	}
	if n := f.countRequestsLocked("/blobs/" + dgst); n != 0 {
		t.Error("a foreign layer was requested from the registry, which never serves one")
	}
}

func TestFetchBlobFallsBackToDescriptorURLs(t *testing.T) {
	f := newFakeRegistry(t)
	body := []byte("only on the mirror")
	dgst := content.DigestBytes(body)
	// Present on the mirror, absent from the registry itself.
	f.mu.Lock()
	f.blobs[dgst] = body
	f.mu.Unlock()
	hexPart := strings.TrimPrefix(dgst, content.Algorithm+":")

	// Make the registry answer 404 for this digest by serving it only via the
	// CDN handler: delete it from the registry's view first.
	mirror := f.CDN.URL + "/blob/" + hexPart
	f2 := newFakeRegistry(t) // an empty registry
	c := f2.Client(Options{})
	rc, err := c.FetchBlob(context.Background(), f2.Ref("library/x:1"), types.Descriptor{
		MediaType: imagespec.MediaTypeImageLayerGzip,
		Digest:    dgst,
		Size:      int64(len(body)),
		URLs:      []string{mirror},
	})
	if err != nil {
		t.Fatalf("FetchBlob did not fall back to the descriptor URL: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading from the mirror: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Error("the mirrored body is wrong")
	}
}

func TestFetchForeignLayerWithoutURLs(t *testing.T) {
	f := newFakeRegistry(t)
	c := f.Client(Options{})
	_, err := c.FetchBlob(context.Background(), f.Ref("library/windows:1"), types.Descriptor{
		MediaType: imagespec.MediaTypeDockerForeignLayer,
		Digest:    content.DigestBytes([]byte("x")),
		Size:      1,
	})
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}
