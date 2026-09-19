package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/oci/imagespec"
	"github.com/rahuldhali/hull/internal/types"
)

func newStore(t *testing.T) *content.Store {
	t.Helper()
	s, err := content.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("content.NewStore: %v", err)
	}
	return s
}

// progressCollector gathers events; the client serialises calls, so no lock is
// strictly needed, but taking one proves the callback contract is honoured
// under -race.
type progressCollector struct {
	mu     sync.Mutex
	events []ProgressEvent
}

func (p *progressCollector) fn() func(ProgressEvent) {
	return func(ev ProgressEvent) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.events = append(p.events, ev)
	}
}

func (p *progressCollector) statuses(digest string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, ev := range p.events {
		if ev.Digest == digest {
			out = append(out, ev.Status)
		}
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestPullFull(t *testing.T) {
	f := newFakeRegistry(t)
	f.RequireAuth = true
	f.Username = "someone"
	f.Password = "s3cret"

	amd := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 1024, 2048)
	arm := buildImage(t, types.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, imagespec.MediaTypeImageManifest, 64)
	f.AddImage(amd)
	f.AddImage(arm)
	idxDesc, idxBody := buildIndex(t, imagespec.MediaTypeImageIndex, amd.ManifestDesc, arm.ManifestDesc)
	f.AddManifest(idxDesc.MediaType, idxBody)
	f.Tag("library/alpine", "3.20", idxDesc.Digest)

	var prog progressCollector
	c := f.Client(Options{Progress: prog.fn()})
	store := newStore(t)
	plat := linux("amd64")

	img, err := c.Pull(context.Background(), f.Ref("library/alpine:3.20"), store, &plat)
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	if img.ID != amd.ConfigDesc.Digest {
		t.Errorf("ID = %s, want the config digest %s", img.ID, amd.ConfigDesc.Digest)
	}
	if img.Digest != amd.ManifestDesc.Digest {
		t.Errorf("Digest = %s, want the manifest digest %s", img.Digest, amd.ManifestDesc.Digest)
	}
	if !reflect.DeepEqual(img.DiffIDs, amd.DiffIDs) {
		t.Errorf("DiffIDs = %v, want %v", img.DiffIDs, amd.DiffIDs)
	}
	if want := ChainID(amd.DiffIDs); img.ChainID != want {
		t.Errorf("ChainID = %s, want %s", img.ChainID, want)
	}
	var wantSize int64
	for _, l := range amd.Layers {
		wantSize += l.Size
	}
	if img.Size != wantSize {
		t.Errorf("Size = %d, want %d", img.Size, wantSize)
	}
	if img.Architecture != "amd64" || img.OS != "linux" {
		t.Errorf("platform = %s/%s", img.OS, img.Architecture)
	}
	if img.ManifestType != imagespec.MediaTypeImageManifest {
		t.Errorf("ManifestType = %s", img.ManifestType)
	}
	if got := img.RepoTags; len(got) != 1 || !strings.HasSuffix(got[0], "/library/alpine:3.20") {
		t.Errorf("RepoTags = %v", got)
	}
	if got := img.RepoDigests; len(got) != 1 || !strings.HasSuffix(got[0], "@"+amd.ManifestDesc.Digest) {
		t.Errorf("RepoDigests = %v", got)
	}
	if img.Config.Entrypoint[0] != "/bin/sh" || img.Config.Env[0] != "PATH=/usr/bin" {
		t.Errorf("Config = %+v", img.Config)
	}
	if img.Labels["org.opencontainers.image.title"] != "fixture" {
		t.Errorf("Labels = %v", img.Labels)
	}
	if img.Created.IsZero() {
		t.Error("Created is zero")
	}

	// Everything must be in the content store, byte for byte.
	for _, want := range append([]types.Descriptor{amd.ManifestDesc, amd.ConfigDesc}, amd.Layers...) {
		if !store.Exists(want.Digest) {
			t.Errorf("blob %s is missing from the store", content.ShortDigest(want.Digest))
			continue
		}
		info, err := store.Stat(want.Digest)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if info.Size != want.Size {
			t.Errorf("blob %s is %d bytes, want %d", content.ShortDigest(want.Digest), info.Size, want.Size)
		}
	}
	// The arm64 image must not have been fetched.
	if store.Exists(arm.ManifestDesc.Digest) {
		t.Error("the arm64 manifest was fetched even though linux/amd64 was requested")
	}

	// Progress: each layer downloads and finishes.
	for _, l := range amd.Layers {
		st := prog.statuses(l.Digest)
		if !contains(st, StatusDownloading) || !contains(st, StatusDone) {
			t.Errorf("layer %s progress = %v, want downloading then done", content.ShortDigest(l.Digest), st)
		}
	}

	// The token dance must have happened exactly as specified: an anonymous
	// request first, a 401, then a token request carrying HTTP Basic.
	f.mu.Lock()
	tokenAuths := append([]string(nil), f.TokenAuths...)
	queries := append([]url.Values(nil), f.TokenQueries...)
	f.mu.Unlock()
	if len(tokenAuths) == 0 {
		t.Fatal("the token server was never contacted")
	}
	if !strings.HasPrefix(tokenAuths[0], "Basic ") {
		t.Errorf("token request Authorization = %q, want HTTP Basic", tokenAuths[0])
	}
	if got := queries[0].Get("service"); got != "fake-registry" {
		t.Errorf("token request service = %q", got)
	}
	if got := queries[0].Get("scope"); got != "repository:library/alpine:pull" {
		t.Errorf("token request scope = %q", got)
	}
	if got := queries[0].Get("account"); got != "someone" {
		t.Errorf("token request account = %q", got)
	}

	// A second pull into the same store transfers nothing.
	var prog2 progressCollector
	c2 := f.Client(Options{Progress: prog2.fn()})
	before := f.countRequests("/blobs/sha256:")
	if _, err := c2.Pull(context.Background(), f.Ref("library/alpine:3.20"), store, &plat); err != nil {
		t.Fatalf("second Pull: %v", err)
	}
	if after := f.countRequests("/blobs/sha256:"); after != before {
		t.Errorf("second pull made %d new blob requests, want 0", after-before)
	}
	for _, l := range amd.Layers {
		if st := prog2.statuses(l.Digest); !contains(st, StatusExists) {
			t.Errorf("second pull of %s reported %v, want %q", content.ShortDigest(l.Digest), st, StatusExists)
		}
	}
}

func TestPullDetectsCorruptedLayer(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 128, 128)
	dgst := f.AddImage(img)
	f.Tag("library/alpine", "3.20", dgst)
	// Same length, different bytes: only a digest check catches this.
	bad := make([]byte, img.Layers[1].Size)
	for i := range bad {
		bad[i] = 0xFF
	}
	f.PutBlobAt(img.Layers[1].Digest, bad)

	c := f.Client(Options{Concurrency: 1})
	store := newStore(t)
	_, err := c.Pull(context.Background(), f.Ref("library/alpine:3.20"), store, nil)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("err = %v, want ErrDigestMismatch", err)
	}
	if store.Exists(img.Layers[1].Digest) {
		t.Error("the corrupted layer was committed to the content store")
	}
}

func TestPullRejectsDiffIDCountMismatch(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 16, 16)

	var cfg imagespec.ImageConfig
	if err := json.Unmarshal(img.ConfigJSON, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.RootFS.DiffIDs = cfg.RootFS.DiffIDs[:1]
	badConfig, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := imagespec.Manifest{
		SchemaVersion: imagespec.SchemaVersion,
		MediaType:     imagespec.MediaTypeImageManifest,
		Config: types.Descriptor{
			MediaType: imagespec.MediaTypeImageConfig,
			Digest:    content.DigestBytes(badConfig),
			Size:      int64(len(badConfig)),
		},
		Layers: img.Layers,
	}
	manifestJSON, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range img.LayerData {
		f.AddBlob(b)
	}
	f.AddBlob(badConfig)
	dgst := f.AddManifest(imagespec.MediaTypeImageManifest, manifestJSON)
	f.Tag("library/bad", "1", dgst)

	c := f.Client(Options{})
	_, err = c.Pull(context.Background(), f.Ref("library/bad:1"), newStore(t), nil)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	if !strings.Contains(err.Error(), "diff_ids") {
		t.Errorf("error %q does not explain the mismatch", err)
	}
}

func TestPullBoundedConcurrency(t *testing.T) {
	f := newFakeRegistry(t)
	f.BlobDelay = 25 * time.Millisecond
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8, 9, 10, 11, 12, 13)
	dgst := f.AddImage(img)
	f.Tag("library/many", "1", dgst)

	c := f.Client(Options{Concurrency: 2})
	if _, err := c.Pull(context.Background(), f.Ref("library/many:1"), newStore(t), nil); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	f.mu.Lock()
	peak := f.MaxInFlight
	f.mu.Unlock()
	if peak > 2 {
		t.Errorf("peak concurrent blob transfers = %d, want at most 2", peak)
	}
	if peak < 2 {
		t.Errorf("peak concurrent blob transfers = %d; the pull did not run in parallel at all", peak)
	}
}

func TestPullCancellation(t *testing.T) {
	f := newFakeRegistry(t)
	f.BlobDelay = 250 * time.Millisecond
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 32, 32)
	dgst := f.AddImage(img)
	f.Tag("library/slow", "1", dgst)

	ctx, cancel := context.WithCancel(context.Background())
	c := f.Client(Options{Concurrency: 1})
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	if _, err := c.Pull(ctx, f.Ref("library/slow:1"), newStore(t), nil); err == nil {
		t.Fatal("Pull succeeded despite cancellation")
	}
}

func TestChainID(t *testing.T) {
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	cc := "sha256:" + strings.Repeat("c", 64)

	// Golden values, computed independently with sha256sum over
	// "<chain> <diffID>".
	const (
		chain1 = "sha256:ccd722928bd92476ba1745586fed6e45a102504185ad88cd89e01ff116fd146c"
		chain2 = "sha256:c1377126441fb2f5ec2c21ae2a60255331d639e830f0ee1b40a36e52d4c40588"
	)

	tests := []struct {
		name    string
		diffIDs []string
		want    string
		wantAll []string
	}{
		{"empty", nil, "", nil},
		{"one layer is its own chain id", []string{a}, a, []string{a}},
		{"two layers", []string{a, b}, chain1, []string{a, chain1}},
		{"three layers", []string{a, b, cc}, chain2, []string{a, chain1, chain2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ChainID(tt.diffIDs); got != tt.want {
				t.Errorf("ChainID(%v) = %q, want %q", tt.diffIDs, got, tt.want)
			}
			if got := ChainIDs(tt.diffIDs); !reflect.DeepEqual(got, tt.wantAll) {
				t.Errorf("ChainIDs(%v) = %v, want %v", tt.diffIDs, got, tt.wantAll)
			}
		})
	}
}

func TestChainIDsMatchChainID(t *testing.T) {
	ids := []string{
		"sha256:" + strings.Repeat("1", 64),
		"sha256:" + strings.Repeat("2", 64),
		"sha256:" + strings.Repeat("3", 64),
		"sha256:" + strings.Repeat("4", 64),
	}
	all := ChainIDs(ids)
	for i := range ids {
		if got, want := ChainID(ids[:i+1]), all[i]; got != want {
			t.Errorf("ChainID of the first %d layers = %s, ChainIDs[%d] = %s", i+1, got, i, want)
		}
		if err := content.ValidateDigest(all[i]); err != nil {
			t.Errorf("ChainIDs[%d] is not a canonical digest: %v", i, err)
		}
	}
}
