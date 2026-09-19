package registry

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/oci/imagespec"
	"github.com/rahuldhali/hull/internal/oci/reference"
	"github.com/rahuldhali/hull/internal/types"
)

// seedStore writes every blob of a fixture into a content store, which is the
// state a push starts from.
func seedStore(t *testing.T, store *content.Store, img imageFixture) {
	t.Helper()
	ctx := context.Background()
	write := func(b []byte, dgst string) {
		t.Helper()
		if _, err := store.WriteBlob(ctx, bytes.NewReader(b), dgst, int64(len(b))); err != nil {
			t.Fatalf("seeding %s: %v", content.ShortDigest(dgst), err)
		}
	}
	for i, b := range img.LayerData {
		write(b, img.Layers[i].Digest)
	}
	write(img.ConfigJSON, img.ConfigDesc.Digest)
	write(img.ManifestJSON, img.ManifestDesc.Digest)
}

func fixtureImage(img imageFixture) *types.Image {
	return &types.Image{
		ID:           img.ConfigDesc.Digest,
		Digest:       img.ManifestDesc.Digest,
		DiffIDs:      img.DiffIDs,
		ChainID:      ChainID(img.DiffIDs),
		ManifestType: img.ManifestDesc.MediaType,
	}
}

func TestPushFull(t *testing.T) {
	f := newFakeRegistry(t)
	f.RequireAuth = true
	f.Username = "pusher"
	f.Password = "pw"

	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 512, 1024)
	store := newStore(t)
	seedStore(t, store, img)

	c := f.Client(Options{})
	ref := f.Ref("me/app:v1")
	if err := c.Push(context.Background(), ref, fixtureImage(img), store); err != nil {
		t.Fatalf("Push: %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	for i, l := range img.Layers {
		got, ok := f.blobs[l.Digest]
		if !ok {
			t.Errorf("layer %d was not uploaded", i)
			continue
		}
		if !bytes.Equal(got, img.LayerData[i]) {
			t.Errorf("layer %d arrived corrupted", i)
		}
	}
	if _, ok := f.blobs[img.ConfigDesc.Digest]; !ok {
		t.Error("the config blob was not uploaded")
	}
	body, ok := f.PutManifests["me/app:v1"]
	if !ok {
		t.Fatal("the manifest was not PUT under the tag")
	}
	if !bytes.Equal(body, img.ManifestJSON) {
		t.Error("the manifest was altered in flight")
	}
	if f.tags["me/app:v1"] != img.ManifestDesc.Digest {
		t.Errorf("tag points at %s, want %s", f.tags["me/app:v1"], img.ManifestDesc.Digest)
	}

	// The token must have been requested with a pull,push scope.
	var sawPush bool
	for _, q := range f.TokenQueries {
		if strings.Contains(q.Get("scope"), "pull,push") {
			sawPush = true
		}
	}
	if !sawPush {
		t.Errorf("no token was requested with a push scope; scopes were %v", f.TokenQueries)
	}
}

func TestPushSkipsBlobsTheRegistryAlreadyHas(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 64, 64)
	store := newStore(t)
	seedStore(t, store, img)

	// The registry already holds the first layer and the config.
	f.AddBlob(img.LayerData[0])
	f.AddBlob(img.ConfigJSON)

	var prog progressCollector
	c := f.Client(Options{Progress: prog.fn()})
	if err := c.Push(context.Background(), f.Ref("me/app:v1"), fixtureImage(img), store); err != nil {
		t.Fatalf("Push: %v", err)
	}

	if n := f.countRequests("POST /v2/me/app/blobs/uploads/"); n != 1 {
		t.Errorf("started %d uploads, want 1 (only the second layer is missing)", n)
	}
	if st := prog.statuses(img.Layers[0].Digest); !contains(st, StatusExists) {
		t.Errorf("layer 0 progress = %v, want %q", st, StatusExists)
	}
	if st := prog.statuses(img.Layers[1].Digest); !contains(st, StatusDone) {
		t.Errorf("layer 1 progress = %v, want %q", st, StatusDone)
	}
}

func TestPushChunked(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 5000)
	store := newStore(t)
	seedStore(t, store, img)

	c := f.Client(Options{})
	c.pushChunkSize = 1024 // force the PATCH path

	if err := c.Push(context.Background(), f.Ref("me/big:v1"), fixtureImage(img), store); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if n := f.countRequests("PATCH /v2/me/big/blobs/uploads/"); n < 5 {
		t.Errorf("sent %d PATCH chunks for a 5000 byte blob with a 1024 byte chunk size, want 5", n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := f.blobs[img.Layers[0].Digest]; !bytes.Equal(got, img.LayerData[0]) {
		t.Errorf("the chunked blob arrived as %d bytes, want %d", len(got), len(img.LayerData[0]))
	}
}

func TestPushByDigestWhenTheReferenceHasNoTag(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 32)
	store := newStore(t)
	seedStore(t, store, img)

	ref := f.Ref("me/app@" + img.ManifestDesc.Digest)
	c := f.Client(Options{})
	if err := c.Push(context.Background(), ref, fixtureImage(img), store); err != nil {
		t.Fatalf("Push: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.PutManifests["me/app:"+img.ManifestDesc.Digest]; !ok {
		t.Errorf("the manifest was not PUT by digest; saw %v", f.PutManifests)
	}
}

func TestPushRejectsAManifestThatIsNotInTheStore(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 32)
	c := f.Client(Options{})
	err := c.Push(context.Background(), f.Ref("me/app:v1"), fixtureImage(img), newStore(t))
	if !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("err = %v, want content.ErrNotFound", err)
	}
}

func TestPushRejectsNilArguments(t *testing.T) {
	c := NewClient(Options{})
	ref, err := reference.Parse("example.com/me/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push(context.Background(), ref, nil, newStore(t)); err == nil {
		t.Error("Push accepted a nil image")
	}
	if err := c.Push(context.Background(), ref, &types.Image{}, nil); err == nil {
		t.Error("Push accepted a nil store")
	}
	if err := c.Push(context.Background(), ref, &types.Image{Digest: "not-a-digest"}, newStore(t)); err == nil {
		t.Error("Push accepted an image with an invalid manifest digest")
	}
}

func TestUploadLocationResolvesRelativePaths(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 16)
	store := newStore(t)
	seedStore(t, store, img)

	// The harness answers with a relative Location, which the client must
	// resolve against the request URL.
	c := f.Client(Options{})
	if err := c.Push(context.Background(), f.Ref("me/rel:v1"), fixtureImage(img), store); err != nil {
		t.Fatalf("Push with a relative upload Location: %v", err)
	}
}
