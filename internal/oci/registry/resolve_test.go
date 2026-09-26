package registry

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ChPuru/hull/internal/content"
	"github.com/ChPuru/hull/internal/oci/imagespec"
	"github.com/ChPuru/hull/internal/types"
)

func linux(arch string) types.Platform { return types.Platform{OS: "linux", Architecture: arch} }

func TestResolveSingleManifest(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest)
	dgst := f.AddImage(img)
	f.Tag("library/alpine", "3.20", dgst)

	c := f.Client(Options{})
	plat := linux("amd64")
	desc, body, err := c.Resolve(context.Background(), f.Ref("library/alpine:3.20"), &plat)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if desc.Digest != img.ManifestDesc.Digest {
		t.Errorf("digest = %s, want %s", desc.Digest, img.ManifestDesc.Digest)
	}
	if desc.MediaType != imagespec.MediaTypeImageManifest {
		t.Errorf("mediaType = %s", desc.MediaType)
	}
	if desc.Size != int64(len(img.ManifestJSON)) {
		t.Errorf("size = %d, want %d", desc.Size, len(img.ManifestJSON))
	}
	if string(body) != string(img.ManifestJSON) {
		t.Error("Resolve returned bytes that are not the manifest verbatim")
	}

	f.mu.Lock()
	accepts := append([]string(nil), f.ManifestAccept...)
	f.mu.Unlock()
	if len(accepts) == 0 {
		t.Fatal("registry saw no manifest request")
	}
	if accepts[0] != imagespec.AllManifestAccept() {
		t.Errorf("Accept = %q, want %q", accepts[0], imagespec.AllManifestAccept())
	}
}

func TestResolvePlatformSelection(t *testing.T) {
	f := newFakeRegistry(t)
	amd := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 32)
	arm := buildImage(t, types.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, imagespec.MediaTypeImageManifest, 48)
	armv7 := buildImage(t, types.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}, imagespec.MediaTypeImageManifest, 16)
	f.AddImage(amd)
	f.AddImage(arm)
	f.AddImage(armv7)
	idxDesc, idxBody := buildIndex(t, imagespec.MediaTypeImageIndex,
		amd.ManifestDesc, arm.ManifestDesc, armv7.ManifestDesc)
	f.AddManifest(idxDesc.MediaType, idxBody)
	f.Tag("library/alpine", "3.20", idxDesc.Digest)

	tests := []struct {
		name string
		want types.Platform
		got  string
	}{
		{"amd64", linux("amd64"), amd.ManifestDesc.Digest},
		{"arm64 without variant", linux("arm64"), arm.ManifestDesc.Digest},
		{"arm64 with v8", types.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, arm.ManifestDesc.Digest},
		{"aarch64 alias", linux("aarch64"), arm.ManifestDesc.Digest},
		{"x86_64 alias", linux("x86_64"), amd.ManifestDesc.Digest},
		{"arm v7", types.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}, armv7.ManifestDesc.Digest},
		{"arm default variant", linux("arm"), armv7.ManifestDesc.Digest},
	}
	c := f.Client(Options{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.want
			desc, _, err := c.Resolve(context.Background(), f.Ref("library/alpine:3.20"), &want)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if desc.Digest != tt.got {
				t.Errorf("selected %s, want %s", content.ShortDigest(desc.Digest), content.ShortDigest(tt.got))
			}
			if !imagespec.IsManifest(desc.MediaType) {
				t.Errorf("mediaType = %s, want a manifest", desc.MediaType)
			}
		})
	}
}

func TestResolveDockerManifestList(t *testing.T) {
	f := newFakeRegistry(t)
	amd := buildImage(t, linux("amd64"), imagespec.MediaTypeDockerManifest, 24)
	f.AddImage(amd)
	idxDesc, idxBody := buildIndex(t, imagespec.MediaTypeDockerManifestList, amd.ManifestDesc)
	f.AddManifest(idxDesc.MediaType, idxBody)
	f.Tag("library/busybox", "latest", idxDesc.Digest)

	c := f.Client(Options{})
	plat := linux("amd64")
	desc, _, err := c.Resolve(context.Background(), f.Ref("library/busybox:latest"), &plat)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if desc.MediaType != imagespec.MediaTypeDockerManifest {
		t.Errorf("mediaType = %s", desc.MediaType)
	}
}

func TestResolvePlatformNotFound(t *testing.T) {
	f := newFakeRegistry(t)
	amd := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	arm := buildImage(t, types.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, imagespec.MediaTypeImageManifest, 8)
	f.AddImage(amd)
	f.AddImage(arm)
	idxDesc, idxBody := buildIndex(t, imagespec.MediaTypeImageIndex, amd.ManifestDesc, arm.ManifestDesc)
	f.AddManifest(idxDesc.MediaType, idxBody)
	f.Tag("library/alpine", "3.20", idxDesc.Digest)

	c := f.Client(Options{})
	want := types.Platform{OS: "linux", Architecture: "riscv64"}
	_, _, err := c.Resolve(context.Background(), f.Ref("library/alpine:3.20"), &want)
	if !errors.Is(err, ErrPlatformNotFound) {
		t.Fatalf("err = %v, want ErrPlatformNotFound", err)
	}
	var pnf *PlatformNotFoundError
	if !errors.As(err, &pnf) {
		t.Fatalf("err is not *PlatformNotFoundError: %T", err)
	}
	if len(pnf.Have) != 2 {
		t.Errorf("Have = %v, want the two real platforms (the attestation entry must be skipped)", pnf.Have)
	}
	msg := err.Error()
	for _, want := range []string{"linux/riscv64", "linux/amd64", "linux/arm64/v8"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q does not mention %q", msg, want)
		}
	}
	if strings.Contains(msg, unknownPlatform) {
		t.Errorf("error message %q lists the attestation entry", msg)
	}
}

func TestResolveSchema1IsRefused(t *testing.T) {
	body := []byte(`{"schemaVersion":1,"name":"library/alpine","tag":"2.6","fsLayers":[{"blobSum":"sha256:` +
		strings.Repeat("a", 64) + `"}],"history":[{"v1Compatibility":"{}"}]}`)

	tests := []struct {
		name      string
		mediaType string
	}{
		{"declared schema1", imagespec.MediaTypeDockerManifestSchema1},
		{"declared signed schema1", imagespec.MediaTypeDockerManifestSchema1Signed},
		{"sniffed from a generic content type", "application/json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			dgst := f.AddManifest(tt.mediaType, body)
			f.Tag("library/alpine", "2.6", dgst)

			c := f.Client(Options{})
			_, _, err := c.Resolve(context.Background(), f.Ref("library/alpine:2.6"), nil)
			if !errors.Is(err, ErrSchema1) {
				t.Fatalf("err = %v, want ErrSchema1", err)
			}
			msg := err.Error()
			for _, want := range []string{
				"is a Docker schema1 image",
				"removed from the ecosystem in 2025",
				"Re-push it as OCI or use a newer tag.",
			} {
				if !strings.Contains(msg, want) {
					t.Errorf("message %q does not contain %q", msg, want)
				}
			}
		})
	}
}

func TestResolveDigestMismatchFromHeader(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	lie := content.DigestBytes([]byte("not the manifest"))
	f.AddRawManifest(imagespec.MediaTypeImageManifest, img.ManifestJSON, lie)
	f.Tag("library/alpine", "3.20", img.ManifestDesc.Digest)

	c := f.Client(Options{})
	_, _, err := c.Resolve(context.Background(), f.Ref("library/alpine:3.20"), nil)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("err = %v, want ErrDigestMismatch", err)
	}
	var dm *DigestMismatchError
	if !errors.As(err, &dm) {
		t.Fatalf("err is not *DigestMismatchError: %T", err)
	}
	if dm.Expected != lie || dm.Actual != img.ManifestDesc.Digest {
		t.Errorf("mismatch = %+v", dm)
	}
}

func TestResolveDigestReferenceIsAlwaysVerified(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	// The registry serves the right-looking header for the wrong content, so
	// only a client that independently verifies a digest reference catches it.
	fake := content.DigestBytes([]byte("a digest nobody has"))
	f.PutManifestAt(fake, imagespec.MediaTypeImageManifest, img.ManifestJSON, img.ManifestDesc.Digest)

	c := f.Client(Options{})
	ref := f.Ref("library/alpine@" + fake)
	_, _, err := c.Resolve(context.Background(), ref, nil)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("err = %v, want ErrDigestMismatch", err)
	}
}

func TestResolveNestedIndex(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	f.AddImage(img)

	inner, innerBody := buildIndex(t, imagespec.MediaTypeImageIndex, img.ManifestDesc)
	f.AddManifest(inner.MediaType, innerBody)
	inner.Platform = &types.Platform{OS: "linux", Architecture: "amd64"}
	inner.MediaType = imagespec.MediaTypeImageIndex

	outer, outerBody := buildIndex(t, imagespec.MediaTypeImageIndex, inner)
	f.AddManifest(outer.MediaType, outerBody)
	f.Tag("library/nested", "1", outer.Digest)

	c := f.Client(Options{})
	plat := linux("amd64")
	desc, _, err := c.Resolve(context.Background(), f.Ref("library/nested:1"), &plat)
	if err != nil {
		t.Fatalf("Resolve through a nested index: %v", err)
	}
	if desc.Digest != img.ManifestDesc.Digest {
		t.Errorf("digest = %s, want %s", desc.Digest, img.ManifestDesc.Digest)
	}
}

func TestResolveRefusesThirdIndexLevel(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	f.AddImage(img)

	l3, b3 := buildIndex(t, imagespec.MediaTypeImageIndex, img.ManifestDesc)
	f.AddManifest(l3.MediaType, b3)
	l3.Platform = &types.Platform{OS: "linux", Architecture: "amd64"}

	l2, b2 := buildIndex(t, imagespec.MediaTypeImageIndex, l3)
	f.AddManifest(l2.MediaType, b2)
	l2.Platform = &types.Platform{OS: "linux", Architecture: "amd64"}

	l1, b1 := buildIndex(t, imagespec.MediaTypeImageIndex, l2)
	f.AddManifest(l1.MediaType, b1)
	f.Tag("library/deep", "1", l1.Digest)

	c := f.Client(Options{})
	plat := linux("amd64")
	_, _, err := c.Resolve(context.Background(), f.Ref("library/deep:1"), &plat)
	if !errors.Is(err, ErrIndexTooDeep) {
		t.Fatalf("err = %v, want ErrIndexTooDeep", err)
	}
}

func TestResolveSniffsWhenContentTypeIsGeneric(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	dgst := f.AddImage(img)
	f.Tag("library/alpine", "3.20", dgst)
	f.mu.Lock()
	f.ContentTypeFor[dgst] = "application/json; charset=utf-8"
	f.mu.Unlock()

	c := f.Client(Options{})
	desc, _, err := c.Resolve(context.Background(), f.Ref("library/alpine:3.20"), nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if desc.MediaType != imagespec.MediaTypeImageManifest {
		t.Errorf("mediaType = %q, want it sniffed as an OCI manifest", desc.MediaType)
	}
}

func TestResolveNotFound(t *testing.T) {
	f := newFakeRegistry(t)
	c := f.Client(Options{})
	_, _, err := c.Resolve(context.Background(), f.Ref("library/absent:1"), nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if !strings.Contains(err.Error(), "MANIFEST_UNKNOWN") {
		t.Errorf("error %q does not carry the registry's error code", err)
	}
}

func TestSelectPlatformSkipsAttestations(t *testing.T) {
	var idx imagespec.Index
	_, body := buildIndex(t, imagespec.MediaTypeImageIndex, types.Descriptor{
		MediaType: imagespec.MediaTypeImageManifest,
		Digest:    content.DigestBytes([]byte("real")),
		Size:      4,
		Platform:  &types.Platform{OS: "linux", Architecture: "amd64"},
	})
	if err := json.Unmarshal(body, &idx); err != nil {
		t.Fatal(err)
	}
	sel, have, ok := selectPlatform(idx, linux("amd64"))
	if !ok {
		t.Fatalf("selectPlatform failed; available = %v", have)
	}
	if sel.Digest != content.DigestBytes([]byte("real")) {
		t.Errorf("selected the wrong entry: %+v", sel)
	}
	if len(have) != 1 {
		t.Errorf("available = %v, want only the real platform", have)
	}
}

func TestPlatformScore(t *testing.T) {
	tests := []struct {
		name     string
		want     types.Platform
		have     types.Platform
		matching bool
	}{
		{"exact", linux("amd64"), linux("amd64"), true},
		{"os differs", linux("amd64"), types.Platform{OS: "windows", Architecture: "amd64"}, false},
		{"arch differs", linux("amd64"), linux("arm64"), false},
		{"arm64 v8 equals empty", linux("arm64"), types.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, true},
		{"empty equals arm64 v8", types.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, linux("arm64"), true},
		{"arm v6 does not satisfy v7", types.Platform{OS: "linux", Architecture: "arm", Variant: "v7"},
			types.Platform{OS: "linux", Architecture: "arm", Variant: "v6"}, false},
		{"unset variant accepts anything", linux("arm"), types.Platform{OS: "linux", Architecture: "arm", Variant: "v6"}, true},
		{"os.version must match when asked for",
			types.Platform{OS: "windows", Architecture: "amd64", OSVersion: "10.0.20348"},
			types.Platform{OS: "windows", Architecture: "amd64", OSVersion: "10.0.17763"}, false},
		{"os features must be present",
			types.Platform{OS: "linux", Architecture: "amd64", OSFeatures: []string{"sse4"}},
			linux("amd64"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := platformScore(tt.want, tt.have) >= 0
			if got != tt.matching {
				t.Errorf("platformScore(%s, %s) matching = %v, want %v",
					PlatformString(tt.want), PlatformString(tt.have), got, tt.matching)
			}
		})
	}
}

func TestValidateManifestTarget(t *testing.T) {
	tests := []struct {
		target  string
		wantErr bool
	}{
		{"3.20", false},
		{"latest", false},
		{"v1.2.3-alpine_3", false},
		{content.DigestBytes([]byte("x")), false},
		{"", true},
		{"../../etc/passwd", true},
		{"tag/with/slash", true},
		{"sha256:short", true},
		{"tag with space", true},
		{strings.Repeat("a", 200), true},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			err := validateManifestTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateManifestTarget(%q) = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
		})
	}
}

func TestResolveAllReportsTheRootDescriptor(t *testing.T) {
	f := newFakeRegistry(t)
	amd := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	f.AddImage(amd)
	idxDesc, idxBody := buildIndex(t, imagespec.MediaTypeImageIndex, amd.ManifestDesc)
	f.AddManifest(idxDesc.MediaType, idxBody)
	f.Tag("library/alpine", "3.20", idxDesc.Digest)

	c := f.Client(Options{})
	plat := linux("amd64")
	root, sel, body, err := c.ResolveAll(context.Background(), f.Ref("library/alpine:3.20"), &plat)
	if err != nil {
		t.Fatalf("ResolveAll: %v", err)
	}
	if root.Digest != idxDesc.Digest {
		t.Errorf("root = %s, want the index %s", root.Digest, idxDesc.Digest)
	}
	if !imagespec.IsManifestList(root.MediaType) {
		t.Errorf("root media type = %s, want an index", root.MediaType)
	}
	if sel.Digest != amd.ManifestDesc.Digest {
		t.Errorf("selected = %s, want %s", sel.Digest, amd.ManifestDesc.Digest)
	}
	if string(body) != string(amd.ManifestJSON) {
		t.Error("body is not the selected manifest")
	}
}

func TestResolveAllRootEqualsSelectedForASinglePlatformImage(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	dgst := f.AddImage(img)
	f.Tag("library/single", "1", dgst)

	c := f.Client(Options{})
	root, sel, _, err := c.ResolveAll(context.Background(), f.Ref("library/single:1"), nil)
	if err != nil {
		t.Fatalf("ResolveAll: %v", err)
	}
	if root.Digest != sel.Digest {
		t.Errorf("root %s != selected %s", root.Digest, sel.Digest)
	}
}
