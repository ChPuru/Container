package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"

	"github.com/rahuldhali/hull/internal/content"
	"github.com/rahuldhali/hull/internal/oci/imagespec"
	"github.com/rahuldhali/hull/internal/oci/reference"
	"github.com/rahuldhali/hull/internal/types"
)

// maxIndexDepth is how many nested image indexes Resolve will unwrap. One
// index pointing at another is legal and happens with some signing and
// attestation layouts; a third level is treated as a loop or an attack.
const maxIndexDepth = 2

// unknownPlatform is the placeholder buildx writes for attestation manifests,
// which must never be selected as an image.
const unknownPlatform = "unknown"

// attestationRefTypeAnnotation marks a buildx attestation manifest.
const attestationRefTypeAnnotation = "vnd.docker.reference.type"

// DefaultPlatform returns the platform hull resolves for when the caller does
// not name one: linux on the architecture this binary was built for.
func DefaultPlatform() types.Platform {
	return types.Platform{OS: "linux", Architecture: runtime.GOARCH}
}

// normalizeArch maps the architecture spellings users and registries actually
// write onto the Go names the OCI image-spec mandates.
func normalizeArch(arch string) string {
	switch strings.ToLower(arch) {
	case "x86_64", "x86-64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7l", "armv7", "arm":
		return "arm"
	case "i386", "i686", "x86", "386":
		return "386"
	default:
		return strings.ToLower(arch)
	}
}

// normalizeVariant folds the variants that mean the same thing, so that an
// index entry tagged arm64/v8 satisfies a request for plain arm64.
func normalizeVariant(arch, variant string) string {
	v := strings.ToLower(variant)
	switch normalizeArch(arch) {
	case "arm64":
		if v == "v8" {
			return ""
		}
	case "arm":
		if v == "" {
			return "v7"
		}
	}
	return v
}

// normalizePlatform fills in the defaults and canonical spellings.
func normalizePlatform(p types.Platform) types.Platform {
	out := p
	if out.OS == "" {
		out.OS = "linux"
	}
	out.OS = strings.ToLower(out.OS)
	if out.Architecture == "" {
		out.Architecture = runtime.GOARCH
	}
	out.Architecture = normalizeArch(out.Architecture)
	out.Variant = strings.ToLower(out.Variant)
	return out
}

// platformScore rates how well an index entry satisfies a request. A negative
// score means it does not satisfy it at all; higher is better.
func platformScore(want, have types.Platform) int {
	w := normalizePlatform(want)
	h := normalizePlatform(have)
	if w.OS != h.OS || w.Architecture != h.Architecture {
		return -1
	}
	if w.OSVersion != "" && w.OSVersion != h.OSVersion {
		return -1
	}
	for _, f := range w.OSFeatures {
		if !containsString(h.OSFeatures, f) {
			return -1
		}
	}
	wv := normalizeVariant(w.Architecture, w.Variant)
	hv := normalizeVariant(h.Architecture, h.Variant)
	switch {
	case w.Variant == h.Variant:
		return 4
	case wv == hv:
		return 3
	case w.Variant == "" && hv == "":
		return 2
	case w.Variant == "":
		// The caller did not care about the variant; accept any, but prefer
		// the entries above.
		return 1
	default:
		return -1
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// isAttestation reports whether an index entry is a buildx attestation rather
// than a runnable image.
func isAttestation(d types.Descriptor) bool {
	if d.Annotations[attestationRefTypeAnnotation] != "" {
		return true
	}
	if d.Platform == nil {
		return false
	}
	return strings.EqualFold(d.Platform.OS, unknownPlatform) ||
		strings.EqualFold(d.Platform.Architecture, unknownPlatform)
}

// selectPlatform picks the index entry for want, and reports the platforms the
// index does carry when nothing matches.
func selectPlatform(idx imagespec.Index, want types.Platform) (types.Descriptor, []types.Platform, bool) {
	var (
		best      types.Descriptor
		bestScore = -1
		available []types.Platform
		unplatted []types.Descriptor
	)
	for _, d := range idx.Manifests {
		if d.MediaType != "" && !imagespec.IsManifest(d.MediaType) && !imagespec.IsManifestList(d.MediaType) {
			continue
		}
		if isAttestation(d) {
			continue
		}
		if d.Platform == nil {
			unplatted = append(unplatted, d)
			continue
		}
		available = append(available, *d.Platform)
		if s := platformScore(want, *d.Platform); s > bestScore {
			best, bestScore = d, s
		}
	}
	if bestScore >= 0 {
		return best, available, true
	}
	// An index with a single entry and no platform information is what some
	// build tools emit for single-arch images; taking it is better than
	// failing, and the config's own platform is checked by the puller.
	if len(available) == 0 && len(unplatted) == 1 {
		return unplatted[0], nil, true
	}
	return types.Descriptor{}, available, false
}

// Resolve fetches the manifest for ref, descending through image indexes until
// it reaches a single-platform manifest for plat.
//
// It returns the descriptor of the manifest that was finally selected — media
// type, digest and size — together with the exact manifest bytes, which the
// caller must store verbatim because the digest covers them byte for byte.
//
// plat may be nil, which means DefaultPlatform. Dispatch is on the response
// Content-Type rather than on the Accept header, because Docker Hub serves
// whatever was pushed regardless of what the client asked for; a schema1
// manifest is refused with ErrSchema1, and an index with no entry for the
// platform yields ErrPlatformNotFound listing what the index does offer.
func (c *Client) Resolve(ctx context.Context, ref reference.Reference, plat *types.Platform) (types.Descriptor, []byte, error) {
	_, desc, body, err := c.ResolveAll(ctx, ref, plat)
	return desc, body, err
}

// ResolveAll is Resolve with the root descriptor as well: the manifest the
// reference itself names, which for a multi-platform tag is the image index
// rather than the platform manifest that was selected inside it.
//
// That root digest is the one a user can re-pull the whole multi-arch image by,
// so it is what hull records in RepoDigests and in hull.lock. For a
// single-platform reference root and selected are the same descriptor.
func (c *Client) ResolveAll(ctx context.Context, ref reference.Reference, plat *types.Platform) (root, selected types.Descriptor, body []byte, err error) {
	want := DefaultPlatform()
	if plat != nil {
		want = *plat
	}
	want = normalizePlatform(want)

	target := ref.Digest
	expect := ref.Digest
	if target == "" {
		target = ref.Tag
	}
	if target == "" {
		target = reference.DefaultTag
	}

	for depth := 0; ; depth++ {
		desc, body, err := c.fetchManifest(ctx, ref, target, expect)
		if err != nil {
			return types.Descriptor{}, types.Descriptor{}, nil, err
		}
		if depth == 0 {
			root = desc
		}

		switch {
		case imagespec.IsSchema1(desc.MediaType):
			return types.Descriptor{}, types.Descriptor{}, nil,
				&SchemaOneError{Ref: ref.FamiliarString(), MediaType: desc.MediaType}

		case imagespec.IsManifest(desc.MediaType):
			return root, desc, body, nil

		case imagespec.IsManifestList(desc.MediaType):
			if depth >= maxIndexDepth {
				return types.Descriptor{}, types.Descriptor{}, nil, fmt.Errorf(
					"registry: %s: image index nests more than %d levels deep: %w",
					ref.FamiliarString(), maxIndexDepth, ErrIndexTooDeep)
			}
			var idx imagespec.Index
			if err := json.Unmarshal(body, &idx); err != nil {
				return types.Descriptor{}, types.Descriptor{}, nil,
					fmt.Errorf("registry: %s: parsing image index: %w: %w", ref.FamiliarString(), err, ErrMalformed)
			}
			sel, have, ok := selectPlatform(idx, want)
			if !ok {
				return types.Descriptor{}, types.Descriptor{}, nil, &PlatformNotFoundError{
					Ref:  ref.FamiliarString(),
					Want: want,
					Have: have,
				}
			}
			if err := content.ValidateDigest(sel.Digest); err != nil {
				return types.Descriptor{}, types.Descriptor{}, nil,
					fmt.Errorf("registry: %s: index entry digest: %w", ref.FamiliarString(), err)
			}
			target, expect = sel.Digest, sel.Digest

		default:
			return types.Descriptor{}, types.Descriptor{}, nil, fmt.Errorf(
				"registry: %s: registry served unsupported manifest media type %q: %w",
				ref.FamiliarString(), desc.MediaType, ErrMalformed)
		}
	}
}

// fetchManifest performs one GET /v2/<name>/manifests/<target>.
//
// expect, when non-empty, is a digest the bytes must hash to. The
// Docker-Content-Digest header is verified whenever the registry sends it.
func (c *Client) fetchManifest(ctx context.Context, ref reference.Reference, target, expect string) (types.Descriptor, []byte, error) {
	if err := validateManifestTarget(target); err != nil {
		return types.Descriptor{}, nil, err
	}
	u := c.repoURL(ref, "manifests", target)
	req, err := c.newRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return types.Descriptor{}, nil, err
	}
	req.Header.Set("Accept", imagespec.AllManifestAccept())

	resp, err := c.do(ctx, req, pullScope(ref))
	if err != nil {
		return types.Descriptor{}, nil, err
	}
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return types.Descriptor{}, nil, err
	}
	if resp.ContentLength > maxManifestSize {
		drain(resp)
		return types.Descriptor{}, nil, fmt.Errorf(
			"registry: %s: manifest is %d bytes, the limit is %d: %w",
			ref.FamiliarString(), resp.ContentLength, maxManifestSize, ErrMalformed)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize+1))
	if err != nil {
		return types.Descriptor{}, nil, fmt.Errorf("registry: %s: reading manifest: %w", ref.FamiliarString(), err)
	}
	if int64(len(body)) > maxManifestSize {
		return types.Descriptor{}, nil, fmt.Errorf(
			"registry: %s: manifest exceeds the %d byte limit: %w", ref.FamiliarString(), maxManifestSize, ErrMalformed)
	}

	actual := content.DigestBytes(body)
	if hdr := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest")); hdr != "" && hdr != actual {
		return types.Descriptor{}, nil, &DigestMismatchError{
			Ref:      ref.FamiliarString(),
			Expected: hdr,
			Actual:   actual,
		}
	}
	if expect != "" && expect != actual {
		return types.Descriptor{}, nil, &DigestMismatchError{
			Ref:      ref.FamiliarString(),
			Expected: expect,
			Actual:   actual,
		}
	}

	mt := contentType(resp)
	if !isKnownManifestType(mt) {
		if sniffed := sniffManifestType(body); sniffed != "" {
			mt = sniffed
		}
	}
	return types.Descriptor{MediaType: mt, Digest: actual, Size: int64(len(body))}, body, nil
}

// validateManifestTarget refuses a tag or digest that would change the shape of
// the request URL.
func validateManifestTarget(target string) error {
	if target == "" {
		return fmt.Errorf("registry: empty manifest reference: %w", ErrMalformed)
	}
	if strings.HasPrefix(target, content.Algorithm+":") {
		return content.ValidateDigest(target)
	}
	if len(target) > reference.MaxTagLength {
		return fmt.Errorf("registry: tag %q is longer than %d characters: %w", target, reference.MaxTagLength, ErrMalformed)
	}
	for i := 0; i < len(target); i++ {
		b := target[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case b == '_', b == '.', b == '-':
		default:
			return fmt.Errorf("registry: tag %q contains an invalid character %q: %w", target, string(b), ErrMalformed)
		}
	}
	return nil
}

func isKnownManifestType(mt string) bool {
	return imagespec.IsManifest(mt) || imagespec.IsManifestList(mt) || imagespec.IsSchema1(mt)
}

// manifestShape is just enough of a manifest document to tell the kinds apart
// when a registry sends a useless Content-Type such as application/json.
type manifestShape struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Manifests     json.RawMessage   `json:"manifests"`
	Config        json.RawMessage   `json:"config"`
	Layers        json.RawMessage   `json:"layers"`
	FSLayers      json.RawMessage   `json:"fsLayers"`
	Signatures    json.RawMessage   `json:"signatures"`
	Annotations   map[string]string `json:"annotations"`
}

// sniffManifestType infers a manifest media type from the document itself.
// This is the fallback for registries that answer with application/json, and
// it is also how an unsigned schema1 manifest is recognised.
func sniffManifestType(body []byte) string {
	var s manifestShape
	if err := json.Unmarshal(body, &s); err != nil {
		return ""
	}
	if isKnownManifestType(strings.ToLower(s.MediaType)) {
		return strings.ToLower(s.MediaType)
	}
	if len(s.FSLayers) > 0 || s.SchemaVersion == 1 {
		if len(s.Signatures) > 0 {
			return imagespec.MediaTypeDockerManifestSchema1Signed
		}
		return imagespec.MediaTypeDockerManifestSchema1
	}
	if len(s.Manifests) > 0 {
		return imagespec.MediaTypeImageIndex
	}
	if len(s.Config) > 0 && len(s.Layers) > 0 {
		return imagespec.MediaTypeImageManifest
	}
	return ""
}
