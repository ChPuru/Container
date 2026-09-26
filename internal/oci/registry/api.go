package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ChPuru/hull/internal/content"
	"github.com/ChPuru/hull/internal/oci/reference"
)

// defaultPageSize is the page size hull asks for when listing tags or
// repositories. Registries are free to ignore it and page differently, which is
// why the Link header is always honoured.
const defaultPageSize = 100

// maxListPages bounds pagination so a registry that keeps returning a "next"
// link cannot loop forever.
const maxListPages = 1000

// CatalogScope is the token scope required to list a registry's repositories.
const CatalogScope = "registry:catalog:*"

// tagList is the body of GET /v2/<name>/tags/list.
type tagList struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// catalogList is the body of GET /v2/_catalog.
type catalogList struct {
	Repositories []string `json:"repositories"`
}

// Ping checks that a registry speaks the v2 distribution API and that the
// configured credentials, if any, are accepted.
//
// registry is a domain such as "docker.io", "ghcr.io" or "localhost:5000".
func (c *Client) Ping(ctx context.Context, registry string) error {
	u := c.registryURL(registry)
	req, err := c.newRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, req, "")
	if err != nil {
		return err
	}
	defer drain(resp)
	if !success(resp.StatusCode) {
		return fmt.Errorf("registry: %s does not answer the v2 API: %w", registry, statusError(resp))
	}
	return nil
}

// Tags lists every tag in the repository named by ref, following the
// registry's Link header through as many pages as it offers.
func (c *Client) Tags(ctx context.Context, ref reference.Reference) ([]string, error) {
	next := c.repoURL(ref, "tags", "list") + "?n=" + strconv.Itoa(defaultPageSize)
	scope := pullScope(ref)

	var out []string
	seen := map[string]bool{}
	for page := 0; next != "" && page < maxListPages; page++ {
		if seen[next] {
			break
		}
		seen[next] = true

		body, link, err := c.getJSONPage(ctx, next, scope)
		if err != nil {
			return nil, fmt.Errorf("registry: listing tags of %s: %w", ref.Repository(), err)
		}
		var tl tagList
		if err := json.Unmarshal(body, &tl); err != nil {
			return nil, fmt.Errorf("registry: listing tags of %s: parsing response: %w: %w",
				ref.Repository(), err, ErrMalformed)
		}
		out = append(out, tl.Tags...)
		next = link
	}
	return out, nil
}

// Catalog lists the repositories a registry offers, stopping once n names have
// been collected. A non-positive n means "as many as the registry will give".
//
// Most public registries, Docker Hub included, do not implement _catalog at
// all and answer 404 or 401; the error says so rather than pretending the
// registry is empty.
func (c *Client) Catalog(ctx context.Context, registry string, n int) ([]string, error) {
	pageSize := defaultPageSize
	if n > 0 && n < pageSize {
		pageSize = n
	}
	next := c.registryURL(registry, "_catalog") + "?n=" + strconv.Itoa(pageSize)

	var out []string
	seen := map[string]bool{}
	for page := 0; next != "" && page < maxListPages; page++ {
		if seen[next] {
			break
		}
		seen[next] = true

		body, link, err := c.getJSONPage(ctx, next, CatalogScope)
		if err != nil {
			return nil, fmt.Errorf("registry: listing repositories of %s: %w", registry, err)
		}
		var cl catalogList
		if err := json.Unmarshal(body, &cl); err != nil {
			return nil, fmt.Errorf("registry: listing repositories of %s: parsing response: %w: %w",
				registry, err, ErrMalformed)
		}
		out = append(out, cl.Repositories...)
		if n > 0 && len(out) >= n {
			return out[:n], nil
		}
		next = link
	}
	return out, nil
}

// Delete removes a manifest from the registry.
//
// Registries only accept deletion by digest, so a tagged reference is resolved
// to the digest the tag currently points at first — the tag's own manifest,
// not a platform-specific child of it. Most hosted registries refuse deletion
// entirely, which surfaces as ErrUnsupported.
func (c *Client) Delete(ctx context.Context, ref reference.Reference) error {
	dgst := ref.Digest
	if dgst == "" {
		target := ref.Tag
		if target == "" {
			target = reference.DefaultTag
		}
		desc, _, err := c.fetchManifest(ctx, ref, target, "")
		if err != nil {
			return fmt.Errorf("registry: deleting %s: resolving the tag: %w", ref.FamiliarString(), err)
		}
		dgst = desc.Digest
	}
	if err := content.ValidateDigest(dgst); err != nil {
		return fmt.Errorf("registry: deleting %s: %w", ref.FamiliarString(), err)
	}

	req, err := c.newRequest(ctx, http.MethodDelete, c.repoURL(ref, "manifests", dgst), nil)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, req, pushScope(ref))
	if err != nil {
		return err
	}
	defer drain(resp)

	switch {
	case success(resp.StatusCode):
		return nil
	case resp.StatusCode == http.StatusMethodNotAllowed, resp.StatusCode == http.StatusNotImplemented:
		return fmt.Errorf("registry: %s does not allow manifest deletion (it must be started with "+
			"REGISTRY_STORAGE_DELETE_ENABLED=true, and most hosted registries never allow it): %w",
			ref.Domain, ErrUnsupported)
	default:
		return fmt.Errorf("registry: deleting %s: %w", ref.FamiliarString(), statusError(resp))
	}
}

// getJSONPage fetches one page of a paginated listing and returns its body and
// the absolute URL of the next page, if any.
func (c *Client) getJSONPage(ctx context.Context, rawurl, scope string) ([]byte, string, error) {
	req, err := c.newRequest(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.do(ctx, req, scope)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return nil, "", err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBody+1))
	if err != nil {
		return nil, "", fmt.Errorf("registry: reading %s: %w", rawurl, err)
	}
	if int64(len(body)) > maxListBody {
		return nil, "", fmt.Errorf("registry: listing from %s exceeds the %d byte limit: %w",
			rawurl, maxListBody, ErrMalformed)
	}
	return body, nextPageLink(resp), nil
}

// nextPageLink returns the absolute URL of the rel="next" Link header, or "".
func nextPageLink(resp *http.Response) string {
	for _, hdr := range resp.Header.Values("Link") {
		for _, part := range splitLinkHeader(hdr) {
			target, rel, ok := parseLinkValue(part)
			if !ok || !strings.EqualFold(rel, "next") {
				continue
			}
			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			return resp.Request.URL.ResolveReference(u).String()
		}
	}
	return ""
}

// splitLinkHeader splits a Link header into its comma-separated values without
// splitting inside the angle-bracketed URL.
func splitLinkHeader(h string) []string {
	var (
		out    []string
		depth  int
		start  int
		quoted bool
	)
	for i := 0; i < len(h); i++ {
		switch h[i] {
		case '<':
			if !quoted {
				depth++
			}
		case '>':
			if !quoted && depth > 0 {
				depth--
			}
		case '"':
			quoted = !quoted
		case ',':
			if depth == 0 && !quoted {
				out = append(out, h[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, h[start:])
	return out
}

// parseLinkValue pulls the target and the rel parameter out of one Link value.
func parseLinkValue(v string) (target, rel string, ok bool) {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "<") {
		return "", "", false
	}
	end := strings.IndexByte(v, '>')
	if end < 0 {
		return "", "", false
	}
	target = v[1:end]
	for _, param := range strings.Split(v[end+1:], ";") {
		k, val, found := strings.Cut(strings.TrimSpace(param), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(k), "rel") {
			continue
		}
		rel = strings.Trim(strings.TrimSpace(val), `"`)
	}
	return target, rel, target != ""
}
