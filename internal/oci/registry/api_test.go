package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/ChPuru/hull/internal/oci/imagespec"
)

func TestPing(t *testing.T) {
	f := newFakeRegistry(t)
	c := f.Client(Options{})
	if err := c.Ping(context.Background(), f.Host()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestPingWithAuth(t *testing.T) {
	f := newFakeRegistry(t)
	f.RequireAuth = true
	f.Username = "u"
	f.Password = "p"
	c := f.Client(Options{})
	if err := c.Ping(context.Background(), f.Host()); err != nil {
		t.Fatalf("Ping against an authenticating registry: %v", err)
	}
}

func TestPingRejectsWrongCredentials(t *testing.T) {
	f := newFakeRegistry(t)
	f.RequireAuth = true
	f.Username = "u"
	f.Password = "p"
	c := f.Client(Options{Auth: &StaticAuth{Username: "u", Password: "wrong"}})
	err := c.Ping(context.Background(), f.Host())
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestPingAgainstSomethingThatIsNotARegistry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(Options{Insecure: true})
	c.baseBackoff = 0
	err := c.Ping(context.Background(), srv.Listener.Addr().String())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestTagsWithPagination(t *testing.T) {
	f := newFakeRegistry(t)
	f.TagPageSize = 2
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	dgst := f.AddImage(img)
	want := []string{"1.0", "1.1", "2.0", "2.1", "latest"}
	for _, tag := range want {
		f.Tag("library/many", tag, dgst)
	}

	c := f.Client(Options{})
	got, err := c.Tags(context.Background(), f.Ref("library/many:latest"))
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Tags = %v, want %v", got, want)
	}
	if n := f.countRequests("/tags/list"); n < 3 {
		t.Errorf("made %d tag requests, want at least 3 pages", n)
	}
}

func TestTagsOfAnUnknownRepository(t *testing.T) {
	f := newFakeRegistry(t)
	c := f.Client(Options{})
	got, err := c.Tags(context.Background(), f.Ref("library/absent:1"))
	if err != nil {
		t.Fatalf("Tags of an empty repository: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Tags = %v, want none", got)
	}
}

func TestCatalog(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	dgst := f.AddImage(img)
	for _, repo := range []string{"a/one", "b/two", "c/three", "d/four"} {
		f.Tag(repo, "latest", dgst)
	}

	c := f.Client(Options{})
	all, err := c.Catalog(context.Background(), f.Host(), 0)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if want := []string{"a/one", "b/two", "c/three", "d/four"}; !reflect.DeepEqual(all, want) {
		t.Errorf("Catalog = %v, want %v", all, want)
	}

	two, err := c.Catalog(context.Background(), f.Host(), 2)
	if err != nil {
		t.Fatalf("Catalog(n=2): %v", err)
	}
	if len(two) != 2 {
		t.Errorf("Catalog(n=2) = %v, want 2 entries", two)
	}
}

func TestDeleteByDigest(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	dgst := f.AddImage(img)
	f.Tag("me/app", "v1", dgst)

	c := f.Client(Options{})
	if err := c.Delete(context.Background(), f.Ref("me/app@"+dgst)); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	f.mu.Lock()
	_, stillThere := f.manifests[dgst]
	f.mu.Unlock()
	if stillThere {
		t.Error("the manifest is still in the registry")
	}
}

func TestDeleteByTagResolvesFirst(t *testing.T) {
	f := newFakeRegistry(t)
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	dgst := f.AddImage(img)
	f.Tag("me/app", "v1", dgst)

	c := f.Client(Options{})
	if err := c.Delete(context.Background(), f.Ref("me/app:v1")); err != nil {
		t.Fatalf("Delete by tag: %v", err)
	}
	if n := f.countRequests("DELETE /v2/me/app/manifests/" + dgst); n != 1 {
		t.Errorf("the DELETE did not go to the resolved digest; requests: %v", f.Requests)
	}
}

func TestDeleteUnsupported(t *testing.T) {
	f := newFakeRegistry(t)
	f.DeleteDenied = true
	img := buildImage(t, linux("amd64"), imagespec.MediaTypeImageManifest, 8)
	dgst := f.AddImage(img)
	f.Tag("me/app", "v1", dgst)

	c := f.Client(Options{})
	err := c.Delete(context.Background(), f.Ref("me/app@"+dgst))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

func TestNextPageLink(t *testing.T) {
	base, err := url.Parse("https://registry.example.com/v2/library/alpine/tags/list?n=100")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		header []string
		want   string
	}{
		{
			name:   "relative next",
			header: []string{`</v2/library/alpine/tags/list?n=100&last=3.20>; rel="next"`},
			want:   "https://registry.example.com/v2/library/alpine/tags/list?n=100&last=3.20",
		},
		{
			name:   "absolute next",
			header: []string{`<https://other.example.com/v2/x/tags/list?last=z>; rel="next"`},
			want:   "https://other.example.com/v2/x/tags/list?last=z",
		},
		{
			name:   "unquoted rel",
			header: []string{`</v2/x/tags/list?last=z>; rel=next`},
			want:   "https://registry.example.com/v2/x/tags/list?last=z",
		},
		{
			name:   "prev is ignored",
			header: []string{`</v2/x?p=1>; rel="prev"`},
			want:   "",
		},
		{
			name:   "two links in one header",
			header: []string{`</v2/x?p=1>; rel="prev", </v2/x?p=3>; rel="next"`},
			want:   "https://registry.example.com/v2/x?p=3",
		},
		{
			name:   "two link headers",
			header: []string{`</v2/x?p=1>; rel="prev"`, `</v2/x?p=3>; rel="next"`},
			want:   "https://registry.example.com/v2/x?p=3",
		},
		{
			name:   "none",
			header: nil,
			want:   "",
		},
		{
			name:   "malformed",
			header: []string{`not a link`},
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header:  http.Header{},
				Request: &http.Request{URL: base},
			}
			for _, h := range tt.header {
				resp.Header.Add("Link", h)
			}
			if got := nextPageLink(resp); got != tt.want {
				t.Errorf("nextPageLink = %q, want %q", got, tt.want)
			}
		})
	}
}
