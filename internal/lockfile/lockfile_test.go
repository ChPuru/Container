package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

func amd64() types.Platform { return types.Platform{OS: "linux", Architecture: "amd64"} }
func arm64() types.Platform {
	return types.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
}

const (
	digestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	digestC = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func sampleLock() *Lockfile {
	return &Lockfile{
		Version:   Version,
		Generated: time.Date(2026, 9, 19, 10, 30, 0, 0, time.UTC),
		Platform:  "linux/amd64",
		Images: []Entry{
			{
				Ref:          "redis:7",
				ResolvedRef:  "docker.io/library/redis:7@" + digestC,
				Digest:       digestC,
				ConfigDigest: digestA,
				Size:         1583,
				Platform:     amd64(),
				Created:      time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
				Source:       "docker-compose.yml",
			},
			{
				Ref:         "alpine:3.20",
				ResolvedRef: "docker.io/library/alpine:3.20@" + digestA,
				Digest:      digestA,
				Size:        612,
				Platform:    amd64(),
				Source:      "Dockerfile",
			},
			{
				Ref:      "alpine:3.20",
				Digest:   digestB,
				Platform: arm64(),
				Source:   "Dockerfile",
			},
		},
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	want := sampleLock()
	if err := want.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Version != want.Version || got.Platform != want.Platform {
		t.Errorf("header = {%d %q}, want {%d %q}", got.Version, got.Platform, want.Version, want.Platform)
	}
	if !got.Generated.Equal(want.Generated) {
		t.Errorf("Generated = %v, want %v", got.Generated, want.Generated)
	}
	if len(got.Images) != len(want.Images) {
		t.Fatalf("got %d images, want %d", len(got.Images), len(want.Images))
	}
	for i, e := range got.Images {
		w := want.Images[i] // want was sorted in place by Save
		if e.Ref != w.Ref || e.Digest != w.Digest || e.ConfigDigest != w.ConfigDigest ||
			e.ResolvedRef != w.ResolvedRef || e.Size != w.Size || e.Source != w.Source {
			t.Errorf("entry %d = %+v, want %+v", i, e, w)
		}
		if FormatPlatform(e.Platform) != FormatPlatform(w.Platform) {
			t.Errorf("entry %d platform = %q, want %q", i, FormatPlatform(e.Platform), FormatPlatform(w.Platform))
		}
		if !e.Created.Equal(w.Created) {
			t.Errorf("entry %d created = %v, want %v", i, e.Created, w.Created)
		}
	}
}

func TestSaveIsStableAndDiffFriendly(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.lock")
	second := filepath.Join(dir, "second.lock")

	a := sampleLock()
	if err := a.Save(first); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Same content, entries added in the opposite order.
	b := &Lockfile{Version: Version, Generated: a.Generated, Platform: a.Platform}
	for i := len(a.Images) - 1; i >= 0; i-- {
		b.Add(a.Images[i])
	}
	if err := b.Save(second); err != nil {
		t.Fatalf("Save: %v", err)
	}

	da, err := os.ReadFile(first)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	db, err := os.ReadFile(second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(da) != string(db) {
		t.Errorf("insertion order changed the file:\n--- first ---\n%s\n--- second ---\n%s", da, db)
	}

	text := string(da)
	if !strings.HasSuffix(text, "}\n") {
		t.Errorf("file does not end with a single trailing newline: %q", text[max(0, len(text)-8):])
	}
	if !strings.Contains(text, `"`+CommentField+`": "`+Comment+`"`) {
		t.Errorf("comment banner missing from:\n%s", text)
	}
	if i := strings.Index(text, `"version"`); i < 0 || i < strings.Index(text, CommentField) {
		t.Errorf("version key is not after the comment banner:\n%s", text)
	}
	if strings.Contains(text, "0001-01-01") {
		t.Errorf("zero times were written out:\n%s", text)
	}

	// Re-saving what was loaded must reproduce the bytes exactly.
	reloaded, err := Load(first)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	third := filepath.Join(dir, "third.lock")
	if err := reloaded.Save(third); err != nil {
		t.Fatalf("Save: %v", err)
	}
	dc, err := os.ReadFile(third)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(dc) != string(da) {
		t.Errorf("round trip changed the bytes:\n--- before ---\n%s\n--- after ---\n%s", da, dc)
	}
}

func TestSaveLeavesNoTempDebris(t *testing.T) {
	dir := t.TempDir()
	if err := sampleLock().Save(filepath.Join(dir, Filename)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(ents) != 1 || ents[0].Name() != Filename {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want just %s", names, Filename)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	tests := []struct {
		name    string
		path    string
		want    *Lockfile
		wantErr error
	}{
		{
			name: "missing file is an empty lock",
			path: filepath.Join(dir, "does-not-exist.lock"),
			want: &Lockfile{Version: Version},
		},
		{
			name: "empty file is an empty lock",
			path: write("empty.lock", "\n  \n"),
			want: &Lockfile{Version: Version},
		},
		{
			name: "hand written without a version",
			path: write("noversion.lock", `{"images":[{"ref":"alpine:3.20","digest":"`+digestA+`"}]}`),
			want: &Lockfile{Version: Version, Images: []Entry{{Ref: "alpine:3.20", Digest: digestA}}},
		},
		{
			name:    "newer schema is refused",
			path:    write("future.lock", `{"version":99,"images":[]}`),
			wantErr: ErrUnsupportedVersion,
		},
		{
			name:    "malformed json is an error",
			path:    write("broken.lock", `{"version":1,`),
			wantErr: nil, // any error will do; checked below
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Load(tc.path)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("Load(%s) = %+v, want an error", tc.path, got)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("Load error = %v, want one matching %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got.Version != tc.want.Version || len(got.Images) != len(tc.want.Images) {
				t.Fatalf("Load = %+v, want %+v", got, tc.want)
			}
			for i := range got.Images {
				if got.Images[i].Ref != tc.want.Images[i].Ref || got.Images[i].Digest != tc.want.Images[i].Digest {
					t.Errorf("entry %d = %+v, want %+v", i, got.Images[i], tc.want.Images[i])
				}
			}
		})
	}
}

func TestLoadRejectsMalformedAndFutureVersions(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.lock")
	if err := os.WriteFile(broken, []byte(`{"version":1,`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(broken); err == nil {
		t.Error("Load of malformed json returned no error")
	}

	future := filepath.Join(dir, "future.lock")
	if err := os.WriteFile(future, []byte(`{"version":99}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(future); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("Load of a future version = %v, want ErrUnsupportedVersion", err)
	}
}

func TestAddAndLookup(t *testing.T) {
	l := &Lockfile{}
	l.Add(Entry{Ref: "alpine:3.20", Digest: digestA, Platform: amd64(), Source: "Dockerfile"})
	l.Add(Entry{Ref: "alpine:3.20", Digest: digestB, Platform: arm64(), Source: "Dockerfile"})
	// Same reference in canonical form and the same platform: replaces.
	l.Add(Entry{Ref: "docker.io/library/alpine:3.20", Digest: digestC, Platform: amd64(), Source: "compose.yml"})

	if len(l.Images) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(l.Images), l.Images)
	}

	tests := []struct {
		name       string
		lookup     string
		wantFound  bool
		wantDigest string
	}{
		{"familiar spelling", "alpine:3.20", true, digestC},
		{"canonical spelling", "docker.io/library/alpine:3.20", true, digestC},
		{"different tag", "alpine:3.19", false, ""},
		{"unknown image", "busybox", false, ""},
		{"unparseable", "NOT A REF", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := l.Lookup(tc.lookup)
			if ok != tc.wantFound {
				t.Fatalf("Lookup(%q) found = %v, want %v", tc.lookup, ok, tc.wantFound)
			}
			if ok && got.Digest != tc.wantDigest {
				t.Errorf("Lookup(%q).Digest = %s, want %s", tc.lookup, got.Digest, tc.wantDigest)
			}
		})
	}
}

func TestLookupDefaultsTheTag(t *testing.T) {
	l := &Lockfile{Images: []Entry{{Ref: "busybox:latest", Digest: digestA}}}
	if _, ok := l.Lookup("busybox"); !ok {
		t.Error(`Lookup("busybox") did not find busybox:latest`)
	}
}

func TestRemove(t *testing.T) {
	l := &Lockfile{Images: []Entry{
		{Ref: "alpine:3.20", Digest: digestA, Platform: amd64()},
		{Ref: "alpine:3.20", Digest: digestB, Platform: arm64()},
		{Ref: "redis:7", Digest: digestC},
	}}
	if !l.Remove("docker.io/library/alpine:3.20") {
		t.Error("Remove reported nothing removed")
	}
	if len(l.Images) != 1 || l.Images[0].Ref != "redis:7" {
		t.Errorf("after Remove: %+v", l.Images)
	}
	if l.Remove("nothing:here") {
		t.Error("Remove of an absent ref reported a removal")
	}
}

func TestPlatformFormatting(t *testing.T) {
	tests := []struct {
		name    string
		plat    types.Platform
		want    string
		parseIn string
		wantErr bool
	}{
		{name: "zero", plat: types.Platform{}, want: "", parseIn: ""},
		{name: "os arch", plat: amd64(), want: "linux/amd64", parseIn: "linux/amd64"},
		{name: "with variant", plat: arm64(), want: "linux/arm64/v8", parseIn: "linux/arm64/v8"},
		{name: "one component", parseIn: "linux", wantErr: true},
		{name: "four components", parseIn: "a/b/c/d", wantErr: true},
		{name: "empty component", parseIn: "linux//v8", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.wantErr && tc.want != FormatPlatform(tc.plat) {
				t.Errorf("FormatPlatform(%+v) = %q, want %q", tc.plat, FormatPlatform(tc.plat), tc.want)
			}
			got, err := ParsePlatform(tc.parseIn)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParsePlatform(%q) = %+v, want an error", tc.parseIn, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePlatform(%q): %v", tc.parseIn, err)
			}
			if FormatPlatform(got) != tc.want {
				t.Errorf("ParsePlatform(%q) = %+v, want %q", tc.parseIn, got, tc.want)
			}
		})
	}
}

func TestSaveFillsVersionAndGenerated(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	l := &Lockfile{}
	before := time.Now().UTC().Add(-time.Second)
	if err := l.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if l.Version != Version {
		t.Errorf("Version = %d, want %d", l.Version, Version)
	}
	if l.Generated.Before(before) {
		t.Errorf("Generated = %v, want at or after %v", l.Generated, before)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), `"images": []`) {
		t.Errorf("empty images marshalled as null, not []:\n%s", data)
	}
}
