package lockfile

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTree writes a map of relative path to contents under dir, creating
// parents as needed.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
}

const composeFixture = `# a project's services
services:
  web:
    image: nginx:1.27-alpine
    ports: ["8080:80"]
  api:
    build: .
    image: "ghcr.io/acme/api:2.3.1"   # built and pushed here
  cache:
    image: 'redis:7'
  db:
    image: postgres:16
    environment:
      POSTGRES_IMAGE_NAME: not-an-image-key
  proxy:
    image: ${REGISTRY}/proxy:latest
  tools:
    image: ${TOOLS_IMAGE:-busybox:1.36}
  broken:
    image:
volumes:
  data:
`

const dockerfileFixture = `# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.26
ARG ALPINE=3.20

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src
RUN go build -o /out/hull \
      ./cmd/hull

FROM builder AS test
RUN go test ./...

FROM alpine:${ALPINE}
COPY --from=builder /out/hull /usr/bin/hull

FROM scratch
COPY --from=builder /out/hull /hull
`

const devcontainerFixture = `{
	// Pinned by the platform team.
	"name": "hull",
	/* the base image */
	"image": "mcr.microsoft.com/devcontainers/go:1.26-bookworm",
	"features": {
		"ghcr.io/devcontainers/features/docker-in-docker:2": {},
	},
}
`

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"docker-compose.yml":              composeFixture,
		"Dockerfile":                      dockerfileFixture,
		".devcontainer/devcontainer.json": devcontainerFixture,
		"docker/worker.Dockerfile":        "FROM python:3.13-slim\nRUN pip install .\n",
		"compose.override.yml":            "services:\n  web:\n    image: nginx:1.27-alpine\n  extra:\n    image: traefik:v3.1\n",
		"node_modules/pkg/Dockerfile":     "FROM evil/should-not-be-locked:1\n",
		".git/Dockerfile":                 "FROM evil/also-not:1\n",
		"README.md":                       "image: not-from-a-real-file:1\n",
	})

	got, err := Discover(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	want := []string{
		// Every file in the root is read, in sorted name order, before any
		// subdirectory is entered: Dockerfile, then compose.override.yml, then
		// docker-compose.yml, then .devcontainer/ and docker/.
		"golang:1.26-alpine",
		"alpine:3.20",
		"nginx:1.27-alpine",
		"traefik:v3.1",
		"ghcr.io/acme/api:2.3.1",
		"redis:7",
		"postgres:16",
		"busybox:1.36",
		"mcr.microsoft.com/devcontainers/go:1.26-bookworm",
		"python:3.13-slim",
	}
	assertRefs(t, got, want)
}

func assertRefs(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d refs\n  %q\nwant %d\n  %q", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("ref %d = %q, want %q\ngot:  %q\nwant: %q", i, got[i], want[i], got, want)
		}
	}
}

func TestDiscoverCompose(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "plain and quoted values",
			body: "services:\n  a:\n    image: alpine:3.20\n  b:\n    image: \"redis:7\"\n  c:\n    image: 'busybox'\n",
			want: []string{"alpine:3.20", "redis:7", "busybox"},
		},
		{
			name: "inline comments are stripped",
			body: "services:\n  a:\n    image: alpine:3.20   # base\n",
			want: []string{"alpine:3.20"},
		},
		{
			name: "keys that merely end in image are ignored",
			body: "services:\n  a:\n    environment:\n      BASE_IMAGE: alpine:3.20\n      images: nope\n",
			want: nil,
		},
		{
			name: "unresolvable interpolation is skipped",
			body: "services:\n  a:\n    image: ${REGISTRY}/app:1\n  b:\n    image: ${TAG:-alpine:3.20}\n",
			want: []string{"alpine:3.20"},
		},
		{
			name: "list item form",
			body: "x-images:\n  - image: alpine:3.20\n",
			want: []string{"alpine:3.20"},
		},
		{
			name: "empty and malformed values are skipped",
			body: "services:\n  a:\n    image:\n  b:\n    image: NOT A REF\n  c:\n    image: UPPER/case:1\n",
			want: nil,
		},
		{
			name: "commented out service",
			body: "services:\n  a:\n    image: alpine:3.20\n#    image: ghost:1\n",
			want: []string{"alpine:3.20"},
		},
		{
			name: "crlf line endings",
			body: "services:\r\n  a:\r\n    image: alpine:3.20\r\n",
			want: []string{"alpine:3.20"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{"compose.yaml": tc.body})
			got, err := Discover(dir)
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			assertRefs(t, got, tc.want)
		})
	}
}

func TestDiscoverDockerfile(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "single stage",
			body: "FROM alpine:3.20\nRUN true\n",
			want: []string{"alpine:3.20"},
		},
		{
			name: "platform flag is stripped",
			body: "FROM --platform=linux/arm64 alpine:3.20 AS base\n",
			want: []string{"alpine:3.20"},
		},
		{
			name: "stage aliases are not images",
			body: "FROM golang:1.26 AS builder\nFROM builder AS test\nFROM BUILDER\nFROM alpine:3.20\n",
			want: []string{"golang:1.26", "alpine:3.20"},
		},
		{
			name: "scratch is not an image",
			body: "FROM scratch\nCOPY hull /hull\n",
			want: nil,
		},
		{
			name: "global arg defaults are substituted",
			body: "ARG VERSION=3.20\nFROM alpine:${VERSION}\n",
			want: []string{"alpine:3.20"},
		},
		{
			name: "bare dollar arg form",
			body: "ARG REG=ghcr.io/acme\nFROM $REG/app:1\n",
			want: []string{"ghcr.io/acme/app:1"},
		},
		{
			name: "arg default inside the expansion",
			body: "FROM alpine:${VERSION:-3.19}\n",
			want: []string{"alpine:3.19"},
		},
		{
			name: "arg with no default is unresolvable",
			body: "ARG BASE\nFROM ${BASE}\nFROM alpine:3.20\n",
			want: []string{"alpine:3.20"},
		},
		{
			name: "lowercase instruction",
			body: "from alpine:3.20 as base\n",
			want: []string{"alpine:3.20"},
		},
		{
			name: "continuation and comments between lines",
			body: "FROM alpine:3.20\nRUN apk add \\\n# a comment inside the continuation\n    curl\nFROM redis:7\n",
			want: []string{"alpine:3.20", "redis:7"},
		},
		{
			name: "backtick escape directive",
			body: "# escape=`\nFROM alpine:3.20\nRUN echo a `\n  && echo b\nFROM redis:7\n",
			want: []string{"alpine:3.20", "redis:7"},
		},
		{
			name: "duplicate FROM collapses",
			body: "FROM alpine:3.20 AS a\nFROM alpine:3.20 AS b\n",
			want: []string{"alpine:3.20"},
		},
		{
			name: "the syntax directive is not locked",
			body: "# syntax=docker/dockerfile:1.7\nFROM alpine:3.20\n",
			want: []string{"alpine:3.20"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{"Dockerfile": tc.body})
			got, err := Discover(dir)
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			assertRefs(t, got, tc.want)
		})
	}
}

func TestDiscoverDevcontainer(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "plain json",
			body: `{"name":"x","image":"alpine:3.20"}`,
			want: []string{"alpine:3.20"},
		},
		{
			name: "comments and trailing commas",
			body: devcontainerFixture,
			want: []string{"mcr.microsoft.com/devcontainers/go:1.26-bookworm"},
		},
		{
			name: "a url inside a string is not a comment",
			body: `{"image":"alpine:3.20","documentationUrl":"https://example.com/a//b"}`,
			want: []string{"alpine:3.20"},
		},
		{
			name: "build instead of image",
			body: `{"name":"x","build":{"dockerfile":"Dockerfile"}}`,
			want: nil,
		},
		{
			name: "local env interpolation is skipped",
			body: `{"image":"${localEnv:BASE_IMAGE}"}`,
			want: nil,
		},
		{
			name: "not json at all",
			body: "this is not json",
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{".devcontainer/devcontainer.json": tc.body})
			got, err := Discover(dir)
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			assertRefs(t, got, tc.want)
		})
	}
}

func TestDiscoverFileNaming(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"Dockerfile.dev":          "FROM one:1\n",
		"api.Dockerfile":          "FROM two:2\n",
		"Containerfile":           "FROM three:3\n",
		"compose.yaml":            "services:\n  a:\n    image: four:4\n",
		"docker-compose.prod.yml": "services:\n  a:\n    image: five:5\n",
		"notes.yml":               "services:\n  a:\n    image: six:6\n",
		"Dockerfile.md":           "FROM seven:7\n",
	})
	got, err := Discover(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	// Sorted file order: Containerfile, Dockerfile.dev, Dockerfile.md,
	// api.Dockerfile, compose.yaml, docker-compose.prod.yml. Dockerfile.md is
	// read as a Dockerfile because of its prefix, which is deliberate: hull
	// would rather lock one extra reference than miss a real one.
	assertRefs(t, got, []string{"three:3", "one:1", "seven:7", "two:2", "four:4", "five:5"})
}

func TestDiscoverEmptyAndMissingDirectories(t *testing.T) {
	empty := t.TempDir()
	got, err := Discover(empty)
	if err != nil {
		t.Fatalf("Discover on an empty directory: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Discover on an empty directory = %v, want nothing", got)
	}

	if _, err := Discover(filepath.Join(empty, "nope")); err == nil {
		t.Error("Discover on a missing directory returned no error")
	}

	file := filepath.Join(empty, "Dockerfile")
	if err := os.WriteFile(file, []byte("FROM alpine:3.20\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Discover(file); err == nil {
		t.Error("Discover on a file returned no error")
	}
}

func TestDiscoverStopsAtTheDepthLimit(t *testing.T) {
	dir := t.TempDir()
	deep := "a/b/c/d/e/Dockerfile"
	writeTree(t, dir, map[string]string{
		"a/b/c/d/Dockerfile": "FROM shallow:1\n",
		deep:                 "FROM toodeep:1\n",
	})
	got, err := Discover(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	assertRefs(t, got, []string{"shallow:1"})
}

func TestDiscoverIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"Dockerfile":         dockerfileFixture,
		"docker-compose.yml": composeFixture,
		"svc/a/Dockerfile":   "FROM a:1\n",
		"svc/b/Dockerfile":   "FROM b:1\n",
	})
	first, err := Discover(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := Discover(dir)
		if err != nil {
			t.Fatalf("Discover: %v", err)
		}
		assertRefs(t, again, first)
	}
}

func TestDiscoverFeedsTheLock(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"Dockerfile": "FROM alpine:3.20\n"})
	refs, err := Discover(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	l, err := Load(filepath.Join(dir, Filename))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, ref := range refs {
		l.Add(Entry{Ref: ref, Digest: digestA, Platform: amd64(), Source: "Dockerfile"})
	}
	if err := l.Save(filepath.Join(dir, Filename)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	back, err := Load(filepath.Join(dir, Filename))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := back.Lookup("alpine:3.20"); !ok {
		t.Errorf("discovered reference did not survive the round trip: %+v", back.Images)
	}
}
