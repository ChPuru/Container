package lockfile

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/ChPuru/hull/internal/types"
)

// fakeResolver answers from a fixed map of reference string to manifest digest.
// Anything absent from the map is reported as not found, which is exactly how a
// registry answers for a deleted tag or a garbage-collected digest.
type fakeResolver struct {
	digests map[string]string // ref -> manifest digest
	fail    map[string]error  // ref -> hard failure
	calls   []string
	plats   []string
}

func (f *fakeResolver) Resolve(ctx context.Context, ref string, plat *types.Platform) (types.Descriptor, error) {
	f.calls = append(f.calls, ref)
	if plat == nil {
		f.plats = append(f.plats, "")
	} else {
		f.plats = append(f.plats, FormatPlatform(*plat))
	}
	if err := ctx.Err(); err != nil {
		return types.Descriptor{}, err
	}
	if err, ok := f.fail[ref]; ok {
		return types.Descriptor{}, err
	}
	d, ok := f.digests[ref]
	if !ok {
		return types.Descriptor{}, fmt.Errorf("resolve %s: %w", ref, ErrNotFound)
	}
	return types.Descriptor{
		MediaType: "application/vnd.oci.image.index.v1+json",
		Digest:    d,
		Size:      1234,
	}, nil
}

const (
	alpineTag    = "docker.io/library/alpine:3.20"
	alpinePinned = "docker.io/library/alpine@" + digestA
	redisTag     = "docker.io/library/redis:7"
	redisPinned  = "docker.io/library/redis@" + digestC
)

func TestVerify(t *testing.T) {
	tests := []struct {
		name    string
		entries []Entry
		digests map[string]string
		want    []Drift
	}{
		{
			name:    "still pinned",
			entries: []Entry{{Ref: "alpine:3.20", Digest: digestA, Platform: amd64()}},
			digests: map[string]string{alpineTag: digestA},
		},
		{
			name:    "tag moved, pin still pullable",
			entries: []Entry{{Ref: "alpine:3.20", Digest: digestA, Platform: amd64()}},
			digests: map[string]string{alpineTag: digestB, alpinePinned: digestA},
			want: []Drift{{
				Ref: "alpine:3.20", Locked: digestA, Current: digestB, Kind: KindMoved,
			}},
		},
		{
			name:    "tag moved and the locked digest is gone",
			entries: []Entry{{Ref: "alpine:3.20", Digest: digestA, Platform: amd64()}},
			digests: map[string]string{alpineTag: digestB},
			want: []Drift{{
				Ref: "alpine:3.20", Locked: digestA, Current: digestB, Kind: KindMissing,
			}},
		},
		{
			name:    "tag deleted but the pin survives",
			entries: []Entry{{Ref: "alpine:3.20", Digest: digestA}},
			digests: map[string]string{alpinePinned: digestA},
			want: []Drift{{
				Ref: "alpine:3.20", Locked: digestA, Kind: KindMoved,
			}},
		},
		{
			name:    "repository gone entirely",
			entries: []Entry{{Ref: "alpine:3.20", Digest: digestA}},
			digests: map[string]string{},
			want: []Drift{{
				Ref: "alpine:3.20", Locked: digestA, Kind: KindMissing,
			}},
		},
		{
			name:    "digest only entry still present",
			entries: []Entry{{Ref: "alpine@" + digestA, Digest: digestA}},
			digests: map[string]string{alpinePinned: digestA},
		},
		{
			name:    "digest only entry gone",
			entries: []Entry{{Ref: "alpine@" + digestA, Digest: digestA}},
			digests: map[string]string{},
			want: []Drift{{
				Ref: "alpine@" + digestA, Locked: digestA, Kind: KindMissing,
			}},
		},
		{
			name: "entry without a digest is skipped",
			entries: []Entry{
				{Ref: "alpine:3.20"},
				{Ref: "redis:7", Digest: digestC},
			},
			digests: map[string]string{redisTag: digestC},
		},
		{
			name: "several entries, drift reported in file order",
			entries: []Entry{
				{Ref: "alpine:3.20", Digest: digestA},
				{Ref: "redis:7", Digest: digestC},
			},
			digests: map[string]string{alpineTag: digestB, alpinePinned: digestA, redisTag: digestC},
			want: []Drift{{
				Ref: "alpine:3.20", Locked: digestA, Current: digestB, Kind: KindMoved,
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := &Lockfile{Version: Version, Images: tc.entries}
			r := &fakeResolver{digests: tc.digests}
			got, err := l.Verify(context.Background(), r)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d drifts %v, want %d %v", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("drift %d = %+v, want %+v", i, got[i], tc.want[i])
				}
				if got[i].String() == "" {
					t.Errorf("drift %d has an empty String()", i)
				}
			}
		})
	}
}

func TestVerifyResolvesOnceWhenNothingMoved(t *testing.T) {
	l := &Lockfile{Images: []Entry{{Ref: "alpine:3.20", Digest: digestA, Platform: amd64()}}}
	r := &fakeResolver{digests: map[string]string{alpineTag: digestA}}
	if _, err := l.Verify(context.Background(), r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(r.calls) != 1 || r.calls[0] != alpineTag {
		t.Errorf("calls = %v, want just the tag", r.calls)
	}
	if r.plats[0] != "linux/amd64" {
		t.Errorf("platform passed = %q, want linux/amd64", r.plats[0])
	}
}

func TestVerifyPassesNilPlatformWhenUnrecorded(t *testing.T) {
	l := &Lockfile{Images: []Entry{{Ref: "alpine:3.20", Digest: digestA}}}
	r := &fakeResolver{digests: map[string]string{alpineTag: digestA}}
	if _, err := l.Verify(context.Background(), r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if r.plats[0] != "" {
		t.Errorf("platform passed = %q, want the resolver default", r.plats[0])
	}
}

func TestVerifyPropagatesRealFailures(t *testing.T) {
	boom := errors.New("registry: 429 rate limited")
	l := &Lockfile{Images: []Entry{{Ref: "alpine:3.20", Digest: digestA}}}
	r := &fakeResolver{
		digests: map[string]string{},
		fail:    map[string]error{alpineTag: boom},
	}
	got, err := l.Verify(context.Background(), r)
	if err == nil {
		t.Fatalf("Verify = %v, want an error", got)
	}
	if !errors.Is(err, boom) {
		t.Errorf("Verify error = %v, want one wrapping %v", err, boom)
	}
	if got != nil {
		t.Errorf("Verify returned drifts alongside the error: %v", got)
	}
}

func TestVerifyHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l := &Lockfile{Images: []Entry{{Ref: "alpine:3.20", Digest: digestA}}}
	r := &fakeResolver{digests: map[string]string{alpineTag: digestA}}
	if _, err := l.Verify(ctx, r); !errors.Is(err, context.Canceled) {
		t.Errorf("Verify error = %v, want context.Canceled", err)
	}
	if len(r.calls) != 0 {
		t.Errorf("resolver was called after cancellation: %v", r.calls)
	}
}

func TestVerifyRejectsNilResolver(t *testing.T) {
	l := &Lockfile{}
	if _, err := l.Verify(context.Background(), nil); err == nil {
		t.Error("Verify with a nil resolver returned no error")
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"sentinel", ErrNotFound, true},
		{"wrapped sentinel", fmt.Errorf("resolve: %w", ErrNotFound), true},
		{"fs.ErrNotExist", fmt.Errorf("open: %w", fs.ErrNotExist), true},
		{"anything else", errors.New("connection reset"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsNotFound(tc.err); got != tc.want {
				t.Errorf("IsNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
