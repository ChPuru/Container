package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// Three DiffIDs and the chain IDs the OCI image-spec formula produces from
// them. The expected values were computed independently of this package:
//
//	printf 'sha256:<A> sha256:<B>' | sha256sum
//	printf 'sha256:<AB> sha256:<C>' | sha256sum
const (
	diffA = "sha256:a9561eb1b190625c9adb5a9513e72c4dedafc1cb2d4c5236c9a6957ec7dfd5a9"
	diffB = "sha256:c6f988f4874bb0add23a778f753c65efe992244e148a1d2ec2a8b664fb66bbd1"
	diffC = "sha256:29f5d56d12684887bdfa50dcd29fc31eea4aaf4ad3bec43daf19026a7ce69912"

	chainAB  = "sha256:0338ef430142a7c820c611a6a60759ff8870c03d52e4813e1c18578109e7ee12"
	chainABC = "sha256:8fc4ba894f0d292a1f539247e1e3a90a85ca4daa13b141588cf20417dd2ea261"
)

func TestChainID(t *testing.T) {
	tests := []struct {
		name    string
		parent  string
		diffID  string
		want    string
		wantErr bool
	}{
		{name: "base layer is its own diff ID", parent: "", diffID: diffA, want: diffA},
		{name: "second layer", parent: diffA, diffID: diffB, want: chainAB},
		{name: "third layer", parent: chainAB, diffID: diffC, want: chainABC},
		{
			name:   "prefix is optional on both sides",
			parent: strings.TrimPrefix(diffA, "sha256:"),
			diffID: strings.TrimPrefix(diffB, "sha256:"),
			want:   chainAB,
		},
		{name: "empty diff ID", parent: "", diffID: "", wantErr: true},
		{name: "short diff ID", parent: "", diffID: "sha256:abcd", wantErr: true},
		{name: "uppercase hex", parent: "", diffID: strings.ToUpper(diffA), wantErr: true},
		{name: "other algorithm", parent: "", diffID: "sha512:" + strings.Repeat("a", 64), wantErr: true},
		{name: "bad parent", parent: "sha256:nope", diffID: diffB, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ChainID(tt.parent, tt.diffID)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ChainID(%q, %q) = %q, want an error", tt.parent, tt.diffID, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ChainID(%q, %q): %v", tt.parent, tt.diffID, err)
			}
			if got != tt.want {
				t.Fatalf("ChainID(%q, %q) = %q, want %q", tt.parent, tt.diffID, got, tt.want)
			}
		})
	}
}

// TestChainIDMatchesFormula re-derives the chain of a random-looking image with
// the spec formula spelled out, so the implementation cannot drift into, say,
// hashing the bare hex or using a different separator.
func TestChainIDMatchesFormula(t *testing.T) {
	diffIDs := []string{diffA, diffB, diffC}
	got, err := ChainIDs(diffIDs)
	if err != nil {
		t.Fatalf("ChainIDs: %v", err)
	}
	want := make([]string, len(diffIDs))
	for i, d := range diffIDs {
		if i == 0 {
			want[i] = d
			continue
		}
		sum := sha256.Sum256([]byte(want[i-1] + " " + d))
		want[i] = "sha256:" + hex.EncodeToString(sum[:])
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("chain %d = %q, want %q", i, got[i], want[i])
		}
	}
	top, err := TopChainID(diffIDs)
	if err != nil {
		t.Fatalf("TopChainID: %v", err)
	}
	if top != chainABC {
		t.Fatalf("TopChainID = %q, want %q", top, chainABC)
	}
}

func TestTopChainIDEmpty(t *testing.T) {
	top, err := TopChainID(nil)
	if err != nil {
		t.Fatalf("TopChainID(nil): %v", err)
	}
	if top != "" {
		t.Fatalf("TopChainID(nil) = %q, want empty", top)
	}
}

func TestNormalizeDigest(t *testing.T) {
	bare := strings.TrimPrefix(diffA, "sha256:")
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: diffA, want: diffA},
		{in: bare, want: diffA},
		{in: "", wantErr: true},
		{in: "sha256:" + strings.Repeat("g", 64), wantErr: true},
		{in: "md5:" + strings.Repeat("a", 64), wantErr: true},
	}
	for _, tt := range tests {
		got, err := NormalizeDigest(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("NormalizeDigest(%q) = %q, want an error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeDigest(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("NormalizeDigest(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNameForIndex(t *testing.T) {
	tests := []struct {
		index int
		want  string
	}{
		{index: 0, want: "aa"},
		{index: 1, want: "ab"},
		{index: 61, want: "aZ"},
		{index: 62, want: "ba"},
		{index: twoCharNames - 1, want: "ZZ"},
		{index: twoCharNames, want: "aaa"},
		{index: twoCharNames + 1, want: "aab"},
		{index: twoCharNames + threeCharNames, want: "aaaa"},
	}
	for _, tt := range tests {
		if got := nameForIndex(tt.index); got != tt.want {
			t.Fatalf("nameForIndex(%d) = %q, want %q", tt.index, got, tt.want)
		}
	}
}

// TestNameForIndexIsInjective checks that the dense index really is dense: no
// two indexes may share a name, or two layers would share a short link and the
// lowerdir list would be silently wrong.
func TestNameForIndexIsInjective(t *testing.T) {
	seen := make(map[string]int, twoCharNames+200)
	for i := 0; i < twoCharNames+200; i++ {
		n := nameForIndex(i)
		if len(n) < 2 || len(n) > 4 {
			t.Fatalf("nameForIndex(%d) = %q, want 2 to 4 characters", i, n)
		}
		if prev, dup := seen[n]; dup {
			t.Fatalf("nameForIndex(%d) and nameForIndex(%d) are both %q", prev, i, n)
		}
		seen[n] = i
	}
}

func TestLinkStartIndexIsInRange(t *testing.T) {
	for i := 0; i < 500; i++ {
		id := fmt.Sprintf("sha256:%064x", i)
		got := linkStartIndex(id)
		if got < 0 || got >= twoCharNames {
			t.Fatalf("linkStartIndex(%s) = %d, want 0 <= n < %d", id, got, twoCharNames)
		}
	}
}

func TestBuildOverlayOptions(t *testing.T) {
	lowers := []string{"/var/lib/hull/l/ab", "/var/lib/hull/l/cd"}
	tests := []struct {
		name      string
		lowers    []string
		upper     string
		work      string
		userxattr bool
		want      string
		wantErr   bool
	}{
		{
			name:   "writable",
			lowers: lowers,
			upper:  "/var/lib/hull/containers/c1/upper",
			work:   "/var/lib/hull/containers/c1/work",
			want: "lowerdir=/var/lib/hull/l/ab:/var/lib/hull/l/cd," +
				"upperdir=/var/lib/hull/containers/c1/upper," +
				"workdir=/var/lib/hull/containers/c1/work," +
				"redirect_dir=off,metacopy=off,index=off",
		},
		{
			name:      "rootless adds userxattr",
			lowers:    lowers,
			upper:     "/u",
			work:      "/w",
			userxattr: true,
			want:      "lowerdir=/var/lib/hull/l/ab:/var/lib/hull/l/cd,upperdir=/u,workdir=/w,redirect_dir=off,metacopy=off,index=off,userxattr",
		},
		{
			name:   "read only has no upper",
			lowers: lowers,
			want:   "lowerdir=/var/lib/hull/l/ab:/var/lib/hull/l/cd,redirect_dir=off,metacopy=off,index=off",
		},
		{name: "read only needs two lowers", lowers: lowers[:1], wantErr: true},
		{name: "no lowers at all", lowers: nil, upper: "/u", work: "/w", wantErr: true},
		{name: "colon in a lower path", lowers: []string{"/a:b", "/c"}, wantErr: true},
		{name: "comma in an upper path", lowers: lowers, upper: "/u,x", work: "/w", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildOverlayOptions(tt.lowers, tt.upper, tt.work, tt.userxattr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("buildOverlayOptions = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildOverlayOptions: %v", err)
			}
			if got != tt.want {
				t.Fatalf("buildOverlayOptions =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

// TestOverlayOptionsAlwaysPinSemantics guards the one option triple that must
// never be left to the module defaults: the WSL 6.6 kernel sets
// OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW=y, which would change what lands in the
// upperdir and therefore what a diff means.
func TestOverlayOptionsAlwaysPinSemantics(t *testing.T) {
	for _, ro := range []bool{false, true} {
		upper, work := "", ""
		if !ro {
			upper, work = "/u", "/w"
		}
		opts, err := buildOverlayOptions([]string{"/l/a", "/l/b"}, upper, work, false)
		if err != nil {
			t.Fatalf("buildOverlayOptions: %v", err)
		}
		for _, want := range []string{"redirect_dir=off", "metacopy=off", "index=off"} {
			if !strings.Contains(opts, want) {
				t.Fatalf("readonly=%v: options %q are missing %q", ro, opts, want)
			}
		}
	}
}

// TestShortLinksKeepSixtyLayersInOnePage is the reason the l/ directory exists:
// the same sixty layers written out as chain-ID paths do not fit in the single
// page mount(2) will copy, and written as short links they fit several times over.
func TestShortLinksKeepSixtyLayersInOnePage(t *testing.T) {
	const root = "/var/lib/hull"
	const layers = 60

	short := make([]string, layers)
	long := make([]string, layers)
	for i := 0; i < layers; i++ {
		short[i] = root + "/" + DirLinks + "/" + nameForIndex(i)
		long[i] = fmt.Sprintf("%s/%s/%064x/%s", root, DirSnapshots, i, DirFS)
	}
	upper := root + "/containers/" + strings.Repeat("a", 64) + "/upper"
	work := root + "/containers/" + strings.Repeat("a", 64) + "/work"

	shortOpts, err := buildOverlayOptions(short, upper, work, false)
	if err != nil {
		t.Fatalf("buildOverlayOptions(short): %v", err)
	}
	if !fitsOnePage(shortOpts) {
		t.Fatalf("%d short-link layers need %d bytes of options, the limit is %d",
			layers, len(shortOpts), MaxMountOptions)
	}
	if len(shortOpts) >= 4096 {
		t.Fatalf("short-link options are %d bytes, want under 4096", len(shortOpts))
	}

	longOpts, err := buildOverlayOptions(long, upper, work, false)
	if err != nil {
		t.Fatalf("buildOverlayOptions(long): %v", err)
	}
	if fitsOnePage(longOpts) {
		t.Fatalf("chain-ID paths for %d layers unexpectedly fit in %d bytes (%d); "+
			"this test no longer proves anything", layers, MaxMountOptions, len(longOpts))
	}
}

func TestValidateName(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
	}{
		{in: "abc123"},
		{in: "a-b_c.d"},
		{in: strings.Repeat("a", 64)},
		{in: "", wantErr: true},
		{in: ".", wantErr: true},
		{in: "..", wantErr: true},
		{in: "a/b", wantErr: true},
		{in: "a b", wantErr: true},
		{in: "a\x00b", wantErr: true},
		{in: strings.Repeat("a", 129), wantErr: true},
	}
	for _, tt := range tests {
		err := validateName("container ID", tt.in)
		if (err != nil) != tt.wantErr {
			t.Fatalf("validateName(%q) error = %v, wantErr = %v", tt.in, err, tt.wantErr)
		}
	}
}

func TestFeaturesErr(t *testing.T) {
	tests := []struct {
		name    string
		feat    Features
		wantErr bool
	}{
		{name: "usable", feat: Features{Supported: true, MountTested: true, MountOK: true}},
		{name: "no overlay in the kernel", feat: Features{}, wantErr: true},
		{name: "never probed", feat: Features{Supported: true}, wantErr: true},
		{name: "probe failed", feat: Features{Supported: true, MountTested: true, MountError: "EPERM"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.feat.Err()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Features.Err() = %v, wantErr = %v", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "overlay") {
				t.Fatalf("Features.Err() = %q, want an actionable message mentioning overlay", err)
			}
		})
	}
}

func TestChangeKindLetter(t *testing.T) {
	tests := map[ChangeKind]string{KindAdded: "A", KindModified: "C", KindDeleted: "D"}
	for k, want := range tests {
		if got := k.Letter(); got != want {
			t.Fatalf("%s.Letter() = %q, want %q", k, got, want)
		}
		if k.String() != string(k) {
			t.Fatalf("%s.String() = %q", k, k.String())
		}
	}
}
