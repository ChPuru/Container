package layer

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
)

func TestCleanName(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{name: "plain", in: "etc/passwd", want: "etc/passwd"},
		{name: "dot slash prefix", in: "./etc/passwd", want: "etc/passwd"},
		{name: "redundant slashes", in: "a//b///c", want: "a/b/c"},
		{name: "trailing slash", in: "usr/bin/", want: "usr/bin"},
		{name: "interior dot", in: "a/./b", want: "a/b"},
		{name: "root dir entry", in: "./", want: ""},
		{name: "bare dot", in: ".", want: ""},
		{name: "empty", in: "", want: ""},
		{name: "absolute", in: "/etc/passwd", wantErr: ErrPathEscape},
		{name: "parent escape", in: "../escape", wantErr: ErrPathEscape},
		{name: "buried parent escape", in: "a/b/../../../etc/passwd", wantErr: ErrPathEscape},
		{name: "trailing parent", in: "a/..", wantErr: ErrPathEscape},
		{name: "nul byte", in: "a\x00b", wantErr: ErrInvalidPath},
		{name: "backslash is a legal linux name", in: "a\\b", want: "a\\b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cleanName(tc.in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("cleanName(%q) error = %v, want %v", tc.in, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("cleanName(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("cleanName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		in       string
		wantDir  string
		wantBase string
	}{
		{in: "a", wantDir: "", wantBase: "a"},
		{in: "a/b", wantDir: "a", wantBase: "b"},
		{in: "a/b/c", wantDir: "a/b", wantBase: "c"},
	}
	for _, tc := range tests {
		dir, base := splitPath(tc.in)
		if dir != tc.wantDir || base != tc.wantBase {
			t.Fatalf("splitPath(%q) = (%q, %q), want (%q, %q)", tc.in, dir, base, tc.wantDir, tc.wantBase)
		}
	}
}

func TestDetectCompression(t *testing.T) {
	gz := func() []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}()

	tests := []struct {
		name string
		in   []byte
		want Compression
	}{
		{name: "gzip", in: gz, want: CompressionGzip},
		{name: "zstd", in: []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00}, want: CompressionZstd},
		{name: "xz", in: []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}, want: CompressionXz},
		{name: "bzip2", in: []byte("BZh9xxx"), want: CompressionBzip2},
		{name: "plain tar", in: bytes.Repeat([]byte{'u'}, 512), want: CompressionNone},
		{name: "empty", in: nil, want: CompressionNone},
		{name: "short", in: []byte{0x1F}, want: CompressionNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReader(bytes.NewReader(tc.in))
			got, err := DetectCompression(br)
			if err != nil {
				t.Fatalf("DetectCompression: %v", err)
			}
			if got != tc.want {
				t.Fatalf("DetectCompression = %v, want %v", got, tc.want)
			}
			// Peeking must not consume anything.
			rest, _ := br.Peek(len(tc.in))
			if !bytes.Equal(rest, tc.in) {
				t.Fatalf("DetectCompression consumed input")
			}
		})
	}
}

func TestCompressionString(t *testing.T) {
	for c, want := range map[Compression]string{
		CompressionNone:   "none",
		CompressionGzip:   "gzip",
		CompressionZstd:   "zstd",
		CompressionXz:     "xz",
		CompressionBzip2:  "bzip2",
		Compression(1234): "none",
	} {
		if got := c.String(); got != want {
			t.Fatalf("Compression(%d).String() = %q, want %q", c, got, want)
		}
	}
}

func TestApplyOptionsDefaults(t *testing.T) {
	o := ApplyOptions{}.withDefaults()
	if o.MaxEntries != DefaultMaxEntries {
		t.Fatalf("MaxEntries = %d, want %d", o.MaxEntries, DefaultMaxEntries)
	}
	if o.MaxBytes != DefaultMaxBytes {
		t.Fatalf("MaxBytes = %d, want %d", o.MaxBytes, DefaultMaxBytes)
	}
	o = ApplyOptions{MaxEntries: -1, MaxBytes: -1}.withDefaults()
	if o.MaxEntries != -1 || o.MaxBytes != -1 {
		t.Fatalf("negative caps must survive withDefaults, got %d/%d", o.MaxEntries, o.MaxBytes)
	}
}

func TestWhiteoutConstants(t *testing.T) {
	// These strings are wire format; a typo here silently corrupts every image.
	for got, want := range map[string]string{
		WhiteoutPrefix:     ".wh.",
		WhiteoutMetaPrefix: ".wh..wh.",
		WhiteoutOpaqueDir:  ".wh..wh..opq",
		WhiteoutLinkDir:    ".wh..wh.plnk",
	} {
		if got != want {
			t.Fatalf("whiteout constant = %q, want %q", got, want)
		}
	}
	if !strings.HasPrefix(WhiteoutOpaqueDir, WhiteoutMetaPrefix) {
		t.Fatal("the opaque marker must be checked before the meta prefix")
	}
}
