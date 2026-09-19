package content

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const emptyDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestValidateDigest(t *testing.T) {
	t.Parallel()
	good := strings.Repeat("ab", 32)
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"canonical", "sha256:" + good, false},
		{"empty blob digest", emptyDigest, false},
		{"empty string", "", true},
		{"no prefix", good, true},
		{"wrong algorithm", "sha512:" + good, true},
		{"uppercase hex", "sha256:" + strings.ToUpper(good), true},
		{"too short", "sha256:" + good[:63], true},
		{"too long", "sha256:" + good + "a", true},
		{"non hex", "sha256:" + strings.Repeat("g", 64), true},
		{"path traversal", "sha256:../../../etc/shadow", true},
		{"slash inside", "sha256:" + good[:32] + "/" + good[33:], true},
		{"nul byte", "sha256:" + good[:63] + "\x00", true},
		{"prefix only", "sha256:", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateDigest(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateDigest(%q) = nil, want an error", tc.in)
				}
				if !errors.Is(err, ErrInvalidDigest) {
					t.Fatalf("ValidateDigest(%q) = %v, want ErrInvalidDigest", tc.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateDigest(%q) = %v, want nil", tc.in, err)
			}
		})
	}
}

func TestDigestBytesAndReader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, emptyDigest},
		{"abc", []byte("abc"), "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := DigestBytes(tc.in); got != tc.want {
				t.Fatalf("DigestBytes = %s, want %s", got, tc.want)
			}
			got, n, err := DigestReader(bytes.NewReader(tc.in))
			if err != nil {
				t.Fatalf("DigestReader: %v", err)
			}
			if got != tc.want {
				t.Fatalf("DigestReader = %s, want %s", got, tc.want)
			}
			if n != int64(len(tc.in)) {
				t.Fatalf("DigestReader size = %d, want %d", n, len(tc.in))
			}
			if err := ValidateDigest(got); err != nil {
				t.Fatalf("computed digest is not canonical: %v", err)
			}
		})
	}
}

func TestShortDigest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"canonical", emptyDigest, "e3b0c44298fc"},
		{"bare hex", emptyDigest[7:], "e3b0c44298fc"},
		{"already short", "abc", "abc"},
		{"empty", "", ""},
		{"short with prefix", "sha256:abcd", "abcd"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ShortDigest(tc.in); got != tc.want {
				t.Fatalf("ShortDigest(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
