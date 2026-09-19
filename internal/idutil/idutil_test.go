package idutil

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"
)

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

func TestNewIDShape(t *testing.T) {
	tests := []struct {
		name string
		gen  func() string
		want int
	}{
		{"NewID", NewID, IDLen},
		{"NewEndpointID", NewEndpointID, IDLen},
		{"NewShortID", NewShortID, ShortIDLen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(map[string]bool, 256)
			for i := 0; i < 256; i++ {
				got := tt.gen()
				if len(got) != tt.want {
					t.Fatalf("len(%q) = %d, want %d", got, len(got), tt.want)
				}
				if !isLowerHex(got) {
					t.Fatalf("%q is not lowercase hex", got)
				}
				if seen[got] {
					t.Fatalf("duplicate id %q after %d draws", got, i)
				}
				seen[got] = true
			}
		})
	}
}

func TestNewIDFrom(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    string
		wantErr bool
	}{
		{
			name: "all zero",
			in:   make([]byte, idBytes),
			want: strings.Repeat("00", idBytes),
		},
		{
			name: "all ff",
			in:   bytes.Repeat([]byte{0xff}, idBytes),
			want: strings.Repeat("ff", idBytes),
		},
		{
			name: "extra bytes ignored",
			in:   bytes.Repeat([]byte{0xab}, idBytes+16),
			want: strings.Repeat("ab", idBytes),
		},
		{
			name:    "short read",
			in:      make([]byte, idBytes-1),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewIDFrom(bytes.NewReader(tt.in))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NewIDFrom() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewIDFrom() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("NewIDFrom() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTruncateID(t *testing.T) {
	full := strings.Repeat("a1b2c3d4", 8) // 64 chars
	tests := []struct {
		name, in, want string
	}{
		{"full id", full, "a1b2c3d4a1b2"},
		{"digest prefix", "sha256:" + full, "a1b2c3d4a1b2"},
		{"exactly short", "0123456789ab", "0123456789ab"},
		{"shorter than short", "abc", "abc"},
		{"empty", "", ""},
		{"prefix only", "sha256:", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TruncateID(tt.in); got != tt.want {
				t.Fatalf("TruncateID(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestShortDigest(t *testing.T) {
	full := strings.Repeat("abc12345", 8)
	tests := []struct {
		name, in, want string
	}{
		{"sha256", "sha256:" + full, "abc12345abc1"},
		{"sha512", "sha512:" + full, "abc12345abc1"},
		{"bare hex", full, "abc12345abc1"},
		{"short", "sha256:abcd", "abcd"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShortDigest(tt.in); got != tt.want {
				t.Fatalf("ShortDigest(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateID(t *testing.T) {
	full := strings.Repeat("0123456789abcdef", 4)
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid", full, true},
		{"valid with prefix", "sha256:" + full, true},
		{"empty", "", false},
		{"too short", full[:63], false},
		{"too long", full + "0", false},
		{"uppercase", strings.ToUpper(full), false},
		{"non hex", strings.Repeat("g", 64), false},
		{"short id", NewShortID(), false},
		{"generated", NewID(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateID(tt.in)
			if tt.ok && err != nil {
				t.Fatalf("ValidateID(%q) = %v, want nil", tt.in, err)
			}
			if !tt.ok {
				if err == nil {
					t.Fatalf("ValidateID(%q) = nil, want error", tt.in)
				}
				if !errors.Is(err, ErrInvalidID) {
					t.Fatalf("ValidateID(%q) error = %v, want ErrInvalidID", tt.in, err)
				}
			}
		})
	}
}

func TestNewMAC(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
	}{
		{"nil ip", nil},
		{"ipv4", net.IPv4(10, 66, 0, 2)},
		{"ipv4 short form", net.IPv4(10, 66, 0, 2).To4()},
		{"ipv6", net.ParseIP("fd00::1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(map[string]bool, 128)
			for i := 0; i < 128; i++ {
				mac := NewMAC(tt.ip)
				if len(mac) != 6 {
					t.Fatalf("len(mac) = %d, want 6", len(mac))
				}
				if mac[0]&0x01 != 0 {
					t.Fatalf("mac %s is multicast", mac)
				}
				if mac[0]&0x02 == 0 {
					t.Fatalf("mac %s is not locally administered", mac)
				}
				if _, err := net.ParseMAC(mac.String()); err != nil {
					t.Fatalf("ParseMAC(%q): %v", mac.String(), err)
				}
				if seen[mac.String()] {
					t.Fatalf("duplicate mac %s after %d draws", mac, i)
				}
				seen[mac.String()] = true
			}
		})
	}
}

// TestNewMACNotDerivedFromIP is the regression test for bocker's bug: the same
// IP must not produce the same MAC twice.
func TestNewMACNotDerivedFromIP(t *testing.T) {
	ip := net.IPv4(10, 66, 0, 7)
	a, b := NewMAC(ip), NewMAC(ip)
	if a.String() == b.String() {
		t.Fatalf("NewMAC is deterministic in the IP: %s == %s", a, b)
	}
}

func BenchmarkNewID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewID()
	}
}
