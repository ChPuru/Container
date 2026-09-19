// Package idutil generates and validates the identifiers hull hands out:
// container, image and endpoint IDs, short display IDs and container MAC
// addresses. Every identifier is drawn from crypto/rand; nothing here derives
// an identifier from user-visible data such as a name or an IP address,
// because that reintroduces collisions and makes IDs guessable.
//
// The package is deliberately dependency-free and builds on every GOOS, so the
// Windows CLI can call it too.
package idutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	// IDLen is the length in characters of a full hull identifier.
	IDLen = 64
	// ShortIDLen is the length in characters of a short (display) identifier.
	ShortIDLen = 12
	// idBytes is the number of random bytes behind a full identifier.
	idBytes = 32
	// digestPrefix is the algorithm prefix hull uses on content digests.
	digestPrefix = "sha256:"
)

// ErrInvalidID is returned by ValidateID for anything that is not a
// 64-character lowercase hex identifier.
var ErrInvalidID = errors.New("invalid id")

// NewID returns a fresh 64-character lowercase hex identifier backed by 32
// bytes of cryptographically secure randomness. It is used for container IDs,
// network IDs and anything else that must never collide.
//
// It panics only if the system entropy source fails, which on Linux means the
// process cannot continue safely anyway.
func NewID() string {
	id, err := NewIDFrom(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("idutil: cannot read %d bytes of entropy: %v", idBytes, err))
	}
	return id
}

// NewIDFrom reads idBytes bytes from r and returns them hex encoded. It exists
// so tests can pin a deterministic identifier; production code calls NewID.
func NewIDFrom(r io.Reader) (string, error) {
	var b [idBytes]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("idutil: read entropy: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// NewShortID returns a fresh 12-character lowercase hex identifier. It is used
// where a full ID is unnecessary (temporary directory names, veth interface
// suffixes) and never where collisions would be fatal.
func NewShortID() string {
	var b [ShortIDLen / 2]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic(fmt.Sprintf("idutil: cannot read %d bytes of entropy: %v", len(b), err))
	}
	return hex.EncodeToString(b[:])
}

// NewEndpointID returns a fresh 64-character identifier for a container's
// attachment to one network. Docker uses the same shape, so the value can be
// reported verbatim through the Docker API.
func NewEndpointID() string { return NewID() }

// TruncateID returns the first ShortIDLen characters of id, tolerating an
// optional "sha256:" prefix, which it strips first. Identifiers shorter than
// ShortIDLen are returned unchanged. It never returns an error: it is a display
// helper, not a validator.
func TruncateID(id string) string {
	id = strings.TrimPrefix(id, digestPrefix)
	if len(id) <= ShortIDLen {
		return id
	}
	return id[:ShortIDLen]
}

// ShortDigest turns a content digest such as "sha256:abc123456789..." into the
// 12-character form hull prints in tables. Any algorithm prefix ending in ':'
// is stripped, so "sha512:..." works too. A value with no prefix is treated as
// the hex part itself.
func ShortDigest(d string) string {
	if i := strings.LastIndex(d, ":"); i >= 0 {
		d = d[i+1:]
	}
	if len(d) <= ShortIDLen {
		return d
	}
	return d[:ShortIDLen]
}

// ValidateID reports whether id is a well-formed hull identifier: exactly 64
// lowercase hex characters, optionally carrying a "sha256:" prefix. Uppercase
// hex is rejected so that IDs compare byte-for-byte everywhere.
func ValidateID(id string) error {
	raw := strings.TrimPrefix(id, digestPrefix)
	if len(raw) != IDLen {
		return fmt.Errorf("%w: %q: want %d hex characters, got %d", ErrInvalidID, id, IDLen, len(raw))
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return fmt.Errorf("%w: %q: byte %d (%q) is not lowercase hex", ErrInvalidID, id, i, string(c))
	}
	return nil
}

// NewMAC returns a random locally administered, unicast MAC address for a
// container interface.
//
// The address is *not* derived from ip. Deriving a MAC from an address (the
// classic 02:42:<ip> trick) makes every engine on the same subnet hand out the
// same MAC for the same IP, which breaks as soon as two bridges overlap, and it
// leaks the address into the L2 header. Docker 28 moved to random MACs for the
// same reason. ip is folded in only as extra entropy alongside 32 bytes from
// crypto/rand, so passing nil is perfectly fine.
//
// Bit 0 of the first octet is cleared (unicast) and bit 1 is set (locally
// administered), as IEEE 802 requires for addresses that are not vendor
// assigned.
func NewMAC(ip net.IP) net.HardwareAddr {
	var seed [32]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		panic(fmt.Sprintf("idutil: cannot read %d bytes of entropy: %v", len(seed), err))
	}
	h := sha256.New()
	h.Write(seed[:])
	if len(ip) > 0 {
		h.Write(ip)
	}
	sum := h.Sum(nil)

	mac := make(net.HardwareAddr, 6)
	copy(mac, sum[:6])
	mac[0] &^= 0x01 // unicast
	mac[0] |= 0x02  // locally administered
	return mac
}
