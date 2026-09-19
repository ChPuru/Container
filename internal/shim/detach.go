package shim

import (
	"bytes"
	"fmt"
	"strings"
)

// DefaultDetachKeys is the sequence Docker uses: ctrl-p then ctrl-q.
const DefaultDetachKeys = "ctrl-p,ctrl-q"

// maxDetachKeys caps a detach sequence. The filter withholds a partial prefix
// from the container until it is resolved, so the sequence has to stay short.
const maxDetachKeys = 16

// ParseDetachKeys turns a Docker-style detach specification into the byte
// sequence it stands for. The specification is a comma-separated list of keys,
// each of which is either
//
//	a single character          e.g. "a", "," is not expressible
//	ctrl-<a-z>                  the corresponding control character, 0x01-0x1a
//	ctrl-<@[\]^_> or ctrl-?     0x00, 0x1b-0x1f and 0x7f
//
// An empty specification yields DefaultDetachKeys.
func ParseDetachKeys(spec string) ([]byte, error) {
	if spec == "" {
		spec = DefaultDetachKeys
	}
	parts := strings.Split(spec, ",")
	if len(parts) > maxDetachKeys {
		return nil, fmt.Errorf("shim: detach key sequence %q has %d keys, at most %d are allowed", spec, len(parts), maxDetachKeys)
	}
	keys := make([]byte, 0, len(parts))
	for _, p := range parts {
		b, err := parseDetachKey(p)
		if err != nil {
			return nil, fmt.Errorf("shim: detach keys %q: %w", spec, err)
		}
		keys = append(keys, b)
	}
	return keys, nil
}

// parseDetachKey parses one comma-separated element of a detach specification.
func parseDetachKey(k string) (byte, error) {
	if k == "" {
		return 0, fmt.Errorf("empty key in sequence")
	}
	if !strings.HasPrefix(k, "ctrl-") {
		if len(k) != 1 {
			return 0, fmt.Errorf("key %q is neither a single character nor ctrl-<key>", k)
		}
		return k[0], nil
	}
	rest := k[len("ctrl-"):]
	if len(rest) != 1 {
		return 0, fmt.Errorf("key %q must name exactly one character after ctrl-", k)
	}
	c := rest[0]
	switch {
	case c >= 'a' && c <= 'z':
		return c - 'a' + 1, nil
	case c >= 'A' && c <= 'Z':
		return c - 'A' + 1, nil
	case c == '@':
		return 0, nil
	case c == '[':
		return 27, nil
	case c == '\\':
		return 28, nil
	case c == ']':
		return 29, nil
	case c == '^':
		return 30, nil
	case c == '_':
		return 31, nil
	case c == '?':
		return 127, nil
	}
	return 0, fmt.Errorf("key %q is not a control character", k)
}

// detachFilter is the state machine that watches an attacher's stdin for the
// detach sequence.
//
// It is a streaming matcher: the sequence may be split across any number of
// writes. Bytes that turn out to be a partial prefix are withheld until the
// next byte decides, and forwarded verbatim the moment the match fails — so
// typing ctrl-p followed by an ordinary character sends both to the container,
// which is what a shell user expects. On a full match the filter reports
// detach and drops everything from that point in the chunk, because the
// attacher is going away.
type detachFilter struct {
	keys []byte
	buf  []byte // the matched prefix so far; always a prefix of keys
}

// newDetachFilter returns a filter for the given sequence. A nil or empty
// sequence disables detaching and makes Filter a pass-through.
func newDetachFilter(keys []byte) *detachFilter {
	d := &detachFilter{keys: keys}
	if len(keys) > 0 {
		d.buf = make([]byte, 0, len(keys))
	}
	return d
}

// Filter returns the bytes of p that must reach the container, and whether the
// detach sequence completed inside p. The returned slice may be longer than p
// when a prefix withheld by an earlier call is released, and shorter when a
// new prefix is withheld. When the sequence is empty p is returned unchanged;
// otherwise the result is a freshly allocated slice the caller owns.
func (d *detachFilter) Filter(p []byte) (out []byte, detached bool) {
	if len(d.keys) == 0 {
		return p, false
	}
	out = make([]byte, 0, len(p)+len(d.buf))
	for i := 0; i < len(p); i++ {
		d.buf = append(d.buf, p[i])
		// Shrink the candidate from the front until what is left is a prefix
		// of the sequence again. Shifting rather than resetting is what makes
		// a repeated first key ("ctrl-p,ctrl-p,ctrl-q" typed as p,p,p,q) match.
		for len(d.buf) > 0 && !bytes.HasPrefix(d.keys, d.buf) {
			out = append(out, d.buf[0])
			copy(d.buf, d.buf[1:])
			d.buf = d.buf[:len(d.buf)-1]
		}
		if len(d.buf) == len(d.keys) {
			d.buf = d.buf[:0]
			return out, true
		}
	}
	return out, false
}

// Flush releases any withheld partial prefix. It is called when the attacher's
// stdin reaches EOF, so a half-typed sequence is not swallowed.
func (d *detachFilter) Flush() []byte {
	if len(d.buf) == 0 {
		return nil
	}
	out := make([]byte, len(d.buf))
	copy(out, d.buf)
	d.buf = d.buf[:0]
	return out
}

// Pending reports how many bytes are currently withheld.
func (d *detachFilter) Pending() int { return len(d.buf) }
