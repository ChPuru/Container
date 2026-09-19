package registry

import (
	"strings"
)

// Challenge is one parsed WWW-Authenticate challenge.
//
// Scheme is lower-cased ("bearer", "basic", "negotiate") so callers can switch
// on it without worrying about the casing a registry happened to use, and the
// keys of Params are lower-cased for the same reason.
type Challenge struct {
	// Scheme is the lower-cased authentication scheme.
	Scheme string
	// Params holds the auth-params with lower-cased keys and unescaped values.
	Params map[string]string
	// Token68 holds the bare token68 form (as in "Negotiate YIIB...") when the
	// challenge used one instead of key=value parameters.
	Token68 string
}

// Realm returns the realm parameter, the URL of the token server for a Bearer
// challenge.
func (c Challenge) Realm() string { return c.Params["realm"] }

// Service returns the service parameter, the registry's name at its token
// server.
func (c Challenge) Service() string { return c.Params["service"] }

// Scope returns the scope parameter, the access the token server should grant.
func (c Challenge) Scope() string { return c.Params["scope"] }

// Scopes splits the scope parameter on spaces, since a challenge may request
// several scopes at once.
func (c Challenge) Scopes() []string {
	return strings.Fields(c.Scope())
}

// IsBearer reports whether this is a Bearer token challenge.
func (c Challenge) IsBearer() bool { return c.Scheme == "bearer" }

// IsBasic reports whether this is an HTTP Basic challenge.
func (c Challenge) IsBasic() bool { return c.Scheme == "basic" }

// tchar reports whether b is an RFC 7230 token character.
func tchar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

func isOWS(b byte) bool { return b == ' ' || b == '\t' }

// ParseChallenges parses a WWW-Authenticate header value into its challenges.
//
// It handles the full real-world range: quoted values with backslash escapes,
// unquoted values containing characters the grammar does not strictly allow
// (Docker Hub emits bare scope values with colons and slashes), arbitrary
// whitespace around the separators, several challenges in one header, and
// token68 forms such as "Negotiate YII...". Anything it cannot make sense of is
// skipped rather than failing the whole header, because a client that cannot
// parse an unrelated Negotiate challenge must still find the Bearer one.
func ParseChallenges(header string) []Challenge {
	var (
		out []Challenge
		cur *Challenge
	)
	s := header
	i := 0
	for i < len(s) {
		// Skip separators and whitespace between items.
		for i < len(s) && (isOWS(s[i]) || s[i] == ',') {
			i++
		}
		if i >= len(s) {
			break
		}
		start := i
		for i < len(s) && tchar(s[i]) {
			i++
		}
		if i == start {
			// Not a token at all: skip one byte and keep going, so a stray
			// quote or control character cannot wedge the parser.
			i++
			continue
		}
		name := s[start:i]

		j := i
		for j < len(s) && isOWS(s[j]) {
			j++
		}
		if j >= len(s) || s[j] != '=' {
			// No "=" follows: this token names a new scheme.
			out = append(out, Challenge{Scheme: strings.ToLower(name), Params: map[string]string{}})
			cur = &out[len(out)-1]
			i = j
			continue
		}

		// A "=" follows. It is either an auth-param or the padding of a
		// token68 value that immediately follows a scheme.
		eq := j
		pad := eq
		for pad < len(s) && s[pad] == '=' {
			pad++
		}
		atDelim := pad >= len(s) || isOWS(s[pad]) || s[pad] == ','
		if atDelim && cur != nil && len(cur.Params) == 0 && cur.Token68 == "" {
			cur.Token68 = s[start:pad]
			i = pad
			continue
		}

		i = eq + 1
		var value string
		value, i = parseAuthParamValue(s, i)
		if cur == nil {
			// A parameter with no scheme in front of it is nonsense; drop it.
			continue
		}
		cur.Params[strings.ToLower(name)] = value
	}
	return out
}

// parseAuthParamValue reads one auth-param value starting at i and returns it
// with the index just past it.
func parseAuthParamValue(s string, i int) (string, int) {
	for i < len(s) && isOWS(s[i]) {
		i++
	}
	if i < len(s) && s[i] == '"' {
		i++
		var b strings.Builder
		for i < len(s) {
			c := s[i]
			if c == '\\' && i+1 < len(s) {
				b.WriteByte(s[i+1])
				i += 2
				continue
			}
			if c == '"' {
				i++
				break
			}
			b.WriteByte(c)
			i++
		}
		return b.String(), i
	}
	start := i
	for i < len(s) && s[i] != ',' && !isOWS(s[i]) {
		i++
	}
	return s[start:i], i
}

// pickChallenge chooses the challenge hull can act on, preferring Bearer over
// Basic and ignoring schemes it does not implement. It reports false when the
// header carried nothing usable.
func pickChallenge(chs []Challenge) (Challenge, bool) {
	var basic Challenge
	haveBasic := false
	for _, ch := range chs {
		if ch.IsBearer() && ch.Realm() != "" {
			return ch, true
		}
		if ch.IsBasic() && !haveBasic {
			basic, haveBasic = ch, true
		}
	}
	if haveBasic {
		return basic, true
	}
	return Challenge{}, false
}
