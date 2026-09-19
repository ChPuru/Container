package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rahuldhali/hull/internal/oci/reference"
)

// discoverMaxDepth is how far below the project root Discover walks. Four
// levels reaches the shapes real projects use - ./docker/api/Dockerfile,
// ./.devcontainer/go/devcontainer.json - without turning a lock into a
// whole-disk crawl.
const discoverMaxDepth = 4

// skipDirs are directory names Discover never descends into. They are either
// dependency trees full of other people's Dockerfiles or build output full of
// copies of the project's own.
var skipDirs = map[string]bool{
	".git":         true,
	".hull":        true,
	".next":        true,
	".terraform":   true,
	".venv":        true,
	"__pycache__":  true,
	"bin":          true,
	"build":        true,
	"dist":         true,
	"node_modules": true,
	"obj":          true,
	"target":       true,
	"testdata":     true,
	"vendor":       true,
}

// Discover finds the image references a project depends on.
//
// It walks dir to a bounded depth and reads three kinds of file:
//
//   - compose files (compose.yml, docker-compose.yaml, compose.override.yml and
//     friends): every "image:" value;
//   - Dockerfiles (Dockerfile, Dockerfile.dev, api.Dockerfile, Containerfile):
//     every FROM, with --platform flags stripped, global ARG defaults
//     substituted, "scratch" ignored, and stage aliases resolved so that the
//     second half of "FROM golang AS builder ... FROM builder" contributes
//     nothing;
//   - devcontainer.json (comments and trailing commas tolerated): the "image"
//     field.
//
// The references come back in discovery order - directories and files visited
// in sorted name order, matches in the order they appear in each file - and are
// de-duplicated by canonical form, so "alpine:3.20" and
// "docker.io/library/alpine:3.20" collapse to whichever the project wrote
// first. Each is returned exactly as the project spells it.
//
// Discover is deliberately forgiving. A value it cannot make sense of - an
// unexpanded "${REGISTRY}/app", a compose file with an unusual shape, a
// devcontainer.json that is not JSON at all - is skipped rather than turned
// into an error, because a lock over the references that did parse is far more
// useful than no lock at all. Only a dir that cannot be read is an error.
func Discover(dir string) ([]string, error) {
	if dir == "" {
		dir = "."
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("lockfile: discover %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("lockfile: discover %s: not a directory", dir)
	}

	var (
		out  []string
		seen = map[string]bool{}
	)
	add := func(refs []string) {
		for _, ref := range refs {
			key := canonical(ref)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ref)
		}
	}

	if err := walk(dir, 0, add); err != nil {
		return nil, err
	}
	return out, nil
}

// walk visits one directory, scanning its files before descending, both in
// sorted name order so that the result is reproducible.
func walk(dir string, depth int, add func([]string)) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if depth == 0 {
			return fmt.Errorf("lockfile: discover %s: %w", dir, err)
		}
		// A subdirectory we may not read is not a reason to fail the lock.
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		scan := scannerFor(name)
		if scan == nil {
			continue
		}
		data, ok := readCapped(filepath.Join(dir, name))
		if !ok {
			continue
		}
		add(scan(data))
	}

	if depth >= discoverMaxDepth {
		return nil
	}
	for _, ent := range entries {
		if !ent.IsDir() || !descend(ent.Name()) {
			continue
		}
		if err := walk(filepath.Join(dir, ent.Name()), depth+1, add); err != nil {
			return err
		}
	}
	return nil
}

// descend reports whether a subdirectory is worth walking into. Hidden
// directories are skipped, .devcontainer excepted, because that is precisely
// where devcontainer.json lives.
func descend(name string) bool {
	if skipDirs[strings.ToLower(name)] {
		return false
	}
	if strings.HasPrefix(name, ".") {
		return strings.EqualFold(name, ".devcontainer")
	}
	return true
}

// readCapped reads a file, refusing anything implausibly large. The bool is
// false when the file could not be read or was skipped.
func readCapped(path string) ([]byte, bool) {
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxFileSize {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

// scannerFor picks the scanner for a file name, or nil when the file is not one
// Discover reads.
func scannerFor(name string) func([]byte) []string {
	lower := strings.ToLower(name)
	switch {
	case lower == "devcontainer.json":
		return scanDevcontainer
	case isComposeName(lower):
		return scanCompose
	case isDockerfileName(lower):
		return scanDockerfile
	}
	return nil
}

// isComposeName matches the compose file names the spec and Docker's own loader
// accept, including the overlay forms (compose.override.yml,
// docker-compose.prod.yaml).
func isComposeName(lower string) bool {
	base, ok := trimSuffixAny(lower, ".yml", ".yaml")
	if !ok {
		return false
	}
	return base == "compose" || base == "docker-compose" ||
		strings.HasPrefix(base, "compose.") || strings.HasPrefix(base, "docker-compose.")
}

// isDockerfileName matches Dockerfile, Containerfile and their suffixed and
// prefixed variants.
func isDockerfileName(lower string) bool {
	switch lower {
	case "dockerfile", "containerfile":
		return true
	}
	return strings.HasPrefix(lower, "dockerfile.") ||
		strings.HasPrefix(lower, "containerfile.") ||
		strings.HasSuffix(lower, ".dockerfile") ||
		strings.HasSuffix(lower, ".containerfile")
}

// trimSuffixAny trims the first matching suffix, reporting whether one matched.
func trimSuffixAny(s string, suffixes ...string) (string, bool) {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return strings.TrimSuffix(s, suf), true
		}
	}
	return "", false
}

// ---------- compose ----------

// scanCompose pulls every "image:" value out of a compose file.
//
// This is a scanner, not a YAML parser: hull takes no third-party modules, and
// the one shape that matters here - a scalar value after an "image:" key - is
// unambiguous at the line level. Quoting, inline comments and list-item
// indentation are handled; block scalars, anchors and aliases are not, and a
// value that still contains "$" after ${VAR:-default} substitution is skipped
// because nothing here can know what the environment will hold.
func scanCompose(data []byte) []string {
	var refs []string
	for _, raw := range splitLines(data) {
		line := strings.TrimLeft(raw, " \t")
		line = strings.TrimPrefix(line, "- ")
		line = strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(line, "image:") {
			continue
		}
		value := strings.TrimSpace(line[len("image:"):])
		if ref, ok := composeValue(value); ok {
			refs = append(refs, ref)
		}
	}
	return refs
}

// composeValue turns the text after "image:" into a reference, or reports that
// it is not one.
func composeValue(value string) (string, bool) {
	value = stripInlineComment(value)
	value = unquote(value)
	value = expandShellDefaults(value)
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "${}") {
		return "", false
	}
	if _, err := reference.Parse(value); err != nil {
		return "", false
	}
	return value, true
}

// stripInlineComment removes a trailing YAML comment. A "#" only starts a
// comment when it follows whitespace and sits outside quotes, so
// "myregistry.io/team/app#1" survives intact.
func stripInlineComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

// unquote removes one layer of matching single or double quotes.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// expandShellDefaults replaces ${VAR:-default} and ${VAR-default} with their
// default, which is the one interpolation whose value is written down in the
// file itself. Everything else is left alone so the caller can see the "$" and
// skip the value.
func expandShellDefaults(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '$' && i+1 < len(s) && s[i+1] == '{' {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				b.WriteString(s[i:])
				break
			}
			inner := s[i+2 : i+end]
			if j := strings.Index(inner, ":-"); j >= 0 {
				b.WriteString(inner[j+2:])
				i += end + 1
				continue
			}
			if j := strings.Index(inner, "-"); j >= 0 && !strings.ContainsAny(inner[:j], ":?") {
				b.WriteString(inner[j+1:])
				i += end + 1
				continue
			}
			b.WriteString(s[i : i+end+1])
			i += end + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// ---------- Dockerfile ----------

// scanDockerfile pulls every FROM image out of a Dockerfile.
//
// It honours the things that change what a FROM line means: the "# escape="
// parser directive, line continuations, comment lines inside a continuation,
// the --platform flag, global ARG defaults (the only ARGs a FROM may use), and
// stage aliases. A FROM naming an earlier stage, or "scratch", yields no
// reference, because neither is an image anyone pulls.
func scanDockerfile(data []byte) []string {
	lines := splitLines(data)
	escape := dockerfileEscape(lines)

	var (
		refs      []string
		stages    = map[string]bool{}
		args      = map[string]string{}
		sawFrom   bool
		logical   strings.Builder
		continued bool
	)

	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if !continued && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if continued && strings.HasPrefix(trimmed, "#") {
			// Comment lines inside a continuation are dropped, as the builder
			// drops them, without ending the continuation.
			continue
		}
		body := strings.TrimRight(raw, " \t")
		if n := len(body); n > 0 && body[n-1] == escape {
			logical.WriteString(body[:n-1])
			logical.WriteByte(' ')
			continued = true
			continue
		}
		logical.WriteString(body)
		line := logical.String()
		logical.Reset()
		continued = false

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "ARG":
			if !sawFrom {
				for _, f := range fields[1:] {
					name, value, ok := strings.Cut(f, "=")
					if !ok {
						value = ""
					}
					args[name] = unquote(value)
				}
			}
		case "FROM":
			sawFrom = true
			image, alias := parseFrom(fields[1:], args)
			if alias != "" {
				stages[strings.ToLower(alias)] = true
			}
			if image == "" || stages[strings.ToLower(image)] || strings.EqualFold(image, "scratch") {
				continue
			}
			if _, err := reference.Parse(image); err != nil {
				continue
			}
			refs = append(refs, image)
		}
	}
	return refs
}

// parseFrom reads the arguments of a FROM instruction, returning the image and
// the stage alias, either of which may be empty.
func parseFrom(fields []string, args map[string]string) (image, alias string) {
	i := 0
	for ; i < len(fields); i++ {
		if !strings.HasPrefix(fields[i], "--") {
			break
		}
		// --platform=linux/arm64 and --from=... style flags are metadata, not
		// the image; hull records the platform per entry, not per reference.
	}
	if i >= len(fields) {
		return "", ""
	}
	image = expandDockerfileArgs(fields[i], args)
	if strings.ContainsAny(image, "${}") {
		image = ""
	}
	if i+2 < len(fields) && strings.EqualFold(fields[i+1], "AS") {
		alias = fields[i+2]
	}
	return image, alias
}

// expandDockerfileArgs substitutes $NAME, ${NAME} and ${NAME:-default} using
// the global ARGs declared before the first FROM. An unknown name expands to
// nothing, which makes the reference unparseable and so skipped.
func expandDockerfileArgs(s string, args map[string]string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+1 < len(s) && s[i+1] == '{' {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				b.WriteString(s[i:])
				break
			}
			inner := s[i+2 : i+end]
			name, def := inner, ""
			hasDef := false
			if j := strings.Index(inner, ":-"); j >= 0 {
				name, def, hasDef = inner[:j], inner[j+2:], true
			} else if j := strings.Index(inner, ":+"); j >= 0 {
				name = inner[:j]
			}
			if v, ok := args[name]; ok && v != "" {
				b.WriteString(v)
			} else if hasDef {
				b.WriteString(def)
			}
			i += end + 1
			continue
		}
		j := i + 1
		for j < len(s) && (s[j] == '_' || isAlnum(s[j])) {
			j++
		}
		if j == i+1 {
			b.WriteByte('$')
			i++
			continue
		}
		b.WriteString(args[s[i+1:j]])
		i = j
	}
	return b.String()
}

// isAlnum reports whether c is an ASCII letter or digit.
func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// dockerfileEscape reads the "# escape=" parser directive, which must appear
// before any instruction or comment that is not itself a directive. It decides
// what a line continuation looks like, so it has to be honoured before the
// logical lines can be assembled.
func dockerfileEscape(lines []string) byte {
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "#") {
			return '\\'
		}
		directive := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		name, value, ok := strings.Cut(directive, "=")
		if !ok {
			return '\\'
		}
		if strings.EqualFold(strings.TrimSpace(name), "escape") {
			if v := strings.TrimSpace(value); v == "`" {
				return '`'
			}
			return '\\'
		}
	}
	return '\\'
}

// ---------- devcontainer.json ----------

// scanDevcontainer reads the "image" field of a devcontainer.json.
//
// The file is JSON with comments in practice - VS Code writes them, and every
// template ships them - so line and block comments and trailing commas are
// stripped before it is parsed. A devcontainer that builds from a Dockerfile
// instead of an image contributes nothing here; the Dockerfile it names is
// found by the walk in its own right.
func scanDevcontainer(data []byte) []string {
	var doc struct {
		Image string `json:"image"`
	}
	if err := json.Unmarshal(stripJSONComments(data), &doc); err != nil {
		return nil
	}
	image := strings.TrimSpace(doc.Image)
	if image == "" || strings.ContainsAny(image, "${}") {
		return nil
	}
	if _, err := reference.Parse(image); err != nil {
		return nil
	}
	return []string{image}
}

// stripJSONComments removes // and /* */ comments and trailing commas, leaving
// string literals untouched. Comments are replaced by nothing and the result is
// plain JSON.
func stripJSONComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	var (
		inString bool
		escaped  bool
	)
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			i++
		default:
			out = append(out, c)
		}
	}
	return stripTrailingCommas(out)
}

// stripTrailingCommas removes a comma that is followed only by whitespace and a
// closing brace or bracket, which encoding/json refuses but every hand-edited
// devcontainer.json eventually grows.
func stripTrailingCommas(data []byte) []byte {
	out := make([]byte, 0, len(data))
	var (
		inString bool
		escaped  bool
	)
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(data) && isJSONSpace(data[j]) {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// isJSONSpace reports whether c is JSON insignificant whitespace.
func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// splitLines splits file contents into lines, tolerating CRLF, which is how
// every file edited on the Windows side of this project arrives.
func splitLines(data []byte) []string {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.Split(text, "\n")
}
