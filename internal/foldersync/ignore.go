package foldersync

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrBadPattern means an ignore pattern could not be compiled - an unterminated
// character class, usually.
var ErrBadPattern = errors.New("foldersync: bad ignore pattern")

// builtinIgnores is the seed set. Excluding node_modules by default is the
// difference between a syncer that is usable on a real project and one that
// spends its life copying a hundred thousand files nobody edits; the rest are
// the same story for other ecosystems. The last two entries are hull's own
// debris: the temporary file a copy lands in before its rename, and the copies
// a conflict preserves - neither may ever be propagated to the other side.
//
// The directory-shaped entries carry a trailing slash, so a *file* called
// build or dist is still synced. That is deliberate: a file by that name is
// nearly always a script somebody wants.
var builtinIgnores = []string{
	".git/",
	"node_modules/",
	"target/",
	"vendor/",
	"__pycache__/",
	".venv/",
	"dist/",
	"build/",
	"*.swp",
	tmpPrefix + "*",
	"*.hull-conflict-*",
}

// DefaultIgnores returns a copy of the built-in ignore patterns, in the order
// they are applied. A caller can pass negations of these in Config.Ignore,
// which is applied afterwards, to bring something back.
func DefaultIgnores() []string {
	out := make([]string, len(builtinIgnores))
	copy(out, builtinIgnores)
	return out
}

// LoadIgnoreFile reads gitignore-style patterns from a file. A missing file is
// not an error and yields no patterns, because .gitignore and .hullignore are
// both optional; anything else that goes wrong is wrapped and returned.
func LoadIgnoreFile(name string) ([]string, error) {
	f, err := os.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("foldersync: read ignore file %s: %w", name, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("foldersync: read ignore file %s: %w", name, err)
	}
	return out, nil
}

// Ignorer decides whether a relative path is excluded from the sync. The rules
// are gitignore's, with the parts that matter here:
//
//   - a blank line or a line starting with # is skipped;
//   - a leading ! negates, and the last pattern that matches a path decides;
//   - a trailing / makes the pattern match directories only;
//   - a pattern containing a slash (other than a trailing one) is anchored to
//     the sync root, one without a slash matches a basename at any depth;
//   - * and ? and [...] never cross a /, and ** does;
//   - once a directory is excluded nothing inside it can be brought back, so
//     an ignored ancestor ignores everything beneath it.
//
// An Ignorer is immutable once built and safe for concurrent use.
type Ignorer struct {
	pats []pattern
	raw  []string
}

// pattern is one compiled ignore line.
type pattern struct {
	raw      string
	negate   bool
	dirOnly  bool
	anchored bool
	segs     []string
}

// NewIgnorer compiles patterns in order. Blank lines and comments are dropped.
// A pattern that cannot be compiled is an error rather than a silent no-op,
// because a typo in a .hullignore that quietly stopped excluding node_modules
// would look exactly like the syncer being broken.
func NewIgnorer(patterns ...string) (*Ignorer, error) {
	ig := &Ignorer{}
	for _, line := range patterns {
		p, ok, err := parsePattern(line)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		ig.pats = append(ig.pats, p)
		ig.raw = append(ig.raw, line)
	}
	return ig, nil
}

// Patterns returns the source lines of the patterns that compiled, in order.
func (ig *Ignorer) Patterns() []string {
	out := make([]string, len(ig.raw))
	copy(out, ig.raw)
	return out
}

// Match reports whether a path relative to a sync root is excluded. rel is
// slash-separated and must not start with a slash; isDir says whether it names
// a directory, which is what a trailing-slash pattern keys on.
func (ig *Ignorer) Match(rel string, isDir bool) bool {
	rel = normaliseRel(rel)
	if rel == "" {
		return false
	}
	comps := strings.Split(rel, "/")
	// An excluded directory excludes its whole subtree, and no negation
	// inside it can undo that - gitignore's rule, and the reason pruning the
	// walk at an ignored directory is correct.
	for i := 1; i < len(comps); i++ {
		if ig.matchPath(strings.Join(comps[:i], "/"), true) {
			return true
		}
	}
	return ig.matchPath(rel, isDir)
}

// matchPath applies last-match-wins to one path, without the ancestor rule.
func (ig *Ignorer) matchPath(rel string, isDir bool) bool {
	ignored := false
	for i := range ig.pats {
		if ig.pats[i].match(rel, isDir) {
			ignored = !ig.pats[i].negate
		}
	}
	return ignored
}

// normaliseRel puts a relative path into the one shape the matcher understands:
// slash-separated, cleaned, with no leading "./" or "/".
func normaliseRel(rel string) string {
	rel = filepath.ToSlash(rel)
	rel = strings.TrimPrefix(rel, "./")
	rel = strings.Trim(rel, "/")
	if rel == "" || rel == "." {
		return ""
	}
	return path.Clean(rel)
}

// parsePattern compiles one line. ok is false for a line that is not a pattern
// at all (blank, or a comment).
func parsePattern(line string) (pattern, bool, error) {
	raw := line
	line = trimTrailingSpace(line)
	if line == "" {
		return pattern{}, false, nil
	}
	if strings.HasPrefix(line, "#") {
		return pattern{}, false, nil
	}

	var p pattern
	p.raw = raw
	if strings.HasPrefix(line, "!") {
		p.negate = true
		line = line[1:]
	}
	// A leading backslash escapes a literal # or !.
	if len(line) > 1 && line[0] == '\\' && (line[1] == '#' || line[1] == '!') {
		line = line[1:]
	}
	if line == "" {
		return pattern{}, false, nil
	}

	if strings.HasSuffix(line, "/") {
		p.dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}
	if line == "" {
		return pattern{}, false, nil
	}
	if strings.HasPrefix(line, "/") {
		p.anchored = true
		line = strings.TrimPrefix(line, "/")
	} else if strings.Contains(line, "/") {
		// A slash anywhere but at the end anchors the pattern to the root.
		p.anchored = true
	}
	if line == "" {
		return pattern{}, false, nil
	}

	p.segs = strings.Split(line, "/")
	for _, seg := range p.segs {
		if seg == "**" {
			continue
		}
		if _, err := path.Match(seg, ""); err != nil {
			return pattern{}, false, fmt.Errorf("%w: %q: %w", ErrBadPattern, raw, err)
		}
	}
	return p, true, nil
}

// trimTrailingSpace strips unescaped trailing whitespace, which gitignore
// treats as insignificant unless a backslash protects it.
func trimTrailingSpace(s string) string {
	i := len(s)
	for i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
		if i >= 2 && s[i-2] == '\\' {
			break
		}
		i--
	}
	return s[:i]
}

// match reports whether this single pattern matches rel.
func (p pattern) match(rel string, isDir bool) bool {
	if p.dirOnly && !isDir {
		return false
	}
	comps := strings.Split(rel, "/")
	if p.anchored {
		return matchSegments(p.segs, comps)
	}
	// An unanchored pattern matches at any depth, so try every suffix of the
	// path's components.
	for i := range comps {
		if matchSegments(p.segs, comps[i:]) {
			return true
		}
	}
	return false
}

// matchSegments matches a compiled pattern's segments against a path's
// components, with ** consuming any number of components including none.
func matchSegments(segs, comps []string) bool {
	if len(segs) == 0 {
		return len(comps) == 0
	}
	if segs[0] == "**" {
		for i := 0; i <= len(comps); i++ {
			if matchSegments(segs[1:], comps[i:]) {
				return true
			}
		}
		return false
	}
	if len(comps) == 0 {
		return false
	}
	ok, err := path.Match(segs[0], comps[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(segs[1:], comps[1:])
}
