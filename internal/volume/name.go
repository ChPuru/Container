package volume

import (
	"fmt"
	"regexp"
	"strings"
)

// nameRE is the set of characters a volume name may use. It matches Docker's
// rule so that names written for docker are accepted unchanged.
var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

const (
	// minNameLen is two rather than one because internal/state's ValidateName,
	// which the index enforces, requires at least two characters.
	minNameLen = 2
	// maxNameLen bounds the on-disk directory name.
	maxNameLen = 128
)

// reservedNames are files the manager itself keeps in the volumes root. A
// volume may not take one of these names or it would collide with the index or
// the reference file.
var reservedNames = map[string]struct{}{
	"volumes.json": {},
	"volumes.lock": {},
	refsFileName:   {},
	refsLockName:   {},
}

// ValidateName reports whether name is usable as a hull volume name. It is the
// same alphabet Docker uses, with hull's extra rules: no name may collide with
// one of the manager's own files, and the length is bounded so the on-disk
// directory stays well inside PATH_MAX.
func ValidateName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: name is empty", ErrInvalidName)
	case len(name) < minNameLen:
		return fmt.Errorf("%w: %q is too short (minimum %d characters)", ErrInvalidName, name, minNameLen)
	case len(name) > maxNameLen:
		return fmt.Errorf("%w: %q is longer than %d characters", ErrInvalidName, name, maxNameLen)
	case !nameRE.MatchString(name):
		return fmt.Errorf("%w: %q must match %s", ErrInvalidName, name, nameRE.String())
	}
	if _, bad := reservedNames[strings.ToLower(name)]; bad {
		return fmt.Errorf("%w: %q is reserved by hull", ErrInvalidName, name)
	}
	return nil
}

// LooksLikeVolumeName reports whether a -v source field should be read as a
// named volume rather than as a host path. A source that names a path (it is
// absolute, relative, or a Windows path) is a bind; anything else is a volume
// name. This is the same disambiguation Docker performs.
func LooksLikeVolumeName(src string) bool {
	if src == "" {
		return false
	}
	if strings.ContainsAny(src, `/\`) {
		return false
	}
	if IsWindowsPath(src) {
		return false
	}
	return nameRE.MatchString(src)
}
