package lockfile

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/rahuldhali/hull/internal/oci/reference"
	"github.com/rahuldhali/hull/internal/types"
)

// ErrNotFound is how a Resolver says a reference is not in the registry: the
// tag has been deleted, or the digest has been garbage-collected. Verify
// classifies drift with it, and anything wrapping it, using errors.Is; every
// other error is a failure to check rather than a finding, and Verify returns
// it to the caller.
//
// An error wrapping fs.ErrNotExist counts too, so a Resolver backed by a local
// content store needs no translation layer. A Resolver in front of
// internal/oci/registry should map that package's ErrNotFound onto this one.
var ErrNotFound = errors.New("lockfile: reference not found in registry")

// IsNotFound reports whether err means "this reference is not in the registry".
// It matches ErrNotFound and fs.ErrNotExist, and anything wrapping either.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, fs.ErrNotExist)
}

// Resolver resolves an image reference to the descriptor it currently names.
//
// ref is a full reference string, tagged or digest-pinned, as it would be typed
// on a command line. plat selects a platform from a multi-platform index and
// may be nil, which means the resolver's own default. The returned descriptor's
// Digest is the manifest digest the reference resolves to today; for a
// multi-platform tag that is the image index digest, matching what Entry.Digest
// records.
//
// A reference that does not exist must be reported with an error satisfying
// IsNotFound. internal/oci/registry's Client satisfies this interface through a
// three-line adapter that parses the reference and maps registry.ErrNotFound
// onto ErrNotFound.
type Resolver interface {
	Resolve(ctx context.Context, ref string, plat *types.Platform) (types.Descriptor, error)
}

// DriftKind says how a locked entry and the registry disagree.
type DriftKind string

// The kinds of drift Verify reports.
const (
	// KindMoved means the tag still exists but now points at a different
	// manifest: the lock is still usable, but "latest" is not what it was.
	// Current holds the digest the tag points at now, or is empty when the tag
	// itself has been deleted while the locked digest survives.
	KindMoved DriftKind = "moved"

	// KindMissing means the locked digest is gone from the registry, so the
	// pin can no longer be restored and the project cannot be rebuilt from it.
	KindMissing DriftKind = "missing"
)

// Drift is one disagreement between the lock file and the registry.
//
// Ref is the reference as the lock file records it, Locked the digest the lock
// pins, Current the digest the registry serves for that reference now (empty
// when nothing is served), and Kind which of the two failures this is.
type Drift struct {
	Ref     string
	Locked  string
	Current string
	Kind    DriftKind
}

// String renders a drift as a single reviewable line.
func (d Drift) String() string {
	switch d.Kind {
	case KindMissing:
		if d.Current != "" {
			return fmt.Sprintf("%s: locked digest %s is gone from the registry; the tag now serves %s", d.Ref, d.Locked, d.Current)
		}
		return fmt.Sprintf("%s: locked digest %s is gone from the registry", d.Ref, d.Locked)
	case KindMoved:
		if d.Current == "" {
			return fmt.Sprintf("%s: the tag no longer exists; locked digest %s is still available", d.Ref, d.Locked)
		}
		return fmt.Sprintf("%s: the tag moved from %s to %s", d.Ref, d.Locked, d.Current)
	default:
		return fmt.Sprintf("%s: %s (locked %s, current %s)", d.Ref, d.Kind, d.Locked, d.Current)
	}
}

// Verify re-resolves every pinned entry against resolver and reports how the
// registry has diverged from the lock. An empty result means the project still
// builds from exactly the images it was locked to.
//
// For a tagged entry the tag is resolved first, which is one request and the
// common case: if it still serves the locked digest, nothing has drifted and no
// further request is made. Otherwise the locked digest itself is resolved to
// decide between the two findings - the tag has merely moved and the pin is
// still pullable (KindMoved), or the pin has been deleted too and the project
// can no longer be rebuilt (KindMissing). A digest-only entry is checked with
// that single request.
//
// Entries with no digest are skipped, since there is nothing to check. Errors
// that are not "not found" - a network failure, a 401, a rate limit - abort the
// verification and are returned wrapped, because reporting them as drift would
// turn a broken connection into a false alarm about the registry's contents.
func (l *Lockfile) Verify(ctx context.Context, resolver Resolver) ([]Drift, error) {
	if resolver == nil {
		return nil, errors.New("lockfile: verify: nil resolver")
	}
	var drifts []Drift
	for _, e := range l.Images {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("lockfile: verify %s: %w", e.Ref, err)
		}
		if e.Digest == "" {
			continue
		}
		d, ok, err := verifyEntry(ctx, resolver, e)
		if err != nil {
			return nil, err
		}
		if ok {
			drifts = append(drifts, d)
		}
	}
	return drifts, nil
}

// verifyEntry checks one entry, reporting at most one drift.
func verifyEntry(ctx context.Context, resolver Resolver, e Entry) (Drift, bool, error) {
	plat := e.platform()

	tagRef, tagged := e.taggedRef()
	if !tagged {
		// Digest-only: the only question is whether the content survives.
		gone, err := digestGone(ctx, resolver, e, plat)
		if err != nil {
			return Drift{}, false, err
		}
		if gone {
			return Drift{Ref: e.Ref, Locked: e.Digest, Kind: KindMissing}, true, nil
		}
		return Drift{}, false, nil
	}

	desc, err := resolver.Resolve(ctx, tagRef, plat)
	switch {
	case err == nil && desc.Digest == e.Digest:
		return Drift{}, false, nil

	case err == nil:
		// The tag points somewhere else. Whether that matters depends on
		// whether the locked digest is still pullable.
		gone, gerr := digestGone(ctx, resolver, e, plat)
		if gerr != nil {
			return Drift{}, false, gerr
		}
		kind := KindMoved
		if gone {
			kind = KindMissing
		}
		return Drift{Ref: e.Ref, Locked: e.Digest, Current: desc.Digest, Kind: kind}, true, nil

	case IsNotFound(err):
		// The tag itself has been deleted. The pin may still be pullable.
		gone, gerr := digestGone(ctx, resolver, e, plat)
		if gerr != nil {
			return Drift{}, false, gerr
		}
		kind := KindMoved
		if gone {
			kind = KindMissing
		}
		return Drift{Ref: e.Ref, Locked: e.Digest, Kind: kind}, true, nil

	default:
		return Drift{}, false, fmt.Errorf("lockfile: resolve %s: %w", tagRef, err)
	}
}

// digestGone reports whether the entry's locked digest has disappeared from the
// registry.
func digestGone(ctx context.Context, resolver Resolver, e Entry, plat *types.Platform) (bool, error) {
	pinned, err := e.pinnedRef()
	if err != nil {
		return false, err
	}
	if _, err := resolver.Resolve(ctx, pinned, plat); err != nil {
		if IsNotFound(err) {
			return true, nil
		}
		return false, fmt.Errorf("lockfile: resolve %s: %w", pinned, err)
	}
	return false, nil
}

// pinnedRef is the entry's repository pinned to its locked digest, with any tag
// dropped, which is the form that asks the registry "does this exact content
// still exist".
func (e Entry) pinnedRef() (string, error) {
	r, err := reference.Parse(e.Ref)
	if err != nil {
		return "", fmt.Errorf("lockfile: entry %q: %w", e.Ref, err)
	}
	r.Tag = ""
	r.Digest = e.Digest
	return r.String(), nil
}

// taggedRef is the entry's repository with its tag and no digest, which is the
// form that asks the registry "where does this tag point now". It reports false
// for a digest-only reference, which cannot move.
func (e Entry) taggedRef() (string, bool) {
	r, err := reference.Parse(e.Ref)
	if err != nil || r.Tag == "" {
		return "", false
	}
	r.Digest = ""
	return r.String(), true
}

// platform returns the entry's platform as the optional argument a Resolver
// takes: nil when the entry did not record one.
func (e Entry) platform() *types.Platform {
	if platformIsZero(e.Platform) {
		return nil
	}
	p := e.Platform
	return &p
}
