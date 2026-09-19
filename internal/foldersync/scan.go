package foldersync

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"time"
)

// entryKind is the shape of one tree entry. Anything that is not a regular
// file, a directory or a symlink - a socket, a fifo, a device node - is not
// synced at all; copying those between a Windows folder and a volume is either
// meaningless or actively wrong.
type entryKind uint8

const (
	kindAbsent entryKind = iota
	kindFile
	kindDir
	kindSymlink
)

// String implements fmt.Stringer, for error messages.
func (k entryKind) String() string {
	switch k {
	case kindFile:
		return "file"
	case kindDir:
		return "directory"
	case kindSymlink:
		return "symlink"
	default:
		return "absent"
	}
}

// entry is everything the syncer records about one path on one side. Only
// (kind, size, mtime, mode, link) - never content hashes, because hashing a
// project tree over 9p on every pass would cost more than the sync saves.
type entry struct {
	kind  entryKind
	size  int64
	mode  os.FileMode // permission bits only
	mtime time.Time
	link  string // symlink target, verbatim
}

// tree is one side's scan, keyed by slash-separated path relative to that
// side's root.
type tree map[string]entry

// sameAs compares two observations of the *same* side, which is the change
// test: both came from the same filesystem, so the comparison is exact.
//
// Directories are compared on their permissions alone. A directory's mtime
// changes every time a child is created or removed, so including it would
// report every parent of every edit as changed and would fight the poller's
// backoff.
func (e entry) sameAs(o entry) bool {
	if e.kind != o.kind || e.mode != o.mode {
		return false
	}
	switch e.kind {
	case kindDir:
		return true
	case kindSymlink:
		return e.link == o.link
	default:
		return e.size == o.size && e.mtime.Equal(o.mtime)
	}
}

// equivalent compares observations of the *two* sides, which needs slack:
// drvfs and ext4 do not agree to the nanosecond about a copied file's mtime,
// and drvfs reports a mode of its own choosing for everything, so permissions
// are deliberately not part of this comparison. Comparing them would copy the
// same bytes back and forth forever.
func equivalent(a, b entry, tol time.Duration) bool {
	if a.kind != b.kind {
		return false
	}
	switch a.kind {
	case kindDir:
		return true
	case kindSymlink:
		return a.link == b.link
	default:
		if a.size != b.size {
			return false
		}
		d := a.mtime.Sub(b.mtime)
		if d < 0 {
			d = -d
		}
		return d <= tol
	}
}

// nonEmpty reports whether an entry has anything worth preserving when it
// loses a conflict. An empty file is not worth a .hull-conflict copy; a
// non-empty directory is.
func nonEmpty(root, rel string, e entry) bool {
	switch e.kind {
	case kindFile:
		return e.size > 0
	case kindSymlink:
		return true
	case kindDir:
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return true // cannot tell; keep it rather than destroy it
		}
		defer f.Close()
		names, err := f.Readdirnames(1)
		return err != nil || len(names) > 0
	default:
		return false
	}
}

// scanStats is the bookkeeping a walk produces alongside the tree.
type scanStats struct {
	// ignored counts entries excluded by the ignore patterns. An ignored
	// directory counts once, not once per file inside it, because the walk
	// never descends into it.
	ignored int

	// skipped counts entries of a kind the syncer does not handle.
	skipped int

	// errs holds per-entry failures; the walk keeps going past them, because
	// one unreadable directory must not stop a project from syncing.
	errs []error
}

// scanTree walks root and records every entry the ignore set admits. Ignored
// directories are pruned rather than descended into, which is both the fast
// path (node_modules is never opened) and the rule that makes an ignored
// directory's contents unrecoverable by a later negation.
func scanTree(ctx context.Context, root string, ig *Ignorer) (tree, scanStats, error) {
	t := make(tree)
	var st scanStats

	var walk func(rel string) error
	walk = func(rel string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		dir := root
		if rel != "" {
			dir = filepath.Join(root, filepath.FromSlash(rel))
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			st.errs = append(st.errs, fmt.Errorf("foldersync: read directory %s: %w", dir, err))
			return nil
		}
		for _, de := range ents {
			childRel := de.Name()
			if rel != "" {
				childRel = path.Join(rel, de.Name())
			}
			if ig.Match(childRel, de.IsDir()) {
				st.ignored++
				continue
			}
			info, err := de.Info()
			if err != nil {
				// A file that vanished mid-walk is not an error; the next
				// pass will see it gone.
				if os.IsNotExist(err) {
					continue
				}
				st.errs = append(st.errs, fmt.Errorf("foldersync: stat %s: %w", filepath.Join(dir, de.Name()), err))
				continue
			}
			e := entry{mode: info.Mode().Perm(), mtime: info.ModTime()}
			switch {
			case info.Mode()&fs.ModeSymlink != 0:
				target, err := os.Readlink(filepath.Join(dir, de.Name()))
				if err != nil {
					st.errs = append(st.errs, fmt.Errorf("foldersync: readlink %s: %w", filepath.Join(dir, de.Name()), err))
					continue
				}
				e.kind = kindSymlink
				e.link = target
			case info.IsDir():
				e.kind = kindDir
			case info.Mode().IsRegular():
				e.kind = kindFile
				e.size = info.Size()
			default:
				st.skipped++
				continue
			}
			t[childRel] = e
			if e.kind == kindDir {
				if err := walk(childRel); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := walk(""); err != nil {
		return nil, st, err
	}
	return t, st, nil
}

// statEntry observes one path on one side, after the syncer has written it, so
// that the recorded baseline is what the filesystem actually holds rather than
// what was asked for. That difference matters on drvfs, which quietly rounds
// timestamps and ignores chmod.
func statEntry(root, rel string) (entry, bool, error) {
	full := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Lstat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return entry{}, false, nil
		}
		return entry{}, false, fmt.Errorf("foldersync: stat %s: %w", full, err)
	}
	e := entry{mode: info.Mode().Perm(), mtime: info.ModTime()}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(full)
		if err != nil {
			return entry{}, false, fmt.Errorf("foldersync: readlink %s: %w", full, err)
		}
		e.kind = kindSymlink
		e.link = target
	case info.IsDir():
		e.kind = kindDir
	case info.Mode().IsRegular():
		e.kind = kindFile
		e.size = info.Size()
	default:
		return entry{}, false, nil
	}
	return e, true, nil
}
