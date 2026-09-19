package foldersync

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"time"
)

// copyEntry writes one path from src to dst. Regular files go through a
// temporary file in the destination directory and a rename, so a container
// watching the destination never observes a half-written file - which is the
// whole point of syncing rather than bind-mounting: a dev server that reloads
// on a truncated file is worse than one that does not reload at all.
//
// Mode and mtime are preserved. mtime preservation is load-bearing: it is what
// makes the next pass agree that the two sides match, and what makes
// "newest wins" mean anything.
func (s *Syncer) copyEntry(rel string, from, to Side, e entry) (int64, error) {
	srcPath := s.abs(from, rel)
	dstPath := s.abs(to, rel)

	if parent := path.Dir(rel); parent != "." && parent != "/" {
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return 0, fmt.Errorf("foldersync: create parent of %s: %w", dstPath, err)
		}
	}

	switch e.kind {
	case kindDir:
		if err := mkdirPreserving(dstPath, e.mode); err != nil {
			return 0, err
		}
		return 0, nil

	case kindSymlink:
		if err := clearDirectoryInTheWay(dstPath); err != nil {
			return 0, err
		}
		if err := replaceSymlink(dstPath, e.link); err != nil {
			return 0, err
		}
		return 0, nil

	case kindFile:
		if err := clearDirectoryInTheWay(dstPath); err != nil {
			return 0, err
		}
		n, err := copyFileAtomic(dstPath, srcPath, e.mode, e.mtime)
		if err != nil {
			return n, err
		}
		return n, nil

	default:
		return 0, fmt.Errorf("foldersync: refusing to copy %s: unsupported kind %s", rel, e.kind)
	}
}

// clearDirectoryInTheWay removes a directory standing where a file or symlink
// is about to be written. A path that was a directory on one side and became a
// file on the other is rare, but rename(2) will not do it, and the caller has
// already decided this side lost - and already preserved it, if the change was
// a conflict.
func clearDirectoryInTheWay(dstPath string) error {
	fi, err := os.Lstat(dstPath)
	if err != nil || !fi.IsDir() {
		return nil
	}
	if err := os.RemoveAll(dstPath); err != nil {
		return fmt.Errorf("foldersync: replace directory %s with a file: %w", dstPath, err)
	}
	return nil
}

// mkdirPreserving creates a directory if it is missing, and fixes its
// permissions if it is there with different ones. An existing non-directory in
// the way is removed first: the caller only gets here after deciding this side
// lost, and after any conflict copy was preserved.
func mkdirPreserving(dstPath string, mode os.FileMode) error {
	fi, err := os.Lstat(dstPath)
	switch {
	case err == nil && fi.IsDir():
		if fi.Mode().Perm() != mode {
			// Best effort: drvfs refuses chmod, and that is not a reason to
			// fail a sync.
			_ = os.Chmod(dstPath, mode)
		}
		return nil
	case err == nil:
		if err := os.Remove(dstPath); err != nil {
			return fmt.Errorf("foldersync: replace %s with a directory: %w", dstPath, err)
		}
	case !os.IsNotExist(err):
		return fmt.Errorf("foldersync: stat %s: %w", dstPath, err)
	}
	if err := os.MkdirAll(dstPath, mode); err != nil {
		return fmt.Errorf("foldersync: create directory %s: %w", dstPath, err)
	}
	return nil
}

// replaceSymlink points dstPath at target, atomically, by creating the link
// under a temporary name and renaming it over whatever was there.
func replaceSymlink(dstPath, target string) error {
	dir := filepath.Dir(dstPath)
	tmp, err := tempName(dir)
	if err != nil {
		return err
	}
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("foldersync: create symlink %s: %w", dstPath, err)
	}
	if err := os.Rename(tmp, dstPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("foldersync: rename symlink onto %s: %w", dstPath, err)
	}
	return nil
}

// copyFileAtomic copies src to dst through a temporary file in dst's own
// directory, then renames. It returns the number of bytes copied.
//
// The copy is not fsynced. A folder sync is a developer convenience, not a
// durability boundary: what it must guarantee is that no reader ever sees a
// partial file, and the rename does that on its own.
func copyFileAtomic(dstPath, srcPath string, mode os.FileMode, mtime time.Time) (int64, error) {
	in, err := os.Open(srcPath)
	if err != nil {
		return 0, fmt.Errorf("foldersync: open %s: %w", srcPath, err)
	}
	defer in.Close()

	dir := filepath.Dir(dstPath)
	out, err := os.CreateTemp(dir, tmpPrefix+"*")
	if err != nil {
		return 0, fmt.Errorf("foldersync: create temporary file in %s: %w", dir, err)
	}
	tmp := out.Name()
	done := false
	defer func() {
		if !done {
			out.Close()
			os.Remove(tmp)
		}
	}()

	n, err := io.Copy(out, in)
	if err != nil {
		return n, fmt.Errorf("foldersync: copy %s to %s: %w", srcPath, dstPath, err)
	}
	if err := out.Close(); err != nil {
		return n, fmt.Errorf("foldersync: close temporary file for %s: %w", dstPath, err)
	}
	// Permissions are best effort: drvfs reports a mode of its own and refuses
	// to change it, and that must not fail a sync. The recorded baseline is
	// re-observed after the copy, so a mode that would not stick does not send
	// the syncer into a loop.
	_ = os.Chmod(tmp, mode)
	if err := os.Chtimes(tmp, mtime, mtime); err != nil {
		return n, fmt.Errorf("foldersync: set times on %s: %w", dstPath, err)
	}
	if err := os.Rename(tmp, dstPath); err != nil {
		return n, fmt.Errorf("foldersync: rename temporary file onto %s: %w", dstPath, err)
	}
	done = true
	return n, nil
}

// tempName reserves a unique name in dir without creating anything at it,
// which is what a symlink needs (it must not exist when symlink(2) runs).
func tempName(dir string) (string, error) {
	f, err := os.CreateTemp(dir, tmpPrefix+"*")
	if err != nil {
		return "", fmt.Errorf("foldersync: create temporary name in %s: %w", dir, err)
	}
	name := f.Name()
	f.Close()
	if err := os.Remove(name); err != nil {
		return "", fmt.Errorf("foldersync: reserve temporary name in %s: %w", dir, err)
	}
	return name, nil
}

// removeEntry deletes one path from one side. Directories are removed
// non-recursively: by the time the pass reaches a directory its synced
// children are already gone, and anything left is either ignored or brand new,
// neither of which a delete propagation is entitled to destroy.
func (s *Syncer) removeEntry(side Side, rel string, e entry) error {
	full := s.abs(side, rel)
	err := os.Remove(full)
	switch {
	case err == nil, os.IsNotExist(err):
		return nil
	case e.kind == kindDir && !dirEmpty(full):
		// ENOTEMPTY by any spelling: something this sync does not own is
		// still in there, so leaving the directory is the correct outcome
		// rather than a failure.
		return nil
	default:
		return fmt.Errorf("foldersync: remove %s: %w", full, err)
	}
}

// dirEmpty reports whether a directory has no entries. An unreadable directory
// is reported as non-empty, because that is the conservative answer.
func dirEmpty(full string) bool {
	f, err := os.Open(full)
	if err != nil {
		return false
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	return err == io.EOF || (err == nil && len(names) == 0)
}

// preserveLoser renames the losing side of a conflict out of the way, so the
// winner can be written over it without the loser's bytes being lost. It
// returns the relative path the loser was kept at, or "" when the loser was
// empty and there was nothing worth keeping.
//
// The preserved name is matched by a default ignore pattern, so it stays where
// it was written and is never propagated to the other side.
func (s *Syncer) preserveLoser(side Side, rel string, e entry, now time.Time) (string, error) {
	root := s.root(side)
	if !nonEmpty(root, rel, e) {
		return "", nil
	}
	dir, base := path.Split(rel)
	stamp := now.UTC().Format(conflictStamp)
	for i := 0; i < 100; i++ {
		name := base + ".hull-conflict-" + stamp
		if i > 0 {
			name = fmt.Sprintf("%s-%d", name, i)
		}
		kept := dir + name
		full := filepath.Join(root, filepath.FromSlash(kept))
		if _, err := os.Lstat(full); err == nil {
			continue
		}
		if err := os.Rename(filepath.Join(root, filepath.FromSlash(rel)), full); err != nil {
			return "", fmt.Errorf("foldersync: keep conflicting %s copy of %s: %w", side, rel, err)
		}
		return kept, nil
	}
	return "", fmt.Errorf("foldersync: keep conflicting %s copy of %s: no free name", side, rel)
}
