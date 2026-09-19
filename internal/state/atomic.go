package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// tmpSuffix is appended to a final file name to form its staging file. Recover
// deletes stray files with this suffix, so nothing else in the store may use it.
const tmpSuffix = ".tmp"

// writeFileAtomic writes data to path so that a reader either sees the previous
// contents or the complete new contents, never a truncated file, even if the
// process is SIGKILLed or the machine loses power mid-write.
//
// The sequence is the classic one: write <path>.tmp, fsync it, close it, rename
// it over <path>, then fsync the containing directory so the rename itself is
// durable.
func writeFileAtomic(path string, data []byte, perm fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp := path + tmpSuffix

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()

	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", tmp, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	if err = syncDir(dir); err != nil {
		return fmt.Errorf("fsync dir %s: %w", dir, err)
	}
	return nil
}

// writeJSONAtomic marshals v as indented JSON with a trailing newline and
// writes it through writeFileAtomic.
func writeJSONAtomic(path string, v any, perm fs.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", filepath.Base(path), err)
	}
	data = append(data, '\n')
	return writeFileAtomic(path, data, perm)
}

// readJSON reads and decodes a JSON file. A missing file is reported with a
// wrapped fs.ErrNotExist so callers can distinguish it from corruption.
func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read %s: %w", path, err)
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

// mkdirAll creates dir and its parents with mode 0o700 semantics applied to the
// leaf, wrapping the error with the path for a useful daemon log line.
func mkdirAll(dir string, perm fs.FileMode) error {
	if err := os.MkdirAll(dir, perm); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	return nil
}
