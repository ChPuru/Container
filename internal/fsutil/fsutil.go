// Package fsutil holds the filesystem primitives every hull subsystem shares:
// crash-safe atomic writes, JSON helpers, flock-based file locks, free-space
// queries and — most importantly — safe resolution of container-controlled
// paths.
//
// The safe-resolution half (SecureOpen, SecureMkdirAll, SecureStat) exists
// because every recent runc breakout came from path-based operations against an
// attacker-controlled rootfs. Nothing in hull may reach into a container
// filesystem with filepath.Join plus os.Open; it goes through this package,
// which uses openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV)
// where the kernel has it and an fd-relative openat walk where it does not.
//
// Syscall-dependent code lives in *_linux.go. The *_other.go files keep the
// Windows CLI build compiling; they return ErrUnsupported.
package fsutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrUnsupported is returned by the operations that only exist on Linux when
// hull is built for another GOOS (the Windows CLI links this package for its
// config handling).
var ErrUnsupported = errors.New("fsutil: operation not supported on this platform")

// ErrLocked is returned by TryFileLock when another holder already owns the
// lock. It is never returned by the blocking FileLock.
var ErrLocked = errors.New("fsutil: file is locked by another holder")

// ErrUnsafePath is returned by the Secure* functions when the requested path is
// rejected before it reaches the kernel: an absolute path, or one that
// lexically climbs out of the root with "..".
var ErrUnsafePath = errors.New("fsutil: path escapes root")

// tmpPrefix is the prefix of the temporary file an atomic write creates next to
// its target. It is dot-prefixed so listings that skip hidden files ignore the
// debris of a crashed write.
const tmpPrefix = "."

// WriteFileAtomic writes data to path so that a concurrent reader sees either
// the previous contents or the complete new contents, never a partial file, and
// so that the new contents survive a crash once the call returns.
//
// It writes a temporary file in the same directory, fsyncs it, renames it over
// path and fsyncs the directory. On any failure the temporary file is removed,
// so a successful call leaves no .tmp debris behind.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	f, err := os.CreateTemp(dir, tmpPrefix+base+".tmp")
	if err != nil {
		return fmt.Errorf("fsutil: create temp for %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() {
		if f != nil {
			f.Close()
		}
		if tmp != "" {
			os.Remove(tmp)
		}
	}()

	if err := f.Chmod(perm); err != nil {
		// Some filesystems refuse fchmod on a fresh handle; fall back to a
		// path-based chmod, which is still ours alone because CreateTemp made
		// the file with O_EXCL under a random name.
		if cerr := os.Chmod(tmp, perm); cerr != nil {
			return fmt.Errorf("fsutil: chmod temp for %s: %w", path, err)
		}
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("fsutil: write temp for %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsutil: fsync temp for %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		f = nil
		return fmt.Errorf("fsutil: close temp for %s: %w", path, err)
	}
	f = nil

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("fsutil: rename temp onto %s: %w", path, err)
	}
	tmp = "" // renamed away; nothing left to clean up

	if err := FSync(dir); err != nil {
		return fmt.Errorf("fsutil: fsync dir of %s: %w", path, err)
	}
	return nil
}

// WriteJSONAtomic marshals v as indented JSON and writes it with
// WriteFileAtomic. It is how every hull state file (state.json, images.json,
// networks.json) reaches disk.
func WriteJSONAtomic(path string, v any, perm os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("fsutil: marshal json for %s: %w", path, err)
	}
	data = append(data, '\n')
	return WriteFileAtomic(path, data, perm)
}

// ReadJSON reads path and unmarshals it into v. A missing file is reported as
// an error wrapping fs.ErrNotExist, so callers can use errors.Is to treat it as
// "no state yet".
func ReadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("fsutil: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("fsutil: parse json in %s: %w", path, err)
	}
	return nil
}

// MkdirAllChown creates path and any missing parents with perm, and chowns
// every directory it actually created to uid/gid. Directories that already
// existed are left untouched, so it is safe to call on a shared tree. A
// negative uid or gid skips the chown, which is also what happens on platforms
// without POSIX ownership.
func MkdirAllChown(path string, perm os.FileMode, uid, gid int) error {
	if path == "" {
		return fmt.Errorf("fsutil: MkdirAllChown: empty path")
	}
	// Collect the missing prefixes, deepest first.
	var missing []string
	p := filepath.Clean(path)
	for {
		fi, err := os.Stat(p)
		if err == nil {
			if !fi.IsDir() {
				return fmt.Errorf("fsutil: MkdirAllChown: %s exists and is not a directory", p)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("fsutil: stat %s: %w", p, err)
		}
		missing = append(missing, p)
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	for i := len(missing) - 1; i >= 0; i-- {
		d := missing[i]
		if err := os.Mkdir(d, perm); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue // raced with another creator
			}
			return fmt.Errorf("fsutil: mkdir %s: %w", d, err)
		}
		// os.Mkdir applies the umask; force the requested bits back on.
		if err := os.Chmod(d, perm); err != nil {
			return fmt.Errorf("fsutil: chmod %s: %w", d, err)
		}
		if uid >= 0 || gid >= 0 {
			if err := os.Chown(d, uid, gid); err != nil {
				return fmt.Errorf("fsutil: chown %s: %w", d, err)
			}
		}
	}
	return nil
}

// CopyFile copies src to dst with the given permissions, atomically: the data
// lands in a temporary file in the destination directory, is fsynced, then
// renamed into place, and the directory is fsynced. dst is replaced only once
// its contents are complete and durable.
func CopyFile(dst, src string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("fsutil: open %s: %w", src, err)
	}
	defer in.Close()

	dir := filepath.Dir(dst)
	out, err := os.CreateTemp(dir, tmpPrefix+filepath.Base(dst)+".tmp")
	if err != nil {
		return fmt.Errorf("fsutil: create temp for %s: %w", dst, err)
	}
	tmp := out.Name()
	defer func() {
		if out != nil {
			out.Close()
		}
		if tmp != "" {
			os.Remove(tmp)
		}
	}()

	if err := out.Chmod(perm); err != nil {
		if cerr := os.Chmod(tmp, perm); cerr != nil {
			return fmt.Errorf("fsutil: chmod temp for %s: %w", dst, err)
		}
	}
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("fsutil: copy %s to %s: %w", src, dst, err)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("fsutil: fsync temp for %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		out = nil
		return fmt.Errorf("fsutil: close temp for %s: %w", dst, err)
	}
	out = nil

	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("fsutil: rename temp onto %s: %w", dst, err)
	}
	tmp = ""

	if err := FSync(dir); err != nil {
		return fmt.Errorf("fsutil: fsync dir of %s: %w", dst, err)
	}
	return nil
}

// FSync flushes a directory's entries to stable storage, which is what makes a
// rename durable. On platforms where directories cannot be synced (Windows) it
// is a documented no-op rather than an error, so the atomic-write helpers work
// there too.
func FSync(dir string) error { return fsyncDir(dir) }

// Exists reports whether path exists, without following a final symlink. A path
// that exists but cannot be stat'ed because of a permission error counts as
// existing.
func Exists(path string) bool {
	_, err := os.Lstat(path)
	if err == nil {
		return true
	}
	return !errors.Is(err, os.ErrNotExist)
}

// IsDir reports whether path exists and is a directory, following symlinks.
func IsDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// IsEscape reports, purely lexically, whether path would leave root. It follows
// no symlinks and touches no filesystem: it is the cheap early rejection in
// front of the Secure* functions, never the security boundary on its own.
//
// A relative path escapes when cleaning it leaves a leading "..". An absolute
// path escapes unless it is root itself or lies under it.
func IsEscape(root, path string) bool {
	if path == "" {
		return false
	}
	sp := filepath.ToSlash(path)
	if strings.HasPrefix(sp, "/") || filepath.IsAbs(path) {
		cr := cleanSlash(root)
		cp := cleanSlash(path)
		return cp != cr && !strings.HasPrefix(cp, strings.TrimSuffix(cr, "/")+"/")
	}
	cp := cleanSlash(path)
	return cp == ".." || strings.HasPrefix(cp, "../")
}

func cleanSlash(p string) string { return path.Clean(filepath.ToSlash(p)) }

// splitComponents splits a slash-separated path into its components, dropping
// empty and "." elements but keeping ".." for the resolver to clamp.
func splitComponents(p string) []string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	out := make([]string, 0, len(parts))
	for _, c := range parts {
		if c == "" || c == "." {
			continue
		}
		out = append(out, c)
	}
	return out
}

// Lock is a held advisory file lock. It owns the descriptor the lock sits on;
// Unlock releases the lock and closes that descriptor.
type Lock struct {
	f    *os.File
	path string
}

// Path returns the path of the file the lock is held on.
func (l *Lock) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}
