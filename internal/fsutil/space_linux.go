package fsutil

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// FreeSpace reports the bytes available to an unprivileged writer and the total
// size of the filesystem holding path. hull uses it to refuse an image pull
// that cannot fit, rather than filling the VM disk and wedging the distro.
//
// free comes from statfs f_bavail (blocks available to non-root), not f_bfree,
// so the number matches what a container can actually write.
func FreeSpace(path string) (free, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, &os.PathError{Op: "statfs", Path: path, Err: err}
	}
	bs := uint64(st.Bsize)
	return st.Bavail * bs, st.Blocks * bs, nil
}

// IsMountpoint reports whether path is the root of a mount.
//
// It first compares the device of path and its parent, which catches every
// mount onto a different filesystem, then falls back to /proc/self/mountinfo,
// which is the only way to see a bind mount of one directory onto another on
// the same filesystem — exactly the case hull hits with /mnt/wsl binds and with
// overlay upperdir binds.
func IsMountpoint(path string) (bool, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return false, &os.PathError{Op: "lstat", Path: path, Err: err}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, fmt.Errorf("fsutil: absolute path for %s: %w", path, err)
	}
	abs = filepath.Clean(abs)

	parent := filepath.Dir(abs)
	var pst unix.Stat_t
	if err := unix.Lstat(parent, &pst); err != nil {
		return false, &os.PathError{Op: "lstat", Path: parent, Err: err}
	}
	if st.Dev != pst.Dev {
		return true, nil
	}
	if st.Ino == pst.Ino {
		return true, nil // "/" is its own parent
	}
	return mountinfoHas(abs)
}

// mountinfoHas scans /proc/self/mountinfo for an exact mount point match. Field
// 5 (1-indexed) is the mount point, with spaces, tabs, newlines and backslashes
// escaped in octal.
func mountinfoHas(target string) (bool, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, fmt.Errorf("fsutil: read mountinfo: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		if unescapeMountinfo(fields[4]) == target {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("fsutil: scan mountinfo: %w", err)
	}
	return false, nil
}

// unescapeMountinfo reverses the octal escaping the kernel applies to mountinfo
// path fields.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
