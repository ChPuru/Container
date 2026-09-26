//go:build linux

package volume

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/fsutil"
)

// maxSeedDepth bounds the recursion of a seeding copy. An image is attacker-
// supplied content; a pathological tree must exhaust a counter, not the stack.
const maxSeedDepth = 128

// copyImageContent copies the image's directory at rel (a path relative to
// rootfs) into dest, which is a hull-owned volume _data directory, and reports
// whether anything was copied.
//
// Security: rootfs is container-controlled, so the top of the tree is opened
// with fsutil.SecureOpen, i.e. openat2 with RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS,
// and every step below it is an fd-relative openat with O_NOFOLLOW. No path in
// the image is ever handed to filepath.Join + os.Open, and no symlink inside the
// image is ever followed: symlinks are recreated verbatim in the volume, which
// is what the image author meant and what Docker does.
//
// Ownership, mode and timestamps are preserved. When hull is not running as
// root the ownership change is refused by the kernel; that is tolerated (the
// files are already owned by the caller) rather than failing the copy.
func copyImageContent(dest, rootfs, rel string) (bool, error) {
	srcDir, err := fsutil.SecureOpen(rootfs, rel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		// Nothing at that path, something that is not a directory, or a
		// symlink that would leave the rootfs: in every case the image has no
		// seedable content there.
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOTDIR) ||
			errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
			return false, nil
		}
		return false, fmt.Errorf("open image content %s in %s: %w", rel, rootfs, err)
	}
	defer srcDir.Close()

	dstDir, err := os.OpenFile(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("open volume data dir %s: %w", dest, err)
	}
	defer dstDir.Close()

	var st unix.Stat_t
	if err := unix.Fstat(int(srcDir.Fd()), &st); err != nil {
		return false, fmt.Errorf("stat image content %s: %w", rel, err)
	}

	n, err := copyDirContents(srcDir, dstDir, 0)
	if err != nil {
		return false, err
	}

	// Mirror the image directory's own mode and ownership onto the volume root,
	// so a database that insists on 0700 data directories still starts.
	if err := unix.Fchmod(int(dstDir.Fd()), st.Mode&0o7777); err != nil {
		return n > 0, fmt.Errorf("chmod volume data dir %s: %w", dest, err)
	}
	if err := tolerateChown(unix.Fchown(int(dstDir.Fd()), int(st.Uid), int(st.Gid))); err != nil {
		return n > 0, fmt.Errorf("chown volume data dir %s: %w", dest, err)
	}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, dest, timespecs(&st), 0); err != nil {
		return n > 0, fmt.Errorf("set times on volume data dir %s: %w", dest, err)
	}
	return n > 0, nil
}

// copyDirContents copies every entry of src into dst, returning how many
// entries it created. src and dst are open directory descriptors; neither is
// closed here.
func copyDirContents(src, dst *os.File, depth int) (int, error) {
	if depth > maxSeedDepth {
		return 0, fmt.Errorf("image content is nested deeper than %d directories", maxSeedDepth)
	}
	entries, err := src.ReadDir(-1)
	if err != nil {
		return 0, fmt.Errorf("read image directory %s: %w", src.Name(), err)
	}
	count := 0
	for _, e := range entries {
		n, err := copyEntry(src, dst, e, depth)
		if err != nil {
			return count, fmt.Errorf("%s: %w", path.Join(src.Name(), e.Name()), err)
		}
		count += n
	}
	return count, nil
}

// copyEntry copies one directory entry. It never follows a symlink: a link is
// recreated as a link, and every open below the top uses O_NOFOLLOW.
func copyEntry(src, dst *os.File, e fs.DirEntry, depth int) (int, error) {
	name := e.Name()
	srcFd, dstFd := int(src.Fd()), int(dst.Fd())

	switch {
	case e.IsDir():
		childFd, err := unix.Openat(srcFd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return 0, fmt.Errorf("open directory: %w", err)
		}
		childSrc := os.NewFile(uintptr(childFd), path.Join(src.Name(), name))
		defer childSrc.Close()

		var st unix.Stat_t
		if err := unix.Fstat(childFd, &st); err != nil {
			return 0, fmt.Errorf("stat directory: %w", err)
		}
		if err := unix.Mkdirat(dstFd, name, st.Mode&0o7777); err != nil && !errors.Is(err, unix.EEXIST) {
			return 0, fmt.Errorf("mkdir in volume: %w", err)
		}
		childDstFd, err := unix.Openat(dstFd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return 0, fmt.Errorf("open new directory in volume: %w", err)
		}
		childDst := os.NewFile(uintptr(childDstFd), name)
		defer childDst.Close()

		n, err := copyDirContents(childSrc, childDst, depth+1)
		if err != nil {
			return n + 1, err
		}
		if err := applyAttrs(dstFd, name, &st, false); err != nil {
			return n + 1, err
		}
		return n + 1, nil

	case e.Type()&fs.ModeSymlink != 0:
		target, err := readLinkAt(srcFd, name)
		if err != nil {
			return 0, fmt.Errorf("read symlink: %w", err)
		}
		if err := unix.Symlinkat(target, dstFd, name); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return 0, nil
			}
			return 0, fmt.Errorf("create symlink in volume: %w", err)
		}
		var st unix.Stat_t
		if err := unix.Fstatat(srcFd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return 1, fmt.Errorf("stat symlink: %w", err)
		}
		if err := applyAttrs(dstFd, name, &st, true); err != nil {
			return 1, err
		}
		return 1, nil

	case e.Type().IsRegular():
		sfd, err := unix.Openat(srcFd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return 0, fmt.Errorf("open file: %w", err)
		}
		in := os.NewFile(uintptr(sfd), path.Join(src.Name(), name))
		defer in.Close()

		var st unix.Stat_t
		if err := unix.Fstat(sfd, &st); err != nil {
			return 0, fmt.Errorf("stat file: %w", err)
		}
		dfd, err := unix.Openat(dstFd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, st.Mode&0o7777)
		if err != nil {
			if errors.Is(err, unix.EEXIST) {
				return 0, nil
			}
			return 0, fmt.Errorf("create file in volume: %w", err)
		}
		out := os.NewFile(uintptr(dfd), name)
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return 1, fmt.Errorf("copy file into volume: %w", err)
		}
		if err := out.Close(); err != nil {
			return 1, fmt.Errorf("close file in volume: %w", err)
		}
		if err := applyAttrs(dstFd, name, &st, false); err != nil {
			return 1, err
		}
		return 1, nil

	case e.Type()&(fs.ModeDevice|fs.ModeCharDevice|fs.ModeNamedPipe) != 0:
		var st unix.Stat_t
		if err := unix.Fstatat(srcFd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return 0, fmt.Errorf("stat special file: %w", err)
		}
		if err := unix.Mknodat(dstFd, name, st.Mode, int(st.Rdev)); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return 0, nil
			}
			if errors.Is(err, unix.EPERM) && os.Geteuid() != 0 {
				// Unprivileged seeding cannot recreate a device node. Say so
				// instead of leaving a volume that silently lacks it.
				return 0, fmt.Errorf("cannot recreate device node without root: %w", err)
			}
			return 0, fmt.Errorf("mknod in volume: %w", err)
		}
		if err := applyAttrs(dstFd, name, &st, false); err != nil {
			return 1, err
		}
		return 1, nil

	default:
		// Sockets, and anything else the kernel invented since. A unix socket
		// in an image layer is a leftover, never content worth copying.
		return 0, nil
	}
}

// applyAttrs copies mode, ownership and timestamps from st onto the entry named
// name inside the destination directory dstFd. The destination tree is created
// by hull and is not container-controlled, so name-relative operations are safe
// here; they are still O_NOFOLLOW-equivalent, because a symlink gets
// AT_SYMLINK_NOFOLLOW and never a chmod.
func applyAttrs(dstFd int, name string, st *unix.Stat_t, isSymlink bool) error {
	if !isSymlink {
		if err := unix.Fchmodat(dstFd, name, st.Mode&0o7777, 0); err != nil {
			return fmt.Errorf("chmod %s in volume: %w", name, err)
		}
	}
	if err := tolerateChown(unix.Fchownat(dstFd, name, int(st.Uid), int(st.Gid), unix.AT_SYMLINK_NOFOLLOW)); err != nil {
		return fmt.Errorf("chown %s in volume: %w", name, err)
	}
	if err := unix.UtimesNanoAt(dstFd, name, timespecs(st), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("set times on %s in volume: %w", name, err)
	}
	return nil
}

// timespecs returns the atime/mtime pair to restore from a stat result.
func timespecs(st *unix.Stat_t) []unix.Timespec {
	return []unix.Timespec{
		{Sec: st.Atim.Sec, Nsec: st.Atim.Nsec},
		{Sec: st.Mtim.Sec, Nsec: st.Mtim.Nsec},
	}
}

// tolerateChown swallows the refusal an unprivileged process gets when it tries
// to hand a file to another user. The daemon runs as root, where this never
// fires; the tests, and a rootless experiment, run without it.
func tolerateChown(err error) error {
	if err == nil {
		return nil
	}
	if (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EINVAL)) && os.Geteuid() != 0 {
		return nil
	}
	return err
}

// readLinkAt reads the target of a symlink relative to an open directory fd,
// growing the buffer until the whole target fits.
func readLinkAt(dirFd int, name string) (string, error) {
	for size := 256; size <= unix.PathMax; size *= 2 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(dirFd, name, buf)
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
	return "", fmt.Errorf("symlink target longer than %d bytes", unix.PathMax)
}
