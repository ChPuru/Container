//go:build linux

package bundle

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// statDevice reads the major/minor numbers, mode and ownership of a host device
// node so --device can be reproduced faithfully inside the container.
//
// The path is a host path, not a container path, so a plain stat is correct
// here; container-relative resolution goes through fsutil.SecureOpen instead.
func statDevice(hostPath string) (deviceInfo, error) {
	var out deviceInfo
	var st unix.Stat_t
	if err := unix.Stat(hostPath, &st); err != nil {
		if os.IsNotExist(err) {
			return out, fmt.Errorf("%s does not exist on the host", hostPath)
		}
		return out, fmt.Errorf("stat %s: %w", hostPath, err)
	}

	switch st.Mode & unix.S_IFMT {
	case unix.S_IFCHR:
		out.Kind = "c"
	case unix.S_IFBLK:
		out.Kind = "b"
	default:
		return out, fmt.Errorf("%s is not a block or character device", hostPath)
	}

	out.Major = int64(unix.Major(uint64(st.Rdev)))
	out.Minor = int64(unix.Minor(uint64(st.Rdev)))
	out.Mode = uint32(st.Mode & 0o7777)
	out.UID = st.Uid
	out.GID = st.Gid
	return out, nil
}
