package initspec

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

// capLastCapPath is the kernel's own statement of the highest capability bit
// it implements. Dropping bits above it from the bounding set returns EINVAL,
// which would otherwise abort the drop loop early and leave real capabilities
// in the bounding set.
const capLastCapPath = "/proc/sys/kernel/cap_last_cap"

// KernelLastCap reads /proc/sys/kernel/cap_last_cap, falling back to the
// highest capability hull knows about when the file is unreadable.
func KernelLastCap() int {
	b, err := os.ReadFile(capLastCapPath)
	if err != nil {
		return CapLast
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n < 0 || n > 63 {
		return CapLast
	}
	return n
}

// ApplyCapabilities installs the five capability sets on the calling process,
// in the only order that works:
//
//  1. the bounding set is shrunk first, with PR_CAPBSET_DROP, because a
//     capability left in the bounding set can be regained across execve;
//  2. capset(2) then sets effective, permitted and inheritable together;
//  3. the ambient set is cleared and raised last, because a capability can
//     only be made ambient once it is both permitted and inheritable.
//
// A nil caps argument drops everything: no bounding, no permitted, no ambient.
// That is the safe reading of "the spec did not ask for any capability".
func ApplyCapabilities(caps *runtimespec.LinuxCapabilities) error {
	var bounding, effective, permitted, inheritable, ambient capMask
	var err error
	if caps != nil {
		if bounding, err = maskOf(caps.Bounding); err != nil {
			return err
		}
		if effective, err = maskOf(caps.Effective); err != nil {
			return err
		}
		if permitted, err = maskOf(caps.Permitted); err != nil {
			return err
		}
		if inheritable, err = maskOf(caps.Inheritable); err != nil {
			return err
		}
		if ambient, err = maskOf(caps.Ambient); err != nil {
			return err
		}
	}

	last := KernelLastCap()
	for bit := 0; bit <= last; bit++ {
		if bounding.has(bit) {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(bit), 0, 0, 0); err != nil {
			if err == unix.EINVAL {
				// The kernel does not implement this bit; nothing to drop.
				continue
			}
			if err == unix.EPERM {
				return fmt.Errorf("initspec: prctl(PR_CAPBSET_DROP, %d): %w "+
					"(CAP_SETPCAP is required to shrink the bounding set)", bit, err)
			}
			return fmt.Errorf("initspec: prctl(PR_CAPBSET_DROP, %d): %w", bit, err)
		}
	}

	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var data [2]unix.CapUserData
	data[0].Effective, data[1].Effective = effective.lo(), effective.hi()
	data[0].Permitted, data[1].Permitted = permitted.lo(), permitted.hi()
	data[0].Inheritable, data[1].Inheritable = inheritable.lo(), inheritable.hi()
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("initspec: capset(effective=%#x permitted=%#x inheritable=%#x): %w",
			uint64(effective), uint64(permitted), uint64(inheritable), err)
	}

	// PR_CAP_AMBIENT_CLEAR_ALL is unavailable before 4.3; on such a kernel
	// there is no ambient set to clear either.
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil &&
		err != unix.EINVAL {
		return fmt.Errorf("initspec: prctl(PR_CAP_AMBIENT_CLEAR_ALL): %w", err)
	}
	for bit := 0; bit <= last; bit++ {
		if !ambient.has(bit) {
			continue
		}
		if !permitted.has(bit) || !inheritable.has(bit) {
			return fmt.Errorf("initspec: capability bit %d is in the ambient set but not in both "+
				"permitted and inheritable; the kernel would refuse to raise it", bit)
		}
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(bit), 0, 0); err != nil {
			return fmt.Errorf("initspec: prctl(PR_CAP_AMBIENT_RAISE, %d): %w", bit, err)
		}
	}
	return nil
}

// SetKeepCaps sets or clears PR_SET_KEEPCAPS, which decides whether the
// permitted set survives a switch away from uid 0. It must be set before the
// setresuid in the privilege drop and is redundant afterwards, since capset
// runs after the drop.
func SetKeepCaps(on bool) error {
	v := uintptr(0)
	if on {
		v = 1
	}
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, v, 0, 0, 0); err != nil {
		return fmt.Errorf("initspec: prctl(PR_SET_KEEPCAPS, %d): %w", v, err)
	}
	return nil
}

// DropPrivileges switches to the container's target credentials in the only
// safe order: supplementary groups first, then the gid, then the uid. Doing
// the uid first would drop the very privilege needed to change the groups, and
// leaving the host's supplementary groups in place would hand the container
// group-based access to host files.
func DropPrivileges(u runtimespec.User) error {
	groups := make([]int, 0, len(u.AdditionalGids))
	for _, g := range u.AdditionalGids {
		groups = append(groups, int(g))
	}
	if err := unix.Setgroups(groups); err != nil {
		// An unprivileged user namespace with setgroups denied cannot
		// change the (empty) supplementary set; that is not a failure.
		if !(err == unix.EPERM && len(groups) == 0) {
			return fmt.Errorf("initspec: setgroups(%v): %w", groups, err)
		}
	}
	if err := unix.Setresgid(int(u.GID), int(u.GID), int(u.GID)); err != nil {
		return fmt.Errorf("initspec: setresgid(%d): %w", u.GID, err)
	}
	if err := unix.Setresuid(int(u.UID), int(u.UID), int(u.UID)); err != nil {
		return fmt.Errorf("initspec: setresuid(%d): %w", u.UID, err)
	}
	return nil
}
