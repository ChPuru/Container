package initspec

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// ptsMajor is the device major number of the UNIX98 pseudo-terminal slave
// devices (/dev/pts/N). A console fd that is not one of these is not a console
// hull handed out.
const ptsMajor = 136

// VerifyConsoleFD checks, by fd and fd alone, that the descriptor really is a
// pty peer before anything is dup'd onto it.
//
// The 2025 runc breakouts (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881) all
// came from the runtime trusting a *path* under a container-controlled rootfs
// to still be the device it was a moment ago. hull never re-opens the console
// by path: the runtime opens the pty peer on the host, passes the descriptor,
// and the container stage confirms with fstat that it is a character device in
// the pts major before using it.
func VerifyConsoleFD(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("initspec: fstat console fd %d: %w", fd, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return fmt.Errorf("initspec: console fd %d is not a character device (mode %#o); "+
			"refusing to use it as the container console", fd, st.Mode)
	}
	if maj := unix.Major(uint64(st.Rdev)); maj != ptsMajor {
		return fmt.Errorf("initspec: console fd %d has device major %d, expected %d (UNIX98 pts); "+
			"refusing to use it as the container console", fd, maj, ptsMajor)
	}
	if _, err := unix.IoctlGetTermios(fd, unix.TCGETS); err != nil {
		return fmt.Errorf("initspec: console fd %d is not a terminal: %w", fd, err)
	}
	return nil
}

// VerifyCharDevice checks that fd is a character device with the expected
// major and minor numbers. It is how the stage confirms that, for example, the
// descriptor it is about to bind over a masked path really is /dev/null (1:3)
// and not something a malicious image left in its place.
func VerifyCharDevice(fd int, major, minor uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("initspec: fstat fd %d: %w", fd, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return fmt.Errorf("initspec: fd %d is not a character device (mode %#o)", fd, st.Mode)
	}
	gotMaj, gotMin := unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev))
	if gotMaj != major || gotMin != minor {
		return fmt.Errorf("initspec: fd %d is device %d:%d, expected %d:%d",
			fd, gotMaj, gotMin, major, minor)
	}
	return nil
}

// SetControllingTerminal makes fd the calling process's controlling terminal
// and installs it as stdin, stdout and stderr. The caller must already be a
// session leader (setsid) and must have verified fd with VerifyConsoleFD.
func SetControllingTerminal(fd int) error {
	if err := unix.IoctlSetInt(fd, unix.TIOCSCTTY, 0); err != nil {
		return fmt.Errorf("initspec: ioctl(TIOCSCTTY) on console fd %d: %w", fd, err)
	}
	for _, std := range []int{0, 1, 2} {
		if err := dup3(fd, std); err != nil {
			return fmt.Errorf("initspec: dup console fd %d onto %d: %w", fd, std, err)
		}
	}
	return nil
}

// dup3 duplicates old onto new, clearing CLOEXEC, and tolerates old == new.
func dup3(old, new int) error {
	if old == new {
		_, err := unix.FcntlInt(uintptr(old), unix.F_SETFD, 0)
		return err
	}
	return unix.Dup3(old, new, 0)
}
