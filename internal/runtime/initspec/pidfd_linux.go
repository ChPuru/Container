package initspec

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ErrNoPidfd reports that the kernel lacks pidfd_open(2) or
// pidfd_send_signal(2). hull refuses to fall back to kill(2) on a bare pid:
// pids are recycled, and signalling a recycled pid is how a container escape
// turns into a host process being killed.
var ErrNoPidfd = errors.New("initspec: the kernel has no pidfd_send_signal(2)")

// PidfdOpen returns a pidfd for pid. The descriptor is CLOEXEC and refers to
// the process itself, so it stays valid - and stays refusing to signal - after
// the pid has been reaped and reused.
func PidfdOpen(pid int) (*os.File, error) {
	fd, err := unix.PidfdOpen(pid, unix.PIDFD_NONBLOCK)
	if err != nil {
		if errors.Is(err, unix.EINVAL) {
			// PIDFD_NONBLOCK arrived in 5.10; retry without it.
			fd, err = unix.PidfdOpen(pid, 0)
		}
	}
	if err != nil {
		if errors.Is(err, unix.ENOSYS) {
			return nil, fmt.Errorf("pidfd_open(%d): %w", pid, ErrNoPidfd)
		}
		return nil, fmt.Errorf("initspec: pidfd_open(%d): %w", pid, err)
	}
	return os.NewFile(uintptr(fd), fmt.Sprintf("pidfd:%d", pid)), nil
}

// PidfdSendSignal signals the process a pidfd refers to. A signal of 0 is the
// liveness probe: it returns nil while the process exists and ESRCH once it
// has been reaped.
func PidfdSendSignal(pidfd int, sig unix.Signal) error {
	if err := unix.PidfdSendSignal(pidfd, sig, nil, 0); err != nil {
		if errors.Is(err, unix.ENOSYS) {
			return fmt.Errorf("pidfd_send_signal: %w", ErrNoPidfd)
		}
		return fmt.Errorf("initspec: pidfd_send_signal(sig %d): %w", int(sig), err)
	}
	return nil
}

// PidfdAlive reports whether the process behind pidfd still exists.
func PidfdAlive(pidfd int) bool {
	err := unix.PidfdSendSignal(pidfd, 0, nil, 0)
	return err == nil
}

// HavePidfdSendSignal probes pidfd_open plus pidfd_send_signal against the
// calling process with signal 0, which has no effect.
func HavePidfdSendSignal() bool {
	f, err := PidfdOpen(os.Getpid())
	if err != nil {
		return false
	}
	defer f.Close()
	return !errors.Is(PidfdSendSignal(int(f.Fd()), 0), ErrNoPidfd)
}

// nsFlags maps a namespace name to the CLONE_NEW* flag setns(2) takes.
var nsFlags = map[string]int{
	"mount":   unix.CLONE_NEWNS,
	"network": unix.CLONE_NEWNET,
	"ipc":     unix.CLONE_NEWIPC,
	"uts":     unix.CLONE_NEWUTS,
	"pid":     unix.CLONE_NEWPID,
	"user":    unix.CLONE_NEWUSER,
	"cgroup":  unix.CLONE_NEWCGROUP,
	"time":    unix.CLONE_NEWTIME,
}

// NamespaceFlag maps a runtime-spec namespace type to its CLONE_NEW* flag.
func NamespaceFlag(name string) (int, bool) {
	f, ok := nsFlags[name]
	return f, ok
}

// SetnsPidfd joins the namespaces named by flags using a pidfd, which is
// race-free in a way that opening /proc/<pid>/ns/<type> by path is not: the
// pidfd cannot start referring to a different process between the open and the
// setns.
func SetnsPidfd(pidfd int, flags int) error {
	if err := unix.Setns(pidfd, flags); err != nil {
		return fmt.Errorf("initspec: setns(pidfd, %#x): %w", flags, err)
	}
	return nil
}
