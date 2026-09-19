package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/rahuldhali/hull/internal/cgroups"
	"github.com/rahuldhali/hull/internal/runtime/initspec"
)

// Syscall numbers hull probes for directly. They are spelled out rather than
// taken from unix.SYS_* so the probe compiles even where x/sys has not caught
// up with a syscall, and so a missing constant can never be mistaken for a
// missing kernel feature.
const (
	sysClone3       = 435
	sysFsopen       = 430
	sysOpenTree     = 428
	sysMountSetattr = 442
)

var (
	probeOnce   sync.Once
	probeResult Features
	probeErr    error
)

// ProbeFeatures probes the running kernel for every facility the native
// runtime is built on and caches the answer for the life of the process.
//
// Nothing is inferred from the kernel version string. The WSL 5.15 kernel has
// clone3, openat2, pidfd and the new mount API but no PSI and no delegated
// cgroup v2 controllers, and the 6.6 kernel flips several of those; a version
// comparison would get it wrong in both directions.
func ProbeFeatures(ctx context.Context) (Features, error) {
	probeOnce.Do(func() {
		probeResult, probeErr = probeFeatures(ctx)
	})
	return probeResult, probeErr
}

func probeFeatures(ctx context.Context) (Features, error) {
	if err := ctx.Err(); err != nil {
		return Features{}, err
	}
	f := Features{}

	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		f.Kernel = strings.TrimRight(string(uts.Release[:]), "\x00")
	}

	f.Clone3 = probeClone3()
	f.Openat2 = initspec.HaveOpenat2()
	f.MountAPI = probeFsopen()
	f.OpenTree = probeOpenTree()
	f.PidfdSendSignal = initspec.HavePidfdSendSignal()
	f.CloseRange = initspec.HaveCloseRange()
	f.Seccomp = initspec.SeccompSupported()
	f.IDMappedMounts = probeMountSetattr()
	f.UserNamespaces = probeUserNamespaces()

	actions, err := initspec.SeccompActionsAvailable()
	if err == nil {
		f.SeccompActions = actions
	}

	info, cerr := cgroups.Detect()
	if cerr == nil {
		f.CgroupV2 = info.Usable()
		f.CgroupKill = info.HasKill
		// CLONE_INTO_CGROUP needs clone3 and a cgroup v2 directory fd; the
		// cgroups probe already answered whether the kernel is new enough.
		f.CloneIntoCgroup = f.Clone3 && info.HasCloneInto && info.Usable()
		f.Warnings = append(f.Warnings, info.Warnings...)
	} else if !errors.Is(cerr, cgroups.ErrUnsupported) {
		f.Warnings = append(f.Warnings, fmt.Sprintf("cgroup probe failed: %v", cerr))
	}

	if !f.CgroupV2 {
		f.Warnings = append(f.Warnings, cgroups.HybridRemedy)
	}
	if !f.Clone3 {
		f.Warnings = append(f.Warnings, "the kernel has no clone3(2); hull will fork and then move the "+
			"container into its cgroup, which leaves a short window where the container is unconstrained")
	}
	if !f.Openat2 {
		f.Warnings = append(f.Warnings, "the kernel has no openat2(2); hull falls back to an fd-relative "+
			"path walk, which contains symlink escapes but is not atomic")
	}
	if !f.PidfdSendSignal {
		f.Warnings = append(f.Warnings, "the kernel has no pidfd_send_signal(2); the native runtime "+
			"cannot signal a container without racing pid reuse and will refuse to start one")
	}
	if !f.Seccomp {
		f.Warnings = append(f.Warnings, "the kernel has no seccomp(2); containers will run without a "+
			"syscall filter")
	}
	if !f.UserNamespaces {
		f.Warnings = append(f.Warnings, "unprivileged user namespaces are disabled "+
			"(/proc/sys/kernel/unprivileged_userns_clone or user.max_user_namespaces); hull cannot "+
			"give containers their own uid range")
	}
	return f, nil
}

// probeClone3 calls clone3 with a zero-size argument struct. A kernel that
// implements it answers EINVAL; one that does not answers ENOSYS. Neither
// creates a process, so the probe is free of side effects.
func probeClone3() bool {
	_, _, errno := unix.RawSyscall(sysClone3, 0, 0, 0)
	return errno != unix.ENOSYS
}

// probeFsopen calls fsopen with a filesystem name that cannot exist. A kernel
// with the new mount API answers ENODEV; one without answers ENOSYS.
func probeFsopen() bool {
	name, err := unix.BytePtrFromString("hull-probe-no-such-fs")
	if err != nil {
		return false
	}
	fd, _, errno := unix.RawSyscall(sysFsopen, uintptr(unsafe.Pointer(name)), 0, 0)
	if errno == 0 {
		unix.Close(int(fd))
		return true
	}
	return errno != unix.ENOSYS
}

// probeOpenTree calls open_tree with an invalid descriptor: EBADF means the
// syscall exists, ENOSYS means it does not.
func probeOpenTree() bool {
	empty, err := unix.BytePtrFromString("")
	if err != nil {
		return false
	}
	fd, _, errno := unix.RawSyscall(sysOpenTree, uintptr(^uintptr(0)), uintptr(unsafe.Pointer(empty)), 0)
	if errno == 0 {
		unix.Close(int(fd))
		return true
	}
	return errno != unix.ENOSYS
}

// probeMountSetattr calls mount_setattr with a null attr pointer: EINVAL on a
// kernel that has it (5.12+), ENOSYS on one that does not.
func probeMountSetattr() bool {
	empty, err := unix.BytePtrFromString("")
	if err != nil {
		return false
	}
	atfd := unix.AT_FDCWD
	_, _, errno := unix.RawSyscall6(sysMountSetattr, uintptr(atfd),
		uintptr(unsafe.Pointer(empty)), 0, 0, 0, 0)
	return errno != unix.ENOSYS
}

// probeUserNamespaces reports whether this host will let hull create a user
// namespace. It reads the two knobs distributions use to switch the feature
// off rather than trying to create one, which would need a fork.
func probeUserNamespaces() bool {
	if b, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n <= 0 {
			return false
		}
	}
	// Debian and Ubuntu historically gated this separately.
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(b)) == "0" && os.Geteuid() != 0 {
			return false
		}
	}
	// The namespace type must at least exist.
	if _, err := os.Stat("/proc/self/ns/user"); err != nil {
		return false
	}
	return true
}
