package initspec

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// seccomp(2) operations, from linux/seccomp.h.
const (
	seccompSetModeFilter  = 1
	seccompGetActionAvail = 2
)

// Install loads the compiled filter on the calling thread group with
// seccomp(SECCOMP_SET_MODE_FILTER).
//
// It refuses to run unless no_new_privs is already set, because a filter
// installed without it can be escaped through a setuid binary and is worse
// than no filter at all: it tells the operator the process is confined when it
// is not. Callers must therefore call SetNoNewPrivs first.
func (p *Program) Install() error {
	if p == nil || len(p.Insns) == 0 {
		return fmt.Errorf("initspec: refusing to install an empty seccomp filter")
	}
	if len(p.Insns) > BPFMaxInsns {
		return fmt.Errorf("initspec: filter is %d instructions: %w", len(p.Insns), ErrFilterTooLarge)
	}
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("initspec: prctl(PR_GET_NO_NEW_PRIVS): %w", err)
	}
	if nnp != 1 {
		return fmt.Errorf("initspec: no_new_privs is not set; a seccomp filter must never be " +
			"installed before it, or a setuid binary escapes the filter")
	}

	filter := make([]unix.SockFilter, len(p.Insns))
	for i, in := range p.Insns {
		filter[i] = unix.SockFilter{Code: in.Code, Jt: in.JT, Jf: in.JF, K: in.K}
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}

	// TSYNC is deliberately not set: the container stage is single-purpose
	// and about to execve, and TSYNC turns a partially-failed apply into a
	// silent one on some kernels.
	flags := uintptr(p.Flags)
	_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, seccompSetModeFilter, flags,
		uintptr(unsafe.Pointer(&prog)))
	if errno == 0 {
		runtime.KeepAlive(filter)
		return nil
	}
	if errno == unix.EINVAL && p.Flags != 0 {
		// An older kernel may not know one of the flags. Retry bare
		// rather than leave the process unconfined, and say so.
		_, _, errno2 := unix.RawSyscall(unix.SYS_SECCOMP, seccompSetModeFilter, 0,
			uintptr(unsafe.Pointer(&prog)))
		if errno2 == 0 {
			runtime.KeepAlive(filter)
			return nil
		}
		return fmt.Errorf("initspec: seccomp(SECCOMP_SET_MODE_FILTER) with flags %#x failed (%w) "+
			"and without flags failed too: %w", p.Flags, errno, errno2)
	}
	return fmt.Errorf("initspec: seccomp(SECCOMP_SET_MODE_FILTER, flags=%#x, %d insns): %w",
		p.Flags, len(filter), errno)
}

// SetNoNewPrivs sets PR_SET_NO_NEW_PRIVS. It is irreversible for the life of
// the process, which is the point: after it, execve can never grant a
// privilege the caller does not already hold.
func SetNoNewPrivs() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("initspec: prctl(PR_SET_NO_NEW_PRIVS, 1): %w", err)
	}
	return nil
}

// SeccompActionsAvailable reads /proc/sys/kernel/seccomp/actions_avail, the
// kernel's own list of the SECCOMP_RET_* actions it implements. An empty slice
// with a nil error means the kernel does not publish the file, which on Linux
// means seccomp predates it rather than that seccomp is missing.
func SeccompActionsAvailable() ([]string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/seccomp/actions_avail")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("initspec: read seccomp actions_avail: %w", err)
	}
	return strings.Fields(string(b)), nil
}

// SeccompSupported reports whether the kernel implements
// seccomp(SECCOMP_GET_ACTION_AVAIL), which is the cheapest side-effect-free
// probe for seccomp being compiled in at all.
func SeccompSupported() bool {
	var act uint32 = RetAllow
	_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, seccompGetActionAvail, 0,
		uintptr(unsafe.Pointer(&act)))
	return errno != unix.ENOSYS
}
