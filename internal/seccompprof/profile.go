// Package seccompprof builds hull's seccomp-bpf profiles as OCI
// runtime-spec LinuxSeccomp values.
//
// The default profile is modelled on Docker's, but it is written from the
// syscall tables and the kernel documentation rather than copied wholesale:
// every rule below has a reason recorded next to it. The shape is a
// deny-by-default allowlist — DefaultAction is SCMP_ACT_ERRNO returning
// EPERM — with a small number of argument-conditioned rules for the syscalls
// that are only dangerous in particular shapes (clone, socket, personality),
// and a set of rules that are unlocked only when the container actually holds
// the matching capability.
//
// A filter is only a hardening measure if no_new_privs is set first. hull's
// runtime sets Process.NoNewPrivileges before it loads the program; see
// ARCHITECTURE.md, "Security posture".
package seccompprof

import (
	"runtime"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

// Errno values returned by the default profile. EPERM is the default for
// anything not on the allowlist; ENOSYS is used where a userspace library
// must be able to detect "this kernel does not have it" and fall back.
const (
	errnoEPERM  uint = 1
	errnoENOSYS uint = 38
)

// Namespace-creating clone(2) flags. The default profile allows clone only
// when every one of these bits is clear, which is what stops a container from
// building a fresh user namespace and re-acquiring capabilities inside it.
const (
	cloneNewNS     = 0x00020000 // CLONE_NEWNS
	cloneNewCgroup = 0x02000000 // CLONE_NEWCGROUP
	cloneNewUTS    = 0x04000000 // CLONE_NEWUTS
	cloneNewIPC    = 0x08000000 // CLONE_NEWIPC
	cloneNewUser   = 0x10000000 // CLONE_NEWUSER
	cloneNewPID    = 0x20000000 // CLONE_NEWPID
	cloneNewNet    = 0x40000000 // CLONE_NEWNET
)

// CloneNamespaceFlags is the OR of every namespace-creating clone(2) flag.
// The default profile masks clone's first argument against it and requires
// the result to be zero.
const CloneNamespaceFlags uint64 = cloneNewNS | cloneNewCgroup | cloneNewUTS |
	cloneNewIPC | cloneNewUser | cloneNewPID | cloneNewNet

// afVSOCK is AF_VSOCK. A container that can open an AF_VSOCK socket can talk
// to the hypervisor, which on WSL2 means talking past the VM boundary, so the
// default profile refuses it unless the container has CAP_SYS_ADMIN.
const afVSOCK uint64 = 40

// Personality values the default profile permits: 0 (PER_LINUX),
// 0x0008 (PER_LINUX32), 0x20000 (READ_IMPLIES_EXEC), their combination, and
// 0xffffffff, which is the "query, do not change" form. Everything else is a
// request to emulate a different ABI and is denied.
var allowedPersonalities = []uint64{0x0, 0x8, 0x20000, 0x20008, 0xffffffff}

// Unconfined returns the profile for a container that must run without any
// seccomp filter at all. It is nil: the runtime spec expresses "no filter" by
// omitting the seccomp block, and hull never installs an allow-everything
// filter, which would only cost syscall performance while providing nothing.
func Unconfined() *runtimespec.LinuxSeccomp { return nil }

// Default returns hull's default seccomp profile: deny by default with EPERM,
// an allowlist covering ordinary Linux workloads, and conditional rules for
// clone, clone3, socket and personality. It grants nothing that depends on a
// capability; ForCapabilities layers those on.
//
// Every call returns a freshly allocated profile, so callers may mutate it.
func Default() *runtimespec.LinuxSeccomp {
	errno := errnoEPERM
	p := &runtimespec.LinuxSeccomp{
		DefaultAction:   runtimespec.ActErrno,
		DefaultErrnoRet: &errno,
		Architectures:   Architectures(),
	}

	p.Syscalls = append(p.Syscalls, runtimespec.LinuxSyscall{
		Names:  allowedSyscalls(),
		Action: runtimespec.ActAllow,
	})

	// ptrace is safe to allow on kernels >= 4.8: since commit 8112c4f1 the
	// seccomp filter of a tracee is inherited across PTRACE_ATTACH, so a
	// traced process cannot be used to escape the filter. The WSL kernels
	// hull targets (5.15 and 6.x) are all well past that.
	p.Syscalls = append(p.Syscalls, runtimespec.LinuxSyscall{
		Names:  []string{"ptrace"},
		Action: runtimespec.ActAllow,
	})

	// personality: only the identity-ish values, one rule per value because
	// argument predicates within a rule are ANDed, not ORed.
	for _, v := range allowedPersonalities {
		p.Syscalls = append(p.Syscalls, runtimespec.LinuxSyscall{
			Names:  []string{"personality"},
			Action: runtimespec.ActAllow,
			Args: []runtimespec.LinuxSeccompArg{{
				Index: 0,
				Value: v,
				Op:    runtimespec.OpEqualTo,
			}},
		})
	}

	// socket: everything except AF_VSOCK.
	p.Syscalls = append(p.Syscalls, runtimespec.LinuxSyscall{
		Names:  []string{"socket"},
		Action: runtimespec.ActAllow,
		Args: []runtimespec.LinuxSeccompArg{{
			Index: 0,
			Value: afVSOCK,
			Op:    runtimespec.OpNotEqual,
		}},
	})

	// clone: allowed only when no namespace-creating flag is set.
	p.Syscalls = append(p.Syscalls, cloneRestrictedRule())

	// clone3 takes its flags in a struct the filter cannot dereference, so it
	// cannot be restricted the way clone can. Return ENOSYS rather than EPERM
	// so that glibc's pthread_create sees "kernel too old" and falls back to
	// clone, which the rule above does constrain. EPERM here breaks every
	// glibc-based image.
	ret := errnoENOSYS
	p.Syscalls = append(p.Syscalls, runtimespec.LinuxSyscall{
		Names:    []string{"clone3"},
		Action:   runtimespec.ActErrno,
		ErrnoRet: &ret,
	})

	return p
}

// cloneRestrictedRule is the default clone rule: arg0 masked against every
// namespace flag must be zero.
func cloneRestrictedRule() runtimespec.LinuxSyscall {
	return runtimespec.LinuxSyscall{
		Names:  []string{"clone"},
		Action: runtimespec.ActAllow,
		Args: []runtimespec.LinuxSeccompArg{{
			Index:    cloneFlagsArgIndex(),
			Value:    CloneNamespaceFlags,
			ValueTwo: 0,
			Op:       runtimespec.OpMaskedEqual,
		}},
	}
}

// cloneFlagsArgIndex is the index of clone(2)'s flags argument. Every
// architecture hull supports puts it first; s390 and s390x swap the first two
// arguments, which is a TODO if hull is ever ported there.
func cloneFlagsArgIndex() uint { return 0 }

// Architectures returns the seccomp architecture tokens for the current
// build. A filter must name every ABI a process can issue syscalls through,
// not just the native one: on x86_64 a 32-bit or x32 binary would otherwise
// bypass the whole filter.
func Architectures() []runtimespec.Arch {
	switch runtime.GOARCH {
	case "arm64":
		return []runtimespec.Arch{runtimespec.ArchAARCH64, runtimespec.ArchARM}
	case "arm":
		return []runtimespec.Arch{runtimespec.ArchARM}
	default:
		// amd64 and 386 both need the full x86 family.
		return []runtimespec.Arch{
			runtimespec.ArchX86_64,
			runtimespec.ArchX86,
			runtimespec.ArchX32,
		}
	}
}

// allowedSyscalls returns the architecture-independent allowlist plus the
// arch-specific additions for the current GOARCH.
func allowedSyscalls() []string {
	out := make([]string, 0, len(baseAllow)+8)
	out = append(out, baseAllow...)
	out = append(out, archAllow()...)
	return out
}

// archAllow returns the syscalls that only exist on some architectures.
func archAllow() []string {
	switch runtime.GOARCH {
	case "arm64", "arm":
		return []string{
			"arm_fadvise64_64",
			"arm_sync_file_range",
			"breakpoint",
			"cacheflush",
			"set_tls",
			"sync_file_range2",
		}
	default:
		// x86 family. arch_prctl is how a 64-bit process sets %fs, so every
		// threaded program needs it; modify_ldt is needed by wine and by some
		// JITs and is harmless without CAP_SYS_ADMIN.
		return []string{"arch_prctl", "modify_ldt"}
	}
}

// baseAllow is the architecture-independent allowlist: the syscalls an
// ordinary containerised workload issues. It is deliberately long. A short
// list looks safer and is not: it breaks real images in ways that are hard to
// diagnose, which pushes users to --security-opt seccomp=unconfined, which
// removes the filter entirely.
//
// The list includes the time64 and 32-bit compat variants (clock_gettime64,
// fstat64, _llseek, ...) because a 32-bit process on an x86_64 kernel issues
// those, and the filter covers SCMP_ARCH_X86 as well as SCMP_ARCH_X86_64.
//
// Deliberately absent, and only reachable through the conditional rules or a
// capability gate: clone, clone3, socket, personality, ptrace, mount, umount,
// umount2, pivot_root, setns, unshare, open_tree, move_mount, fsopen,
// fsconfig, fsmount, fspick, mount_setattr, init_module, finit_module,
// delete_module, kexec_load, kexec_file_load, bpf, reboot, chroot, iopl,
// ioperm, syslog, acct, settimeofday, stime, clock_settime, adjtimex,
// process_vm_readv, process_vm_writev, kcmp, get_mempolicy, set_mempolicy,
// mbind, migrate_pages, move_pages, add_key, request_key, keyctl,
// nfsservctl, swapon, swapoff, vhangup, pciconfig_*, create_module,
// query_module, get_kernel_syms, uselib, userfaultfd, perf_event_open,
// setdomainname, sethostname, quotactl, lookup_dcookie, fanotify_init,
// open_by_handle_at.
var baseAllow = []string{
	"accept",
	"accept4",
	"access",
	"alarm",
	"bind",
	"brk",
	"capget",
	"capset",
	"chdir",
	"chmod",
	"chown",
	"chown32",
	"clock_adjtime",
	"clock_adjtime64",
	"clock_getres",
	"clock_getres_time64",
	"clock_gettime",
	"clock_gettime64",
	"clock_nanosleep",
	"clock_nanosleep_time64",
	"close",
	"close_range",
	"connect",
	"copy_file_range",
	"creat",
	"dup",
	"dup2",
	"dup3",
	"epoll_create",
	"epoll_create1",
	"epoll_ctl",
	"epoll_ctl_old",
	"epoll_pwait",
	"epoll_pwait2",
	"epoll_wait",
	"epoll_wait_old",
	"eventfd",
	"eventfd2",
	"execve",
	"execveat",
	"exit",
	"exit_group",
	"faccessat",
	"faccessat2",
	"fadvise64",
	"fadvise64_64",
	"fallocate",
	"fanotify_mark",
	"fchdir",
	"fchmod",
	"fchmodat",
	"fchmodat2",
	"fchown",
	"fchown32",
	"fchownat",
	"fcntl",
	"fcntl64",
	"fdatasync",
	"fgetxattr",
	"flistxattr",
	"flock",
	"fork",
	"fremovexattr",
	"fsetxattr",
	"fstat",
	"fstat64",
	"fstatat64",
	"fstatfs",
	"fstatfs64",
	"fsync",
	"ftruncate",
	"ftruncate64",
	"futex",
	"futex_requeue",
	"futex_time64",
	"futex_wait",
	"futex_waitv",
	"futex_wake",
	"futimesat",
	"getcpu",
	"getcwd",
	"getdents",
	"getdents64",
	"getegid",
	"getegid32",
	"geteuid",
	"geteuid32",
	"getgid",
	"getgid32",
	"getgroups",
	"getgroups32",
	"getitimer",
	"getpeername",
	"getpgid",
	"getpgrp",
	"getpid",
	"getppid",
	"getpriority",
	"getrandom",
	"getresgid",
	"getresgid32",
	"getresuid",
	"getresuid32",
	"getrlimit",
	"get_robust_list",
	"getrusage",
	"getsid",
	"getsockname",
	"getsockopt",
	"get_thread_area",
	"gettid",
	"gettimeofday",
	"getuid",
	"getuid32",
	"getxattr",
	"inotify_add_watch",
	"inotify_init",
	"inotify_init1",
	"inotify_rm_watch",
	"io_cancel",
	"ioctl",
	"io_destroy",
	"io_getevents",
	"io_pgetevents",
	"io_pgetevents_time64",
	"ioprio_get",
	"ioprio_set",
	"io_setup",
	"io_submit",
	"io_uring_enter",
	"io_uring_register",
	"io_uring_setup",
	"ipc",
	"kill",
	"landlock_add_rule",
	"landlock_create_ruleset",
	"landlock_restrict_self",
	"lchown",
	"lchown32",
	"lgetxattr",
	"link",
	"linkat",
	"listen",
	"listxattr",
	"llistxattr",
	"_llseek",
	"lremovexattr",
	"lseek",
	"lsetxattr",
	"lstat",
	"lstat64",
	"madvise",
	"map_shadow_stack",
	"membarrier",
	"memfd_create",
	"memfd_secret",
	"mincore",
	"mkdir",
	"mkdirat",
	"mknod",
	"mknodat",
	"mlock",
	"mlock2",
	"mlockall",
	"mmap",
	"mmap2",
	"mprotect",
	"mq_getsetattr",
	"mq_notify",
	"mq_open",
	"mq_timedreceive",
	"mq_timedreceive_time64",
	"mq_timedsend",
	"mq_timedsend_time64",
	"mq_unlink",
	"mremap",
	"msgctl",
	"msgget",
	"msgrcv",
	"msgsnd",
	"msync",
	"munlock",
	"munlockall",
	"munmap",
	"name_to_handle_at",
	"nanosleep",
	"newfstatat",
	"_newselect",
	"open",
	"openat",
	"openat2",
	"pause",
	"pidfd_getfd",
	"pidfd_open",
	"pidfd_send_signal",
	"pipe",
	"pipe2",
	"poll",
	"ppoll",
	"ppoll_time64",
	"prctl",
	"pread64",
	"preadv",
	"preadv2",
	"prlimit64",
	"process_mrelease",
	"pselect6",
	"pselect6_time64",
	"pwrite64",
	"pwritev",
	"pwritev2",
	"read",
	"readahead",
	"readlink",
	"readlinkat",
	"readv",
	"recv",
	"recvfrom",
	"recvmmsg",
	"recvmmsg_time64",
	"recvmsg",
	"remap_file_pages",
	"removexattr",
	"rename",
	"renameat",
	"renameat2",
	"restart_syscall",
	"rmdir",
	"rseq",
	"rt_sigaction",
	"rt_sigpending",
	"rt_sigprocmask",
	"rt_sigqueueinfo",
	"rt_sigreturn",
	"rt_sigsuspend",
	"rt_sigtimedwait",
	"rt_sigtimedwait_time64",
	"rt_tgsigqueueinfo",
	"sched_getaffinity",
	"sched_getattr",
	"sched_getparam",
	"sched_get_priority_max",
	"sched_get_priority_min",
	"sched_getscheduler",
	"sched_rr_get_interval",
	"sched_rr_get_interval_time64",
	"sched_setaffinity",
	"sched_setattr",
	"sched_setparam",
	"sched_setscheduler",
	"sched_yield",
	"seccomp",
	"select",
	"semctl",
	"semget",
	"semop",
	"semtimedop",
	"semtimedop_time64",
	"send",
	"sendfile",
	"sendfile64",
	"sendmmsg",
	"sendmsg",
	"sendto",
	"setfsgid",
	"setfsgid32",
	"setfsuid",
	"setfsuid32",
	"setgid",
	"setgid32",
	"setgroups",
	"setgroups32",
	"setitimer",
	"setpgid",
	"setpriority",
	"setregid",
	"setregid32",
	"setresgid",
	"setresgid32",
	"setresuid",
	"setresuid32",
	"setreuid",
	"setreuid32",
	"setrlimit",
	"set_robust_list",
	"setsid",
	"setsockopt",
	"set_thread_area",
	"set_tid_address",
	"setuid",
	"setuid32",
	"setxattr",
	"shmat",
	"shmctl",
	"shmdt",
	"shmget",
	"shutdown",
	"sigaltstack",
	"signalfd",
	"signalfd4",
	"sigprocmask",
	"sigreturn",
	"socketcall",
	"socketpair",
	"splice",
	"stat",
	"stat64",
	"statfs",
	"statfs64",
	"statx",
	"symlink",
	"symlinkat",
	"sync",
	"sync_file_range",
	"syncfs",
	"sysinfo",
	"tee",
	"tgkill",
	"time",
	"timer_create",
	"timer_delete",
	"timer_getoverrun",
	"timer_gettime",
	"timer_gettime64",
	"timer_settime",
	"timer_settime64",
	"timerfd_create",
	"timerfd_gettime",
	"timerfd_gettime64",
	"timerfd_settime",
	"timerfd_settime64",
	"times",
	"tkill",
	"truncate",
	"truncate64",
	"ugetrlimit",
	"umask",
	"uname",
	"unlink",
	"unlinkat",
	"utime",
	"utimensat",
	"utimensat_time64",
	"utimes",
	"vfork",
	"vmsplice",
	"wait4",
	"waitid",
	"waitpid",
	"write",
	"writev",
}
