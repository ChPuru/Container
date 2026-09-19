package bundle

import (
	"runtime"
	"sort"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

// DefaultSeccompProfile builds hull's built-in seccomp filter for a resolved
// capability set: default-deny with EPERM, plus an allowlist of the syscalls a
// normal container needs, plus the extra syscalls a capability implies (mount
// for CAP_SYS_ADMIN, bpf for CAP_BPF, and so on).
//
// It is the fallback used when Options.SeccompProfile is nil. The daemon should
// set Options.SeccompProfile to internal/seccompprof.ForCapabilities, which
// owns the canonical, fully curated profile; this function exists so that a
// bundle generated without that wiring is still confined rather than open.
//
// A privileged container gets no filter at all, matching Docker: the filter
// would be trivially removable by a process that already has CAP_SYS_ADMIN.
//
// The runtime must set no_new_privs before installing the returned filter.
// hull always does (Process.NoNewPrivileges), and refuses to combine
// no-new-privileges=false with a profile.
func DefaultSeccompProfile(caps []string, privileged bool) *runtimespec.LinuxSeccomp {
	if privileged {
		return nil
	}

	allowed := make(map[string]bool, len(baseSyscalls)+32)
	for _, s := range baseSyscalls {
		allowed[s] = true
	}
	have := make(map[string]bool, len(caps))
	for _, c := range caps {
		have[c] = true
	}
	for capName, extra := range capSyscalls {
		if !have[capName] {
			continue
		}
		for _, s := range extra {
			allowed[s] = true
		}
	}

	names := make([]string, 0, len(allowed))
	for s := range allowed {
		names = append(names, s)
	}
	sort.Strings(names)

	eperm := uint(1) // EPERM
	prof := &runtimespec.LinuxSeccomp{
		DefaultAction:   runtimespec.ActErrno,
		DefaultErrnoRet: &eperm,
		Architectures:   hostSeccompArches(),
		Syscalls: []runtimespec.LinuxSyscall{
			{Names: names, Action: runtimespec.ActAllow},
		},
	}

	// personality(2) is allowed only for the handful of values that do not
	// disable ASLR or emulate a different ABI. runc does the same.
	for _, v := range []uint64{0x0, 0x0008, 0x20000, 0x20008} {
		prof.Syscalls = append(prof.Syscalls, runtimespec.LinuxSyscall{
			Names:  []string{"personality"},
			Action: runtimespec.ActAllow,
			Args: []runtimespec.LinuxSeccompArg{
				{Index: 0, Value: v, Op: runtimespec.OpEqualTo},
			},
		})
	}

	// clone(2) without CAP_SYS_ADMIN may not create new namespaces. The mask
	// covers CLONE_NEWNS|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET|NEWCGROUP; the
	// rule allows a clone whose flags have none of those bits set.
	if !have["CAP_SYS_ADMIN"] {
		const nsMask = 0x7E020000
		prof.Syscalls = append(prof.Syscalls, runtimespec.LinuxSyscall{
			Names:  []string{"clone"},
			Action: runtimespec.ActAllow,
			Args: []runtimespec.LinuxSeccompArg{
				{Index: cloneFlagsArgIndex(), Value: nsMask, ValueTwo: 0, Op: runtimespec.OpMaskedEqual},
			},
		})
	} else {
		prof.Syscalls = append(prof.Syscalls, runtimespec.LinuxSyscall{
			Names:  []string{"clone", "clone3"},
			Action: runtimespec.ActAllow,
		})
	}
	return prof
}

// cloneFlagsArgIndex is the position of the flags argument of clone(2), which
// differs between s390 and everything else.
func cloneFlagsArgIndex() uint {
	switch runtime.GOARCH {
	case "s390x", "s390":
		return 1
	default:
		return 0
	}
}

// hostSeccompArches returns the seccomp architecture tokens for the machine the
// daemon runs on, including the compat personalities a 64-bit kernel still
// accepts, so a 32-bit binary inside the container is filtered rather than
// killed outright.
func hostSeccompArches() []runtimespec.Arch {
	switch runtime.GOARCH {
	case "amd64":
		return []runtimespec.Arch{runtimespec.ArchX86_64, runtimespec.ArchX86, runtimespec.ArchX32}
	case "arm64":
		return []runtimespec.Arch{runtimespec.ArchAARCH64, runtimespec.ArchARM}
	case "arm":
		return []runtimespec.Arch{runtimespec.ArchARM}
	case "386":
		return []runtimespec.Arch{runtimespec.ArchX86}
	case "ppc64le":
		return []runtimespec.Arch{runtimespec.ArchPPC64LE}
	case "s390x":
		return []runtimespec.Arch{runtimespec.ArchS390X, runtimespec.ArchS390}
	case "riscv64":
		return []runtimespec.Arch{runtimespec.ArchRISCV64}
	default:
		return nil
	}
}

// capSyscalls are the syscalls unlocked by holding a particular capability.
// Without the capability the syscall would fail with EPERM anyway, so denying
// it in the filter costs nothing and shrinks the attack surface of the kernel.
var capSyscalls = map[string][]string{
	"CAP_SYS_ADMIN": {
		"bpf", "clone", "clone3", "fanotify_init", "fsconfig", "fsmount", "fsopen",
		"fspick", "lookup_dcookie", "mount", "mount_setattr", "move_mount",
		"name_to_handle_at", "open_tree", "perf_event_open", "quotactl",
		"quotactl_fd", "setdomainname", "sethostname", "setns", "syslog",
		"umount", "umount2", "unshare",
	},
	"CAP_SYS_BOOT":   {"reboot"},
	"CAP_SYS_CHROOT": {"chroot"},
	"CAP_SYS_MODULE": {"delete_module", "init_module", "finit_module", "query_module"},
	"CAP_SYS_PACCT":  {"acct"},
	"CAP_SYS_PTRACE": {"kcmp", "pidfd_getfd", "process_madvise", "process_vm_readv", "process_vm_writev", "ptrace"},
	"CAP_SYS_RAWIO":  {"iopl", "ioperm"},
	"CAP_SYS_TIME":   {"adjtimex", "clock_adjtime", "clock_adjtime64", "clock_settime", "clock_settime64", "settimeofday"},
	"CAP_SYS_NICE":   {"get_mempolicy", "mbind", "set_mempolicy", "set_mempolicy_home_node"},
	"CAP_SYSLOG":     {"syslog"},
	"CAP_BPF":        {"bpf"},
	"CAP_PERFMON":    {"perf_event_open"},
	"CAP_NET_ADMIN":  {"bpf"},
	"CAP_CHECKPOINT_RESTORE": {
		"clone3", "kcmp", "pidfd_getfd", "process_vm_readv", "process_vm_writev",
	},
}

// baseSyscalls is the allowlist every unprivileged container gets. It is the
// runc/Docker default set: everything a normal userspace program, libc, runtime
// and language VM needs, minus the syscalls that only exist to administer the
// host. clone and personality are handled separately with argument filters.
var baseSyscalls = []string{
	"accept", "accept4", "access", "adjtimex", "alarm", "bind", "brk",
	"cachestat", "capget", "capset", "chdir", "chmod", "chown", "chown32",
	"clock_adjtime", "clock_adjtime64", "clock_getres", "clock_getres_time64",
	"clock_gettime", "clock_gettime64", "clock_nanosleep", "clock_nanosleep_time64",
	"close", "close_range", "connect", "copy_file_range", "creat", "dup", "dup2",
	"dup3", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_ctl_old",
	"epoll_pwait", "epoll_pwait2", "epoll_wait", "epoll_wait_old", "eventfd",
	"eventfd2", "execve", "execveat", "exit", "exit_group", "faccessat",
	"faccessat2", "fadvise64", "fadvise64_64", "fallocate", "fanotify_mark",
	"fchdir", "fchmod", "fchmodat", "fchmodat2", "fchown", "fchown32", "fchownat",
	"fcntl", "fcntl64", "fdatasync", "fgetxattr", "flistxattr", "flock", "fork",
	"fremovexattr", "fsetxattr", "fstat", "fstat64", "fstatat64", "fstatfs",
	"fstatfs64", "fsync", "ftruncate", "ftruncate64", "futex", "futex_requeue",
	"futex_time64", "futex_wait", "futex_waitv", "futex_wake", "futimesat",
	"getcpu", "getcwd", "getdents", "getdents64", "getegid", "getegid32",
	"geteuid", "geteuid32", "getgid", "getgid32", "getgroups", "getgroups32",
	"getitimer", "getpeername", "getpgid", "getpgrp", "getpid", "getppid",
	"getpriority", "getrandom", "getresgid", "getresgid32", "getresuid",
	"getresuid32", "getrlimit", "get_robust_list", "getrusage", "getsid",
	"getsockname", "getsockopt", "get_thread_area", "gettid", "gettimeofday",
	"getuid", "getuid32", "getxattr", "inotify_add_watch", "inotify_init",
	"inotify_init1", "inotify_rm_watch", "io_cancel", "ioctl", "io_destroy",
	"io_getevents", "io_pgetevents", "io_pgetevents_time64", "ioprio_get",
	"ioprio_set", "io_setup", "io_submit", "io_uring_enter", "io_uring_register",
	"io_uring_setup", "ipc", "keyctl", "kill", "landlock_add_rule",
	"landlock_create_ruleset", "landlock_restrict_self", "lchown", "lchown32",
	"lgetxattr", "link", "linkat", "listen", "listxattr", "llistxattr",
	"_llseek", "lremovexattr", "lseek", "lsetxattr", "lstat", "lstat64",
	"madvise", "map_shadow_stack", "membarrier", "memfd_create", "memfd_secret",
	"mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mlock2",
	"mlockall", "mmap", "mmap2", "mprotect", "mq_getsetattr", "mq_notify",
	"mq_open", "mq_timedreceive", "mq_timedreceive_time64", "mq_timedsend",
	"mq_timedsend_time64", "mq_unlink", "mremap", "msgctl", "msgget", "msgrcv",
	"msgsnd", "msync", "munlock", "munlockall", "munmap", "nanosleep",
	"newfstatat", "_newselect", "open", "openat", "openat2", "pause", "pidfd_open",
	"pidfd_send_signal", "pipe", "pipe2", "pkey_alloc", "pkey_free",
	"pkey_mprotect", "poll", "ppoll", "ppoll_time64", "prctl", "pread64",
	"preadv", "preadv2", "prlimit64", "pselect6", "pselect6_time64", "pwrite64",
	"pwritev", "pwritev2", "read", "readahead", "readlink", "readlinkat", "readv",
	"recv", "recvfrom", "recvmmsg", "recvmmsg_time64", "recvmsg", "remap_file_pages",
	"removexattr", "rename", "renameat", "renameat2", "restart_syscall", "rmdir",
	"rseq", "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigqueueinfo",
	"rt_sigreturn", "rt_sigsuspend", "rt_sigtimedwait", "rt_sigtimedwait_time64",
	"rt_tgsigqueueinfo", "sched_getaffinity", "sched_getattr", "sched_getparam",
	"sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler",
	"sched_rr_get_interval", "sched_rr_get_interval_time64", "sched_setaffinity",
	"sched_setattr", "sched_setparam", "sched_setscheduler", "sched_yield",
	"seccomp", "select", "semctl", "semget", "semop", "semtimedop",
	"semtimedop_time64", "send", "sendfile", "sendfile64", "sendmmsg", "sendmsg",
	"sendto", "setfsgid", "setfsgid32", "setfsuid", "setfsuid32", "setgid",
	"setgid32", "setgroups", "setgroups32", "setitimer", "setpgid", "setpriority",
	"setregid", "setregid32", "setresgid", "setresgid32", "setresuid",
	"setresuid32", "setreuid", "setreuid32", "setrlimit", "set_robust_list",
	"setsid", "setsockopt", "set_thread_area", "set_tid_address", "setuid",
	"setuid32", "setxattr", "shmat", "shmctl", "shmdt", "shmget", "shutdown",
	"sigaltstack", "signalfd", "signalfd4", "sigprocmask", "sigreturn", "socket",
	"socketcall", "socketpair", "splice", "stat", "stat64", "statfs", "statfs64",
	"statx", "symlink", "symlinkat", "sync", "sync_file_range", "syncfs",
	"sysinfo", "tee", "tgkill", "time", "timer_create", "timer_delete",
	"timer_getoverrun", "timer_gettime", "timer_gettime64", "timer_settime",
	"timer_settime64", "timerfd_create", "timerfd_gettime", "timerfd_gettime64",
	"timerfd_settime", "timerfd_settime64", "times", "tkill", "truncate",
	"truncate64", "ugetrlimit", "umask", "uname", "unlink", "unlinkat",
	"utime", "utimensat", "utimensat_time64", "utimes", "vfork", "vmsplice",
	"wait4", "waitid", "waitpid", "write", "writev",
}
