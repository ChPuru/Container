package runtimespec

// DefaultCapabilities is the bounding/permitted/effective capability set hull
// gives an unprivileged container. It matches the Docker/OCI default list with
// CAP_NET_RAW retained so ping works inside the container.
func DefaultCapabilities() []string {
	return []string{
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE",
		"CAP_FSETID",
		"CAP_FOWNER",
		"CAP_MKNOD",
		"CAP_NET_RAW",
		"CAP_SETGID",
		"CAP_SETUID",
		"CAP_SETFCAP",
		"CAP_SETPCAP",
		"CAP_NET_BIND_SERVICE",
		"CAP_SYS_CHROOT",
		"CAP_KILL",
		"CAP_AUDIT_WRITE",
	}
}

// DefaultMaskedPaths is the OCI default list of /proc and /sys entries that
// must be masked with /dev/null (files) or an empty read-only tmpfs (dirs) so
// a container cannot read host state or crash the kernel.
func DefaultMaskedPaths() []string {
	return []string{
		"/proc/acpi",
		"/proc/asound",
		"/proc/interrupts",
		"/proc/kcore",
		"/proc/keys",
		"/proc/latency_stats",
		"/proc/timer_list",
		"/proc/timer_stats",
		"/proc/sched_debug",
		"/proc/scsi",
		"/sys/firmware",
		"/sys/devices/virtual/powercap",
	}
}

// DefaultReadonlyPaths is the OCI default list of /proc entries remounted
// read-only inside the container.
func DefaultReadonlyPaths() []string {
	return []string{
		"/proc/bus",
		"/proc/fs",
		"/proc/irq",
		"/proc/sys",
		"/proc/sysrq-trigger",
	}
}

// DefaultNamespaces is the namespace set hull unshares for a normal container.
// The user namespace is added separately by the engine, because hull only
// enables it when the kernel probe says unprivileged userns are available.
func DefaultNamespaces() []LinuxNamespace {
	return []LinuxNamespace{
		{Type: PIDNamespace},
		{Type: NetworkNamespace},
		{Type: IPCNamespace},
		{Type: UTSNamespace},
		{Type: MountNamespace},
		{Type: CgroupNamespace},
	}
}

// DefaultMounts is the standard set of pseudo-filesystems every Linux
// container needs: /proc, /dev, /dev/pts, /dev/shm, /dev/mqueue, /sys and the
// read-only cgroup view.
func DefaultMounts() []Mount {
	return []Mount{
		{
			Destination: "/proc",
			Type:        "proc",
			Source:      "proc",
			Options:     []string{"nosuid", "noexec", "nodev"},
		},
		{
			Destination: "/dev",
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
		},
		{
			Destination: "/dev/pts",
			Type:        "devpts",
			Source:      "devpts",
			Options:     []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"},
		},
		{
			Destination: "/dev/shm",
			Type:        "tmpfs",
			Source:      "shm",
			Options:     []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"},
		},
		{
			Destination: "/dev/mqueue",
			Type:        "mqueue",
			Source:      "mqueue",
			Options:     []string{"nosuid", "noexec", "nodev"},
		},
		{
			Destination: "/sys",
			Type:        "sysfs",
			Source:      "sysfs",
			Options:     []string{"nosuid", "noexec", "nodev", "ro"},
		},
		{
			Destination: "/sys/fs/cgroup",
			Type:        "cgroup",
			Source:      "cgroup",
			Options:     []string{"nosuid", "noexec", "nodev", "relatime", "ro"},
		},
	}
}

// DefaultRlimits is the rlimit set hull applies unless the user overrides it.
func DefaultRlimits() []POSIXRlimit {
	return []POSIXRlimit{
		{Type: "RLIMIT_NOFILE", Hard: 1024, Soft: 1024},
	}
}

// DefaultSpec returns the standard Linux runtime-spec skeleton: version
// 1.2.0, a non-terminal root process running /bin/sh in /, the default mount
// set, the OCI default masked and read-only path lists, and the default
// namespace set. Callers fill in Root.Path, Process.Args, resources and
// namespaces before writing config.json.
//
// Every call returns freshly allocated slices and maps, so the result is safe
// to mutate.
func DefaultSpec() *Spec {
	caps := DefaultCapabilities()
	return &Spec{
		Version: Version,
		Process: &Process{
			Terminal: false,
			User:     User{UID: 0, GID: 0},
			Args:     []string{"/bin/sh"},
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"TERM=xterm",
			},
			Cwd: "/",
			Capabilities: &LinuxCapabilities{
				Bounding:  append([]string(nil), caps...),
				Effective: append([]string(nil), caps...),
				Permitted: append([]string(nil), caps...),
			},
			Rlimits:         DefaultRlimits(),
			NoNewPrivileges: true,
		},
		Root: &Root{
			Path:     "rootfs",
			Readonly: false,
		},
		Hostname: "hull",
		Mounts:   DefaultMounts(),
		Linux: &Linux{
			Namespaces:        DefaultNamespaces(),
			MaskedPaths:       DefaultMaskedPaths(),
			ReadonlyPaths:     DefaultReadonlyPaths(),
			RootfsPropagation: "private",
			Resources: &LinuxResources{
				Devices: []LinuxDeviceCgroup{
					{Allow: false, Access: "rwm"},
				},
			},
		},
	}
}
