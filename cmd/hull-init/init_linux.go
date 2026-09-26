package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/runtime/initspec"
)

// runInit is the container stage. It runs as the freshly cloned child, inside
// whatever namespaces the runtime asked the kernel for, with its uid and gid
// maps already written by the parent - a process cannot usefully map itself,
// and by the time execve of this binary happened the maps had to exist or the
// exec would have dropped every capability.
//
// The order below is load-bearing. Each step depends on the one before it, and
// the last three (capabilities, no_new_privs, seccomp) must happen in exactly
// that order or the confinement is decorative.
func runInit() error {
	sock := initspec.FDSync
	start := initspec.FDStart

	// The configuration arrives on the socket, never through argv or the
	// environment: /proc/<pid>/cmdline is world-readable, and a container
	// config routinely carries secrets in its env block.
	msg, err := initspec.RecvMessage(sock)
	if err != nil {
		return fmt.Errorf("read the container configuration: %w", err)
	}
	if msg.Type != initspec.MsgConfig || msg.Cfg == nil {
		return fmt.Errorf("expected a config message, got %q", msg.Type)
	}
	cfg := msg.Cfg
	if err := cfg.Validate(); err != nil {
		reportAndExit(sock, err)
	}

	if err := buildContainer(cfg); err != nil {
		reportAndExit(sock, err)
	}

	// Everything irreversible has succeeded. Tell the runtime, then block
	// until it says to go: a created-but-not-started container is exactly
	// this process, parked on a one-byte read.
	if err := initspec.SendMessage(sock, &initspec.Message{
		Type: initspec.MsgReady, Pid: os.Getpid(),
	}); err != nil {
		return fmt.Errorf("report ready: %w", err)
	}
	if err := waitForStart(start); err != nil {
		return err
	}

	if cfg.Init {
		// The container asked for a real init. Stay resident as PID 1 and
		// supervise the entrypoint instead of becoming it. The seccomp
		// filter and credentials already applied are inherited by the
		// child, so the supervisor is no more privileged than what it
		// supervises.
		//
		// close_range(3, ~0) is deliberately NOT used here. The Go runtime
		// is still running and owns descriptors of its own - the netpoll
		// epoll fd among them - and closing those crashes the supervisor
		// instead of confining it. Closing the handshake descriptors, whose
		// close-on-exec flag the runtime cleared on purpose, and re-arming
		// close-on-exec on everything else gives the entrypoint the same
		// guarantee: nothing above stderr survives the execve
		// (CVE-2024-21626).
		initspec.CloseHandshakeFDs()
		if err := initspec.SetCloexecFrom(3); err != nil {
			return err
		}
		path, lerr := initspec.LookupInPath(cfg.Exec.Process.Args[0], cfg.Exec.Process.Env)
		if lerr != nil {
			return lerr
		}
		os.Exit(supervise(path, cfg.Exec.Process.Args, cfg.Exec.Process.Env))
	}
	return execProcess(&cfg.Exec)
}

// buildContainer performs every step between the clone and the start
// handshake.
func buildContainer(cfg *initspec.Config) error {
	// Close anything the runtime did not mean to hand over before any of it
	// can be observed. The final close_range still runs before execve.
	if err := initspec.SanitizeFDs(initspec.FDSync, initspec.FDStart,
		initspec.FDConsole, initspec.FDSelf); err != nil {
		return err
	}

	if err := joinNamespaces(cfg); err != nil {
		return err
	}
	if cfg.Hostname != "" {
		if err := unix.Sethostname([]byte(cfg.Hostname)); err != nil {
			return fmt.Errorf("set hostname to %q: %w "+
				"(the bundle must request a uts namespace)", cfg.Hostname, err)
		}
	}
	if cfg.Domainname != "" {
		if err := unix.Setdomainname([]byte(cfg.Domainname)); err != nil {
			return fmt.Errorf("set domainname to %q: %w", cfg.Domainname, err)
		}
	}
	// Sysctls are written through the host procfs while it is still
	// reachable; each one lands in the namespace this process has just
	// entered.
	if err := initspec.WriteSysctls(cfg.Sysctl); err != nil {
		return err
	}

	if err := initspec.SetupRootfs(cfg); err != nil {
		return err
	}

	// From here on "/" is the container root.
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the new container root: %w", err)
	}
	defer unix.Close(rootFD)

	if err := initspec.EnsureProc(rootFD, cfg.Mounts); err != nil {
		return err
	}
	if err := initspec.CreateDevSymlinks(rootFD); err != nil {
		return err
	}
	if err := initspec.ApplyMaskedPaths(rootFD, cfg.MaskedPaths); err != nil {
		return err
	}
	if err := initspec.ApplyReadonlyPaths(rootFD, cfg.ReadonlyPaths); err != nil {
		return err
	}
	if cfg.RootfsReadonly {
		if err := initspec.MakeRootReadonly(); err != nil {
			return err
		}
	}

	if cfg.Exec.Terminal {
		if err := setupConsole(); err != nil {
			return err
		}
	}

	// Credentials, capabilities, no_new_privs and seccomp, in that order.
	return initspec.Confine(&cfg.Exec)
}

// joinNamespaces enters any namespace the bundle asked to be shared rather
// than created. The pid and user types are refused by Config.Validate: a
// multi-threaded Go process cannot enter either, and pretending otherwise
// would silently leave the container in the wrong namespace.
func joinNamespaces(cfg *initspec.Config) error {
	if len(cfg.NamespacePaths) == 0 {
		return nil
	}
	// Order matters: the mount namespace is entered last, because the paths
	// of the others are looked up in the current one.
	order := []string{"uts", "ipc", "network", "cgroup", "time", "mount"}
	for _, name := range order {
		p, ok := cfg.NamespacePaths[name]
		if !ok {
			continue
		}
		flag, ok := initspec.NamespaceFlag(name)
		if !ok {
			return fmt.Errorf("unknown namespace type %q", name)
		}
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open %s namespace %s: %w", name, p, err)
		}
		err = unix.Setns(fd, flag)
		unix.Close(fd)
		if err != nil {
			return fmt.Errorf("join %s namespace %s: %w", name, p, err)
		}
	}
	return nil
}

// setupConsole installs the pty peer the runtime opened on the host.
//
// The descriptor is verified with fstat - character device, pts major - and is
// never re-opened by path. Re-opening /dev/console by path under a
// container-controlled rootfs is precisely the 2025 runc console CVE family
// (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881).
func setupConsole() error {
	fd := initspec.FDConsole
	if err := initspec.VerifyConsoleFD(fd); err != nil {
		return err
	}
	// The process is already a session leader: the runtime cloned it with
	// Setsid. Claiming the terminal needs that.
	if _, err := unix.Setsid(); err != nil && !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("setsid before claiming the console: %w", err)
	}
	if err := initspec.SetControllingTerminal(fd); err != nil {
		return err
	}
	return nil
}

// waitForStart blocks on the start pipe until the runtime writes a byte, which
// is what Start does. A closed pipe means the runtime gave up; the container
// exits rather than running an entrypoint nobody is waiting for.
func waitForStart(fd int) error {
	buf := make([]byte, 1)
	for {
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("wait for start: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("the runtime closed the start pipe without starting the container")
		}
		return nil
	}
}
