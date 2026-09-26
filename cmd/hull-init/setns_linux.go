package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/runtime/initspec"
)

// setnsOrder is the order namespaces are joined in. The user namespace has to
// be first when it can be joined at all, because entering it is what grants
// the capabilities the rest need; the mount namespace is last, because the
// paths used before it are looked up in the caller's own.
var setnsOrder = []struct {
	name string
	flag int
}{
	{"user", unix.CLONE_NEWUSER},
	{"uts", unix.CLONE_NEWUTS},
	{"ipc", unix.CLONE_NEWIPC},
	{"network", unix.CLONE_NEWNET},
	{"cgroup", unix.CLONE_NEWCGROUP},
	{"pid", unix.CLONE_NEWPID},
	{"mount", unix.CLONE_NEWNS},
}

// runSetns joins an existing container's namespaces and forks the exec stage
// inside them.
//
// This stage exists because Go cannot do the job in-process. setns(2) into a
// mount namespace requires the calling thread's fs_struct to be unshared, and
// setns into a user namespace requires the process to be single-threaded,
// which the Go runtime never is. The workaround is exact rather than
// approximate:
//
//   - the goroutine is pinned to one OS thread and that thread unshares
//     CLONE_FS, which satisfies the mount namespace's fs->users == 1 check;
//   - the user namespace is attempted and, if the kernel refuses because this
//     process has more than one thread, is skipped - which is safe only
//     because the exec'd process is then confined by exactly the same
//     capability sets, no_new_privs and seccomp filter as the container's own
//     init, and is reported as a warning rather than silently ignored;
//   - the pid namespace only affects children, so the target process is
//     created by forking from the very thread that did the setns.
//
// The target is identified by a pidfd on fd 7, never by a pid: a pid can be
// recycled between the runtime deciding to exec and this process running,
// and exec'ing into a recycled pid means exec'ing into a host process.
func runSetns() error {
	sock := initspec.FDSync
	self := initspec.FDSelf
	target := initspec.FDTarget

	msg, err := initspec.RecvMessage(sock)
	if err != nil {
		return fmt.Errorf("read the exec configuration: %w", err)
	}
	if msg.Type != initspec.MsgConfig || msg.Exec == nil {
		return fmt.Errorf("expected an exec config message, got %q", msg.Type)
	}
	e := msg.Exec
	if err := e.Validate(); err != nil {
		reportAndExit(sock, err)
	}

	// Join the container's cgroup before anything else: this happens while
	// the host's /sys/fs/cgroup is still reachable, and the forked child
	// inherits the membership, so the exec'd process is accounted and
	// limited from its first instruction.
	if e.CgroupPath != "" {
		if err := joinCgroup(e.CgroupPath); err != nil {
			reportAndExit(sock, err)
		}
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		reportAndExit(sock, fmt.Errorf("unshare(CLONE_FS) before setns: %w", err))
	}

	if !initspec.PidfdAlive(target) {
		reportAndExit(sock, fmt.Errorf("the container process has exited; refusing to exec into it"))
	}

	var joined int
	for _, ns := range setnsOrder {
		if err := unix.Setns(target, ns.flag); err != nil {
			if ns.name == "user" && errors.Is(err, unix.EINVAL) {
				// A multi-threaded process cannot enter a user
				// namespace. The exec'd process is still confined by
				// the container's capability sets, no_new_privs and
				// seccomp filter, but it is worth saying out loud.
				fmt.Fprintln(os.Stderr, "hull-init: this kernel will not let a multi-threaded "+
					"process join the container's user namespace; the exec'd process runs with the "+
					"container's credentials and seccomp filter but in the host user namespace")
				continue
			}
			if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
				// The container does not have this namespace type.
				continue
			}
			reportAndExit(sock, fmt.Errorf("setns into the container's %s namespace: %w", ns.name, err))
		}
		joined++
	}
	if joined == 0 {
		reportAndExit(sock, fmt.Errorf("could not join any of the container's namespaces"))
	}

	childSock, parentSock, err := seqpacketPair()
	if err != nil {
		reportAndExit(sock, err)
	}

	devNull, err := unix.Open("/dev/null", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		// The container may have no /dev/null; an already-open descriptor
		// is fine as a placeholder because the exec stage never reads it.
		devNull = int(os.Stdin.Fd())
	}

	// Files land on 0..6 in the child, which puts the handshake socket on
	// FDSync, the console on FDConsole and the sealed hull-init memfd on
	// FDSelf, exactly where the exec stage looks for them.
	files := []uintptr{0, 1, 2, uintptr(childSock), uintptr(devNull), uintptr(initspec.FDConsole), uintptr(self)}
	pid, err := syscall.ForkExec(initspec.ProcFD(initspec.FDSelf),
		[]string{initspec.ArgvName, initspec.StageFlagPrefix + initspec.StageExec},
		&syscall.ProcAttr{
			Dir:   "/",
			Env:   []string{"HULL_STAGE=" + initspec.StageExec},
			Files: files,
			Sys:   &syscall.SysProcAttr{},
		})
	unix.Close(childSock)
	if err != nil {
		reportAndExit(sock, fmt.Errorf("fork the exec stage inside the container: %w", err))
	}

	if err := initspec.SendMessage(parentSock, &initspec.Message{Type: initspec.MsgConfig, Exec: e}); err != nil {
		_ = unix.Kill(pid, unix.SIGKILL)
		reportAndExit(sock, fmt.Errorf("send the exec configuration to the container: %w", err))
	}
	reply, err := initspec.RecvMessage(parentSock)
	if err != nil {
		_ = unix.Kill(pid, unix.SIGKILL)
		reportAndExit(sock, fmt.Errorf("the exec stage never reported ready: %w", err))
	}
	if reply.Type == initspec.MsgError {
		_ = unix.Kill(pid, unix.SIGKILL)
		reportAndExit(sock, fmt.Errorf("%s", reply.Err))
	}
	unix.Close(parentSock)

	// The runtime wants the pid it can signal, which is this fork's pid in
	// the host pid namespace, not the one the container sees.
	if err := initspec.SendMessage(sock, &initspec.Message{Type: initspec.MsgReady, Pid: pid}); err != nil {
		return fmt.Errorf("report the exec'd pid: %w", err)
	}

	var ws unix.WaitStatus
	for {
		_, err := unix.Wait4(pid, &ws, 0, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("wait for the exec'd process: %w", err)
		}
		break
	}
	if ws.Signaled() {
		os.Exit(128 + int(ws.Signal()))
	}
	os.Exit(ws.ExitStatus())
	return nil
}

// runExec is the confinement-only stage. It runs inside the container's
// namespaces, having been forked by the setns stage, and does the same
// credential, capability, no_new_privs and seccomp work the init stage does -
// then execs. It never touches the filesystem layout: the container is
// already built.
func runExec() error {
	sock := initspec.FDSync
	msg, err := initspec.RecvMessage(sock)
	if err != nil {
		return fmt.Errorf("read the exec configuration: %w", err)
	}
	if msg.Type != initspec.MsgConfig || msg.Exec == nil {
		return fmt.Errorf("expected an exec config message, got %q", msg.Type)
	}
	e := msg.Exec
	if err := e.Validate(); err != nil {
		reportAndExit(sock, err)
	}
	if err := initspec.SanitizeFDs(initspec.FDSync, initspec.FDConsole, initspec.FDSelf); err != nil {
		reportAndExit(sock, err)
	}
	if e.Terminal {
		if err := initspec.VerifyConsoleFD(initspec.FDConsole); err != nil {
			reportAndExit(sock, err)
		}
		if _, err := unix.Setsid(); err != nil && !errors.Is(err, unix.EPERM) {
			reportAndExit(sock, fmt.Errorf("setsid before claiming the console: %w", err))
		}
		if err := initspec.SetControllingTerminal(initspec.FDConsole); err != nil {
			reportAndExit(sock, err)
		}
	}
	if err := initspec.Confine(e); err != nil {
		reportAndExit(sock, err)
	}
	if err := initspec.SendMessage(sock, &initspec.Message{Type: initspec.MsgReady, Pid: os.Getpid()}); err != nil {
		return fmt.Errorf("report ready: %w", err)
	}
	return execProcess(e)
}

// joinCgroup writes this process into an existing cgroup v2 directory.
func joinCgroup(path string) error {
	f, err := os.OpenFile(path+"/cgroup.procs", os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s/cgroup.procs: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(strconv.Itoa(os.Getpid())); err != nil {
		return fmt.Errorf("join cgroup %s: %w", path, err)
	}
	return nil
}

// seqpacketPair returns the two ends of a SOCK_SEQPACKET socketpair. The
// second end keeps CLOEXEC; the first is handed to a child explicitly.
func seqpacketPair() (child, parent int, err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, -1, fmt.Errorf("socketpair for the exec handshake: %w", err)
	}
	return fds[1], fds[0], nil
}
