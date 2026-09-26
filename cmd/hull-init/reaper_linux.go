package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/runtime/initspec"
)

// runPID1 is hull-init's default mode: a real, minimal init for a container
// started with HostConfig.Init.
//
// A container's PID 1 has two duties an ordinary program does not expect and
// almost never performs:
//
//   - it inherits every orphaned process in the namespace and must reap them,
//     or the namespace slowly fills with zombies until it hits pids.max;
//   - it receives the signals sent to the container, and the kernel applies no
//     default action to a signal sent to PID 1, so a container whose PID 1
//     ignores SIGTERM can only ever be SIGKILLed.
//
// This mode does both: it forwards every forwardable signal to the child's
// process group, reaps everything with waitpid(-1, WNOHANG) on SIGCHLD, and
// exits with the child's status - 128+N when the child was killed by signal N,
// which is what a shell reports and what Docker records.
func runPID1(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "hull-init: nothing to run; usage: hull-init <command> [args...]")
		return 127
	}
	path, err := initspec.LookupInPath(args[0], os.Environ())
	if err != nil {
		fmt.Fprintf(os.Stderr, "hull-init: %v\n", err)
		return 127
	}
	return supervise(path, args, os.Environ())
}

// supervise starts the command in its own process group and runs the reaper
// loop until it exits. The return value is the status hull-init should exit
// with.
func supervise(path string, argv, env []string) int {
	// Signals are blocked before the fork so nothing sent between fork and
	// the first Notify is lost.
	sigs := make(chan os.Signal, 64)
	signal.Notify(sigs)
	defer signal.Stop(sigs)

	pid, err := syscall.ForkExec(path, argv, &syscall.ProcAttr{
		Env:   env,
		Files: []uintptr{0, 1, 2},
		Sys:   &syscall.SysProcAttr{Setpgid: true},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "hull-init: start %s: %v\n", path, err)
		return 127
	}

	for s := range sigs {
		sig, ok := s.(syscall.Signal)
		if !ok {
			continue
		}
		switch sig {
		case unix.SIGCHLD:
			if done, code := reap(pid); done {
				// Give any remaining orphans a moment to be reaped,
				// then leave: the container's job is finished when
				// its main process is.
				_ = reapAll()
				return code
			}
		case unix.SIGURG:
			// The Go runtime uses SIGURG for preemption; it is never
			// meant for the container.
		default:
			// Signal the whole process group so a shell-style
			// entrypoint's children see it too. A failure means the
			// group is already gone.
			_ = unix.Kill(-pid, sig)
		}
	}
	// signal.Notify's channel is never closed, so this is only reached if
	// the runtime tears it down during shutdown.
	return 128 + int(unix.SIGTERM)
}

// reap waits for every exited child without blocking. It reports whether the
// supervised process was among them, and with what status.
func reap(main int) (bool, int) {
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || pid <= 0 {
			// ECHILD means nothing is left to reap; pid 0 means
			// nothing has exited yet.
			return false, 0
		}
		if pid == main {
			if ws.Signaled() {
				return true, 128 + int(ws.Signal())
			}
			return true, ws.ExitStatus()
		}
	}
}

// reapAll drains any remaining zombies so the pid namespace is not torn down
// with accounting still outstanding.
func reapAll() error {
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || pid <= 0 {
			return nil
		}
	}
}
