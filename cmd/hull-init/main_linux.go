// Command hull-init is the only hull code that ever runs inside a container.
//
// It is a small, static binary with four modes, selected by --hull-stage=:
//
//	init   the post-clone container stage - namespaces, mounts, pivot_root,
//	       devices, console, credentials, capabilities, no_new_privs, seccomp -
//	       driven entirely by a JSON configuration read from a socketpair, so
//	       nothing sensitive is ever visible in /proc/<pid>/cmdline;
//	setns  join an existing container's namespaces from a pidfd on fd 7 and
//	       fork the exec stage inside them;
//	exec   apply the process confinement and execve, for a process joining a
//	       container that already exists;
//	pid1   (the default) a real minimal init: reap orphans, forward signals to
//	       the container's process group, and exit with the child's status.
//
// The binary is loaded into a sealed memfd by the runtime and exec'd through
// /proc/self/fd. hull never re-execs /proc/self/exe into a container, which is
// the whole of CVE-2019-5736.
//
// Nothing here imports more than the standard library, golang.org/x/sys/unix
// and hull's own initspec package: this binary is copied into every container
// start, so its size is a running cost.
package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/runtime/initspec"
)

func main() {
	stage, err := initspec.StageFromArgs(os.Args[1:])
	if err != nil {
		fail(err)
	}
	switch stage {
	case initspec.StageInit:
		err = runInit()
	case initspec.StageSetns:
		err = runSetns()
	case initspec.StageExec:
		err = runExec()
	default:
		// As the container's PID 1, everything after the binary name is
		// the command to supervise.
		os.Exit(runPID1(stripStageFlag(os.Args[1:])))
	}
	if err != nil {
		fail(err)
	}
	// Every stage either execs or exits from inside its own function; a
	// plain return means a stage forgot to.
	fail(fmt.Errorf("hull-init: stage %s returned without exec'ing", stage))
}

// fail reports an error on stderr and exits 127, the shell's "command could
// not be executed" status.
func fail(err error) {
	fmt.Fprintf(os.Stderr, "hull-init: %v\n", err)
	os.Exit(127)
}

// stripStageFlag removes the stage flag from an argument list, leaving the
// command PID 1 mode should supervise.
func stripStageFlag(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if len(a) >= len(initspec.StageFlagPrefix) && a[:len(initspec.StageFlagPrefix)] == initspec.StageFlagPrefix {
			continue
		}
		out = append(out, a)
	}
	return out
}

// reportAndExit sends a failure back to the runtime over the handshake socket
// before exiting, so the operator sees the real reason a container did not
// start rather than an exit status.
func reportAndExit(sockFD int, err error) {
	_ = initspec.SendMessage(sockFD, &initspec.Message{
		Type: initspec.MsgError,
		Err:  err.Error(),
	})
	fmt.Fprintf(os.Stderr, "hull-init: %v\n", err)
	os.Exit(1)
}

// execProcess is the final step of the init and exec stages: close every
// inherited descriptor above stderr and replace this process with the
// container's entrypoint.
//
// The close_range is the CVE-2024-21626 mitigation. It runs last, after the
// handshake is finished, so not even a descriptor hull itself opened survives
// into the container: a leaked directory fd is a path out through
// /proc/self/fd, whatever it was opened for.
func execProcess(e *initspec.Exec) error {
	if err := initspec.CloseRangeFrom(3); err != nil {
		return err
	}
	path, err := initspec.LookupInPath(e.Process.Args[0], e.Process.Env)
	if err != nil {
		return err
	}
	if err := unix.Exec(path, e.Process.Args, e.Process.Env); err != nil {
		return fmt.Errorf("execve %s: %w", path, err)
	}
	return nil
}
