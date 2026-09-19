package runtime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
	"github.com/rahuldhali/hull/internal/runtime/initspec"
)

// Exec runs an extra process inside a running container.
//
// Go cannot setns into a mount or user namespace once its runtime has started
// threads, so hull re-execs hull-init from a freshly sealed memfd in its setns
// stage, hands it the target's pidfd as a descriptor, and lets that
// single-purpose process do the joining. /proc/self/exe is never named
// (CVE-2019-5736), and the pidfd - not a pid - is what identifies the target,
// so a container that has exited cannot redirect the exec at a recycled pid.
func (r *NativeRuntime) Exec(ctx context.Context, id string, process *runtimespec.Process, opts ExecOptions) (*Status, error) {
	c, err := r.lookup(id)
	if err != nil {
		return nil, err
	}
	if process == nil || len(process.Args) == 0 {
		return nil, fmt.Errorf("runtime: exec in %s needs a process with args", id)
	}
	if err := r.loadInit(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	exited := c.status.Exited
	running := c.status.Status == StatusRunning
	pidfd := c.pidfd
	cg := c.cg
	spec := c.spec
	c.mu.Unlock()
	if exited || !running {
		return nil, fmt.Errorf("container %s: %w", id, ErrNotRunning)
	}
	if pidfd == nil {
		return nil, fmt.Errorf("runtime: container %s has no pidfd; it was not created by this "+
			"process: %w", id, ErrUnsupported)
	}

	memfd, err := initspec.SealedMemfd("hull-init", r.initBin)
	if err != nil {
		return nil, err
	}
	defer memfd.Close()

	parentSock, childSock, err := seqpacketPair(id + "-exec")
	if err != nil {
		return nil, err
	}
	defer parentSock.Close()
	defer childSock.Close()

	var consolePeer, consoleMaster *os.File
	if opts.Terminal {
		m, p, perr := openPTY()
		if perr != nil {
			return nil, perr
		}
		consoleMaster, consolePeer = m, p
		defer consolePeer.Close()
		if opts.ConsoleSocket != "" {
			if serr := sendConsoleMaster(opts.ConsoleSocket, consoleMaster); serr != nil {
				consoleMaster.Close()
				return nil, serr
			}
			defer consoleMaster.Close()
		} else {
			defer consoleMaster.Close()
		}
	}

	placeholder := consolePeer
	if placeholder == nil {
		devNull, oerr := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if oerr != nil {
			return nil, fmt.Errorf("runtime: open %s: %w", os.DevNull, oerr)
		}
		defer devNull.Close()
		placeholder = devNull
	}
	unusedStart, oerr := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if oerr != nil {
		return nil, fmt.Errorf("runtime: open %s: %w", os.DevNull, oerr)
	}
	defer unusedStart.Close()

	cmd := &exec.Cmd{
		Path: initspec.ProcFD(initspec.FDSelf),
		Args: []string{initspec.ArgvName, initspec.StageFlagPrefix + initspec.StageSetns},
		Env:  []string{"HULL_STAGE=" + initspec.StageSetns},
		Dir:  "/",
		// FDSync, FDStart (unused), FDConsole, FDSelf, FDTarget.
		ExtraFiles:  []*os.File{childSock, unusedStart, placeholder, memfd, pidfd},
		SysProcAttr: &syscall.SysProcAttr{Setsid: opts.Terminal},
	}
	if !opts.Terminal {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = opts.Stdin, opts.Stdout, opts.Stderr
	} else if consoleMaster != nil && opts.ConsoleSocket == "" {
		// Nobody else took the master, so wire it to the caller's streams.
		if opts.Stdout != nil {
			go drainTo(opts.Stdout, consoleMaster)
		}
		if opts.Stdin != nil {
			go func() { _, _ = ioCopy(consoleMaster, opts.Stdin) }()
		}
	}

	execCfg := &initspec.Exec{
		Process:  *process,
		Terminal: opts.Terminal,
		Features: initspec.StageFeatures{
			MountAPI:         r.features.MountAPI,
			Openat2:          r.features.Openat2,
			CloseRange:       r.features.CloseRange,
			SeccompSpecAllow: true,
		},
	}
	if spec != nil && spec.Linux != nil {
		execCfg.Seccomp = spec.Linux.Seccomp
	}
	if cg != nil {
		execCfg.CgroupPath = cg.Path()
	}
	if err := execCfg.Validate(); err != nil {
		return nil, err
	}
	if execCfg.Seccomp != nil {
		if _, cerr := initspec.CompileSeccomp(execCfg.Seccomp); cerr != nil {
			return nil, fmt.Errorf("runtime: exec seccomp profile for %s: %w", id, cerr)
		}
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("runtime: start setns helper for %s: %w", id, err)
	}
	childSock.Close()

	st := &Status{ID: id, Status: StatusRunning, Bundle: c.bundle, Created: time.Now().UTC()}

	sockFD := int(parentSock.Fd())
	if err := initspec.SendMessage(sockFD, &initspec.Message{Type: initspec.MsgConfig, Exec: execCfg}); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, fmt.Errorf("runtime: send exec config for %s: %w", id, err)
	}

	type result struct {
		msg *initspec.Message
		err error
	}
	ch := make(chan result, 1)
	go func() {
		m, rerr := initspec.RecvMessage(sockFD)
		ch <- result{m, rerr}
	}()
	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return nil, fmt.Errorf("runtime: exec in %s never reported ready: %w", id, res.err)
		}
		if res.msg.Type == initspec.MsgError {
			_, _ = cmd.Process.Wait()
			return nil, fmt.Errorf("runtime: exec in %s failed: %s", id, res.msg.Err)
		}
		st.Pid = res.msg.Pid
	}

	if opts.PidFile != "" && st.Pid > 0 {
		if werr := os.WriteFile(opts.PidFile, []byte(strconv.Itoa(st.Pid)+"\n"), 0o644); werr != nil {
			return nil, fmt.Errorf("runtime: write exec pid file %s: %w", opts.PidFile, werr)
		}
	}

	if opts.Detach {
		go func() { _, _ = cmd.Process.Wait() }()
		return st, nil
	}

	waitErr := cmd.Wait()
	st.Exited = true
	st.Status = StatusStopped
	if cmd.ProcessState != nil {
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			st.ExitCode = ExitCodeOf(ws)
		} else {
			st.ExitCode = cmd.ProcessState.ExitCode()
		}
	} else if waitErr != nil {
		st.ExitCode = 255
	}
	st.Pid = 0
	return st, nil
}

// ioCopy is io.Copy behind a name that does not collide with the io import in
// the surrounding file.
func ioCopy(dst *os.File, src interface{ Read([]byte) (int, error) }) (int64, error) {
	buf := make([]byte, 32*1024)
	var n int64
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			n += int64(nw)
			if werr != nil {
				return n, werr
			}
		}
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return n, nil
		}
	}
}
