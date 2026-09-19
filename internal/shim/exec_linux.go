package shim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// execRingSize is the replay buffer for an exec'd process. It is smaller than
// the container's because an exec stream almost always has a live attacher.
const execRingSize = 16 << 10

// execProc is one process started with Exec inside a running container.
//
// Exec output deliberately does not reach the json-file log: `docker logs`
// shows what the container's main process printed, not what someone typed in
// an exec session, and hull matches that.
type execProc struct {
	id  string
	pid int

	pidfd    *PidFD
	hub      *Hub
	terminal bool

	master  *os.File
	stdinW  *os.File
	stdoutR *os.File
	stderrR *os.File

	specPath string

	wg sync.WaitGroup

	mu       sync.Mutex
	exitCode int
	exited   chan struct{}
	once     sync.Once
}

// Exec starts an additional process in the running container and returns a
// handle on it. spec is an OCI runtime-spec Process object as JSON.
func (s *supervisor) Exec(ctx context.Context, id string, spec []byte, terminal, openStdin bool) (*execProc, error) {
	s.mu.Lock()
	exited := s.st.Exited
	running := s.started
	s.mu.Unlock()
	if exited || !running {
		return nil, ErrNotRunning
	}
	if id == "" {
		return nil, errors.New("shim: exec needs a non-empty id")
	}
	if !validExecID(id) {
		return nil, fmt.Errorf("shim: exec id %q must be hex, alphanumeric, '-' or '_'", id)
	}

	s.execMu.Lock()
	if _, ok := s.execs[id]; ok {
		s.execMu.Unlock()
		return nil, fmt.Errorf("shim: exec %s already exists", id)
	}
	s.execMu.Unlock()

	specPath, err := tempSpecFile(s.cfg.ContainerDir, id, spec)
	if err != nil {
		return nil, err
	}
	e := &execProc{id: id, terminal: terminal, specPath: specPath, exited: make(chan struct{})}

	pidPath := filepath.Join(s.cfg.ContainerDir, "exec-"+id+".pid")
	argv := s.runtimeArgv("exec", "--process", specPath, "--detach", "--pid-file", pidPath)

	var (
		files   []*os.File
		cleanup []*os.File
		console *ConsoleSocket
	)
	defer func() {
		for _, f := range cleanup {
			f.Close()
		}
		if console != nil {
			console.Close()
		}
	}()

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		e.cleanupFiles()
		return nil, fmt.Errorf("shim: open %s: %w", os.DevNull, err)
	}
	cleanup = append(cleanup, devNull)

	if terminal {
		sockPath := filepath.Join(s.cfg.ContainerDir, "e-"+id+".sock")
		console, err = NewConsoleSocket(sockPath)
		if err != nil {
			e.cleanupFiles()
			return nil, err
		}
		argv = append(argv, "--console-socket", console.Path())
		files = []*os.File{devNull, nil, nil}
	} else {
		stdinR, stdoutW, stderrW, perr := e.makePipes(openStdin)
		if perr != nil {
			e.cleanupFiles()
			return nil, perr
		}
		cleanup = append(cleanup, stdinR, stdoutW, stderrW)
		files = []*os.File{stdinR, stdoutW, stderrW}
	}
	argv = append(argv, s.cfg.ID)

	var (
		code int
		out  []byte
	)
	if terminal {
		code, out, err = runCaptured(ctx, s.rp, argv, runtimeEnv(), nil)
	} else {
		code, out, err = runWithFiles(ctx, s.rp, argv, runtimeEnv(), files)
	}
	if err != nil {
		e.cleanupFiles()
		return nil, fmt.Errorf("shim: run %s exec: %w", s.cfg.RuntimeName, err)
	}
	if code != 0 {
		e.cleanupFiles()
		return nil, fmt.Errorf("shim: %s exec failed with exit code %d: %s", s.cfg.RuntimeName, code, strings.TrimSpace(string(out)))
	}

	if terminal {
		master, rerr := console.Receive(consoleTimeout)
		if rerr != nil {
			e.cleanupFiles()
			return nil, rerr
		}
		e.master = master
	}

	pid, err := readPidFile(pidPath)
	if err != nil {
		e.cleanupFiles()
		return nil, err
	}
	os.Remove(pidPath)
	e.pid = pid

	// Wire up the streams before anything can block: even an exec that has
	// already finished left bytes in the pipes, and they still belong to the
	// caller.
	var stdin io.WriteCloser
	switch {
	case e.master != nil:
		stdin = e.master
	case e.stdinW != nil:
		stdin = e.stdinW
	}
	e.hub = NewHub(stdin, execRingSize)
	e.startCopiers()

	s.execMu.Lock()
	s.execs[id] = e
	s.execMu.Unlock()

	// A short-lived exec — `echo hi`, a healthcheck probe — can be gone before
	// pidfd_open runs, and the shim's own reaper may already have collected
	// it. ESRCH is therefore a normal outcome here, not a failure: the status
	// is waiting in the reaper's table, so finish the exec directly instead of
	// pretending it never started.
	pfd, err := OpenPidFD(pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			go s.finishExec(e)
			return e, nil
		}
		e.cleanupFiles()
		return nil, err
	}
	e.pidfd = pfd

	go s.watchExec(e)
	return e, nil
}

// validExecID rejects an id that could escape the container directory when it
// is pasted into a spec or pid file name. The id comes from the daemon, but
// the daemon takes it from an API client, so it is checked here too.
func validExecID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// makePipes builds the exec's stdio pipes.
func (e *execProc) makePipes(openStdin bool) (stdinR, stdoutW, stderrW *os.File, err error) {
	if openStdin {
		r, w, perr := os.Pipe()
		if perr != nil {
			return nil, nil, nil, fmt.Errorf("shim: exec stdin pipe: %w", perr)
		}
		stdinR, e.stdinW = r, w
	} else {
		f, oerr := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
		if oerr != nil {
			return nil, nil, nil, fmt.Errorf("shim: open %s for exec stdin: %w", os.DevNull, oerr)
		}
		stdinR = f
	}
	or, ow, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("shim: exec stdout pipe: %w", err)
	}
	e.stdoutR, stdoutW = or, ow
	er, ew, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("shim: exec stderr pipe: %w", err)
	}
	e.stderrR, stderrW = er, ew
	return stdinR, stdoutW, stderrW, nil
}

// startCopiers pumps the exec's output into its hub.
func (e *execProc) startCopiers() {
	pump := func(r *os.File, stream byte) {
		defer e.wg.Done()
		defer r.Close()
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				_, _ = e.hub.Write(stream, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}
	if e.master != nil {
		e.wg.Add(1)
		go pump(e.master, KindStdout)
		return
	}
	if e.stdoutR != nil {
		e.wg.Add(1)
		go pump(e.stdoutR, KindStdout)
	}
	if e.stderrR != nil {
		e.wg.Add(1)
		go pump(e.stderrR, KindStderr)
	}
}

// watchExec waits for one exec to exit and publishes its status.
func (s *supervisor) watchExec(e *execProc) {
	if e.pidfd != nil {
		if err := e.pidfd.WaitExit(context.Background()); err != nil {
			log.Printf("shim: wait for exec %s: %v", e.id, err)
		}
	}
	s.finishExec(e)
}

// finishExec collects an exec's status, drains its output and publishes its
// exit. It is reached both from the pidfd watcher and directly, for an exec
// that was already gone by the time the shim looked.
func (s *supervisor) finishExec(e *execProc) {
	code := 255
	ctx, cancel := context.WithTimeout(context.Background(), reapWindow)
	ws, err := s.rp.wait(ctx, e.pid)
	cancel()
	if err != nil {
		log.Printf("shim: exec %s exited but its status was not collected: %v", e.id, err)
	} else {
		code = exitCodeOf(ws)
	}

	if e.stdinW != nil {
		_ = e.stdinW.Close()
	}
	waitTimeout(&e.wg, 5*time.Second)
	if e.hub != nil {
		_ = e.hub.Close()
	}
	e.cleanupFiles()

	e.mu.Lock()
	e.exitCode = code
	e.mu.Unlock()
	e.once.Do(func() { close(e.exited) })

	s.events.Publish(Event{Type: EventExecExit, ID: e.id, ExitCode: code, Time: time.Now()})
}

// cleanupFiles removes the transient spec file and closes any fd still held.
func (e *execProc) cleanupFiles() {
	if e.specPath != "" {
		os.Remove(e.specPath)
		e.specPath = ""
	}
	if e.pidfd != nil {
		_ = e.pidfd.Close()
	}
}

// Wait blocks until the exec'd process exits.
func (e *execProc) Wait(ctx context.Context) (int, error) {
	select {
	case <-e.exited:
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.exitCode, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// Resize sets the exec's terminal size.
func (e *execProc) Resize(h, w uint16) error {
	if e.master == nil {
		return ErrNoTerminal
	}
	return SetWinsize(e.master, h, w)
}

// Signal sends sig to the exec'd process through its pidfd.
func (e *execProc) Signal(sig syscall.Signal) error {
	if e.pidfd == nil {
		return ErrNotRunning
	}
	if err := e.pidfd.Signal(sig); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return ErrNotRunning
		}
		return err
	}
	return nil
}

// lookupExec finds a previously started exec.
func (s *supervisor) lookupExec(id string) (*execProc, error) {
	s.execMu.Lock()
	defer s.execMu.Unlock()
	e, ok := s.execs[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchExec, id)
	}
	return e, nil
}

// killExecs signals every live exec, used when the container is going away.
func (s *supervisor) killExecs(sig syscall.Signal) {
	s.execMu.Lock()
	execs := make([]*execProc, 0, len(s.execs))
	for _, e := range s.execs {
		execs = append(execs, e)
	}
	s.execMu.Unlock()
	for _, e := range execs {
		select {
		case <-e.exited:
		default:
			if err := e.Signal(sig); err != nil && !errors.Is(err, ErrNotRunning) {
				log.Printf("shim: signal exec %s: %v", e.id, err)
			}
		}
	}
}
