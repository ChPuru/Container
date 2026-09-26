package shim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/logbuf"
	"github.com/ChPuru/hull/internal/types"
)

// consoleTimeout bounds how long the shim waits for the runtime to hand over
// the container's terminal.
const consoleTimeout = 30 * time.Second

// reapWindow is how long the supervisor waits for its reaper to produce the
// container init's wait status after the pidfd said it exited. It is generous
// because the only cost of waiting is a delayed exit event, while giving up
// early means recording the wrong exit code.
const reapWindow = 10 * time.Second

// supervisor owns one container: its stdio, its pidfd, its logs and its fate.
type supervisor struct {
	cfg Config
	cg  *cgroupReader
	rp  *reaper

	hub    *Hub
	logw   *logbuf.Writer
	events *eventBus

	// Container stdio. master is set for a terminal container; the three
	// pipe ends are set otherwise.
	master  *os.File
	stdinW  *os.File
	stdoutR *os.File
	stderrR *os.File

	pidfd *PidFD

	mu      sync.Mutex
	st      State
	started bool
	oomBase uint64

	outputWG sync.WaitGroup

	exitOnce sync.Once
	exited   chan struct{}
	ackOnce  sync.Once
	acked    chan struct{}

	execMu sync.Mutex
	execs  map[string]*execProc
}

// newSupervisor prepares a supervisor: it opens the log writer and the
// container's stdio, but creates nothing in the runtime yet.
func newSupervisor(cfg Config, rp *reaper) (*supervisor, error) {
	s := &supervisor{
		cfg:    cfg,
		cg:     newCgroupReader(cfg.CgroupPath),
		rp:     rp,
		events: newEventBus(),
		exited: make(chan struct{}),
		acked:  make(chan struct{}),
		execs:  make(map[string]*execProc),
		st:     State{Status: StatusCreated},
	}
	if cfg.LogPath != "" {
		w, err := logbuf.NewWriter(cfg.LogPath, logbuf.WriterOptions{
			MaxSize:  cfg.LogMaxSize,
			MaxFiles: cfg.LogMaxFiles,
		})
		if err != nil {
			return nil, err
		}
		s.logw = w
	}
	if n, ok := s.cg.OOMKills(); ok {
		s.oomBase = n
	}
	return s, nil
}

// Create asks the runtime to create the container, takes hold of its stdio and
// opens its pidfd.
//
// For a terminal container the OCI --console-socket protocol is used: the shim
// listens on a unix socket, the runtime allocates the pty and sends the master
// fd back over SCM_RIGHTS before exec'ing the container. The master therefore
// belongs to the shim from the very first moment and never to hulld, which is
// what lets a container's terminal outlive a daemon restart.
func (s *supervisor) Create(ctx context.Context) error {
	argv := []string{s.cfg.RuntimeBinary}
	if s.cfg.RuntimeRoot != "" {
		argv = append(argv, "--root", s.cfg.RuntimeRoot)
	}
	argv = append(argv, "create", "--bundle", s.cfg.BundleDir, "--pid-file", s.cfg.PidPath())

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
		return fmt.Errorf("shim: open %s: %w", os.DevNull, err)
	}
	cleanup = append(cleanup, devNull)

	if s.cfg.Terminal {
		console, err = NewConsoleSocket(s.cfg.ConsolePath())
		if err != nil {
			return err
		}
		argv = append(argv, "--console-socket", console.Path())
		// The runtime's own stdio is only used for its diagnostics.
		files = []*os.File{devNull, nil, nil}
	} else {
		stdinR, stdoutW, stderrW, err := s.makePipes()
		if err != nil {
			return err
		}
		cleanup = append(cleanup, stdinR, stdoutW, stderrW)
		files = []*os.File{stdinR, stdoutW, stderrW}
	}
	argv = append(argv, s.cfg.ID)

	// The runtime's stderr has to be captured separately when it owns the
	// container's stdout and stderr, so a crun error message is not mistaken
	// for container output.
	var (
		code int
		out  []byte
	)
	if s.cfg.Terminal {
		code, out, err = runCaptured(ctx, s.rp, argv, runtimeEnv(), nil)
	} else {
		code, out, err = runWithFiles(ctx, s.rp, argv, runtimeEnv(), files)
	}
	if err != nil {
		return fmt.Errorf("shim: run %s create: %w", s.cfg.RuntimeName, err)
	}
	if code != 0 {
		return fmt.Errorf("shim: %s create failed with exit code %d: %s", s.cfg.RuntimeName, code, strings.TrimSpace(string(out)))
	}

	if s.cfg.Terminal {
		master, err := console.Receive(consoleTimeout)
		if err != nil {
			return err
		}
		s.master = master
	}

	pid, err := readPidFile(s.cfg.PidPath())
	if err != nil {
		return err
	}
	// Opened while the init is still parked in the runtime's create step
	// waiting to be started, so the pid cannot have been recycled between the
	// pid file and this call — and if the init is somehow already gone, that
	// is a broken bundle, not a race the shim should paper over.
	pfd, err := OpenPidFD(pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("shim: the container's init (pid %d) was gone before it could be supervised; the %s create may have failed halfway", pid, s.cfg.RuntimeName)
		}
		return err
	}
	s.pidfd = pfd

	s.mu.Lock()
	s.st.Pid = pid
	s.st.Status = StatusCreated
	s.mu.Unlock()

	s.startCopiers()
	go s.watchExit()
	return nil
}

// makePipes builds the three stdio pipes for a container without a terminal
// and keeps the shim's ends.
func (s *supervisor) makePipes() (stdinR, stdoutW, stderrW *os.File, err error) {
	if s.cfg.OpenStdin {
		r, w, perr := os.Pipe()
		if perr != nil {
			return nil, nil, nil, fmt.Errorf("shim: stdin pipe: %w", perr)
		}
		stdinR, s.stdinW = r, w
	} else {
		// No stdin means /dev/null, not a pipe nobody writes to: a container
		// reading stdin must see EOF immediately, not hang.
		f, oerr := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
		if oerr != nil {
			return nil, nil, nil, fmt.Errorf("shim: open %s for container stdin: %w", os.DevNull, oerr)
		}
		stdinR = f
	}
	or, ow, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("shim: stdout pipe: %w", err)
	}
	s.stdoutR, stdoutW = or, ow
	er, ew, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("shim: stderr pipe: %w", err)
	}
	s.stderrR, stderrW = er, ew
	return stdinR, stdoutW, stderrW, nil
}

// startCopiers wires the container's output into the log writer and the attach
// hub, and builds the hub around the container's input sink.
func (s *supervisor) startCopiers() {
	var stdin io.WriteCloser
	switch {
	case s.master != nil:
		stdin = s.master
	case s.stdinW != nil:
		stdin = s.stdinW
	}
	s.hub = NewHub(stdin, s.cfg.RingSize)

	if s.master != nil {
		// A terminal merges the streams; everything is stdout.
		s.outputWG.Add(1)
		go func() {
			defer s.outputWG.Done()
			s.copyOutput(s.master, KindStdout, logbuf.StreamStdout)
		}()
		return
	}
	if s.stdoutR != nil {
		s.outputWG.Add(1)
		go func() {
			defer s.outputWG.Done()
			s.copyOutput(s.stdoutR, KindStdout, logbuf.StreamStdout)
		}()
	}
	if s.stderrR != nil {
		s.outputWG.Add(1)
		go func() {
			defer s.outputWG.Done()
			s.copyOutput(s.stderrR, KindStderr, logbuf.StreamStderr)
		}()
	}
}

// copyOutput pumps one container stream into the json-file log and into every
// live attacher, until the stream ends.
//
// A pty master reports EIO rather than EOF once the last slave fd is gone,
// which is a normal end of stream and not an error worth logging.
func (s *supervisor) copyOutput(r *os.File, stream byte, logStream string) {
	defer r.Close()
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if s.logw != nil {
				if _, werr := s.logw.Write(logStream, buf[:n]); werr != nil {
					log.Printf("shim: write %s to log: %v", logStream, werr)
				}
			}
			_, _ = s.hub.Write(stream, buf[:n])
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, unix.EIO) && !errors.Is(err, os.ErrClosed) {
				log.Printf("shim: read container %s: %v", logStream, err)
			}
			return
		}
	}
}

// Start starts a created container.
func (s *supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return ErrAlreadyStarted
	}
	if s.st.Exited {
		s.mu.Unlock()
		return ErrNotRunning
	}
	s.started = true
	s.mu.Unlock()

	argv := s.runtimeArgv("start", s.cfg.ID)
	code, out, err := runCaptured(ctx, s.rp, argv, runtimeEnv(), nil)
	if err != nil {
		s.markStartFailed(err)
		return fmt.Errorf("shim: run %s start: %w", s.cfg.RuntimeName, err)
	}
	if code != 0 {
		err := fmt.Errorf("shim: %s start failed with exit code %d: %s", s.cfg.RuntimeName, code, strings.TrimSpace(string(out)))
		s.markStartFailed(err)
		return err
	}

	s.mu.Lock()
	s.st.Status = StatusRunning
	s.st.StartedAt = time.Now()
	s.mu.Unlock()
	return nil
}

// markStartFailed records a failed start so State and exit.json say why.
func (s *supervisor) markStartFailed(err error) {
	s.mu.Lock()
	s.started = false
	s.st.Error = err.Error()
	s.mu.Unlock()
}

// runtimeArgv builds a runtime command line with the shared flags.
func (s *supervisor) runtimeArgv(args ...string) []string {
	argv := []string{s.cfg.RuntimeBinary}
	if s.cfg.RuntimeRoot != "" {
		argv = append(argv, "--root", s.cfg.RuntimeRoot)
	}
	return append(argv, args...)
}

// runtimeEnv is the environment handed to the runtime. It is deliberately
// minimal: the shim's own environment may carry anything hulld was started
// with, and none of it belongs in a container runtime.
func runtimeEnv() []string {
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	for _, k := range []string{"XDG_RUNTIME_DIR", "TMPDIR"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// watchExit blocks on the container's pidfd and records the exit exactly once.
func (s *supervisor) watchExit() {
	if err := s.pidfd.WaitExit(context.Background()); err != nil {
		log.Printf("shim: wait for container exit: %v", err)
	}
	s.recordExit()
}

// recordExit collects the wait status, detects an OOM kill, drains the
// container's output and writes exit.json. It runs at most once.
func (s *supervisor) recordExit() {
	s.exitOnce.Do(func() {
		pid := s.pidfd.Pid()
		code := 255
		var supervisionErr string

		ctx, cancel := context.WithTimeout(context.Background(), reapWindow)
		ws, err := s.rp.wait(ctx, pid)
		cancel()
		if err != nil {
			// The init was not our child after all, e.g. the runtime kept it.
			// Ask the runtime what it saw rather than inventing a code.
			supervisionErr = fmt.Sprintf("container init %d exited but its status was not collected: %v", pid, err)
			log.Printf("shim: %s", supervisionErr)
		} else {
			code = exitCodeOf(ws)
		}

		oom := false
		if n, ok := s.cg.OOMKills(); ok && n > s.oomBase {
			oom = true
		}

		// Let the last bytes of output land in the log and in the attachers
		// before the streams are closed under them.
		s.closeContainerWriteEnds()
		waitTimeout(&s.outputWG, 5*time.Second)
		if s.logw != nil {
			if err := s.logw.Close(); err != nil {
				log.Printf("shim: close log writer: %v", err)
			}
		}
		if s.hub != nil {
			_ = s.hub.Close()
		}

		finished := time.Now()
		s.mu.Lock()
		s.st.Exited = true
		s.st.Status = StatusStopped
		s.st.ExitCode = code
		s.st.OOMKilled = oom
		s.st.FinishedAt = finished
		s.st.Pid = 0
		if supervisionErr != "" && s.st.Error == "" {
			s.st.Error = supervisionErr
		}
		errText := s.st.Error
		s.mu.Unlock()

		// This write is the whole point of the shim: once it returns, the
		// container's fate survives a crash of everything above it.
		st := ExitStatus{ExitCode: code, FinishedAt: finished, OOMKilled: oom, Error: errText}
		if err := WriteExitStatus(s.cfg.ExitPath(), st); err != nil {
			log.Printf("shim: %v", err)
		}

		if oom {
			s.events.Publish(Event{Type: EventOOM, ID: s.cfg.ID, Time: finished})
		}
		s.events.Publish(Event{Type: EventExit, ID: s.cfg.ID, ExitCode: code, OOMKilled: oom, Time: finished})

		// Let the runtime drop its own state directory now that the container
		// is gone, so a later create with the same id is not refused.
		dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
		if _, out, derr := runCaptured(dctx, s.rp, s.runtimeArgv("delete", "--force", s.cfg.ID), runtimeEnv(), nil); derr != nil {
			log.Printf("shim: %s delete: %v: %s", s.cfg.RuntimeName, derr, strings.TrimSpace(string(out)))
		}
		dcancel()

		close(s.exited)
	})
}

// closeContainerWriteEnds drops the shim's copies of the container's input
// sink so a process blocked on stdin sees EOF, and so the pty master is
// released.
func (s *supervisor) closeContainerWriteEnds() {
	if s.stdinW != nil {
		_ = s.stdinW.Close()
	}
}

// waitTimeout waits for wg but gives up after d, so one stuck reader cannot
// keep the exit status off disk.
func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// State returns the container's current state.
func (s *supervisor) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

// Exited is closed once the container's exit has been recorded.
func (s *supervisor) Exited() <-chan struct{} { return s.exited }

// Acked is closed once the daemon has acknowledged the exit status.
func (s *supervisor) Acked() <-chan struct{} { return s.acked }

// Ack marks the exit status as acknowledged, releasing the grace period.
func (s *supervisor) Ack() {
	s.ackOnce.Do(func() { close(s.acked) })
}

// Wait blocks until the container exits and returns its exit code.
func (s *supervisor) Wait(ctx context.Context) (int, error) {
	select {
	case <-s.exited:
		return s.State().ExitCode, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// Kill sends sig to the container.
//
// Signals always travel through the pidfd, so a container that exited a
// microsecond ago can never have its signal land on an unrelated process that
// inherited its pid. With all set, SIGKILL goes through cgroup.kill where the
// kernel has it — which is atomic, so nothing can fork its way out — and
// otherwise through the runtime's kill --all.
func (s *supervisor) Kill(ctx context.Context, sig syscall.Signal, all bool) error {
	s.mu.Lock()
	exited := s.st.Exited
	s.mu.Unlock()
	if exited {
		return ErrNotRunning
	}
	if all {
		if sig == unix.SIGKILL {
			if err := s.cg.KillAll(); err == nil {
				return nil
			}
		}
		argv := s.runtimeArgv("kill", "--all", s.cfg.ID, strconv.Itoa(int(sig)))
		code, out, err := runCaptured(ctx, s.rp, argv, runtimeEnv(), nil)
		if err != nil {
			return fmt.Errorf("shim: run %s kill --all: %w", s.cfg.RuntimeName, err)
		}
		if code != 0 {
			return fmt.Errorf("shim: %s kill --all failed with exit code %d: %s", s.cfg.RuntimeName, code, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if s.pidfd == nil {
		return ErrNotRunning
	}
	if err := s.pidfd.Signal(sig); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return ErrNotRunning
		}
		return err
	}
	return nil
}

// Resize sets the container terminal's window size.
func (s *supervisor) Resize(h, w uint16) error {
	if s.master == nil {
		return ErrNoTerminal
	}
	return SetWinsize(s.master, h, w)
}

// Stats samples the container's cgroup.
func (s *supervisor) Stats() types.Stats {
	return s.cg.Stats(nil)
}

// Stop forwards the container's stop signal, waits out the stop timeout and
// then resorts to SIGKILL. It is what a SIGTERM to the shim, and an explicit
// shutdown request, both do.
func (s *supervisor) Stop(ctx context.Context) {
	select {
	case <-s.exited:
		return
	default:
	}
	sig, ok := signalName(s.cfg.StopSignal)
	if !ok {
		log.Printf("shim: unknown stop signal %q, using SIGTERM", s.cfg.StopSignal)
		sig = unix.SIGTERM
	}
	if err := s.Kill(ctx, sig, false); err != nil && !errors.Is(err, ErrNotRunning) {
		log.Printf("shim: forward %s to container: %v", sig, err)
	}
	select {
	case <-s.exited:
		return
	case <-time.After(s.cfg.stopTimeout()):
	case <-ctx.Done():
		return
	}
	log.Printf("shim: container %s did not stop within %s, sending SIGKILL", s.cfg.ID, s.cfg.stopTimeout())
	if err := s.Kill(ctx, unix.SIGKILL, true); err != nil && !errors.Is(err, ErrNotRunning) {
		log.Printf("shim: SIGKILL container: %v", err)
	}
	select {
	case <-s.exited:
	case <-time.After(10 * time.Second):
		log.Printf("shim: container %s is still not reaped after SIGKILL", s.cfg.ID)
	}
}

// Close releases the supervisor's resources.
func (s *supervisor) Close() {
	if s.hub != nil {
		_ = s.hub.Close()
	}
	if s.logw != nil {
		_ = s.logw.Close()
	}
	if s.pidfd != nil {
		_ = s.pidfd.Close()
	}
	if s.master != nil {
		_ = s.master.Close()
	}
	s.events.Close()
}

// readPidFile reads the pid the runtime wrote after create.
func readPidFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("shim: read container pid file %s: %w", path, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("shim: parse container pid from %s: %w", path, err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("shim: container pid file %s holds %d", path, pid)
	}
	return pid, nil
}

// runWithFiles runs argv with an explicit fd table and captures nothing; it is
// used when the runtime's stdout and stderr *are* the container's.
func runWithFiles(ctx context.Context, r *reaper, argv []string, env []string, files []*os.File) (int, []byte, error) {
	code, _, err := runProcess(ctx, r, argv, env, "", files)
	return code, nil, err
}

// tempSpecFile writes an OCI process spec where the runtime can read it.
func tempSpecFile(dir, id string, spec []byte) (string, error) {
	path := filepath.Join(dir, "exec-"+id+".json")
	if err := os.WriteFile(path, spec, 0o600); err != nil {
		return "", fmt.Errorf("shim: write exec spec %s: %w", path, err)
	}
	return path, nil
}
