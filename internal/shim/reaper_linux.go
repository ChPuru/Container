package shim

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// exit is one reaped child.
type exit struct {
	pid    int
	status unix.WaitStatus
	when   time.Time
}

// reaper waits for every child the shim ever acquires.
//
// The shim sets PR_SET_CHILD_SUBREAPER, so the container's init and anything
// the runtime leaves behind are reparented here rather than to PID 1. That
// makes wait4(-1) the only correct way to collect statuses — and it means
// os/exec's Cmd.Wait can never be used, because the reaper would win the race
// and Wait would see ECHILD. Every process the shim starts therefore goes
// through runProcess, which subscribes to the reaper before forking.
type reaper struct {
	mu       sync.Mutex
	statuses map[int]exit
	subs     map[chan exit]struct{}

	sigCh chan os.Signal
	stop  chan struct{}
	once  sync.Once
}

// newReaper installs a SIGCHLD handler and starts reaping.
func newReaper() *reaper {
	r := &reaper{
		statuses: make(map[int]exit),
		subs:     make(map[chan exit]struct{}),
		sigCh:    make(chan os.Signal, 64),
		stop:     make(chan struct{}),
	}
	signal.Notify(r.sigCh, unix.SIGCHLD)
	go r.loop()
	return r
}

// setSubreaper asks the kernel to reparent our descendants' orphans to us.
// Without it the container init, which the runtime double-forks away, would be
// reparented to PID 1 and its exit status would be lost.
func setSubreaper() error {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("shim: PR_SET_CHILD_SUBREAPER: %w", err)
	}
	return nil
}

// loop drains SIGCHLD and reaps continuously. A single SIGCHLD can stand for
// several exits, so every wakeup reaps until wait4 says there is nothing left.
func (r *reaper) loop() {
	for {
		select {
		case <-r.stop:
			return
		case <-r.sigCh:
			r.reapAll()
		case <-time.After(500 * time.Millisecond):
			// Belt and braces: a signal lost while the buffer was full would
			// otherwise strand a zombie forever.
			r.reapAll()
		}
	}
}

// reapAll collects every finished child.
func (r *reaper) reapAll() {
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return // ECHILD: no children left
		}
		if pid <= 0 {
			return
		}
		r.publish(exit{pid: pid, status: ws, when: time.Now()})
	}
}

// publish records a status and fans it out to every subscriber.
func (r *reaper) publish(e exit) {
	r.mu.Lock()
	r.statuses[e.pid] = e
	subs := make([]chan exit, 0, len(r.subs))
	for ch := range r.subs {
		subs = append(subs, ch)
	}
	r.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- e:
		default: // a slow subscriber falls back to the statuses map
		}
	}
}

// subscribe returns a channel of every exit from now on. The caller must
// unsubscribe.
func (r *reaper) subscribe() chan exit {
	ch := make(chan exit, 64)
	r.mu.Lock()
	r.subs[ch] = struct{}{}
	r.mu.Unlock()
	return ch
}

// unsubscribe removes a subscription.
func (r *reaper) unsubscribe(ch chan exit) {
	r.mu.Lock()
	delete(r.subs, ch)
	r.mu.Unlock()
}

// status reports a already-reaped pid's exit, if it has been seen.
func (r *reaper) status(pid int) (exit, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.statuses[pid]
	return e, ok
}

// forget drops a recorded status once the caller has consumed it, so the map
// does not grow without bound over a long-lived container's execs.
func (r *reaper) forget(pid int) {
	r.mu.Lock()
	delete(r.statuses, pid)
	r.mu.Unlock()
}

// wait blocks until pid is reaped, ctx is done, or the reaper stops.
func (r *reaper) wait(ctx context.Context, pid int) (unix.WaitStatus, error) {
	ch := r.subscribe()
	defer r.unsubscribe(ch)
	if e, ok := r.status(pid); ok {
		r.forget(pid)
		return e.status, nil
	}
	for {
		select {
		case e := <-ch:
			if e.pid == pid {
				r.forget(pid)
				return e.status, nil
			}
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-r.stop:
			return 0, errors.New("shim: reaper stopped before the process was reaped")
		case <-time.After(200 * time.Millisecond):
			// Cover the case where the status landed between the map check
			// and the subscription taking effect.
			if e, ok := r.status(pid); ok {
				r.forget(pid)
				return e.status, nil
			}
		}
	}
}

// Close stops the reaper.
func (r *reaper) Close() {
	r.once.Do(func() {
		signal.Stop(r.sigCh)
		close(r.stop)
	})
}

// exitCodeOf turns a wait status into Docker's exit-code convention: the
// process's own code, or 128+N when a signal killed it.
func exitCodeOf(ws unix.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

// runProcess starts argv and waits for it through the reaper, returning its
// exit code and whatever it wrote to stderr.
//
// files are the child's fds 0,1,2,... A nil entry closes that slot. stderr is
// always captured through a pipe when files has fewer than three entries, so
// a runtime failure reaches the caller as a message rather than as a number.
func runProcess(ctx context.Context, r *reaper, argv []string, env []string, dir string, files []*os.File) (int, []byte, error) {
	if len(argv) == 0 {
		return 0, nil, errors.New("shim: runProcess needs a command")
	}

	attr := &os.ProcAttr{Dir: dir, Env: env, Files: files}

	// Subscribe before forking so an instant exit cannot be missed.
	ch := r.subscribe()
	defer r.unsubscribe(ch)

	proc, err := os.StartProcess(argv[0], argv, attr)
	if err != nil {
		return 0, nil, fmt.Errorf("shim: start %s: %w", argv[0], err)
	}
	pid := proc.Pid
	// The reaper owns this pid; os.Process must not try to wait for it too.
	_ = proc.Release()

	for {
		if e, ok := r.status(pid); ok {
			r.forget(pid)
			return exitCodeOf(e.status), nil, nil
		}
		select {
		case e := <-ch:
			if e.pid == pid {
				r.forget(pid)
				return exitCodeOf(e.status), nil, nil
			}
		case <-ctx.Done():
			_ = unix.Kill(pid, unix.SIGKILL)
			return 0, nil, fmt.Errorf("shim: %s did not finish: %w", argv[0], ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// runCaptured runs argv with its stdout and stderr captured, returning the
// combined output. It is how every runtime invocation is made, so a crun
// error message ends up in the shim log and in the daemon's error.
func runCaptured(ctx context.Context, r *reaper, argv []string, env []string, extra []*os.File) (int, []byte, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return 0, nil, fmt.Errorf("shim: pipe for %s output: %w", argv[0], err)
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		pr.Close()
		pw.Close()
		return 0, nil, fmt.Errorf("shim: open %s: %w", os.DevNull, err)
	}
	files := []*os.File{devNull, pw, pw}
	files = append(files, extra...)

	var (
		out  []byte
		done = make(chan struct{})
	)
	go func() {
		defer close(done)
		buf := make([]byte, 0, 4096)
		chunk := make([]byte, 4096)
		for {
			n, err := pr.Read(chunk)
			if n > 0 && len(buf) < 64<<10 {
				buf = append(buf, chunk[:n]...)
			}
			if err != nil {
				break
			}
		}
		out = buf
	}()

	code, _, runErr := runProcess(ctx, r, argv, env, "", files)
	pw.Close()
	devNull.Close()
	<-done
	pr.Close()
	return code, out, runErr
}

// signalName maps a signal name, with or without the SIG prefix, to a signal.
func signalName(name string) (syscall.Signal, bool) {
	if name == "" {
		return unix.SIGTERM, true
	}
	n := name
	if len(n) > 3 && (n[:3] == "SIG" || n[:3] == "sig") {
		n = n[3:]
	}
	sigs := map[string]syscall.Signal{
		"HUP": unix.SIGHUP, "INT": unix.SIGINT, "QUIT": unix.SIGQUIT,
		"ILL": unix.SIGILL, "TRAP": unix.SIGTRAP, "ABRT": unix.SIGABRT,
		"BUS": unix.SIGBUS, "FPE": unix.SIGFPE, "KILL": unix.SIGKILL,
		"USR1": unix.SIGUSR1, "SEGV": unix.SIGSEGV, "USR2": unix.SIGUSR2,
		"PIPE": unix.SIGPIPE, "ALRM": unix.SIGALRM, "TERM": unix.SIGTERM,
		"CHLD": unix.SIGCHLD, "CONT": unix.SIGCONT, "STOP": unix.SIGSTOP,
		"TSTP": unix.SIGTSTP, "TTIN": unix.SIGTTIN, "TTOU": unix.SIGTTOU,
		"URG": unix.SIGURG, "XCPU": unix.SIGXCPU, "XFSZ": unix.SIGXFSZ,
		"VTALRM": unix.SIGVTALRM, "PROF": unix.SIGPROF, "WINCH": unix.SIGWINCH,
		"IO": unix.SIGIO, "PWR": unix.SIGPWR, "SYS": unix.SIGSYS,
	}
	s, ok := sigs[unixUpper(n)]
	return s, ok
}

// unixUpper upper-cases ASCII without pulling in the unicode tables.
func unixUpper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}
