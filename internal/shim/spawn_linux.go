package shim

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Spawn starts a shim for cfg and returns a Client connected to it.
//
// The shim is double-forked and setsid'd so it ends up reparented to PID 1:
// hulld starts stage 1 in a new session, stage 1 starts stage 2 and exits at
// once, and stage 2 is orphaned onto init. hulld therefore has no child to
// reap and, crucially, killing hulld does not kill the container.
//
// (This depends on hulld *not* being a subreaper itself: if it sets
// PR_SET_CHILD_SUBREAPER, stage 2 is reparented to hulld instead of init and
// the container dies with the daemon.)
//
// The configuration travels on a pipe at fd 3 rather than in argv, so a
// container id, log path or runtime root is never visible in /proc/*/cmdline
// to every user on the box. Stage 2 reports success or failure as one JSON
// line on fd 4 — including a create failure, so a broken bundle surfaces here
// rather than as a container that is silently never going to start.
func Spawn(ctx context.Context, shimBinary string, cfg Config) (*Client, error) {
	if shimBinary == "" {
		return nil, errors.New("shim: Spawn needs the path of the hull-shim binary")
	}
	abs, err := filepath.Abs(shimBinary)
	if err != nil {
		return nil, fmt.Errorf("shim: resolve %s: %w", shimBinary, err)
	}
	if st, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("shim: stat shim binary %s: %w", abs, err)
	} else if st.IsDir() || st.Mode()&0o111 == 0 {
		return nil, fmt.Errorf("shim: %s is not an executable file", abs)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if _, err := CleanStale(cfg.ContainerDir); err != nil {
		return nil, err
	}

	payload, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("shim: marshal config for %s: %w", cfg.ID, err)
	}

	cfgR, cfgW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("shim: config pipe: %w", err)
	}
	defer cfgW.Close()
	readyR, readyW, err := os.Pipe()
	if err != nil {
		cfgR.Close()
		return nil, fmt.Errorf("shim: ready pipe: %w", err)
	}
	defer readyR.Close()

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		cfgR.Close()
		readyW.Close()
		return nil, fmt.Errorf("shim: open %s: %w", os.DevNull, err)
	}
	defer devNull.Close()

	cmd := exec.Command(abs)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devNull, devNull, devNull
	cmd.ExtraFiles = []*os.File{cfgR, readyW} // fds 3 and 4
	cmd.Env = []string{
		EnvStage + "=" + stageIntermediate,
		EnvBinary + "=" + abs,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		cfgR.Close()
		readyW.Close()
		return nil, fmt.Errorf("shim: start %s: %w", abs, err)
	}
	// The child has its own copies now; hold neither end open here or stage 2
	// would never see EOF on the config pipe and hulld would never see EOF on
	// the ready pipe.
	cfgR.Close()
	readyW.Close()

	if _, err := cfgW.Write(payload); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("shim: hand the config to %s: %w", abs, err)
	}
	cfgW.Close()

	// Stage 1 exits as soon as it has started stage 2; reaping it here is what
	// keeps hulld free of shim zombies.
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("shim: the intermediate stage of %s failed: %w (%s)", abs, err, readTail(cfg.ShimLogPath()))
	}

	msg, err := awaitReady(ctx, readyR, cfg)
	if err != nil {
		return nil, err
	}
	c, err := Connect(msg.Socket)
	if err != nil {
		return nil, fmt.Errorf("shim: the shim for %s reported ready on pid %d but its socket did not answer: %w", cfg.ID, msg.Pid, err)
	}
	return c, nil
}

// awaitReady reads the shim's one-line readiness report, bounded by ctx and
// by DefaultReadyTimeout.
func awaitReady(ctx context.Context, r *os.File, cfg Config) (readyMessage, error) {
	type result struct {
		msg readyMessage
		err error
	}
	ch := make(chan result, 1)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 8192), 1<<20)
		if !sc.Scan() {
			err := sc.Err()
			if err == nil {
				err = fmt.Errorf("shim: the shim for %s exited before it reported ready: %s", cfg.ID, readTail(cfg.ShimLogPath()))
			}
			ch <- result{err: err}
			return
		}
		var msg readyMessage
		if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
			ch <- result{err: fmt.Errorf("shim: unreadable readiness report from the shim for %s: %w", cfg.ID, err)}
			return
		}
		ch <- result{msg: msg}
	}()

	timer := time.NewTimer(DefaultReadyTimeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		if res.err != nil {
			return readyMessage{}, res.err
		}
		if res.msg.Error != "" {
			return readyMessage{}, fmt.Errorf("shim: the shim for %s failed to start the container: %s", cfg.ID, res.msg.Error)
		}
		if res.msg.Socket == "" {
			res.msg.Socket = cfg.SocketPath()
		}
		return res.msg, nil
	case <-timer.C:
		// Unblock the reader goroutine.
		_ = r.SetReadDeadline(time.Now())
		return readyMessage{}, fmt.Errorf("shim: the shim for %s did not report ready within %s: %s", cfg.ID, DefaultReadyTimeout, readTail(cfg.ShimLogPath()))
	case <-ctx.Done():
		_ = r.SetReadDeadline(time.Now())
		return readyMessage{}, ctx.Err()
	}
}

// readTail returns the last few hundred bytes of the shim log, so a failure
// message carries the shim's own diagnosis rather than just a timeout.
func readTail(path string) string {
	if path == "" {
		return "no shim log"
	}
	f, err := os.Open(path)
	if err != nil {
		return "no shim log at " + path
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "no shim log at " + path
	}
	const window = 2048
	off := st.Size() - window
	if off < 0 {
		off = 0
	}
	buf := make([]byte, min(int(st.Size()-off), window))
	if _, err := f.ReadAt(buf, off); err != nil && len(buf) == 0 {
		return "empty shim log"
	}
	s := strings.TrimSpace(string(buf))
	if s == "" {
		return "empty shim log"
	}
	return "shim log: " + s
}
