package shim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/unix"
)

// Environment variables the shim uses to talk to its own stages. Nothing
// sensitive travels this way: the configuration itself comes over a pipe.
const (
	// EnvStage selects which half of the double fork this process is.
	EnvStage = "HULL_SHIM_STAGE"
	// EnvBinary is the absolute path of the shim binary, so stage 1 can start
	// stage 2 without resolving argv[0] or re-execing /proc/self/exe.
	EnvBinary = "HULL_SHIM_BINARY"

	stageIntermediate = "1"
	stageSupervisor   = "2"
)

// Inherited file descriptors. hulld passes both; stage 1 passes them on.
const (
	// ConfigFD carries the JSON Config.
	ConfigFD = 3
	// ReadyFD carries one JSON readyMessage back to hulld.
	ReadyFD = 4
)

// readyMessage is the single line the shim writes on ReadyFD. hulld reads it
// and then dials the socket.
type readyMessage struct {
	// Pid is the supervising shim's pid.
	Pid int `json:"pid,omitempty"`
	// Socket is the control socket path.
	Socket string `json:"socket,omitempty"`
	// ContainerPid is the container init's pid.
	ContainerPid int `json:"containerPid,omitempty"`
	// Error is non-empty when the shim failed before it could serve.
	Error string `json:"error,omitempty"`
}

// Main is the hull-shim entry point. It returns the process exit code.
//
// The process runs in one of two stages, selected by EnvStage:
//
//	1  the intermediate fork. It reads and validates the configuration, so a
//	   bad config is reported to hulld synchronously, opens the shim log, and
//	   starts stage 2 before exiting immediately. Its exit is what orphans
//	   stage 2 onto PID 1.
//	2  the supervisor proper.
//
// Running the binary with neither is a user error, not a mode: the shim is
// spawned by hulld, never by hand.
func Main() int {
	switch os.Getenv(EnvStage) {
	case stageIntermediate:
		if err := runIntermediate(); err != nil {
			fmt.Fprintf(os.Stderr, "hull-shim: %v\n", err)
			return 1
		}
		return 0
	case stageSupervisor:
		if err := Run(context.Background()); err != nil {
			log.Printf("hull-shim: %v", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintln(os.Stderr, "hull-shim: this binary is spawned by hulld and cannot be run directly")
		return 2
	}
}

// runIntermediate is stage 1 of the double fork.
func runIntermediate() error {
	cfgFile := os.NewFile(ConfigFD, "config")
	readyFile := os.NewFile(ReadyFD, "ready")
	if cfgFile == nil || readyFile == nil {
		return fmt.Errorf("expected the config on fd %d and the ready pipe on fd %d", ConfigFD, ReadyFD)
	}
	defer readyFile.Close()

	data, err := io.ReadAll(io.LimitReader(cfgFile, 1<<20))
	cfgFile.Close()
	if err != nil {
		return reportReady(readyFile, fmt.Errorf("read config from fd %d: %w", ConfigFD, err))
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return reportReady(readyFile, fmt.Errorf("parse config: %w", err))
	}
	if err := cfg.Validate(); err != nil {
		return reportReady(readyFile, err)
	}

	binary := os.Getenv(EnvBinary)
	if binary == "" {
		return reportReady(readyFile, fmt.Errorf("%s is not set, so stage 1 cannot start stage 2", EnvBinary))
	}

	logFile, err := os.OpenFile(cfg.ShimLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return reportReady(readyFile, fmt.Errorf("open %s: %w", cfg.ShimLogPath(), err))
	}
	defer logFile.Close()

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return reportReady(readyFile, fmt.Errorf("open %s: %w", os.DevNull, err))
	}
	defer devNull.Close()

	// Stage 2 gets a fresh config pipe rather than the one hulld wrote to,
	// because stage 1 has already drained it.
	pr, pw, err := os.Pipe()
	if err != nil {
		return reportReady(readyFile, fmt.Errorf("config pipe: %w", err))
	}
	defer pw.Close()

	proc, err := os.StartProcess(binary, []string{binary}, &os.ProcAttr{
		Env: []string{
			EnvStage + "=" + stageSupervisor,
			EnvBinary + "=" + binary,
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		},
		Files: []*os.File{devNull, logFile, logFile, pr, readyFile},
	})
	pr.Close()
	if err != nil {
		return reportReady(readyFile, fmt.Errorf("start the supervisor stage: %w", err))
	}
	// Stage 1 must not wait for stage 2: exiting is what reparents it.
	_ = proc.Release()

	if _, err := pw.Write(data); err != nil {
		return fmt.Errorf("hand the config to the supervisor stage: %w", err)
	}
	return nil
}

// reportReady writes an error back to hulld on the ready pipe and returns it.
func reportReady(ready *os.File, cause error) error {
	msg, _ := json.Marshal(readyMessage{Error: cause.Error()})
	_, _ = ready.Write(append(msg, '\n'))
	return cause
}

// Run is stage 2: the supervisor proper. It reads its configuration from
// ConfigFD, creates the container, publishes shim.json, reports ready on
// ReadyFD and then serves until the container has exited and its status has
// been collected.
func Run(ctx context.Context) error {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("hull-shim: ")

	cfgFile := os.NewFile(ConfigFD, "config")
	readyFile := os.NewFile(ReadyFD, "ready")
	if cfgFile == nil || readyFile == nil {
		return fmt.Errorf("expected the config on fd %d and the ready pipe on fd %d", ConfigFD, ReadyFD)
	}
	data, err := io.ReadAll(io.LimitReader(cfgFile, 1<<20))
	cfgFile.Close()
	if err != nil {
		return reportReady(readyFile, fmt.Errorf("read config from fd %d: %w", ConfigFD, err))
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return reportReady(readyFile, fmt.Errorf("parse config: %w", err))
	}
	if err := cfg.Validate(); err != nil {
		return reportReady(readyFile, err)
	}
	log.SetPrefix("hull-shim[" + shortID(cfg.ID) + "]: ")
	return Supervise(ctx, cfg, readyFile)
}

// Supervise runs the whole shim lifecycle for cfg, reporting readiness on
// ready (which it closes). It is exported so an integration test can drive a
// shim in-process; the real shim reaches it through Run.
func Supervise(ctx context.Context, cfg Config, ready *os.File) (err error) {
	defer func() {
		if ready != nil {
			ready.Close()
		}
	}()

	// Refuse to take over a container another live shim already owns, and
	// clear the debris of one that is gone.
	if _, cerr := CleanStale(cfg.ContainerDir); cerr != nil {
		log.Printf("clean stale shim state: %v", cerr)
	}
	if st, rerr := ReadShimState(cfg.StatePath()); rerr == nil && st.Validate() && st.Pid != os.Getpid() {
		return reportReady(ready, fmt.Errorf("container %s is already supervised by shim pid %d", cfg.ID, st.Pid))
	}

	if err := setSubreaper(); err != nil {
		// Without it the container's init is reparented to PID 1 and its exit
		// status is lost, which is the one thing the shim exists to prevent.
		return reportReady(ready, err)
	}
	rp := newReaper()
	defer rp.Close()

	sup, err := newSupervisor(cfg, rp)
	if err != nil {
		return reportReady(ready, err)
	}
	defer sup.Close()

	l, err := listenControl(cfg.SocketPath())
	if err != nil {
		return reportReady(ready, err)
	}

	srv := newServer(ctx, cfg, sup, l)
	go srv.Serve()
	defer srv.Close()

	createCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	createErr := sup.Create(createCtx)
	cancel()
	if createErr != nil {
		// The container never came up: record it so hulld sees a real status
		// rather than a container stuck in "created" forever.
		st := ExitStatus{ExitCode: 127, FinishedAt: time.Now(), Error: createErr.Error()}
		if werr := WriteExitStatus(cfg.ExitPath(), st); werr != nil {
			log.Printf("%v", werr)
		}
		return reportReady(ready, createErr)
	}

	startTime, sterr := ProcessStartTime(os.Getpid())
	if sterr != nil {
		log.Printf("read own start time: %v", sterr)
	}
	state := ShimState{
		Pid:          os.Getpid(),
		StartTime:    startTime,
		Socket:       cfg.SocketPath(),
		ContainerID:  cfg.ID,
		ContainerPid: sup.State().Pid,
		CreatedAt:    time.Now(),
		Version:      ShimStateVersion,
	}
	if err := WriteShimState(cfg.StatePath(), state); err != nil {
		return reportReady(ready, err)
	}

	msg, _ := json.Marshal(readyMessage{
		Pid:          state.Pid,
		Socket:       state.Socket,
		ContainerPid: state.ContainerPid,
	})
	if _, werr := ready.Write(append(msg, '\n')); werr != nil {
		log.Printf("report ready: %v", werr)
	}
	ready.Close()
	ready = nil

	waitForExit(ctx, cfg, sup)

	// Everything below runs after the container is gone.
	sup.killExecs(unix.SIGKILL)
	srv.Close()
	if err := os.Remove(cfg.StatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("remove %s: %v", cfg.StatePath(), err)
	}
	log.Printf("container %s exited with code %d; shim exiting", cfg.ID, sup.State().ExitCode)
	return nil
}

// waitForExit blocks until the container has exited and the daemon has had its
// chance to collect the status.
//
// SIGTERM to the shim does not mean "die": it means "stop the container".
// hulld sends it on shutdown, and the shim forwards the container's stop
// signal, waits out the stop timeout and then resorts to SIGKILL, exactly as
// if the daemon had asked politely.
func waitForExit(ctx context.Context, cfg Config, sup *supervisor) {
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, unix.SIGTERM, unix.SIGINT)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-sup.Exited():
			holdExitStatus(ctx, cfg, sup)
			return
		case sig := <-sigCh:
			log.Printf("got %s: stopping container %s", sig, cfg.ID)
			stopCtx, cancel := context.WithTimeout(context.Background(), cfg.stopTimeout()+30*time.Second)
			sup.Stop(stopCtx)
			cancel()
		case <-ctx.Done():
			stopCtx, cancel := context.WithTimeout(context.Background(), cfg.stopTimeout()+30*time.Second)
			sup.Stop(stopCtx)
			cancel()
			<-sup.Exited()
			holdExitStatus(ctx, cfg, sup)
			return
		}
	}
}

// holdExitStatus keeps the control socket answering State and Wait after the
// container has exited, so a daemon that happens to be restarting at that
// moment can still collect the status from a live shim rather than having to
// fall back to exit.json.
//
// It ends early the moment the daemon acknowledges.
func holdExitStatus(ctx context.Context, cfg Config, sup *supervisor) {
	grace := cfg.exitGrace()
	log.Printf("container %s exited; serving its status for up to %s", cfg.ID, grace)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-sup.Acked():
		log.Printf("the daemon acknowledged the exit status")
	case <-timer.C:
		log.Printf("no acknowledgement within %s; exit.json is authoritative from here", grace)
	case <-ctx.Done():
	}
}

// shortID trims a container id for log prefixes.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
