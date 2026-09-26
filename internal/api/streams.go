package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ChPuru/hull/internal/engine"
	"github.com/ChPuru/hull/internal/logbuf"
	"github.com/ChPuru/hull/internal/types"
)

// version1_42 is where Docker started labelling a framed stream with its own
// content type instead of calling everything a raw stream. Older clients
// choke on the newer label, so the gate is real and not cosmetic.
var version1_42 = Version{Major: 1, Minor: 42}

// streamContentType picks the content type for a log or attach stream.
func streamContentType(r *http.Request, tty bool) string {
	if tty || clientVersion(r).LessThan(version1_42) {
		return RawStreamContentType
	}
	return MultiplexedStreamContentType
}

// getContainerLogs answers GET /containers/{id}/logs.
//
// Without a TTY the output is multiplexed with logbuf's 8-byte frame header;
// with one it passes through unframed. Getting that backwards produces
// garbage on a terminal rather than an error, so the container's own Tty flag
// decides, never the client's request.
func (s *Server) getContainerLogs(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	c, err := s.backend.Inspect(r.Context(), id)
	if err != nil {
		return containerError(err, id)
	}

	opts, err := logReadOptions(r)
	if err != nil {
		return err
	}
	if !opts.Stdout && !opts.Stderr {
		return errBadParameter("Bad parameters: you must choose at least one stream")
	}

	w.Header().Set("Content-Type", streamContentType(r, c.Config.Tty))
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()

	out := &flushWriter{w: w, flush: func() { _ = rc.Flush() }}
	err = s.backend.Logs(r.Context(), id, opts, out, !c.Config.Tty)
	if err != nil && !errors.Is(err, io.EOF) && r.Context().Err() == nil {
		// The 200 has already gone out; the honest thing left is to say so in
		// the stream and let the client's reader see a final line.
		_, _ = io.WriteString(out, "\n"+errorMessage(err)+"\n")
	}
	return nil
}

// logReadOptions builds the log reader's options from the query string.
func logReadOptions(r *http.Request) (logbuf.ReadOptions, error) {
	var opts logbuf.ReadOptions
	opts.Follow = boolValue(r, "follow")
	opts.Stdout = boolValue(r, "stdout")
	opts.Stderr = boolValue(r, "stderr")
	opts.Timestamps = boolValue(r, "timestamps")

	tail, ok := lookupQuery(r, "tail")
	switch {
	case !ok || tail == "" || strings.EqualFold(tail, "all"):
		opts.Tail = -1
	default:
		n, err := strconv.Atoi(tail)
		if err != nil || n < 0 {
			return opts, errBadParameter("invalid tail %q: expected a non-negative number or \"all\"", tail)
		}
		opts.Tail = n
	}

	if v, ok := lookupQuery(r, "since"); ok && v != "" && v != "0" {
		t, err := parseTimestamp(v, time.Time{})
		if err != nil {
			return opts, err
		}
		opts.Since = t
	}
	if v, ok := lookupQuery(r, "until"); ok && v != "" && v != "0" {
		t, err := parseTimestamp(v, time.Time{})
		if err != nil {
			return opts, err
		}
		opts.Until = t
	}
	return opts, nil
}

// flushWriter flushes after every write, which is what keeps `docker logs -f`
// and `docker events` live rather than arriving a buffer at a time.
type flushWriter struct {
	w     io.Writer
	flush func()
}

// Write writes and flushes.
func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if f.flush != nil {
		f.flush()
	}
	return n, err
}

// getContainerExport answers GET /containers/{id}/export.
func (s *Server) getContainerExport(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.WriteHeader(http.StatusOK)
	if err := s.backend.Export(r.Context(), id, w); err != nil {
		s.log.Warn("hull: export failed after the response started", "container", id, "err", err)
	}
	return nil
}

// postContainerAttach answers POST /containers/{id}/attach.
func (s *Server) postContainerAttach(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	c, err := s.backend.Inspect(r.Context(), id)
	if err != nil {
		return containerError(err, id)
	}
	// Docker's raw attach deliberately does NOT require a running container, and
	// `docker run` depends on that: the CLI creates the container, attaches to it
	// while it is still in "created", and only then calls start. Rejecting a
	// created container here makes every `docker run` fail with the unhelpful
	// "unable to upgrade to tcp, received 409".
	//
	// The two states moby does refuse are paused and restarting, because in both
	// the streams would hang with no explanation. Everything else — created,
	// running, exited — attaches. (The websocket variant is stricter and does
	// require a running container; that matches moby too.)
	switch c.State {
	case types.StatePaused:
		return wrapStatus(http.StatusConflict, engine.ErrNotRunning,
			"Container %s is paused, unpause the container before attach", id)
	case types.StateRestarting:
		return wrapStatus(http.StatusConflict, engine.ErrNotRunning,
			"Container %s is restarting, wait until the container is running", id)
	}

	useStdin := boolValue(r, "stdin")
	useStdout := boolValueOrDefault(r, "stdout", false)
	useStderr := boolValueOrDefault(r, "stderr", false)
	if !useStdin && !useStdout && !useStderr {
		return errBadParameter("Bad parameters: you must choose at least one stream")
	}
	detachKeys, _ := lookupQuery(r, "detachKeys")

	conn, brw, err := hijackConn(w, r)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// `docker run` attaches while the container is still in "created" and only
	// then calls start, so attaching to a created container has to mean "wait
	// for it, then stream". Returning an empty stream instead leaves the client
	// hanging on output that never arrives.
	//
	// The hijack has already happened, so a failure from here on can only be
	// reported by closing the connection: there is no status line left to send.
	if c.State == types.StateCreated {
		started, werr := s.waitForStart(r.Context(), id)
		if werr != nil {
			s.log.Debug("hull: attach gave up waiting for the container to start",
				"container", id, "err", werr)
			return nil
		}
		c = started
	}

	// A short-lived container is the normal case, not an edge case: by the time
	// anyone notices `echo hello` has started, it has already exited. A live
	// attach then fails with "container is not running" and the client is left
	// with an empty stream, which is what made every `hull run` and `docker run`
	// of a fast command produce no output.
	//
	// What the client actually wants is the output, so replay the log instead.
	// The framing is the same either way, so it is indistinguishable from having
	// been attached the whole time.
	if c.State == types.StateExited || c.State == types.StateDead {
		return s.replayLog(r.Context(), brw, c, useStdout, useStderr)
	}

	cfg := engine.AttachConfig{
		UseStdin:   useStdin,
		UseStdout:  useStdout,
		UseStderr:  useStderr,
		DetachKeys: detachKeys,
		Logs:       boolValue(r, "logs"),
		Framed:     !c.Config.Tty,
	}
	if useStdin {
		cfg.Stdin = hijackedStdin{r: brw}
	}
	out := hijackedStdout{w: brw}
	if useStdout {
		cfg.Stdout = out
	}
	if useStderr {
		cfg.Stderr = out
	}

	// The container can still exit between the state check above and the
	// attach reaching its supervisor; the attach then fails before a single
	// byte is streamed. Started tells the two cases apart: if the attachment
	// never went live, nothing has been sent, so the log can be replayed
	// without duplicating anything.
	started := make(chan struct{})
	cfg.Started = started
	if err := s.backend.Attach(r.Context(), id, cfg); err != nil && r.Context().Err() == nil {
		select {
		case <-started:
		default:
			if now := s.exitedAfterLostAttach(r.Context(), id, err); now != nil && !cfg.Logs {
				_ = s.replayLog(r.Context(), brw, now, useStdout, useStderr)
				_ = closeWrite(conn)
				return nil
			}
		}
		s.log.Debug("hull: attach ended", "container", id, "err", err)
	}
	_ = brw.Flush()
	_ = closeWrite(conn)
	return nil
}

// getContainerAttachWS answers GET /containers/{id}/attach/ws.
//
// This is the transport browser-based clients and docker-py's attach_socket
// use. Two things about it are version-gated, and both are behaviours Docker
// itself changed at 1.42:
//
//   - Before 1.42 the stream selectors were ignored and all three streams were
//     attached. From 1.42 the stdin, stdout and stderr query parameters decide,
//     the way they do everywhere else.
//   - Before 1.42 output was never multiplexed, so a non-TTY container's stderr
//     arrived interleaved with its stdout and no client could separate them.
//     From 1.42 a non-TTY container's output carries the 8-byte frame header.
//
// Guessing either of those wrong produces garbled output rather than an error,
// so the negotiated version decides, never the client's hopes.
func (s *Server) getContainerAttachWS(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	c, err := s.backend.Inspect(r.Context(), id)
	if err != nil {
		return containerError(err, id)
	}
	if c.State != types.StateRunning && c.State != types.StatePaused {
		return wrapStatus(http.StatusConflict, engine.ErrNotRunning,
			"Container %s is not running", id)
	}

	modern := clientVersion(r).AtLeast(version1_42)
	useStdin, useStdout, useStderr := true, true, true
	if modern {
		useStdin = boolValue(r, "stdin")
		useStdout = boolValue(r, "stdout")
		useStderr = boolValue(r, "stderr")
		if !useStdin && !useStdout && !useStderr {
			return errBadParameter("Bad parameters: you must choose at least one stream")
		}
	}
	detachKeys, _ := lookupQuery(r, "detachKeys")

	ws, err := wsUpgrade(w, r)
	if err != nil {
		return err
	}
	defer func() { _ = ws.Close() }()

	cfg := engine.AttachConfig{
		UseStdin:   useStdin,
		UseStdout:  useStdout,
		UseStderr:  useStderr,
		DetachKeys: detachKeys,
		Logs:       boolValue(r, "logs"),
		Framed:     modern && !c.Config.Tty,
	}
	if useStdin {
		cfg.Stdin = ws
	}
	if useStdout {
		cfg.Stdout = ws
	}
	if useStderr {
		cfg.Stderr = ws
	}

	if err := s.backend.Attach(r.Context(), id, cfg); err != nil && r.Context().Err() == nil {
		s.log.Debug("hull: websocket attach ended", "container", id, "err", err)
	}
	return nil
}

// postContainerExec answers POST /containers/{id}/exec.
func (s *Server) postContainerExec(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	var req ExecCreateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		return err
	}
	if len(req.Cmd) == 0 {
		return errBadParameter("No exec command specified")
	}
	execID, err := s.backend.Exec(r.Context(), id, engine.ExecConfig{
		Cmd:          req.Cmd,
		Env:          req.Env,
		User:         req.User,
		WorkingDir:   req.WorkingDir,
		Tty:          req.Tty,
		AttachStdin:  req.AttachStdin,
		AttachStdout: req.AttachStdout,
		AttachStderr: req.AttachStderr,
		Privileged:   req.Privileged,
		DetachKeys:   req.DetachKeys,
	})
	if err != nil {
		if errors.Is(err, engine.ErrNotRunning) {
			return wrapStatus(http.StatusConflict, err, "Container %s is not running", id)
		}
		return containerError(err, id)
	}
	writeJSON(w, http.StatusCreated, IDResponse{ID: execID})
	return nil
}

// postExecStart answers POST /exec/{id}/start.
//
// With Detach the exec runs to completion with no stream and the response is a
// plain 200. Otherwise the connection is hijacked and the raw stream begins,
// framed exactly when the exec has no TTY.
func (s *Server) postExecStart(w http.ResponseWriter, r *http.Request) error {
	execID, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	var req ExecStartRequest
	if err := decodeJSONBody(r, &req); err != nil {
		return err
	}
	inspect, err := s.backend.ExecInspect(r.Context(), execID)
	if err != nil {
		if errors.Is(err, engine.ErrNotFound) {
			return errNoSuchExec(execID)
		}
		return err
	}
	if inspect.Running {
		return wrapStatus(http.StatusConflict, engine.ErrConflict,
			"Exec command %s is already running", execID)
	}

	if req.Detach {
		// A detached exec outlives its request, so it must not inherit the
		// request's context: cancelling on the client's disconnect would kill
		// the very thing the client asked to run unattended.
		bg := context.WithoutCancel(r.Context())
		go func() {
			if err := s.backend.ExecStart(bg, execID, engine.AttachConfig{}); err != nil {
				s.log.Debug("hull: detached exec ended", "exec", execID, "err", err)
			}
		}()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		return nil
	}

	conn, brw, err := hijackConn(w, r)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	cfg := engine.AttachConfig{
		UseStdin:  inspect.AttachStdin,
		UseStdout: inspect.AttachStdout,
		UseStderr: inspect.AttachStderr,
		Framed:    !inspect.Tty,
	}
	if cfg.UseStdin {
		cfg.Stdin = hijackedStdin{r: brw}
	}
	out := hijackedStdout{w: brw}
	if cfg.UseStdout {
		cfg.Stdout = out
	}
	if cfg.UseStderr {
		cfg.Stderr = out
	}
	if !cfg.UseStdout && !cfg.UseStderr {
		// A client that created the exec with no output streams still needs
		// the process to run; give it stdout so the stream is not dead.
		cfg.UseStdout = true
		cfg.Stdout = out
	}

	if err := s.backend.ExecStart(r.Context(), execID, cfg); err != nil && r.Context().Err() == nil {
		s.log.Debug("hull: exec ended", "exec", execID, "err", err)
	}
	_ = brw.Flush()
	_ = closeWrite(conn)
	return nil
}

// postExecResize answers POST /exec/{id}/resize.
func (s *Server) postExecResize(w http.ResponseWriter, r *http.Request) error {
	execID, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	h, width, err := resizeDimensions(r)
	if err != nil {
		return err
	}
	if err := s.backend.ExecResize(r.Context(), execID, h, width); err != nil {
		if errors.Is(err, engine.ErrNotFound) {
			return errNoSuchExec(execID)
		}
		return err
	}
	writeJSON(w, http.StatusOK, nil)
	return nil
}

// getExecJSON answers GET /exec/{id}/json.
func (s *Server) getExecJSON(w http.ResponseWriter, r *http.Request) error {
	execID, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	in, err := s.backend.ExecInspect(r.Context(), execID)
	if err != nil {
		if errors.Is(err, engine.ErrNotFound) {
			return errNoSuchExec(execID)
		}
		return err
	}
	entrypoint := ""
	var args []string
	if len(in.Cmd) > 0 {
		entrypoint, args = in.Cmd[0], in.Cmd[1:]
	}
	writeJSON(w, http.StatusOK, ExecInspect{
		ID:          in.ID,
		Running:     in.Running,
		ExitCode:    in.ExitCode,
		ContainerID: in.ContainerID,
		OpenStdin:   in.AttachStdin,
		OpenStdout:  in.AttachStdout,
		OpenStderr:  in.AttachStderr,
		Pid:         in.Pid,
		ProcessConfig: &ExecProcessConfig{
			Tty:        in.Tty,
			Entrypoint: entrypoint,
			Arguments:  stringsOrEmpty(args),
			Privileged: in.Privileged,
			User:       in.User,
		},
	})
	return nil
}

// --- stats ---

// StatsCPUUsage is the cpu_usage block of a stats sample.
type StatsCPUUsage struct {
	// TotalUsage is cumulative CPU time in nanoseconds.
	TotalUsage uint64 `json:"total_usage"`
	// UsageInKernelmode and UsageInUsermode split it; hull's cgroup reader
	// reports only the total, so both are zero rather than invented.
	UsageInKernelmode uint64 `json:"usage_in_kernelmode"`
	UsageInUsermode   uint64 `json:"usage_in_usermode"`
	// PercpuUsage is absent on cgroup v2.
	PercpuUsage []uint64 `json:"percpu_usage,omitempty"`
}

// StatsThrottling is the throttling_data block.
type StatsThrottling struct {
	// Periods, ThrottledPeriods and ThrottledTime describe CFS throttling.
	Periods          uint64 `json:"periods"`
	ThrottledPeriods uint64 `json:"throttled_periods"`
	ThrottledTime    uint64 `json:"throttled_time"`
}

// StatsCPU is one cpu_stats or precpu_stats block.
type StatsCPU struct {
	// CPUUsage is the container's own usage.
	CPUUsage StatsCPUUsage `json:"cpu_usage"`
	// SystemCPUUsage is host-wide CPU time, the denominator of the
	// percentage the CLI prints.
	SystemCPUUsage uint64 `json:"system_cpu_usage"`
	// OnlineCPUs is how many CPUs the host has.
	OnlineCPUs int `json:"online_cpus"`
	// ThrottlingData reports CFS throttling.
	ThrottlingData StatsThrottling `json:"throttling_data"`
}

// StatsMemory is the memory_stats block.
type StatsMemory struct {
	// Usage and Limit are the current and maximum bytes.
	Usage uint64 `json:"usage"`
	Limit uint64 `json:"limit"`
	// Stats carries the per-counter detail; the CLI subtracts "cache".
	Stats map[string]uint64 `json:"stats,omitempty"`
}

// StatsPids is the pids_stats block.
type StatsPids struct {
	// Current and Limit are the process count and its cap.
	Current uint64 `json:"current"`
	Limit   uint64 `json:"limit,omitempty"`
}

// StatsBlkioEntry is one blkio counter.
type StatsBlkioEntry struct {
	// Major and Minor identify the device.
	Major uint64 `json:"major"`
	Minor uint64 `json:"minor"`
	// Op is "Read" or "Write", Value the byte count.
	Op    string `json:"op"`
	Value uint64 `json:"value"`
}

// StatsBlkio is the blkio_stats block.
type StatsBlkio struct {
	// IoServiceBytesRecursive is the only counter hull populates.
	IoServiceBytesRecursive []StatsBlkioEntry `json:"io_service_bytes_recursive"`
}

// StatsNetwork is one interface's counters.
type StatsNetwork struct {
	// The eight counters `docker stats` reads.
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
	TxDropped uint64 `json:"tx_dropped"`
}

// StatsJSON is one sample of GET /containers/{id}/stats.
type StatsJSON struct {
	// Read and PreRead bound the sampling interval.
	Read    string `json:"read"`
	PreRead string `json:"preread"`
	// PidsStats, BlkioStats, CPUStats, PreCPUStats and MemoryStats are the
	// counters.
	PidsStats   StatsPids   `json:"pids_stats"`
	BlkioStats  StatsBlkio  `json:"blkio_stats"`
	NumProcs    uint32      `json:"num_procs"`
	CPUStats    StatsCPU    `json:"cpu_stats"`
	PreCPUStats StatsCPU    `json:"precpu_stats"`
	MemoryStats StatsMemory `json:"memory_stats"`
	// Name and ID identify the container.
	Name string `json:"name"`
	ID   string `json:"id"`
	// Networks is keyed by interface name.
	Networks map[string]StatsNetwork `json:"networks,omitempty"`
}

// toStatsJSON converts one engine sample into Docker's shape.
//
// hull records CPU time in microseconds and Docker reports nanoseconds, so
// every CPU counter is scaled here rather than in the engine, where the native
// unit is the cgroup's own.
func toStatsJSON(c *types.Container, s types.Stats) StatsJSON {
	const usecToNsec = 1000
	out := StatsJSON{
		Read:    timeString(s.Read),
		PreRead: timeString(s.PreRead),
		Name:    "/" + c.Name,
		ID:      c.ID,
		PidsStats: StatsPids{
			Current: s.PidsCurrent,
			Limit:   s.PidsLimit,
		},
		BlkioStats: StatsBlkio{IoServiceBytesRecursive: []StatsBlkioEntry{}},
		CPUStats: StatsCPU{
			CPUUsage:       StatsCPUUsage{TotalUsage: s.CPUUsage * usecToNsec},
			SystemCPUUsage: s.SystemUsage * usecToNsec,
			OnlineCPUs:     s.OnlineCPUs,
		},
		PreCPUStats: StatsCPU{
			CPUUsage:       StatsCPUUsage{TotalUsage: s.PreCPUUsage * usecToNsec},
			SystemCPUUsage: s.PreSystemUsage * usecToNsec,
			OnlineCPUs:     s.OnlineCPUs,
		},
		MemoryStats: StatsMemory{
			Usage: s.MemoryUsage,
			Limit: s.MemoryLimit,
			Stats: map[string]uint64{"cache": s.MemoryCache},
		},
	}
	if s.BlkRead > 0 || s.BlkWrite > 0 {
		out.BlkioStats.IoServiceBytesRecursive = []StatsBlkioEntry{
			{Op: "read", Value: s.BlkRead},
			{Op: "write", Value: s.BlkWrite},
		}
	}
	if s.RxBytes > 0 || s.TxBytes > 0 || s.RxPackets > 0 || s.TxPackets > 0 {
		out.Networks = map[string]StatsNetwork{
			"eth0": {
				RxBytes:   s.RxBytes,
				RxPackets: s.RxPackets,
				TxBytes:   s.TxBytes,
				TxPackets: s.TxPackets,
			},
		}
	}
	return out
}

// getContainerStats answers GET /containers/{id}/stats.
func (s *Server) getContainerStats(w http.ResponseWriter, r *http.Request) error {
	id, err := pathVar(r, "id")
	if err != nil {
		return err
	}
	c, err := s.backend.Inspect(r.Context(), id)
	if err != nil {
		return containerError(err, id)
	}
	stream := boolValueOrDefault(r, "stream", true)
	if boolValue(r, "one-shot") {
		stream = false
	}

	w.Header().Set("Content-Type", "application/json")
	if stream {
		w.Header().Set("Transfer-Encoding", "chunked")
	}
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()

	enc := json.NewEncoder(w)
	err = s.backend.Stats(r.Context(), id, stream, func(sample types.Stats) error {
		if err := enc.Encode(toStatsJSON(c, sample)); err != nil {
			return err
		}
		_ = rc.Flush()
		return nil
	})
	if err != nil && r.Context().Err() == nil && !errors.Is(err, io.EOF) {
		s.log.Debug("hull: stats stream ended", "container", id, "err", err)
	}
	return nil
}
