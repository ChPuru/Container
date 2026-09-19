package shim

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// requireRootRuntime skips unless this test can really start a container:
// root, a crun on PATH, and a static busybox to put in the rootfs.
func requireRootRuntime(t *testing.T) (crun string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	crun, err := exec.LookPath("crun")
	if err != nil {
		t.Skip("crun is not installed; the shim's runtime driver cannot be exercised")
	}
	return crun
}

// buildShim compiles cmd/hull-shim into a temporary directory and returns its
// path. The shim has to be a real binary: Spawn double-forks into it.
func buildShim(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH to build hull-shim with")
	}
	out := filepath.Join(t.TempDir(), "hull-shim")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, "build", "-o", out, "./cmd/hull-shim")
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build cmd/hull-shim here: %v\n%s", err, combined)
	}
	return out
}

// staticBusybox finds a statically linked busybox to seed a rootfs with.
func staticBusybox(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"../../test/fixtures/rootfs/bin/busybox",
		"/usr/bin/busybox",
		"/bin/busybox",
		"/sbin/busybox",
	}
	for _, c := range candidates {
		st, err := os.Stat(c)
		if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
			continue
		}
		// A dynamically linked busybox is useless: the rootfs has no loader.
		if err := exec.Command("ldd", c).Run(); err != nil {
			return c
		}
	}
	t.Skip("no static busybox to build a test rootfs from (apt-get install busybox-static)")
	return ""
}

// makeBundle builds an OCI bundle whose init runs args, and returns its path.
//
// The spec itself comes from `crun spec`, so the test exercises the runtime's
// own idea of a valid configuration rather than a hand-rolled one that might
// drift away from it.
func makeBundle(t *testing.T, crun, root string, terminal bool, args []string) string {
	t.Helper()
	bundle := filepath.Join(root, "b")
	rootfs := filepath.Join(bundle, "rootfs")
	for _, d := range []string{"bin", "proc", "dev", "sys", "tmp", "etc", "root"} {
		if err := os.MkdirAll(filepath.Join(rootfs, d), 0o755); err != nil {
			t.Fatalf("mkdir rootfs/%s: %v", d, err)
		}
	}
	bb := staticBusybox(t)
	data, err := os.ReadFile(bb)
	if err != nil {
		t.Fatalf("read %s: %v", bb, err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "bin", "busybox"), data, 0o755); err != nil {
		t.Fatalf("install busybox: %v", err)
	}
	for _, applet := range []string{"sh", "sleep", "echo", "cat", "true"} {
		if err := os.Symlink("busybox", filepath.Join(rootfs, "bin", applet)); err != nil {
			t.Fatalf("link %s: %v", applet, err)
		}
	}

	cmd := exec.Command(crun, "spec", "--bundle", bundle)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("crun spec: %v\n%s", err, out)
	}
	specPath := filepath.Join(bundle, "config.json")
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse config.json: %v", err)
	}
	proc, _ := spec["process"].(map[string]any)
	if proc == nil {
		t.Fatalf("crun spec produced no process block")
	}
	proc["args"] = args
	proc["terminal"] = terminal
	proc["cwd"] = "/"
	if rootBlock, ok := spec["root"].(map[string]any); ok {
		rootBlock["path"] = "rootfs"
		rootBlock["readonly"] = false
	}
	patched, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		t.Fatalf("marshal config.json: %v", err)
	}
	if err := os.WriteFile(specPath, patched, 0o644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	return bundle
}

// dumpShimLog prints the shim's own diagnostics, which is the only way to see
// why a shim that never reported ready gave up.
func dumpShimLog(t *testing.T, containerDir string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(containerDir, ShimLogName))
	if err != nil {
		return
	}
	if len(data) > 0 {
		t.Logf("shim log:\n%s", data)
	}
}

// TestShimSupervisesARealContainer is the whole contract end to end: spawn a
// shim around a real crun container with a terminal, attach to it, resize its
// pty, reconnect the way a restarted daemon would, kill it, and check that the
// exit code reaches both the client and exit.json.
func TestShimSupervisesARealContainer(t *testing.T) {
	crun := requireRootRuntime(t)
	shimBin := buildShim(t)

	root := t.TempDir()
	containerDir := filepath.Join(root, "c")
	if err := os.MkdirAll(containerDir, 0o700); err != nil {
		t.Fatalf("mkdir container dir: %v", err)
	}
	runtimeRoot := filepath.Join(root, "r")
	bundle := makeBundle(t, crun, root, true, []string{"/bin/sh", "-c", "echo hull-ready; sleep 30"})

	cfg := Config{
		ID:            "hulle2e1",
		BundleDir:     bundle,
		ContainerDir:  containerDir,
		RuntimeName:   "crun",
		RuntimeBinary: crun,
		RuntimeRoot:   runtimeRoot,
		Terminal:      true,
		LogPath:       filepath.Join(containerDir, "log.json"),
		LogMaxSize:    1 << 20,
		LogMaxFiles:   2,
		ExitGrace:     20 * time.Second,
		StopTimeout:   2 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := Spawn(ctx, shimBin, cfg)
	if err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("Spawn: %v", err)
	}
	defer client.Close()
	defer func() {
		// Never leave a container behind, whatever the test did.
		_ = exec.Command(crun, "--root", runtimeRoot, "delete", "--force", cfg.ID).Run()
	}()

	// The shim published itself, and the record validates.
	state, err := ReadShimState(cfg.StatePath())
	if err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("ReadShimState: %v", err)
	}
	if !state.Validate() {
		t.Fatalf("shim.json for pid %d does not validate", state.Pid)
	}
	if state.Pid == os.Getpid() {
		t.Fatal("the shim is running in the test process; the double fork did not happen")
	}
	if state.ContainerPid <= 0 {
		t.Fatalf("shim.json records container pid %d", state.ContainerPid)
	}
	// The shim must be a child of init, not of this process: that is what
	// makes it survive the daemon.
	if ppid := parentOf(t, state.Pid); ppid == os.Getpid() {
		t.Errorf("the shim's parent is this process (%d); it was not reparented", ppid)
	}

	st, err := client.State(ctx)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.Status != StatusCreated {
		t.Fatalf("Status = %q before Start, want %q", st.Status, StatusCreated)
	}

	// Attach before starting, so the very first bytes are seen.
	stream, err := client.Attach(ctx, AttachOptions{Stdout: true, Stderr: true})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer stream.Close()
	if !stream.Terminal {
		t.Error("the stream should report a terminal")
	}

	if err := client.Start(ctx); err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("Start: %v", err)
	}
	st, err = client.State(ctx)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.Status != StatusRunning || st.Pid <= 0 {
		t.Fatalf("State = %+v, want a running container", st)
	}

	if got := readUntil(t, stream.Stdout, "hull-ready", 20*time.Second); !strings.Contains(got, "hull-ready") {
		t.Fatalf("attach saw %q, want the container's greeting", got)
	}

	// TIOCSWINSZ on the pty master the runtime handed over.
	if err := client.Resize(ctx, 30, 100); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	// A second resize proves the master is still ours, not a one-shot fd.
	if err := client.Resize(ctx, 50, 200); err != nil {
		t.Fatalf("Resize again: %v", err)
	}

	// A second attacher must also receive output, and must be refused stdin
	// only if someone already holds it.
	second, err := client.Attach(ctx, AttachOptions{Stdout: true})
	if err != nil {
		t.Fatalf("second Attach: %v", err)
	}
	defer second.Close()

	// Simulate a daemon restart: drop every handle and find the shim again
	// through shim.json alone.
	_ = stream.Close()
	_ = second.Close()
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reconnected, err := Reconnect(containerDir)
	if err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("Reconnect after a simulated daemon restart: %v", err)
	}
	defer reconnected.Close()
	st, err = reconnected.State(ctx)
	if err != nil {
		t.Fatalf("State after reconnect: %v", err)
	}
	if st.Status != StatusRunning {
		t.Fatalf("Status after reconnect = %q, want the container still running", st.Status)
	}

	events, err := reconnected.Events(ctx)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}

	if err := reconnected.Kill(ctx, unix.SIGKILL, false); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
	defer waitCancel()
	code, err := reconnected.Wait(waitCtx)
	if err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("Wait: %v", err)
	}
	const wantCode = 128 + int(unix.SIGKILL)
	if code != wantCode {
		t.Errorf("Wait = %d, want %d (128+SIGKILL)", code, wantCode)
	}

	select {
	case ev := <-events:
		if ev.Type != EventExit || ev.ExitCode != wantCode {
			t.Errorf("event = %+v, want an exit with code %d", ev, wantCode)
		}
	case <-time.After(30 * time.Second):
		t.Error("no exit event arrived")
	}

	st, err = reconnected.State(ctx)
	if err != nil {
		t.Fatalf("State after exit: %v", err)
	}
	if !st.Exited || st.Status != StatusStopped || st.ExitCode != wantCode {
		t.Errorf("State after exit = %+v", st)
	}

	// exit.json is the durable record; it must already be on disk.
	exitStatus, err := ReadExitStatus(cfg.ExitPath())
	if err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("ReadExitStatus: %v", err)
	}
	if exitStatus.ExitCode != wantCode {
		t.Errorf("exit.json exit code = %d, want %d", exitStatus.ExitCode, wantCode)
	}
	if exitStatus.FinishedAt.IsZero() {
		t.Error("exit.json has no finish time")
	}

	// The container's output reached the json-file log too.
	logData, err := os.ReadFile(cfg.LogPath)
	if err != nil {
		t.Fatalf("read the json log: %v", err)
	}
	if !strings.Contains(string(logData), "hull-ready") {
		t.Errorf("the json log does not contain the container's output:\n%s", logData)
	}

	// Acknowledge, and the shim should stop serving and clean up promptly
	// rather than sitting out its grace period.
	if err := reconnected.Ack(ctx); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.StatePath()); errors.Is(err, os.ErrNotExist) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(cfg.StatePath()); !errors.Is(err, os.ErrNotExist) {
		dumpShimLog(t, containerDir)
		t.Errorf("shim.json survived the acknowledged exit: %v", err)
	}
	dumpShimLog(t, containerDir)
}

// TestShimPipesStdinAndStdout covers the non-terminal path: three real pipes,
// stdin granted to exactly one attacher, and output split across stdout and
// stderr in the json log.
func TestShimPipesStdinAndStdout(t *testing.T) {
	crun := requireRootRuntime(t)
	shimBin := buildShim(t)

	root := t.TempDir()
	containerDir := filepath.Join(root, "c")
	if err := os.MkdirAll(containerDir, 0o700); err != nil {
		t.Fatalf("mkdir container dir: %v", err)
	}
	runtimeRoot := filepath.Join(root, "r")
	bundle := makeBundle(t, crun, root, false, []string{
		"/bin/sh", "-c", "echo to-stderr 1>&2; while read line; do echo got:$line; done",
	})

	cfg := Config{
		ID:            "hulle2e2",
		BundleDir:     bundle,
		ContainerDir:  containerDir,
		RuntimeName:   "crun",
		RuntimeBinary: crun,
		RuntimeRoot:   runtimeRoot,
		OpenStdin:     true,
		LogPath:       filepath.Join(containerDir, "log.json"),
		LogMaxSize:    1 << 20,
		LogMaxFiles:   2,
		ExitGrace:     15 * time.Second,
		StopTimeout:   2 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := Spawn(ctx, shimBin, cfg)
	if err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("Spawn: %v", err)
	}
	defer client.Close()
	defer func() {
		_ = exec.Command(crun, "--root", runtimeRoot, "delete", "--force", cfg.ID).Run()
	}()

	stream, err := client.Attach(ctx, AttachOptions{Stdin: true, Stdout: true, Stderr: true})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer stream.Close()
	if stream.Terminal {
		t.Error("this container has no terminal")
	}
	if stream.Stdin == nil || stream.Stderr == nil {
		t.Fatal("a non-terminal attach should expose stdin and a separate stderr")
	}

	// A second attacher asking for stdin is refused, with a clear reason.
	if _, err := client.Attach(ctx, AttachOptions{Stdin: true, Stdout: true}); !errors.Is(err, ErrStdinInUse) {
		t.Errorf("second stdin attach = %v, want ErrStdinInUse", err)
	}
	// Resize must refuse too: there is no pty.
	if err := client.Resize(ctx, 24, 80); !errors.Is(err, ErrNoTerminal) {
		t.Errorf("Resize = %v, want ErrNoTerminal", err)
	}

	if err := client.Start(ctx); err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("Start: %v", err)
	}

	if got := readUntil(t, stream.Stderr, "to-stderr", 20*time.Second); !strings.Contains(got, "to-stderr") {
		t.Fatalf("stderr saw %q", got)
	}
	if _, err := stream.Stdin.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if got := readUntil(t, stream.Stdout, "got:ping", 20*time.Second); !strings.Contains(got, "got:ping") {
		t.Fatalf("stdout saw %q, want the container's echo of our stdin", got)
	}

	// Closing stdin ends the read loop, so the shell exits 0 on its own.
	if err := stream.Stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
	defer waitCancel()
	code, err := client.Wait(waitCtx)
	if err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("Wait: %v", err)
	}
	if code != 0 {
		t.Errorf("Wait = %d, want 0 after stdin was closed", code)
	}

	exitStatus, err := ReadExitStatus(cfg.ExitPath())
	if err != nil {
		t.Fatalf("ReadExitStatus: %v", err)
	}
	if exitStatus.ExitCode != 0 {
		t.Errorf("exit.json exit code = %d, want 0", exitStatus.ExitCode)
	}

	logData, err := os.ReadFile(cfg.LogPath)
	if err != nil {
		t.Fatalf("read the json log: %v", err)
	}
	for _, want := range []string{`"stream":"stderr"`, "to-stderr", `"stream":"stdout"`, "got:ping"} {
		if !strings.Contains(string(logData), want) {
			t.Errorf("the json log is missing %q:\n%s", want, logData)
		}
	}
	dumpShimLog(t, containerDir)
}

// TestSpawnReportsABrokenBundle checks the error path hulld cares about most:
// a container that can never start must fail loudly at Spawn, with the
// runtime's own message, and must leave a recorded exit status behind.
func TestSpawnReportsABrokenBundle(t *testing.T) {
	crun := requireRootRuntime(t)
	shimBin := buildShim(t)

	root := t.TempDir()
	containerDir := filepath.Join(root, "c")
	if err := os.MkdirAll(containerDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bundle := filepath.Join(root, "empty")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := Config{
		ID:            "hullbroken",
		BundleDir:     bundle, // no config.json at all
		ContainerDir:  containerDir,
		RuntimeName:   "crun",
		RuntimeBinary: crun,
		RuntimeRoot:   filepath.Join(root, "r"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if _, err := Spawn(ctx, shimBin, cfg); err == nil {
		t.Fatal("Spawn succeeded against a bundle with no config.json")
	} else if !strings.Contains(err.Error(), "crun") {
		t.Errorf("error %q does not carry the runtime's own complaint", err)
	}

	st, err := ReadExitStatus(cfg.ExitPath())
	if err != nil {
		t.Fatalf("a container that never started left no exit.json: %v", err)
	}
	if st.ExitCode == 0 || st.Error == "" {
		t.Errorf("exit.json = %+v, want a non-zero code and an explanation", st)
	}
}

func TestSpawnValidatesItsArguments(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	good := Config{
		ID:            "x",
		BundleDir:     dir,
		ContainerDir:  dir,
		RuntimeBinary: "/bin/true",
	}
	if _, err := Spawn(ctx, "", good); err == nil {
		t.Error("Spawn with no shim binary should fail")
	}
	if _, err := Spawn(ctx, filepath.Join(dir, "nope"), good); err == nil {
		t.Error("Spawn with a missing shim binary should fail")
	}
	if _, err := Spawn(ctx, dir, good); err == nil {
		t.Error("Spawn with a directory as the shim binary should fail")
	}
	bad := good
	bad.ID = ""
	if _, err := Spawn(ctx, "/bin/true", bad); err == nil {
		t.Error("Spawn with an invalid config should fail")
	}
}

// parentOf reads a pid's parent from /proc/<pid>/stat.
func parentOf(t *testing.T, pid int) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("/proc", itoa(pid), "stat"))
	if err != nil {
		return -1
	}
	s := string(data)
	end := strings.LastIndexByte(s, ')')
	if end < 0 || end+2 >= len(s) {
		return -1
	}
	fields := strings.Fields(s[end+2:])
	if len(fields) < 2 {
		return -1
	}
	return atoi(fields[1])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return -1
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// readUntil reads from r until want appears or the timeout expires.
func readUntil(t *testing.T, r io.Reader, want string, d time.Duration) string {
	t.Helper()
	type chunk struct {
		s   string
		err error
	}
	ch := make(chan chunk)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			ch <- chunk{string(buf[:n]), err}
			if err != nil {
				return
			}
		}
	}()
	var acc strings.Builder
	deadline := time.After(d)
	for {
		select {
		case c := <-ch:
			acc.WriteString(c.s)
			if strings.Contains(acc.String(), want) {
				return acc.String()
			}
			if c.err != nil {
				return acc.String()
			}
		case <-deadline:
			return acc.String()
		}
	}
}

// TestShimExecInARunningContainer covers the exec path: a second process in an
// already-running container, with its own stdio stream and its own exit code,
// and with its output deliberately kept out of the container's json log.
func TestShimExecInARunningContainer(t *testing.T) {
	crun := requireRootRuntime(t)
	shimBin := buildShim(t)

	root := t.TempDir()
	containerDir := filepath.Join(root, "c")
	if err := os.MkdirAll(containerDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	runtimeRoot := filepath.Join(root, "r")
	bundle := makeBundle(t, crun, root, false, []string{"/bin/sleep", "60"})

	cfg := Config{
		ID:            "hulle2e3",
		BundleDir:     bundle,
		ContainerDir:  containerDir,
		RuntimeName:   "crun",
		RuntimeBinary: crun,
		RuntimeRoot:   runtimeRoot,
		LogPath:       filepath.Join(containerDir, "log.json"),
		ExitGrace:     15 * time.Second,
		StopTimeout:   2 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := Spawn(ctx, shimBin, cfg)
	if err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("Spawn: %v", err)
	}
	defer client.Close()
	defer func() {
		_ = exec.Command(crun, "--root", runtimeRoot, "delete", "--force", cfg.ID).Run()
	}()
	if err := client.Start(ctx); err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("Start: %v", err)
	}

	spec := []byte(`{"terminal":false,"args":["/bin/sh","-c","echo from-exec; exit 7"],` +
		`"cwd":"/","env":["PATH=/bin"],"user":{"uid":0,"gid":0}}`)
	session, err := client.Exec(ctx, "e1", spec, AttachOptions{Stdout: true, Stderr: true})
	if err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("Exec: %v", err)
	}
	defer session.Close()
	if session.Pid <= 0 {
		t.Errorf("exec pid = %d, want a real pid", session.Pid)
	}

	if got := readUntil(t, session.Stream.Stdout, "from-exec", 20*time.Second); !strings.Contains(got, "from-exec") {
		t.Fatalf("exec stdout = %q", got)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	code, err := session.Wait(waitCtx)
	if err != nil {
		dumpShimLog(t, containerDir)
		t.Fatalf("exec Wait: %v", err)
	}
	if code != 7 {
		t.Errorf("exec exit code = %d, want 7", code)
	}

	// The container's own process is untouched.
	st, err := client.State(ctx)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.Exited || st.Status != StatusRunning {
		t.Fatalf("State after the exec finished = %+v, want the container still running", st)
	}

	// An unknown exec id is reported precisely.
	if _, err := client.Exec(ctx, "e1", spec, AttachOptions{}); err == nil {
		t.Error("reusing an exec id should fail")
	}

	if err := client.Kill(ctx, unix.SIGKILL, false); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if _, err := client.Wait(waitCtx); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	// `hull logs` shows the container's output, never an exec's.
	logData, err := os.ReadFile(cfg.LogPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read the json log: %v", err)
	}
	if strings.Contains(string(logData), "from-exec") {
		t.Errorf("exec output leaked into the container log:\n%s", logData)
	}
	dumpShimLog(t, containerDir)
}
