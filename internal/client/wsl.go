package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// defaultRelayScript is the shell hull runs inside the engine distro to bridge
// wsl.exe's stdio onto the engine's unix socket.
//
// Windows AF_UNIX interop into WSL2 does not work, and hvsock needs the VM's
// runtime id, which is undiscoverable without admin — so a "wsl.exe --exec"
// stdio relay is the supported transport. The script prefers hull's own
// hidden relay subcommand, then socat, then a unix-capable nc, and says which
// it wanted when none is present rather than failing with an empty stream.
const defaultRelayScript = `p="$1"; ` +
	`if command -v hull >/dev/null 2>&1; then exec hull __relay --socket "$p"; ` +
	`elif command -v socat >/dev/null 2>&1; then exec socat - "UNIX-CONNECT:$p"; ` +
	`elif command -v nc >/dev/null 2>&1 && nc -h 2>&1 | grep -q -- -U; then exec nc -U "$p"; ` +
	`else echo "hull: no relay helper in this distro (want hull, socat or nc -U)" >&2; exit 127; fi`

// wslExe is the Windows-side launcher. It is a variable so tests can point it
// at a stub.
var wslExe = "wsl.exe"

// EnvRelay overrides the relay argv whole, for a distro that keeps hull
// somewhere unusual. It is split on spaces, so it suits a path plus a flag or
// two rather than a shell pipeline.
const EnvRelay = "HULL_WSL_RELAY"

// relayCommand builds the argv that opens one relay connection.
func relayCommand(h Host, override []string) []string {
	if len(override) == 0 {
		if env := strings.Fields(strings.TrimSpace(os.Getenv(EnvRelay))); len(env) > 0 {
			override = env
		}
	}
	if len(override) > 0 {
		out := make([]string, len(override))
		copy(out, override)
		return out
	}
	sock := h.SocketPath
	if sock == "" {
		sock = DefaultUnixSocket
	}
	return []string{wslExe, "-d", h.Addr, "-u", "root", "--exec",
		"/bin/sh", "-c", defaultRelayScript, "hull-relay", sock}
}

// dialWSL starts one relay process and presents its stdio as a net.Conn.
func dialWSL(ctx context.Context, h Host, override []string) (net.Conn, error) {
	argv := relayCommand(h, override)
	// The relay must outlive the dial context: ctx here bounds the dial, not
	// the connection, and net/http cancels it as soon as the response headers
	// are in. The connection's own Close tears the process down.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "WSL_UTF8=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("client: wsl relay stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("client: wsl relay stdout: %w", err)
	}
	var stderr strings.Builder
	cmd.Stderr = &lockedWriter{w: &stderr}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("client: starting %s: %w", argv[0], err)
	}
	c := &execConn{
		cmd:    cmd,
		r:      stdout,
		w:      stdin,
		stderr: &stderr,
		addr:   pipeAddr{network: string(SchemeWSL), addr: h.Addr},
	}
	select {
	case <-ctx.Done():
		_ = c.Close()
		return nil, fmt.Errorf("client: dialling %s: %w", h.String(), ctx.Err())
	default:
	}
	return c, nil
}

// lockedWriter serialises writes into a strings.Builder that another goroutine
// may read while the process is still running.
type lockedWriter struct {
	mu sync.Mutex
	w  *strings.Builder
}

// Write implements io.Writer.
func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// execConn is a net.Conn backed by a child process's standard streams.
type execConn struct {
	cmd    *exec.Cmd
	r      io.ReadCloser
	w      io.WriteCloser
	stderr *strings.Builder
	addr   pipeAddr

	mu     sync.Mutex
	rTimer *time.Timer
	wTimer *time.Timer
	closed bool
	once   sync.Once
}

// Read implements net.Conn. A relay that died before saying anything reports
// its stderr, which is the only place a missing helper is ever mentioned.
func (c *execConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err != nil && n == 0 {
		c.mu.Lock()
		msg := strings.TrimSpace(c.stderr.String())
		c.mu.Unlock()
		if msg != "" {
			return 0, fmt.Errorf("wsl relay: %s", msg)
		}
	}
	return n, err
}

// Write implements net.Conn.
func (c *execConn) Write(p []byte) (int, error) { return c.w.Write(p) }

// Close shuts the relay down and reaps it.
func (c *execConn) Close() error {
	c.mu.Lock()
	c.closed = true
	if c.rTimer != nil {
		c.rTimer.Stop()
	}
	if c.wTimer != nil {
		c.wTimer.Stop()
	}
	c.mu.Unlock()
	c.once.Do(func() {
		_ = c.w.Close()
		_ = c.r.Close()
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		_ = c.cmd.Wait()
	})
	return nil
}

// LocalAddr implements net.Conn.
func (c *execConn) LocalAddr() net.Addr { return c.addr }

// RemoteAddr implements net.Conn.
func (c *execConn) RemoteAddr() net.Addr { return c.addr }

// SetDeadline implements net.Conn by arming both watchdogs.
func (c *execConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn.
func (c *execConn) SetReadDeadline(t time.Time) error { return c.arm(&c.rTimer, t) }

// SetWriteDeadline implements net.Conn.
func (c *execConn) SetWriteDeadline(t time.Time) error { return c.arm(&c.wTimer, t) }

// arm resets one watchdog. A pipe to a child process has no kernel deadline,
// so an expired one closes the connection instead.
func (c *execConn) arm(slot **time.Timer, t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if *slot != nil {
		(*slot).Stop()
		*slot = nil
	}
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		go func() { _ = c.Close() }()
		return nil
	}
	*slot = time.AfterFunc(d, func() { _ = c.Close() })
	return nil
}
