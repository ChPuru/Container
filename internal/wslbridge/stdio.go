package wslbridge

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// StreamSpawner starts the child process whose stdin and stdout together form
// one duplex byte stream to the engine distro. It exists as an interface so the
// selection and multiplexing logic can be tested on Linux, where there is no
// wsl.exe to spawn.
type StreamSpawner interface {
	// Spawn starts a relay child. Closing the returned stream terminates it.
	// The context bounds the child's whole lifetime, not just the start.
	Spawn(ctx context.Context, cfg Config) (io.ReadWriteCloser, error)

	// Describe renders the command it would run, for logs and error messages.
	Describe(cfg Config) string
}

// relayArgs is the wsl.exe argument list for the Linux end of the stdio
// transport. "--exec" matters: without it wsl.exe runs the command through a
// login shell, which would rewrite the byte stream.
func (c Config) relayArgs() []string {
	return c.wslArgs(c.RelayBinary, RelaySubcommand, "--socket", c.SocketPath)
}

// WSLSpawner is the real spawner: one long-lived
// `wsl.exe -d <distro> -u root --exec /usr/local/bin/hull __relay --socket <path>`
// child, with WSL_UTF8=1 set, whose stdio carries every multiplexed stream.
type WSLSpawner struct{}

// Describe implements StreamSpawner.
func (WSLSpawner) Describe(cfg Config) string {
	cfg = cfg.WithDefaults()
	return cfg.WSLPath + " " + strings.Join(cfg.relayArgs(), " ")
}

// Spawn implements StreamSpawner.
func (WSLSpawner) Spawn(ctx context.Context, cfg Config) (io.ReadWriteCloser, error) {
	cfg = cfg.WithDefaults()
	cmd := exec.CommandContext(ctx, cfg.WSLPath, cfg.relayArgs()...)
	cmd.Env = wslEnv(nil)
	// Without this a console window flashes on every relay restart when
	// hull.exe runs from a GUI shell.
	hideWindow(cmd)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("wslbridge: relay stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("wslbridge: relay stdout: %w", err)
	}
	errs := &ringBuffer{max: 4096}
	cmd.Stderr = errs

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("wslbridge: start %s: %w", WSLSpawner{}.Describe(cfg), err)
	}
	return &procStream{cmd: cmd, stdin: stdin, stdout: stdout, errs: errs}, nil
}

// procStream presents a child process's stdin and stdout as one duplex stream.
type procStream struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	errs   *ringBuffer

	once sync.Once
}

// Read reads from the child's standard output.
func (p *procStream) Read(b []byte) (int, error) {
	n, err := p.stdout.Read(b)
	if err != nil && err != io.EOF {
		if msg := p.errs.String(); msg != "" {
			return n, fmt.Errorf("wslbridge: relay read: %w (relay said: %s)", err, msg)
		}
	}
	return n, err
}

// Write writes to the child's standard input.
func (p *procStream) Write(b []byte) (int, error) {
	return p.stdin.Write(b)
}

// Close stops the relay child: stdin first, so a well-behaved relay exits on
// its own, then a kill for one that does not.
func (p *procStream) Close() error {
	p.once.Do(func() {
		_ = p.stdin.Close()
		done := make(chan struct{})
		go func() {
			_ = p.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = p.cmd.Process.Kill()
			<-done
		}
		_ = p.stdout.Close()
	})
	return nil
}

// Stderr returns whatever the child last wrote to standard error, which is the
// only clue when wsl.exe refuses to run the relay at all.
func (p *procStream) Stderr() string { return p.errs.String() }

// ringBuffer keeps the last max bytes written to it, so a chatty child cannot
// grow the bridge's memory while its diagnostics stay available.
type ringBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

// Write implements io.Writer, discarding all but the most recent max bytes.
func (r *ringBuffer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	max := r.max
	if max <= 0 {
		max = 4096
	}
	r.buf = append(r.buf, p...)
	if len(r.buf) > max {
		r.buf = r.buf[len(r.buf)-max:]
	}
	return len(p), nil
}

// String returns the retained bytes with surrounding whitespace trimmed.
func (r *ringBuffer) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.TrimSpace(string(decodeWSLBytes(r.buf)))
}

// StdioTransport is hull's default transport: one long-lived relay child whose
// stdio carries a multiplexed frame stream, so many concurrent Docker API
// connections share a single wsl.exe.
//
// It is the default because it is the only transport that always works. It also
// re-spawns its child on demand, which is what lets the bridge survive WSL
// reclaiming the distro underneath it.
type StdioTransport struct {
	base    context.Context
	cfg     Config
	spawner StreamSpawner

	mu     sync.Mutex
	sess   *Session
	stream io.ReadWriteCloser
	closed bool
}

var _ Transport = (*StdioTransport)(nil)

// NewStdioTransport returns a stdio transport. The context bounds the lifetime
// of every relay child it spawns, so cancelling it reaps the wsl.exe process.
func NewStdioTransport(ctx context.Context, cfg Config) *StdioTransport {
	cfg = cfg.WithDefaults()
	sp := cfg.Spawner
	if sp == nil {
		sp = WSLSpawner{}
	}
	return &StdioTransport{base: ctx, cfg: cfg, spawner: sp}
}

// Name implements Transport.
func (t *StdioTransport) Name() string { return "stdio" }

// session returns a live multiplexer session, spawning a relay child if there is
// none or if the previous one died.
func (t *StdioTransport) session() (*Session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, ErrSessionClosed
	}
	if t.sess != nil {
		select {
		case <-t.sess.Done():
			// The relay child is gone: WSL reclaimed the distro, the user ran
			// "wsl --shutdown", or the engine restarted. Drop it and respawn.
			t.cfg.Logger.Debug("wslbridge: relay session ended, respawning",
				"error", t.sess.Err())
			t.discardLocked()
		default:
			return t.sess, nil
		}
	}

	stream, err := t.spawner.Spawn(t.base, t.cfg)
	if err != nil {
		return nil, err
	}
	sess := NewSession(stream, t.cfg.sessionOptions(false))
	t.sess, t.stream = sess, stream
	t.cfg.Logger.Debug("wslbridge: relay started", "command", t.spawner.Describe(t.cfg))
	return sess, nil
}

// discardLocked drops the current session and child. Callers hold t.mu.
func (t *StdioTransport) discardLocked() {
	if t.sess != nil {
		_ = t.sess.Close()
		t.sess = nil
	}
	if t.stream != nil {
		_ = t.stream.Close()
		t.stream = nil
	}
}

// Dial implements Transport. Each call is a new multiplexed stream, which the
// relay connects to hulld's unix socket.
func (t *StdioTransport) Dial(ctx context.Context) (net.Conn, error) {
	sess, err := t.session()
	if err != nil {
		return nil, fmt.Errorf("wslbridge: stdio transport: %w", err)
	}
	st, err := sess.Open(ctx)
	if err != nil {
		return nil, fmt.Errorf("wslbridge: stdio transport: %w", err)
	}
	return st, nil
}

// Probe implements Transport. It opens a real stream and closes it, so a relay
// that starts but cannot reach the engine socket fails here rather than on the
// user's first docker command.
func (t *StdioTransport) Probe(ctx context.Context) error {
	conn, err := t.Dial(ctx)
	if err != nil {
		return err
	}
	return conn.Close()
}

// Release drops the relay child without retiring the transport, and the next
// Dial spawns a fresh one.
//
// This exists because the keep-alive agent is not the only thing holding the
// distro open: a live `wsl.exe --exec hull __relay` child is itself a
// Windows-side client, so releasing the keep-alive while the relay is still
// running reclaims nothing at all. Scale-to-zero needs both to let go.
func (t *StdioTransport) Release() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.sess == nil {
		return
	}
	t.cfg.Logger.Debug("wslbridge: releasing the relay child so WSL can reclaim the VM")
	t.discardLocked()
}

// Close stops the relay child and fails every stream still open on it.
func (t *StdioTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	t.discardLocked()
	return nil
}
