// Package wslbridge is the Windows half of hull.
//
// hull's engine runs as a daemon inside a dedicated WSL2 distro and speaks the
// Docker Engine API over a unix socket. Windows cannot reach that socket: WSL2's
// AF_UNIX interop does not work across the VM boundary, and hvsock needs the
// VM's runtime ID, which has no supported discovery path. wslbridge therefore
// does three things, and hull is unusable on Windows without all three:
//
//  1. Serves \\.\pipe\hull_engine (and \\.\pipe\docker_engine when it is free),
//     so hull.exe, the stock docker CLI, docker compose, VS Code Dev Containers
//     and Testcontainers all have something to connect to.
//
//  2. Carries those connections into the distro over a Transport. The default
//     and only universally available transport is a long-lived
//     "wsl.exe --exec hull __relay" child whose stdin and stdout carry a
//     multiplexed frame stream, because one process gives one byte stream while
//     the Docker API needs many concurrent connections. AF_HYPERV and loopback
//     TCP are opportunistic alternatives.
//
//  3. Holds the distro alive. WSL tears a distro down roughly 15 seconds after
//     its last Windows-side client exits, no matter what is running inside it, so
//     a resident hulld does not keep itself alive. A long-lived wsl.exe child on
//     the Windows side does.
//
// Only the named pipe, the hvsock dialler and the bridge's Windows entrypoint are
// Windows-only. The frame codec, the transport interface, the keep-alive agent,
// the distro helpers and the "hull __relay" Linux side all build everywhere, so
// CI on Linux exercises the protocol.
package wslbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Defaults for the bridge. They match scripts/install.ps1, distro/rootfs and
// docs/CLI.md; changing one here means changing it there too.
const (
	// DefaultDistro is the WSL distro that holds the engine.
	DefaultDistro = "hull-engine"

	// DefaultSocketPath is hulld's API socket inside the engine distro. This is
	// the path hull-boot passes to hulld as --socket.
	DefaultSocketPath = "/run/hull/hull.sock"

	// DefaultRelayBinary is the hull binary inside the engine distro, which the
	// stdio transport re-executes as "hull __relay".
	DefaultRelayBinary = "/usr/local/bin/hull"

	// BootBinary starts the engine inside the distro. wsl.conf runs it on boot
	// too; StartEngine runs it again because a distro that WSL reclaimed and
	// restarted can race the first client.
	BootBinary = "/usr/local/bin/hull-boot"

	// DefaultPipeName is hull's own named pipe.
	DefaultPipeName = `\\.\pipe\hull_engine`

	// DockerPipeName is the pipe the stock docker CLI uses with no
	// configuration at all. hull serves it only when nothing else holds it, so
	// a running Docker Desktop is never disturbed.
	DockerPipeName = `\\.\pipe\docker_engine`

	// RelaySubcommand is the hidden hull subcommand that runs the Linux end of
	// the stdio transport.
	RelaySubcommand = "__relay"

	// BridgeSubcommand is the hidden hull subcommand that runs this package's
	// Run on Windows.
	BridgeSubcommand = "__bridge"

	// DefaultVsockPort is the AF_HYPERV port the engine would listen on, when
	// the vsock transport is enabled and the VM's runtime ID can be found.
	DefaultVsockPort = 2376

	// DefaultTCPAddress is the loopback address the TCP transport uses. WSL's
	// NAT-mode localhost relay makes a listener inside the VM reachable here.
	DefaultTCPAddress = "127.0.0.1:2376"

	// EnvDistro overrides the distro name, as documented in docs/CLI.md.
	EnvDistro = "HULL_DISTRO"

	// EnvUTF8 is the variable that makes wsl.exe emit UTF-8 instead of
	// UTF-16LE. Every wsl.exe invocation in this package sets it.
	EnvUTF8 = "WSL_UTF8"
)

// Errors the bridge reports to the CLI. They are sentinel values so "hull
// doctor" and the CLI can branch on them instead of matching strings.
var (
	// ErrDistroMissing means the engine distro is not registered with WSL.
	ErrDistroMissing = errors.New("wslbridge: engine distro is not registered")

	// ErrNoTransport means every transport failed to probe.
	ErrNoTransport = errors.New("wslbridge: no working transport to the engine")

	// ErrUnsupportedPlatform is returned by the Windows-only parts of the
	// package when they are called on another operating system.
	ErrUnsupportedPlatform = errors.New("wslbridge: named pipes are only available on Windows")

	// ErrPipeInUse means another process already owns the pipe name.
	ErrPipeInUse = errors.New("wslbridge: pipe is already owned by another process")
)

// Config describes one bridge: which distro to reach, how to reach it, and what
// to serve on Windows. The zero value is usable; WithDefaults fills it in.
type Config struct {
	// Distro is the WSL distro holding the engine. Empty means $HULL_DISTRO,
	// then DefaultDistro.
	Distro string

	// SocketPath is hulld's API socket inside that distro.
	SocketPath string

	// RelayBinary is the hull binary inside the distro, re-executed as
	// "hull __relay".
	RelayBinary string

	// PipeName is the primary named pipe to serve on Windows.
	PipeName string

	// ServeDockerPipe additionally serves DockerPipeName when it is free, so
	// DOCKER_HOST needs no configuration. It is skipped, with a log line and no
	// error, when Docker Desktop already owns it.
	ServeDockerPipe bool

	// DockerPipeName overrides the compatibility pipe name.
	DockerPipeName string

	// WSLPath is the wsl.exe to run. Empty means "wsl.exe" from PATH.
	WSLPath string

	// EnableVsock allows the opportunistic AF_HYPERV transport to be probed.
	// It is off by default: the VM runtime ID discovery routes it depends on
	// are undocumented and have disappeared across WSL updates before.
	EnableVsock bool

	// VsockPort is the AF_HYPERV port to try. Zero means DefaultVsockPort.
	VsockPort uint32

	// EnableTCP allows the loopback TCP transport to be probed. It is off by
	// default because anything running as the user can reach a loopback port;
	// the shared secret in TokenPath is what makes it safe to turn on.
	EnableTCP bool

	// TCPAddress is the loopback address for the TCP transport.
	TCPAddress string

	// TokenPath is the shared secret file for the TCP transport. Empty means
	// %LOCALAPPDATA%\hull\token.
	TokenPath string

	// KeepAlive holds the distro open for the lifetime of the bridge. It is on
	// by default and turning it off means WSL will reclaim the VM about 15
	// seconds after the last client disconnects.
	KeepAlive bool

	// DialTimeout bounds a single transport dial. Zero means 10s.
	DialTimeout time.Duration

	// ProbeTimeout bounds a single transport probe during selection. Zero means
	// 5s.
	ProbeTimeout time.Duration

	// EngineStartTimeout bounds StartEngine's wait for the API socket. Zero
	// means 30s.
	EngineStartTimeout time.Duration

	// Window is the per-stream receive window for the multiplexed transports.
	// Zero means DefaultWindow.
	Window int

	// Logger receives the bridge's diagnostics. Zero means a discarding logger.
	Logger *slog.Logger

	// Runner runs wsl.exe. Zero means a real exec.Command runner; tests
	// substitute their own.
	Runner CommandRunner

	// Spawner starts the stdio relay child. Zero means a real wsl.exe spawner.
	Spawner StreamSpawner

	// Transports, when set, replaces the built-in candidate list in
	// SelectTransport. It exists for tests and for a caller that has already
	// decided which transport to use.
	Transports []Transport

	// OnStart, when set, is called once with a Control as soon as Run is
	// serving. It is how hull's idle-exit signal reaches the bridge: the
	// engine tells the CLI it is going to sleep, and the CLI calls
	// Control.Release so WSL can reclaim the VM's memory. It is called on
	// Run's goroutine, so it must not block.
	OnStart func(*Control)
}

// DefaultConfig returns the configuration hull.exe uses when the user has set
// nothing: the hull-engine distro, hull's own pipe plus the docker_engine
// compatibility pipe, the stdio transport and the keep-alive agent.
func DefaultConfig() Config {
	return Config{
		ServeDockerPipe: true,
		KeepAlive:       true,
	}.WithDefaults()
}

// WithDefaults returns a copy of c with every zero field filled in. It is
// idempotent, so callers may apply it more than once.
func (c Config) WithDefaults() Config {
	if c.Distro == "" {
		c.Distro = os.Getenv(EnvDistro)
	}
	if c.Distro == "" {
		c.Distro = DefaultDistro
	}
	if c.SocketPath == "" {
		c.SocketPath = DefaultSocketPath
	}
	if c.RelayBinary == "" {
		c.RelayBinary = DefaultRelayBinary
	}
	if c.PipeName == "" {
		c.PipeName = DefaultPipeName
	}
	if c.DockerPipeName == "" {
		c.DockerPipeName = DockerPipeName
	}
	if c.WSLPath == "" {
		c.WSLPath = "wsl.exe"
	}
	if c.VsockPort == 0 {
		c.VsockPort = DefaultVsockPort
	}
	if c.TCPAddress == "" {
		c.TCPAddress = DefaultTCPAddress
	}
	if c.TokenPath == "" {
		c.TokenPath = DefaultTokenPath()
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = 5 * time.Second
	}
	if c.EngineStartTimeout <= 0 {
		c.EngineStartTimeout = 30 * time.Second
	}
	if c.Window <= 0 {
		c.Window = DefaultWindow
	}
	if c.Logger == nil {
		c.Logger = discardLogger()
	}
	if c.Runner == nil {
		c.Runner = ExecRunner{}
	}
	return c
}

// sessionOptions maps a Config onto the multiplexer's options.
func (c Config) sessionOptions(server bool) SessionOptions {
	return SessionOptions{
		Server:      server,
		Window:      c.Window,
		OpenTimeout: c.DialTimeout,
		Logger:      c.Logger,
	}
}

// DefaultTokenPath is where the loopback TCP transport's shared secret lives:
// %LOCALAPPDATA%\hull\token on Windows, and $XDG_CONFIG_HOME/hull/token (or
// ~/.config/hull/token) elsewhere, so the Linux-side tests and tooling have a
// path too.
func DefaultTokenPath() string {
	if runtime.GOOS == "windows" {
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			return filepath.Join(dir, "hull", "token")
		}
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "hull", "token")
	}
	return filepath.Join(os.TempDir(), "hull", "token")
}

// CommandRunner runs a Windows-side command and returns its standard output.
// Every wsl.exe call in this package goes through one, so tests never need a
// real WSL installation.
type CommandRunner interface {
	// Run executes name with args and returns its standard output. The error
	// wraps the command's standard error, because wsl.exe reports everything
	// interesting there.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner is the real CommandRunner: os/exec with WSL_UTF8=1 set, which is
// what stops wsl.exe emitting UTF-16LE that mangles every string comparison.
type ExecRunner struct {
	// Env is added to the child's environment. WSL_UTF8=1 is always set.
	Env []string
}

// Run implements CommandRunner.
func (r ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = wslEnv(r.Env)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(string(decodeWSLBytes(out)))
		}
		if msg != "" {
			return out, fmt.Errorf("wslbridge: %s %s: %w: %s", name, strings.Join(args, " "), err, msg)
		}
		return out, fmt.Errorf("wslbridge: %s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

// wslEnv returns the current environment with WSL_UTF8=1 forced on, plus extra.
func wslEnv(extra []string) []string {
	env := make([]string, 0, len(os.Environ())+len(extra)+1)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(strings.ToUpper(kv), EnvUTF8+"=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, EnvUTF8+"=1")
	env = append(env, extra...)
	return env
}

// discardLogger is the logger used when a caller supplies none.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// halfCloser is implemented by connections that can signal end-of-write without
// tearing the whole connection down: TCP, the multiplexer's streams, and the
// unix socket inside the distro. Named pipes cannot, which is exactly why the
// relay has to check rather than assume.
type halfCloser interface {
	CloseWrite() error
}

// closeWrite half-closes conn when it can, and reports whether it did. A
// connection that cannot half-close is left alone: closing it outright here
// would cut off the response the peer is still writing.
func closeWrite(conn io.Writer) bool {
	if hc, ok := conn.(halfCloser); ok {
		return hc.CloseWrite() == nil
	}
	return false
}
