package wslbridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The relay's command line is built by Config.relayArgs and parsed by RelayMain.
// These tests hold the two together: a mismatch there is invisible until a
// user's first docker command, because the relay runs inside WSL with nothing
// watching its stderr.

func TestRelayMainParsesWhatRelayArgsBuilds(t *testing.T) {
	t.Parallel()

	cfg := Config{Distro: "hull-engine", SocketPath: "/run/hull/hull.sock"}.WithDefaults()
	args := cfg.relayArgs()

	// Drop the wsl.exe preamble and the binary, leaving what RelayMain sees.
	idx := -1
	for i, a := range args {
		if a == RelaySubcommand {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("relayArgs %q does not contain %q", args, RelaySubcommand)
	}
	rest := args[idx+1:]

	// A cancelled context makes RunRelay return immediately, so this exercises
	// the parse without needing an engine socket.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RelayMain(ctx, rest); err != nil {
		t.Fatalf("RelayMain(%q) = %v, want the flags to parse", rest, err)
	}
}

func TestRelayMainRejectsBadFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{name: "unknown flag", args: []string{"--nope"}},
		{name: "stray positional argument", args: []string{"--socket", "/run/hull/hull.sock", "extra"}},
		{name: "non-numeric window", args: []string{"--window", "wide"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := RelayMain(ctx, tc.args); err == nil {
				t.Fatalf("RelayMain(%q) succeeded, want an error", tc.args)
			}
		})
	}
}

// TestRelayMainServesTheConfiguredSocket drives the whole relay path the way
// wsl.exe drives it: a frame stream in, a unix socket out.
func TestRelayMainServesTheConfiguredSocket(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	socket := startEngine(t)
	windowsSide, relaySide := net.Pipe()
	defer windowsSide.Close()

	done := make(chan error, 1)
	go func() {
		done <- RunRelay(ctx, RelayOptions{
			Config: Config{SocketPath: socket},
			In:     relaySide,
			Out:    relaySide,
		})
	}()

	sess := NewSession(windowsSide, SessionOptions{OpenTimeout: 10 * time.Second})
	defer sess.Close()

	st, err := sess.Open(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st.Write([]byte("GET /_ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatalf("half-close: %v", err)
	}
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := `engine saw "GET /_ping"`; string(got) != want {
		t.Errorf("response = %q, want %q", got, want)
	}

	_ = sess.Close()
	_ = relaySide.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunRelay returned %v, want a clean end when the link closes", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("RunRelay did not return after its link closed")
	}
}

func TestBridgeConfigFromArgs(t *testing.T) {
	t.Setenv(EnvDistro, "")

	tests := []struct {
		name    string
		args    []string
		check   func(t *testing.T, cfg Config)
		wantErr bool
	}{
		{
			name: "defaults match DefaultConfig",
			args: nil,
			check: func(t *testing.T, cfg Config) {
				if cfg.Distro != DefaultDistro {
					t.Errorf("distro = %q, want %q", cfg.Distro, DefaultDistro)
				}
				if cfg.PipeName != DefaultPipeName {
					t.Errorf("pipe = %q, want %q", cfg.PipeName, DefaultPipeName)
				}
				if !cfg.ServeDockerPipe {
					t.Error("the docker compatibility pipe is off by default, want it on")
				}
				if !cfg.KeepAlive {
					t.Error("keep-alive is off by default; WSL would reclaim the distro in ~15s")
				}
				if cfg.EnableVsock || cfg.EnableTCP {
					t.Error("an opportunistic transport is on by default, want stdio only")
				}
			},
		},
		{
			name: "every switch flipped",
			args: []string{
				"--distro", "my-engine",
				"--socket", "/tmp/hull.sock",
				"--pipe", `\\.\pipe\hull_test`,
				"--docker-pipe=false",
				"--keep-alive=false",
				"--vsock",
				"--tcp",
			},
			check: func(t *testing.T, cfg Config) {
				if cfg.Distro != "my-engine" || cfg.SocketPath != "/tmp/hull.sock" {
					t.Errorf("distro/socket = %q/%q", cfg.Distro, cfg.SocketPath)
				}
				if cfg.PipeName != `\\.\pipe\hull_test` {
					t.Errorf("pipe = %q", cfg.PipeName)
				}
				if cfg.ServeDockerPipe || cfg.KeepAlive {
					t.Error("--docker-pipe=false / --keep-alive=false were not honoured")
				}
				if !cfg.EnableVsock || !cfg.EnableTCP {
					t.Error("--vsock / --tcp were not honoured")
				}
			},
		},
		{name: "unknown flag", args: []string{"--zoom"}, wantErr: true},
		{name: "stray argument", args: []string{"extra"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := BridgeConfigFromArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("BridgeConfigFromArgs(%q) succeeded, want an error", tc.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("BridgeConfigFromArgs(%q): %v", tc.args, err)
			}
			tc.check(t, cfg)
		})
	}
}

// TestRunOffWindows pins the one thing a Linux developer running the bridge
// should see: a clear unsupported-platform error from the pipe, not a panic and
// not a silent success.
func TestRunOffWindows(t *testing.T) {
	if runtimeIsWindows() {
		t.Skip("this asserts the non-Windows path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	runner := &fakeRunner{handler: func(_ string, args []string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--list" {
			return []byte("hull-engine\n"), nil
		}
		return nil, nil
	}}
	cfg, err := BridgeConfigFromArgs([]string{"--keep-alive=false"})
	if err != nil {
		t.Fatalf("BridgeConfigFromArgs: %v", err)
	}
	cfg.Distro = "hull-engine"
	cfg.Runner = runner

	var mu sync.Mutex
	order := []string{}
	cfg.Transports = []Transport{&fakeTransport{name: "stdio", order: &order, mu: &mu}}

	err = Run(ctx, cfg)
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Run error = %v, want one wrapping ErrUnsupportedPlatform", err)
	}
}

func TestDescribeConfig(t *testing.T) {
	t.Setenv(EnvDistro, "")

	got := DescribeConfig(Config{ServeDockerPipe: true, KeepAlive: true})
	for _, want := range []string{
		"distro=" + DefaultDistro,
		"socket=" + DefaultSocketPath,
		"pipe=" + DefaultPipeName,
		"docker-pipe=" + DockerPipeName,
		"keep-alive=true",
		"transports=stdio",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("DescribeConfig = %q, want it to contain %q", got, want)
		}
	}

	all := DescribeConfig(Config{EnableVsock: true, EnableTCP: true})
	if !strings.Contains(all, "transports=stdio,vsock,tcp") {
		t.Errorf("DescribeConfig = %q, want every enabled transport in probe order", all)
	}
}

// TestVerboseLoggingStaysOffStdout is the one invariant the relay cannot
// survive breaking: its standard output carries the frame stream, so a single
// log line written there desynchronises the wire for good.
func TestVerboseLoggingStaysOffStdout(t *testing.T) {
	var buf bytes.Buffer
	original := stderrWriter
	stderrWriter = func() io.Writer { return &buf }
	t.Cleanup(func() { stderrWriter = original })

	stderrLogger().Info("hello", "stream", 3)
	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("verbose log went somewhere else: %q", buf.String())
	}

	stderrWriter = original
	if w := stderrWriter(); w != os.Stderr {
		t.Errorf("the default verbose destination is %v, want os.Stderr", w)
	}
}

// TestDefaultTokenPathIsUnderTheUserProfile keeps the loopback secret out of a
// world-readable directory on both platforms.
func TestDefaultTokenPathIsUnderTheUserProfile(t *testing.T) {
	got := DefaultTokenPath()
	if got == "" {
		t.Fatal("DefaultTokenPath is empty")
	}
	if filepath.Base(got) != "token" || filepath.Base(filepath.Dir(got)) != "hull" {
		t.Errorf("DefaultTokenPath = %q, want it to end in hull%ctoken", got, filepath.Separator)
	}
}
