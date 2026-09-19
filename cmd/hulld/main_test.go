package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		check   func(t *testing.T, o *options)
	}{
		{
			name: "defaults",
			args: nil,
			check: func(t *testing.T, o *options) {
				if o.logLevel != "info" {
					t.Errorf("logLevel = %q, want info", o.logLevel)
				}
				if o.socketMode != defaultSocketMode {
					t.Errorf("socketMode = %#o, want %#o", o.socketMode, defaultSocketMode)
				}
				if o.idleFreeze != 0 || o.idleExit != 0 {
					t.Errorf("idle defaults = %v/%v, want both zero", o.idleFreeze, o.idleExit)
				}
				if o.debug || o.accessLog || o.showVersion {
					t.Errorf("boolean defaults are not all false: %+v", o)
				}
			},
		},
		{
			name: "every documented flag",
			args: []string{
				"--data-root", "/tmp/hull",
				"--socket", "/tmp/hull.sock",
				"--shared-socket", "/tmp/shared.sock",
				"--tcp", "127.0.0.1:2375",
				"--tcp-token", "s3cret",
				"--shim", "/opt/hull-shim",
				"--init-binary", "/opt/hull-init",
				"--runtime", "crun",
				"--runtime-binary", "/usr/bin/crun",
				"--default-pool", "10.99.0.0/16",
				"--idle-freeze", "5m",
				"--idle-exit", "30m",
				"--log-level", "debug",
				"--debug",
			},
			check: func(t *testing.T, o *options) {
				if o.tcpToken != "s3cret" || o.tcp != "127.0.0.1:2375" {
					t.Errorf("tcp = %q token = %q", o.tcp, o.tcpToken)
				}
				if o.runtimeName != "crun" || o.runtimeBinary != "/usr/bin/crun" {
					t.Errorf("runtime = %q %q", o.runtimeName, o.runtimeBinary)
				}
				if o.idleFreeze != 5*time.Minute || o.idleExit != 30*time.Minute {
					t.Errorf("idle = %v/%v", o.idleFreeze, o.idleExit)
				}
				if !o.debug || o.logLevel != "debug" {
					t.Errorf("debug=%v logLevel=%q", o.debug, o.logLevel)
				}
				// --debug implies the access log; an operator who asked for
				// debugging should not have to ask twice.
				if !o.accessLog {
					t.Error("--debug did not turn the access log on")
				}
				if o.defaultPool != "10.99.0.0/16" {
					t.Errorf("defaultPool = %q", o.defaultPool)
				}
				if o.shim != "/opt/hull-shim" || o.initBinary != "/opt/hull-init" {
					t.Errorf("helpers = %q %q", o.shim, o.initBinary)
				}
			},
		},
		{
			name: "socket mode is read as octal",
			args: []string{"--socket-mode", "0600"},
			check: func(t *testing.T, o *options) {
				if o.socketMode != 0o600 {
					t.Errorf("socketMode = %#o, want 0600", o.socketMode)
				}
			},
		},
		{
			name:  "version",
			args:  []string{"--version"},
			check: func(t *testing.T, o *options) { mustBeTrue(t, o.showVersion, "showVersion") },
		},
		{name: "unknown flag", args: []string{"--nope"}, wantErr: true},
		{name: "positional argument", args: []string{"serve"}, wantErr: true},
		{name: "unparseable duration", args: []string{"--idle-freeze", "soon"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o, err := parseFlags(tc.args, io.Discard)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseFlags(%v) = nil error, want one", tc.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFlags(%v): %v", tc.args, err)
			}
			if tc.check != nil {
				tc.check(t, o)
			}
		})
	}
}

func TestOptionsResolve(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	tests := []struct {
		name    string
		in      options
		wantErr string
		check   func(t *testing.T, o *options)
	}{
		{
			name: "socket defaults under the data root",
			in:   options{dataRoot: root, socketMode: defaultSocketMode},
			check: func(t *testing.T, o *options) {
				want := filepath.Join(root, filepath.FromSlash(defaultSocketName))
				if o.socket != want {
					t.Errorf("socket = %q, want %q", o.socket, want)
				}
			},
		},
		{
			name: "socket none still needs another listener",
			in: options{
				dataRoot: root, socket: "none", socketMode: defaultSocketMode,
				sharedSocket: filepath.Join(root, "shared.sock"),
			},
			check: func(t *testing.T, o *options) {
				if o.socket != "" {
					t.Errorf("socket = %q, want it disabled", o.socket)
				}
				if o.sharedSocket == "" {
					t.Error("an explicitly named shared socket was dropped")
				}
			},
		},
		{
			name:    "no listener at all",
			in:      options{dataRoot: root, socket: "none", socketMode: defaultSocketMode},
			wantErr: "no listener configured",
		},
		{
			name: "tcp without a token is refused",
			in: options{
				dataRoot: root, socket: "none", socketMode: defaultSocketMode,
				tcp: "127.0.0.1:2375",
			},
			wantErr: "--tcp requires --tcp-token",
		},
		{
			name: "tcp with a token is accepted",
			in: options{
				dataRoot: root, socket: "none", socketMode: defaultSocketMode,
				tcp: "127.0.0.1:2375", tcpToken: "abc",
			},
			check: func(t *testing.T, o *options) {
				if o.tcp == "" {
					t.Error("tcp was cleared")
				}
			},
		},
		{
			name: "shared socket must differ from the primary",
			in: options{
				dataRoot: root, socket: filepath.Join(root, "a.sock"),
				sharedSocket: filepath.Join(root, "a.sock"), socketMode: defaultSocketMode,
			},
			wantErr: "same path",
		},
		{
			name:    "impossible socket mode",
			in:      options{dataRoot: root, socketMode: 0o7777},
			wantErr: "is not a permission mask",
		},
		{
			name:    "zero socket mode",
			in:      options{dataRoot: root, socketMode: 0},
			wantErr: "is not a permission mask",
		},
		{
			name:    "negative idle durations",
			in:      options{dataRoot: root, socketMode: defaultSocketMode, idleFreeze: -time.Second},
			wantErr: "cannot be negative",
		},
		{
			name: "the default shared socket is dropped off WSL",
			in: options{
				dataRoot: root, socketMode: defaultSocketMode,
				sharedSocket: defaultSharedSocket,
			},
			check: func(t *testing.T, o *options) {
				// On a real WSL host /mnt/wsl exists and the socket stays; off
				// one it is dropped with a note rather than failing the daemon.
				if _, err := os.Stat("/mnt/wsl"); err != nil {
					if o.sharedSocket != "" {
						t.Errorf("sharedSocket = %q, want it dropped with /mnt/wsl absent", o.sharedSocket)
					}
					if len(o.notes) == 0 {
						t.Error("dropping the shared socket was not explained")
					}
				}
			},
		},
		{
			name: "an empty pool falls back to the documented default",
			in:   options{dataRoot: root, socketMode: defaultSocketMode},
			check: func(t *testing.T, o *options) {
				if o.defaultPool == "" {
					t.Error("defaultPool was left empty")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := tc.in
			err := o.resolve()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("resolve() = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve(): %v", err)
			}
			if tc.check != nil {
				tc.check(t, &o)
			}
		})
	}
}

func TestNormalizeListener(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in       string
		want     string
		disabled bool
	}{
		{in: "", want: ""},
		{in: "  ", want: ""},
		{in: "none", want: "", disabled: true},
		{in: "NONE", want: "", disabled: true},
		{in: " off ", want: "", disabled: true},
		{in: "disabled", want: "", disabled: true},
		{in: "/run/hull.sock", want: "/run/hull.sock"},
		{in: " 127.0.0.1:2375 ", want: "127.0.0.1:2375"},
	}
	for _, tc := range tests {
		t.Run("listener="+tc.in, func(t *testing.T) {
			t.Parallel()
			if got := normalizeListener(tc.in); got != tc.want {
				t.Errorf("normalizeListener(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if got := listenerDisabled(tc.in); got != tc.disabled {
				t.Errorf("listenerDisabled(%q) = %v, want %v", tc.in, got, tc.disabled)
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    slog.Level
		wantErr bool
	}{
		{in: "debug", want: slog.LevelDebug},
		{in: "", want: slog.LevelInfo},
		{in: "info", want: slog.LevelInfo},
		{in: "WARN", want: slog.LevelWarn},
		{in: "warning", want: slog.LevelWarn},
		{in: " error ", want: slog.LevelError},
		{in: "loud", wantErr: true},
	}
	for _, tc := range tests {
		t.Run("level="+tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := parseLevel(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseLevel(%q) = %v, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseLevel(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseLevel(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNewLoggerUsesJSONOffATerminal(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	newLogger(&buf, slog.LevelInfo, false).Info("hello", "k", "v")
	if out := buf.String(); !strings.Contains(out, `"msg":"hello"`) {
		t.Errorf("a non-terminal writer should get JSON, got %q", out)
	}

	buf.Reset()
	newLogger(&buf, slog.LevelInfo, true).Info("hello", "k", "v")
	if out := buf.String(); !strings.Contains(out, "msg=hello") {
		t.Errorf("a terminal writer should get text, got %q", out)
	}

	buf.Reset()
	newLogger(&buf, slog.LevelWarn, false).Info("quiet")
	if buf.Len() != 0 {
		t.Errorf("info was logged at warn level: %q", buf.String())
	}
}

func TestIsTerminal(t *testing.T) {
	t.Parallel()
	if isTerminal(new(bytes.Buffer)) {
		t.Error("a bytes.Buffer is not a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = f.Close() }()
	if isTerminal(f) {
		t.Error("a regular file is not a terminal")
	}
}

func TestResolveHelperPrefersAnExplicitPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	explicit := filepath.Join(dir, "hull-shim")
	if err := os.WriteFile(explicit, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got := resolveHelper(explicit, "hull-shim"); got != explicit {
		t.Errorf("resolveHelper(explicit) = %q, want %q", got, explicit)
	}
	// An explicit path that does not exist is still honoured: failing loudly
	// beats silently running a different binary than the operator named.
	missing := filepath.Join(dir, "absent")
	if got := resolveHelper(missing, "hull-shim"); got != missing {
		t.Errorf("resolveHelper(missing) = %q, want %q", got, missing)
	}
	// A helper nobody could possibly have installed resolves to nothing,
	// which the daemon reports as a warning rather than a crash.
	if got := resolveHelper("", "hull-definitely-not-installed"); got != "" {
		t.Errorf("resolveHelper(absent helper) = %q, want empty", got)
	}
}

func TestFileExists(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !fileExists(file) {
		t.Error("a regular file was not found")
	}
	if fileExists(dir) {
		t.Error("a directory is not a file")
	}
	if fileExists("") || fileExists(filepath.Join(dir, "nope")) {
		t.Error("a missing path was reported as existing")
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("HULLD_TEST_KEY", "  from-env  ")
	if got := envOr("HULLD_TEST_KEY", "fallback"); got != "from-env" {
		t.Errorf("envOr = %q, want from-env", got)
	}
	t.Setenv("HULLD_TEST_KEY", "   ")
	if got := envOr("HULLD_TEST_KEY", "fallback"); got != "fallback" {
		t.Errorf("envOr with a blank value = %q, want fallback", got)
	}
}

func TestWritePIDFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d := &daemon{opts: &options{dataRoot: root}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	remove := d.writePIDFile()

	path := filepath.Join(root, filepath.FromSlash(defaultPIDName))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("pid file not written: %v", err)
	}
	if strings.TrimSpace(string(data)) != strconv.Itoa(os.Getpid()) {
		t.Errorf("pid file holds %q, want %d", string(data), os.Getpid())
	}

	remove()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("pid file survived removal: %v", err)
	}

	// A file another daemon has since replaced must be left alone.
	remove2 := d.writePIDFile()
	if err := os.WriteFile(path, []byte("123456\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	remove2()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("a pid file owned by another process was removed: %v", err)
	}
}

func TestRunVersion(t *testing.T) {
	t.Parallel()
	var out, errBuf bytes.Buffer
	if code := run([]string{"--version"}, &out, &errBuf); code != exitOK {
		t.Fatalf("run(--version) = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "hulld ") || !strings.Contains(out.String(), "api ") {
		t.Errorf("--version printed %q", out.String())
	}
}

func TestRunRejectsABadCommandLine(t *testing.T) {
	t.Parallel()
	tests := [][]string{
		{"--not-a-flag"},
		{"--log-level", "shouty", "--socket", "none"},
		{"--socket", "none", "--shared-socket", "none"},
		{"--socket", "none", "--tcp", "127.0.0.1:2375"},
		{"serve"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != exitUsage {
				t.Errorf("run(%v) = %d, want %d", args, code, exitUsage)
			}
		})
	}
}

func TestRunHelpIsNotAnError(t *testing.T) {
	t.Parallel()
	var out, errBuf bytes.Buffer
	if code := run([]string{"-h"}, &out, &errBuf); code != exitOK {
		t.Errorf("run(-h) = %d, want 0", code)
	}
	if !strings.Contains(errBuf.String(), "hulld") {
		t.Errorf("-h printed no usage: %q", errBuf.String())
	}
}

func TestShutdownSignalsAreNotEmpty(t *testing.T) {
	t.Parallel()
	if len(shutdownSignals()) == 0 {
		t.Fatal("no shutdown signal is watched, so the daemon could never drain")
	}
}

// mustBeTrue fails the test when cond is false, naming the field.
func mustBeTrue(t *testing.T, cond bool, what string) {
	t.Helper()
	if !cond {
		t.Errorf("%s = false, want true", what)
	}
}
