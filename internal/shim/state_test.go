package shim

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExitStatusRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := ExitPath(dir)

	tests := []struct {
		name string
		st   ExitStatus
	}{
		{"clean exit", ExitStatus{ExitCode: 0, FinishedAt: time.Unix(1700000000, 0).UTC()}},
		{"failure", ExitStatus{ExitCode: 1, FinishedAt: time.Unix(1700000001, 0).UTC()}},
		{"sigkill", ExitStatus{ExitCode: 137, FinishedAt: time.Unix(1700000002, 0).UTC()}},
		{"oom", ExitStatus{ExitCode: 137, OOMKilled: true, FinishedAt: time.Unix(1700000003, 0).UTC()}},
		{"never started", ExitStatus{ExitCode: 127, Error: "crun create failed: no such file", FinishedAt: time.Unix(1700000004, 0).UTC()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := WriteExitStatus(path, tt.st); err != nil {
				t.Fatalf("WriteExitStatus: %v", err)
			}
			got, err := ReadExitStatus(path)
			if err != nil {
				t.Fatalf("ReadExitStatus: %v", err)
			}
			if got.ExitCode != tt.st.ExitCode || got.OOMKilled != tt.st.OOMKilled || got.Error != tt.st.Error {
				t.Fatalf("read back %+v, want %+v", got, tt.st)
			}
			if !got.FinishedAt.Equal(tt.st.FinishedAt) {
				t.Fatalf("FinishedAt = %v, want %v", got.FinishedAt, tt.st.FinishedAt)
			}
		})
	}
}

// TestExitStatusIsWrittenAtomically checks the property the whole shim exists
// for: a reader either sees the previous status or the complete new one, and
// never a half-written file. It also checks that a crashed write leaves no
// debris that a later reader could mistake for the real thing.
func TestExitStatusIsWrittenAtomically(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := ExitPath(dir)

	if err := WriteExitStatus(path, ExitStatus{ExitCode: 1, FinishedAt: time.Now()}); err != nil {
		t.Fatalf("WriteExitStatus: %v", err)
	}
	// Rewrite it many times while reading; every read must parse.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			if err := WriteExitStatus(path, ExitStatus{ExitCode: i % 256, FinishedAt: time.Now()}); err != nil {
				t.Errorf("WriteExitStatus: %v", err)
				return
			}
		}
	}()
	for i := 0; i < 500; i++ {
		var st ExitStatus
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read exit.json: %v", err)
		}
		if err := json.Unmarshal(data, &st); err != nil {
			t.Fatalf("exit.json was observed half-written: %v (%q)", err, data)
		}
	}
	<-done

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != ExitName {
			t.Errorf("atomic writes left debris behind: %s", e.Name())
		}
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("exit.json is not there: %v", err)
	}
	st, err := ReadExitStatus(path)
	if err != nil {
		t.Fatalf("ReadExitStatus: %v", err)
	}
	if st.ExitCode != 199%256 {
		t.Fatalf("final exit code = %d, want the last one written", st.ExitCode)
	}
}

func TestExitStatusMissingFile(t *testing.T) {
	t.Parallel()
	_, err := ReadExitStatus(ExitPath(t.TempDir()))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want one wrapping fs.ErrNotExist", err)
	}
}

func TestExitStatusPermissions(t *testing.T) {
	t.Parallel()
	path := ExitPath(t.TempDir())
	if err := WriteExitStatus(path, ExitStatus{}); err != nil {
		t.Fatalf("WriteExitStatus: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("exit.json mode = %o, want 600: it names the container's fate", perm)
	}
}

func TestShimStateRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := StatePath(dir)
	want := ShimState{
		Pid:          4242,
		StartTime:    998877,
		Socket:       SocketPath(dir),
		ContainerID:  "7f3ab2",
		ContainerPid: 4243,
		CreatedAt:    time.Unix(1700000000, 0).UTC(),
	}
	if err := WriteShimState(path, want); err != nil {
		t.Fatalf("WriteShimState: %v", err)
	}
	got, err := ReadShimState(path)
	if err != nil {
		t.Fatalf("ReadShimState: %v", err)
	}
	if got.Pid != want.Pid || got.StartTime != want.StartTime || got.Socket != want.Socket ||
		got.ContainerID != want.ContainerID || got.ContainerPid != want.ContainerPid {
		t.Fatalf("read back %+v, want %+v", got, want)
	}
	if got.Version != ShimStateVersion {
		t.Fatalf("Version = %d, want %d to be stamped on write", got.Version, ShimStateVersion)
	}
}

func TestShimStateRejectsANewerFormat(t *testing.T) {
	t.Parallel()
	path := StatePath(t.TempDir())
	data, err := json.Marshal(ShimState{Pid: 1, Version: ShimStateVersion + 1})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ReadShimState(path); err == nil || !strings.Contains(err.Error(), "newer hull") {
		t.Fatalf("err = %v, want a refusal to read a newer format", err)
	}
}

func TestPathHelpers(t *testing.T) {
	t.Parallel()
	dir := filepath.Join("/var", "lib", "hull", "containers", "abc")
	cfg := Config{ContainerDir: dir}
	tests := []struct {
		got  string
		want string
	}{
		{cfg.SocketPath(), filepath.Join(dir, SocketName)},
		{cfg.StatePath(), filepath.Join(dir, StateName)},
		{cfg.ExitPath(), filepath.Join(dir, ExitName)},
		{cfg.ConsolePath(), filepath.Join(dir, ConsoleName)},
		{cfg.PidPath(), filepath.Join(dir, PidFileName)},
		{cfg.ShimLogPath(), filepath.Join(dir, ShimLogName)},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("path = %q, want %q", tt.got, tt.want)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	good := Config{
		ID:            "abc123",
		BundleDir:     "/var/lib/hull/containers/abc123",
		ContainerDir:  "/var/lib/hull/containers/abc123",
		RuntimeBinary: "/usr/bin/crun",
		RuntimeName:   "crun",
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("a well-formed config was rejected: %v", err)
	}

	tests := []struct {
		name  string
		mutp  func(*Config)
		wants string
	}{
		{"no id", func(c *Config) { c.ID = "" }, "no container id"},
		{"no bundle", func(c *Config) { c.BundleDir = "" }, "no bundle directory"},
		{"relative bundle", func(c *Config) { c.BundleDir = "bundle" }, "must be absolute"},
		{"no container dir", func(c *Config) { c.ContainerDir = "" }, "no container directory"},
		{"relative container dir", func(c *Config) { c.ContainerDir = "./x" }, "must be absolute"},
		{"no runtime", func(c *Config) { c.RuntimeBinary = "" }, "names no runtime binary"},
		{"relative runtime", func(c *Config) { c.RuntimeBinary = "crun" }, "must be absolute"},
		{"relative log", func(c *Config) { c.LogPath = "log.json" }, "must be absolute"},
		{"relative cgroup", func(c *Config) { c.CgroupPath = "hull/abc" }, "must be absolute"},
		{"socket path too long", func(c *Config) { c.ContainerDir = "/" + strings.Repeat("d", 120) }, "sockaddr_un limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := good
			tt.mutp(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected an error containing %q", tt.wants)
			}
			if !strings.Contains(err.Error(), tt.wants) {
				t.Fatalf("error %q does not contain %q", err, tt.wants)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	t.Parallel()
	var cfg Config
	if got := cfg.stopTimeout(); got != DefaultStopTimeout {
		t.Errorf("stopTimeout = %v, want %v", got, DefaultStopTimeout)
	}
	if got := cfg.exitGrace(); got != DefaultExitGrace {
		t.Errorf("exitGrace = %v, want %v", got, DefaultExitGrace)
	}
	cfg.StopTimeout = time.Second
	cfg.ExitGrace = time.Minute
	if got := cfg.stopTimeout(); got != time.Second {
		t.Errorf("stopTimeout = %v, want 1s", got)
	}
	if got := cfg.exitGrace(); got != time.Minute {
		t.Errorf("exitGrace = %v, want 1m", got)
	}
}
