package cli

import (
	"strings"
	"testing"
)

// TestParseGlobalFlags covers the options that appear before the subcommand.
// They are parsed by hand rather than by a FlagSet, so every spelling a user
// might reach for needs a case here.
func TestParseGlobalFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		want     Global
		wantRest []string
		wantErr  bool
	}{
		{
			name:     "no flags",
			args:     []string{"ps", "-a"},
			wantRest: []string{"ps", "-a"},
		},
		{
			name:     "long host with separate value",
			args:     []string{"--host", "tcp://127.0.0.1:2375", "ps"},
			want:     Global{Host: "tcp://127.0.0.1:2375"},
			wantRest: []string{"ps"},
		},
		{
			name:     "long host with equals",
			args:     []string{"--host=unix:///tmp/hull.sock", "ps"},
			want:     Global{Host: "unix:///tmp/hull.sock"},
			wantRest: []string{"ps"},
		},
		{
			name:     "short host with separate value",
			args:     []string{"-H", "npipe:////./pipe/hull_engine", "images"},
			want:     Global{Host: `npipe:////./pipe/hull_engine`},
			wantRest: []string{"images"},
		},
		{
			name:     "short host attached",
			args:     []string{"-Htcp://[::1]:2375", "ps"},
			want:     Global{Host: "tcp://[::1]:2375"},
			wantRest: []string{"ps"},
		},
		{
			name:     "log level",
			args:     []string{"--log-level", "debug", "ps"},
			want:     Global{LogLevel: "debug"},
			wantRest: []string{"ps"},
		},
		{
			name:     "debug shorthand",
			args:     []string{"-D", "ps"},
			want:     Global{Debug: true},
			wantRest: []string{"ps"},
		},
		{
			name: "version",
			args: []string{"--version"},
			want: Global{Version: true},
		},
		{
			name: "short version",
			args: []string{"-v"},
			want: Global{Version: true},
		},
		{
			name:     "clustered global booleans",
			args:     []string{"-Dv", "ps"},
			want:     Global{Debug: true, Version: true},
			wantRest: []string{"ps"},
		},
		{
			name:     "double dash ends global parsing",
			args:     []string{"--", "--host", "x"},
			wantRest: []string{"--host", "x"},
		},
		{
			name:     "unknown flag belongs to the command",
			args:     []string{"--rm", "alpine"},
			wantRest: []string{"--rm", "alpine"},
		},
		{
			name:     "host wins over a later command flag of the same name",
			args:     []string{"-H", "tcp://a:1", "run", "--host", "b"},
			want:     Global{Host: "tcp://a:1"},
			wantRest: []string{"run", "--host", "b"},
		},
		{
			name:    "host with no value",
			args:    []string{"--host"},
			wantErr: true,
		},
		{
			name:    "short host with no value",
			args:    []string{"-H"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, rest, err := ParseGlobal(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseGlobal(%q) = %+v, want an error", tt.args, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseGlobal(%q): %v", tt.args, err)
			}
			if got != tt.want {
				t.Errorf("ParseGlobal(%q) options = %+v, want %+v", tt.args, got, tt.want)
			}
			if strings.Join(rest, " ") != strings.Join(tt.wantRest, " ") {
				t.Errorf("ParseGlobal(%q) rest = %q, want %q", tt.args, rest, tt.wantRest)
			}
		})
	}
}

// TestApplyGlobalSetsDebug checks that --log-level debug turns on hull's own
// diagnostics, which is the only way Debugf output ever appears.
func TestApplyGlobalSetsDebug(t *testing.T) {
	env := NewEnv(nil, nil, nil)
	env.Apply(Global{LogLevel: "debug"})
	if !env.Debug {
		t.Fatalf("--log-level debug did not enable debug output")
	}
	if env.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q, want debug", env.LogLevel)
	}

	env2 := NewEnv(nil, nil, nil)
	env2.Apply(Global{Debug: true})
	if !env2.Debug || env2.LogLevel != "debug" {
		t.Fatalf("-D did not imply --log-level debug: %+v", env2)
	}
}

// TestRootTreeIsWellFormed walks the command tree and checks the invariants a
// broken node would only reveal at run time: no duplicate names among
// siblings, every leaf able to run, and every node carrying help text.
func TestRootTreeIsWellFormed(t *testing.T) {
	var walk func(cmd *Command, path string)
	walk = func(cmd *Command, path string) {
		seen := map[string]string{}
		for _, sub := range cmd.Subcommands {
			for _, name := range append([]string{sub.Name}, sub.Aliases...) {
				if prev, dup := seen[name]; dup {
					t.Errorf("%s has two subcommands called %q (%s and %s)", path, name, prev, sub.Name)
				}
				seen[name] = sub.Name
			}
			if sub.Short == "" {
				t.Errorf("%s %s has no Short description", path, sub.Name)
			}
			if sub.Run == nil && len(sub.Subcommands) == 0 {
				t.Errorf("%s %s can neither run nor dispatch", path, sub.Name)
			}
			if sub.Run != nil && sub.MaxArgs < -1 {
				t.Errorf("%s %s has a nonsensical MaxArgs %d", path, sub.Name, sub.MaxArgs)
			}
			walk(sub, path+" "+sub.Name)
		}
	}
	root := NewRootCommand()
	walk(root, "hull")

	// Every command docs/CLI.md promises has to be reachable.
	required := []string{
		"run", "create", "start", "stop", "restart", "kill", "pause", "unpause",
		"rm", "ps", "inspect", "logs", "exec", "attach", "top", "stats", "port",
		"rename", "update", "wait", "cp", "diff", "commit", "export", "prune",
		"pull", "push", "images", "rmi", "tag", "save", "load", "login",
		"logout", "history", "build", "network", "volume", "doctor", "ui",
		"events", "snapshot", "revert", "branch", "lock", "sync", "debug",
		"engine", "version", "info", "docker-compat",
	}
	for _, name := range required {
		if root.lookup(name) == nil {
			t.Errorf("docs/CLI.md promises %q but the tree has no such command", name)
		}
	}
}

// TestDockerCompatMentionsDockerHost checks the one piece of help a user
// coming from Docker needs first.
func TestDockerCompatMentionsDockerHost(t *testing.T) {
	var out strings.Builder
	root := NewRootCommand()
	fs := NewFlagSet("hull")
	registerGlobalFlags(fs)
	if err := WriteHelp(&out, root, fs); err != nil {
		t.Fatalf("WriteHelp: %v", err)
	}
	help := out.String()
	if !strings.Contains(help, "docker-compat") {
		t.Errorf("the top-level help never mentions 'hull docker-compat':\n%s", help)
	}
	if !strings.Contains(help, "DOCKER_HOST") {
		t.Errorf("the top-level help never mentions DOCKER_HOST:\n%s", help)
	}
	for _, flag := range []string{"--host", "--log-level", "--version"} {
		if !strings.Contains(help, flag) {
			t.Errorf("the top-level help does not document %s:\n%s", flag, help)
		}
	}
}
