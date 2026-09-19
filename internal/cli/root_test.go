package cli

import (
	"context"
	"strings"
	"testing"
)

// TestDocumentedSubcommandsExist checks the nested verbs docs/CLI.md promises.
//
// The top-level names are checked elsewhere; what is easy to get wrong, and
// invisible until someone types it, is a group whose own subcommands are
// missing — "hull volume ls" is a different promise from "hull volume".
func TestDocumentedSubcommandsExist(t *testing.T) {
	documented := [][]string{
		{"image", "inspect"},
		{"network", "create"}, {"network", "ls"}, {"network", "inspect"},
		{"network", "rm"}, {"network", "connect"}, {"network", "disconnect"},
		{"network", "prune"},
		{"volume", "create"}, {"volume", "ls"}, {"volume", "inspect"},
		{"volume", "rm"}, {"volume", "prune"},
		{"snapshot", "ls"}, {"snapshot", "diff"},
		{"engine", "status"}, {"engine", "start"}, {"engine", "stop"},
		{"engine", "restart"}, {"engine", "logs"}, {"engine", "gc"},
	}
	root := NewRootCommand()
	for _, path := range documented {
		cmd := root
		ok := true
		for _, name := range path {
			next := cmd.lookup(name)
			if next == nil {
				t.Errorf("docs/CLI.md documents %q, which the tree does not have", strings.Join(path, " "))
				ok = false
				break
			}
			cmd = next
		}
		if ok && cmd.Run == nil && len(cmd.Subcommands) == 0 {
			t.Errorf("%q resolves to a command that does nothing", strings.Join(path, " "))
		}
	}
}

// TestEveryCommandRendersHelp walks the tree and renders help for every node,
// which is also the only cheap way to catch a duplicate flag registration: the
// flag set panics on one, and a panic inside --help is the worst possible
// moment for it.
func TestEveryCommandRendersHelp(t *testing.T) {
	var walk func(path string, c *Command)
	walk = func(path string, c *Command) {
		full := strings.TrimSpace(path + " " + c.Name)
		fs := NewFlagSet(full)
		if c.Flags != nil {
			c.Flags(fs)
		}
		var out strings.Builder
		if err := WriteHelp(&out, c, fs); err != nil {
			t.Errorf("%s: WriteHelp: %v", full, err)
			return
		}
		if !strings.Contains(out.String(), "Usage:") {
			t.Errorf("%s: help has no usage line:\n%s", full, out.String())
		}
		for _, sub := range c.Subcommands {
			walk(full, sub)
		}
	}
	walk("", NewRootCommand())
}

// TestDockerCompatOutputNamesTheAddress checks what the command actually
// prints, not just that the help mentions it: the value has to be one the user
// can paste, and it has to follow --host rather than always naming the
// platform default.
func TestDockerCompatOutputNamesTheAddress(t *testing.T) {
	env, out, _ := testEnv(t)
	env.Host = "npipe:////./pipe/hull_engine"
	if err := Execute(context.Background(), env, NewRootCommand(), []string{"docker-compat"}); err != nil {
		t.Fatalf("hull docker-compat: %v", err)
	}
	body := readFile(t, out)
	for _, want := range []string{"DOCKER_HOST", "npipe:////./pipe/hull_engine", "HULL_HOST"} {
		if !strings.Contains(body, want) {
			t.Errorf("docker-compat output is missing %q:\n%s", want, body)
		}
	}
}

// TestRunReportsAnUnknownCommand checks the first thing a mistyped verb does:
// name what was typed, point at help, and exit with hull's own status rather
// than a container's.
func TestRunReportsAnUnknownCommand(t *testing.T) {
	env, _, errOut := testEnv(t)
	err := Run(context.Background(), env, []string{"pss"})
	if err == nil {
		t.Fatal("an unknown command = nil error")
	}
	if code := env.ReportError(err); code != ExitFailure {
		t.Errorf("exit code = %d, want %d", code, ExitFailure)
	}
	body := readFile(t, errOut)
	if !strings.Contains(body, "pss") {
		t.Errorf("the message does not name the typo:\n%s", body)
	}
}
