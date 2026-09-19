package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Exit codes, which follow Docker's so scripts that branch on them keep
// working.
const (
	// ExitOK is success.
	ExitOK = 0
	// ExitFailure is a hull-level failure: a bad flag, an unreachable
	// engine, a refused request. Docker uses 125 for exactly this, so a
	// script can still tell hull's own failure from the container's.
	ExitFailure = 125
	// ExitCannotInvoke means the container's command was found but could not
	// be run.
	ExitCannotInvoke = 126
	// ExitNotFound means the container's command was not found.
	ExitNotFound = 127
)

// ExitError carries a specific process exit status out of a command. Anything
// else that fails exits with ExitFailure.
type ExitError struct {
	// Code is the status to exit with.
	Code int
	// Err is the underlying failure; nil means exit quietly.
	Err error
}

// Error implements the error interface.
func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit status %d", e.Code)
	}
	return e.Err.Error()
}

// Unwrap exposes the underlying failure.
func (e *ExitError) Unwrap() error { return e.Err }

// Exit builds an ExitError with no message, for a command that has already
// said everything it has to say.
func Exit(code int) error { return &ExitError{Code: code} }

// Errorf builds a plain command failure, which the top level turns into exit
// status 125.
func Errorf(format string, args ...any) error { return fmt.Errorf(format, args...) }

// ExitCodeOf reports the process exit status an error should produce.
func ExitCodeOf(err error) int {
	if err == nil {
		return ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return ExitFailure
}

// Command is one node of the command tree. A node with subcommands and no Run
// dispatches; a node with Run is a leaf.
type Command struct {
	// Name is the word the user types.
	Name string
	// Aliases are alternative spellings, such as "rm" for "remove".
	Aliases []string
	// Usage is the argument summary shown in help, without the "hull "
	// prefix, e.g. "run [OPTIONS] IMAGE [COMMAND] [ARG...]".
	Usage string
	// Short is the one-line description shown in the parent's listing.
	Short string
	// Long is the extended description shown in this command's own help.
	Long string
	// Example is a block of example invocations.
	Example string
	// Hidden keeps the command out of help listings, for the internal verbs.
	Hidden bool
	// StopAtOperand ends flag parsing at the first non-flag argument, which
	// commands that pass a command line through to a container need.
	StopAtOperand bool
	// MinArgs and MaxArgs bound the operand count. MaxArgs -1 means no upper
	// bound; both zero means the command takes no operands.
	MinArgs int
	MaxArgs int
	// Flags registers this command's flags.
	Flags func(fs *FlagSet)
	// Run executes the command.
	Run func(ctx context.Context, env *Env, fs *FlagSet, args []string) error
	// Subcommands are the children of a dispatching node.
	Subcommands []*Command

	// parent is filled in during traversal so help can print the full path.
	parent *Command
}

// matches reports whether name selects this command.
func (c *Command) matches(name string) bool {
	if c.Name == name {
		return true
	}
	for _, a := range c.Aliases {
		if a == name {
			return true
		}
	}
	return false
}

// Path returns the full command path, e.g. "hull volume ls".
func (c *Command) Path() string {
	if c.parent == nil {
		return c.Name
	}
	return c.parent.Path() + " " + c.Name
}

// lookup finds a subcommand by name or alias.
func (c *Command) lookup(name string) *Command {
	for _, sub := range c.Subcommands {
		if sub.matches(name) {
			sub.parent = c
			return sub
		}
	}
	return nil
}

// Execute walks the tree from root, parses flags and runs the selected
// command. It returns the error the command produced; the caller maps it to an
// exit status with [ExitCodeOf].
func Execute(ctx context.Context, env *Env, root *Command, args []string) error {
	cmd := root
	for len(args) > 0 && len(cmd.Subcommands) > 0 {
		next := cmd.lookup(args[0])
		if next == nil {
			break
		}
		cmd, args = next, args[1:]
	}
	fs := NewFlagSet(cmd.Path())
	fs.SetOutput(env.Err)
	fs.StopAtOperand(cmd.StopAtOperand)
	if cmd.Flags != nil {
		cmd.Flags(fs)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, ErrHelp) {
			return WriteHelp(env.Out, cmd, fs)
		}
		return &ExitError{Code: ExitFailure, Err: fmt.Errorf("%s: %w\nSee '%s --help'", cmd.Path(), err, cmd.Path())}
	}
	operands := fs.Args()
	if cmd.Run == nil {
		if len(operands) > 0 {
			return &ExitError{Code: ExitFailure, Err: fmt.Errorf("%q is not a %s command\nSee '%s --help'", operands[0], cmd.Path(), cmd.Path())}
		}
		return WriteHelp(env.Out, cmd, fs)
	}
	if err := checkArgs(cmd, operands); err != nil {
		return &ExitError{Code: ExitFailure, Err: err}
	}
	return cmd.Run(ctx, env, fs, operands)
}

// checkArgs enforces MinArgs and MaxArgs.
func checkArgs(cmd *Command, args []string) error {
	if len(args) < cmd.MinArgs {
		return fmt.Errorf("%q requires at least %s\nUsage:  %s",
			cmd.Path(), plural(cmd.MinArgs, "argument"), cmd.UsageLine())
	}
	if cmd.MaxArgs >= 0 && len(args) > cmd.MaxArgs {
		return fmt.Errorf("%q accepts at most %s\nUsage:  %s",
			cmd.Path(), plural(cmd.MaxArgs, "argument"), cmd.UsageLine())
	}
	return nil
}

// UsageLine renders the full invocation line, e.g. "hull volume ls [OPTIONS]".
//
// Usage is written starting with the command's own name — "run [OPTIONS]
// IMAGE" — so that a command reads the way it is typed when it is declared.
// The name is therefore dropped here before the parent path is prepended, or
// every nested command would print its own name twice.
func (c *Command) UsageLine() string {
	usage := c.Usage
	if usage == "" {
		if len(c.Subcommands) > 0 {
			usage = "COMMAND"
		} else {
			usage = "[OPTIONS]"
		}
		return c.Path() + " " + usage
	}
	if usage == c.Name {
		return c.Path()
	}
	if strings.HasPrefix(usage, c.Name+" ") {
		return c.Path() + usage[len(c.Name):]
	}
	return c.Path() + " " + usage
}

// plural renders "1 argument" or "3 arguments".
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// WriteHelp renders one command's help page.
func WriteHelp(w io.Writer, cmd *Command, fs *FlagSet) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage:  %s\n", cmd.UsageLine())
	if cmd.Long != "" {
		fmt.Fprintf(&b, "\n%s\n", strings.TrimRight(cmd.Long, "\n"))
	} else if cmd.Short != "" {
		fmt.Fprintf(&b, "\n%s\n", cmd.Short)
	}
	if len(cmd.Subcommands) > 0 {
		visible := make([]*Command, 0, len(cmd.Subcommands))
		for _, sub := range cmd.Subcommands {
			if !sub.Hidden {
				visible = append(visible, sub)
			}
		}
		sort.SliceStable(visible, func(i, j int) bool { return visible[i].Name < visible[j].Name })
		width := 0
		for _, sub := range visible {
			if len(sub.Name) > width {
				width = len(sub.Name)
			}
		}
		b.WriteString("\nCommands:\n")
		for _, sub := range visible {
			fmt.Fprintf(&b, "  %s%s   %s\n", sub.Name, strings.Repeat(" ", width-len(sub.Name)), sub.Short)
		}
	}
	if fs != nil {
		if flags := fs.FlagUsage(); flags != "" {
			b.WriteString("\nOptions:\n")
			b.WriteString(flags)
		}
	}
	if cmd.Example != "" {
		fmt.Fprintf(&b, "\nExamples:\n%s\n", strings.TrimRight(cmd.Example, "\n"))
	}
	if len(cmd.Subcommands) > 0 {
		fmt.Fprintf(&b, "\nRun '%s COMMAND --help' for more information on a command.\n", cmd.Path())
	}
	_, err := io.WriteString(w, b.String())
	return err
}
