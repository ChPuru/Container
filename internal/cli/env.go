package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/rahuldhali/hull/internal/client"
)

// Env is everything a command needs that is not its own arguments: the three
// standard streams, what the terminal can do, and a lazily built engine
// client.
//
// Output discipline lives here. When stdout is not a terminal — a pipe into
// jq, a redirect into a file, a CI log — colour, spinners and progress bars
// are dropped entirely, because a script must never have to strip escape
// codes out of hull's output.
type Env struct {
	// In, Out and Err are the process streams. They are files rather than
	// plain readers so terminal size and raw mode are reachable.
	In  *os.File
	Out *os.File
	Err *os.File

	// Host overrides the engine address for this invocation, from --host.
	Host string
	// APIVersion pins the Docker API version, from $HULL_API_VERSION.
	APIVersion string
	// LogLevel is the --log-level setting, used by the debug narration.
	LogLevel string
	// Debug turns on hull's own diagnostic output.
	Debug bool

	// stdoutTTY, stderrTTY and stdinTTY are probed once at construction.
	stdoutTTY bool
	stderrTTY bool
	stdinTTY  bool
	// color is whether ANSI colour is allowed on stdout.
	color bool

	once sync.Once
	cli  *client.Client
	err  error

	// newClient builds the engine client. Tests replace it.
	newClient func(opts client.Options) (*client.Client, error)
}

// NewEnv builds an Env around the given streams, probing each for a terminal.
//
// $NO_COLOR disables colour even on a terminal, and $HULL_FORCE_COLOR enables
// it even off one, which is what a CI job that renders ANSI wants.
func NewEnv(in, out, errw *os.File) *Env {
	e := &Env{In: in, Out: out, Err: errw, newClient: client.New}
	e.stdinTTY = isTerminal(in)
	e.stdoutTTY = isTerminal(out)
	e.stderrTTY = isTerminal(errw)
	e.color = e.stdoutTTY
	if _, off := os.LookupEnv("NO_COLOR"); off {
		e.color = false
	}
	if v := os.Getenv("HULL_FORCE_COLOR"); v != "" && v != "0" {
		e.color = true
	}
	return e
}

// StdinIsTerminal reports whether input comes from a terminal.
func (e *Env) StdinIsTerminal() bool { return e.stdinTTY }

// StdoutIsTerminal reports whether output goes to a terminal.
func (e *Env) StdoutIsTerminal() bool { return e.stdoutTTY }

// StderrIsTerminal reports whether the error stream is a terminal.
func (e *Env) StderrIsTerminal() bool { return e.stderrTTY }

// Color reports whether ANSI colour should be emitted on stdout.
func (e *Env) Color() bool { return e.color }

// SetColor overrides colour detection, for --no-color and for tests.
func (e *Env) SetColor(on bool) { e.color = on }

// Width returns the terminal width, or a sane default when stdout is not a
// terminal. A listing sizes its columns against this.
func (e *Env) Width() int {
	if !e.stdoutTTY {
		return 0
	}
	w, _, err := terminalSize(e.Out)
	if err != nil || w <= 0 {
		return 0
	}
	return w
}

// Client returns the engine client, building it on first use and negotiating
// the API version down to whatever this engine actually serves.
//
// Negotiation happens here rather than in every command because it is a ping,
// and a ping that fails is not itself an error: the request that follows will
// report the real problem with a better message than a ping ever could.
func (e *Env) Client(ctx context.Context) (*client.Client, error) {
	e.once.Do(func() {
		e.cli, e.err = e.newClient(client.Options{
			Host:    e.Host,
			Version: e.APIVersion,
		})
		if e.err == nil && e.cli != nil {
			e.cli.NegotiateAPIVersion(ctx)
		}
	})
	return e.cli, e.err
}

// SetClientFactory replaces the client constructor, which is how tests point
// the CLI at an httptest server.
func (e *Env) SetClientFactory(fn func(opts client.Options) (*client.Client, error)) {
	e.newClient = fn
}

// Printf writes to stdout.
func (e *Env) Printf(format string, args ...any) {
	fmt.Fprintf(e.Out, format, args...)
}

// Println writes one line to stdout.
func (e *Env) Println(args ...any) {
	fmt.Fprintln(e.Out, args...)
}

// Warnf writes a warning to stderr, prefixed the way every hull diagnostic is.
//
// This is where the engine's bundle warnings surface. A resource limit that
// the host cannot enforce is reported rather than failing the container, so if
// this line does not reach the user they silently get an unlimited container.
func (e *Env) Warnf(format string, args ...any) {
	msg := strings.TrimRight(fmt.Sprintf(format, args...), "\n")
	if e.color && e.stderrTTY {
		fmt.Fprintf(e.Err, "\x1b[33mhull: warning:\x1b[0m %s\n", msg)
		return
	}
	fmt.Fprintf(e.Err, "hull: warning: %s\n", msg)
}

// ShowWarnings prints every engine warning, one line each. It is called after
// create, start and update.
func (e *Env) ShowWarnings(warnings []string) {
	for _, w := range warnings {
		if strings.TrimSpace(w) == "" {
			continue
		}
		e.Warnf("%s", w)
	}
}

// Debugf writes a diagnostic line when --log-level debug is in effect.
func (e *Env) Debugf(format string, args ...any) {
	if !e.Debug {
		return
	}
	fmt.Fprintf(e.Err, "hull: debug: %s\n", strings.TrimRight(fmt.Sprintf(format, args...), "\n"))
}

// ReportError prints a command failure on stderr and returns the process exit
// status for it. Every hull diagnostic is prefixed "hull: " so it is
// distinguishable from a container's own output on a shared terminal.
func (e *Env) ReportError(err error) int {
	if err == nil {
		return ExitOK
	}
	code := ExitCodeOf(err)
	var ee *ExitError
	if errors.As(err, &ee) && ee.Err == nil {
		return code
	}
	msg := hintFor(err, e.Host)
	if e.color && e.stderrTTY {
		fmt.Fprintf(e.Err, "\x1b[31mhull:\x1b[0m %s\n", msg)
	} else {
		fmt.Fprintf(e.Err, "hull: %s\n", msg)
	}
	return code
}

// hintFor turns a raw failure into something the user can act on. An engine
// that is not running is by far the most common first failure, and "connection
// refused" alone tells nobody what to do about it.
func hintFor(err error, host string) string {
	msg := err.Error()
	if client.IsConnectionFailed(err) {
		where := host
		if where == "" {
			where = client.DefaultHost()
		}
		return msg + "\n" +
			"       Is the hull engine running? Start it with 'hull engine start'.\n" +
			"       hull is trying " + where + "; override it with --host or $HULL_HOST."
	}
	if client.IsNotImplemented(err) {
		return msg
	}
	return msg
}

// ansi wraps s in an ANSI code when colour is enabled.
func (e *Env) ansi(code, s string) string {
	if !e.color || s == "" {
		return s
	}
	return code + s + "\x1b[0m"
}

// Bold renders s in bold when colour is enabled.
func (e *Env) Bold(s string) string { return e.ansi("\x1b[1m", s) }

// Green renders s in green when colour is enabled.
func (e *Env) Green(s string) string { return e.ansi("\x1b[32m", s) }

// Yellow renders s in yellow when colour is enabled.
func (e *Env) Yellow(s string) string { return e.ansi("\x1b[33m", s) }

// Red renders s in red when colour is enabled.
func (e *Env) Red(s string) string { return e.ansi("\x1b[31m", s) }

// Dim renders s dimmed when colour is enabled.
func (e *Env) Dim(s string) string { return e.ansi("\x1b[2m", s) }

// newTable starts a listing table already sized to this terminal.
func (e *Env) newTable(headers ...string) *Table {
	t := NewTable(headers...)
	t.Width = e.Width()
	return t
}

// renderList prints a listing in whichever of the four shapes the user asked
// for: bare ids with -q, a JSON array with --format json, a Go template with
// any other --format, or the default aligned table.
//
// rows and items must be parallel: rows is what the table prints, items is
// what a template or JSON sees.
func (e *Env) renderList(quiet bool, format string, ids []string, items []any, table *Table) error {
	switch {
	case quiet:
		for _, id := range ids {
			fmt.Fprintln(e.Out, id)
		}
		return nil
	case format == FormatJSON:
		if items == nil {
			items = []any{}
		}
		return WriteJSON(e.Out, items)
	case format != "":
		t, err := NewTemplate(format)
		if err != nil {
			return err
		}
		return RenderTemplate(e.Out, t, items)
	default:
		return table.Render(e.Out)
	}
}

// discard is an io.Writer that throws everything away, used when a stream is
// deselected.
var discard io.Writer = io.Discard
