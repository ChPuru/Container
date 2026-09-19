package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/client"
)

// TestFlagSetParseTable exercises every spelling the CLI promises to accept:
// long and short, attached and detached values, clustered short booleans,
// repeated flags and "--" to end parsing.
func TestFlagSetParseTable(t *testing.T) {
	type result struct {
		interactive bool
		tty         bool
		detach      bool
		name        string
		env         []string
		count       int
		operands    []string
	}
	build := func(stopAtOperand bool) (*FlagSet, *result) {
		r := &result{}
		fs := NewFlagSet("test")
		fs.StopAtOperand(stopAtOperand)
		fs.BoolVar(&r.interactive, "interactive", "i", false, "stdin")
		fs.BoolVar(&r.tty, "tty", "t", false, "tty")
		fs.BoolVar(&r.detach, "detach", "d", false, "detach")
		fs.StringVar(&r.name, "name", "n", "", "name")
		fs.StringSliceVar(&r.env, "env", "e", "env")
		fs.IntVar(&r.count, "count", "c", 0, "count")
		return fs, r
	}

	tests := []struct {
		name          string
		args          []string
		stopAtOperand bool
		want          result
	}{
		{
			name: "clustered short booleans",
			args: []string{"-it", "alpine"},
			want: result{interactive: true, tty: true, operands: []string{"alpine"}},
		},
		{
			name: "cluster ending in a value flag takes the next word",
			args: []string{"-itn", "web", "alpine"},
			want: result{interactive: true, tty: true, name: "web", operands: []string{"alpine"}},
		},
		{
			name: "cluster with an attached value",
			args: []string{"-itnweb"},
			want: result{interactive: true, tty: true, name: "web"},
		},
		{
			name: "short flag with an attached equals value",
			args: []string{"-n=web"},
			want: result{name: "web"},
		},
		{
			name: "long flag with an equals value",
			args: []string{"--name=web"},
			want: result{name: "web"},
		},
		{
			name: "long flag with a separate value",
			args: []string{"--name", "web"},
			want: result{name: "web"},
		},
		{
			name: "repeated short flag accumulates",
			args: []string{"-e", "A=1", "-e", "B=2"},
			want: result{env: []string{"A=1", "B=2"}},
		},
		{
			name: "repeated long flag accumulates, mixed spellings",
			args: []string{"--env=A=1", "--env", "B=2", "-eC=3"},
			want: result{env: []string{"A=1", "B=2", "C=3"}},
		},
		{
			name: "double dash ends flag parsing",
			args: []string{"-i", "--", "-t", "--name", "x"},
			want: result{interactive: true, operands: []string{"-t", "--name", "x"}},
		},
		{
			name: "explicit negation of a clustered boolean",
			args: []string{"-d=false", "-i"},
			want: result{detach: false, interactive: true},
		},
		{
			name: "a lone dash is an operand, not a flag",
			args: []string{"-i", "-"},
			want: result{interactive: true, operands: []string{"-"}},
		},
		{
			name: "integer flag",
			args: []string{"--count", "7", "x"},
			want: result{count: 7, operands: []string{"x"}},
		},
		{
			name:          "stop at operand leaves the container's own flags alone",
			args:          []string{"-it", "alpine", "sh", "-c", "echo hi"},
			stopAtOperand: true,
			want: result{
				interactive: true, tty: true,
				operands: []string{"alpine", "sh", "-c", "echo hi"},
			},
		},
		{
			name:          "without stop-at-operand a later flag is still hull's",
			args:          []string{"alpine", "-i"},
			stopAtOperand: false,
			want:          result{interactive: true, operands: []string{"alpine"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs, got := build(tc.stopAtOperand)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatalf("Parse(%q): %v", tc.args, err)
			}
			got.operands = fs.Args()
			if got.interactive != tc.want.interactive || got.tty != tc.want.tty || got.detach != tc.want.detach {
				t.Errorf("booleans = (i=%v t=%v d=%v), want (i=%v t=%v d=%v)",
					got.interactive, got.tty, got.detach,
					tc.want.interactive, tc.want.tty, tc.want.detach)
			}
			if got.name != tc.want.name {
				t.Errorf("name = %q, want %q", got.name, tc.want.name)
			}
			if got.count != tc.want.count {
				t.Errorf("count = %d, want %d", got.count, tc.want.count)
			}
			if strings.Join(got.env, ",") != strings.Join(tc.want.env, ",") {
				t.Errorf("env = %v, want %v", got.env, tc.want.env)
			}
			if strings.Join(got.operands, "\x00") != strings.Join(tc.want.operands, "\x00") {
				t.Errorf("operands = %v, want %v", got.operands, tc.want.operands)
			}
		})
	}
}

// TestFlagSetParseErrors checks that the parser rejects what it should, with a
// message naming the flag.
func TestFlagSetParseErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"unknown long flag", []string{"--nope"}, "unknown flag: --nope"},
		{"unknown short flag", []string{"-z"}, "unknown shorthand flag"},
		{"missing long value", []string{"--name"}, "flag needs an argument: --name"},
		{"missing short value", []string{"-n"}, "flag needs an argument: -n"},
		{"bad integer", []string{"--count", "many"}, "invalid argument"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := NewFlagSet("test")
			fs.Bool("interactive", "i", false, "stdin")
			fs.String("name", "n", "", "name")
			fs.Int("count", "c", 0, "count")
			err := fs.Parse(tc.args)
			if err == nil {
				t.Fatalf("Parse(%q) = nil, want an error", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Parse(%q) error = %q, want it to contain %q", tc.args, err, tc.want)
			}
		})
	}
}

// TestFlagSetHelpIsASentinel checks that -h and --help come back as ErrHelp so
// the command tree can print help instead of an error.
func TestFlagSetHelpIsASentinel(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		fs := NewFlagSet("test")
		fs.Bool("interactive", "i", false, "stdin")
		if err := fs.Parse([]string{arg}); err != ErrHelp {
			t.Errorf("Parse(%q) = %v, want ErrHelp", arg, err)
		}
		if !fs.HelpRequested() {
			t.Errorf("Parse(%q): HelpRequested = false", arg)
		}
	}
}

// TestTableColumnSizing checks the listing formatter: columns are measured
// from their content, a width of zero never truncates, and a narrow terminal
// shrinks the widest column rather than wrapping.
func TestTableColumnSizing(t *testing.T) {
	newTable := func(width int) *Table {
		tbl := NewTable("NAME", "STATUS")
		tbl.Width = width
		tbl.Row("web", "Up 3 minutes")
		tbl.Row("a-very-long-container-name", "Exited (0) 2 hours ago")
		return tbl
	}

	t.Run("unlimited width aligns and never truncates", func(t *testing.T) {
		var b strings.Builder
		if err := newTable(0).Render(&b); err != nil {
			t.Fatalf("Render: %v", err)
		}
		lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
		if len(lines) != 3 {
			t.Fatalf("got %d lines, want 3:\n%s", len(lines), b.String())
		}
		if !strings.Contains(lines[2], "a-very-long-container-name") {
			t.Errorf("long name was truncated with no width limit: %q", lines[2])
		}
		// The second column must start at the same offset on every line,
		// which is the whole point of measuring columns from their content.
		want := strings.Index(lines[0], "STATUS")
		for i, cell := range []string{"Up 3 minutes", "Exited (0) 2 hours ago"} {
			if got := strings.Index(lines[i+1], cell); got != want {
				t.Errorf("row %d starts its second column at %d, want %d: %q", i+1, got, want, lines[i+1])
			}
		}
	})

	t.Run("narrow terminal shrinks and ellipsises", func(t *testing.T) {
		var b strings.Builder
		if err := newTable(30).Render(&b); err != nil {
			t.Fatalf("Render: %v", err)
		}
		for _, line := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
			if len([]rune(line)) > 30 {
				t.Errorf("line is %d cells wide, want at most 30: %q", len([]rune(line)), line)
			}
		}
		if !strings.Contains(b.String(), "…") {
			t.Errorf("nothing was ellipsised at width 30:\n%s", b.String())
		}
	})

	t.Run("missing and extra cells cannot break alignment", func(t *testing.T) {
		tbl := NewTable("A", "B")
		tbl.Row("only-one")
		tbl.Row("one", "two", "three")
		var b strings.Builder
		if err := tbl.Render(&b); err != nil {
			t.Fatalf("Render: %v", err)
		}
		if strings.Contains(b.String(), "three") {
			t.Errorf("an extra cell leaked into the output:\n%s", b.String())
		}
	})
}

// TestHumanSize checks the size humaniser against the figures a user compares
// with "docker images".
func TestHumanSize(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{0, "0B"},
		{-1, "0B"},
		{999, "999B"},
		{1000, "1kB"},
		{1500, "1.5kB"},
		{1_000_000, "1MB"},
		{1_234_567, "1.23MB"},
		{5_368_709_120, "5.37GB"},
	}
	for _, tc := range tests {
		if got := HumanSize(tc.in); got != tc.want {
			t.Errorf("HumanSize(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestHumanDuration checks the age phrases every listing prints.
func TestHumanDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{500 * time.Millisecond, "Less than a second"},
		{time.Second, "1 second"},
		{45 * time.Second, "45 seconds"},
		{time.Minute, "About a minute"},
		{3 * time.Minute, "3 minutes"},
		{90 * time.Minute, "2 hours"},
		{time.Hour, "About an hour"},
		{72 * time.Hour, "3 days"},
		{21 * 24 * time.Hour, "3 weeks"},
		{75 * 24 * time.Hour, "2 months"},
		{3 * 365 * 24 * time.Hour, "3 years"},
		{-3 * time.Minute, "3 minutes"},
	}
	for _, tc := range tests {
		if got := HumanDuration(tc.in); got != tc.want {
			t.Errorf("HumanDuration(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestHumanSince checks that "3 minutes ago" reads the way it should, and that
// a container which has never run is not reported as decades old.
func TestHumanSince(t *testing.T) {
	if got := HumanSince(time.Now().Add(-3 * time.Minute)); got != "3 minutes ago" {
		t.Errorf("HumanSince(3m ago) = %q, want %q", got, "3 minutes ago")
	}
	if got := HumanSince(time.Time{}); got != "N/A" {
		t.Errorf("HumanSince(zero) = %q, want N/A", got)
	}
	if got := HumanTime(""); got != "N/A" {
		t.Errorf("HumanTime(\"\") = %q, want N/A", got)
	}
	if got := HumanTime("0001-01-01T00:00:00Z"); got != "N/A" {
		t.Errorf("HumanTime(zero time) = %q, want N/A", got)
	}
	stamp := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	if got := HumanTime(stamp); got != "2 hours ago" {
		t.Errorf("HumanTime(2h ago) = %q, want %q", got, "2 hours ago")
	}
}

// TestTruncateAndEllipsis checks the two shorteners a listing relies on.
func TestTruncateAndEllipsis(t *testing.T) {
	const digest = "sha256:0123456789abcdef0123456789abcdef"
	if got := TruncateID(digest); got != "0123456789ab" {
		t.Errorf("TruncateID = %q, want 0123456789ab", got)
	}
	if got := TruncateID("short"); got != "short" {
		t.Errorf("TruncateID(short) = %q, want short", got)
	}
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"abcdef", 10, "abcdef"},
		{"abcdef", 6, "abcdef"},
		{"abcdef", 3, "ab…"},
		{"abcdef", 1, "…"},
		{"abcdef", 0, ""},
		// Multi-byte runes must not be sliced in half.
		{"日本語テキスト", 3, "日本…"},
	}
	for _, tc := range tests {
		if got := Ellipsis(tc.in, tc.n); got != tc.want {
			t.Errorf("Ellipsis(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

// TestFormatTemplates checks --format: Docker's "table " prefix is tolerated,
// literal escapes are expanded, and hull's humanisers are callable from a
// template.
func TestFormatTemplates(t *testing.T) {
	type row struct {
		Names  string
		Status string
		Bytes  int64
	}
	items := []any{
		row{Names: "web", Status: "Up 3 minutes", Bytes: 1_500_000},
		row{Names: "db", Status: "Exited (0)", Bytes: 512},
	}

	tests := []struct {
		name   string
		format string
		want   string
	}{
		{
			name:   "plain fields",
			format: "{{.Names}} {{.Status}}",
			want:   "web Up 3 minutes\ndb Exited (0)\n",
		},
		{
			name:   "a leading table prefix is stripped",
			format: "table {{.Names}}",
			want:   "web\ndb\n",
		},
		{
			name:   "literal tab escapes are expanded",
			format: `{{.Names}}\t{{.Status}}`,
			want:   "web\tUp 3 minutes\ndb\tExited (0)\n",
		},
		{
			name:   "the size humaniser is available",
			format: "{{size .Bytes}}",
			want:   "1.5MB\n512B\n",
		},
		{
			name:   "json of a whole row",
			format: "{{json .Names}}",
			want:   "\"web\"\n\"db\"\n",
		},
		{
			name:   "upper and truncate",
			format: "{{upper .Names}}|{{truncate .Status 5}}",
			want:   "WEB|Up 3…\nDB|Exit…\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := NewTemplate(tc.format)
			if err != nil {
				t.Fatalf("NewTemplate(%q): %v", tc.format, err)
			}
			var b strings.Builder
			if err := RenderTemplate(&b, tmpl, items); err != nil {
				t.Fatalf("RenderTemplate: %v", err)
			}
			if b.String() != tc.want {
				t.Errorf("format %q gave %q, want %q", tc.format, b.String(), tc.want)
			}
		})
	}

	t.Run("a broken template names the flag", func(t *testing.T) {
		if _, err := NewTemplate("{{.Names"); err == nil {
			t.Fatal("NewTemplate on a malformed template = nil error")
		} else if !strings.Contains(err.Error(), "--format") {
			t.Errorf("error = %q, want it to mention --format", err)
		}
	})
}

// TestPublishParsing checks every -p spelling, since a misparsed port is a
// container nobody can reach.
func TestPublishParsing(t *testing.T) {
	tests := []struct {
		spec     string
		exposed  []string
		hostPort string
		hostIP   string
		wantErr  bool
	}{
		{spec: "80", exposed: []string{"80/tcp"}},
		{spec: "8080:80", exposed: []string{"80/tcp"}, hostPort: "8080"},
		{spec: "127.0.0.1:8080:80", exposed: []string{"80/tcp"}, hostPort: "8080", hostIP: "127.0.0.1"},
		{spec: "127.0.0.1::80", exposed: []string{"80/tcp"}, hostIP: "127.0.0.1"},
		{spec: "53:53/udp", exposed: []string{"53/udp"}, hostPort: "53"},
		{spec: "8000-8002:8000-8002", exposed: []string{"8000/tcp", "8001/tcp", "8002/tcp"}, hostPort: "8000"},
		{spec: "[::1]:8080:80", exposed: []string{"80/tcp"}, hostPort: "8080", hostIP: "::1"},
		{spec: "", wantErr: true},
		{spec: "notaport", wantErr: true},
		{spec: "8080:80/sctpx", wantErr: true},
		{spec: "8000-8002:8000-8003", wantErr: true},
		{spec: "notanip:8080:80", wantErr: true},
	}
	for _, tc := range tests {
		exposed, bindings, err := ParsePublish(tc.spec)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParsePublish(%q) = nil error, want one", tc.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePublish(%q): %v", tc.spec, err)
			continue
		}
		if strings.Join(exposed, ",") != strings.Join(tc.exposed, ",") {
			t.Errorf("ParsePublish(%q) exposed = %v, want %v", tc.spec, exposed, tc.exposed)
		}
		first := bindings[tc.exposed[0]]
		if len(first) != 1 {
			t.Errorf("ParsePublish(%q) gave %d bindings for %s, want 1", tc.spec, len(first), tc.exposed[0])
			continue
		}
		if first[0].HostPort != tc.hostPort {
			t.Errorf("ParsePublish(%q) host port = %q, want %q", tc.spec, first[0].HostPort, tc.hostPort)
		}
		if first[0].HostIP != tc.hostIP {
			t.Errorf("ParsePublish(%q) host IP = %q, want %q", tc.spec, first[0].HostIP, tc.hostIP)
		}
	}
}

// TestTranslateHostPath checks the Windows-to-VM path rewrite that makes
// "hull run -v C:\src:/src" work from PowerShell.
func TestTranslateHostPath(t *testing.T) {
	tests := []struct{ in, want string }{
		{`C:\src\app`, "/mnt/c/src/app"},
		{`c:/src/app`, "/mnt/c/src/app"},
		{`D:\`, "/mnt/d"},
		{"/already/posix", "/already/posix"},
		{"named-volume", "named-volume"},
		{`\\wsl$\Ubuntu\home\me`, "/home/me"},
		{`\\wsl.localhost\hull-engine\var\lib\hull`, "/var/lib/hull"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := TranslateHostPath(tc.in); got != tc.want {
			t.Errorf("TranslateHostPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestParseBindKeepsWindowsDrive checks that a drive letter's colon is not
// mistaken for the volume spec's own separator.
func TestParseBindKeepsWindowsDrive(t *testing.T) {
	tests := []struct{ in, want string }{
		{`C:\src:/src`, "/mnt/c/src:/src"},
		{`C:\src:/src:ro`, "/mnt/c/src:/src:ro"},
		{"data:/var/lib/data", "data:/var/lib/data"},
		{"/data", "/data"},
	}
	for _, tc := range tests {
		got, err := ParseBind(tc.in)
		if err != nil {
			t.Errorf("ParseBind(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseBind(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if _, err := ParseBind("relative-path-only"); err == nil {
		t.Error("ParseBind of a bare relative path = nil error, want one")
	}
}

// TestParseSizeAndUlimit checks the two option parsers a resource limit goes
// through before it reaches the engine.
func TestParseSizeAndUlimit(t *testing.T) {
	sizes := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{in: "1024", want: 1024},
		{in: "64m", want: 64 * 1024 * 1024},
		{in: "1g", want: 1024 * 1024 * 1024},
		{in: "nonsense", wantErr: true},
	}
	for _, tc := range sizes {
		got, err := ParseSize(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseSize(%q) = nil error, want one", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSize(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}

	u, err := ParseUlimit("nofile=1024:2048")
	if err != nil {
		t.Fatalf("ParseUlimit: %v", err)
	}
	if u.Name != "nofile" || u.Soft != 1024 || u.Hard != 2048 {
		t.Errorf("ParseUlimit = %+v, want {nofile 1024 2048}", u)
	}
	if u, err := ParseUlimit("nproc=unlimited"); err != nil || u.Soft != -1 || u.Hard != -1 {
		t.Errorf("ParseUlimit(unlimited) = %+v, %v; want soft and hard -1", u, err)
	}
	if _, err := ParseUlimit("nofile"); err == nil {
		t.Error("ParseUlimit without a value = nil error, want one")
	}
}

// TestExitCodeMapping checks that hull's own failures, a container's exit code
// and a quiet exit all map to the statuses a script branches on.
func TestExitCodeMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, ExitOK},
		{"a plain failure is a hull failure", Errorf("boom"), ExitFailure},
		{"a container's own code passes through", &ExitError{Code: 3}, 3},
		{"cannot invoke", &ExitError{Code: ExitCannotInvoke}, ExitCannotInvoke},
		{"not found", &ExitError{Code: ExitNotFound}, ExitNotFound},
		{"a quiet exit carries no message", Exit(7), 7},
	}
	for _, tc := range tests {
		if got := ExitCodeOf(tc.err); got != tc.want {
			t.Errorf("%s: ExitCodeOf = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestCommandTreeDispatch checks that the tree finds nested commands, enforces
// operand counts and prints help rather than failing on --help.
func TestCommandTreeDispatch(t *testing.T) {
	var ran string
	leaf := &Command{
		Name:    "ls",
		Usage:   "ls",
		Short:   "list",
		MaxArgs: 1,
		Run: func(_ context.Context, _ *Env, _ *FlagSet, args []string) error {
			ran = "ls:" + strings.Join(args, ",")
			return nil
		},
	}
	root := &Command{
		Name:        "hull",
		Subcommands: []*Command{{Name: "volume", Subcommands: []*Command{leaf}}},
	}

	env, out, errOut := testEnv(t)
	if err := Execute(context.Background(), env, root, []string{"volume", "ls", "one"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if ran != "ls:one" {
		t.Errorf("leaf ran as %q, want ls:one", ran)
	}

	err := Execute(context.Background(), env, root, []string{"volume", "ls", "one", "two"})
	if err == nil {
		t.Fatal("too many operands = nil error, want one")
	}
	if ExitCodeOf(err) != ExitFailure {
		t.Errorf("too many operands gave exit %d, want %d", ExitCodeOf(err), ExitFailure)
	}

	truncate(t, out)
	if err := Execute(context.Background(), env, root, []string{"volume", "ls", "--help"}); err != nil {
		t.Fatalf("Execute --help: %v", err)
	}
	if body := readFile(t, out); !strings.Contains(body, "Usage:  hull volume ls") {
		t.Errorf("--help did not print usage:\n%s", body)
	}
	if body := readFile(t, errOut); body != "" {
		t.Errorf("--help wrote to stderr: %q", body)
	}
}

// TestOutputDisciplineOffATerminal checks the promise that a pipe gets no
// colour: every helper must pass its argument through untouched.
func TestOutputDisciplineOffATerminal(t *testing.T) {
	env, _, _ := testEnv(t)
	if env.StdoutIsTerminal() {
		t.Fatal("a temp file should not look like a terminal")
	}
	if env.Color() {
		t.Fatal("colour is enabled with no terminal")
	}
	for _, got := range []string{env.Bold("x"), env.Red("x"), env.Green("x"), env.Yellow("x"), env.Dim("x")} {
		if got != "x" {
			t.Errorf("colour helper emitted %q off a terminal, want %q", got, "x")
		}
	}
	if env.Width() != 0 {
		t.Errorf("Width() = %d off a terminal, want 0 (no truncation)", env.Width())
	}
}

// TestWarningsReachStderr is the regression test for the failure mode
// docs/INTEGRATION-NOTES.md calls out: the engine reports a resource limit it
// cannot enforce as a warning rather than an error, and a warning that never
// reaches the user is a silently unlimited container.
func TestWarningsReachStderr(t *testing.T) {
	env, _, errOut := testEnv(t)
	env.ShowWarnings([]string{
		"memory limit ignored: no delegated cgroup v2 controllers on this host",
		"",
		"cpu quota ignored",
	})
	body := readFile(t, errOut)
	if !strings.Contains(body, "memory limit ignored") || !strings.Contains(body, "cpu quota ignored") {
		t.Errorf("warnings did not reach stderr:\n%s", body)
	}
	if strings.Count(body, "hull: warning:") != 2 {
		t.Errorf("want two prefixed warnings and no blank one, got:\n%s", body)
	}
}

// TestClientRoundTripThroughAListing drives a command end to end against an
// httptest server, which is the only way to check that the CLI's rendering and
// the client's decoding agree.
func TestClientRoundTripThroughAListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			w.Header().Set("Api-Version", "1.43")
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]client.ContainerSummary{{
				ID:      "0123456789abcdef0123456789abcdef",
				Names:   []string{"/web"},
				Image:   "nginx:1.27",
				Command: "nginx -g daemon off;",
				Created: time.Now().Add(-3 * time.Minute).Unix(),
				State:   "running",
				Status:  "Up 3 minutes",
				Ports: []client.Port{{
					IP: "0.0.0.0", PrivatePort: 80, PublicPort: 8080, Type: "tcp",
				}},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	env, out, _ := testEnv(t)
	env.Host = "tcp://" + strings.TrimPrefix(srv.URL, "http://")

	root := NewRootCommand()
	if err := Execute(context.Background(), env, root, []string{"ps"}); err != nil {
		t.Fatalf("hull ps: %v", err)
	}
	body := readFile(t, out)
	for _, want := range []string{"CONTAINER ID", "0123456789ab", "nginx:1.27", "Up 3 minutes", "0.0.0.0:8080->80/tcp", "web"} {
		if !strings.Contains(body, want) {
			t.Errorf("hull ps output is missing %q:\n%s", want, body)
		}
	}

	truncate(t, out)
	if err := Execute(context.Background(), env, root, []string{"ps", "-q"}); err != nil {
		t.Fatalf("hull ps -q: %v", err)
	}
	if got := strings.TrimSpace(readFile(t, out)); got != "0123456789ab" {
		t.Errorf("hull ps -q = %q, want the short id alone", got)
	}

	truncate(t, out)
	if err := Execute(context.Background(), env, root, []string{"ps", "--format", "json"}); err != nil {
		t.Fatalf("hull ps --format json: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(readFile(t, out)), &rows); err != nil {
		t.Fatalf("--format json did not produce a JSON array: %v", err)
	}
	if len(rows) != 1 || rows[0]["Names"] != "web" {
		t.Errorf("--format json = %v, want one row named web", rows)
	}
}

// TestUnreachableEngineExplainsItself checks that the most common first
// failure says what to do about it rather than only "connection refused".
func TestUnreachableEngineExplainsItself(t *testing.T) {
	env, _, errOut := testEnv(t)
	// Port 1 on loopback is never listening, and the dial fails fast.
	env.Host = "tcp://127.0.0.1:1"
	root := NewRootCommand()
	err := Execute(context.Background(), env, root, []string{"ps"})
	if err == nil {
		t.Fatal("hull ps against a dead endpoint = nil error")
	}
	if code := env.ReportError(err); code != ExitFailure {
		t.Errorf("exit code = %d, want %d", code, ExitFailure)
	}
	body := readFile(t, errOut)
	if !strings.HasPrefix(body, "hull: ") {
		t.Errorf("error is not prefixed:\n%s", body)
	}
	if !strings.Contains(body, "hull engine start") {
		t.Errorf("error does not name the fix:\n%s", body)
	}
}

// ---------- helpers ----------

// testEnv builds an Env whose three streams are temp files, which is how a
// test reads what a command printed without pretending to be a terminal.
func testEnv(t *testing.T) (env *Env, out, errOut *os.File) {
	t.Helper()
	dir := t.TempDir()
	open := func(name string) *os.File {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	in := open("stdin")
	out = open("stdout")
	errOut = open("stderr")
	return NewEnv(in, out, errOut), out, errOut
}

// readFile returns everything written to one of the test streams so far.
func readFile(t *testing.T, f *os.File) string {
	t.Helper()
	buf, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("reading %s: %v", f.Name(), err)
	}
	return string(buf)
}

// truncate empties a test stream between assertions.
func truncate(t *testing.T, f *os.File) {
	t.Helper()
	if err := f.Truncate(0); err != nil {
		t.Fatalf("truncating %s: %v", f.Name(), err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("rewinding %s: %v", f.Name(), err)
	}
}
