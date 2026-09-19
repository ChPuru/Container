// Command hulld is hull's daemon: the Docker Engine API v1.43 server over
// hull's container engine.
//
// It runs inside the hull-engine WSL distro and serves the API on a unix
// socket, optionally on a second socket in the shared /mnt/wsl tmpfs so other
// distros reach it without the Windows relay, and optionally on a loopback TCP
// listener guarded by a shared secret.
//
// # Shutdown
//
// SIGTERM and SIGINT start a graceful drain: the listeners stop accepting, the
// in-flight requests are given a moment to finish, and the engine detaches
// from every per-container shim. Running containers deliberately survive —
// each is supervised by a hull-shim reparented to PID 1, and the next daemon
// start re-adopts them. A second signal gives up waiting and exits at once.
//
// # Sockets
//
// A stale socket is removed only after a dial confirms nothing answers on it,
// so restarting into a data root a live daemon already owns fails loudly
// instead of leaving two daemons fighting over the same state.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/rahuldhali/hull/internal/engine"
	"github.com/rahuldhali/hull/internal/version"
)

// Process exit codes. Anything non-zero means the daemon did not start, or did
// not stop cleanly, and a supervisor should say why rather than restart in a
// loop.
const (
	// exitOK means a clean start and a clean drain.
	exitOK = 0
	// exitFailure means the daemon could not start or could not stop cleanly.
	exitFailure = 1
	// exitUsage means the command line was wrong.
	exitUsage = 2
)

// Paths under the data root. They are slash-spelled and converted with
// [filepath.FromSlash] so the package still behaves on a non-Unix host, where
// hulld does not run for real but must still build and test.
const (
	// defaultSocketName is the Docker API socket, relative to the data root.
	defaultSocketName = "run/hull.sock"
	// defaultPIDName is the advisory pid file, relative to the data root.
	defaultPIDName = "run/hull.pid"
)

// defaultSharedSocket is the bind point in the shared /mnt/wsl tmpfs. Every
// WSL distro sees that tmpfs, so a socket there is how the user's own Ubuntu
// talks to the engine distro without going out through Windows and back.
const defaultSharedSocket = "/mnt/wsl/hull/hull.sock"

// defaultSocketMode is the permission the API sockets are created with: owner
// and group only. The daemon runs as root in its own distro, and the group is
// how a non-root user is granted access deliberately rather than by accident.
const defaultSocketMode uint = 0o660

// closeTimeout bounds both the API drain and the engine's own shutdown, which
// has real work to do: detaching from every shim, stopping the port proxies
// and the embedded DNS, then flushing and unlocking the state store.
const closeTimeout = 20 * time.Second

// options is the resolved command line.
//
// It is a plain struct rather than a flag.FlagSet so [options.resolve] can be
// unit-tested without parsing anything, which is where the interesting rules
// live: the socket defaults, the TCP token requirement and the permission-mask
// check.
type options struct {
	// dataRoot is hull's state directory.
	dataRoot string
	// socket is the primary unix socket path, or "" when disabled.
	socket string
	// sharedSocket is the /mnt/wsl socket path, or "" when disabled.
	sharedSocket string
	// socketMode is the permission mask both unix sockets are chmod'd to.
	socketMode uint
	// tcp is the host:port of the TCP listener, or "" when disabled.
	tcp string
	// tcpToken is the shared secret every TCP request must present.
	tcpToken string
	// shim is the path to hull-shim, the per-container supervisor.
	shim string
	// initBinary is the path to hull-init, used by --init containers.
	initBinary string
	// runtimeName selects the container driver.
	runtimeName string
	// runtimeBinary is an explicit path to the external OCI runtime.
	runtimeBinary string
	// defaultPool is the CIDR container networks are carved out of.
	defaultPool string
	// buildKitAddr is where a bundled buildkitd listens.
	buildKitAddr string
	// cors is the Access-Control-Allow-Origin value; empty disables CORS.
	cors string
	// idleFreeze is how long a container may idle before it is frozen.
	idleFreeze time.Duration
	// idleExit is how long everything must idle before the daemon stops.
	idleExit time.Duration
	// logLevel is debug, info, warn or error.
	logLevel string
	// accessLog logs one line per API request.
	accessLog bool
	// debug turns on debug logging and the access log together.
	debug bool
	// showVersion prints the build identity and exits.
	showVersion bool

	// notes are the resolution decisions worth telling the operator about,
	// collected here because resolve has no logger of its own.
	notes []string
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run parses the command line, builds the daemon and returns the process exit
// code. Diagnostics go to errOut and the --version report to out, so the whole
// entrypoint is testable without capturing the process's own streams.
func run(args []string, out, errOut io.Writer) int {
	opts, err := parseFlags(args, errOut)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintln(errOut, "hulld:", err)
		return exitUsage
	}
	if opts.showVersion {
		printVersion(out)
		return exitOK
	}

	level, err := parseLevel(opts.logLevel)
	if err != nil {
		fmt.Fprintln(errOut, "hulld:", err)
		return exitUsage
	}
	if opts.debug {
		level = slog.LevelDebug
	}
	if err := opts.resolve(); err != nil {
		fmt.Fprintln(errOut, "hulld:", err)
		return exitUsage
	}

	log := newLogger(errOut, level, isTerminal(errOut))
	slog.SetDefault(log)
	for _, note := range opts.notes {
		log.Info("hulld: " + note)
	}
	log.Info("hulld: starting",
		"version", version.Version,
		"commit", version.Commit,
		"dataRoot", opts.dataRoot,
		"api", version.APIVersion,
		"minAPI", version.MinAPIVersion)

	d := &daemon{opts: opts, log: log}
	if err := d.run(); err != nil {
		log.Error("hulld: stopped with an error", "err", err)
		return exitFailure
	}
	log.Info("hulld: stopped")
	return exitOK
}

// printVersion writes the build identity in the shape `hull version` parses.
func printVersion(w io.Writer) {
	fmt.Fprintf(w, "hulld %s\n", version.Version)
	fmt.Fprintf(w, "  commit %s\n", version.Commit)
	fmt.Fprintf(w, "  built  %s\n", version.BuildDate)
	fmt.Fprintf(w, "  api    %s (minimum %s, reported as Docker %s)\n",
		version.APIVersion, version.MinAPIVersion, version.DockerVersion)
	fmt.Fprintf(w, "  go     %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// parseFlags turns the command line into options, writing flag errors and the
// usage message to w.
//
// It deliberately does no validation beyond what the flag package does: the
// rules that need a filesystem or a policy decision live in [options.resolve],
// so they can be tested on their own.
func parseFlags(args []string, w io.Writer) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet("hulld", flag.ContinueOnError)
	fs.SetOutput(w)
	fs.Usage = func() {
		fmt.Fprintln(w, "hulld — hull's container daemon, speaking the Docker Engine API.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Usage: hulld [flags]")
		fmt.Fprintln(w)
		fs.PrintDefaults()
	}

	fs.StringVar(&o.dataRoot, "data-root", envOr("HULL_DATA_ROOT", engine.DefaultDataRoot),
		"hull's state directory")
	fs.StringVar(&o.socket, "socket", envOr("HULL_SOCKET", ""),
		"unix socket for the Docker API (default <data-root>/"+defaultSocketName+"; \"none\" disables it)")
	fs.StringVar(&o.sharedSocket, "shared-socket", envOr("HULL_SHARED_SOCKET", defaultSharedSocket),
		"second unix socket in the shared /mnt/wsl tmpfs, reachable from other WSL distros "+
			"(\"none\" disables it)")
	fs.UintVar(&o.socketMode, "socket-mode", defaultSocketMode,
		"permission mask for the unix sockets, in octal")
	fs.StringVar(&o.tcp, "tcp", envOr("HULL_TCP", ""),
		"host:port for the TCP listener; requires --tcp-token (\"none\" disables it)")
	fs.StringVar(&o.tcpToken, "tcp-token", os.Getenv("HULL_TCP_TOKEN"),
		"shared secret every TCP request must send in the Authorization header")
	fs.StringVar(&o.shim, "shim", envOr("HULL_SHIM", ""),
		"path to hull-shim, the per-container supervisor (default: found next to hulld)")
	fs.StringVar(&o.initBinary, "init-binary", envOr("HULL_INIT", ""),
		"path to hull-init, bind-mounted into containers started with --init")
	fs.StringVar(&o.runtimeName, "runtime", envOr("HULL_RUNTIME", ""),
		`container runtime: "hull" for the native driver, or "crun"/"runc"`)
	fs.StringVar(&o.runtimeBinary, "runtime-binary", envOr("HULL_RUNTIME_BINARY", ""),
		"explicit path to the external OCI runtime binary")
	fs.StringVar(&o.defaultPool, "default-pool", envOr("HULL_SUBNET_POOL", engine.DefaultSubnetPool),
		"CIDR that container networks are carved out of")
	fs.StringVar(&o.buildKitAddr, "buildkit-addr", envOr("HULL_BUILDKIT_ADDR", ""),
		"address of a bundled buildkitd for /build (default: probe the usual paths)")
	fs.StringVar(&o.cors, "cors", "",
		"value for Access-Control-Allow-Origin; empty disables CORS, which is the right default")
	fs.DurationVar(&o.idleFreeze, "idle-freeze", 0,
		"freeze a container after this long with no CPU movement and no attached client (0 disables)")
	fs.DurationVar(&o.idleExit, "idle-exit", 0,
		"stop the daemon once everything has been idle this long, so WSL can reclaim the VM (0 disables)")
	fs.StringVar(&o.logLevel, "log-level", envOr("HULL_LOG_LEVEL", "info"),
		"debug, info, warn or error")
	fs.BoolVar(&o.accessLog, "access-log", false, "log one line per API request")
	fs.BoolVar(&o.debug, "debug", false, "debug logging plus the per-request access log")
	fs.BoolVar(&o.showVersion, "version", false, "print the version and exit")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q; hulld takes flags only", fs.Arg(0))
	}
	if o.debug {
		o.accessLog = true
	}
	return o, nil
}

// resolve fills in the defaults that need the filesystem and rejects a command
// line that cannot work.
//
// The refusals are deliberate rather than best-effort: a TCP listener with no
// token is a DNS-rebinding hole, two listeners on one path is a race whose
// loser leaves no socket at all, and a daemon with no listener at all is a
// process that looks healthy and serves nobody.
func (o *options) resolve() error {
	if strings.TrimSpace(o.dataRoot) == "" {
		o.dataRoot = engine.DefaultDataRoot
	}
	root, err := filepath.Abs(o.dataRoot)
	if err != nil {
		return fmt.Errorf("resolve --data-root %q: %w", o.dataRoot, err)
	}
	o.dataRoot = root

	if o.socketMode == 0 || o.socketMode > 0o777 {
		return fmt.Errorf("--socket-mode %#o is not a permission mask: "+
			"it must be between 0001 and 0777", o.socketMode)
	}

	// "--socket none" and an unset --socket both normalize to the empty
	// string, but they mean opposite things, so the explicit refusal is
	// recorded before the value is flattened.
	socketTurnedOff := listenerDisabled(o.socket)
	o.socket = normalizeListener(o.socket)
	o.sharedSocket = normalizeListener(o.sharedSocket)
	o.tcp = normalizeListener(o.tcp)

	if o.socket == "" && !socketTurnedOff {
		o.socket = filepath.Join(o.dataRoot, filepath.FromSlash(defaultSocketName))
	}

	if o.sharedSocket != "" {
		// /mnt/wsl only exists inside WSL. Outside it the shared socket is
		// meaningless rather than broken, so the built-in default is dropped
		// with an explanation instead of failing the whole daemon. A path the
		// operator typed is never second-guessed.
		if o.sharedSocket == defaultSharedSocket {
			mnt := filepath.Dir(filepath.Dir(filepath.FromSlash(o.sharedSocket)))
			if fi, err := os.Stat(mnt); err != nil || !fi.IsDir() {
				o.notes = append(o.notes,
					"skipping the shared socket: "+mnt+" does not exist, so this is not a WSL host")
				o.sharedSocket = ""
			}
		}
	}
	if o.sharedSocket != "" && o.socket != "" && sameSocketPath(o.socket, o.sharedSocket) {
		return fmt.Errorf("--socket and --shared-socket name the same path %q; "+
			"two listeners on one socket cannot both survive", o.socket)
	}

	if o.tcp != "" && strings.TrimSpace(o.tcpToken) == "" {
		return errors.New("--tcp requires --tcp-token (or HULL_TCP_TOKEN): " +
			"an unauthenticated TCP listener lets any web page in the browser drive the daemon")
	}
	if o.socket == "" && o.sharedSocket == "" && o.tcp == "" {
		return errors.New("no listener configured: pass --socket, --shared-socket or --tcp")
	}

	if o.idleFreeze < 0 || o.idleExit < 0 {
		return errors.New("--idle-freeze and --idle-exit cannot be negative")
	}
	if strings.TrimSpace(o.defaultPool) == "" {
		o.defaultPool = engine.DefaultSubnetPool
	}

	o.shim = resolveHelper(o.shim, "hull-shim")
	o.initBinary = resolveHelper(o.initBinary, "hull-init")
	return nil
}

// listenerDisabled reports whether a listener flag was explicitly turned off,
// which is not the same as being left unset.
func listenerDisabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "none", "off", "disabled", "no", "false":
		return true
	default:
		return false
	}
}

// normalizeListener maps the spellings that mean "off" onto the empty string
// and trims the rest.
func normalizeListener(v string) string {
	if listenerDisabled(v) {
		return ""
	}
	return strings.TrimSpace(v)
}

// sameSocketPath reports whether two socket paths are the same file. It
// compares cleaned absolute paths, which is enough: hulld creates both, so
// neither can be a pre-existing symlink to the other without the second
// listener failing anyway.
func sameSocketPath(a, b string) bool {
	ca, err := filepath.Abs(filepath.Clean(a))
	if err != nil {
		ca = filepath.Clean(a)
	}
	cb, err := filepath.Abs(filepath.Clean(b))
	if err != nil {
		cb = filepath.Clean(b)
	}
	return ca == cb
}

// resolveHelper finds one of hull's helper binaries.
//
// An explicit path is returned untouched even when it does not exist: failing
// loudly at the first container start beats silently running a different
// binary than the operator named. Otherwise the search is deliberately
// narrow — next to hulld itself first, because that is how hull ships, then
// the install directories, then PATH.
func resolveHelper(explicit, name string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if self, err := os.Executable(); err == nil {
		if cand := filepath.Join(filepath.Dir(self), name); fileExists(cand) {
			return cand
		}
	}
	for _, dir := range []string{"/usr/local/libexec/hull", "/usr/libexec/hull",
		"/usr/local/lib/hull", "/usr/lib/hull", "/usr/local/bin", "/usr/bin"} {
		if cand := filepath.Join(dir, name); fileExists(cand) {
			return cand
		}
	}
	if cand, err := exec.LookPath(name); err == nil {
		return cand
	}
	return ""
}

// fileExists reports whether path names an existing regular file.
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// parseLevel maps a log-level name onto a slog level. An empty name is info,
// and an unknown one is an error rather than a silent fallback: a typo in a
// service unit should not quietly turn debugging off.
func parseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "err", "fatal":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown --log-level %q: want debug, info, warn or error", name)
	}
}

// newLogger builds the daemon logger: human-readable text for a terminal, JSON
// for anything else, because anything else is a file or a journal and a
// supervisor wants to parse it.
func newLogger(w io.Writer, level slog.Level, textOutput bool) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if textOutput {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

// isTerminal reports whether w is an interactive terminal. Anything that is
// not an *os.File — a buffer in a test, a pipe wrapper — is not.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// envOr returns the environment variable's trimmed value, or def when it is
// unset or blank.
func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}
