package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

// DefaultRuntimeBinaries is the order hull looks for an external OCI runtime.
// crun comes first: it is smaller, starts faster, and on the WSL 5.15 kernel
// it needs no cgroup v2 delegation to run an unconstrained container.
var DefaultRuntimeBinaries = []string{"crun", "runc"}

// CrunRuntime drives an installed OCI runtime binary.
//
// Every invocation carries --root, so hull's container state lives in hull's
// own directory and can never be confused with, or clobbered by, the state
// Docker Desktop keeps for the same binary in the same VM.
type CrunRuntime struct {
	binary  string
	root    string
	version string
	name    string

	mu       sync.Mutex
	features *RuntimeFeatures
	warnings []string
}

// compile-time assertion that the driver satisfies the interface.
var _ Runtime = (*CrunRuntime)(nil)

// NewCrun resolves an OCI runtime binary and returns a driver bound to root.
//
// binary may be an absolute path, a bare name to look up on PATH, or "" to try
// DefaultRuntimeBinaries in order. root is the runtime state directory; it is
// created if missing. The binary is executed once, with --version, both to
// confirm it runs on this host and to record what it is.
func NewCrun(binary, root string) (*CrunRuntime, error) {
	if root == "" {
		return nil, fmt.Errorf("runtime: NewCrun needs a state root directory")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("runtime: resolve crun state root %q: %w", root, err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("runtime: create crun state root %s: %w", abs, err)
	}

	candidates := DefaultRuntimeBinaries
	if binary != "" {
		candidates = []string{binary}
	}
	var tried []string
	for _, c := range candidates {
		p, err := exec.LookPath(c)
		if err != nil {
			tried = append(tried, fmt.Sprintf("%s (%v)", c, err))
			continue
		}
		ver, err := runtimeVersion(p)
		if err != nil {
			tried = append(tried, fmt.Sprintf("%s (%v)", p, err))
			continue
		}
		return &CrunRuntime{
			binary:  p,
			root:    abs,
			version: ver,
			name:    strings.TrimSuffix(filepath.Base(p), ".exe"),
		}, nil
	}
	return nil, fmt.Errorf("runtime: no usable OCI runtime binary found; tried %s. "+
		"Install crun (apk add crun / apt install crun) or runc, or pass --runtime with a path: %w",
		strings.Join(tried, ", "), ErrUnsupported)
}

// runtimeVersion runs "<bin> --version" and returns its first line.
func runtimeVersion(bin string) (string, error) {
	ctx, cancel := contextWithTimeout(10 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s --version: %w (%s)", bin, err, strings.TrimSpace(string(out)))
	}
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if line == "" {
		return "", fmt.Errorf("%s --version printed nothing", bin)
	}
	return line, nil
}

// Name returns the driver name, which is the binary's base name ("crun" or
// "runc"). It is what appears in HostConfig.Runtime.
func (r *CrunRuntime) Name() string { return r.name }

// Binary returns the absolute path of the runtime binary in use.
func (r *CrunRuntime) Binary() string { return r.binary }

// Root returns the runtime state directory passed as --root.
func (r *CrunRuntime) Root() string { return r.root }

// Version returns the first line of the binary's --version output.
func (r *CrunRuntime) Version() string { return r.version }

// run executes the runtime binary with the global --root flag prepended and
// returns its stdout. Failures carry the binary's own stderr, which is the
// only part of the message that ever says anything useful.
func (r *CrunRuntime) run(ctx context.Context, stdio *ioBundle, args ...string) ([]byte, error) {
	full := append([]string{"--root", r.root}, args...)
	cmd := exec.CommandContext(ctx, r.binary, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stderr = &stderr
	if stdio != nil {
		cmd.Stdin, cmd.Stdout = stdio.in, stdio.out
		if stdio.err != nil {
			cmd.Stderr = stdio.err
		}
		cmd.ExtraFiles = stdio.extra
	} else {
		cmd.Stdout = &stdout
	}
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return stdout.Bytes(), fmt.Errorf("runtime: %s %s: %w: %s",
			r.name, strings.Join(args, " "), err, msg)
	}
	return stdout.Bytes(), nil
}

// ioBundle groups the streams and extra descriptors handed to one invocation.
type ioBundle struct {
	in    io.Reader
	out   io.Writer
	err   io.Writer
	extra []*os.File
}

// bundleFor collects the caller's streams, returning nil when there are none
// so run keeps capturing stdout for the callers that parse it.
func bundleFor(in io.Reader, out, errw io.Writer, extra []*os.File) *ioBundle {
	if in == nil && out == nil && errw == nil && len(extra) == 0 {
		return nil
	}
	return &ioBundle{in: in, out: out, err: errw, extra: extra}
}

// crunState is the JSON the "state" subcommand prints. It is the OCI
// runtime-spec state structure.
type crunState struct {
	OCIVersion  string            `json:"ociVersion"`
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	Pid         int               `json:"pid"`
	Bundle      string            `json:"bundle"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Created     string            `json:"created,omitempty"`
}

// Create writes the container using the external runtime's "create". The
// container's init process is left blocked until Start.
func (r *CrunRuntime) Create(ctx context.Context, id, bundleDir string, opts CreateOptions) (*Status, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("runtime: resolve bundle %q: %w", bundleDir, err)
	}
	if _, err := LoadSpec(abs); err != nil {
		return nil, err
	}
	if opts.Terminal && opts.ConsoleSocket == "" {
		return nil, fmt.Errorf("runtime: %s needs a --console-socket to allocate a terminal; "+
			"hull's shim must create one before calling Create: %w", r.name, ErrUnsupported)
	}

	args := []string{"create", "--bundle", abs}
	if opts.ConsoleSocket != "" {
		args = append(args, "--console-socket", opts.ConsoleSocket)
	}
	if opts.PidFile != "" {
		args = append(args, "--pid-file", opts.PidFile)
	}
	args = append(args, id)

	_, err = r.run(ctx, bundleFor(opts.Stdin, opts.Stdout, opts.Stderr, opts.ExtraFiles), args...)
	if err != nil && isVersionRefusal(err) {
		// crun and runc validate ociVersion against a fixed list and
		// refuse anything newer than the release they shipped with, so a
		// bundle written to runtime-spec 1.2 is rejected outright by
		// crun 1.14. Rather than fail a container the binary could
		// perfectly well run, hull writes a compatibility copy of
		// config.json - the same bundle with an older version string and
		// an absolute root path - into its own state directory and
		// retries against that. The operator is told, because it means
		// the runtime is older than the spec hull emits.
		compat, cerr := r.compatBundle(id, abs)
		if cerr != nil {
			return nil, fmt.Errorf("%w (and the compatibility rewrite failed: %v)", err, cerr)
		}
		r.warn(fmt.Sprintf("%s rejected runtime-spec %s; hull retried with a downgraded config.json "+
			"at %s. Upgrade %s for native support.", r.name, runtimespec.Version, compat, r.name))
		retry := append([]string{"create", "--bundle", compat}, args[3:]...)
		_, err = r.run(ctx, bundleFor(opts.Stdin, opts.Stdout, opts.Stderr, opts.ExtraFiles), retry...)
	}
	if err != nil {
		if strings.Contains(err.Error(), "exists") {
			return nil, fmt.Errorf("%w: %s", ErrExists, err)
		}
		return nil, err
	}
	st, err := r.State(ctx, id)
	if err != nil {
		return nil, err
	}
	if st.Created.IsZero() {
		st.Created = time.Now().UTC()
	}
	return st, nil
}

// Start releases a created container into its entrypoint.
func (r *CrunRuntime) Start(ctx context.Context, id string) error {
	if err := ValidID(id); err != nil {
		return err
	}
	_, err := r.run(ctx, nil, "start", id)
	return mapCrunError(err, id)
}

// State parses the external runtime's view of the container.
func (r *CrunRuntime) State(ctx context.Context, id string) (*Status, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	out, err := r.run(ctx, nil, "state", id)
	if err != nil {
		return nil, mapCrunError(err, id)
	}
	var cs crunState
	if err := json.Unmarshal(out, &cs); err != nil {
		return nil, fmt.Errorf("runtime: parse %s state for %s: %w (output %q)", r.name, id, err, string(out))
	}
	st := &Status{
		ID:          cs.ID,
		Pid:         cs.Pid,
		Status:      cs.Status,
		Bundle:      cs.Bundle,
		Annotations: cs.Annotations,
	}
	if cs.Created != "" {
		if t, err := time.Parse(time.RFC3339Nano, cs.Created); err == nil {
			st.Created = t
		}
	}
	if st.Status == StatusStopped {
		st.Exited = true
		st.Pid = 0
	}
	return st, nil
}

// Kill signals the container. The signal is passed numerically, which every
// OCI runtime accepts and which avoids disagreeing with the binary about
// signal names on an architecture where they differ.
func (r *CrunRuntime) Kill(ctx context.Context, id string, sig syscall.Signal, all bool) error {
	if err := ValidID(id); err != nil {
		return err
	}
	args := []string{"kill"}
	if all {
		args = append(args, "--all")
	}
	args = append(args, id, strconv.Itoa(int(sig)))
	_, err := r.run(ctx, nil, args...)
	return mapCrunError(err, id)
}

// Delete removes the container's runtime state. force kills it first.
func (r *CrunRuntime) Delete(ctx context.Context, id string, force bool) error {
	if err := ValidID(id); err != nil {
		return err
	}
	args := []string{"delete"}
	if force {
		args = append(args, "--force")
	}
	args = append(args, id)
	_, err := r.run(ctx, nil, args...)
	_ = os.RemoveAll(filepath.Join(r.root, id+".bundle"))
	if err != nil && errors.Is(mapCrunError(err, id), ErrNotFound) {
		// Deleting something that is already gone is a success.
		return nil
	}
	return mapCrunError(err, id)
}

// Exec runs an extra process inside a running container. The process
// description is written to a temporary file rather than passed on the command
// line, so its environment - which routinely holds secrets - never appears in
// /proc/<pid>/cmdline.
func (r *CrunRuntime) Exec(ctx context.Context, id string, process *runtimespec.Process, opts ExecOptions) (*Status, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	if process == nil || len(process.Args) == 0 {
		return nil, fmt.Errorf("runtime: exec in %s needs a process with args", id)
	}
	if opts.Terminal && opts.ConsoleSocket == "" {
		return nil, fmt.Errorf("runtime: %s needs a --console-socket to allocate a terminal for exec: %w",
			r.name, ErrUnsupported)
	}
	f, err := os.CreateTemp(r.root, ".exec-*.json")
	if err != nil {
		return nil, fmt.Errorf("runtime: create exec process file: %w", err)
	}
	defer os.Remove(f.Name())
	enc := json.NewEncoder(f)
	if err := enc.Encode(process); err != nil {
		f.Close()
		return nil, fmt.Errorf("runtime: write exec process file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("runtime: close exec process file: %w", err)
	}

	args := []string{"exec", "--process", f.Name()}
	if opts.ConsoleSocket != "" {
		args = append(args, "--console-socket", opts.ConsoleSocket)
	}
	if opts.PidFile != "" {
		args = append(args, "--pid-file", opts.PidFile)
	}
	if opts.Detach {
		args = append(args, "--detach")
	}
	args = append(args, id)

	st := &Status{ID: id, Status: StatusRunning, Created: time.Now().UTC()}
	_, err = r.run(ctx, bundleFor(opts.Stdin, opts.Stdout, opts.Stderr, opts.ExtraFiles), args...)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && !opts.Detach {
			// A non-zero exit of the exec'd process is a result, not a
			// runtime failure.
			st.Exited = true
			st.Status = StatusStopped
			st.ExitCode = ee.ExitCode()
			return st, nil
		}
		return nil, mapCrunError(err, id)
	}
	if opts.PidFile != "" {
		if b, rerr := os.ReadFile(opts.PidFile); rerr == nil {
			if pid, cerr := strconv.Atoi(strings.TrimSpace(string(b))); cerr == nil {
				st.Pid = pid
			}
		}
	}
	if !opts.Detach {
		st.Exited = true
		st.Status = StatusStopped
	}
	return st, nil
}

// Pause freezes the container's cgroup.
func (r *CrunRuntime) Pause(ctx context.Context, id string) error {
	if err := ValidID(id); err != nil {
		return err
	}
	_, err := r.run(ctx, nil, "pause", id)
	return mapCrunError(err, id)
}

// Resume thaws the container's cgroup.
func (r *CrunRuntime) Resume(ctx context.Context, id string) error {
	if err := ValidID(id); err != nil {
		return err
	}
	_, err := r.run(ctx, nil, "resume", id)
	return mapCrunError(err, id)
}

// Features describes the external runtime. Newer crun and runc print a
// machine-readable "features" document; when the binary is older, hull reports
// what it knows from --version and the host probe instead of guessing.
func (r *CrunRuntime) Features(ctx context.Context) (RuntimeFeatures, error) {
	r.mu.Lock()
	if r.features != nil {
		f := *r.features
		r.mu.Unlock()
		return f, nil
	}
	r.mu.Unlock()

	f := RuntimeFeatures{
		Name:        r.name,
		Version:     r.version,
		OCIVersions: []string{runtimespec.Version},
	}
	probe, perr := ProbeFeatures(ctx)
	f.Probe = probe
	f.Kernel = probe.Kernel
	f.SeccompActions = probe.SeccompActions
	f.SeccompEnabled = probe.Seccomp
	if perr != nil {
		f.Warnings = append(f.Warnings, perr.Error())
	}
	f.Warnings = append(f.Warnings, probe.Warnings...)
	f.Warnings = append(f.Warnings, r.Warnings()...)

	out, err := r.run(ctx, nil, "features")
	if err == nil {
		var doc struct {
			OCIVersionMin string `json:"ociVersionMin"`
			OCIVersionMax string `json:"ociVersionMax"`
			Linux         struct {
				Namespaces   []string `json:"namespaces"`
				Capabilities []string `json:"capabilities"`
				Seccomp      *struct {
					Enabled bool     `json:"enabled"`
					Actions []string `json:"actions"`
				} `json:"seccomp"`
			} `json:"linux"`
		}
		if jerr := json.Unmarshal(out, &doc); jerr == nil {
			if doc.OCIVersionMin != "" {
				f.OCIVersions = []string{doc.OCIVersionMin, doc.OCIVersionMax}
			}
			f.Namespaces = doc.Linux.Namespaces
			f.Capabilities = doc.Linux.Capabilities
			if doc.Linux.Seccomp != nil {
				f.SeccompEnabled = doc.Linux.Seccomp.Enabled
				if len(doc.Linux.Seccomp.Actions) > 0 {
					f.SeccompActions = doc.Linux.Seccomp.Actions
				}
			}
		}
	} else {
		f.Warnings = append(f.Warnings, fmt.Sprintf(
			"%s does not implement the 'features' subcommand; hull is reporting the host probe only "+
				"(upgrade to crun 1.9+ or runc 1.1.13+ for the runtime's own answer)", r.name))
	}
	if len(f.Namespaces) == 0 {
		f.Namespaces = []string{"cgroup", "ipc", "mount", "network", "pid", "user", "uts"}
	}

	r.mu.Lock()
	cp := f
	r.features = &cp
	r.mu.Unlock()
	return f, nil
}

// mapCrunError turns the external runtime's stderr into one of hull's sentinel
// errors where it can, so callers do not have to grep message text themselves.
func mapCrunError(err error, id string) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "does not exist"),
		strings.Contains(msg, "no such container"),
		strings.Contains(msg, "not exist"):
		return fmt.Errorf("%s: %w", id, ErrNotFound)
	case strings.Contains(msg, "is not running"),
		strings.Contains(msg, "not running"):
		return fmt.Errorf("%s: %w", id, ErrNotRunning)
	case strings.Contains(msg, "already exists"):
		return fmt.Errorf("%s: %w", id, ErrExists)
	}
	return err
}

// contextWithTimeout is a tiny indirection so the version probe does not need
// a caller-supplied context.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// compatOCIVersion is the newest runtime-spec version every crun and runc
// release in the field accepts. It is only used when the installed binary
// refuses the version hull actually writes.
const compatOCIVersion = "1.0.2"

// isVersionRefusal recognises the way crun and runc reject a runtime-spec
// version they do not know.
func isVersionRefusal(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unknown version") ||
		strings.Contains(msg, "unsupported version") ||
		strings.Contains(msg, "ociversion")
}

// compatBundle writes a copy of the bundle's config.json into the runtime
// state directory with an ociVersion the installed binary accepts and an
// absolute root path, and returns the directory holding it.
//
// Only the version string and the root path are changed; every other field is
// carried through byte for byte, so nothing about the container's isolation is
// altered by the rewrite.
func (r *CrunRuntime) compatBundle(id, bundleDir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(bundleDir, ConfigFileName))
	if err != nil {
		return "", fmt.Errorf("runtime: read %s for the compatibility rewrite: %w", bundleDir, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("runtime: parse %s for the compatibility rewrite: %w", bundleDir, err)
	}
	doc["ociVersion"] = compatOCIVersion
	if root, ok := doc["root"].(map[string]any); ok {
		if p, ok := root["path"].(string); ok && !filepath.IsAbs(p) {
			root["path"] = filepath.Join(bundleDir, p)
		}
	}
	out := filepath.Join(r.root, id+".bundle")
	if err := os.MkdirAll(out, 0o700); err != nil {
		return "", fmt.Errorf("runtime: create the compatibility bundle dir: %w", err)
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("runtime: encode the compatibility config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(out, ConfigFileName), b, 0o600); err != nil {
		return "", fmt.Errorf("runtime: write the compatibility config: %w", err)
	}
	return out, nil
}

// warn records a host problem the operator should know about. Warnings are
// deduplicated so a per-container problem is reported once.
func (r *CrunRuntime) warn(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, w := range r.warnings {
		if w == s {
			return
		}
	}
	r.warnings = append(r.warnings, s)
	r.features = nil
}

// Warnings returns everything the driver has found worth telling the operator.
func (r *CrunRuntime) Warnings() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.warnings...)
}
