package runtime

import (
	"context"
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

	"golang.org/x/sys/unix"

	"github.com/rahuldhali/hull/internal/cgroups"
	"github.com/rahuldhali/hull/internal/oci/runtimespec"
	"github.com/rahuldhali/hull/internal/runtime/initspec"
)

// NativeName is the value HostConfig.Runtime takes to select hull's own
// runtime rather than an external OCI binary.
const NativeName = "hull"

// InitBinaryEnv names the environment variable that overrides where hull looks
// for the hull-init binary. It exists for development and for tests.
const InitBinaryEnv = "HULL_INIT"

// initSearchPaths are the fixed locations hull looks for hull-init, after
// InitBinaryEnv and the directory holding the running daemon.
var initSearchPaths = []string{
	"/usr/libexec/hull/hull-init",
	"/usr/local/libexec/hull/hull-init",
	"/usr/lib/hull/hull-init",
	"/usr/local/bin/hull-init",
	"/usr/bin/hull-init",
}

// NativeRuntime is hull's own container runtime.
//
// It never shells out, never re-execs /proc/self/exe into a container, and
// resolves every container-controlled path fd-relative. The container stage
// lives in a separate binary, hull-init, which is loaded into a sealed memfd
// at Create time and exec'd through /proc/self/fd - so the thing the container
// could overwrite to escape (CVE-2019-5736) does not exist.
type NativeRuntime struct {
	root     string
	features Features

	cgInfo cgroups.Info
	cgErr  error

	initOnce sync.Once
	initBin  []byte
	initPath string
	initErr  error

	mu   sync.Mutex
	ctrs map[string]*nativeContainer
}

var _ Runtime = (*NativeRuntime)(nil)

// nativeContainer is one container this process created and still owns.
type nativeContainer struct {
	id      string
	bundle  string
	dir     string
	rootfs  string
	spec    *runtimespec.Spec
	cmd     *exec.Cmd
	pidfd   *os.File
	startW  *os.File
	sock    *os.File
	console *os.File
	cg      *cgroups.Manager

	mu     sync.Mutex
	status Status
	done   chan struct{}
	waited bool
}

// NewNative returns hull's own runtime, storing its state under root.
//
// features is the host probe; pass the zero Features to have NewNative probe
// the kernel itself. The probe result is what every later decision is made
// from, so a caller that has already probed should pass its result rather than
// letting the kernel be probed twice.
func NewNative(root string, features Features) (*NativeRuntime, error) {
	if root == "" {
		return nil, fmt.Errorf("runtime: NewNative needs a state root directory")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("runtime: resolve native state root %q: %w", root, err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("runtime: create native state root %s: %w", abs, err)
	}
	if features.Kernel == "" {
		probed, perr := ProbeFeatures(context.Background())
		if perr != nil {
			return nil, fmt.Errorf("runtime: probe kernel features: %w", perr)
		}
		features = probed
	}
	r := &NativeRuntime{root: abs, features: features, ctrs: map[string]*nativeContainer{}}
	r.cgInfo, r.cgErr = cgroups.Detect()
	return r, nil
}

// Name returns "hull".
func (r *NativeRuntime) Name() string { return NativeName }

// Root returns the runtime state directory.
func (r *NativeRuntime) Root() string { return r.root }

// SetInitBinary supplies the hull-init image explicitly, bypassing the search
// on disk. It is how tests and a single-binary distribution hand hull the
// container stage.
func (r *NativeRuntime) SetInitBinary(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("runtime: SetInitBinary was given no bytes")
	}
	r.initOnce.Do(func() {})
	r.initBin = b
	r.initPath = "<supplied by the caller>"
	r.initErr = nil
	return nil
}

// InitBinaryPath reports where the hull-init image was loaded from.
func (r *NativeRuntime) InitBinaryPath() string {
	r.loadInit()
	return r.initPath
}

// loadInit finds and reads hull-init exactly once.
func (r *NativeRuntime) loadInit() error {
	r.initOnce.Do(func() {
		var tried []string
		var candidates []string
		if p := os.Getenv(InitBinaryEnv); p != "" {
			candidates = append(candidates, p)
		}
		if exe, err := os.Executable(); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(exe), "hull-init"))
		}
		candidates = append(candidates, initSearchPaths...)
		for _, c := range candidates {
			b, err := os.ReadFile(c)
			if err != nil {
				tried = append(tried, fmt.Sprintf("%s (%v)", c, err))
				continue
			}
			if len(b) < 4 || string(b[:4]) != "\x7fELF" {
				tried = append(tried, fmt.Sprintf("%s (not an ELF binary)", c))
				continue
			}
			r.initBin, r.initPath = b, c
			return
		}
		r.initErr = fmt.Errorf("runtime: cannot find the hull-init binary; tried %s. "+
			"Build it with 'make build' and install it next to hulld, or set %s: %w",
			strings.Join(tried, ", "), InitBinaryEnv, ErrUnsupported)
	})
	if r.initErr == nil && len(r.initBin) == 0 {
		return fmt.Errorf("runtime: the hull-init binary is empty: %w", ErrUnsupported)
	}
	return r.initErr
}

// requireFeatures refuses to start a container the kernel cannot actually
// isolate, with a message that names the missing facility and what to do.
func (r *NativeRuntime) requireFeatures() error {
	var missing []string
	if !r.features.PidfdSendSignal {
		missing = append(missing, "pidfd_send_signal(2) (Linux 5.1); without it hull would have to "+
			"signal containers by pid, which races pid reuse")
	}
	if !r.features.UserNamespaces {
		// Not fatal: a privileged daemon can still run host-uid containers.
		_ = missing
	}
	if len(missing) > 0 {
		return fmt.Errorf("runtime: this kernel (%s) is missing %s: %w",
			r.features.Kernel, strings.Join(missing, "; "), ErrUnsupported)
	}
	return nil
}

// ---------- Create ----------

// Create builds the container and leaves its init process blocked on the start
// pipe. The order of operations is fixed and security-relevant:
//
//  1. read and validate the bundle;
//  2. create the cgroup, so the child can be born inside it and is never
//     unconstrained even for an instant;
//  3. open the handshake socketpair;
//  4. seal hull-init into a memfd;
//  5. clone the child with the spec's namespace flags, letting the parent
//     write uid_map and gid_map (a process cannot usefully map itself) with
//     setgroups denied first;
//  6. hand the child its configuration over the socket and wait for it to
//     report that every irreversible step short of execve has succeeded.
func (r *NativeRuntime) Create(ctx context.Context, id, bundleDir string, opts CreateOptions) (st *Status, err error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	if err := r.requireFeatures(); err != nil {
		return nil, err
	}
	if err := r.loadInit(); err != nil {
		return nil, err
	}

	r.mu.Lock()
	_, dup := r.ctrs[id]
	r.mu.Unlock()
	if dup {
		return nil, fmt.Errorf("%s: %w", id, ErrExists)
	}
	dir := filepath.Join(r.root, id)
	if _, serr := os.Stat(dir); serr == nil {
		return nil, fmt.Errorf("%s: %w", id, ErrExists)
	}

	bundle, err := filepath.Abs(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("runtime: resolve bundle %q: %w", bundleDir, err)
	}
	spec, err := LoadSpec(bundle)
	if err != nil {
		return nil, err
	}
	if spec.Process == nil {
		return nil, fmt.Errorf("runtime: bundle %s has no process block", bundle)
	}
	if spec.Root == nil {
		return nil, fmt.Errorf("runtime: bundle %s has no root block", bundle)
	}
	rootfs := spec.Root.Path
	if !filepath.IsAbs(rootfs) {
		rootfs = filepath.Join(bundle, rootfs)
	}
	rootfs = filepath.Clean(rootfs)
	if fi, serr := os.Stat(rootfs); serr != nil || !fi.IsDir() {
		return nil, fmt.Errorf("runtime: container root %s is not a directory: %v", rootfs, serr)
	}
	if opts.Terminal != spec.Process.Terminal {
		return nil, fmt.Errorf("runtime: CreateOptions.Terminal is %v but the bundle says %v; "+
			"they must agree", opts.Terminal, spec.Process.Terminal)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("runtime: create state dir %s: %w", dir, err)
	}
	c := &nativeContainer{
		id: id, bundle: bundle, dir: dir, rootfs: rootfs, spec: spec,
		done: make(chan struct{}),
		status: Status{
			ID: id, Bundle: bundle, Status: StatusCreating,
			Created: time.Now().UTC(), Annotations: spec.Annotations,
		},
	}
	defer func() {
		if err != nil {
			c.cleanup()
			os.RemoveAll(dir)
		}
	}()

	// 2. cgroup, before anything is cloned.
	if err = r.setupCgroup(c, opts); err != nil {
		return nil, err
	}

	// 3. handshake socketpair, and the start pipe.
	parentSock, childSock, err := seqpacketPair(id)
	if err != nil {
		return nil, err
	}
	defer childSock.Close()
	c.sock = parentSock

	startR, startW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("runtime: create start pipe for %s: %w", id, err)
	}
	defer startR.Close()
	c.startW = startW

	// 4. hull-init, sealed into a memfd. This is the whole of the
	// CVE-2019-5736 mitigation: the binary the container is about to run is
	// immutable and anonymous, and is not the daemon.
	memfd, err := initspec.SealedMemfd("hull-init", r.initBin)
	if err != nil {
		return nil, err
	}
	defer memfd.Close()

	// 5. the console, if any.
	var consoleSlave *os.File
	if opts.Terminal {
		master, slave, perr := openPTY()
		if perr != nil {
			return nil, perr
		}
		consoleSlave = slave
		defer consoleSlave.Close()
		c.console = master
		if opts.ConsoleSocket != "" {
			if serr := sendConsoleMaster(opts.ConsoleSocket, master); serr != nil {
				master.Close()
				c.console = nil
				return nil, serr
			}
		}
	}

	cmd, err := r.buildCommand(c, spec, opts, childSock, startR, consoleSlave, memfd)
	if err != nil {
		return nil, err
	}
	c.cmd = cmd

	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("runtime: clone container %s: %w", id, err)
	}
	pid := cmd.Process.Pid
	c.status.Pid = pid

	// The pidfd is taken immediately: from here on every signal hull sends
	// goes through it, so a pid recycled after an unnoticed exit can never
	// be signalled by mistake.
	if err = r.attachPidfd(c); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, err
	}

	if c.cg != nil && !r.features.CloneIntoCgroup {
		if aerr := c.cg.AddProcess(pid); aerr != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return nil, fmt.Errorf("runtime: move container %s into its cgroup: %w", id, aerr)
		}
	}

	cfg, err := r.buildInitConfig(c, spec, opts)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, err
	}
	if err = r.handshake(ctx, c, cfg); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, err
	}

	c.status.Status = StatusCreated
	if opts.PidFile != "" {
		if werr := os.WriteFile(opts.PidFile, []byte(strconv.Itoa(pid)+"\n"), 0o644); werr != nil {
			return nil, fmt.Errorf("runtime: write pid file %s: %w", opts.PidFile, werr)
		}
	}
	if serr := saveStatus(dir, &c.status); serr != nil {
		return nil, serr
	}

	r.mu.Lock()
	r.ctrs[id] = c
	r.mu.Unlock()
	go r.reap(c)

	out := c.status
	return &out, nil
}

// setupCgroup creates, or adopts, the cgroup the container is born into.
func (r *NativeRuntime) setupCgroup(c *nativeContainer, opts CreateOptions) error {
	wantsLimits := hasResourceLimits(c.spec)
	if opts.CgroupFD > 0 {
		// The caller already made one; hull only needs to know it exists.
		return nil
	}
	if r.cgErr != nil || !r.cgInfo.Usable() {
		if wantsLimits {
			return fmt.Errorf("runtime: container %s asks for resource limits but this host has no "+
				"usable cgroup v2 hierarchy. %s: %w", c.id, cgroups.HybridRemedy, ErrUnsupported)
		}
		return nil
	}
	path := c.spec.Linux.CgroupsPath
	if path == "" {
		path = "hull/" + c.id
	}
	cg, err := cgroups.New(r.cgInfo, path)
	if err != nil {
		if wantsLimits {
			return fmt.Errorf("runtime: create cgroup for %s: %w", c.id, err)
		}
		return nil
	}
	c.cg = cg
	if c.spec.Linux != nil && c.spec.Linux.Resources != nil {
		if err := applyResources(cg, c.spec.Linux.Resources); err != nil {
			return fmt.Errorf("runtime: apply resources to %s: %w", c.id, err)
		}
	}
	return nil
}

func hasResourceLimits(spec *runtimespec.Spec) bool {
	if spec.Linux == nil || spec.Linux.Resources == nil {
		return false
	}
	res := spec.Linux.Resources
	return res.Memory != nil || res.CPU != nil || res.Pids != nil || res.BlockIO != nil ||
		len(res.Unified) > 0
}

// buildCommand assembles the exec.Cmd that clones the container.
//
// Path is /proc/self/fd/<FDSelf>: at execve time that descriptor is the sealed
// memfd holding hull-init. The daemon binary is never named, so a container
// that can write to a file cannot arrange to be re-exec'd from it.
func (r *NativeRuntime) buildCommand(c *nativeContainer, spec *runtimespec.Spec, opts CreateOptions,
	childSock, startR, consoleSlave, memfd *os.File) (*exec.Cmd, error) {

	flags, nsPaths, userns, err := cloneFlagsFor(spec)
	if err != nil {
		return nil, err
	}
	c.status.Annotations = spec.Annotations

	placeholder := consoleSlave
	if placeholder == nil {
		devNull, oerr := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if oerr != nil {
			return nil, fmt.Errorf("runtime: open %s: %w", os.DevNull, oerr)
		}
		placeholder = devNull
	}

	cmd := &exec.Cmd{
		Path: initspec.ProcFD(initspec.FDSelf),
		Args: []string{initspec.ArgvName, initspec.StageFlagPrefix + initspec.StageInit},
		// hull-init reads nothing from the environment. A minimal one is
		// passed so a stray inherited value cannot reach the container.
		Env: []string{"HULL_STAGE=" + initspec.StageInit},
		Dir: "/",
		// ExtraFiles land on 3, 4, 5, 6 in that order, matching the
		// initspec.FD* constants.
		ExtraFiles: []*os.File{childSock, startR, placeholder, memfd},
	}
	if placeholder != consoleSlave {
		// Close hull's copy once the child has been cloned.
		defer placeholder.Close()
	}
	if !opts.Terminal {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = opts.Stdin, opts.Stdout, opts.Stderr
	}

	pidfd := -1
	sys := &syscall.SysProcAttr{
		Cloneflags: flags,
		Setsid:     true,
		// Ask the kernel for a pidfd at clone time. It is the only way to
		// get one that cannot possibly refer to a recycled pid, because it
		// is created before the child can exit.
		PidFD: &pidfd,
	}
	if userns {
		uid, gid := idMappings(spec)
		if len(uid) == 0 || len(gid) == 0 {
			return nil, fmt.Errorf("runtime: container %s asks for a user namespace but the bundle "+
				"has no uidMappings/gidMappings: %w", c.id, ErrUnsupported)
		}
		sys.UidMappings = uid
		sys.GidMappings = gid
		// setgroups is denied before the gid map is written, so the
		// container cannot drop a supplementary group to gain access to a
		// host file (CVE-2014-8989).
		sys.GidMappingsEnableSetgroups = false
	}
	if c.cg != nil && r.features.CloneIntoCgroup {
		fd, ferr := c.cg.FD()
		if ferr != nil {
			return nil, fmt.Errorf("runtime: open cgroup dir for %s: %w", c.id, ferr)
		}
		sys.UseCgroupFD = true
		sys.CgroupFD = fd
	} else if opts.CgroupFD > 0 && r.features.CloneIntoCgroup {
		sys.UseCgroupFD = true
		sys.CgroupFD = opts.CgroupFD
	}
	cmd.SysProcAttr = sys

	if len(nsPaths) > 0 {
		c.status.Annotations = spec.Annotations
	}
	return cmd, nil
}

// attachPidfd records a pidfd for the container's init process, preferring the
// one clone3 handed back over a separate pidfd_open.
func (r *NativeRuntime) attachPidfd(c *nativeContainer) error {
	if c.cmd.SysProcAttr != nil && c.cmd.SysProcAttr.PidFD != nil && *c.cmd.SysProcAttr.PidFD >= 0 {
		c.pidfd = os.NewFile(uintptr(*c.cmd.SysProcAttr.PidFD), "pidfd:"+c.id)
		return nil
	}
	f, err := initspec.PidfdOpen(c.cmd.Process.Pid)
	if err != nil {
		return fmt.Errorf("runtime: take a pidfd for container %s: %w", c.id, err)
	}
	c.pidfd = f
	return nil
}

// handshake sends the container configuration and waits for the child to
// report readiness, honouring context cancellation.
func (r *NativeRuntime) handshake(ctx context.Context, c *nativeContainer, cfg *initspec.Config) error {
	sockFD := int(c.sock.Fd())
	if err := initspec.SendMessage(sockFD, &initspec.Message{Type: initspec.MsgConfig, Cfg: cfg}); err != nil {
		return fmt.Errorf("runtime: send config to container %s: %w", c.id, err)
	}

	type result struct {
		msg *initspec.Message
		err error
	}
	ch := make(chan result, 1)
	go func() {
		m, err := initspec.RecvMessage(sockFD)
		ch <- result{m, err}
	}()

	select {
	case <-ctx.Done():
		c.sock.Close()
		return fmt.Errorf("runtime: waiting for container %s to become ready: %w", c.id, ctx.Err())
	case res := <-ch:
		if res.err != nil {
			return fmt.Errorf("runtime: container %s never reported ready: %w", c.id, res.err)
		}
		switch res.msg.Type {
		case initspec.MsgReady:
			return nil
		case initspec.MsgError:
			return fmt.Errorf("runtime: container %s failed to start: %s", c.id, res.msg.Err)
		default:
			return fmt.Errorf("runtime: container %s sent an unexpected %q message", c.id, res.msg.Type)
		}
	}
}

// buildInitConfig translates the bundle into the container stage's
// configuration. Nothing container-controlled is read here: the spec is
// hull's own file, and every path in it is resolved by the stage fd-relative.
func (r *NativeRuntime) buildInitConfig(c *nativeContainer, spec *runtimespec.Spec, opts CreateOptions) (*initspec.Config, error) {
	cfg := &initspec.Config{
		ID:             c.id,
		Rootfs:         c.rootfs,
		RootfsReadonly: spec.Root.Readonly,
		Hostname:       spec.Hostname,
		Domainname:     spec.Domainname,
		Mounts:         spec.Mounts,
		Exec: initspec.Exec{
			Process:  *spec.Process,
			Terminal: opts.Terminal,
		},
		Features: initspec.StageFeatures{
			MountAPI:         r.features.MountAPI,
			Openat2:          r.features.Openat2,
			CloseRange:       r.features.CloseRange,
			SeccompSpecAllow: true,
		},
	}
	if spec.Linux != nil {
		cfg.RootfsPropagation = spec.Linux.RootfsPropagation
		cfg.MaskedPaths = spec.Linux.MaskedPaths
		cfg.ReadonlyPaths = spec.Linux.ReadonlyPaths
		cfg.Sysctl = spec.Linux.Sysctl
		cfg.Devices = spec.Linux.Devices
		cfg.Exec.Seccomp = spec.Linux.Seccomp
		_, nsPaths, userns, err := cloneFlagsFor(spec)
		if err != nil {
			return nil, err
		}
		cfg.NamespacePaths = nsPaths
		cfg.UserNS = userns
	}
	if cfg.Exec.Seccomp != nil && !r.features.Seccomp {
		return nil, fmt.Errorf("runtime: container %s has a seccomp profile but this kernel has no "+
			"seccomp(2); refusing to run it unconfined: %w", c.id, ErrUnsupported)
	}
	if cfg.Exec.Seccomp != nil {
		// Compile on the host so a bad profile is a Create error with a
		// clear message, not an opaque failure inside the container.
		if _, err := initspec.CompileSeccomp(cfg.Exec.Seccomp); err != nil {
			return nil, fmt.Errorf("runtime: container %s seccomp profile: %w", c.id, err)
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("runtime: container %s: %w", c.id, err)
	}
	return cfg, nil
}

// reap waits for the container's init process and records its exit.
func (r *NativeRuntime) reap(c *nativeContainer) {
	err := c.cmd.Wait()
	c.mu.Lock()
	c.waited = true
	c.status.Exited = true
	c.status.Status = StatusStopped
	c.status.Pid = 0
	if c.cmd.ProcessState != nil {
		if ws, ok := c.cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			c.status.ExitCode = ExitCodeOf(ws)
		} else {
			c.status.ExitCode = c.cmd.ProcessState.ExitCode()
		}
	} else if err != nil {
		c.status.ExitCode = 255
	}
	if c.cg != nil {
		if st, serr := c.cg.Stat(); serr == nil && st.OOMKills > 0 {
			c.status.OOMKilled = true
		}
	}
	st := c.status
	c.mu.Unlock()
	_ = saveStatus(c.dir, &st)
	close(c.done)
}

// cleanup closes every descriptor a container holds. It is safe to call twice.
func (c *nativeContainer) cleanup() {
	for _, f := range []**os.File{&c.sock, &c.startW, &c.console, &c.pidfd} {
		if *f != nil {
			(*f).Close()
			*f = nil
		}
	}
}

// ---------- lifecycle ----------

// Start releases the container's init process, which then execs the
// entrypoint. It is a single byte on the start pipe: the child has been
// blocked reading it since Create returned.
func (r *NativeRuntime) Start(ctx context.Context, id string) error {
	c, err := r.lookup(id)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.Status != StatusCreated {
		return fmt.Errorf("runtime: container %s is %s, not created: %w", id, c.status.Status, ErrNotRunning)
	}
	if c.startW == nil {
		return fmt.Errorf("runtime: container %s has no start pipe; it was not created by this process: %w",
			id, ErrUnsupported)
	}
	if _, err := c.startW.Write([]byte{0}); err != nil {
		return fmt.Errorf("runtime: signal container %s to start: %w", id, err)
	}
	c.startW.Close()
	c.startW = nil
	c.status.Status = StatusRunning
	st := c.status
	return saveStatus(c.dir, &st)
}

// State reports what hull knows about a container. Liveness is confirmed
// through the pidfd rather than by looking at /proc, so a recycled pid is
// never mistaken for a live container.
func (r *NativeRuntime) State(ctx context.Context, id string) (*Status, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	r.mu.Lock()
	c := r.ctrs[id]
	r.mu.Unlock()
	if c == nil {
		st, err := loadStatus(filepath.Join(r.root, id))
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("%s: %w", id, ErrNotFound)
			}
			return nil, err
		}
		return st, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.status.Exited && c.pidfd != nil && !initspec.PidfdAlive(int(c.pidfd.Fd())) {
		// The reaper will fill in the exit code; report what is certain.
		c.status.Status = StatusStopped
	}
	if c.cg != nil && c.status.Status == StatusRunning {
		if frozen, err := c.cg.Frozen(); err == nil && frozen {
			c.status.Status = StatusPaused
		}
	}
	out := c.status
	return &out, nil
}

// Kill signals the container.
//
// The init process is always signalled through its pidfd: pids are recycled,
// and a stale pid is a host process. "all" uses cgroup.kill where the kernel
// has it, which is atomic against a fork bomb in a way that walking
// cgroup.procs is not.
func (r *NativeRuntime) Kill(ctx context.Context, id string, sig syscall.Signal, all bool) error {
	c, err := r.lookup(id)
	if err != nil {
		return err
	}
	c.mu.Lock()
	exited := c.status.Exited
	cg := c.cg
	c.mu.Unlock()
	if exited {
		return fmt.Errorf("container %s: %w", id, ErrNotRunning)
	}
	if all {
		if sig == unix.SIGKILL && cg != nil && r.features.CgroupKill {
			if err := cg.Kill(); err == nil {
				return nil
			}
		}
		if cg != nil {
			pids, perr := cg.Procs()
			if perr == nil && len(pids) > 0 {
				var firstErr error
				for _, p := range pids {
					f, oerr := initspec.PidfdOpen(p)
					if oerr != nil {
						continue
					}
					if serr := initspec.PidfdSendSignal(int(f.Fd()), unix.Signal(sig)); serr != nil && firstErr == nil {
						firstErr = serr
					}
					f.Close()
				}
				return firstErr
			}
		}
		// No cgroup to enumerate: the init process is in its own pid
		// namespace, so signalling it is the closest honest approximation.
		if cg == nil {
			return r.signalInit(c, sig, fmt.Sprintf(
				"container %s has no cgroup, so hull cannot signal every process in it; "+
					"signalling the init process only", id))
		}
	}
	return r.signalInit(c, sig, "")
}

func (r *NativeRuntime) signalInit(c *nativeContainer, sig syscall.Signal, note string) error {
	c.mu.Lock()
	pidfd := c.pidfd
	c.mu.Unlock()
	if pidfd == nil {
		return fmt.Errorf("runtime: container %s has no pidfd; it was not created by this process: %w",
			c.id, ErrUnsupported)
	}
	if err := initspec.PidfdSendSignal(int(pidfd.Fd()), unix.Signal(sig)); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("container %s: %w", c.id, ErrNotRunning)
		}
		if note != "" {
			return fmt.Errorf("%s: %w", note, err)
		}
		return err
	}
	return nil
}

// Pause freezes every process in the container with cgroup.freeze.
func (r *NativeRuntime) Pause(ctx context.Context, id string) error {
	c, err := r.lookup(id)
	if err != nil {
		return err
	}
	if c.cg == nil {
		return fmt.Errorf("runtime: cannot pause %s: it has no cgroup. %s: %w",
			id, cgroups.HybridRemedy, ErrUnsupported)
	}
	if err := c.cg.Freeze(); err != nil {
		return fmt.Errorf("runtime: pause %s: %w", id, err)
	}
	c.mu.Lock()
	c.status.Status = StatusPaused
	st := c.status
	c.mu.Unlock()
	return saveStatus(c.dir, &st)
}

// Resume thaws a paused container.
func (r *NativeRuntime) Resume(ctx context.Context, id string) error {
	c, err := r.lookup(id)
	if err != nil {
		return err
	}
	if c.cg == nil {
		return fmt.Errorf("runtime: cannot resume %s: it has no cgroup: %w", id, ErrUnsupported)
	}
	if err := c.cg.Thaw(); err != nil {
		return fmt.Errorf("runtime: resume %s: %w", id, err)
	}
	c.mu.Lock()
	c.status.Status = StatusRunning
	st := c.status
	c.mu.Unlock()
	return saveStatus(c.dir, &st)
}

// Delete removes a stopped container's cgroup and runtime state. force kills
// it first and waits for it to be reaped.
func (r *NativeRuntime) Delete(ctx context.Context, id string, force bool) error {
	if err := ValidID(id); err != nil {
		return err
	}
	r.mu.Lock()
	c := r.ctrs[id]
	r.mu.Unlock()
	if c == nil {
		dir := filepath.Join(r.root, id)
		if _, err := os.Stat(dir); err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		return os.RemoveAll(dir)
	}

	c.mu.Lock()
	exited := c.status.Exited
	c.mu.Unlock()
	if !exited {
		if !force {
			return fmt.Errorf("container %s: %w", id, ErrRunning)
		}
		if c.cg != nil && r.features.CgroupKill {
			_ = c.cg.Kill()
		}
		_ = r.signalInit(c, unix.SIGKILL, "")
		select {
		case <-c.done:
		case <-time.After(10 * time.Second):
			return fmt.Errorf("runtime: container %s did not exit within 10s of SIGKILL", id)
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	c.cleanup()
	if c.cg != nil {
		if err := c.cg.Delete(); err != nil {
			return fmt.Errorf("runtime: remove cgroup for %s: %w", id, err)
		}
	}
	r.mu.Lock()
	delete(r.ctrs, id)
	r.mu.Unlock()
	if err := os.RemoveAll(c.dir); err != nil {
		return fmt.Errorf("runtime: remove state dir for %s: %w", id, err)
	}
	return nil
}

func (r *NativeRuntime) lookup(id string) (*nativeContainer, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	r.mu.Lock()
	c := r.ctrs[id]
	r.mu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("%s: %w", id, ErrNotFound)
	}
	return c, nil
}

// Features reports the driver and the host probe, caching nothing that the
// probe has not already cached.
func (r *NativeRuntime) Features(ctx context.Context) (RuntimeFeatures, error) {
	probe, err := ProbeFeatures(ctx)
	if err != nil {
		return RuntimeFeatures{}, err
	}
	r.features = probe
	f := RuntimeFeatures{
		Name:           NativeName,
		Version:        "hull-native",
		OCIVersions:    []string{runtimespec.Version},
		Kernel:         probe.Kernel,
		Namespaces:     []string{"cgroup", "ipc", "mount", "network", "pid", "user", "uts"},
		Capabilities:   initspec.CapNames(),
		SeccompEnabled: probe.Seccomp,
		SeccompActions: probe.SeccompActions,
		Probe:          probe,
		Warnings:       probe.Warnings,
	}
	if err := r.loadInit(); err != nil {
		f.Warnings = append(f.Warnings, err.Error())
	}
	return f, nil
}

// ---------- helpers ----------

// cloneFlagsFor turns the spec's namespace list into clone(2) flags, the set
// of namespaces to join by path, and whether a user namespace is created.
func cloneFlagsFor(spec *runtimespec.Spec) (uintptr, map[string]string, bool, error) {
	var flags uintptr
	paths := map[string]string{}
	userns := false
	haveMount := false
	if spec.Linux == nil {
		return 0, nil, false, fmt.Errorf("runtime: bundle has no linux block; the native runtime needs one")
	}
	for _, ns := range spec.Linux.Namespaces {
		name := string(ns.Type)
		if ns.Path != "" {
			switch name {
			case "pid", "user":
				return 0, nil, false, fmt.Errorf("runtime: joining an existing %s namespace by path is "+
					"not supported by the native runtime; use --runtime crun for that container: %w",
					name, ErrUnsupported)
			}
			paths[name] = ns.Path
			if name == "mount" {
				haveMount = true
			}
			continue
		}
		flag, ok := initspec.NamespaceFlag(name)
		if !ok {
			return 0, nil, false, fmt.Errorf("runtime: unknown namespace type %q", name)
		}
		flags |= uintptr(flag)
		switch name {
		case "user":
			userns = true
		case "mount":
			haveMount = true
		}
	}
	if !haveMount {
		return 0, nil, false, fmt.Errorf("runtime: the native runtime always needs a mount namespace; "+
			"add {\"type\":\"mount\"} to linux.namespaces: %w", ErrUnsupported)
	}
	if len(paths) == 0 {
		paths = nil
	}
	return flags, paths, userns, nil
}

func idMappings(spec *runtimespec.Spec) ([]syscall.SysProcIDMap, []syscall.SysProcIDMap) {
	var uid, gid []syscall.SysProcIDMap
	for _, m := range spec.Linux.UIDMappings {
		uid = append(uid, syscall.SysProcIDMap{
			ContainerID: int(m.ContainerID), HostID: int(m.HostID), Size: int(m.Size),
		})
	}
	for _, m := range spec.Linux.GIDMappings {
		gid = append(gid, syscall.SysProcIDMap{
			ContainerID: int(m.ContainerID), HostID: int(m.HostID), Size: int(m.Size),
		})
	}
	return uid, gid
}

// applyResources maps the runtime-spec resource block onto the cgroup driver's
// types.Resources vocabulary.
func applyResources(cg *cgroups.Manager, res *runtimespec.LinuxResources) error {
	r := resourcesFromSpec(res)
	if err := cg.Apply(r); err != nil {
		return err
	}
	if res.Pids != nil && res.Pids.Limit > 0 {
		if err := cg.SetPidsLimit(res.Pids.Limit); err != nil {
			return err
		}
	}
	if res.CPU != nil && res.CPU.Burst != nil {
		if err := cg.SetCPUBurst(*res.CPU.Burst); err != nil {
			return err
		}
	}
	return nil
}

// seqpacketPair creates the handshake socket. SOCK_SEQPACKET keeps message
// boundaries, so a config that needs several kernel buffers can never be
// spliced into the ready message.
func seqpacketPair(id string) (parent, child *os.File, err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("runtime: socketpair for %s: %w", id, err)
	}
	return os.NewFile(uintptr(fds[0]), "hull-sync-parent:"+id),
		os.NewFile(uintptr(fds[1]), "hull-sync-child:"+id), nil
}

// drainTo copies from r to w until r is exhausted, ignoring the "input/output
// error" a pty master reports when its last slave closes.
func drainTo(w io.Writer, r io.Reader) {
	_, err := io.Copy(w, r)
	if err != nil && !errors.Is(err, unix.EIO) {
		return
	}
}
