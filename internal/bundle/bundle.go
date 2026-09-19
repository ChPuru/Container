// Package bundle translates hull's domain model — a types.Container plus the
// types.Image it was created from — into an OCI runtime-spec v1.2 config.json.
//
// This is the layer where "docker run flags" become "what the kernel actually
// does", so it is deliberately explicit: every default it inserts is written
// out, every feature it cannot provide produces a warning or an error, and it
// never guesses about kernel capability. Callers pass an Options.Features
// describing what the running kernel really supports (see internal/hostinfo);
// bundle refuses to emit a spec that would silently be weaker than asked for.
//
// The package performs a small amount of I/O — it reads the container's
// /etc/passwd and /etc/group to resolve a user, and stats bind sources and
// device nodes — but it never writes anything except through Write. Every read
// of a container-controlled path goes through internal/fsutil.SecureOpen, which
// resolves with openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS) or an
// fd-relative walk; filepath.Join on a container rootfs never appears here.
//
// The package builds on every GOOS so the Windows hull CLI can reuse
// TranslateWindowsPath, though a full Generate is only meaningful on Linux.
package bundle

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
	"github.com/rahuldhali/hull/internal/types"
)

// DefaultPath is the PATH hull guarantees is present in every container's
// environment when neither the image nor the user supplied one.
const DefaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// DefaultShmSize is the size of /dev/shm when HostConfig.ShmSize is zero.
const DefaultShmSize int64 = 64 << 20

// InitTarget is the in-container path the hull init shim is bind-mounted at
// when Options.Init is set. It is deliberately not /proc/self/exe and not a
// copy of the daemon binary: re-executing the daemon inside the container is
// CVE-2019-5736.
const InitTarget = "/.hull-init"

// AnnotationNoPivot is set on the spec when Options.NoPivot is requested. The
// runtime-spec has no field for it, so hull's native runtime and its crun
// driver read this annotation instead.
const AnnotationNoPivot = "org.hull.no-pivot"

// AnnotationContainerID and AnnotationContainerName record the hull identity of
// the container in the bundle, so a bundle on disk is self-describing.
const (
	AnnotationContainerID   = "org.hull.container.id"
	AnnotationContainerName = "org.hull.container.name"
)

// ErrNoCommand is returned by Generate when neither the image nor the container
// supplies anything to execute.
var ErrNoCommand = errors.New("bundle: no command specified")

// UserNS describes the user namespace the container runs in. A nil *UserNS in
// Options means the container shares the host user namespace.
type UserNS struct {
	// UIDMappings and GIDMappings are the /proc/<pid>/uid_map and gid_map
	// lines, container id first. They are copied onto linux.uidMappings and,
	// when the kernel supports idmapped mounts, onto every host bind mount.
	UIDMappings []runtimespec.LinuxIDMapping
	GIDMappings []runtimespec.LinuxIDMapping
}

// Features is what the kernel under this daemon actually supports. hull probes
// this once at startup (internal/hostinfo) and hands the answer down; bundle
// never assumes a capability it was not told about.
type Features struct {
	// IdmappedMounts reports that mount_setattr(MOUNT_ATTR_IDMAP) works for
	// the filesystems hull bind-mounts from. Kernel 5.15 has it for ext4 and
	// btrfs but not for overlay layers (5.19) or tmpfs (6.3).
	IdmappedMounts bool
	// CgroupV2 reports a unified hierarchy with controllers delegated. On the
	// hybrid WSL 2.4.13 layout this is false and resource limits are refused
	// rather than silently dropped.
	CgroupV2 bool
	// Seccomp reports CONFIG_SECCOMP_FILTER.
	Seccomp bool
	// Landlock reports Landlock ABI >= 1. bundle does not emit Landlock rules
	// itself; the field travels with the rest of the probe for the runtime.
	Landlock bool
	// KernelMajor and KernelMinor are the running kernel version. Zero means
	// "unknown", in which case version-gated checks assume a modern kernel and
	// leave the real decision to the explicit booleans above.
	KernelMajor int
	KernelMinor int
}

// kernelAtLeast reports whether the probed kernel is at least maj.min. An
// unknown kernel version (major 0) is treated as new enough: the caller is
// expected to gate anything genuinely risky on an explicit feature bool.
func (f Features) kernelAtLeast(maj, min int) bool {
	if f.KernelMajor == 0 {
		return true
	}
	if f.KernelMajor != maj {
		return f.KernelMajor > maj
	}
	return f.KernelMinor >= min
}

// SeccompFunc builds a seccomp filter for a resolved capability set. It matches
// the signature of internal/seccompprof.ForCapabilities so the daemon can wire
// that package in without bundle depending on it.
type SeccompFunc func(caps []string, privileged bool) *runtimespec.LinuxSeccomp

// Options are the host-side facts bundle cannot derive from the container
// record: where the rootfs is, what the kernel can do, and what the engine has
// already prepared on disk.
type Options struct {
	// RootFS is the merged overlay path that becomes root.path.
	RootFS string
	// BundleDir is where Write places config.json.
	BundleDir string
	// CgroupsPath is the cgroup v2 path relative to the root of the hierarchy,
	// e.g. "hull/<id>".
	CgroupsPath string
	// UserNS is the user namespace mapping, or nil for the host namespace.
	UserNS *UserNS
	// Hostname overrides ContainerConfig.Hostname when non-empty.
	Hostname string
	// Init injects the hull init shim as pid 1 so orphaned children are reaped.
	Init bool
	// InitPath is the host path of the init binary bind-mounted at InitTarget.
	InitPath string
	// NoPivot asks the runtime to use MS_MOVE + chroot instead of pivot_root.
	// It is recorded as AnnotationNoPivot; pivot_root is always preferred.
	NoPivot bool
	// Features is the kernel feature probe result.
	Features Features

	// VolumePaths maps a named volume to its host directory. Every
	// HostConfig.Mounts entry of type "volume" must have an entry here.
	VolumePaths map[string]string
	// ImageVolumePaths maps an image VOLUME destination to the host directory
	// of the anonymous volume the engine created for it. A destination with no
	// entry produces a warning rather than an unbacked mount.
	ImageVolumePaths map[string]string

	// NetworkNSPath joins an existing network namespace. When NetworkMode is
	// "container:<id>" and this is empty, SharedNetworkPID is used instead.
	NetworkNSPath string
	// SharedNetworkPID is the pid of the container whose network namespace this
	// container joins; it becomes /proc/<pid>/ns/net.
	SharedNetworkPID int

	// SeccompProfile builds the seccomp filter. When nil, DefaultSeccompProfile
	// is used. Set it to seccompprof.ForCapabilities in the daemon.
	SeccompProfile SeccompFunc

	// Annotations are merged into the spec's annotations, after hull's own.
	Annotations map[string]string
}

// builder carries the per-call state of a Generate, mainly so warnings can be
// collected from every corner of the translation without threading a pointer
// through fifteen signatures.
type builder struct {
	c    *types.Container
	img  *types.Image
	opts Options

	privileged bool
	hostname   string
	warnings   []string
}

func (b *builder) warnf(format string, args ...any) {
	b.warnings = append(b.warnings, fmt.Sprintf(format, args...))
}

// Generate translates a container and its image into a complete runtime-spec.
//
// It returns the spec, a list of human-readable warnings the caller should
// print (ownership caveats under a user namespace, unbacked image volumes,
// ignored security options), and an error. A warning never hides a failure:
// anything hull cannot do correctly is an error, not a warning.
//
// Generate reads the container rootfs (for /etc/passwd and /etc/group) and
// stats host bind sources, so it must run on the host that will start the
// container.
func Generate(c *types.Container, img *types.Image, opts Options) (*runtimespec.Spec, []string, error) {
	if c == nil {
		return nil, nil, errors.New("bundle: nil container")
	}
	if img == nil {
		return nil, nil, errors.New("bundle: nil image")
	}
	if opts.RootFS == "" {
		return nil, nil, errors.New("bundle: Options.RootFS is empty; the overlay must be mounted before the bundle is generated")
	}

	b := &builder{c: c, img: img, opts: opts, privileged: c.HostConfig.Privileged}
	b.hostname = resolveHostname(c, opts)

	args, err := ResolveArgs(c, img)
	if err != nil {
		return nil, nil, err
	}

	cwd := c.Config.WorkingDir
	if cwd == "" {
		cwd = img.Config.WorkingDir
	}
	if cwd == "" {
		cwd = "/"
	}
	if !strings.HasPrefix(cwd, "/") {
		return nil, nil, fmt.Errorf("bundle: working directory %q must be an absolute path", cwd)
	}
	cwd = path.Clean(cwd)

	usr, err := b.resolveUser()
	if err != nil {
		return nil, nil, err
	}

	env, err := b.buildEnv(usr.Home)
	if err != nil {
		return nil, nil, err
	}

	caps, err := b.resolveCapabilities()
	if err != nil {
		return nil, nil, err
	}

	sec, err := parseSecurityOpt(c.HostConfig.SecurityOpt)
	if err != nil {
		return nil, nil, err
	}
	for _, ig := range sec.ignored {
		b.warnf("security-opt %q is not enforced on this kernel (WSL ships no AppArmor and no SELinux) and was ignored", ig)
	}

	mounts, err := b.buildMounts()
	if err != nil {
		return nil, nil, err
	}

	if opts.Init {
		if opts.InitPath == "" {
			return nil, nil, errors.New("bundle: Init requested but Options.InitPath is empty")
		}
		if err := checkHostPath(opts.InitPath, "init binary"); err != nil {
			return nil, nil, err
		}
		args = append([]string{InitTarget, "--"}, args...)
		mounts = append(mounts, runtimespec.Mount{
			Destination: InitTarget,
			Type:        "bind",
			Source:      opts.InitPath,
			Options:     []string{"rbind", "rprivate", "ro", "nosuid", "nodev"},
		})
	}

	mounts = dedupeMounts(mounts)
	b.applyIDMappedBinds(mounts)
	sortMountsByDepth(mounts)

	namespaces, err := b.buildNamespaces()
	if err != nil {
		return nil, nil, err
	}

	sysctls, err := b.buildSysctls()
	if err != nil {
		return nil, nil, err
	}

	resources, devices, err := b.buildResources()
	if err != nil {
		return nil, nil, err
	}

	rlimits, err := buildRlimits(c.HostConfig.Ulimits)
	if err != nil {
		return nil, nil, err
	}

	proc := &runtimespec.Process{
		Terminal: c.Config.Tty,
		User: runtimespec.User{
			UID:            usr.UID,
			GID:            usr.GID,
			Umask:          u32p(0o022),
			AdditionalGids: usr.AdditionalGids,
		},
		Args:            args,
		Env:             env,
		Cwd:             cwd,
		Capabilities:    capsToSpec(caps),
		Rlimits:         rlimits,
		NoNewPrivileges: sec.noNewPrivileges,
	}
	if c.HostConfig.OomScoreAdj != 0 {
		v := c.HostConfig.OomScoreAdj
		proc.OOMScoreAdj = &v
	}
	if b.privileged {
		proc.ApparmorProfile = "unconfined"
	} else if sec.apparmor != "" {
		proc.ApparmorProfile = sec.apparmor
	}

	seccomp, err := b.buildSeccomp(caps, sec)
	if err != nil {
		return nil, nil, err
	}

	lx := &runtimespec.Linux{
		Sysctl:            sysctls,
		Resources:         resources,
		CgroupsPath:       opts.CgroupsPath,
		Namespaces:        namespaces,
		Devices:           devices,
		Seccomp:           seccomp,
		RootfsPropagation: "rprivate",
	}
	if !b.privileged {
		lx.MaskedPaths = MaskedPaths()
		lx.ReadonlyPaths = ReadonlyPaths()
	}
	if opts.UserNS != nil {
		lx.UIDMappings = append([]runtimespec.LinuxIDMapping(nil), opts.UserNS.UIDMappings...)
		lx.GIDMappings = append([]runtimespec.LinuxIDMapping(nil), opts.UserNS.GIDMappings...)
	}

	annotations := map[string]string{
		AnnotationContainerID:   c.ID,
		AnnotationContainerName: c.Name,
	}
	if opts.NoPivot {
		annotations[AnnotationNoPivot] = "true"
	}
	for k, v := range opts.Annotations {
		annotations[k] = v
	}

	spec := &runtimespec.Spec{
		Version:     runtimespec.Version,
		Process:     proc,
		Root:        &runtimespec.Root{Path: opts.RootFS, Readonly: c.HostConfig.ReadonlyRootfs},
		Hostname:    b.hostname,
		Domainname:  c.Config.Domainname,
		Mounts:      mounts,
		Annotations: annotations,
		Linux:       lx,
		// Hooks stay nil on purpose: hull configures networking from the
		// daemon, where failures are visible, not from a hook the runtime runs
		// with the daemon's privileges and no error reporting.
	}

	if err := spec.Validate(); err != nil {
		return nil, nil, fmt.Errorf("bundle: generated spec is invalid: %w", err)
	}
	return spec, b.warnings, nil
}

// GenerateSpec is Generate without the warnings, for callers that only want the
// spec. Warnings describe real fidelity gaps (ownership under a user namespace,
// unbacked image volumes), so prefer Generate and print them.
func GenerateSpec(c *types.Container, img *types.Image, opts Options) (*runtimespec.Spec, error) {
	spec, _, err := Generate(c, img, opts)
	return spec, err
}

// resolveHostname picks the hostname: the explicit Options override, then the
// container config, then the first 12 characters of the container id, which is
// what Docker does.
func resolveHostname(c *types.Container, opts Options) string {
	if opts.Hostname != "" {
		return opts.Hostname
	}
	if c.Config.Hostname != "" {
		return c.Config.Hostname
	}
	if len(c.ID) >= 12 {
		return c.ID[:12]
	}
	if c.ID != "" {
		return c.ID
	}
	return "hull"
}

// buildNamespaces assembles linux.namespaces. pid, ipc, uts and mount are
// unconditional; network depends on NetworkMode; cgroup depends on the kernel;
// user depends on Options.UserNS.
func (b *builder) buildNamespaces() ([]runtimespec.LinuxNamespace, error) {
	ns := []runtimespec.LinuxNamespace{
		{Type: runtimespec.PIDNamespace},
		{Type: runtimespec.IPCNamespace},
		{Type: runtimespec.UTSNamespace},
		{Type: runtimespec.MountNamespace},
	}

	mode := b.c.HostConfig.NetworkMode
	switch {
	case mode == "host":
		// No network namespace: the container shares the root netns.
	case strings.HasPrefix(mode, "container:"):
		p := b.opts.NetworkNSPath
		if p == "" {
			if b.opts.SharedNetworkPID <= 0 {
				return nil, fmt.Errorf("bundle: network mode %q needs the target container's pid; set Options.SharedNetworkPID or Options.NetworkNSPath", mode)
			}
			p = fmt.Sprintf("/proc/%d/ns/net", b.opts.SharedNetworkPID)
		}
		ns = append(ns, runtimespec.LinuxNamespace{Type: runtimespec.NetworkNamespace, Path: p})
	default:
		ns = append(ns, runtimespec.LinuxNamespace{Type: runtimespec.NetworkNamespace})
	}

	// Cgroup namespaces landed in 4.6. Every kernel hull supports has them, but
	// the check is explicit so an ancient kernel gets a plain spec instead of a
	// runtime error from the OCI runtime.
	if b.opts.Features.kernelAtLeast(4, 6) {
		ns = append(ns, runtimespec.LinuxNamespace{Type: runtimespec.CgroupNamespace})
	}

	if b.opts.UserNS != nil {
		if len(b.opts.UserNS.UIDMappings) == 0 || len(b.opts.UserNS.GIDMappings) == 0 {
			return nil, errors.New("bundle: Options.UserNS requires at least one uid and one gid mapping")
		}
		for i, m := range b.opts.UserNS.UIDMappings {
			if m.Size == 0 {
				return nil, fmt.Errorf("bundle: Options.UserNS.UIDMappings[%d] has size 0", i)
			}
		}
		for i, m := range b.opts.UserNS.GIDMappings {
			if m.Size == 0 {
				return nil, fmt.Errorf("bundle: Options.UserNS.GIDMappings[%d] has size 0", i)
			}
		}
		ns = append(ns, runtimespec.LinuxNamespace{Type: runtimespec.UserNamespace})
	}
	return ns, nil
}

// applyIDMappedBinds annotates every host bind mount with the container's id
// mappings when the kernel can do it, and warns loudly when it cannot, because
// an un-idmapped bind under a user namespace shows up inside the container
// owned by an unmapped uid and silently breaks writes.
func (b *builder) applyIDMappedBinds(mounts []runtimespec.Mount) {
	if b.opts.UserNS == nil {
		return
	}
	for i := range mounts {
		m := &mounts[i]
		if m.Type != "bind" && m.Type != "rbind" {
			continue
		}
		if !strings.HasPrefix(m.Source, "/") {
			continue
		}
		if b.opts.Features.IdmappedMounts {
			m.UIDMappings = append([]runtimespec.LinuxIDMapping(nil), b.opts.UserNS.UIDMappings...)
			m.GIDMappings = append([]runtimespec.LinuxIDMapping(nil), b.opts.UserNS.GIDMappings...)
			continue
		}
		b.warnf("bind mount %s -> %s is not id-mapped: this %s cannot apply MOUNT_ATTR_IDMAP to it, "+
			"so host files will appear owned by an unmapped uid inside the container and writes may fail; "+
			"chown the host path into the container's uid range, or run with --userns=host",
			m.Source, m.Destination, b.kernelString())
	}
}

func (b *builder) kernelString() string {
	if b.opts.Features.KernelMajor == 0 {
		return "kernel"
	}
	return fmt.Sprintf("kernel %d.%d", b.opts.Features.KernelMajor, b.opts.Features.KernelMinor)
}

// dedupeMounts keeps the last entry for each destination, so a later mount
// shadows an earlier one, while preserving the relative order of survivors.
func dedupeMounts(ms []runtimespec.Mount) []runtimespec.Mount {
	seen := make(map[string]bool, len(ms))
	out := make([]runtimespec.Mount, 0, len(ms))
	for i := len(ms) - 1; i >= 0; i-- {
		d := path.Clean(ms[i].Destination)
		if seen[d] {
			continue
		}
		seen[d] = true
		m := ms[i]
		m.Destination = d
		out = append(out, m)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// sortMountsByDepth orders mounts so a parent directory is always mounted
// before anything mounted inside it. The sort is stable, so entries at the same
// depth keep the order the caller built them in.
func sortMountsByDepth(ms []runtimespec.Mount) {
	sort.SliceStable(ms, func(i, j int) bool {
		return mountDepth(ms[i].Destination) < mountDepth(ms[j].Destination)
	})
}

func mountDepth(dest string) int {
	return strings.Count(path.Clean(dest), "/")
}

func u32p(v uint32) *uint32 { return &v }
func i64p(v int64) *int64   { return &v }
func u64p(v uint64) *uint64 { return &v }
