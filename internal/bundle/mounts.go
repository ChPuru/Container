package bundle

import (
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
	"github.com/rahuldhali/hull/internal/types"
)

// ---------- Windows path translation ----------

// ErrUNCPath is returned by TranslateWindowsPath for a UNC bind source.
var ErrUNCPath = errors.New("bundle: UNC paths cannot be bind-mounted")

// TranslateWindowsPath converts a Windows bind source into the path the engine
// distro sees, so `hull run -v C:\Users\me\src:/src` works from PowerShell.
//
//	C:\Users\x      -> /mnt/c/Users/x
//	c:/Users/x      -> /mnt/c/Users/x
//	C:              -> /mnt/c
//	/mnt/c/Users/x  -> unchanged (already translated)
//	/srv/data       -> unchanged (a Linux path)
//	\\wsl$\Ubuntu\home\me      -> error
//	\\wsl.localhost\Ubuntu\... -> error
//	\\server\share             -> error
//
// A \\wsl$\ path is rejected rather than rewritten because it names a path
// through the 9p/virtiofs server of another distro: bind-mounting it would give
// the container a loopback view of a filesystem it is already inside, with
// different inode identity and no working file locking. The right answer is the
// distro-local path, and saying so is more useful than a mount that misbehaves
// under load.
//
// The function is exported so the CLI can translate paths before they reach the
// daemon, and so it can be unit tested from either platform.
func TranslateWindowsPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("bundle: empty bind source path")
	}

	// UNC: \\host\share or //host/share.
	if isUNC(p) {
		norm := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
		switch {
		case strings.HasPrefix(norm, "//wsl$/"), strings.HasPrefix(norm, "//wsl.localhost/"):
			return "", fmt.Errorf("%w: %q crosses back into WSL through the 9p share; "+
				"use the path as the engine distro sees it (for example /home/you/project), not the \\\\wsl$ view", ErrUNCPath, p)
		default:
			return "", fmt.Errorf("%w: %q is a network share; mount it inside WSL first and bind the local mountpoint", ErrUNCPath, p)
		}
	}

	// Drive-letter paths: C:\... , c:/... , C: .
	if len(p) >= 2 && isDriveLetter(p[0]) && p[1] == ':' {
		if len(p) > 2 && p[2] != '\\' && p[2] != '/' {
			// "C:relative" is a per-drive relative path; there is no sane
			// translation and silently guessing the wrong one is worse.
			return "", fmt.Errorf("bundle: %q is a drive-relative path; give an absolute path such as %c:\\path", p, p[0])
		}
		drive := strings.ToLower(string(p[0]))
		rest := strings.ReplaceAll(p[2:], "\\", "/")
		rest = strings.TrimPrefix(rest, "/")
		out := "/mnt/" + drive
		if rest != "" {
			out += "/" + rest
		}
		return path.Clean(out), nil
	}

	// Anything else with backslashes is a Windows relative path.
	if strings.Contains(p, "\\") {
		return "", fmt.Errorf("bundle: %q is a relative Windows path; bind sources must be absolute", p)
	}

	// Already a POSIX path, including an already-translated /mnt/<drive>/...
	if strings.HasPrefix(p, "/") {
		return path.Clean(p), nil
	}
	return "", fmt.Errorf("bundle: %q is a relative path; bind sources must be absolute", p)
}

func isUNC(p string) bool {
	return strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//")
}

func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// looksLikeHostPath reports whether s names a host filesystem path (as opposed
// to a named volume). Volume names may not contain a slash or a backslash, so
// anything that does is a path.
func looksLikeHostPath(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") {
		return true
	}
	if isUNC(s) {
		return true
	}
	if len(s) >= 2 && isDriveLetter(s[0]) && s[1] == ':' {
		return true
	}
	return strings.ContainsAny(s, `/\`)
}

// ---------- bind spec parsing ----------

// ParseBind parses one Docker `-v` / `--volume` specification into a
// types.Mount. It understands the Windows-source forms, which is why it cannot
// simply split on ":".
//
//	/data                       anonymous volume at /data
//	vol:/data                   named volume
//	/host/dir:/data             bind
//	/host/dir:/data:ro          read-only bind
//	C:\Users\me:/data:ro        Windows bind
//	vol:/data:ro,nocopy         named volume with options
func ParseBind(spec string) (types.Mount, error) {
	var m types.Mount
	if spec == "" {
		return m, errors.New("bundle: empty -v specification")
	}
	parts, err := splitBindSpec(spec)
	if err != nil {
		return m, err
	}

	var source, target, optstr string
	switch len(parts) {
	case 1:
		target = parts[0]
	case 2:
		source, target = parts[0], parts[1]
	case 3:
		source, target, optstr = parts[0], parts[1], parts[2]
	default:
		return m, fmt.Errorf("bundle: -v %q has too many colon-separated fields", spec)
	}

	if !strings.HasPrefix(target, "/") {
		return m, fmt.Errorf("bundle: -v %q: the container path %q must be absolute", spec, target)
	}
	m.Target = path.Clean(target)

	switch {
	case source == "":
		m.Type = "volume" // anonymous volume, the engine names it
	case looksLikeHostPath(source):
		m.Type = "bind"
		translated, err := TranslateWindowsPath(source)
		if err != nil {
			return m, fmt.Errorf("bundle: -v %q: %w", spec, err)
		}
		m.Source = translated
	default:
		m.Type = "volume"
		m.Source = source
	}

	if optstr != "" {
		bo := &types.BindOptions{}
		for _, opt := range strings.Split(optstr, ",") {
			switch opt := strings.TrimSpace(opt); opt {
			case "":
			case "ro", "readonly":
				m.ReadOnly = true
			case "rw":
				m.ReadOnly = false
			case "private", "rprivate", "shared", "rshared", "slave", "rslave", "unbindable", "runbindable":
				bo.Propagation = opt
			case "z", "Z":
				// SELinux relabelling. WSL has no SELinux; accepted and ignored
				// so compose files written for Fedora hosts still work.
			case "nocopy":
				// Volume option handled by the volume driver, not the spec.
			case "delegated", "cached", "consistent":
				// Docker Desktop osxfs consistency hints; no-ops on Linux.
			case "bind", "rbind":
				// Explicit bind type; hull always uses rbind.
			default:
				return m, fmt.Errorf("bundle: -v %q: unknown mount option %q", spec, opt)
			}
		}
		if bo.Propagation != "" {
			m.BindOptions = bo
		}
	}
	return m, nil
}

// splitBindSpec splits a -v specification on colons, treating a leading
// "<letter>:" drive prefix as part of the source rather than a separator.
func splitBindSpec(spec string) ([]string, error) {
	rest := spec
	var parts []string
	if len(rest) >= 3 && isDriveLetter(rest[0]) && rest[1] == ':' && (rest[2] == '\\' || rest[2] == '/') {
		i := strings.IndexByte(rest[2:], ':')
		if i < 0 {
			return nil, fmt.Errorf("bundle: -v %q: a Windows source needs a container path after it", spec)
		}
		parts = append(parts, rest[:2+i])
		rest = rest[2+i+1:]
	}
	parts = append(parts, strings.Split(rest, ":")...)
	return parts, nil
}

// ---------- mount assembly ----------

// buildMounts assembles the container's mount list in the order fidelity
// requires: the OCI pseudo-filesystems first, then the image's VOLUME
// declarations, then --tmpfs, then the user's -v and --mount requests, so a
// later request can shadow anything before it. The result is deduplicated and
// depth-sorted by the caller.
func (b *builder) buildMounts() ([]runtimespec.Mount, error) {
	mounts := b.defaultMounts()

	imgVols, err := b.imageVolumeMounts()
	if err != nil {
		return nil, err
	}
	mounts = append(mounts, imgVols...)

	tmpfs, err := b.tmpfsMounts()
	if err != nil {
		return nil, err
	}
	mounts = append(mounts, tmpfs...)

	user, err := b.userMounts()
	if err != nil {
		return nil, err
	}
	mounts = append(mounts, user...)
	return mounts, nil
}

// defaultMounts is the OCI baseline: /proc, a /dev tmpfs, a private devpts
// instance, /dev/shm at the requested size, /dev/mqueue, /sys and the read-only
// cgroup view.
func (b *builder) defaultMounts() []runtimespec.Mount {
	shm := b.c.HostConfig.ShmSize
	if shm <= 0 {
		shm = DefaultShmSize
	}

	mounts := []runtimespec.Mount{
		{
			Destination: "/proc",
			Type:        "proc",
			Source:      "proc",
			Options:     []string{"nosuid", "noexec", "nodev"},
		},
	}

	if b.privileged {
		// A privileged container is entitled to the host's devices. Rather
		// than enumerating every node in /dev and re-creating it (which needs
		// the device cgroup to already allow it, and races with hotplug), hull
		// recursively binds the host /dev and then mounts a private devpts,
		// shm and mqueue over it, so the container still gets its own ptys.
		mounts = append(mounts, runtimespec.Mount{
			Destination: "/dev",
			Type:        "bind",
			Source:      "/dev",
			Options:     []string{"rbind", "rprivate"},
		})
	} else {
		mounts = append(mounts, runtimespec.Mount{
			Destination: "/dev",
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
		})
	}

	mounts = append(mounts,
		runtimespec.Mount{
			Destination: "/dev/pts",
			Type:        "devpts",
			Source:      "devpts",
			Options:     []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"},
		},
		runtimespec.Mount{
			Destination: "/dev/shm",
			Type:        "tmpfs",
			Source:      "shm",
			Options:     []string{"nosuid", "noexec", "nodev", "mode=1777", sizeOption(shm)},
		},
		runtimespec.Mount{
			Destination: "/dev/mqueue",
			Type:        "mqueue",
			Source:      "mqueue",
			Options:     []string{"nosuid", "noexec", "nodev"},
		},
	)

	mounts = append(mounts, b.sysMount())

	cgroupOpts := []string{"nosuid", "noexec", "nodev", "relatime", "ro"}
	if b.privileged {
		cgroupOpts = []string{"nosuid", "noexec", "nodev", "relatime", "rw"}
	}
	mounts = append(mounts, runtimespec.Mount{
		Destination: "/sys/fs/cgroup",
		Type:        "cgroup",
		Source:      "cgroup",
		Options:     cgroupOpts,
	})
	return mounts
}

// sysMount decides between a fresh sysfs and a read-only recursive bind.
//
// Mounting sysfs requires CAP_SYS_ADMIN over the network namespace the mount
// will be associated with. A container that does not own its network namespace
// — host networking, or "container:<id>" — cannot do that, so the kernel
// refuses the mount outright. Docker solves this with a read-only bind of the
// host /sys, and so does hull.
func (b *builder) sysMount() runtimespec.Mount {
	mode := b.c.HostConfig.NetworkMode
	sharesNetns := mode == "host" || strings.HasPrefix(mode, "container:")

	if b.privileged {
		if sharesNetns {
			return runtimespec.Mount{
				Destination: "/sys",
				Type:        "bind",
				Source:      "/sys",
				Options:     []string{"rbind", "nosuid", "noexec", "nodev", "rw"},
			}
		}
		return runtimespec.Mount{
			Destination: "/sys",
			Type:        "sysfs",
			Source:      "sysfs",
			Options:     []string{"nosuid", "noexec", "nodev", "rw"},
		}
	}
	if sharesNetns {
		return runtimespec.Mount{
			Destination: "/sys",
			Type:        "bind",
			Source:      "/sys",
			Options:     []string{"rbind", "nosuid", "noexec", "nodev", "ro"},
		}
	}
	return runtimespec.Mount{
		Destination: "/sys",
		Type:        "sysfs",
		Source:      "sysfs",
		Options:     []string{"nosuid", "noexec", "nodev", "ro"},
	}
}

// sizeOption renders a tmpfs size option, preferring the kilobyte spelling
// Docker uses so `mount` output inside the container looks familiar.
func sizeOption(bytes int64) string {
	if bytes%1024 == 0 {
		return fmt.Sprintf("size=%dk", bytes/1024)
	}
	return fmt.Sprintf("size=%d", bytes)
}

// imageVolumeMounts turns the image's VOLUME declarations (plus any the
// container config repeats) into binds of the anonymous volumes the engine
// created for them. A declaration with no backing volume is reported as a
// warning, never mounted as something else.
func (b *builder) imageVolumeMounts() ([]runtimespec.Mount, error) {
	targets := make(map[string]struct{})
	for t := range b.img.Config.Volumes {
		targets[t] = struct{}{}
	}
	for t := range b.c.Config.Volumes {
		targets[t] = struct{}{}
	}
	if len(targets) == 0 {
		return nil, nil
	}

	// Anything the user mounted explicitly wins outright; emitting a mount for
	// it here and relying on shadowing would leave a stale entry in the spec.
	explicit, err := b.explicitTargets()
	if err != nil {
		return nil, err
	}

	sorted := make([]string, 0, len(targets))
	for t := range targets {
		sorted = append(sorted, t)
	}
	sort.Strings(sorted)

	var out []runtimespec.Mount
	for _, t := range sorted {
		if !strings.HasPrefix(t, "/") {
			return nil, fmt.Errorf("bundle: image VOLUME %q is not an absolute path", t)
		}
		clean := path.Clean(t)
		if _, ok := explicit[clean]; ok {
			continue
		}
		src, ok := b.opts.ImageVolumePaths[clean]
		if !ok {
			src, ok = b.opts.ImageVolumePaths[t]
		}
		if !ok || src == "" {
			b.warnf("image VOLUME %s has no anonymous volume backing it; it will be part of the container's writable layer and will be lost when the container is removed", clean)
			continue
		}
		out = append(out, runtimespec.Mount{
			Destination: clean,
			Type:        "bind",
			Source:      src,
			Options:     []string{"rbind", "rprivate", "rw"},
		})
	}
	return out, nil
}

// explicitTargets is the set of destinations the user asked for with -v,
// --mount or --tmpfs.
func (b *builder) explicitTargets() (map[string]struct{}, error) {
	out := make(map[string]struct{})
	for _, spec := range b.c.HostConfig.Binds {
		m, err := ParseBind(spec)
		if err != nil {
			return nil, err
		}
		out[m.Target] = struct{}{}
	}
	for _, m := range b.c.HostConfig.Mounts {
		if m.Target == "" {
			return nil, errors.New("bundle: --mount entry with an empty target")
		}
		out[path.Clean(m.Target)] = struct{}{}
	}
	for t := range b.c.HostConfig.Tmpfs {
		out[path.Clean(t)] = struct{}{}
	}
	return out, nil
}

// tmpfsMounts renders --tmpfs requests. The option string is Docker's:
// a comma list such as "rw,noexec,nosuid,size=65536k".
func (b *builder) tmpfsMounts() ([]runtimespec.Mount, error) {
	if len(b.c.HostConfig.Tmpfs) == 0 {
		return nil, nil
	}
	targets := make([]string, 0, len(b.c.HostConfig.Tmpfs))
	for t := range b.c.HostConfig.Tmpfs {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	out := make([]runtimespec.Mount, 0, len(targets))
	for _, t := range targets {
		if !strings.HasPrefix(t, "/") {
			return nil, fmt.Errorf("bundle: --tmpfs %q: the container path must be absolute", t)
		}
		opts := []string{"nosuid", "nodev", "noexec"}
		for _, o := range strings.Split(b.c.HostConfig.Tmpfs[t], ",") {
			if o = strings.TrimSpace(o); o != "" {
				opts = append(opts, o)
			}
		}
		out = append(out, runtimespec.Mount{
			Destination: path.Clean(t),
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     opts,
		})
	}
	return out, nil
}

// userMounts renders HostConfig.Binds (the -v short form) followed by
// HostConfig.Mounts (the --mount long form), in that order, so a --mount can
// override a -v for the same destination.
func (b *builder) userMounts() ([]runtimespec.Mount, error) {
	var out []runtimespec.Mount
	for _, spec := range b.c.HostConfig.Binds {
		m, err := ParseBind(spec)
		if err != nil {
			return nil, err
		}
		sm, err := b.renderMount(m)
		if err != nil {
			return nil, err
		}
		out = append(out, sm)
	}
	for _, m := range b.c.HostConfig.Mounts {
		sm, err := b.renderMount(m)
		if err != nil {
			return nil, err
		}
		out = append(out, sm)
	}
	return out, nil
}

// renderMount turns one types.Mount into a spec mount, resolving named volumes
// through Options.VolumePaths and translating Windows bind sources.
func (b *builder) renderMount(m types.Mount) (runtimespec.Mount, error) {
	var out runtimespec.Mount
	if m.Target == "" {
		return out, errors.New("bundle: mount with an empty target")
	}
	if !strings.HasPrefix(m.Target, "/") {
		return out, fmt.Errorf("bundle: mount target %q must be an absolute path", m.Target)
	}
	target := path.Clean(m.Target)

	switch m.Type {
	case "tmpfs":
		opts := []string{"nosuid", "nodev", "noexec"}
		if m.TmpfsOptions != nil {
			if m.TmpfsOptions.SizeBytes > 0 {
				opts = append(opts, sizeOption(m.TmpfsOptions.SizeBytes))
			}
			if m.TmpfsOptions.Mode != 0 {
				opts = append(opts, fmt.Sprintf("mode=%o", m.TmpfsOptions.Mode))
			}
		}
		if m.ReadOnly {
			opts = append(opts, "ro")
		}
		return runtimespec.Mount{Destination: target, Type: "tmpfs", Source: "tmpfs", Options: opts}, nil

	case "volume":
		if m.Source == "" {
			return out, fmt.Errorf("bundle: anonymous volume at %s was not resolved to a named volume before the bundle was generated", target)
		}
		src, ok := b.opts.VolumePaths[m.Source]
		if !ok || src == "" {
			return out, fmt.Errorf("bundle: volume %q has no host path; the engine must create the volume before generating the bundle", m.Source)
		}
		return runtimespec.Mount{
			Destination: target,
			Type:        "bind",
			Source:      src,
			Options:     bindOptions(m),
		}, nil

	case "bind", "":
		if m.Source == "" {
			return out, fmt.Errorf("bundle: bind mount at %s has no source", target)
		}
		src, err := TranslateWindowsPath(m.Source)
		if err != nil {
			return out, err
		}
		create := m.BindOptions != nil && m.BindOptions.CreateMountpoint
		if !create {
			if err := checkHostPath(src, fmt.Sprintf("bind source for %s", target)); err != nil {
				return out, err
			}
		}
		return runtimespec.Mount{
			Destination: target,
			Type:        "bind",
			Source:      src,
			Options:     bindOptions(m),
		}, nil

	default:
		return out, fmt.Errorf("bundle: mount type %q is not supported; hull understands bind, volume and tmpfs", m.Type)
	}
}

// bindOptions renders the option list for a bind: always recursive and private
// unless a propagation mode was asked for, plus ro when requested.
func bindOptions(m types.Mount) []string {
	prop := "rprivate"
	if m.BindOptions != nil && m.BindOptions.Propagation != "" {
		prop = m.BindOptions.Propagation
	}
	opts := []string{"rbind", prop}
	if m.ReadOnly {
		opts = append(opts, "ro")
	} else {
		opts = append(opts, "rw")
	}
	return opts
}

// checkHostPath rejects a missing bind source with a message naming what it was
// for, so `-v ./typo:/app` fails at create time instead of producing an empty
// directory inside the container.
func checkHostPath(p, what string) error {
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("bundle: %s: %s does not exist on the host; create it first, or set createMountpoint", what, p)
		}
		return fmt.Errorf("bundle: %s: %s: %w", what, p, err)
	}
	return nil
}
