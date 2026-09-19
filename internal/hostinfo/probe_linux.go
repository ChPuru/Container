//go:build linux

package hostinfo

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultDataRoot is where hull keeps its content store, snapshots and
// container state when HULL_DATA_ROOT is unset.
const DefaultDataRoot = "/var/lib/hull"

// commandTimeout bounds each helper binary the probe shells out to, so a wedged
// iptables can never hang "hull doctor".
const commandTimeout = 5 * time.Second

// Probe inspects the running host and returns a complete [Report]. It never
// mutates persistent state: the only writes it performs are inside a temporary
// directory it creates and removes, when running as root, to test a real
// overlay mount.
//
// Probe does not return an error for a missing feature — that is what the
// checks are for. It returns an error only when the environment is so broken
// that no report can be produced (for example uname(2) failing).
func Probe(ctx context.Context) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("hostinfo: probe cancelled: %w", err)
	}

	r := &Report{Generated: time.Now().UTC()}

	kernel, err := probeKernel()
	if err != nil {
		return nil, err
	}
	r.Kernel = kernel

	mounts, mountsErr := readMounts()

	r.WSL = probeWSL(r.Kernel, mounts)
	r.Cgroups = probeCgroups(r.Kernel, mounts)
	r.Overlay = probeOverlay(ctx, r.Kernel)
	r.Namespaces = probeNamespaces()
	r.Security = probeSecurity(r.Kernel)
	r.Storage = probeStorage(mounts)
	r.Network = probeNetwork(ctx, r.Kernel)

	r.Checks = buildChecks(r)

	if mountsErr != nil {
		r.Checks = append(r.Checks, Check{
			Name:   "mount table",
			Detail: "could not read /proc/mounts: " + mountsErr.Error(),
			Remedy: "Ensure /proc is mounted inside this distro; hull cannot see filesystem or cgroup layout without it.",
			Status: StatusFail,
		})
		sortChecks(r.Checks)
	}
	return r, nil
}

// ---------- small file helpers ----------

// readTrimmed reads a small pseudo-file and trims trailing whitespace.
func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// readBool reads a sysctl-style file holding 0 or 1.
func readBool(path string) (value, present bool) {
	s, err := readTrimmed(path)
	if err != nil {
		return false, false
	}
	return s == "1", true
}

// readInt reads a sysctl-style file holding a decimal integer.
func readInt(path string) (int, bool) {
	s, err := readTrimmed(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func readMounts() ([]MountEntry, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, fmt.Errorf("hostinfo: opening /proc/mounts: %w", err)
	}
	defer f.Close()
	return ParseMounts(f)
}

// ---------- kernel ----------

func probeKernel() (KernelInfo, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return KernelInfo{}, fmt.Errorf("hostinfo: uname: %w", err)
	}
	k := KernelInfo{
		Release: utsString(u.Release[:]),
		Version: utsString(u.Version[:]),
		Arch:    utsString(u.Machine[:]),
	}
	if major, minor, err := ParseKernelRelease(k.Release); err == nil {
		k.Major, k.Minor = major, minor
	}

	if f, err := os.Open("/proc/config.gz"); err == nil {
		defer f.Close()
		if cfg, err := ParseKernelConfig(f); err == nil {
			k.Config, k.ConfigSource = cfg, "/proc/config.gz"
		} else {
			k.ConfigSource = "/proc/config.gz unreadable: " + err.Error()
		}
	} else {
		boot := "/boot/config-" + k.Release
		if f, err := os.Open(boot); err == nil {
			defer f.Close()
			if cfg, err := ParsePlainKernelConfig(f); err == nil {
				k.Config, k.ConfigSource = cfg, boot
			}
		}
		if k.ConfigSource == "" {
			k.ConfigSource = "unavailable (no /proc/config.gz, no /boot/config-*)"
		}
	}
	return k, nil
}

// utsString converts a NUL-padded utsname field to a Go string.
func utsString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// ---------- WSL ----------

func probeWSL(k KernelInfo, mounts []MountEntry) WSLInfo {
	w := WSLInfo{}

	osrelease, _ := readTrimmed("/proc/sys/kernel/osrelease")
	lowered := strings.ToLower(k.Release + " " + osrelease)
	w.IsWSL = strings.Contains(lowered, "microsoft") || strings.Contains(lowered, "wsl") || exists("/run/WSL")

	if f, err := os.Open("/etc/os-release"); err == nil {
		defer f.Close()
		if kv, err := ParseOSRelease(f); err == nil {
			w.Distro = kv["ID"]
		}
	}

	// WSL names the handler WSLInterop on older builds and WSLInterop-late on
	// newer ones; either proves interop is wired up.
	for _, name := range []string{"WSLInterop", "WSLInterop-late"} {
		if exists("/proc/sys/fs/binfmt_misc/" + name) {
			w.Interop = true
			break
		}
	}

	if comm, err := readTrimmed("/proc/1/comm"); err == nil {
		w.SystemdPID1 = comm == "systemd"
	}

	if _, ok := FindMount(mounts, "/mnt/wsl"); ok {
		w.SharedMntWSL = true
	}

	w.MirroredNet, w.MirroredNetKnown = probeMirroredNet()
	if w.IsWSL {
		w.WSLVersionHint = wslVersionHint(k.Major, k.Minor, k.Release)
	}
	return w
}

// probeMirroredNet decides between WSL's NAT and mirrored networking modes.
// Mirrored mode creates a "loopback0" interface and clones the Windows host's
// adapters; NAT mode gives the distro a single eth0 behind a default route.
// When neither signature matches, the result is reported as unknown rather
// than guessed.
func probeMirroredNet() (mirrored, known bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, false
	}
	names := make(map[string]bool, len(ifaces))
	for _, i := range ifaces {
		names[i.Name] = true
	}
	if names["loopback0"] {
		return true, true
	}

	f, err := os.Open("/proc/net/route")
	if err != nil {
		return false, false
	}
	defer f.Close()
	routes, err := ParseProcNetRoute(f)
	if err != nil {
		return false, false
	}
	for _, rt := range routes {
		if rt.IsDefault() && rt.Iface == "eth0" && names["eth0"] {
			return false, true
		}
	}
	return false, false
}

// ---------- cgroups ----------

// probeCgroups inspects the cgroup hierarchy.
//
// TODO(hull): delegate to internal/cgroups.Detect() once that package exists
// and translate its Warnings into Checks; the logic below is deliberately the
// same shape so the swap is mechanical.
func probeCgroups(k KernelInfo, mounts []MountEntry) CgroupInfo {
	cg := CgroupInfo{Mode: "none"}

	var v1 []string
	for _, m := range mounts {
		switch m.FSType {
		case "cgroup2":
			// Prefer /sys/fs/cgroup itself over a nested hybrid mount.
			if cg.UnifiedRoot == "" || m.Target == "/sys/fs/cgroup" {
				cg.UnifiedRoot = m.Target
				cg.NSDelegate = m.HasOption("nsdelegate")
			}
		case "cgroup":
			for _, o := range m.Options {
				switch o {
				case "rw", "ro", "nosuid", "nodev", "noexec", "relatime", "noatime", "xattr", "seclabel":
					continue
				}
				if strings.HasPrefix(o, "name=") {
					v1 = append(v1, o)
					continue
				}
				v1 = append(v1, o)
			}
		}
	}
	sort.Strings(v1)
	cg.V1Controllers = dedupe(v1)

	switch {
	case cg.UnifiedRoot != "" && len(cg.V1Controllers) > 0:
		cg.Mode = "hybrid"
	case cg.UnifiedRoot != "":
		cg.Mode = "unified"
	case len(cg.V1Controllers) > 0:
		cg.Mode = "legacy"
	}

	if cg.UnifiedRoot != "" {
		if s, err := readTrimmed(filepath.Join(cg.UnifiedRoot, "cgroup.controllers")); err == nil {
			cg.Controllers = ParseControllers(s)
		}
		if s, err := readTrimmed(filepath.Join(cg.UnifiedRoot, "cgroup.subtree_control")); err == nil {
			cg.SubtreeControl = ParseControllers(s)
		}
		// cgroup.kill and cgroup.freeze never exist in the ROOT cgroup, only in
		// its descendants, so probing the root would always answer "absent".
		cg.CgroupKill, cg.FreezeV2 = probeCgroupChildFiles(cg.UnifiedRoot, k)
	}
	cg.Delegated = len(cg.MissingControllers()) == 0 && len(cg.Controllers) > 0
	cg.PSI = exists("/proc/pressure") && configIs(k.Config, "CONFIG_PSI", "y") || exists("/proc/pressure/cpu")

	if cg.Mode == "hybrid" && len(cg.Controllers) == 0 {
		cg.Warnings = append(cg.Warnings, fmt.Sprintf(
			"cgroup2 is mounted at %s but cgroup.controllers is empty: every controller is owned by the v1 hierarchies %s",
			cg.UnifiedRoot, strings.Join(cg.V1Controllers, ",")))
	}
	if cg.UnifiedRoot != "" && !cg.CgroupKill {
		cg.Warnings = append(cg.Warnings, "cgroup.kill is absent, so hull must fall back to walking cgroup.procs when killing a container")
	}
	if cg.UnifiedRoot != "" && !cg.FreezeV2 {
		cg.Warnings = append(cg.Warnings, "cgroup.freeze is absent, so hull's scale-to-zero freezing is unavailable")
	}
	return cg
}

// probeCgroupChildFiles reports whether cgroup.kill and cgroup.freeze exist on
// a NON-ROOT cgroup, which is the only place the kernel ever creates them. It
// prefers a throwaway cgroup it creates and removes; failing that it inspects
// an existing child; failing that it falls back to the kernel version floors
// (cgroup.freeze is 5.2+, cgroup.kill is 5.14+).
func probeCgroupChildFiles(root string, k KernelInfo) (kill, freeze bool) {
	probe := filepath.Join(root, ".hull-probe")
	if err := os.Mkdir(probe, 0o755); err == nil {
		defer func() { _ = os.Remove(probe) }()
		return exists(filepath.Join(probe, "cgroup.kill")), exists(filepath.Join(probe, "cgroup.freeze"))
	}
	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			child := filepath.Join(root, e.Name())
			if !exists(filepath.Join(child, "cgroup.procs")) {
				continue
			}
			return exists(filepath.Join(child, "cgroup.kill")), exists(filepath.Join(child, "cgroup.freeze"))
		}
	}
	return k.AtLeast(5, 14), k.AtLeast(5, 2)
}

func dedupe(v []string) []string {
	if len(v) == 0 {
		return nil
	}
	out := v[:0:0]
	seen := make(map[string]bool, len(v))
	for _, s := range v {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ---------- overlay ----------

func probeOverlay(ctx context.Context, k KernelInfo) OverlayInfo {
	o := OverlayInfo{}

	if b, err := os.ReadFile("/proc/filesystems"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(strings.TrimPrefix(line, "nodev")) == "overlay" {
				o.Supported = true
				break
			}
		}
	}

	param := func(name string) string {
		s, err := readTrimmed("/sys/module/overlay/parameters/" + name)
		if err != nil {
			return ""
		}
		return s
	}
	o.Redirect = param("redirect_dir")
	o.Metacopy = param("metacopy")
	o.Index = param("index")
	o.RedirectAlwaysFollow = param("redirect_always_follow")
	o.Xino = param("xino")
	if o.Xino == "" {
		o.Xino = param("xino_auto")
	}

	// Feature floors, by kernel version. These are the honest upper bound; the
	// live mount below is what actually proves overlay works here.
	o.UserXattr = k.AtLeast(5, 11)
	o.IdmappedLayers = k.AtLeast(5, 19)
	o.LowerdirPlus = k.AtLeast(6, 7)

	if o.Supported && os.Geteuid() == 0 {
		o.MountTested = true
		if err := testOverlayMount(ctx); err != nil {
			o.MountError = err.Error()
		} else {
			o.MountOK = true
		}
	}
	return o
}

// OverlayMountOptions is the option string hull always uses. redirect_dir,
// metacopy and index are pinned off explicitly because the 6.6 WSL kernel
// config turns redirect-always-follow on, and because metacopy/index break
// layer portability and rootless operation.
const OverlayMountOptions = "redirect_dir=off,metacopy=off,index=off"

// testOverlayMount mounts a throwaway overlay with hull's exact option set and
// unmounts it again. It requires root and returns a wrapped error describing
// exactly what the kernel refused.
func testOverlayMount(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("cancelled: %w", err)
	}
	// Short base path: the legacy overlay option string is capped at one page.
	base, err := os.MkdirTemp("", "hullov")
	if err != nil {
		return fmt.Errorf("creating scratch dir: %w", err)
	}
	defer os.RemoveAll(base)

	lower := filepath.Join(base, "l")
	upper := filepath.Join(base, "u")
	work := filepath.Join(base, "w")
	merged := filepath.Join(base, "m")
	for _, d := range []string{lower, upper, work, merged} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", filepath.Base(d), err)
		}
	}
	if err := os.WriteFile(filepath.Join(lower, "probe"), []byte("hull\n"), 0o644); err != nil {
		return fmt.Errorf("seeding lower layer: %w", err)
	}

	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,%s", lower, upper, work, OverlayMountOptions)
	if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		return fmt.Errorf("mount(overlay, %s): %w", OverlayMountOptions, err)
	}
	defer func() { _ = unix.Unmount(merged, unix.MNT_DETACH) }()

	if _, err := os.ReadFile(filepath.Join(merged, "probe")); err != nil {
		return fmt.Errorf("reading through the merged dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(merged, "copyup"), []byte("hull\n"), 0o644); err != nil {
		return fmt.Errorf("writing to the merged dir: %w", err)
	}
	return nil
}

// ---------- namespaces ----------

func probeNamespaces() NamespaceInfo {
	n := NamespaceInfo{MaxUserNamespaces: -1}
	n.User = exists("/proc/self/ns/user")
	n.PID = exists("/proc/self/ns/pid")
	n.Net = exists("/proc/self/ns/net")
	n.Mount = exists("/proc/self/ns/mnt")
	n.IPC = exists("/proc/self/ns/ipc")
	n.UTS = exists("/proc/self/ns/uts")
	n.Cgroup = exists("/proc/self/ns/cgroup")
	n.Time = exists("/proc/self/ns/time")

	if v, ok := readInt("/proc/sys/user/max_user_namespaces"); ok {
		n.MaxUserNamespaces = v
	}
	if v, present := readBool("/proc/sys/kernel/unprivileged_userns_clone"); present {
		n.UsernsCloneSysctl = true
		n.UnprivilegedUsernsClone = v
	} else {
		// Absent means mainline behaviour: unprivileged clone is permitted.
		n.UnprivilegedUsernsClone = true
	}

	name := currentUserName()
	n.SubuidRange = subIDRange("/etc/subuid", name)
	n.SubgidRange = subIDRange("/etc/subgid", name)
	return n
}

// currentUserName resolves the running user's login name, falling back to the
// numeric uid when /etc/passwd has no entry (common in scratch containers).
func currentUserName() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	return strconv.Itoa(os.Getuid())
}

func subIDRange(path, user string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	v, err := ParseSubIDRange(f, user)
	if err != nil {
		return ""
	}
	return v
}

// ---------- security ----------

func probeSecurity(k KernelInfo) SecurityInfo {
	s := SecurityInfo{}

	if v, err := readTrimmed("/proc/sys/kernel/seccomp/actions_avail"); err == nil {
		s.SeccompActions = strings.Fields(v)
		s.Seccomp = true
	}
	if configIs(k.Config, "CONFIG_SECCOMP", "y") || configIs(k.Config, "CONFIG_SECCOMP_FILTER", "y") {
		s.Seccomp = true
	}

	if v, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0); err == nil {
		s.NoNewPrivs = v == 1
	}

	s.Landlock = landlockABI()

	// AppArmor is only real when the securityfs directory exists AND the
	// profiles file is readable; WSL kernels ship neither.
	if exists("/sys/kernel/security/apparmor/profiles") {
		s.AppArmor = true
	}
	s.SELinux = exists("/sys/fs/selinux/enforce")

	if f, err := os.Open("/proc/self/status"); err == nil {
		defer f.Close()
		if caps, err := ParseCapBnd(f); err == nil {
			s.Capabilities = caps
		}
	}
	return s
}

// landlockCreateRulesetVersion is LANDLOCK_CREATE_RULESET_VERSION: asking the
// kernel for the ABI version rather than creating a ruleset.
const landlockCreateRulesetVersion = 1 << 0

// landlockABI returns the Landlock ABI version supported by this kernel, or 0
// when Landlock is unavailable or disabled.
func landlockABI() int {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, landlockCreateRulesetVersion)
	if errno != 0 {
		return 0
	}
	if int(v) < 0 {
		return 0
	}
	return int(v)
}

// ---------- storage ----------

// fsTypeNames maps statfs f_type magic numbers to filesystem names, for the
// cases where /proc/mounts cannot answer.
var fsTypeNames = map[int64]string{
	0xef53:     "ext4",
	0x9123683e: "btrfs",
	0x58465342: "xfs",
	0x01021994: "tmpfs",
	0x794c7630: "overlayfs",
	0x01021997: "9p",
	0x65735546: "fuse",
	0x6969:     "nfs",
	0xff534d42: "cifs",
	0x5346544e: "ntfs",
	0x4d44:     "vfat",
	0x2011bab0: "exfat",
	0x73717368: "squashfs",
	0x858458f6: "ramfs",
	0x2fc12fc1: "zfs",
	0x9fa0:     "proc",
	0x62656572: "sysfs",
	0x63677270: "cgroup2",
	0x0027e0eb: "cgroup",
	0x1cd1:     "devpts",
	0x6c6f6f70: "gfs2",
	0x5a3c69f0: "aufs",
	0x2fc12fc2: "zfs-alt",
	0x0bad1dea: "futexfs",
	0x19800202: "mqueue",
	0x00c36400: "ceph",
	0x0bd00bd0: "lustre",
	0x0000f15f: "ecryptfs",
	0x42465331: "befs",
	0x24051905: "ubifs",
	0x0000482b: "hfsplus",
	0x0000564c: "ncpfs",
}

// drvfsTypes are the filesystem types that mean "this path is really Windows
// storage reached over a share", which is catastrophic for container I/O.
var drvfsTypes = map[string]bool{
	"9p":       true,
	"drvfs":    true,
	"drvfs2":   true,
	"virtiofs": true,
	"cifs":     true,
	"smb3":     true,
	"ntfs":     true,
	"ntfs3":    true,
	"vfat":     true,
	"exfat":    true,
	"msdos":    true,
	"fuseblk":  true,
}

func probeStorage(mounts []MountEntry) StorageInfo {
	st := StorageInfo{DataRoot: DefaultDataRoot}
	if v := os.Getenv("HULL_DATA_ROOT"); v != "" {
		st.DataRoot = v
	}
	if abs, err := filepath.Abs(st.DataRoot); err == nil {
		st.DataRoot = abs
	}

	probed := nearestExisting(st.DataRoot)
	if probed == "" {
		return st
	}
	st.Probed = probed

	var sfs unix.Statfs_t
	if err := unix.Statfs(probed, &sfs); err == nil {
		st.TotalBytes = sfs.Blocks * uint64(sfs.Bsize)
		st.FreeBytes = sfs.Bavail * uint64(sfs.Bsize)
		if name, ok := fsTypeNames[int64(sfs.Type)]; ok {
			st.FSType = name
		} else {
			st.FSType = fmt.Sprintf("unknown(0x%x)", uint64(sfs.Type))
		}
	}
	// /proc/mounts knows the real name ("drvfs", "virtiofs"), which statfs
	// flattens into 9p or fuse magic numbers, so it wins when it has an answer.
	if m, ok := FindMountFor(mounts, probed); ok && m.FSType != "" {
		st.FSType = m.FSType
	}
	st.OnDrvFs = drvfsTypes[st.FSType]
	st.SupportsDType = probeDType(probed)
	return st
}

// nearestExisting walks up from path to the first component that exists.
func nearestExisting(path string) string {
	for p := filepath.Clean(path); ; {
		if exists(p) {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return ""
		}
		p = parent
	}
}

// probeDType reports whether readdir on dir returns a populated d_type field.
// overlayfs refuses an upper layer on a filesystem that does not. When dir is
// empty the probe creates and removes one throwaway entry; if it cannot write,
// it answers false rather than guessing.
func probeDType(dir string) bool {
	if ok, decided := dtypeFromDir(dir); decided {
		return ok
	}
	scratch, err := os.MkdirTemp(dir, ".hull-dtype-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(scratch)
	if err := os.Mkdir(filepath.Join(scratch, "d"), 0o700); err != nil {
		return false
	}
	ok, _ := dtypeFromDir(scratch)
	return ok
}

// dtypeFromDir parses raw getdents64 records looking for any entry other than
// "." and ".." and reports whether its d_type is populated. decided is false
// when the directory holds no usable entry.
func dtypeFromDir(dir string) (ok, decided bool) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, false
	}
	defer unix.Close(fd)

	buf := make([]byte, 8192)
	for {
		n, err := unix.Getdents(fd, buf)
		if err != nil || n <= 0 {
			return false, false
		}
		for off := 0; off+19 <= n; {
			// struct linux_dirent64: ino(8) off(8) reclen(2) type(1) name...
			reclen := int(buf[off+16]) | int(buf[off+17])<<8
			if reclen <= 0 || off+reclen > n {
				return false, false
			}
			dtype := buf[off+18]
			name := buf[off+19 : off+reclen]
			if i := bytes.IndexByte(name, 0); i >= 0 {
				name = name[:i]
			}
			if s := string(name); s != "." && s != ".." {
				return dtype != unix.DT_UNKNOWN, true
			}
			off += reclen
		}
	}
}

// ---------- network ----------

func probeNetwork(ctx context.Context, k KernelInfo) NetworkInfo {
	n := NetworkInfo{}

	n.IPForward, _ = readBool("/proc/sys/net/ipv4/ip_forward")

	modules := map[string]bool{}
	if f, err := os.Open("/proc/modules"); err == nil {
		if m, err := ParseModules(f); err == nil {
			modules = m
		}
		f.Close()
	}
	have := func(module string, configKeys ...string) bool {
		if modules[module] || exists("/sys/module/"+module) {
			return true
		}
		for _, key := range configKeys {
			if configIs(k.Config, key, "y", "m") {
				return true
			}
		}
		return false
	}
	n.BridgeModule = have("bridge", "CONFIG_BRIDGE")
	n.VethModule = have("veth", "CONFIG_VETH")
	n.NftablesModule = have("nf_tables", "CONFIG_NF_TABLES")

	n.NftBinary, _ = exec.LookPath("nft")
	n.IptablesBinary = lookPathLinuxOnly("iptables")

	if n.IptablesBinary != "" {
		if _, err := runTool(ctx, n.IptablesBinary, "-t", "nat", "-S"); err == nil {
			n.IptablesNAT = true
		}
	}

	n.ForwardPolicy, n.ForwardPolicySource = probeForwardPolicy(ctx, n)
	n.DockerForwardPolicyDrop = n.ForwardPolicy == "DROP"

	// Docker Desktop may be running in a sibling distro rather than this one:
	// it still shares the VM's single network namespace and netfilter ruleset,
	// so a docker CLI reachable only through WSL interop still counts.
	dockerInterop := false
	if p, err := exec.LookPath("docker"); err == nil && strings.HasPrefix(p, "/mnt/") {
		dockerInterop = true
	}
	n.DockerPresent = exists("/var/run/docker.sock") || exists("/run/docker.sock") ||
		exists("/sys/class/net/docker0") || lookPathLinuxOnly("dockerd") != "" || dockerInterop

	n.ExistingSubnets, n.WSLNATSubnet = probeSubnets()
	return n
}

// lookPathLinuxOnly resolves a binary but ignores anything under /mnt/, which
// on WSL is a Windows .exe reached through interop and cannot manage the
// Linux kernel's netfilter tables.
func lookPathLinuxOnly(name string) string {
	p, err := exec.LookPath(name)
	if err != nil || strings.HasPrefix(p, "/mnt/") {
		return ""
	}
	return p
}

// runTool executes a helper binary with a bounded timeout and returns its
// combined output.
func runTool(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("hostinfo: running %s: %w", name, err)
	}
	return string(out), nil
}

// probeForwardPolicy reads the filter FORWARD chain policy, preferring
// iptables (which is what Docker Desktop actually installs) and falling back
// to nft. A missing binary yields an empty policy, which the check reports as
// skip rather than inventing an answer.
func probeForwardPolicy(ctx context.Context, n NetworkInfo) (policy, source string) {
	if n.IptablesBinary != "" {
		if out, err := runTool(ctx, n.IptablesBinary, "-S", "FORWARD"); err == nil {
			if p, ok := ParseIptablesForwardPolicy(out); ok {
				return p, "iptables"
			}
		}
	}
	if n.NftBinary != "" {
		if out, err := runTool(ctx, n.NftBinary, "list", "chain", "ip", "filter", "FORWARD"); err == nil {
			if p, ok := ParseNftForwardPolicy(out); ok {
				return p, "nft"
			}
		}
	}
	return "", ""
}

// probeSubnets lists the IPv4 networks already claimed by bridges and the WSL
// NAT interface, so the IPAM layer can steer clear of them.
func probeSubnets() (subnets []string, wslNAT string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, ""
	}
	seen := map[string]bool{}
	for _, iface := range ifaces {
		if !interestingIface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			cidr := (&net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}).String()
			if !seen[cidr] {
				seen[cidr] = true
				subnets = append(subnets, cidr)
			}
			if iface.Name == "eth0" && wslNAT == "" {
				wslNAT = cidr
			}
		}
	}
	sort.Strings(subnets)
	return subnets, wslNAT
}

// interestingIface reports whether an interface's addresses matter to IPAM.
func interestingIface(name string) bool {
	switch {
	case name == "eth0", name == "docker0":
		return true
	case strings.HasPrefix(name, "br-"), strings.HasPrefix(name, "docker"),
		strings.HasPrefix(name, "hull"), strings.HasPrefix(name, "virbr"),
		strings.HasPrefix(name, "cni"):
		return true
	}
	return false
}
