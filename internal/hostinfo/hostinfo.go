// Package hostinfo probes the host environment hull is about to run on and
// reports, honestly, whether every feature the engine depends on is present.
//
// It is the implementation behind "hull doctor". Every finding is expressed as
// a [Check] carrying a [Status] (ok, warn, fail or skip), a human-readable
// detail and — when something is wrong — a specific, actionable remedy. The
// package never silently degrades: a missing feature is reported, not guessed
// around.
//
// [Probe] is implemented for Linux only. On every other GOOS it returns
// [ErrUnsupported]; the report rendering helpers ([Report.Text],
// [Report.JSON]) are portable so the Windows CLI can print a report relayed
// from the engine distro.
package hostinfo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// ErrUnsupported is returned by [Probe] on operating systems where hull has no
// environment probe (anything other than Linux). It wraps [errors.ErrUnsupported]
// so callers may test it with errors.Is.
var ErrUnsupported = fmt.Errorf("hostinfo: probing is only implemented on linux: %w", errors.ErrUnsupported)

// Status is the outcome of a single [Check].
type Status string

// The possible check outcomes, ordered by severity.
const (
	// StatusOK means the feature is present and usable.
	StatusOK Status = "ok"
	// StatusWarn means hull will work but in a degraded or surprising way.
	StatusWarn Status = "warn"
	// StatusFail means hull cannot function correctly until the remedy is applied.
	StatusFail Status = "fail"
	// StatusSkip means the check could not be evaluated (missing tool, no
	// permission) and the result is genuinely unknown.
	StatusSkip Status = "skip"
)

// severity orders statuses for sorting and summarising.
func (s Status) severity() int {
	switch s {
	case StatusFail:
		return 3
	case StatusWarn:
		return 2
	case StatusSkip:
		return 1
	default:
		return 0
	}
}

// Check is one environment assertion with its verdict.
type Check struct {
	// Name is a short, stable identifier such as "cgroup v2 delegated".
	Name string `json:"name"`
	// Detail states what was actually observed.
	Detail string `json:"detail"`
	// Remedy states what the user should do. Empty when Status is StatusOK.
	Remedy string `json:"remedy,omitempty"`
	// Status is the verdict.
	Status Status `json:"status"`
	// Docs is an optional pointer into hull's documentation.
	Docs string `json:"docs,omitempty"`
}

// KernelInfo describes the running kernel.
type KernelInfo struct {
	// Release is uname -r, e.g. "5.15.167.4-microsoft-standard-WSL2".
	Release string `json:"release"`
	// Version is uname -v, the build string.
	Version string `json:"version"`
	// Arch is uname -m.
	Arch string `json:"arch"`
	// Major is the leading version component of Release.
	Major int `json:"major"`
	// Minor is the second version component of Release.
	Minor int `json:"minor"`
	// Config holds CONFIG_* values decoded from /proc/config.gz when present.
	// A value is either "y", "m" or the literal option value.
	Config map[string]string `json:"config,omitempty"`
	// ConfigSource records where Config came from, or why it is empty.
	ConfigSource string `json:"configSource,omitempty"`
}

// AtLeast reports whether the running kernel is at least major.minor.
func (k KernelInfo) AtLeast(major, minor int) bool {
	if k.Major != major {
		return k.Major > major
	}
	return k.Minor >= minor
}

// WSLInfo describes the WSL2 environment, if any.
type WSLInfo struct {
	// IsWSL is true when the kernel or runtime markers identify WSL.
	IsWSL bool `json:"isWSL"`
	// Distro is the ID= field of /etc/os-release.
	Distro string `json:"distro,omitempty"`
	// Interop is true when a WSLInterop binfmt handler is registered.
	Interop bool `json:"interop"`
	// SystemdPID1 is true when /proc/1/comm is "systemd".
	SystemdPID1 bool `json:"systemdPID1"`
	// MirroredNet reports WSL's mirrored networking mode. It is only
	// meaningful when MirroredNetKnown is true.
	MirroredNet bool `json:"mirroredNet"`
	// MirroredNetKnown is false when the probe could not decide; the report
	// then prints "unknown" rather than guessing.
	MirroredNetKnown bool `json:"mirroredNetKnown"`
	// WSLVersionHint is a human sentence about the kernel generation in use.
	WSLVersionHint string `json:"wslVersionHint,omitempty"`
	// SharedMntWSL is true when /mnt/wsl is a mountpoint, which is where hull
	// publishes its socket for sibling distros.
	SharedMntWSL bool `json:"sharedMntWSL"`
}

// CgroupInfo describes the cgroup hierarchy layout.
//
// TODO(hull): once internal/cgroups lands, replace probeCgroups with a call to
// cgroups.Detect() and translate its Warnings into Checks. The field set here
// deliberately mirrors what that detector must return.
type CgroupInfo struct {
	// Mode is "unified" (pure v2), "hybrid" (v1 and v2 both mounted),
	// "legacy" (v1 only) or "none".
	Mode string `json:"mode"`
	// UnifiedRoot is the mountpoint of the cgroup2 filesystem, if any.
	UnifiedRoot string `json:"unifiedRoot,omitempty"`
	// Controllers are the v2 controllers available at UnifiedRoot
	// (cgroup.controllers). Empty on a WSL 5.15 hybrid host.
	Controllers []string `json:"controllers,omitempty"`
	// SubtreeControl are the controllers enabled for children
	// (cgroup.subtree_control) at the root.
	SubtreeControl []string `json:"subtreeControl,omitempty"`
	// V1Controllers are the legacy controllers mounted under /sys/fs/cgroup.
	V1Controllers []string `json:"v1Controllers,omitempty"`
	// Delegated is true when the v2 hierarchy actually offers the controllers
	// hull needs (cpu, memory and pids).
	Delegated bool `json:"delegated"`
	// NSDelegate is true when the cgroup2 mount carries the nsdelegate option.
	NSDelegate bool `json:"nsDelegate"`
	// CgroupKill is true when cgroup.kill exists at the root (5.14+).
	CgroupKill bool `json:"cgroupKill"`
	// FreezeV2 is true when cgroup.freeze exists at the root.
	FreezeV2 bool `json:"freezeV2"`
	// PSI is true when /proc/pressure exists (CONFIG_PSI).
	PSI bool `json:"psi"`
	// Warnings collects non-fatal observations about the hierarchy.
	Warnings []string `json:"warnings,omitempty"`
}

// MissingControllers returns the controllers hull needs that the v2 hierarchy
// does not offer.
func (c CgroupInfo) MissingControllers() []string {
	have := make(map[string]bool, len(c.Controllers))
	for _, ctrl := range c.Controllers {
		have[ctrl] = true
	}
	var missing []string
	for _, want := range []string{"cpu", "memory", "pids"} {
		if !have[want] {
			missing = append(missing, want)
		}
	}
	return missing
}

// OverlayInfo describes overlayfs support.
type OverlayInfo struct {
	// Supported is true when "overlay" appears in /proc/filesystems.
	Supported bool `json:"supported"`
	// Redirect is the redirect_dir module parameter; empty when absent.
	Redirect string `json:"redirectDir,omitempty"`
	// Metacopy is the metacopy module parameter.
	Metacopy string `json:"metacopy,omitempty"`
	// Index is the index module parameter.
	Index string `json:"index,omitempty"`
	// Xino is the xino (or xino_auto) module parameter.
	Xino string `json:"xino,omitempty"`
	// RedirectAlwaysFollow is the redirect_always_follow parameter.
	RedirectAlwaysFollow string `json:"redirectAlwaysFollow,omitempty"`
	// UserXattr reports support for the userxattr mount option (5.11+).
	UserXattr bool `json:"userxattr"`
	// LowerdirPlus reports support for the lowerdir+= syntax (6.7+).
	LowerdirPlus bool `json:"lowerdirPlus"`
	// IdmappedLayers reports support for idmapped overlay lower layers (5.19+).
	IdmappedLayers bool `json:"idmappedLayers"`
	// MountTested is true when the probe actually performed a test mount.
	MountTested bool `json:"mountTested"`
	// MountOK is the result of that test mount.
	MountOK bool `json:"mountOK"`
	// MountError is the error text when MountTested is true and MountOK false.
	MountError string `json:"mountError,omitempty"`
}

// NamespaceInfo describes namespace availability for the current process.
type NamespaceInfo struct {
	// User is true when /proc/self/ns/user exists.
	User bool `json:"user"`
	// PID is true when /proc/self/ns/pid exists.
	PID bool `json:"pid"`
	// Net is true when /proc/self/ns/net exists.
	Net bool `json:"net"`
	// Mount is true when /proc/self/ns/mnt exists.
	Mount bool `json:"mount"`
	// IPC is true when /proc/self/ns/ipc exists.
	IPC bool `json:"ipc"`
	// UTS is true when /proc/self/ns/uts exists.
	UTS bool `json:"uts"`
	// Cgroup is true when /proc/self/ns/cgroup exists.
	Cgroup bool `json:"cgroup"`
	// Time is true when /proc/self/ns/time exists (5.6+).
	Time bool `json:"time"`
	// MaxUserNamespaces is /proc/sys/user/max_user_namespaces; -1 when unread.
	MaxUserNamespaces int `json:"maxUserNamespaces"`
	// UnprivilegedUsernsClone is the Debian/Ubuntu-specific sysctl. It is
	// reported true when the sysctl is absent, because absence means the
	// restriction does not exist on this kernel.
	UnprivilegedUsernsClone bool `json:"unprivilegedUsernsClone"`
	// UsernsCloneSysctl is true when the sysctl file actually exists.
	UsernsCloneSysctl bool `json:"usernsCloneSysctl"`
	// SubuidRange is the current user's /etc/subuid entry as "start:count".
	SubuidRange string `json:"subuidRange,omitempty"`
	// SubgidRange is the current user's /etc/subgid entry as "start:count".
	SubgidRange string `json:"subgidRange,omitempty"`
}

// SecurityInfo describes the kernel's sandboxing facilities.
type SecurityInfo struct {
	// Seccomp is true when CONFIG_SECCOMP is enabled or actions_avail exists.
	Seccomp bool `json:"seccomp"`
	// SeccompActions is /proc/sys/kernel/seccomp/actions_avail, split.
	SeccompActions []string `json:"seccompActions,omitempty"`
	// NoNewPrivs is the current process's PR_GET_NO_NEW_PRIVS value.
	NoNewPrivs bool `json:"noNewPrivs"`
	// Landlock is the Landlock ABI version, or 0 when Landlock is unavailable.
	Landlock int `json:"landlock"`
	// AppArmor is true when the AppArmor LSM is mounted and active.
	AppArmor bool `json:"apparmor"`
	// SELinux is true when the SELinux LSM is mounted.
	SELinux bool `json:"selinux"`
	// Capabilities is the decoded bounding set from /proc/self/status CapBnd.
	Capabilities []string `json:"capabilities,omitempty"`
}

// StorageInfo describes the filesystem holding hull's data root.
type StorageInfo struct {
	// DataRoot is the configured data root (HULL_DATA_ROOT or /var/lib/hull).
	DataRoot string `json:"dataRoot"`
	// Probed is the nearest existing ancestor of DataRoot that was statfs'd.
	Probed string `json:"probed,omitempty"`
	// FSType is the filesystem name, e.g. "ext4", "9p", "virtiofs".
	FSType string `json:"fsType"`
	// FreeBytes is the space available to an unprivileged writer.
	FreeBytes uint64 `json:"freeBytes"`
	// TotalBytes is the filesystem size.
	TotalBytes uint64 `json:"totalBytes"`
	// SupportsDType is true when readdir returns a populated d_type, which
	// overlayfs requires of its upper layer.
	SupportsDType bool `json:"supportsDType"`
	// OnDrvFs is true when the data root lives on a Windows drive share
	// (9p / drvfs / virtiofs / cifs), which is catastrophically slow.
	OnDrvFs bool `json:"onDrvFs"`
}

// NetworkInfo describes the host's networking prerequisites.
type NetworkInfo struct {
	// IPForward is /proc/sys/net/ipv4/ip_forward.
	IPForward bool `json:"ipForward"`
	// BridgeModule reports whether the bridge driver is loaded or built in.
	BridgeModule bool `json:"bridgeModule"`
	// VethModule reports whether the veth driver is loaded or built in.
	VethModule bool `json:"vethModule"`
	// NftablesModule reports whether nf_tables is loaded or built in.
	NftablesModule bool `json:"nftablesModule"`
	// IptablesNAT is true when an iptables NAT table could be listed.
	IptablesNAT bool `json:"iptablesNAT"`
	// NftBinary is the resolved path to nft, empty when absent.
	NftBinary string `json:"nftBinary,omitempty"`
	// IptablesBinary is the resolved path to iptables, empty when absent.
	IptablesBinary string `json:"iptablesBinary,omitempty"`
	// DockerPresent is true when Docker Desktop shares this VM.
	DockerPresent bool `json:"dockerPresent"`
	// DockerForwardPolicyDrop is true when the filter FORWARD chain policy is
	// DROP, which silently breaks hull's bridge traffic unless hull inserts an
	// explicit ACCEPT.
	DockerForwardPolicyDrop bool `json:"dockerForwardPolicyDrop"`
	// ForwardPolicy is the raw observed policy ("ACCEPT", "DROP" or "").
	ForwardPolicy string `json:"forwardPolicy,omitempty"`
	// ForwardPolicySource names the tool that reported ForwardPolicy.
	ForwardPolicySource string `json:"forwardPolicySource,omitempty"`
	// ExistingSubnets are the CIDRs already claimed by docker*, br-*, hull*
	// and eth0 interfaces, so hull's IPAM can avoid them.
	ExistingSubnets []string `json:"existingSubnets,omitempty"`
	// WSLNATSubnet is the subnet of the WSL NAT interface (usually eth0).
	WSLNATSubnet string `json:"wslNATSubnet,omitempty"`
}

// Report is the full output of one [Probe] run.
type Report struct {
	Kernel     KernelInfo    `json:"kernel"`
	WSL        WSLInfo       `json:"wsl"`
	Cgroups    CgroupInfo    `json:"cgroups"`
	Overlay    OverlayInfo   `json:"overlay"`
	Namespaces NamespaceInfo `json:"namespaces"`
	Security   SecurityInfo  `json:"security"`
	Storage    StorageInfo   `json:"storage"`
	Network    NetworkInfo   `json:"network"`
	Checks     []Check       `json:"checks"`
	Generated  time.Time     `json:"generated"`
}

// Failed reports whether any check failed outright.
func (r *Report) Failed() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return true
		}
	}
	return false
}

// Warned reports whether any check produced a warning.
func (r *Report) Warned() bool {
	for _, c := range r.Checks {
		if c.Status == StatusWarn {
			return true
		}
	}
	return false
}

// Counts returns how many checks landed in each status.
func (r *Report) Counts() map[Status]int {
	m := map[Status]int{StatusOK: 0, StatusWarn: 0, StatusFail: 0, StatusSkip: 0}
	for _, c := range r.Checks {
		m[c.Status]++
	}
	return m
}

// JSON writes the report as indented JSON.
func (r *Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("hostinfo: encoding report: %w", err)
	}
	return nil
}

// ---------- text rendering ----------

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

type painter struct{ on bool }

func (p painter) wrap(code, s string) string {
	if !p.on || s == "" {
		return s
	}
	return code + s + ansiReset
}

// status renders a fixed-visible-width status label such as "[fail]".
func (p painter) status(s Status) string {
	label := pad("["+string(s)+"]", 6)
	if !p.on {
		return label
	}
	switch s {
	case StatusOK:
		return ansiGreen + label + ansiReset
	case StatusWarn:
		return ansiYellow + label + ansiReset
	case StatusFail:
		return ansiRed + label + ansiReset
	default:
		return ansiDim + label + ansiReset
	}
}

type kv struct{ k, v string }

// Text writes the human-readable report: the fact sections first, then the
// checks, all aligned into columns. When color is true the output carries ANSI
// escapes. The layout is stable: the same Report always renders identically.
func (r *Report) Text(w io.Writer, color bool) error {
	p := painter{on: color}
	var b strings.Builder

	b.WriteString(p.wrap(ansiBold, "hull doctor"))
	b.WriteString("  ")
	b.WriteString(p.wrap(ansiDim, r.Generated.UTC().Format(time.RFC3339)))
	b.WriteString("\n")

	sections := []struct {
		name string
		rows []kv
	}{
		{"Kernel", r.kernelRows()},
		{"WSL", r.wslRows()},
		{"Cgroups", r.cgroupRows()},
		{"Overlay", r.overlayRows()},
		{"Namespaces", r.namespaceRows()},
		{"Security", r.securityRows()},
		{"Storage", r.storageRows()},
		{"Network", r.networkRows()},
	}

	// One shared key-column width across every section keeps the whole report
	// visually aligned rather than ragged section by section.
	width := 0
	for _, s := range sections {
		for _, row := range s.rows {
			if len(row.k) > width {
				width = len(row.k)
			}
		}
	}

	for _, s := range sections {
		b.WriteString("\n")
		b.WriteString(p.wrap(ansiBold, s.name))
		b.WriteString("\n")
		for _, row := range s.rows {
			b.WriteString("  ")
			b.WriteString(p.wrap(ansiCyan, pad(row.k, width)))
			b.WriteString("  ")
			b.WriteString(row.v)
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(p.wrap(ansiBold, "Checks"))
	b.WriteString("\n")
	nameWidth := 0
	for _, c := range r.Checks {
		if len(c.Name) > nameWidth {
			nameWidth = len(c.Name)
		}
	}
	indent := strings.Repeat(" ", 2+6+2+nameWidth+2)
	for _, c := range r.Checks {
		b.WriteString("  ")
		b.WriteString(p.status(c.Status))
		b.WriteString("  ")
		b.WriteString(pad(c.Name, nameWidth))
		b.WriteString("  ")
		b.WriteString(c.Detail)
		b.WriteString("\n")
		for _, line := range wrapText(c.Remedy, 78) {
			b.WriteString(indent)
			b.WriteString(p.wrap(ansiDim, "-> "+line))
			b.WriteString("\n")
		}
		if c.Docs != "" {
			b.WriteString(indent)
			b.WriteString(p.wrap(ansiDim, "   "+c.Docs))
			b.WriteString("\n")
		}
	}

	counts := r.Counts()
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("%d ok, %d warn, %d fail, %d skip\n",
		counts[StatusOK], counts[StatusWarn], counts[StatusFail], counts[StatusSkip]))

	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("hostinfo: writing report: %w", err)
	}
	return nil
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// wrapText greedily wraps s to lines of at most n bytes, never breaking words.
// It returns nil for an empty string.
func wrapText(s string, n int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var out []string
	cur := words[0]
	for _, word := range words[1:] {
		if len(cur)+1+len(word) > n {
			out = append(out, cur)
			cur = word
			continue
		}
		cur += " " + word
	}
	return append(out, cur)
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func joinOr(v []string, fallback string) string {
	if len(v) == 0 {
		return fallback
	}
	return strings.Join(v, " ")
}

// humanBytes formats n with binary units, e.g. "229.7 GiB".
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 5; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func (r *Report) kernelRows() []kv {
	rows := []kv{
		{"release", or(r.Kernel.Release, "unknown")},
		{"version", or(r.Kernel.Version, "unknown")},
		{"arch", or(r.Kernel.Arch, "unknown")},
		{"parsed", fmt.Sprintf("%d.%d", r.Kernel.Major, r.Kernel.Minor)},
	}
	if r.Kernel.ConfigSource != "" {
		rows = append(rows, kv{"kconfig", fmt.Sprintf("%s (%d options)", r.Kernel.ConfigSource, len(r.Kernel.Config))})
	}
	return rows
}

func (r *Report) wslRows() []kv {
	mirrored := "unknown"
	if r.WSL.MirroredNetKnown {
		mirrored = yesno(r.WSL.MirroredNet)
	}
	return []kv{
		{"is wsl", yesno(r.WSL.IsWSL)},
		{"distro", or(r.WSL.Distro, "unknown")},
		{"interop", yesno(r.WSL.Interop)},
		{"systemd pid1", yesno(r.WSL.SystemdPID1)},
		{"mirrored net", mirrored},
		{"/mnt/wsl", yesno(r.WSL.SharedMntWSL)},
		{"generation", or(r.WSL.WSLVersionHint, "unknown")},
	}
}

func (r *Report) cgroupRows() []kv {
	return []kv{
		{"mode", or(r.Cgroups.Mode, "unknown")},
		{"unified root", or(r.Cgroups.UnifiedRoot, "-")},
		{"v2 controllers", joinOr(r.Cgroups.Controllers, "(none)")},
		{"v2 subtree", joinOr(r.Cgroups.SubtreeControl, "(none)")},
		{"v1 controllers", joinOr(r.Cgroups.V1Controllers, "(none)")},
		{"nsdelegate", yesno(r.Cgroups.NSDelegate)},
		{"cgroup.kill", yesno(r.Cgroups.CgroupKill)},
		{"cgroup.freeze", yesno(r.Cgroups.FreezeV2)},
		{"psi", yesno(r.Cgroups.PSI)},
	}
}

func (r *Report) overlayRows() []kv {
	test := "not run (needs root)"
	if r.Overlay.MountTested {
		test = "mounted and unmounted cleanly"
		if !r.Overlay.MountOK {
			test = "FAILED: " + r.Overlay.MountError
		}
	}
	return []kv{
		{"supported", yesno(r.Overlay.Supported)},
		{"redirect_dir", or(r.Overlay.Redirect, "-")},
		{"metacopy", or(r.Overlay.Metacopy, "-")},
		{"index", or(r.Overlay.Index, "-")},
		{"xino", or(r.Overlay.Xino, "-")},
		{"userxattr", yesno(r.Overlay.UserXattr)},
		{"lowerdir+", yesno(r.Overlay.LowerdirPlus)},
		{"idmapped layers", yesno(r.Overlay.IdmappedLayers)},
		{"live mount test", test},
	}
}

func (r *Report) namespaceRows() []kv {
	var present []string
	for _, n := range []struct {
		name string
		ok   bool
	}{
		{"user", r.Namespaces.User}, {"pid", r.Namespaces.PID}, {"net", r.Namespaces.Net},
		{"mnt", r.Namespaces.Mount}, {"ipc", r.Namespaces.IPC}, {"uts", r.Namespaces.UTS},
		{"cgroup", r.Namespaces.Cgroup}, {"time", r.Namespaces.Time},
	} {
		if n.ok {
			present = append(present, n.name)
		}
	}
	clone := "sysctl absent (unrestricted)"
	if r.Namespaces.UsernsCloneSysctl {
		clone = yesno(r.Namespaces.UnprivilegedUsernsClone)
	}
	return []kv{
		{"available", joinOr(present, "(none)")},
		{"max user ns", fmt.Sprintf("%d", r.Namespaces.MaxUserNamespaces)},
		{"unpriv clone", clone},
		{"subuid", or(r.Namespaces.SubuidRange, "(none)")},
		{"subgid", or(r.Namespaces.SubgidRange, "(none)")},
	}
}

func (r *Report) securityRows() []kv {
	landlock := "unavailable"
	if r.Security.Landlock > 0 {
		landlock = fmt.Sprintf("ABI %d", r.Security.Landlock)
	}
	return []kv{
		{"seccomp", yesno(r.Security.Seccomp)},
		{"seccomp actions", joinOr(r.Security.SeccompActions, "(unknown)")},
		{"no_new_privs", yesno(r.Security.NoNewPrivs)},
		{"landlock", landlock},
		{"apparmor", yesno(r.Security.AppArmor)},
		{"selinux", yesno(r.Security.SELinux)},
		{"cap bounding", fmt.Sprintf("%d capabilities", len(r.Security.Capabilities))},
	}
}

func (r *Report) storageRows() []kv {
	return []kv{
		{"data root", or(r.Storage.DataRoot, "unknown")},
		{"probed path", or(r.Storage.Probed, "-")},
		{"fstype", or(r.Storage.FSType, "unknown")},
		{"free", fmt.Sprintf("%s of %s", humanBytes(r.Storage.FreeBytes), humanBytes(r.Storage.TotalBytes))},
		{"d_type", yesno(r.Storage.SupportsDType)},
		{"on drvfs", yesno(r.Storage.OnDrvFs)},
	}
}

func (r *Report) networkRows() []kv {
	policy := or(r.Network.ForwardPolicy, "unknown")
	if r.Network.ForwardPolicySource != "" {
		policy += " (via " + r.Network.ForwardPolicySource + ")"
	}
	return []kv{
		{"ip_forward", yesno(r.Network.IPForward)},
		{"bridge", yesno(r.Network.BridgeModule)},
		{"veth", yesno(r.Network.VethModule)},
		{"nf_tables", yesno(r.Network.NftablesModule)},
		{"nft binary", or(r.Network.NftBinary, "(absent)")},
		{"iptables binary", or(r.Network.IptablesBinary, "(absent)")},
		{"iptables nat", yesno(r.Network.IptablesNAT)},
		{"docker present", yesno(r.Network.DockerPresent)},
		{"FORWARD policy", policy},
		{"wsl nat subnet", or(r.Network.WSLNATSubnet, "unknown")},
		{"claimed subnets", joinOr(r.Network.ExistingSubnets, "(none)")},
	}
}

// sortChecks orders checks worst-first, then by name, so the report opens with
// what the user must fix. It is stable for identical inputs.
func sortChecks(checks []Check) {
	sort.SliceStable(checks, func(i, j int) bool {
		si, sj := checks[i].Status.severity(), checks[j].Status.severity()
		if si != sj {
			return si > sj
		}
		return checks[i].Name < checks[j].Name
	})
}
