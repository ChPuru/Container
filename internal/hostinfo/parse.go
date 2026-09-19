package hostinfo

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"math/bits"
	"strconv"
	"strings"
)

// MountEntry is one line of /proc/mounts or /proc/self/mountinfo, reduced to
// the fields hull cares about.
type MountEntry struct {
	// Source is the device or filesystem source field.
	Source string
	// Target is the mountpoint.
	Target string
	// FSType is the filesystem type name.
	FSType string
	// Options are the per-mount options, already split on commas.
	Options []string
}

// HasOption reports whether the mount carries the named option. An option of
// the form "key=value" matches the bare key as well.
func (m MountEntry) HasOption(name string) bool {
	for _, o := range m.Options {
		if o == name {
			return true
		}
		if k, _, ok := strings.Cut(o, "="); ok && k == name {
			return true
		}
	}
	return false
}

// unescapeMountField decodes the octal escapes (\040, \011, \012, \134) that
// the kernel uses for spaces and tabs in /proc/mounts fields.
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 4
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// ParseMounts parses /proc/mounts (or /etc/mtab) content.
func ParseMounts(r io.Reader) ([]MountEntry, error) {
	var out []MountEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		out = append(out, MountEntry{
			Source:  unescapeMountField(fields[0]),
			Target:  unescapeMountField(fields[1]),
			FSType:  fields[2],
			Options: strings.Split(fields[3], ","),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("hostinfo: reading mounts: %w", err)
	}
	return out, nil
}

// FindMount returns the last mount entry whose target equals path. The last
// wins because a later mount shadows an earlier one at the same point.
func FindMount(mounts []MountEntry, path string) (MountEntry, bool) {
	var found MountEntry
	ok := false
	for _, m := range mounts {
		if m.Target == path {
			found, ok = m, true
		}
	}
	return found, ok
}

// FindMountFor returns the mount entry governing path, i.e. the entry with the
// longest target that is a prefix of path.
func FindMountFor(mounts []MountEntry, path string) (MountEntry, bool) {
	var best MountEntry
	ok := false
	for _, m := range mounts {
		if m.Target != "/" && !strings.HasPrefix(path, m.Target+"/") && path != m.Target {
			continue
		}
		if len(m.Target) >= len(best.Target) || !ok {
			best, ok = m, true
		}
	}
	return best, ok
}

// ParseKernelRelease splits a uname release string such as
// "5.15.167.4-microsoft-standard-WSL2" into its major and minor components.
func ParseKernelRelease(release string) (major, minor int, err error) {
	s := strings.TrimSpace(release)
	if s == "" {
		return 0, 0, fmt.Errorf("hostinfo: empty kernel release")
	}
	// Cut at the first character that cannot start a version component.
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || s[end] == '.') {
		end++
	}
	parts := strings.Split(s[:end], ".")
	if len(parts) == 0 || parts[0] == "" {
		return 0, 0, fmt.Errorf("hostinfo: kernel release %q has no numeric prefix", release)
	}
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("hostinfo: kernel release %q major: %w", release, err)
	}
	if len(parts) > 1 {
		if parts[1] == "" {
			return 0, 0, fmt.Errorf("hostinfo: kernel release %q has a trailing dot with no minor version", release)
		}
		minor, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("hostinfo: kernel release %q minor: %w", release, err)
		}
	}
	return major, minor, nil
}

// ParseKernelConfig decodes a gzip-compressed kernel .config (the content of
// /proc/config.gz) into a map of option name to value. Comment lines and
// "# CONFIG_X is not set" lines are dropped.
func ParseKernelConfig(r io.Reader) (map[string]string, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("hostinfo: opening kernel config gzip stream: %w", err)
	}
	defer zr.Close()
	cfg, err := ParsePlainKernelConfig(zr)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// ParsePlainKernelConfig parses an uncompressed kernel .config.
func ParsePlainKernelConfig(r io.Reader) (map[string]string, error) {
	out := make(map[string]string)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(k, "CONFIG_") {
			continue
		}
		out[k] = strings.Trim(v, `"`)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("hostinfo: reading kernel config: %w", err)
	}
	return out, nil
}

// configIs reports whether a CONFIG_ option has one of the given values.
func configIs(cfg map[string]string, key string, values ...string) bool {
	v, ok := cfg[key]
	if !ok {
		return false
	}
	for _, want := range values {
		if v == want {
			return true
		}
	}
	return false
}

// ParseOSRelease parses an os-release file into its key/value pairs, stripping
// the optional surrounding quotes.
func ParseOSRelease(r io.Reader) (map[string]string, error) {
	out := make(map[string]string)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("hostinfo: reading os-release: %w", err)
	}
	return out, nil
}

// ParseModules parses /proc/modules into a set of loaded module names. On a
// kernel where everything is built in the file is empty, which is why callers
// must also consult /sys/module and the kernel config.
func ParseModules(r io.Reader) (map[string]bool, error) {
	out := make(map[string]bool)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		name, _, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if name != "" {
			out[name] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("hostinfo: reading modules: %w", err)
	}
	return out, nil
}

// ParseProcStatusField returns the value of a "Key:\tvalue" field from
// /proc/<pid>/status content.
func ParseProcStatusField(r io.Reader, key string) (string, bool, error) {
	sc := bufio.NewScanner(r)
	want := key + ":"
	for sc.Scan() {
		line := sc.Text()
		k, v, ok := strings.Cut(line, ":")
		if !ok || k+":" != want {
			continue
		}
		return strings.TrimSpace(v), true, nil
	}
	if err := sc.Err(); err != nil {
		return "", false, fmt.Errorf("hostinfo: reading proc status: %w", err)
	}
	return "", false, nil
}

// capNames maps a capability bit index to its lowercase kernel name.
var capNames = [...]string{
	"chown", "dac_override", "dac_read_search", "fowner", "fsetid",
	"kill", "setgid", "setuid", "setpcap", "linux_immutable",
	"net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock",
	"ipc_owner", "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace",
	"sys_pacct", "sys_admin", "sys_boot", "sys_nice", "sys_resource",
	"sys_time", "sys_tty_config", "mknod", "lease", "audit_write",
	"audit_control", "setfcap", "mac_override", "mac_admin", "syslog",
	"wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf",
	"checkpoint_restore",
}

// DecodeCapMask turns a capability bitmask into CAP_* names, in bit order.
// Bits with no known name are rendered as "cap_<n>".
func DecodeCapMask(mask uint64) []string {
	if mask == 0 {
		return nil
	}
	out := make([]string, 0, bits.OnesCount64(mask))
	for i := 0; i < 64; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		if i < len(capNames) {
			out = append(out, "CAP_"+strings.ToUpper(capNames[i]))
			continue
		}
		out = append(out, fmt.Sprintf("CAP_%d", i))
	}
	return out
}

// ParseCapBnd extracts the CapBnd line from /proc/<pid>/status content and
// decodes it into capability names.
func ParseCapBnd(r io.Reader) ([]string, error) {
	v, ok, err := ParseProcStatusField(r, "CapBnd")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("hostinfo: no CapBnd field in proc status")
	}
	mask, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
	if err != nil {
		return nil, fmt.Errorf("hostinfo: parsing CapBnd %q: %w", v, err)
	}
	return DecodeCapMask(mask), nil
}

// RouteEntry is one line of /proc/net/route.
type RouteEntry struct {
	// Iface is the outgoing interface name.
	Iface string
	// Destination, Gateway and Mask are the raw little-endian hex fields
	// converted to host byte order as 32-bit values.
	Destination uint32
	Gateway     uint32
	Mask        uint32
	// Flags is the route flag word.
	Flags uint32
}

// IsDefault reports whether the route is a default route (0.0.0.0/0 with a
// gateway).
func (e RouteEntry) IsDefault() bool { return e.Destination == 0 && e.Mask == 0 }

// ParseProcNetRoute parses /proc/net/route, skipping its header line.
func ParseProcNetRoute(r io.Reader) ([]RouteEntry, error) {
	var out []RouteEntry
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if first {
			first = false
			if len(fields) > 0 && fields[0] == "Iface" {
				continue
			}
		}
		if len(fields) < 8 {
			continue
		}
		dst, err1 := strconv.ParseUint(fields[1], 16, 32)
		gw, err2 := strconv.ParseUint(fields[2], 16, 32)
		flags, err3 := strconv.ParseUint(fields[3], 16, 32)
		mask, err4 := strconv.ParseUint(fields[7], 16, 32)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			continue
		}
		out = append(out, RouteEntry{
			Iface:       fields[0],
			Destination: uint32(dst),
			Gateway:     uint32(gw),
			Mask:        uint32(mask),
			Flags:       uint32(flags),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("hostinfo: reading /proc/net/route: %w", err)
	}
	return out, nil
}

// ParseSubIDRange finds the entry for user in an /etc/subuid or /etc/subgid
// file and returns it formatted as "start:count". It returns "" when the user
// has no entry.
func ParseSubIDRange(r io.Reader, user string) (string, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 || parts[0] != user {
			continue
		}
		return parts[1] + ":" + parts[2], nil
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("hostinfo: reading subid file: %w", err)
	}
	return "", nil
}

// ParseIptablesForwardPolicy extracts the FORWARD chain policy from the output
// of "iptables -S FORWARD". It returns ok=false when no policy line is found.
func ParseIptablesForwardPolicy(out string) (policy string, ok bool) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 3 && fields[0] == "-P" && fields[1] == "FORWARD" {
			return fields[2], true
		}
	}
	return "", false
}

// ParseNftForwardPolicy extracts the base-chain policy from the output of
// "nft list chain ip filter FORWARD". The policy is upper-cased so it compares
// with the iptables spelling.
func ParseNftForwardPolicy(out string) (policy string, ok bool) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		idx := strings.Index(line, "policy ")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len("policy "):])
		rest = strings.TrimRight(rest, ";}")
		rest = strings.TrimSpace(rest)
		if rest == "" {
			continue
		}
		return strings.ToUpper(strings.Fields(rest)[0]), true
	}
	return "", false
}

// ParseControllers splits a cgroup.controllers / cgroup.subtree_control file
// body into controller names.
func ParseControllers(s string) []string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return nil
	}
	return f
}

// wslVersionHint turns a kernel version into a sentence about which WSL kernel
// generation is running and what it implies.
func wslVersionHint(major, minor int, release string) string {
	switch {
	case major > 6 || (major == 6 && minor >= 6):
		return fmt.Sprintf("WSL kernel %s (6.x generation: pure cgroup v2, PSI available)", release)
	case major == 5 && minor == 15:
		return fmt.Sprintf("WSL kernel %s (legacy 5.15 generation: hybrid cgroups, no PSI, no idmapped overlay)", release)
	default:
		return fmt.Sprintf("kernel %s", release)
	}
}
