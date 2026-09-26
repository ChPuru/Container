package cli

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ChPuru/hull/internal/client"
)

// ParsePublish expands one -p/--publish spec into exposed ports and host
// bindings.
//
// Every Docker spelling is accepted:
//
//	80                       one container port, random host port
//	8080:80                  a fixed host port
//	127.0.0.1:8080:80        bound to one host address
//	127.0.0.1::80            one address, random host port
//	8000-8010:8000-8010/udp  equal-length ranges, with a protocol
func ParsePublish(spec string) (exposed []string, bindings map[string][]client.PortBinding, err error) {
	raw := strings.TrimSpace(spec)
	if raw == "" {
		return nil, nil, fmt.Errorf("invalid publish spec: empty")
	}
	proto := "tcp"
	if body, p, ok := strings.Cut(raw, "/"); ok {
		raw, proto = body, strings.ToLower(p)
		if proto != "tcp" && proto != "udp" && proto != "sctp" {
			return nil, nil, fmt.Errorf("invalid publish spec %q: unknown protocol %q", spec, proto)
		}
	}
	hostIP, hostPart, ctrPart, err := splitPublish(raw, spec)
	if err != nil {
		return nil, nil, err
	}
	ctrPorts, err := expandPortRange(ctrPart, spec)
	if err != nil {
		return nil, nil, err
	}
	var hostPorts []string
	if hostPart != "" {
		hostPorts, err = expandPortRange(hostPart, spec)
		if err != nil {
			return nil, nil, err
		}
		if len(hostPorts) != len(ctrPorts) {
			return nil, nil, fmt.Errorf("invalid publish spec %q: host and container port ranges differ in length", spec)
		}
	}
	bindings = make(map[string][]client.PortBinding, len(ctrPorts))
	for i, cp := range ctrPorts {
		key := cp + "/" + proto
		exposed = append(exposed, key)
		b := client.PortBinding{HostIP: hostIP}
		if hostPorts != nil {
			b.HostPort = hostPorts[i]
		}
		bindings[key] = append(bindings[key], b)
	}
	return exposed, bindings, nil
}

// splitPublish separates the optional host address, the optional host port and
// the container port of a publish spec. An IPv6 literal must be bracketed, so
// colon counting alone is not enough.
func splitPublish(raw, spec string) (hostIP, hostPart, ctrPart string, err error) {
	if strings.HasPrefix(raw, "[") {
		end := strings.Index(raw, "]")
		if end < 0 {
			return "", "", "", fmt.Errorf("invalid publish spec %q: unterminated IPv6 address", spec)
		}
		hostIP = raw[1:end]
		rest := strings.TrimPrefix(raw[end+1:], ":")
		hostPart, ctrPart, _ = strings.Cut(rest, ":")
		if ctrPart == "" {
			ctrPart, hostPart = hostPart, ""
		}
		return hostIP, hostPart, ctrPart, nil
	}
	parts := strings.Split(raw, ":")
	switch len(parts) {
	case 1:
		return "", "", parts[0], nil
	case 2:
		return "", parts[0], parts[1], nil
	case 3:
		if parts[0] != "" && net.ParseIP(parts[0]) == nil {
			return "", "", "", fmt.Errorf("invalid publish spec %q: %q is not an IP address", spec, parts[0])
		}
		return parts[0], parts[1], parts[2], nil
	default:
		return "", "", "", fmt.Errorf("invalid publish spec %q", spec)
	}
}

// expandPortRange turns "80" or "8000-8010" into the list of ports it covers.
func expandPortRange(s, spec string) ([]string, error) {
	lo, hi, isRange := strings.Cut(s, "-")
	start, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil || start < 1 || start > 65535 {
		return nil, fmt.Errorf("invalid publish spec %q: %q is not a port", spec, lo)
	}
	if !isRange {
		return []string{strconv.Itoa(start)}, nil
	}
	end, err := strconv.Atoi(strings.TrimSpace(hi))
	if err != nil || end < start || end > 65535 {
		return nil, fmt.Errorf("invalid publish spec %q: %q is not a port range", spec, s)
	}
	if end-start > 1024 {
		return nil, fmt.Errorf("invalid publish spec %q: range of %d ports is too large", spec, end-start+1)
	}
	out := make([]string, 0, end-start+1)
	for p := start; p <= end; p++ {
		out = append(out, strconv.Itoa(p))
	}
	return out, nil
}

// ParseExpose expands one --expose spec, which is a port or a port range with
// an optional protocol and no host side.
func ParseExpose(spec string) ([]string, error) {
	body, proto, ok := strings.Cut(spec, "/")
	if !ok || proto == "" {
		proto = "tcp"
	}
	ports, err := expandPortRange(body, spec)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, p+"/"+strings.ToLower(proto))
	}
	return out, nil
}

// ParseMount parses one --mount spec: comma-separated key=value pairs with
// type, source, target and the type-specific options.
func ParseMount(spec string) (client.Mount, error) {
	m := client.Mount{Type: "volume"}
	var tmpfsSize, tmpfsMode string
	for _, field := range splitOptions(spec) {
		key, value, _ := strings.Cut(field, "=")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "type":
			m.Type = value
		case "source", "src":
			m.Source = value
		case "target", "destination", "dst":
			m.Target = value
		case "readonly", "ro":
			m.ReadOnly = value == "" || isTrue(value)
		case "bind-propagation":
			if m.BindOptions == nil {
				m.BindOptions = &client.BindOptions{}
			}
			m.BindOptions.Propagation = value
		case "bind-nonrecursive":
			if m.BindOptions == nil {
				m.BindOptions = &client.BindOptions{}
			}
			m.BindOptions.Propagation = "rprivate"
		case "volume-nocopy":
			if m.VolumeOptions == nil {
				m.VolumeOptions = &client.VolumeOptions{}
			}
			m.VolumeOptions.NoCopy = value == "" || isTrue(value)
		case "tmpfs-size":
			tmpfsSize = value
		case "tmpfs-mode":
			tmpfsMode = value
		case "":
			continue
		default:
			return client.Mount{}, fmt.Errorf("invalid --mount %q: unknown field %q", spec, key)
		}
	}
	if m.Target == "" {
		return client.Mount{}, fmt.Errorf("invalid --mount %q: target is required", spec)
	}
	switch m.Type {
	case "bind":
		if m.Source == "" {
			return client.Mount{}, fmt.Errorf("invalid --mount %q: a bind needs a source", spec)
		}
		m.Source = TranslateHostPath(m.Source)
	case "volume", "tmpfs":
	default:
		return client.Mount{}, fmt.Errorf("invalid --mount %q: unknown type %q", spec, m.Type)
	}
	if tmpfsSize != "" || tmpfsMode != "" {
		opts := &client.TmpfsOptions{}
		if tmpfsSize != "" {
			n, err := ParseSize(tmpfsSize)
			if err != nil {
				return client.Mount{}, fmt.Errorf("invalid --mount %q: %w", spec, err)
			}
			opts.SizeBytes = n
		}
		if tmpfsMode != "" {
			mode, err := strconv.ParseUint(tmpfsMode, 8, 32)
			if err != nil {
				return client.Mount{}, fmt.Errorf("invalid --mount %q: bad tmpfs-mode %q", spec, tmpfsMode)
			}
			opts.Mode = uint32(mode)
		}
		m.TmpfsOptions = opts
	}
	return m, nil
}

// splitOptions splits a comma-separated option list, honouring a quoted value
// so a bind source containing a comma survives.
func splitOptions(s string) []string {
	var out []string
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0 && c == quote:
			quote = 0
		case quote == 0 && (c == '"' || c == '\''):
			quote = c
		case quote == 0 && c == ',':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// isTrue reads the loose booleans users type into option lists.
func isTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "on":
		return true
	}
	return false
}

// ParseTmpfs parses one --tmpfs spec, "PATH" or "PATH:OPTIONS".
func ParseTmpfs(spec string) (path, options string, err error) {
	path, options, _ = strings.Cut(spec, ":")
	if path == "" || !strings.HasPrefix(path, "/") {
		return "", "", fmt.Errorf("invalid --tmpfs %q: the path must be absolute", spec)
	}
	return path, options, nil
}

// ParseDevice parses one --device spec,
// "HOST[:CONTAINER[:PERMISSIONS]]".
func ParseDevice(spec string) (client.DeviceMapping, error) {
	parts := strings.Split(spec, ":")
	d := client.DeviceMapping{CgroupPermissions: "rwm"}
	switch len(parts) {
	case 1:
		d.PathOnHost, d.PathInContainer = parts[0], parts[0]
	case 2:
		d.PathOnHost = parts[0]
		if isPermissions(parts[1]) {
			d.PathInContainer, d.CgroupPermissions = parts[0], parts[1]
		} else {
			d.PathInContainer = parts[1]
		}
	case 3:
		d.PathOnHost, d.PathInContainer, d.CgroupPermissions = parts[0], parts[1], parts[2]
		if !isPermissions(d.CgroupPermissions) {
			return client.DeviceMapping{}, fmt.Errorf("invalid --device %q: %q is not a permission string", spec, d.CgroupPermissions)
		}
	default:
		return client.DeviceMapping{}, fmt.Errorf("invalid --device %q", spec)
	}
	if d.PathOnHost == "" || d.PathInContainer == "" {
		return client.DeviceMapping{}, fmt.Errorf("invalid --device %q: both paths must be set", spec)
	}
	return d, nil
}

// isPermissions reports whether s is a cgroup device permission string.
func isPermissions(s string) bool {
	if s == "" || len(s) > 3 {
		return false
	}
	for _, r := range s {
		if r != 'r' && r != 'w' && r != 'm' {
			return false
		}
	}
	return true
}

// ParseUlimit parses one --ulimit spec, "NAME=SOFT[:HARD]".
func ParseUlimit(spec string) (client.Ulimit, error) {
	name, limits, ok := strings.Cut(spec, "=")
	if !ok || name == "" {
		return client.Ulimit{}, fmt.Errorf("invalid --ulimit %q: want NAME=SOFT[:HARD]", spec)
	}
	softStr, hardStr, hasHard := strings.Cut(limits, ":")
	soft, err := parseLimit(softStr)
	if err != nil {
		return client.Ulimit{}, fmt.Errorf("invalid --ulimit %q: %w", spec, err)
	}
	hard := soft
	if hasHard {
		hard, err = parseLimit(hardStr)
		if err != nil {
			return client.Ulimit{}, fmt.Errorf("invalid --ulimit %q: %w", spec, err)
		}
	}
	return client.Ulimit{Name: name, Soft: soft, Hard: hard}, nil
}

// parseLimit reads one rlimit value, where "unlimited" and -1 both mean no
// limit.
func parseLimit(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "unlimited" || s == "-1" {
		return -1, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a limit", s)
	}
	return v, nil
}

// ParseRestartPolicy parses one --restart spec, "no", "always",
// "unless-stopped" or "on-failure[:MAX]".
func ParseRestartPolicy(spec string) (client.RestartPolicy, error) {
	name, maxStr, hasMax := strings.Cut(spec, ":")
	p := client.RestartPolicy{Name: name}
	switch name {
	case "", "no", "always", "unless-stopped":
		if hasMax {
			return client.RestartPolicy{}, fmt.Errorf("invalid --restart %q: only on-failure takes a retry count", spec)
		}
	case "on-failure":
		if hasMax {
			n, err := strconv.Atoi(maxStr)
			if err != nil || n < 0 {
				return client.RestartPolicy{}, fmt.Errorf("invalid --restart %q: %q is not a retry count", spec, maxStr)
			}
			p.MaximumRetryCount = n
		}
	default:
		return client.RestartPolicy{}, fmt.Errorf("invalid --restart %q: want no, always, unless-stopped or on-failure[:max]", spec)
	}
	return p, nil
}

// ParseKeyValue splits "K=V" into its halves. A bare "K" takes its value from
// the current environment, which is what "-e PATH" means.
func ParseKeyValue(spec string) (key, value string) {
	key, value, ok := strings.Cut(spec, "=")
	if !ok {
		return key, os.Getenv(key)
	}
	return key, value
}

// ReadEnvFile reads an --env-file: one KEY=VALUE per line, with blank lines
// and # comments ignored, and a bare KEY taking its value from the
// environment.
func ReadEnvFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading env file: %w", err)
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("%s:%d: no variable name", path, line)
		}
		if !ok {
			if v, present := os.LookupEnv(key); present {
				out = append(out, key+"="+v)
			}
			continue
		}
		out = append(out, key+"="+value)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading env file %s: %w", path, err)
	}
	return out, nil
}

// ReadLabelFile reads a --label-file, which has the same shape as an env file.
func ReadLabelFile(path string) ([]string, error) { return ReadEnvFile(path) }

// ParseLabels folds "k=v" strings into a map, later entries winning.
func ParseLabels(specs []string) map[string]string {
	if len(specs) == 0 {
		return nil
	}
	out := make(map[string]string, len(specs))
	for _, s := range specs {
		k, v, _ := strings.Cut(s, "=")
		if k == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// ParseAddHost validates one --add-host entry, "NAME:IP". The special address
// "host-gateway" resolves to the bridge gateway inside the engine, so it is
// passed through rather than parsed.
func ParseAddHost(spec string) (string, error) {
	name, addr, ok := strings.Cut(spec, ":")
	if !ok || name == "" || addr == "" {
		return "", fmt.Errorf("invalid --add-host %q: want NAME:IP", spec)
	}
	if addr != "host-gateway" && net.ParseIP(addr) == nil {
		return "", fmt.Errorf("invalid --add-host %q: %q is not an IP address", spec, addr)
	}
	return spec, nil
}

// ParseHealthcheck builds a healthcheck from the --health-* flags. It returns
// nil when the user asked for nothing.
func ParseHealthcheck(cmd string, interval, timeout, startPeriod time.Duration, retries int, none bool) *client.HealthConfig {
	if none {
		return &client.HealthConfig{Test: []string{"NONE"}}
	}
	if cmd == "" && interval == 0 && timeout == 0 && startPeriod == 0 && retries == 0 {
		return nil
	}
	hc := &client.HealthConfig{
		Interval:    interval,
		Timeout:     timeout,
		StartPeriod: startPeriod,
		Retries:     retries,
	}
	if cmd != "" {
		hc.Test = []string{"CMD-SHELL", cmd}
	}
	return hc
}

// TranslateHostPath rewrites a Windows path into the path the engine sees
// inside the WSL VM, so "hull run -v C:\src:/src" works from PowerShell.
//
// A drive letter becomes /mnt/<drive>, backslashes become forward slashes, and
// anything that is already a POSIX path or a volume name is left alone. The
// translation happens in the CLI rather than the engine because only the
// client knows whether the string came from a Windows shell.
func TranslateHostPath(p string) string {
	if p == "" {
		return p
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") {
		return p
	}
	// \\wsl$\distro\... and \\wsl.localhost\distro\... name a path that is
	// already inside the VM.
	lower := strings.ToLower(p)
	for _, prefix := range []string{`\\wsl$\`, `\\wsl.localhost\`} {
		if strings.HasPrefix(lower, prefix) {
			rest := p[len(prefix):]
			if _, tail, ok := strings.Cut(rest, `\`); ok {
				return "/" + strings.ReplaceAll(tail, `\`, "/")
			}
			return "/"
		}
	}
	if len(p) >= 2 && p[1] == ':' && isDriveLetter(p[0]) {
		rest := strings.ReplaceAll(p[2:], `\`, "/")
		rest = strings.TrimPrefix(rest, "/")
		drive := strings.ToLower(string(p[0]))
		if rest == "" {
			return "/mnt/" + drive
		}
		return "/mnt/" + drive + "/" + rest
	}
	return p
}

// isDriveLetter reports whether c is an ASCII letter.
func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// ParseBind normalises one -v/--volume spec, translating a Windows source path
// and leaving a named volume alone.
//
// A Windows path has a colon after its drive letter, which collides with the
// spec's own separator, so the split is done by counting from the right: the
// mode, if any, then the container path, then whatever remains is the source.
func ParseBind(spec string) (string, error) {
	parts := splitBind(spec)
	switch len(parts) {
	case 1:
		if !strings.HasPrefix(parts[0], "/") {
			return "", fmt.Errorf("invalid -v %q: an anonymous volume needs an absolute container path", spec)
		}
		return parts[0], nil
	case 2:
		return TranslateHostPath(parts[0]) + ":" + parts[1], nil
	case 3:
		return TranslateHostPath(parts[0]) + ":" + parts[1] + ":" + parts[2], nil
	default:
		return "", fmt.Errorf("invalid -v %q", spec)
	}
}

// splitBind splits a volume spec into at most three fields, treating a
// leading "C:" as part of the source rather than as a separator.
func splitBind(spec string) []string {
	rest := spec
	var head string
	if len(rest) >= 3 && rest[1] == ':' && isDriveLetter(rest[0]) && (rest[2] == '\\' || rest[2] == '/') {
		head, rest = rest[:2], rest[2:]
	}
	parts := strings.Split(rest, ":")
	if head != "" {
		parts[0] = head + parts[0]
	}
	return parts
}
