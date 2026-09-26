package bundle

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/ChPuru/hull/internal/fsutil"
	"github.com/ChPuru/hull/internal/oci/runtimespec"
	"github.com/ChPuru/hull/internal/types"
)

// ---------- entrypoint / cmd ----------

// ResolveArgs computes the container's argv exactly the way Docker does:
//
//	args = (container Entrypoint ?? image Entrypoint) + (container Cmd ?? image Cmd)
//
// with one exception that trips people up constantly: supplying a container
// Entrypoint and no container Cmd CLEARS the image Cmd, because the image Cmd
// was written as arguments to the image Entrypoint and is meaningless once the
// entrypoint is replaced.
//
// A container Entrypoint of exactly [""] is Docker's "--entrypoint ”", which
// removes the image entrypoint while still counting as "specified", so
// "--entrypoint ” image" with no command is an error, not a silent fallback to
// the image Cmd.
//
// An empty result is ErrNoCommand.
func ResolveArgs(c *types.Container, img *types.Image) ([]string, error) {
	if c == nil {
		return nil, errors.New("bundle: nil container")
	}
	var imgEnt, imgCmd []string
	if img != nil {
		imgEnt = img.Config.Entrypoint
		imgCmd = img.Config.Cmd
	}

	entSpecified := len(c.Config.Entrypoint) > 0
	cmdSpecified := len(c.Config.Cmd) > 0

	var ent []string
	if entSpecified {
		ent = clearedEntrypoint(c.Config.Entrypoint)
	} else {
		ent = imgEnt
	}

	var cmd []string
	switch {
	case cmdSpecified:
		cmd = c.Config.Cmd
	case entSpecified:
		// A replaced entrypoint invalidates the image's default arguments.
		cmd = nil
	default:
		cmd = imgCmd
	}

	args := make([]string, 0, len(ent)+len(cmd))
	args = append(args, ent...)
	args = append(args, cmd...)
	if len(args) == 0 {
		return nil, fmt.Errorf("%w: the image defines no Entrypoint or Cmd, so one must be given on the command line", ErrNoCommand)
	}
	return args, nil
}

// clearedEntrypoint turns Docker's "--entrypoint ”" spelling, which arrives as
// a one-element slice holding the empty string, into no entrypoint at all.
func clearedEntrypoint(ent []string) []string {
	if len(ent) == 1 && ent[0] == "" {
		return nil
	}
	return ent
}

// ---------- environment ----------

// MergeEnv merges two KEY=VALUE environment lists. Entries from over replace
// same-key entries from base in place, keeping the position of the first
// occurrence so the resulting order is stable and diff-friendly; new keys are
// appended in the order they appear in over.
//
// An entry without an "=" or with an empty key is an error: the OCI spec
// requires KEY=VALUE, and silently dropping a malformed variable is how a
// container ends up missing the one setting that mattered.
func MergeEnv(base, over []string) ([]string, error) {
	out := make([]string, 0, len(base)+len(over))
	index := make(map[string]int, len(base)+len(over))
	for _, list := range [][]string{base, over} {
		for _, kv := range list {
			k, err := envKey(kv)
			if err != nil {
				return nil, err
			}
			if i, ok := index[k]; ok {
				out[i] = kv
				continue
			}
			index[k] = len(out)
			out = append(out, kv)
		}
	}
	return out, nil
}

// envKey returns the variable name of a KEY=VALUE entry, splitting on the first
// "=" so values may contain any number of them.
func envKey(kv string) (string, error) {
	i := strings.IndexByte(kv, '=')
	if i < 0 {
		return "", fmt.Errorf("bundle: environment entry %q is not KEY=VALUE", kv)
	}
	if i == 0 {
		return "", fmt.Errorf("bundle: environment entry %q has an empty variable name", kv)
	}
	return kv[:i], nil
}

// hasEnv reports whether key is already present in a merged environment.
func hasEnv(env []string, key string) bool {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return true
		}
	}
	return false
}

// buildEnv merges the image environment with the container's, then guarantees
// the three variables every container is entitled to expect: PATH, HOSTNAME and
// (with a tty) TERM. HOME is filled in from the resolved user's passwd entry
// when the image did not set it, matching Docker.
func (b *builder) buildEnv(home string) ([]string, error) {
	env, err := MergeEnv(b.img.Config.Env, b.c.Config.Env)
	if err != nil {
		return nil, err
	}
	if !hasEnv(env, "PATH") {
		env = append(env, "PATH="+DefaultPath)
	}
	if !hasEnv(env, "HOSTNAME") {
		env = append(env, "HOSTNAME="+b.hostname)
	}
	if b.c.Config.Tty && !hasEnv(env, "TERM") {
		env = append(env, "TERM=xterm")
	}
	if home != "" && !hasEnv(env, "HOME") {
		env = append(env, "HOME="+home)
	}
	return env, nil
}

// ---------- user ----------

// ResolvedUser is the outcome of parsing a "--user" string against the
// container's own /etc/passwd and /etc/group.
type ResolvedUser struct {
	UID            uint32
	GID            uint32
	Username       string
	Home           string
	AdditionalGids []uint32
}

// passwdEntry is one line of /etc/passwd.
type passwdEntry struct {
	Name string
	UID  uint32
	GID  uint32
	Home string
}

// groupEntry is one line of /etc/group.
type groupEntry struct {
	Name    string
	GID     uint32
	Members []string
}

// ResolveUser parses spec ("", "uid", "uid:gid", "user", "user:group",
// "uid:group", "user:gid") against the /etc/passwd and /etc/group *inside*
// rootfs, and returns the uid, gid and supplementary groups to run as.
//
// rootfs is opened through fsutil.SecureOpen, so a symlinked /etc/passwd inside
// a hostile image resolves within the rootfs instead of reaching the host's
// files. When the files are absent — the distroless case — purely numeric specs
// still resolve, and a name-based spec fails with a message that says why.
//
// groupAdd is HostConfig.GroupAdd: group names or numeric gids added to the
// supplementary set.
func ResolveUser(rootfs, spec string, groupAdd []string) (ResolvedUser, error) {
	var out ResolvedUser

	passwd, passwdErr := readPasswd(rootfs)
	groups, groupErr := readGroup(rootfs)

	userPart, groupPart, hasGroup := strings.Cut(spec, ":")

	var pw *passwdEntry
	switch {
	case userPart == "":
		out.UID = 0
		out.GID = 0
		pw = findPasswdByUID(passwd, 0)
	case isAllDigits(userPart):
		n, err := strconv.ParseUint(userPart, 10, 32)
		if err != nil {
			return out, fmt.Errorf("bundle: user %q: uid out of range: %w", spec, err)
		}
		out.UID = uint32(n)
		pw = findPasswdByUID(passwd, out.UID)
		if pw != nil {
			out.GID = pw.GID
		}
	default:
		pw = findPasswdByName(passwd, userPart)
		if pw == nil {
			if passwdErr != nil {
				return out, fmt.Errorf("bundle: user %q: the image has no /etc/passwd (%v), so only numeric uids can be used; try --user %s", spec, passwdErr, "<uid>")
			}
			return out, fmt.Errorf("bundle: user %q: no such user in the image's /etc/passwd", spec)
		}
		out.UID = pw.UID
		out.GID = pw.GID
	}
	if pw != nil {
		out.Username = pw.Name
		out.Home = pw.Home
	}

	if hasGroup && groupPart != "" {
		switch {
		case isAllDigits(groupPart):
			n, err := strconv.ParseUint(groupPart, 10, 32)
			if err != nil {
				return out, fmt.Errorf("bundle: user %q: gid out of range: %w", spec, err)
			}
			out.GID = uint32(n)
		default:
			g := findGroupByName(groups, groupPart)
			if g == nil {
				if groupErr != nil {
					return out, fmt.Errorf("bundle: group %q: the image has no /etc/group (%v), so only numeric gids can be used", groupPart, groupErr)
				}
				return out, fmt.Errorf("bundle: group %q: no such group in the image's /etc/group", groupPart)
			}
			out.GID = g.GID
		}
	} else if hasGroup && groupPart == "" {
		return out, fmt.Errorf("bundle: user %q: the group after %q is empty", spec, ":")
	}

	// Supplementary groups: every group that lists this user as a member, plus
	// whatever --group-add asked for. The primary gid is never repeated.
	seen := map[uint32]bool{out.GID: true}
	if out.Username != "" {
		for _, g := range groups {
			if g.GID == out.GID || seen[g.GID] {
				continue
			}
			for _, m := range g.Members {
				if m == out.Username {
					seen[g.GID] = true
					out.AdditionalGids = append(out.AdditionalGids, g.GID)
					break
				}
			}
		}
	}
	for _, ga := range groupAdd {
		ga = strings.TrimSpace(ga)
		if ga == "" {
			continue
		}
		var gid uint32
		if isAllDigits(ga) {
			n, err := strconv.ParseUint(ga, 10, 32)
			if err != nil {
				return out, fmt.Errorf("bundle: --group-add %q: gid out of range: %w", ga, err)
			}
			gid = uint32(n)
		} else {
			g := findGroupByName(groups, ga)
			if g == nil {
				return out, fmt.Errorf("bundle: --group-add %q: no such group in the image's /etc/group", ga)
			}
			gid = g.GID
		}
		if seen[gid] {
			continue
		}
		seen[gid] = true
		out.AdditionalGids = append(out.AdditionalGids, gid)
	}
	return out, nil
}

// resolveUser resolves the container's user, falling back to the image's User
// when the container did not override it.
func (b *builder) resolveUser() (ResolvedUser, error) {
	spec := b.c.Config.User
	if spec == "" {
		spec = b.img.Config.User
	}
	u, err := ResolveUser(b.opts.RootFS, spec, b.c.HostConfig.GroupAdd)
	if err != nil {
		return u, err
	}
	return u, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func findPasswdByName(entries []passwdEntry, name string) *passwdEntry {
	for i := range entries {
		if entries[i].Name == name {
			return &entries[i]
		}
	}
	return nil
}

func findPasswdByUID(entries []passwdEntry, uid uint32) *passwdEntry {
	for i := range entries {
		if entries[i].UID == uid {
			return &entries[i]
		}
	}
	return nil
}

func findGroupByName(entries []groupEntry, name string) *groupEntry {
	for i := range entries {
		if entries[i].Name == name {
			return &entries[i]
		}
	}
	return nil
}

// readPasswd reads rootfs/etc/passwd through a root-anchored safe open. A
// missing file is not an error: distroless images have none, and numeric uids
// still work. The returned error is the reason the file could not be read, for
// use in a message when a name lookup then fails.
func readPasswd(rootfs string) ([]passwdEntry, error) {
	lines, err := readRootFile(rootfs, "etc/passwd")
	if err != nil {
		return nil, err
	}
	out := make([]passwdEntry, 0, len(lines))
	for _, line := range lines {
		f := strings.Split(line, ":")
		if len(f) < 6 {
			continue
		}
		uid, err1 := strconv.ParseUint(f[2], 10, 32)
		gid, err2 := strconv.ParseUint(f[3], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, passwdEntry{Name: f[0], UID: uint32(uid), GID: uint32(gid), Home: f[5]})
	}
	return out, nil
}

// readGroup reads rootfs/etc/group through a root-anchored safe open, with the
// same "missing is not fatal" rule as readPasswd.
func readGroup(rootfs string) ([]groupEntry, error) {
	lines, err := readRootFile(rootfs, "etc/group")
	if err != nil {
		return nil, err
	}
	out := make([]groupEntry, 0, len(lines))
	for _, line := range lines {
		f := strings.Split(line, ":")
		if len(f) < 4 {
			continue
		}
		gid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			continue
		}
		var members []string
		if f[3] != "" {
			members = strings.Split(f[3], ",")
			for i := range members {
				members[i] = strings.TrimSpace(members[i])
			}
		}
		out = append(out, groupEntry{Name: f[0], GID: uint32(gid), Members: members})
	}
	return out, nil
}

// maxUserDBBytes caps how much of a container-supplied /etc/passwd or
// /etc/group hull will read. A hostile image can make these files arbitrarily
// large; 4 MiB is far beyond any real one.
const maxUserDBBytes = 4 << 20

// readRootFile opens rel inside rootfs with fsutil.SecureOpen — never
// filepath.Join — and returns its non-comment, non-empty lines.
func readRootFile(rootfs, rel string) ([]string, error) {
	if rootfs == "" {
		return nil, errors.New("no container rootfs available")
	}
	f, err := fsutil.SecureOpen(rootfs, rel, os.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("/%s does not exist in the image", rel)
		}
		return nil, fmt.Errorf("/%s could not be read: %w", rel, err)
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(io.LimitReader(f, maxUserDBBytes))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("/%s could not be read: %w", rel, err)
	}
	return lines, nil
}

// ---------- rlimits ----------

// DefaultNofile is the RLIMIT_NOFILE hull applies when the user gives no
// --ulimit. Containers routinely need far more descriptors than the host
// default, and a low limit surfaces as bizarre application errors.
const DefaultNofile uint64 = 1048576

// buildRlimits starts from hull's default RLIMIT_NOFILE and applies the user's
// --ulimit flags on top, replacing a default of the same type.
func buildRlimits(ulimits []types.Ulimit) ([]runtimespec.POSIXRlimit, error) {
	out := []runtimespec.POSIXRlimit{
		{Type: "RLIMIT_NOFILE", Soft: DefaultNofile, Hard: DefaultNofile},
	}
	for _, u := range ulimits {
		name := strings.ToUpper(strings.TrimSpace(u.Name))
		if name == "" {
			return nil, errors.New("bundle: --ulimit with an empty name")
		}
		if !strings.HasPrefix(name, "RLIMIT_") {
			name = "RLIMIT_" + name
		}
		if !validRlimits[name] {
			return nil, fmt.Errorf("bundle: --ulimit %q is not a known rlimit", u.Name)
		}
		soft, hard := u.Soft, u.Hard
		if hard != -1 && soft != -1 && soft > hard {
			return nil, fmt.Errorf("bundle: --ulimit %s soft limit %d exceeds hard limit %d", u.Name, soft, hard)
		}
		rl := runtimespec.POSIXRlimit{Type: name, Soft: rlimitValue(soft), Hard: rlimitValue(hard)}
		replaced := false
		for i := range out {
			if out[i].Type == name {
				out[i] = rl
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, rl)
		}
	}
	return out, nil
}

// rlimitValue maps Docker's -1 ("unlimited") onto RLIM_INFINITY.
func rlimitValue(v int64) uint64 {
	if v < 0 {
		return ^uint64(0)
	}
	return uint64(v)
}

// validRlimits is the set of rlimits Linux actually implements, so a typo in
// --ulimit is rejected at create time instead of being ignored by the runtime.
var validRlimits = map[string]bool{
	"RLIMIT_AS":         true,
	"RLIMIT_CORE":       true,
	"RLIMIT_CPU":        true,
	"RLIMIT_DATA":       true,
	"RLIMIT_FSIZE":      true,
	"RLIMIT_LOCKS":      true,
	"RLIMIT_MEMLOCK":    true,
	"RLIMIT_MSGQUEUE":   true,
	"RLIMIT_NICE":       true,
	"RLIMIT_NOFILE":     true,
	"RLIMIT_NPROC":      true,
	"RLIMIT_RSS":        true,
	"RLIMIT_RTPRIO":     true,
	"RLIMIT_RTTIME":     true,
	"RLIMIT_SIGPENDING": true,
	"RLIMIT_STACK":      true,
}
