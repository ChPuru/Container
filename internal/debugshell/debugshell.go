// Package debugshell implements "hull debug <ctr>": a busybox toolbox shell
// inside a container that has no shell of its own.
//
// Distroless images are the reason this exists. They ship an application and
// its libraries and nothing else - no /bin/sh, no ls, no ps - which is exactly
// what you want in production and exactly what you do not want at 2am. There
// is nothing to "docker exec" into, so the usual answer is to rebuild the
// image with a debug tag and lose the state you were trying to look at.
//
// hull instead attaches a toolbox from outside. It joins the target's
// namespaces with setns(2) on a pidfd, mounts a tmpfs holding a static
// busybox, and starts a shell whose PATH points at it.
//
// The namespace set is the whole trick. It defaults to pid, net, ipc and uts
// and deliberately NOT mount:
//
//   - joining the mount namespace would replace the filesystem with the
//     target's, which is the one that has no tools in it;
//   - staying out of it means the toolbox, the engine distro's own binaries
//     and /proc are all still reachable, while the target's filesystem is
//     visible at /proc/1/root (the pid namespace is joined, so pid 1 is the
//     container's init) and bind-mounted read-only at /host-root;
//   - the pid, net, ipc and uts namespaces are what you actually want for
//     debugging: the same process table, the same interfaces and sockets, the
//     same hostname, the same SysV IPC.
//
// The target container is never modified. Nothing is written into its
// filesystem, no mount is made inside its mount namespace, its cgroup is not
// touched and its processes are not signalled. Every mount the debug session
// makes lives in a mount namespace the session unshares for itself, which the
// kernel destroys when the shell exits.
//
// The toolbox is a static busybox fetched once into the data root with
// EmbedToolbox, not compiled into the daemon, so hull's binaries stay small.
//
// One honest caveat: the two mountpoints, Options.ToolboxMount and
// Options.HostRoot, are directories on the engine distro's own filesystem, and
// creating them is the single thing a session leaves behind. They are empty,
// they are reused by every later session, and both paths are options so a
// caller that wants them somewhere else can say so.
package debugshell

import (
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ChPuru/hull/internal/explain"
	"github.com/ChPuru/hull/internal/hostinfo"
	"github.com/ChPuru/hull/internal/types"
)

// Errors a caller is expected to test for.
var (
	// ErrUnsupportedPlatform reports that a debug shell needs Linux
	// namespaces. The Windows hull CLI asks the daemon inside WSL instead.
	ErrUnsupportedPlatform = errors.New("debugshell: a debug shell requires Linux namespaces")
	// ErrNoToolbox reports that no toolbox has been embedded yet. The
	// remedy is EmbedToolbox with a static busybox.
	ErrNoToolbox = errors.New("debugshell: no toolbox has been embedded")
	// ErrNotRunning reports that the target container has no live process to
	// join.
	ErrNotRunning = errors.New("debugshell: the container is not running")
	// ErrInvalidOptions reports an Options value the package refuses to act
	// on.
	ErrInvalidOptions = errors.New("debugshell: invalid options")
)

// Defaults. Every one of them is overridable through Options, because the
// engine distro is not the only place a debug shell runs.
const (
	// DefaultToolboxMount is where the toolbox tmpfs is mounted inside the
	// debug session's private mount namespace.
	DefaultToolboxMount = "/.hull-toolbox"
	// DefaultHostRoot is where the target's root filesystem is
	// bind-mounted, read-only, inside the same private mount namespace.
	DefaultHostRoot = "/host-root"
	// DefaultToolboxSize is the size of the toolbox tmpfs. A static busybox
	// is about 1 MB; 16 MB leaves room for a second tool and for the applet
	// symlinks without ever being worth a size flag.
	DefaultToolboxSize = 16 << 20
	// ToolboxDir is the directory under the data root that holds the
	// embedded toolbox.
	ToolboxDir = "toolbox"
	// ToolboxName is the file name of the embedded busybox.
	ToolboxName = "busybox"
	// toolboxPerm is the mode the embedded toolbox is stored with: readable
	// and executable by everyone, writable only by the daemon.
	toolboxPerm fs.FileMode = 0o755
)

// DefaultPath is the PATH a debug shell starts with once the toolbox
// directory has been prepended. It is bundle.DefaultPath's value, repeated
// here so this package does not drag the bundle generator into the CLI.
const DefaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// DefaultNamespaces is the namespace set Attach joins when Options.Namespaces
// is empty: the target's process table, network, SysV IPC and hostname. The
// mount namespace is deliberately absent - see the package comment.
var DefaultNamespaces = []string{"pid", "net", "ipc", "uts"}

// DefaultCommand is what Attach runs when Options.Command is empty. The path
// is resolved inside the toolbox mount, so the default shell is the toolbox's
// own busybox ash and never something the target image was supposed to have.
var DefaultCommand = []string{"/bin/sh"}

// Applets are the busybox applets Attach symlinks into the toolbox bin
// directory, so a shell that runs "ps" or "ip" finds them on PATH.
//
// busybox dispatches on argv[0], so a symlink is all an applet needs. A
// symlink for an applet this particular busybox build does not carry costs
// nothing until it is run, when busybox says so plainly; the toolbox binary
// itself is always present as "busybox", so "busybox <anything>" works
// regardless of what this list says.
var Applets = []string{
	"[", "arp", "ash", "awk", "base64", "basename", "brctl", "cat", "chmod", "chown",
	"chroot", "cmp", "cp", "cut", "date", "dd", "df", "diff", "dirname", "dmesg",
	"du", "echo", "env", "expr", "false", "find", "free", "grep", "gunzip", "gzip",
	"head", "hexdump", "hostname", "id", "ifconfig", "ip", "kill", "killall", "less",
	"ln", "ls", "lsof", "md5sum", "mkdir", "mkfifo", "mknod", "mktemp", "more", "mount",
	"mv", "nc", "netstat", "nslookup", "od", "pgrep", "pidof", "ping", "printenv",
	"printf", "ps", "pwd", "readlink", "realpath", "rm", "rmdir", "route", "sed",
	"seq", "sh", "sha256sum", "sleep", "sort", "stat", "strings", "stty", "sync",
	"tail", "tar", "tee", "test", "time", "top", "touch", "tr", "traceroute", "true",
	"umount", "uname", "uniq", "uptime", "vi", "watch", "wc", "wget", "which", "who",
	"whoami", "xargs", "yes",
}

// Options describe one debug session.
//
// The zero value is not usable: ContainerID is required. Everything else has a
// default that suits "hull debug <ctr>" on the engine distro.
type Options struct {
	// ContainerID is the container to attach to. It is passed to Resolve
	// unchanged, so whatever that function accepts - a full id, a prefix, a
	// name - is accepted here.
	ContainerID string

	// Toolbox is the host path of the static busybox to stage. Empty means
	// the toolbox embedded in the data root by EmbedToolbox.
	Toolbox string

	// Command is what to run inside the target's namespaces. Empty means
	// DefaultCommand, resolved inside ToolboxMount. A relative command is
	// looked up on the session's PATH, which starts with the toolbox.
	Command []string

	// Namespaces are the namespace kinds to join. Empty means
	// DefaultNamespaces. "mount" and "user" are refused: joining the
	// target's mount namespace would hide the toolbox, and a multi-threaded
	// Go process cannot enter a user namespace at all.
	Namespaces []string

	// Tty allocates a pseudo-terminal for the session and makes it the
	// shell's controlling terminal.
	Tty bool

	// Attach is the caller's end of the session: read from for the shell's
	// stdin, written to with its stdout. Nil means os.Stdin and os.Stdout,
	// which is what the engine-distro CLI wants.
	Attach io.ReadWriter

	// Stderr receives the shell's standard error when Tty is false. Nil
	// sends it to Attach, which is what a single-stream client expects. It
	// is ignored when Tty is set, because a terminal has one stream.
	Stderr io.Writer

	// Env is extra environment for the shell, in KEY=VALUE form. It is
	// appended after hull's own, so it can override PATH deliberately.
	Env []string

	// Width and Height are the initial terminal size when Tty is set. Zero
	// leaves the kernel default of 80x24.
	Width, Height uint16

	// DataRoot is hull's data directory. Empty means DataRoot().
	DataRoot string

	// ToolboxMount and HostRoot are where the toolbox tmpfs and the
	// read-only view of the target's filesystem are mounted inside the
	// session's private mount namespace. Empty means DefaultToolboxMount
	// and DefaultHostRoot.
	ToolboxMount string
	HostRoot     string

	// NoBanner suppresses the greeting that tells the operator where the
	// toolbox and the target's filesystem are. Set it for a scripted
	// session, where the banner would be noise on stdout.
	NoBanner bool

	// Resolve maps ContainerID to the host pid of the container's init
	// process. Nil means StateResolver over DataRoot, which reads the
	// daemon's state files; the daemon passes its own lookup instead so it
	// never races its own writer.
	Resolve func(ctx context.Context, containerID string) (int, error)

	// Tracer narrates the session's own kernel steps - the setns, the
	// unshare, each mount - the same way --explain narrates a container
	// start. Nil means explain.Nop.
	Tracer explain.Tracer
}

// DataRoot returns hull's data directory: $HULL_DATA_ROOT when it is set, and
// hostinfo.DefaultDataRoot otherwise.
func DataRoot() string {
	if v := os.Getenv("HULL_DATA_ROOT"); v != "" {
		return v
	}
	return hostinfo.DefaultDataRoot
}

// ToolboxPath returns the path of the embedded toolbox under the current data
// root, which is where EmbedToolbox puts it and where Attach looks for it.
func ToolboxPath() string {
	return filepath.Join(DataRoot(), ToolboxDir, ToolboxName)
}

// ToolboxPresent reports whether a usable toolbox has been embedded: a regular,
// non-empty, executable file at ToolboxPath.
func ToolboxPresent() bool {
	st, err := os.Stat(ToolboxPath())
	if err != nil {
		return false
	}
	return st.Mode().IsRegular() && st.Size() > 0 && st.Mode().Perm()&0o111 != 0
}

// EmbedToolbox installs the static busybox at path as hull's debug toolbox,
// copying it into the data root so later sessions need no network and no
// second copy of the file.
//
// The binary is verified before it is stored, because an unusable toolbox is
// only discovered at 2am otherwise: it must be a regular file, an ELF
// executable, and statically linked. A dynamically linked busybox is refused
// rather than stored, since the whole point of the toolbox is that it runs
// where nothing else does.
//
// The write is atomic - a temporary file in the same directory, then rename -
// so a crash mid-copy can never leave a half-written toolbox behind.
func EmbedToolbox(path string) error {
	if path == "" {
		return fmt.Errorf("%w: EmbedToolbox needs a path to a static busybox", ErrInvalidOptions)
	}
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("debugshell: stat toolbox %s: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%w: toolbox %s is not a regular file", ErrInvalidOptions, path)
	}
	if err := verifyStaticELF(path); err != nil {
		return err
	}

	dir := filepath.Join(DataRoot(), ToolboxDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("debugshell: create toolbox directory %s: %w", dir, err)
	}
	dst := filepath.Join(dir, ToolboxName)

	tmp, err := os.CreateTemp(dir, ToolboxName+".*.tmp")
	if err != nil {
		return fmt.Errorf("debugshell: create temporary toolbox in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		_ = os.Remove(tmpName)
	}()

	src, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("debugshell: open toolbox %s: %w", path, err)
	}
	defer src.Close()
	if _, err := io.Copy(tmp, src); err != nil {
		return fmt.Errorf("debugshell: copy toolbox into %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(toolboxPerm); err != nil {
		return fmt.Errorf("debugshell: chmod toolbox %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("debugshell: sync toolbox %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("debugshell: close toolbox %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("debugshell: install toolbox at %s: %w", dst, err)
	}
	return nil
}

// verifyStaticELF rejects anything that is not a statically linked ELF
// executable. A PT_INTERP program header is the definitive marker of a
// dynamically linked binary; a .interp section alone can be stripped.
func verifyStaticELF(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("%w: toolbox %s is not an ELF binary: %w", ErrInvalidOptions, path, err)
	}
	defer f.Close()
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return fmt.Errorf("%w: toolbox %s is an ELF %s, not an executable", ErrInvalidOptions, path, f.Type)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return fmt.Errorf("%w: toolbox %s is dynamically linked (it has a PT_INTERP header); "+
				"hull's debug toolbox must be static, because it has to run where its loader may not exist",
				ErrInvalidOptions, path)
		}
	}
	return nil
}

// StateResolver returns a Resolve function that reads the container records
// the daemon writes under dataRoot, matching a full id, an unambiguous id
// prefix or a container name.
//
// It opens nothing exclusively and takes no lock: a debug session must be
// possible while the daemon is running, and the state file is written
// atomically by internal/state, so a read either sees the previous record or
// the next one and never a torn one.
func StateResolver(dataRoot string) func(ctx context.Context, containerID string) (int, error) {
	if dataRoot == "" {
		dataRoot = DataRoot()
	}
	return func(ctx context.Context, id string) (int, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		c, err := findContainer(dataRoot, id)
		if err != nil {
			return 0, err
		}
		if c.State != types.StateRunning && c.State != types.StatePaused {
			return 0, fmt.Errorf("%w: container %s is %s", ErrNotRunning, id, c.State)
		}
		if c.Pid <= 0 {
			return 0, fmt.Errorf("%w: container %s has no recorded pid", ErrNotRunning, id)
		}
		return c.Pid, nil
	}
}

// findContainer locates one container record under dataRoot by full id, id
// prefix or name.
func findContainer(dataRoot, id string) (*types.Container, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: no container given", ErrInvalidOptions)
	}
	if strings.ContainsAny(id, "/\\") || id == "." || id == ".." {
		return nil, fmt.Errorf("%w: %q is not a container id or name", ErrInvalidOptions, id)
	}
	dir := filepath.Join(dataRoot, "containers")
	if c, err := readContainer(filepath.Join(dir, id)); err == nil {
		return c, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("debugshell: read container records in %s: %w", dir, err)
	}
	var matches []*types.Container
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		c, err := readContainer(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if c.Name == id {
			return c, nil
		}
		if strings.HasPrefix(c.ID, id) {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("debugshell: no such container: %s", id)
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("debugshell: %q matches %d containers; use a longer prefix", id, len(matches))
	}
}

// readContainer reads one state.json.
func readContainer(dir string) (*types.Container, error) {
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return nil, err
	}
	var c types.Container
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("debugshell: parse %s/state.json: %w", dir, err)
	}
	if c.ID == "" {
		return nil, fmt.Errorf("debugshell: %s/state.json has no container id", dir)
	}
	return &c, nil
}

// normalize fills in every default and rejects what Attach cannot do. It
// returns a copy, so a caller's Options value is never mutated and can be
// reused for a second session.
func (o Options) normalize() (Options, error) {
	if strings.TrimSpace(o.ContainerID) == "" {
		return o, fmt.Errorf("%w: Options.ContainerID is empty", ErrInvalidOptions)
	}
	if o.DataRoot == "" {
		o.DataRoot = DataRoot()
	}
	if o.Toolbox == "" {
		o.Toolbox = filepath.Join(o.DataRoot, ToolboxDir, ToolboxName)
	}
	if o.ToolboxMount == "" {
		o.ToolboxMount = DefaultToolboxMount
	}
	if o.HostRoot == "" {
		o.HostRoot = DefaultHostRoot
	}
	for name, p := range map[string]string{"ToolboxMount": o.ToolboxMount, "HostRoot": o.HostRoot} {
		if !strings.HasPrefix(p, "/") {
			return o, fmt.Errorf("%w: Options.%s %q is not an absolute path", ErrInvalidOptions, name, p)
		}
		if path.Clean(p) != p || p == "/" {
			return o, fmt.Errorf("%w: Options.%s %q must be a clean absolute path below the root",
				ErrInvalidOptions, name, p)
		}
	}
	if o.ToolboxMount == o.HostRoot {
		return o, fmt.Errorf("%w: Options.ToolboxMount and Options.HostRoot are both %q",
			ErrInvalidOptions, o.HostRoot)
	}

	ns, err := canonicalNamespaces(o.Namespaces)
	if err != nil {
		return o, err
	}
	o.Namespaces = ns

	if len(o.Command) == 0 {
		o.Command = []string{o.ToolboxMount + DefaultCommand[0]}
	} else {
		o.Command = append([]string(nil), o.Command...)
		if o.Command[0] == "" {
			return o, fmt.Errorf("%w: Options.Command[0] is empty", ErrInvalidOptions)
		}
	}
	if o.Resolve == nil {
		o.Resolve = StateResolver(o.DataRoot)
	}
	o.Tracer = explain.OrNop(o.Tracer)
	o.Env = append([]string(nil), o.Env...)
	return o, nil
}

// namespaceAliases maps every spelling hull's CLI and docs use for a namespace
// onto the runtime-spec name internal/runtime/initspec keys its CLONE_NEW*
// table by. Keeping the aliases here and the flags there means there is
// exactly one CLONE_NEW* table in the tree.
var namespaceAliases = map[string]string{
	"pid":     "pid",
	"net":     "network",
	"network": "network",
	"ipc":     "ipc",
	"uts":     "uts",
	"cgroup":  "cgroup",
	"time":    "time",
	"mnt":     "mount",
	"mount":   "mount",
	"user":    "user",
	"userns":  "user",
}

// refusedNamespaces are the kinds Attach will not join, with the reason, which
// is printed verbatim: a debug shell that silently did something other than
// what was asked would be worse than one that refuses.
var refusedNamespaces = map[string]string{
	"mount": "joining the target's mount namespace would replace the filesystem with the one that has no " +
		"tools in it; hull leaves it alone so the toolbox stays reachable and the target's root is " +
		"visible at /proc/1/root and " + DefaultHostRoot,
	"user": "a multi-threaded Go process cannot setns into a user namespace; the debug shell runs with the " +
		"daemon's credentials in the host user namespace",
}

// canonicalNamespaces validates and canonicalises a namespace set, applying
// DefaultNamespaces when it is empty. The caller's order is preserved and
// duplicates are dropped.
func canonicalNamespaces(names []string) ([]string, error) {
	if len(names) == 0 {
		// The defaults go through the same table as anything else, so
		// DefaultNamespaces can stay spelled the way the CLI and docs spell
		// it and still come out canonical.
		names = DefaultNamespaces
	}
	out := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, raw := range names {
		n := strings.ToLower(strings.TrimSpace(raw))
		if n == "" {
			continue
		}
		canon, ok := namespaceAliases[n]
		if !ok {
			return nil, fmt.Errorf("%w: unknown namespace %q", ErrInvalidOptions, raw)
		}
		if why, refused := refusedNamespaces[canon]; refused {
			return nil, fmt.Errorf("%w: hull will not join the %s namespace: %s", ErrInvalidOptions, canon, why)
		}
		if _, dup := seen[canon]; dup {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: Options.Namespaces named no namespace to join", ErrInvalidOptions)
	}
	return out, nil
}

// environ builds the environment the debug shell starts with. The toolbox
// comes first on PATH so "ps" is busybox's ps and not whatever the engine
// distro happens to ship, and the two locations the banner names are also
// exported so a script can find them without parsing the banner.
func (o Options) environ() []string {
	hostRoot := o.HostRoot
	if hostRoot == "" {
		hostRoot = "/proc/1/root"
	}
	env := []string{
		"PATH=" + o.ToolboxMount + "/bin:" + DefaultPath,
		"HOME=/root",
		"TERM=xterm",
		"PS1=hull-debug " + shortID(o.ContainerID) + ":\\w# ",
		"HULL_DEBUG_CONTAINER=" + o.ContainerID,
		"HULL_DEBUG_TOOLBOX=" + o.ToolboxMount + "/bin",
		"HULL_DEBUG_HOST_ROOT=" + hostRoot,
	}
	return append(env, o.Env...)
}

// banner is the greeting the shell prints before it hands over. It names every
// location the session created, because the one thing an operator needs in the
// first five seconds is where the target's filesystem went.
//
// An empty HostRoot means the read-only bind was refused by the kernel, in
// which case the banner says so rather than pointing at an empty directory.
func (o Options) banner(pid int) string {
	fs := "/proc/1/root (live, through the joined pid namespace)"
	if o.HostRoot != "" {
		fs = o.HostRoot + " (read-only), and /proc/1/root (live)"
	}
	var b strings.Builder
	b.WriteString("hull debug: busybox toolbox attached to container " + shortID(o.ContainerID) + "\n")
	b.WriteString("  namespaces joined : " + strings.Join(o.Namespaces, ", ") +
		"  (" + explain.CloneFlags(o.Namespaces...) + ")\n")
	b.WriteString("  target pid        : " + strconv.Itoa(pid) + " on the host, 1 in here\n")
	b.WriteString("  target filesystem : " + fs + "\n")
	b.WriteString("  toolbox           : " + o.ToolboxMount + "/bin, already on PATH\n")
	b.WriteString("  this shell's mounts are private; the container is not modified.\n")
	return b.String()
}

// shortID truncates a container id the way every hull surface does, and leaves
// a name or an already-short id alone.
func shortID(id string) string {
	const short = 12
	if len(id) > short {
		return id[:short]
	}
	return id
}
