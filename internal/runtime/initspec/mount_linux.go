package initspec

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/oci/runtimespec"
)

// move_mount(2) flags. They are spelled out because not every x/sys release
// exports the "to" side, and getting them wrong silently moves the wrong
// mount.
const (
	moveMountFEmptyPath = 0x00000004
	moveMountTEmptyPath = 0x00000040
)

// mount_setattr / fsmount attribute bits, from linux/mount.h.
const (
	mountAttrRDONLY = 0x00000001
	mountAttrNOSUID = 0x00000002
	mountAttrNODEV  = 0x00000004
	mountAttrNOEXEC = 0x00000008
)

// PutOldName is the directory pivot_root moves the old root to. It lives
// inside the new root, is unmounted with MNT_DETACH immediately afterwards,
// and is then removed, so nothing in the container ever sees it.
const PutOldName = ".hull-put-old"

// mountFlagOption is one recognised mount option token.
type mountFlagOption struct {
	clear bool
	flag  uintptr
}

// mountFlags is the option vocabulary util-linux and the OCI runtimes share.
var mountFlags = map[string]mountFlagOption{
	"async":         {true, unix.MS_SYNCHRONOUS},
	"atime":         {true, unix.MS_NOATIME},
	"bind":          {false, unix.MS_BIND},
	"defaults":      {false, 0},
	"dev":           {true, unix.MS_NODEV},
	"diratime":      {true, unix.MS_NODIRATIME},
	"dirsync":       {false, unix.MS_DIRSYNC},
	"exec":          {true, unix.MS_NOEXEC},
	"iversion":      {false, unix.MS_I_VERSION},
	"lazytime":      {false, unix.MS_LAZYTIME},
	"loud":          {true, unix.MS_SILENT},
	"mand":          {false, unix.MS_MANDLOCK},
	"noatime":       {false, unix.MS_NOATIME},
	"nodev":         {false, unix.MS_NODEV},
	"nodiratime":    {false, unix.MS_NODIRATIME},
	"noexec":        {false, unix.MS_NOEXEC},
	"noiversion":    {true, unix.MS_I_VERSION},
	"nolazytime":    {true, unix.MS_LAZYTIME},
	"nomand":        {true, unix.MS_MANDLOCK},
	"norelatime":    {true, unix.MS_RELATIME},
	"nostrictatime": {true, unix.MS_STRICTATIME},
	"nosuid":        {false, unix.MS_NOSUID},
	"rbind":         {false, unix.MS_BIND | unix.MS_REC},
	"relatime":      {false, unix.MS_RELATIME},
	"remount":       {false, unix.MS_REMOUNT},
	"ro":            {false, unix.MS_RDONLY},
	"rw":            {true, unix.MS_RDONLY},
	"silent":        {false, unix.MS_SILENT},
	"strictatime":   {false, unix.MS_STRICTATIME},
	"suid":          {true, unix.MS_NOSUID},
	"sync":          {false, unix.MS_SYNCHRONOUS},
}

// propagationFlags are the mount-propagation options, which must be applied in
// their own mount(2) call and never mixed with the others.
var propagationFlags = map[string]uintptr{
	"private":     unix.MS_PRIVATE,
	"rprivate":    unix.MS_PRIVATE | unix.MS_REC,
	"shared":      unix.MS_SHARED,
	"rshared":     unix.MS_SHARED | unix.MS_REC,
	"slave":       unix.MS_SLAVE,
	"rslave":      unix.MS_SLAVE | unix.MS_REC,
	"unbindable":  unix.MS_UNBINDABLE,
	"runbindable": unix.MS_UNBINDABLE | unix.MS_REC,
}

// ParseMountOptions splits an OCI mount option list into mount(2) flags, the
// separate propagation flags, and the filesystem-specific data string.
func ParseMountOptions(opts []string) (flags, propagation uintptr, data string) {
	var kv []string
	for _, o := range opts {
		if p, ok := propagationFlags[o]; ok {
			propagation |= p
			continue
		}
		if f, ok := mountFlags[o]; ok {
			if f.clear {
				flags &^= f.flag
			} else {
				flags |= f.flag
			}
			continue
		}
		kv = append(kv, o)
	}
	return flags, propagation, strings.Join(kv, ",")
}

// SetupRootfs performs every filesystem step of container creation, in order:
// isolate the mount tree, make the new root a mount point, mount everything
// the bundle asks for with each destination resolved fd-relative inside the
// new root, materialise the device nodes, and pivot_root into it.
//
// No path under the container root is ever handed to a syscall as a string.
// Every destination is opened with OpenInRoot and named to the kernel as
// /proc/self/fd/<n>, which is what makes a symlink planted by a malicious
// image unable to redirect a mount onto the host (the CVE-2019-16884 /
// CVE-2021-30465 class).
func SetupRootfs(cfg *Config) error {
	// Nothing hull does inside the container may propagate back out.
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("initspec: make the mount tree private: %w", err)
	}

	// pivot_root refuses a new root that is not itself a mount point.
	if err := unix.Mount(cfg.Rootfs, cfg.Rootfs, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("initspec: bind container root %s onto itself: %w", cfg.Rootfs, err)
	}

	prop := uintptr(unix.MS_PRIVATE | unix.MS_REC)
	if cfg.RootfsPropagation != "" {
		p, ok := propagationFlags[cfg.RootfsPropagation]
		if !ok {
			return fmt.Errorf("initspec: unknown rootfsPropagation %q", cfg.RootfsPropagation)
		}
		prop = p
	}
	if err := unix.Mount("", cfg.Rootfs, "", prop, ""); err != nil {
		return fmt.Errorf("initspec: set propagation on %s: %w", cfg.Rootfs, err)
	}

	rootFD, err := unix.Open(cfg.Rootfs, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("initspec: open container root %s: %w", cfg.Rootfs, err)
	}
	defer unix.Close(rootFD)

	userNS := inUserNamespace()
	for i := range cfg.Mounts {
		m := &cfg.Mounts[i]
		// type:"cgroup" is a request, not an instruction: what actually gets mounted
		// depends on the host's cgroup layout. See cgroupmount_linux.go.
		var err error
		if isCgroupMount(m) {
			err = mountCgroup(rootFD, m, cfg.Features, userNS)
		} else {
			err = mountOne(rootFD, m, cfg.Features)
		}
		if err != nil {
			return fmt.Errorf("initspec: mount %s: %w", m.Destination, err)
		}
	}
	// The standard /dev nodes come first: masking a path binds /dev/null over it, so
	// an empty /dev fails later in a way that says nothing about devices.
	if err := SetupDefaultDevices(rootFD, cfg.Devices); err != nil {
		return err
	}
	if err := SetupDevices(rootFD, cfg.Devices); err != nil {
		return err
	}
	return pivotRoot(rootFD, cfg.Rootfs)
}

// mountOne performs a single bundle mount.
func mountOne(rootFD int, m *runtimespec.Mount, feat StageFeatures) error {
	flags, prop, data := ParseMountOptions(m.Options)
	isBind := flags&unix.MS_BIND != 0
	dest := m.Destination
	if dest == "" || !strings.HasPrefix(dest, "/") {
		return fmt.Errorf("destination %q is not an absolute path", dest)
	}

	// The destination must exist and must be the right kind of thing: a
	// bind of a file needs a file to land on.
	wantFile := false
	if isBind {
		var st unix.Stat_t
		if err := unix.Stat(m.Source, &st); err != nil {
			return fmt.Errorf("bind source %s: %w", m.Source, err)
		}
		wantFile = st.Mode&unix.S_IFMT != unix.S_IFDIR
	}
	if wantFile {
		if err := EnsureFileInRoot(rootFD, dest, 0o644); err != nil {
			return err
		}
	} else if err := MkdirAllInRoot(rootFD, dest, 0o755); err != nil {
		return err
	}

	destFD, err := OpenInRoot(rootFD, dest, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(destFD)

	if !isBind && feat.MountAPI && m.Type != "" {
		switch err := mountViaFsopen(destFD, m, flags, data); {
		case err == nil:
			return applyPropagation(rootFD, dest, prop)
		case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EOPNOTSUPP):
			// Fall through to mount(2).
		default:
			// The new API is present but refused this filesystem; the
			// classic call is still worth trying and gives a better
			// error if it fails too.
		}
	}

	source := m.Source
	if source == "" {
		source = m.Type
	}
	// MS_RDONLY is silently ignored on the initial bind mount; it has to be
	// applied by a second, remount call, which is done below.
	initial := flags
	if isBind {
		initial &^= unix.MS_RDONLY
	}
	if err := unix.Mount(source, ProcFD(destFD), m.Type, initial, data); err != nil {
		return fmt.Errorf("mount(%s, type %s, flags %#x, data %q): %w", source, m.Type, initial, data, err)
	}
	if isBind && flags&unix.MS_RDONLY != 0 {
		if err := RemountReadonly(rootFD, dest); err != nil {
			return err
		}
	}
	return applyPropagation(rootFD, dest, prop)
}

// applyPropagation sets the propagation mode of a freshly made mount. The
// destination is re-opened because the descriptor used to create the mount
// still refers to what is now underneath it.
func applyPropagation(rootFD int, dest string, prop uintptr) error {
	if prop == 0 {
		return nil
	}
	fd, err := OpenInRoot(rootFD, dest, unix.O_PATH, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Mount("", ProcFD(fd), "", prop, ""); err != nil {
		return fmt.Errorf("set propagation %#x on %s: %w", prop, dest, err)
	}
	return nil
}

// mountViaFsopen mounts a filesystem with the fd-based mount API. The mount is
// fully configured while it is still detached and is only then attached to the
// destination descriptor, so a half-built filesystem is never visible inside
// the container.
func mountViaFsopen(destFD int, m *runtimespec.Mount, flags uintptr, data string) error {
	fsfd, err := unix.Fsopen(m.Type, unix.FSOPEN_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(fsfd)

	if m.Source != "" && m.Source != m.Type {
		if err := unix.FsconfigSetString(fsfd, "source", m.Source); err != nil {
			return fmt.Errorf("fsconfig source=%s: %w", m.Source, err)
		}
	}
	for _, opt := range strings.Split(data, ",") {
		if opt == "" {
			continue
		}
		k, v, found := strings.Cut(opt, "=")
		var cerr error
		if found {
			cerr = unix.FsconfigSetString(fsfd, k, v)
		} else {
			cerr = unix.FsconfigSetFlag(fsfd, k)
		}
		if cerr != nil {
			return fmt.Errorf("fsconfig %s: %w", opt, cerr)
		}
	}
	if err := unix.FsconfigCreate(fsfd); err != nil {
		return fmt.Errorf("fsconfig create %s: %w", m.Type, err)
	}

	var attrs int
	if flags&unix.MS_RDONLY != 0 {
		attrs |= mountAttrRDONLY
	}
	if flags&unix.MS_NOSUID != 0 {
		attrs |= mountAttrNOSUID
	}
	if flags&unix.MS_NODEV != 0 {
		attrs |= mountAttrNODEV
	}
	if flags&unix.MS_NOEXEC != 0 {
		attrs |= mountAttrNOEXEC
	}
	mfd, err := unix.Fsmount(fsfd, unix.FSMOUNT_CLOEXEC, attrs)
	if err != nil {
		return fmt.Errorf("fsmount %s: %w", m.Type, err)
	}
	defer unix.Close(mfd)

	if err := unix.MoveMount(mfd, "", destFD, "", moveMountFEmptyPath|moveMountTEmptyPath); err != nil {
		return fmt.Errorf("move_mount %s onto %s: %w", m.Type, m.Destination, err)
	}
	return nil
}

// statfsToMountFlags converts the flags fstatfs reports back into the MS_*
// bits a remount has to repeat. Omitting them makes the remount fail with
// EPERM inside a user namespace, where those flags are locked.
func statfsToMountFlags(f int64) uintptr {
	var out uintptr
	pairs := []struct {
		st int64
		ms uintptr
	}{
		{unix.ST_NOSUID, unix.MS_NOSUID},
		{unix.ST_NODEV, unix.MS_NODEV},
		{unix.ST_NOEXEC, unix.MS_NOEXEC},
		{unix.ST_NOATIME, unix.MS_NOATIME},
		{unix.ST_NODIRATIME, unix.MS_NODIRATIME},
		{unix.ST_RELATIME, unix.MS_RELATIME},
	}
	for _, p := range pairs {
		if f&p.st != 0 {
			out |= p.ms
		}
	}
	return out
}

// RemountReadonly makes an existing mount inside the container read-only,
// carrying over the flags the kernel has locked on it.
func RemountReadonly(rootFD int, dest string) error {
	fd, err := OpenInRoot(rootFD, dest, unix.O_PATH, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var sfs unix.Statfs_t
	flags := uintptr(unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY)
	if err := unix.Fstatfs(fd, &sfs); err == nil {
		flags |= statfsToMountFlags(int64(sfs.Flags))
	}
	if err := unix.Mount("", ProcFD(fd), "", flags, ""); err != nil {
		return fmt.Errorf("remount %s read-only: %w", dest, err)
	}
	return nil
}

// SetupDevices materialises the device nodes the bundle asks for.
//
// mknod is tried first and a bind-mount of the host node is the fallback,
// because an unprivileged user namespace cannot create device nodes at all.
// Every fallback source is opened and verified by fd before it is used, so a
// malicious image cannot substitute something else for /dev/null.
func SetupDevices(rootFD int, devices []runtimespec.LinuxDevice) error {
	for _, d := range devices {
		if err := setupDevice(rootFD, d); err != nil {
			return fmt.Errorf("initspec: device %s: %w", d.Path, err)
		}
	}
	return nil
}

func setupDevice(rootFD int, d runtimespec.LinuxDevice) error {
	var kind uint32
	switch d.Type {
	case "c", "u":
		kind = unix.S_IFCHR
	case "b":
		kind = unix.S_IFBLK
	case "p":
		kind = unix.S_IFIFO
	default:
		return fmt.Errorf("unknown device type %q", d.Type)
	}
	mode := uint32(0o666)
	if d.FileMode != nil {
		mode = *d.FileMode & 0o7777
	}
	dir, base := splitDir(strings.TrimPrefix(d.Path, "/"))
	if base == "" {
		return fmt.Errorf("device path %q has no name", d.Path)
	}
	if dir != "" {
		if err := MkdirAllInRoot(rootFD, dir, 0o755); err != nil {
			return err
		}
	}
	parentFD, err := OpenInRoot(rootFD, "/"+dir, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)

	dev := unix.Mkdev(uint32(d.Major), uint32(d.Minor))
	err = unix.Mknodat(parentFD, base, kind|mode, int(dev))
	switch {
	case err == nil:
		if d.UID != nil && d.GID != nil {
			_ = unix.Fchownat(parentFD, base, int(*d.UID), int(*d.GID), unix.AT_SYMLINK_NOFOLLOW)
		}
		return nil
	case errors.Is(err, unix.EEXIST):
		return nil
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES), errors.Is(err, unix.EINVAL):
		// No CAP_MKNOD (the normal case in a user namespace): bind the
		// host node instead, after proving by fd that it really is the
		// device the bundle named.
		return bindHostDevice(rootFD, d, kind)
	default:
		return fmt.Errorf("mknodat(%s, %s %d:%d): %w", d.Path, d.Type, d.Major, d.Minor, err)
	}
}

// bindHostDevice binds the host's own device node over a placeholder file in
// the container.
func bindHostDevice(rootFD int, d runtimespec.LinuxDevice, kind uint32) error {
	if kind == unix.S_IFIFO {
		return fmt.Errorf("cannot create fifo %s without CAP_MKNOD", d.Path)
	}
	srcFD, err := unix.Open(d.Path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open host device %s to bind it: %w", d.Path, err)
	}
	defer unix.Close(srcFD)
	var st unix.Stat_t
	if err := unix.Fstat(srcFD, &st); err != nil {
		return fmt.Errorf("fstat host device %s: %w", d.Path, err)
	}
	if st.Mode&unix.S_IFMT != kind {
		return fmt.Errorf("host %s is not a %s device", d.Path, d.Type)
	}
	if unix.Major(uint64(st.Rdev)) != uint32(d.Major) || unix.Minor(uint64(st.Rdev)) != uint32(d.Minor) {
		return fmt.Errorf("host %s is device %d:%d but the bundle asks for %d:%d",
			d.Path, unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)), d.Major, d.Minor)
	}
	rel := strings.TrimPrefix(d.Path, "/")
	if err := EnsureFileInRoot(rootFD, rel, 0o644); err != nil {
		return err
	}
	destFD, err := OpenInRoot(rootFD, rel, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(destFD)
	if err := unix.Mount(ProcFD(srcFD), ProcFD(destFD), "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind host %s into the container: %w", d.Path, err)
	}
	return nil
}

// DefaultDevSymlinks are the /dev entries every container is expected to have
// and which are links rather than nodes.
var DefaultDevSymlinks = [][2]string{
	{"/proc/self/fd", "dev/fd"},
	{"/proc/self/fd/0", "dev/stdin"},
	{"/proc/self/fd/1", "dev/stdout"},
	{"/proc/self/fd/2", "dev/stderr"},
	{"pts/ptmx", "dev/ptmx"},
}

// CreateDevSymlinks creates the conventional /dev symlinks, skipping any that
// already exist. It runs after pivot_root, where "/" is the container root.
func CreateDevSymlinks(rootFD int) error {
	for _, l := range DefaultDevSymlinks {
		target, link := l[0], l[1]
		dir, base := splitDir(link)
		if dir != "" {
			if err := MkdirAllInRoot(rootFD, dir, 0o755); err != nil {
				return err
			}
		}
		parentFD, err := OpenInRoot(rootFD, "/"+dir, unix.O_PATH|unix.O_DIRECTORY, 0)
		if err != nil {
			return err
		}
		err = unix.Symlinkat(target, parentFD, base)
		unix.Close(parentFD)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("initspec: symlink /%s -> %s: %w", link, target, err)
		}
	}
	return nil
}

// pivotRoot swaps the container root in for "/" and detaches the old one.
//
// The new root is entered by descriptor first, so the pivot_root call itself
// names only "." and a fixed child of it: there is no absolute path for a
// racing rename to redirect.
func pivotRoot(rootFD int, rootfs string) error {
	if err := MkdirAllInRoot(rootFD, PutOldName, 0o700); err != nil {
		return fmt.Errorf("initspec: create %s: %w", PutOldName, err)
	}
	if err := unix.Fchdir(rootFD); err != nil {
		return fmt.Errorf("initspec: chdir into the new root: %w", err)
	}
	if err := unix.PivotRoot(".", PutOldName); err != nil {
		return fmt.Errorf("initspec: pivot_root into %s: %w "+
			"(the new root must be a mount point and must not be the current root)", rootfs, err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("initspec: chdir to the new /: %w", err)
	}
	old := "/" + PutOldName
	if err := unix.Unmount(old, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("initspec: detach the old root at %s: %w", old, err)
	}
	if err := unix.Rmdir(old); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("initspec: remove %s: %w", old, err)
	}
	return nil
}

// EnsureProc mounts a fresh procfs at /proc when the bundle did not, so that
// /proc reflects the container's own pid namespace rather than the host's.
// A container whose /proc is the host's can read every host process.
func EnsureProc(rootFD int, mounts []runtimespec.Mount) error {
	for _, m := range mounts {
		if m.Type == "proc" && m.Destination == "/proc" {
			return nil
		}
	}
	if err := MkdirAllInRoot(rootFD, "proc", 0o755); err != nil {
		return err
	}
	fd, err := OpenInRoot(rootFD, "/proc", unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := unix.Mount("proc", ProcFD(fd), "proc", flags, ""); err != nil {
		return fmt.Errorf("initspec: mount /proc for the new pid namespace: %w", err)
	}
	return nil
}

// ApplyMaskedPaths hides each path: a directory is covered with an empty
// read-only tmpfs, a file with a bind of /dev/null.
//
// /dev/null is opened and checked by descriptor (character device 1:3) before
// it is used as a source, and the bind names it as /proc/self/fd/<n>. A
// container image that ships a symlink called /dev/null therefore cannot turn
// a mask into a mount of something it controls (CVE-2025-31133).
func ApplyMaskedPaths(rootFD int, paths []string) error {
	var nullFD = -1
	defer func() {
		if nullFD >= 0 {
			unix.Close(nullFD)
		}
	}()
	for _, p := range paths {
		fd, err := OpenInRoot(rootFD, p, unix.O_PATH, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
				continue
			}
			return fmt.Errorf("initspec: mask %s: %w", p, err)
		}
		var st unix.Stat_t
		serr := unix.Fstat(fd, &st)
		if serr != nil {
			unix.Close(fd)
			return fmt.Errorf("initspec: fstat %s to mask it: %w", p, serr)
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			err = unix.Mount("tmpfs", ProcFD(fd), "tmpfs",
				unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=0k,mode=0555")
			unix.Close(fd)
			if err != nil && !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("initspec: mask directory %s with a tmpfs: %w", p, err)
			}
			continue
		}
		if nullFD < 0 {
			nullFD, err = openVerifiedDevNull(rootFD)
			if err != nil {
				unix.Close(fd)
				return err
			}
		}
		err = unix.Mount(ProcFD(nullFD), ProcFD(fd), "", unix.MS_BIND, "")
		unix.Close(fd)
		if err != nil {
			return fmt.Errorf("initspec: mask file %s with /dev/null: %w", p, err)
		}
	}
	return nil
}

// openVerifiedDevNull opens the container's /dev/null and proves by fstat that
// it is the null device before anything is mounted from it.
func openVerifiedDevNull(rootFD int) (int, error) {
	fd, err := OpenInRoot(rootFD, "/dev/null", unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("initspec: open /dev/null to mask a file: %w", err)
	}
	if err := VerifyCharDevice(fd, 1, 3); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("initspec: refusing to mask with the container's /dev/null: %w", err)
	}
	return fd, nil
}

// ApplyReadonlyPaths binds each path onto itself and remounts it read-only,
// which is the only way to make a single path read-only without making its
// whole filesystem read-only.
func ApplyReadonlyPaths(rootFD int, paths []string) error {
	for _, p := range paths {
		fd, err := OpenInRoot(rootFD, p, unix.O_PATH, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
				continue
			}
			return fmt.Errorf("initspec: make %s read-only: %w", p, err)
		}
		berr := unix.Mount(ProcFD(fd), ProcFD(fd), "", unix.MS_BIND|unix.MS_REC, "")
		unix.Close(fd)
		if berr != nil {
			return fmt.Errorf("initspec: bind %s onto itself: %w", p, berr)
		}
		if err := RemountReadonly(rootFD, p); err != nil {
			return err
		}
	}
	return nil
}

// MakeRootReadonly remounts "/" read-only. It is the last mount step, because
// every earlier one needs to write into the root.
func MakeRootReadonly() error {
	flags := uintptr(unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY)
	var sfs unix.Statfs_t
	if err := unix.Statfs("/", &sfs); err == nil {
		flags |= statfsToMountFlags(int64(sfs.Flags))
	}
	if err := unix.Mount("", "/", "", flags, ""); err != nil {
		return fmt.Errorf("initspec: remount / read-only: %w", err)
	}
	return nil
}

// WriteSysctls applies the bundle's sysctl settings through the host procfs,
// before pivot_root. Each one lands in the namespace the calling process is
// already in, which is why this must run after the namespaces are entered and
// before the root is swapped.
func WriteSysctls(sysctls map[string]string) error {
	for k, v := range sysctls {
		if strings.Contains(k, "/") || strings.Contains(k, "..") {
			return fmt.Errorf("initspec: refusing sysctl key %q: it is a path, not a sysctl name", k)
		}
		p := "/proc/sys/" + strings.ReplaceAll(k, ".", "/")
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			return fmt.Errorf("initspec: set sysctl %s=%s: %w", k, v, err)
		}
	}
	return nil
}
