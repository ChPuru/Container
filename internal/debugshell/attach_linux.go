//go:build linux

package debugshell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/explain"
	"github.com/ChPuru/hull/internal/runtime/initspec"
)

// ExitError reports that the debug session's command finished with a non-zero
// status. It is returned instead of a plain error so "hull debug ctr -- cmd"
// can propagate the status without the caller parsing a string.
type ExitError struct {
	// Code is the exit status, or 128+signal when the command was killed.
	Code int
	// Signal is the signal that killed the command, or 0.
	Signal syscall.Signal
}

// Error implements error.
func (e *ExitError) Error() string {
	if e.Signal != 0 {
		return fmt.Sprintf("debugshell: the debug session was killed by %s", e.Signal)
	}
	return fmt.Sprintf("debugshell: the debug session exited with status %d", e.Code)
}

// NamespaceFlags translates namespace names into the CLONE_NEW* bitmask
// setns(2) takes. Names are the spellings hull's CLI accepts ("net" as well as
// "network", "mnt" as well as "mount"); the CLONE_NEW* values themselves come
// from internal/runtime/initspec, so there is one such table in the tree.
//
// It is available only on Linux, because the constants it returns are.
func NamespaceFlags(names []string) (int, error) {
	canon, err := canonicalNamespaces(names)
	if err != nil {
		return 0, err
	}
	var flags int
	for _, n := range canon {
		f, ok := initspec.NamespaceFlag(n)
		if !ok {
			return 0, fmt.Errorf("%w: namespace %q has no CLONE_NEW* flag", ErrInvalidOptions, n)
		}
		flags |= f
	}
	return flags, nil
}

// Attach starts a busybox toolbox shell inside the target container's
// namespaces and runs it until it exits.
//
// The sequence, all of it narrated through Options.Tracer:
//
//  1. resolve the container to the host pid of its init process and take a
//     pidfd on it, so a pid recycled between the lookup and the setns cannot
//     redirect the session at an unrelated host process;
//  2. open_tree(2) a detached, recursively read-only clone of the target's
//     root mount tree, while the daemon is still in its own mount namespace;
//  3. on one dedicated OS thread, setns(2) into the requested namespaces -
//     pid, net, ipc and uts by default, never mount and never user;
//  4. unshare a private mount namespace for the session and make it slave, so
//     nothing it mounts can propagate anywhere, least of all into the target;
//  5. move_mount(2) that detached tree onto Options.HostRoot and mount a tmpfs
//     holding the toolbox at Options.ToolboxMount;
//  6. fork the shell from that same thread, with PATH pointing at the toolbox
//     and a banner saying where everything is;
//  7. put the thread's own namespaces back and let the Go runtime destroy it.
//
// Every mount lives in the session's own mount namespace, which the kernel
// destroys when the shell exits, so nothing has to be cleaned up afterwards.
//
// The target container is not modified: nothing is written into its
// filesystem, nothing is mounted in its mount namespace, its cgroup is
// untouched and its processes are not signalled.
//
// A non-zero exit status from the session's command is returned as *ExitError.
func Attach(ctx context.Context, opts Options) error {
	o, err := opts.normalize()
	if err != nil {
		return err
	}
	tr := o.Tracer
	defer tr.Enter("debug shell for " + shortID(o.ContainerID))()

	toolbox, err := openToolbox(o.Toolbox)
	if err != nil {
		tr.Err(err)
		return err
	}
	defer toolbox.Close()

	pid, err := o.Resolve(ctx, o.ContainerID)
	if err != nil {
		tr.Err(err)
		return err
	}
	tr.Step(explain.KindProcess, "container %s is host pid %d", shortID(o.ContainerID), pid)

	pidfd, err := initspec.PidfdOpen(pid)
	if err != nil {
		tr.Err(err)
		return fmt.Errorf("debugshell: take a pidfd on container %s: %w", shortID(o.ContainerID), err)
	}
	defer pidfd.Close()
	fd := int(pidfd.Fd())
	tr.Step(explain.KindProcess, "pidfd_open(%d) -> fd %d", pid, fd)
	if !initspec.PidfdAlive(fd) {
		return fmt.Errorf("%w: pid %d has already exited", ErrNotRunning, pid)
	}

	flags, err := NamespaceFlags(o.Namespaces)
	if err != nil {
		return err
	}

	hostRoot, err := captureHostRoot(pid, tr)
	if err != nil {
		tr.Err(err)
		return err
	}
	if hostRoot != nil {
		defer hostRoot.Close()
	}

	sio, err := o.openStdio()
	if err != nil {
		tr.Err(err)
		return err
	}
	defer sio.closeParent()

	childPID, err := o.spawn(fd, flags, pid, toolbox, hostRoot, sio.child)
	sio.closeChild()
	if err != nil {
		tr.Err(err)
		return err
	}
	tr.Step(explain.KindProcess, "debug shell running as host pid %d", childPID)

	return o.wait(ctx, childPID, sio)
}

// openToolbox opens the staged busybox before any namespace is joined, so the
// session copies it from a descriptor it already holds rather than from a path
// it has to be able to resolve later.
func openToolbox(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w at %s; fetch a static busybox and run hull debug --install-toolbox "+
				"(or call debugshell.EmbedToolbox) once: %w", ErrNoToolbox, path, err)
		}
		return nil, fmt.Errorf("debugshell: open toolbox %s: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("debugshell: stat toolbox %s: %w", path, err)
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		f.Close()
		return nil, fmt.Errorf("%w: %s is not a usable toolbox binary", ErrNoToolbox, path)
	}
	return f, nil
}

// spawn runs the namespace-joining half of the session on a dedicated OS
// thread and returns the pid of the shell it forked.
//
// Everything between the setns and the fork has to happen on one thread,
// because setns(2) changes the calling thread and nothing else. The thread is
// never unlocked: a goroutine that returns while still locked makes the Go
// runtime terminate its thread, which is the only way to be sure a thread that
// has been inside another container's namespaces is never handed back to the
// scheduler.
//
// The runtime can still clone a fresh M from this thread while it is joined,
// and such a thread would inherit the namespaces, so spawnLocked also puts the
// thread's own namespaces back the instant the fork returns. The window is the
// handful of syscalls in between, with no blocking call among them.
func (o Options) spawn(pidfd, flags, targetPID int, toolbox, hostRoot *os.File, files [3]*os.File) (int, error) {
	type result struct {
		pid int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		pid, err := o.spawnLocked(pidfd, flags, targetPID, toolbox, hostRoot, files)
		ch <- result{pid, err}
		// No UnlockOSThread on purpose; see the doc comment.
	}()
	r := <-ch
	return r.pid, r.err
}

// spawnLocked must run on a locked OS thread.
func (o Options) spawnLocked(pidfd, flags, targetPID int, toolbox, hostRoot *os.File, files [3]*os.File) (int, error) {
	tr := o.Tracer

	saved, err := saveNamespaces(flags)
	if err != nil {
		return 0, err
	}
	defer saved.close()

	tr.Step(explain.KindNamespace, "setns(pidfd of %d, %s)", targetPID, explain.CloneFlags(o.Namespaces...))
	if err := initspec.SetnsPidfd(pidfd, flags); err != nil {
		return 0, fmt.Errorf("debugshell: join the namespaces of container %s: %w",
			shortID(o.ContainerID), err)
	}
	// Restore before the thread dies, so the window in which the Go runtime
	// could clone a new thread out of this one is as short as possible.
	defer saved.restore(tr)

	tr.Step(explain.KindNamespace, "unshare(CLONE_NEWNS)   (this session's mounts, nobody else's)")
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return 0, fmt.Errorf("debugshell: unshare a private mount namespace: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_SLAVE, ""); err != nil {
		tr.Detail("MS_REC|MS_SLAVE", err.Error())
		if perr := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); perr != nil {
			return 0, fmt.Errorf("debugshell: make the session's mount tree non-propagating: %w", perr)
		}
		tr.Step(explain.KindMount, "mount(\"\", \"/\", MS_REC|MS_PRIVATE)")
	} else {
		tr.Step(explain.KindMount, "mount(\"\", \"/\", MS_REC|MS_SLAVE)")
	}

	if err := o.mountHostRoot(hostRoot); err != nil {
		// Not fatal: the operator still gets a shell, and the banner then
		// points at /proc/1/root instead of an empty directory.
		tr.Err(err)
		o.HostRoot = ""
	}
	if err := o.mountToolbox(toolbox); err != nil {
		return 0, err
	}

	argv := o.argv(targetPID)
	tr.Step(explain.KindProcess, "execve(%q, %d args, %d env)", argv[0], len(argv), len(o.environ()))
	pid, err := syscall.ForkExec(argv[0], argv, &syscall.ProcAttr{
		Dir:   "/",
		Env:   o.environ(),
		Files: []uintptr{files[0].Fd(), files[1].Fd(), files[2].Fd()},
		Sys:   &syscall.SysProcAttr{Setsid: o.Tty, Setctty: o.Tty, Ctty: 0},
	})
	if err != nil {
		return 0, fmt.Errorf("debugshell: start %s inside container %s: %w",
			argv[0], shortID(o.ContainerID), err)
	}
	return pid, nil
}

// captureHostRoot takes a detached, read-only copy of the target's whole root
// mount tree, before any namespace has been joined, and returns the descriptor
// that holds it.
//
// It has to be a detached tree rather than a plain bind. The source is
// /proc/<pid>/root, the kernel's own live handle on the container's root, and
// its mounts belong to the daemon's mount namespace; mount(2) refuses to bind
// a source whose mount is not in the caller's current namespace, and by the
// time the session needs it the caller has unshared its own. open_tree(2) with
// OPEN_TREE_CLONE produces an anonymous tree instead, which move_mount(2) will
// graft into whatever namespace asks for it later.
//
// The clone is made read-only here, while it is still attached to nothing, so
// the session cannot change what it came to look at. A caller on a kernel
// without open_tree gets a nil file and no error: the session then points the
// operator at /proc/1/root, which needs no mount at all.
func captureHostRoot(targetPID int, tr explain.Tracer) (*os.File, error) {
	src := "/proc/" + strconv.Itoa(targetPID) + "/root"
	fd, err := unix.OpenTree(unix.AT_FDCWD, src,
		uint(unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_RECURSIVE))
	if err != nil {
		tr.Detail("open_tree("+src+", OPEN_TREE_CLONE|AT_RECURSIVE)", err.Error())
		return nil, nil
	}
	f := os.NewFile(uintptr(fd), src)
	tr.Step(explain.KindMount, "open_tree(%q, OPEN_TREE_CLONE|AT_RECURSIVE) -> fd %d", src, fd)

	attr := &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}
	if err := unix.MountSetattr(int(f.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_RECURSIVE, attr); err != nil {
		f.Close()
		return nil, fmt.Errorf("debugshell: make the container's root read-only before it is attached "+
			"(mount_setattr AT_RECURSIVE|MOUNT_ATTR_RDONLY): %w", err)
	}
	tr.Step(explain.KindMount, "mount_setattr(fd %d, AT_EMPTY_PATH|AT_RECURSIVE, MOUNT_ATTR_RDONLY)", int(f.Fd()))
	return f, nil
}

// mountHostRoot grafts the detached tree captured by captureHostRoot onto
// Options.HostRoot inside the session's private mount namespace.
//
// A failure is reported rather than returned fatal by the caller: a debug
// shell that refuses to start because one convenience mount was refused would
// be exactly the wrong trade, and /proc/1/root still shows the same files.
func (o Options) mountHostRoot(tree *os.File) error {
	if tree == nil {
		return fmt.Errorf("debugshell: this kernel has no open_tree(2), so the container's root "+
			"cannot be attached at %s; use /proc/1/root instead", o.HostRoot)
	}
	if err := os.MkdirAll(o.HostRoot, 0o755); err != nil {
		return fmt.Errorf("debugshell: create the mountpoint %s: %w", o.HostRoot, err)
	}
	if err := unix.MoveMount(int(tree.Fd()), "", unix.AT_FDCWD, o.HostRoot,
		unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("debugshell: move_mount the container's root onto %s: %w", o.HostRoot, err)
	}
	o.Tracer.Step(explain.KindMount, "move_mount(fd %d, \"\", %q, MOVE_MOUNT_F_EMPTY_PATH)",
		int(tree.Fd()), o.HostRoot)
	return nil
}

// mountToolbox mounts the toolbox tmpfs and stages busybox plus its applet
// symlinks in it.
//
// A tmpfs rather than a bind of the data root means the toolbox is writable
// scratch space for the operator, disappears with the session, and cannot be
// used to modify hull's own files by accident. It is mounted nosuid and nodev
// but of course not noexec.
func (o Options) mountToolbox(toolbox *os.File) error {
	tr := o.Tracer
	if err := os.MkdirAll(o.ToolboxMount, 0o755); err != nil {
		return fmt.Errorf("debugshell: create the mountpoint %s: %w", o.ToolboxMount, err)
	}
	data := "mode=0755,size=" + strconv.Itoa(DefaultToolboxSize)
	tr.Step(explain.KindMount, "mount(\"tmpfs\", %q, \"tmpfs\", MS_NOSUID|MS_NODEV, %q)", o.ToolboxMount, data)
	if err := unix.Mount("tmpfs", o.ToolboxMount, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, data); err != nil {
		return fmt.Errorf("debugshell: mount the toolbox tmpfs at %s: %w", o.ToolboxMount, err)
	}

	bin := o.ToolboxMount + "/bin"
	if err := os.Mkdir(bin, 0o755); err != nil {
		return fmt.Errorf("debugshell: create %s: %w", bin, err)
	}
	if _, err := toolbox.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("debugshell: rewind the toolbox binary: %w", err)
	}
	dst, err := os.OpenFile(bin+"/"+ToolboxName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, toolboxPerm)
	if err != nil {
		return fmt.Errorf("debugshell: create %s/%s: %w", bin, ToolboxName, err)
	}
	n, err := io.Copy(dst, toolbox)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("debugshell: stage the toolbox in %s: %w", bin, err)
	}

	linked := 0
	for _, applet := range Applets {
		if applet == ToolboxName {
			continue
		}
		if err := os.Symlink(ToolboxName, bin+"/"+applet); err != nil {
			return fmt.Errorf("debugshell: link the %s applet: %w", applet, err)
		}
		linked++
	}
	tr.Step(explain.KindMount, "staged %d-byte busybox and %d applet symlinks in %s", n, linked, bin)
	return nil
}

// argv builds the command line the session's shell is exec'd with.
//
// The requested command is wrapped in the toolbox shell rather than exec'd
// directly, because two things have to happen inside the target's pid
// namespace and cannot be done from outside it: mounting a fresh procfs, which
// takes the pid namespace of the process that mounts it and is what makes
// /proc and /proc/1/root show the container rather than the host, and printing
// the banner into the session's own terminal.
func (o Options) argv(targetPID int) []string {
	shell := o.ToolboxMount + "/bin/sh"
	prelude := "mount -t proc -o nosuid,nodev,noexec proc /proc 2>/dev/null\n"
	if !o.NoBanner {
		prelude += "printf '%s' " + shellQuote(o.banner(targetPID)) + "\n"
	}
	prelude += "exec \"$@\"\n"
	return append([]string{shell, "-c", prelude, "hull-debug"}, o.Command...)
}

// shellQuote wraps s in single quotes for /bin/sh, which has no escape inside
// them: a single quote is emitted by closing the string, escaping the quote
// and opening a new one.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ---------- the thread's own namespaces ----------

// savedNS holds this thread's original namespaces so they can be restored
// after the fork.
type savedNS struct {
	fds   []int
	flags []int
}

// nsFileFor maps a CLONE_NEW* flag to its /proc/self/ns file name.
var nsFileFor = map[int]string{
	unix.CLONE_NEWNS:     "mnt",
	unix.CLONE_NEWNET:    "net",
	unix.CLONE_NEWIPC:    "ipc",
	unix.CLONE_NEWUTS:    "uts",
	unix.CLONE_NEWPID:    "pid",
	unix.CLONE_NEWCGROUP: "cgroup",
	unix.CLONE_NEWTIME:   "time",
}

// nsRestoreOrder is the order namespaces are put back in: everything the
// session joined first, then the mount namespace it unshared, which is the one
// whose restoration needs the others to have been sane.
var nsRestoreOrder = []int{
	unix.CLONE_NEWNET, unix.CLONE_NEWIPC, unix.CLONE_NEWUTS,
	unix.CLONE_NEWPID, unix.CLONE_NEWCGROUP, unix.CLONE_NEWTIME, unix.CLONE_NEWNS,
}

// saveNamespaces opens this thread's current namespace files for every flag in
// joinFlags, plus the mount namespace, which the session always unshares.
//
// CLONE_NEWPID is saved like the rest: setns(2) with it sets only
// pid_ns_for_children, and setting that back to the thread's own active pid
// namespace is explicitly allowed.
func saveNamespaces(joinFlags int) (*savedNS, error) {
	s := &savedNS{}
	want := joinFlags | unix.CLONE_NEWNS
	for _, flag := range nsRestoreOrder {
		if want&flag == 0 {
			continue
		}
		name := nsFileFor[flag]
		fd, err := unix.Open("/proc/self/ns/"+name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			s.close()
			return nil, fmt.Errorf("debugshell: open /proc/self/ns/%s so the daemon's thread can be "+
				"put back afterwards: %w", name, err)
		}
		s.fds = append(s.fds, fd)
		s.flags = append(s.flags, flag)
	}
	return s, nil
}

// restore puts the thread back in its own namespaces. Failures are narrated
// rather than returned: the thread is destroyed either way, and a restore
// failure must not mask the session's own result.
func (s *savedNS) restore(tr explain.Tracer) {
	for i, fd := range s.fds {
		if err := unix.Setns(fd, s.flags[i]); err != nil {
			tr.Err(fmt.Errorf("debugshell: put this thread back in the daemon's %s namespace: %w",
				nsFileFor[s.flags[i]], err))
		}
	}
	tr.Step(explain.KindNamespace, "setns back to the daemon's own namespaces; the joined thread is discarded")
}

// close releases the saved descriptors.
func (s *savedNS) close() {
	for _, fd := range s.fds {
		_ = unix.Close(fd)
	}
	s.fds = nil
	s.flags = nil
}

// ---------- stdio ----------

// sessionIO holds the descriptors handed to the shell and the relays that
// carry bytes between them and the caller.
type sessionIO struct {
	child   [3]*os.File
	parent  []*os.File
	master  *os.File
	drained chan struct{}
}

// closeChild closes the descriptors that now belong to the forked shell. The
// parent must not keep them, or a pipe never reports EOF.
func (s *sessionIO) closeChild() {
	seen := map[*os.File]bool{}
	for _, f := range s.child {
		if f == nil || seen[f] || f == os.Stdin || f == os.Stdout || f == os.Stderr {
			continue
		}
		seen[f] = true
		_ = f.Close()
	}
}

// closeParent releases the caller's ends once the session is over.
func (s *sessionIO) closeParent() {
	for _, f := range s.parent {
		_ = f.Close()
	}
	s.parent = nil
}

// openStdio wires the session to Options.Attach, allocating a pty when
// Options.Tty is set and three pipes when it is not.
func (o Options) openStdio() (*sessionIO, error) {
	in, out, errw := o.streams()
	s := &sessionIO{drained: make(chan struct{})}

	if o.Tty {
		master, peer, err := openPTY()
		if err != nil {
			return nil, err
		}
		if o.Width > 0 && o.Height > 0 {
			if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ,
				&unix.Winsize{Row: o.Height, Col: o.Width}); err != nil {
				master.Close()
				peer.Close()
				return nil, fmt.Errorf("debugshell: set the session window size: %w", err)
			}
		}
		s.child = [3]*os.File{peer, peer, peer}
		s.master = master
		s.parent = []*os.File{master}
		go func() {
			defer close(s.drained)
			_, _ = io.Copy(out, master)
		}()
		go func() { _, _ = io.Copy(master, in) }()
		return s, nil
	}

	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("debugshell: create the session stdin pipe: %w", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return nil, fmt.Errorf("debugshell: create the session stdout pipe: %w", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return nil, fmt.Errorf("debugshell: create the session stderr pipe: %w", err)
	}
	s.child = [3]*os.File{inR, outW, errW}
	s.parent = []*os.File{inW, outR, errR}

	var pending = make(chan struct{}, 2)
	go func() { _, _ = io.Copy(out, outR); pending <- struct{}{} }()
	go func() { _, _ = io.Copy(errw, errR); pending <- struct{}{} }()
	go func() {
		defer close(s.drained)
		<-pending
		<-pending
	}()
	go func() {
		_, _ = io.Copy(inW, in)
		_ = inW.Close()
	}()
	return s, nil
}

// streams resolves Options.Attach and Options.Stderr into the three streams
// the session uses, defaulting to the process's own.
func (o Options) streams() (in io.Reader, out io.Writer, errw io.Writer) {
	in, out = io.Reader(os.Stdin), io.Writer(os.Stdout)
	if o.Attach != nil {
		in, out = o.Attach, o.Attach
	}
	errw = out
	if !o.Tty && o.Stderr != nil {
		errw = o.Stderr
	}
	return in, out, errw
}

// wait blocks until the session's shell exits, killing it if ctx is cancelled
// first, and then waits for the output relays to drain.
func (o Options) wait(ctx context.Context, pid int, sio *sessionIO) error {
	type outcome struct {
		ws  unix.WaitStatus
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		var ws unix.WaitStatus
		for {
			_, err := unix.Wait4(pid, &ws, 0, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			done <- outcome{ws, err}
			return
		}
	}()

	var res outcome
	select {
	case <-ctx.Done():
		o.Tracer.Step(explain.KindSignal, "kill(%d, SIGKILL)   (the debug session's context was cancelled)", pid)
		_ = unix.Kill(pid, unix.SIGKILL)
		res = <-done
		o.drain(sio)
		if res.err != nil {
			return fmt.Errorf("debugshell: wait for the cancelled debug session: %w", res.err)
		}
		return ctx.Err()
	case res = <-done:
	}
	o.drain(sio)
	if res.err != nil {
		return fmt.Errorf("debugshell: wait for the debug session: %w", res.err)
	}
	switch {
	case res.ws.Signaled():
		sig := res.ws.Signal()
		o.Tracer.Step(explain.KindSignal, "the debug session was killed by %s", sig)
		return &ExitError{Code: 128 + int(sig), Signal: sig}
	case res.ws.ExitStatus() != 0:
		o.Tracer.Step(explain.KindProcess, "the debug session exited with status %d", res.ws.ExitStatus())
		return &ExitError{Code: res.ws.ExitStatus()}
	}
	o.Tracer.Step(explain.KindProcess, "the debug session exited cleanly; its mount namespace is gone with it")
	return nil
}

// drain closes the caller's ends and waits for the output relays to finish, so
// the last line the shell wrote has reached the caller before Attach returns.
func (o Options) drain(sio *sessionIO) {
	sio.closeParent()
	<-sio.drained
}

// openPTY allocates a UNIX98 pseudo-terminal pair on the host, before any
// namespace is joined, and returns the master and the peer.
//
// The peer is verified with fstat through initspec.VerifyConsoleFD and is
// never re-opened by path, which is the shape of the 2025 runc console CVEs
// (CVE-2025-31133 / 52565 / 52881).
func openPTY() (master, peer *os.File, err error) {
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("debugshell: open /dev/ptmx: %w", err)
	}
	master = os.NewFile(uintptr(mfd), "pty-master")
	defer func() {
		if err != nil {
			master.Close()
		}
	}()
	if err = unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		return nil, nil, fmt.Errorf("debugshell: unlock the session pty: %w", err)
	}
	n, err := unix.IoctlGetInt(mfd, unix.TIOCGPTN)
	if err != nil {
		return nil, nil, fmt.Errorf("debugshell: read the session pty number: %w", err)
	}
	name := "/dev/pts/" + strconv.Itoa(n)
	pfd, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("debugshell: open the session pty peer %s: %w", name, err)
	}
	peer = os.NewFile(uintptr(pfd), name)
	if verr := initspec.VerifyConsoleFD(pfd); verr != nil {
		peer.Close()
		return nil, nil, verr
	}
	return master, peer, nil
}
