package initspec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func openRoot(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open root %s: %v", dir, err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

// TestOpenInRootContainsSymlinks is the core containment test: no symlink
// inside a container-controlled tree may resolve to anything outside it.
func TestOpenInRootContainsSymlinks(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "inside.txt"), "inside")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "etc", "passwd"), "container-passwd")

	// An absolute symlink: inside the container it must resolve to
	// <root>/etc/passwd, never to the host's /etc/passwd.
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "abs-link")); err != nil {
		t.Fatal(err)
	}
	// A climbing symlink: ".." must not escape.
	if err := os.Symlink("../../../../etc/passwd", filepath.Join(root, "climb-link")); err != nil {
		t.Fatal(err)
	}
	// A symlink to the host's shadow file, which the container must never
	// be able to reach.
	if err := os.Symlink("/etc/shadow", filepath.Join(root, "shadow-link")); err != nil {
		t.Fatal(err)
	}

	rootFD := openRoot(t, root)

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "plain file", path: "inside.txt", want: "inside"},
		{name: "absolute symlink is re-rooted", path: "abs-link", want: "container-passwd"},
		{name: "climbing symlink is clamped", path: "climb-link", want: "container-passwd"},
		{name: "absolute path is re-rooted", path: "/etc/passwd", want: "container-passwd"},
		{name: "explicit dot-dot is clamped", path: "../../etc/passwd", want: "container-passwd"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := OpenInRoot(rootFD, tc.path, unix.O_RDONLY, 0)
			if err != nil {
				t.Fatalf("OpenInRoot(%q): %v", tc.path, err)
			}
			defer unix.Close(fd)
			f := os.NewFile(uintptr(fd), tc.path)
			b := make([]byte, 64)
			n, _ := f.Read(b)
			if got := strings.TrimSpace(string(b[:n])); got != tc.want {
				t.Fatalf("read %q, want %q - the path escaped the root", got, tc.want)
			}
		})
	}

	// The host's /etc/shadow is not reachable: <root>/etc/shadow does not
	// exist, so the open fails rather than reading the host file.
	if fd, err := OpenInRoot(rootFD, "shadow-link", unix.O_RDONLY, 0); err == nil {
		unix.Close(fd)
		t.Fatal("a symlink to /etc/shadow resolved; it must be contained inside the root")
	}
}

// TestOpenInRootWalkMatchesOpenat2 runs the same containment table through the
// fallback walk, which is what hull uses on a kernel without openat2.
func TestOpenInRootWalkMatchesOpenat2(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "a", "b", "f"), "deep")
	if err := os.Symlink("/a/b/f", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../../../../etc/passwd", filepath.Join(root, "a", "climb")); err != nil {
		t.Fatal(err)
	}
	rootFD := openRoot(t, root)

	for _, path := range []string{"a/b/f", "link", "/a/b/f"} {
		fd, err := openInRootWalk(rootFD, strings.TrimPrefix(path, "/"), unix.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("openInRootWalk(%q): %v", path, err)
		}
		f := os.NewFile(uintptr(fd), path)
		b := make([]byte, 16)
		n, _ := f.Read(b)
		f.Close()
		if got := strings.TrimSpace(string(b[:n])); got != "deep" {
			t.Fatalf("openInRootWalk(%q) read %q, want %q", path, got, "deep")
		}
	}
	// The climbing link lands on <root>/etc/passwd, which does not exist.
	if fd, err := openInRootWalk(rootFD, "a/climb", unix.O_RDONLY, 0); err == nil {
		unix.Close(fd)
		t.Fatal("the fallback walk followed a climbing symlink out of the root")
	}
}

func TestMkdirAllInRoot(t *testing.T) {
	root := t.TempDir()
	rootFD := openRoot(t, root)

	if err := MkdirAllInRoot(rootFD, "/var/lib/hull/deep", 0o755); err != nil {
		t.Fatalf("MkdirAllInRoot: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(root, "var", "lib", "hull", "deep")); err != nil || !fi.IsDir() {
		t.Fatalf("directory was not created: %v", err)
	}
	// Idempotent.
	if err := MkdirAllInRoot(rootFD, "/var/lib/hull/deep", 0o755); err != nil {
		t.Fatalf("second MkdirAllInRoot: %v", err)
	}
	// A symlinked parent must not redirect the mkdir out of the root.
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	// Either the create is refused (the re-rooted target does not exist) or
	// it lands inside the root. What must never happen is a directory
	// appearing in the host directory the symlink names.
	_ = MkdirAllInRoot(rootFD, "/escape/made-it", 0o755)
	if _, err := os.Stat(filepath.Join(outside, "made-it")); err == nil {
		t.Fatal("mkdir escaped the root through a symlinked parent")
	}
	if err := MkdirAllInRoot(rootFD, "../escaped", 0o755); err == nil {
		t.Fatal("MkdirAllInRoot accepted a path that climbs out of the root")
	}
}

func TestEnsureFileInRoot(t *testing.T) {
	root := t.TempDir()
	rootFD := openRoot(t, root)
	if err := EnsureFileInRoot(rootFD, "/etc/hosts", 0o644); err != nil {
		t.Fatalf("EnsureFileInRoot: %v", err)
	}
	fi, err := os.Stat(filepath.Join(root, "etc", "hosts"))
	if err != nil || fi.IsDir() {
		t.Fatalf("file was not created: %v", err)
	}
	if err := EnsureFileInRoot(rootFD, "/etc/hosts", 0o644); err != nil {
		t.Fatalf("EnsureFileInRoot is not idempotent: %v", err)
	}
}

// TestSealedMemfd checks the memfd really is immutable. This is the
// CVE-2019-5736 mitigation: if the seals are missing, a container that can
// open the fd can rewrite the binary it is about to be exec'd from.
func TestSealedMemfd(t *testing.T) {
	payload := []byte("\x7fELF fake hull-init")
	f, err := SealedMemfd("hull-init-test", payload)
	if err != nil {
		t.Fatalf("SealedMemfd: %v", err)
	}
	defer f.Close()

	seals, err := MemfdSeals(f.Fd())
	if err != nil {
		t.Fatalf("MemfdSeals: %v", err)
	}
	for _, s := range []struct {
		name string
		bit  int
	}{
		{"F_SEAL_SEAL", unix.F_SEAL_SEAL},
		{"F_SEAL_SHRINK", unix.F_SEAL_SHRINK},
		{"F_SEAL_GROW", unix.F_SEAL_GROW},
		{"F_SEAL_WRITE", unix.F_SEAL_WRITE},
	} {
		if seals&s.bit == 0 {
			t.Errorf("%s is not set (seals = %#x)", s.name, seals)
		}
	}
	if _, err := f.WriteAt([]byte("x"), 0); err == nil {
		t.Fatal("a sealed memfd accepted a write")
	}
	// The contents are still readable, which is what execve needs.
	got := make([]byte, len(payload))
	if _, err := f.ReadAt(got, 0); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("contents = %q, want %q", got, payload)
	}
	// A second seal attempt must be refused by F_SEAL_SEAL.
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE); err == nil {
		t.Fatal("F_SEAL_SEAL did not stop further sealing")
	}
}

// TestSanitizeFDs is the CVE-2024-21626 guard: nothing above stderr survives
// into the container except the descriptors hull deliberately keeps.
func TestSanitizeFDs(t *testing.T) {
	// Closing descriptors in the test process would break the test runner,
	// so the real work happens in a subprocess.
	out := runHelper(t, "fdsanitize")
	if !strings.Contains(out, "OK") {
		t.Fatalf("helper said: %s", out)
	}
}

func TestCloseRangeProbe(t *testing.T) {
	// The probe must not close anything in this process.
	before, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer before.Close()
	_ = HaveCloseRange()
	if _, err := before.Stat(); err != nil {
		t.Fatalf("HaveCloseRange closed a live descriptor: %v", err)
	}
}

func TestPidfdHelpers(t *testing.T) {
	f, err := PidfdOpen(os.Getpid())
	if err != nil {
		if errors.Is(err, ErrNoPidfd) {
			t.Skip("kernel has no pidfd_open")
		}
		t.Fatalf("PidfdOpen: %v", err)
	}
	defer f.Close()
	if !PidfdAlive(int(f.Fd())) {
		t.Fatal("this process reports as not alive through its own pidfd")
	}
	if err := PidfdSendSignal(int(f.Fd()), 0); err != nil {
		t.Fatalf("PidfdSendSignal with signal 0: %v", err)
	}
	if !HavePidfdSendSignal() {
		t.Fatal("HavePidfdSendSignal is false on a kernel that just answered a pidfd call")
	}
}

// TestPidfdRefusesDeadProcess proves the pid-reuse defence: once the process
// is gone, the pidfd refuses to signal, where a bare pid would have been
// reused and signalled something else.
func TestPidfdRefusesDeadProcess(t *testing.T) {
	pid, err := forkTrue(t)
	if err != nil {
		t.Skipf("cannot fork a helper: %v", err)
	}
	f, err := PidfdOpen(pid)
	if err != nil {
		t.Fatalf("PidfdOpen(%d): %v", pid, err)
	}
	defer f.Close()
	var ws unix.WaitStatus
	for {
		_, werr := unix.Wait4(pid, &ws, 0, nil)
		if errors.Is(werr, unix.EINTR) {
			continue
		}
		if werr != nil {
			t.Fatalf("wait4: %v", werr)
		}
		break
	}
	if PidfdAlive(int(f.Fd())) {
		t.Fatal("a reaped process still reports alive through its pidfd")
	}
	err = PidfdSendSignal(int(f.Fd()), unix.SIGTERM)
	if err == nil {
		t.Fatal("signalling a reaped process through its pidfd succeeded; pid reuse is not defended")
	}
	if !errors.Is(err, unix.ESRCH) {
		t.Fatalf("err = %v, want ESRCH", err)
	}
}

func TestNamespaceFlag(t *testing.T) {
	for _, name := range []string{"mount", "network", "ipc", "uts", "pid", "user", "cgroup"} {
		if _, ok := NamespaceFlag(name); !ok {
			t.Errorf("NamespaceFlag(%q) is not known", name)
		}
	}
	if _, ok := NamespaceFlag("quantum"); ok {
		t.Error("NamespaceFlag invented a namespace type")
	}
}

func TestProcFD(t *testing.T) {
	if got := ProcFD(7); got != "/proc/self/fd/7" {
		t.Fatalf("ProcFD(7) = %q", got)
	}
}

func TestVerifyCharDevice(t *testing.T) {
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no /dev/null: %v", err)
	}
	defer unix.Close(fd)
	if err := VerifyCharDevice(fd, 1, 3); err != nil {
		t.Fatalf("VerifyCharDevice(/dev/null, 1, 3): %v", err)
	}
	if err := VerifyCharDevice(fd, 1, 5); err == nil {
		t.Fatal("VerifyCharDevice accepted the wrong minor number")
	}
	// A regular file must never pass as a device.
	tmp, err := os.CreateTemp(t.TempDir(), "notadev")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	if err := VerifyCharDevice(int(tmp.Fd()), 1, 3); err == nil {
		t.Fatal("VerifyCharDevice accepted a regular file")
	}
	if err := VerifyConsoleFD(int(tmp.Fd())); err == nil {
		t.Fatal("VerifyConsoleFD accepted a regular file as a console")
	}
}

func TestParseMountOptions(t *testing.T) {
	tests := []struct {
		name  string
		opts  []string
		flags uintptr
		prop  uintptr
		data  string
	}{
		{name: "empty"},
		{
			name:  "the standard proc options",
			opts:  []string{"nosuid", "noexec", "nodev"},
			flags: unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV,
		},
		{
			name:  "rbind is recursive",
			opts:  []string{"rbind", "ro"},
			flags: unix.MS_BIND | unix.MS_REC | unix.MS_RDONLY,
		},
		{
			name:  "rw clears ro",
			opts:  []string{"ro", "rw"},
			flags: 0,
		},
		{
			name:  "propagation is separated out",
			opts:  []string{"rbind", "rprivate"},
			flags: unix.MS_BIND | unix.MS_REC,
			prop:  unix.MS_PRIVATE | unix.MS_REC,
		},
		{
			name:  "unknown options become the data string",
			opts:  []string{"nosuid", "mode=1777", "size=64m"},
			flags: unix.MS_NOSUID,
			data:  "mode=1777,size=64m",
		},
		{
			name:  "tmpfs devpts options",
			opts:  []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"},
			flags: unix.MS_NOSUID | unix.MS_NOEXEC,
			data:  "newinstance,ptmxmode=0666,mode=0620,gid=5",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flags, prop, data := ParseMountOptions(tc.opts)
			if flags != tc.flags {
				t.Errorf("flags = %#x, want %#x", flags, tc.flags)
			}
			if prop != tc.prop {
				t.Errorf("propagation = %#x, want %#x", prop, tc.prop)
			}
			if data != tc.data {
				t.Errorf("data = %q, want %q", data, tc.data)
			}
		})
	}
}

func TestLookupInPath(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "hull-fake")
	mustWrite(t, exe, "#!/bin/sh\n")
	if err := os.Chmod(exe, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := LookupInPath("hull-fake", []string{"PATH=" + dir})
	if err != nil {
		t.Fatalf("LookupInPath: %v", err)
	}
	if got != exe {
		t.Fatalf("resolved %q, want %q", got, exe)
	}
	if _, err := LookupInPath("hull-definitely-missing", []string{"PATH=" + dir}); err == nil {
		t.Fatal("LookupInPath found something that does not exist")
	}
	if _, err := LookupInPath(exe, nil); err != nil {
		t.Fatalf("LookupInPath with an absolute path: %v", err)
	}
}

func TestSeccompActionsAvailable(t *testing.T) {
	actions, err := SeccompActionsAvailable()
	if err != nil {
		t.Fatalf("SeccompActionsAvailable: %v", err)
	}
	if len(actions) == 0 {
		t.Skip("this kernel does not publish actions_avail")
	}
	found := false
	for _, a := range actions {
		if a == "allow" {
			found = true
		}
	}
	if !found {
		t.Errorf("actions_avail %v does not contain 'allow'", actions)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// forkTrue starts /bin/true (or busybox true) without letting the os/exec
// package reap it, so the test can control the wait itself.
func forkTrue(t *testing.T) (int, error) {
	t.Helper()
	for _, cand := range []string{"/bin/true", "/usr/bin/true"} {
		if _, err := os.Stat(cand); err != nil {
			continue
		}
		return syscall.ForkExec(cand, []string{cand}, &syscall.ProcAttr{Files: []uintptr{0, 1, 2}})
	}
	return 0, errors.New("no /bin/true on this host")
}
