package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

func TestCloneFlagsFor(t *testing.T) {
	tests := []struct {
		name      string
		nss       []runtimespec.LinuxNamespace
		wantFlags uintptr
		wantUser  bool
		wantErr   string
	}{
		{
			name: "the default set",
			nss:  runtimespec.DefaultNamespaces(),
			wantFlags: unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWIPC |
				unix.CLONE_NEWUTS | unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP,
		},
		{
			name: "with a user namespace",
			nss: append(runtimespec.DefaultNamespaces(),
				runtimespec.LinuxNamespace{Type: runtimespec.UserNamespace}),
			wantFlags: unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWIPC |
				unix.CLONE_NEWUTS | unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUSER,
			wantUser: true,
		},
		{
			name: "a joined network namespace is not a clone flag",
			nss: []runtimespec.LinuxNamespace{
				{Type: runtimespec.MountNamespace},
				{Type: runtimespec.NetworkNamespace, Path: "/run/netns/hull0"},
			},
			wantFlags: unix.CLONE_NEWNS,
		},
		{
			name:    "no mount namespace is refused",
			nss:     []runtimespec.LinuxNamespace{{Type: runtimespec.PIDNamespace}},
			wantErr: "always needs a mount namespace",
		},
		{
			name: "joining a pid namespace by path is refused",
			nss: []runtimespec.LinuxNamespace{
				{Type: runtimespec.MountNamespace},
				{Type: runtimespec.PIDNamespace, Path: "/proc/1/ns/pid"},
			},
			wantErr: "not supported by the native runtime",
		},
		{
			name: "joining a user namespace by path is refused",
			nss: []runtimespec.LinuxNamespace{
				{Type: runtimespec.MountNamespace},
				{Type: runtimespec.UserNamespace, Path: "/proc/1/ns/user"},
			},
			wantErr: "not supported by the native runtime",
		},
		{
			name: "unknown namespace type",
			nss: []runtimespec.LinuxNamespace{
				{Type: runtimespec.MountNamespace},
				{Type: "quantum"},
			},
			wantErr: "unknown namespace type",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := &runtimespec.Spec{Linux: &runtimespec.Linux{Namespaces: tc.nss}}
			flags, _, userns, err := cloneFlagsFor(spec)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatal("expected an error")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("cloneFlagsFor: %v", err)
			}
			if flags != tc.wantFlags {
				t.Errorf("flags = %#x, want %#x", flags, tc.wantFlags)
			}
			if userns != tc.wantUser {
				t.Errorf("userns = %v, want %v", userns, tc.wantUser)
			}
		})
	}

	t.Run("no linux block", func(t *testing.T) {
		if _, _, _, err := cloneFlagsFor(&runtimespec.Spec{}); err == nil {
			t.Fatal("cloneFlagsFor accepted a spec with no linux block")
		}
	})
}

func TestHasResourceLimits(t *testing.T) {
	i64 := func(v int64) *int64 { return &v }
	tests := []struct {
		name string
		spec *runtimespec.Spec
		want bool
	}{
		{name: "no linux block", spec: &runtimespec.Spec{}},
		{name: "no resources", spec: &runtimespec.Spec{Linux: &runtimespec.Linux{}}},
		{
			name: "only a device rule is not a limit",
			spec: &runtimespec.Spec{Linux: &runtimespec.Linux{Resources: &runtimespec.LinuxResources{
				Devices: []runtimespec.LinuxDeviceCgroup{{Allow: false, Access: "rwm"}},
			}}},
		},
		{
			name: "a memory limit is",
			spec: &runtimespec.Spec{Linux: &runtimespec.Linux{Resources: &runtimespec.LinuxResources{
				Memory: &runtimespec.LinuxMemory{Limit: i64(1 << 20)},
			}}},
			want: true,
		},
		{
			name: "a pids limit is",
			spec: &runtimespec.Spec{Linux: &runtimespec.Linux{Resources: &runtimespec.LinuxResources{
				Pids: &runtimespec.LinuxPids{Limit: 64},
			}}},
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasResourceLimits(tc.spec); got != tc.want {
				t.Fatalf("hasResourceLimits = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNewNativeRejectsEmptyRoot(t *testing.T) {
	if _, err := NewNative("", Features{Kernel: "test"}); err == nil {
		t.Fatal("NewNative accepted an empty state root")
	}
}

func TestNativeCreateNeedsInitBinary(t *testing.T) {
	r, err := NewNative(t.TempDir(), Features{Kernel: "test", PidfdSendSignal: true})
	if err != nil {
		t.Fatalf("NewNative: %v", err)
	}
	// Point the search at a directory that has no hull-init.
	t.Setenv(InitBinaryEnv, filepath.Join(t.TempDir(), "nope"))
	_, err = r.Create(context.Background(), "abc", t.TempDir(), CreateOptions{})
	if err == nil {
		t.Fatal("Create succeeded without a hull-init binary")
	}
	if !strings.Contains(err.Error(), "hull-init") {
		t.Fatalf("the error should name hull-init: %v", err)
	}
}

func TestNativeRefusesKernelWithoutPidfd(t *testing.T) {
	r, err := NewNative(t.TempDir(), Features{Kernel: "2.6.32", PidfdSendSignal: false})
	if err != nil {
		t.Fatalf("NewNative: %v", err)
	}
	_, err = r.Create(context.Background(), "abc", t.TempDir(), CreateOptions{})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "pidfd_send_signal") {
		t.Fatalf("the error should name the missing syscall: %v", err)
	}
}

func TestNativeLifecycleErrorsOnUnknownContainer(t *testing.T) {
	r, err := NewNative(t.TempDir(), Features{Kernel: "test", PidfdSendSignal: true})
	if err != nil {
		t.Fatalf("NewNative: %v", err)
	}
	ctx := context.Background()
	if err := r.Start(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Start = %v, want ErrNotFound", err)
	}
	if _, err := r.State(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("State = %v, want ErrNotFound", err)
	}
	if err := r.Kill(ctx, "ghost", syscall.SIGTERM, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("Kill = %v, want ErrNotFound", err)
	}
	if err := r.Pause(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Pause = %v, want ErrNotFound", err)
	}
	// Deleting something that was never created is a success.
	if err := r.Delete(ctx, "ghost", false); err != nil {
		t.Errorf("Delete on an unknown container = %v, want nil", err)
	}
	// An unsafe id is rejected before anything touches the filesystem.
	if err := r.Start(ctx, "../escape"); errors.Is(err, ErrNotFound) {
		t.Error("an unsafe id should be rejected as invalid, not merely not-found")
	}
}

func TestProbeFeaturesIsConsistent(t *testing.T) {
	f, err := ProbeFeatures(context.Background())
	if err != nil {
		t.Fatalf("ProbeFeatures: %v", err)
	}
	if f.Kernel == "" {
		t.Error("the probe did not record a kernel version")
	}
	// The host this is developed against is WSL 5.15, which has all of
	// these. Any Linux new enough to build hull has them too.
	for _, c := range []struct {
		name string
		got  bool
	}{
		{"clone3", f.Clone3},
		{"openat2", f.Openat2},
		{"pidfd_send_signal", f.PidfdSendSignal},
		{"close_range", f.CloseRange},
		{"seccomp", f.Seccomp},
		{"the new mount API", f.MountAPI},
	} {
		if !c.got {
			t.Logf("this kernel (%s) lacks %s; hull will report it in doctor", f.Kernel, c.name)
		}
	}
	// A second call must return the cached answer, not re-probe.
	f2, err := ProbeFeatures(context.Background())
	if err != nil || f2.Kernel != f.Kernel {
		t.Fatalf("second ProbeFeatures disagreed: %v %q vs %q", err, f2.Kernel, f.Kernel)
	}
	if !f.CgroupV2 && len(f.Warnings) == 0 {
		t.Error("a host with no usable cgroup v2 must produce a warning")
	}
}

// ---------- end-to-end, root only ----------

// hullInitBinary returns the path of a hull-init binary to use in the
// end-to-end tests, building one if HULL_INIT does not already name one.
var (
	initBuildOnce sync.Once
	initBuildPath string
	initBuildErr  error
)

func hullInitBinary(t *testing.T) string {
	t.Helper()
	initBuildOnce.Do(func() {
		if p := os.Getenv(InitBinaryEnv); p != "" {
			if _, err := os.Stat(p); err == nil {
				initBuildPath = p
				return
			}
		}
		goBin, err := exec.LookPath("go")
		if err != nil {
			initBuildErr = err
			return
		}
		dir, err := os.MkdirTemp("", "hull-init-build")
		if err != nil {
			initBuildErr = err
			return
		}
		out := filepath.Join(dir, "hull-init")
		cmd := exec.Command(goBin, "build", "-o", out, "github.com/rahuldhali/hull/cmd/hull-init")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, berr := cmd.CombinedOutput(); berr != nil {
			initBuildErr = fmt.Errorf("%v: %s", berr, b)
			return
		}
		initBuildPath = out
	})
	if initBuildErr != nil {
		t.Skipf("cannot build hull-init: %v", initBuildErr)
	}
	return initBuildPath
}

// testRootfs copies the busybox fixture into a fresh temp directory. It is
// copied rather than used in place because the container stage creates and
// removes a put_old directory inside it, and because the fixture lives on the
// Windows drive mount, which cannot be pivot_root'ed into.
func testRootfs(t *testing.T) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "test", "fixtures", "rootfs"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(src, "bin", "busybox")); err != nil {
		t.Skip("no busybox fixture; run test/fixtures/make-rootfs.sh")
	}
	dst := filepath.Join(t.TempDir(), "rootfs")
	if err := copyTree(src, dst); err != nil {
		t.Skipf("cannot copy the rootfs fixture: %v", err)
	}
	return dst
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		switch {
		case fi.IsDir():
			return os.MkdirAll(target, fi.Mode().Perm())
		case fi.Mode()&os.ModeSymlink != 0:
			link, lerr := os.Readlink(p)
			if lerr != nil {
				return lerr
			}
			_ = os.Remove(target)
			return os.Symlink(link, target)
		case fi.Mode().IsRegular():
			in, oerr := os.Open(p)
			if oerr != nil {
				return oerr
			}
			defer in.Close()
			out, cerr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm())
			if cerr != nil {
				return cerr
			}
			defer out.Close()
			_, werr := io.Copy(out, in)
			return werr
		default:
			// Device nodes and sockets in a fixture are not interesting.
			return nil
		}
	})
}

// e2eSpec builds a bundle config that works on a hybrid-cgroup WSL kernel: the
// default mounts minus the cgroup view, plus the standard device nodes.
func e2eSpec(rootfs string, args []string) *runtimespec.Spec {
	spec := runtimespec.DefaultSpec()
	spec.Root = &runtimespec.Root{Path: rootfs}
	spec.Process.Args = args
	spec.Process.Cwd = "/"
	spec.Hostname = "hull-e2e"

	var mounts []runtimespec.Mount
	for _, m := range spec.Mounts {
		if m.Destination == "/sys/fs/cgroup" {
			// A cgroup mount needs a delegated v2 hierarchy, which the
			// WSL 5.15 kernel does not have.
			continue
		}
		mounts = append(mounts, m)
	}
	spec.Mounts = mounts

	mode := uint32(0o666)
	dev := func(path string, major, minor int64) runtimespec.LinuxDevice {
		return runtimespec.LinuxDevice{Path: path, Type: "c", Major: major, Minor: minor, FileMode: &mode}
	}
	spec.Linux.Devices = []runtimespec.LinuxDevice{
		dev("/dev/null", 1, 3),
		dev("/dev/zero", 1, 5),
		dev("/dev/full", 1, 7),
		dev("/dev/random", 1, 8),
		dev("/dev/urandom", 1, 9),
		dev("/dev/tty", 5, 0),
	}
	return spec
}

func writeE2EBundle(t *testing.T, spec *runtimespec.Spec) string {
	t.Helper()
	dir := t.TempDir()
	b, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigFileName), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newE2ERuntime(t *testing.T) *NativeRuntime {
	t.Helper()
	feat, err := ProbeFeatures(context.Background())
	if err != nil {
		t.Fatalf("ProbeFeatures: %v", err)
	}
	r, err := NewNative(filepath.Join(t.TempDir(), "state"), feat)
	if err != nil {
		t.Fatalf("NewNative: %v", err)
	}
	b, err := os.ReadFile(hullInitBinary(t))
	if err != nil {
		t.Fatalf("read hull-init: %v", err)
	}
	if err := r.SetInitBinary(b); err != nil {
		t.Fatalf("SetInitBinary: %v", err)
	}
	return r
}

// TestNativeEndToEnd runs a real container: create, start, wait, delete.
func TestNativeEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	rootfs := testRootfs(t)
	r := newE2ERuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  string
	}{
		{name: "true exits 0", args: []string{"/bin/true"}, wantCode: 0},
		{name: "false exits 1", args: []string{"/bin/false"}, wantCode: 1},
		{name: "exit code is carried", args: []string{"/bin/sh", "-c", "exit 42"}, wantCode: 42},
		{
			name:    "the container is in the new root",
			args:    []string{"/bin/cat", "/.hull-marker"},
			wantOut: "hull-test-rootfs",
		},
		{
			name:    "the hostname comes from the bundle",
			args:    []string{"/bin/hostname"},
			wantOut: "hull-e2e",
		},
		{
			name:    "the container is pid 1 of its own namespace",
			args:    []string{"/bin/sh", "-c", "echo pid=$$"},
			wantOut: "pid=1",
		},
		{
			name:    "proc reflects the container pid namespace",
			args:    []string{"/bin/sh", "-c", "ls /proc | grep -c '^1$'"},
			wantOut: "1",
		},
		{
			name:    "dev/null is the null device",
			args:    []string{"/bin/sh", "-c", "echo discarded > /dev/null && echo ok"},
			wantOut: "ok",
		},
		{
			name:     "a masked proc path is empty or unreadable",
			args:     []string{"/bin/sh", "-c", "head -c 1 /proc/kcore 2>/dev/null | wc -c"},
			wantOut:  "0",
			wantCode: 0,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := "e2e" + string(rune('a'+i))
			spec := e2eSpec(rootfs, tc.args)
			bundle := writeE2EBundle(t, spec)

			var out strings.Builder
			var mu sync.Mutex
			st, err := r.Create(ctx, id, bundle, CreateOptions{
				Stdout: &lockedWriter{w: &out, mu: &mu},
				Stderr: &lockedWriter{w: &out, mu: &mu},
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if st.Status != StatusCreated {
				t.Fatalf("status after Create = %q, want %q", st.Status, StatusCreated)
			}
			if st.Pid <= 0 {
				t.Fatalf("Create returned pid %d", st.Pid)
			}
			defer func() {
				if err := r.Delete(context.Background(), id, true); err != nil {
					t.Errorf("Delete: %v", err)
				}
				if _, err := os.Stat(filepath.Join(r.Root(), id)); !os.IsNotExist(err) {
					t.Errorf("state dir survived Delete: %v", err)
				}
			}()

			if err := r.Start(ctx, id); err != nil {
				t.Fatalf("Start: %v", err)
			}
			final := waitStopped(t, ctx, r, id)
			if final.ExitCode != tc.wantCode {
				t.Errorf("exit code = %d, want %d (output %q)", final.ExitCode, tc.wantCode, out.String())
			}
			if tc.wantOut != "" {
				mu.Lock()
				got := strings.TrimSpace(out.String())
				mu.Unlock()
				if !strings.Contains(got, tc.wantOut) {
					t.Errorf("output = %q, want it to contain %q", got, tc.wantOut)
				}
			}
		})
	}
}

// TestNativeKillAndDelete checks the signal path and that Delete refuses a
// running container unless forced.
func TestNativeKillAndDelete(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	rootfs := testRootfs(t)
	r := newE2ERuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	id := "killme"
	bundle := writeE2EBundle(t, e2eSpec(rootfs, []string{"/bin/sleep", "300"}))
	if _, err := r.Create(ctx, id, bundle, CreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := r.Start(ctx, id); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := r.Delete(ctx, id, false); !errors.Is(err, ErrRunning) {
		t.Fatalf("Delete without force = %v, want ErrRunning", err)
	}
	if err := r.Kill(ctx, id, syscall.SIGKILL, false); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	final := waitStopped(t, ctx, r, id)
	if final.ExitCode != 137 {
		t.Errorf("exit code after SIGKILL = %d, want 137", final.ExitCode)
	}
	if err := r.Delete(ctx, id, false); err != nil {
		t.Fatalf("Delete after exit: %v", err)
	}
	// Signalling a container that no longer exists must not signal anything.
	if err := r.Kill(ctx, id, syscall.SIGKILL, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("Kill after Delete = %v, want ErrNotFound", err)
	}
}

// TestNativeUserNamespace runs a container with its own uid range and checks
// the process really is mapped.
func TestNativeUserNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	feat, err := ProbeFeatures(context.Background())
	if err != nil {
		t.Fatalf("ProbeFeatures: %v", err)
	}
	if !feat.UserNamespaces {
		t.Skip("user namespaces are disabled on this host")
	}
	rootfs := testRootfs(t)
	r := newE2ERuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The container runs as host uid 100000, so the rootfs and every
	// directory above it must be reachable by that uid. Real hull does this
	// by extracting layers into the container's own id range; the test does
	// it directly.
	chownTree(t, rootfs, 100000, 100000)
	openParents(t, rootfs)

	spec := e2eSpec(rootfs, []string{"/bin/sh", "-c", "id -u; cat /proc/self/uid_map"})
	spec.Linux.Namespaces = append(spec.Linux.Namespaces,
		runtimespec.LinuxNamespace{Type: runtimespec.UserNamespace})
	spec.Linux.UIDMappings = []runtimespec.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}
	spec.Linux.GIDMappings = []runtimespec.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}
	// Device nodes cannot be created inside a user namespace, so the stage
	// binds the host's instead; that path is exercised here on purpose.
	bundle := writeE2EBundle(t, spec)

	var out strings.Builder
	var mu sync.Mutex
	id := "userns"
	if _, err := r.Create(ctx, id, bundle, CreateOptions{
		Stdout: &lockedWriter{w: &out, mu: &mu},
		Stderr: &lockedWriter{w: &out, mu: &mu},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer r.Delete(context.Background(), id, true)
	if err := r.Start(ctx, id); err != nil {
		t.Fatalf("Start: %v", err)
	}
	final := waitStopped(t, ctx, r, id)
	mu.Lock()
	got := out.String()
	mu.Unlock()
	if final.ExitCode != 0 {
		t.Fatalf("exit code = %d, output %q", final.ExitCode, got)
	}
	if !strings.Contains(got, "100000") {
		t.Errorf("uid_map does not mention the host range: %q", got)
	}
	if !strings.HasPrefix(strings.TrimSpace(got), "0") {
		t.Errorf("the container process is not uid 0 inside its namespace: %q", got)
	}
}

// TestNativeExec runs a second process inside a live container.
func TestNativeExec(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	rootfs := testRootfs(t)
	r := newE2ERuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	id := "execme"
	bundle := writeE2EBundle(t, e2eSpec(rootfs, []string{"/bin/sleep", "60"}))
	if _, err := r.Create(ctx, id, bundle, CreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer r.Delete(context.Background(), id, true)
	if err := r.Start(ctx, id); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var out strings.Builder
	var mu sync.Mutex
	proc := &runtimespec.Process{
		Args: []string{"/bin/cat", "/.hull-marker"},
		Cwd:  "/",
		Env:  []string{"PATH=/bin:/usr/bin"},
		User: runtimespec.User{UID: 0, GID: 0},
	}
	st, err := r.Exec(ctx, id, proc, ExecOptions{
		Stdout: &lockedWriter{w: &out, mu: &mu},
		Stderr: &lockedWriter{w: &out, mu: &mu},
	})
	if err != nil {
		t.Fatalf("Exec: %v (output %q)", err, out.String())
	}
	if st.ExitCode != 0 {
		t.Fatalf("exec exit code = %d, output %q", st.ExitCode, out.String())
	}
	mu.Lock()
	got := strings.TrimSpace(out.String())
	mu.Unlock()
	if !strings.Contains(got, "hull-test-rootfs") {
		t.Fatalf("the exec'd process was not inside the container: %q", got)
	}
}

// TestCrunEndToEnd exercises the fallback driver, which is hull's documented
// default until the native one has passed the CVE suite.
func TestCrunEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("crun"); err != nil {
		if _, err := exec.LookPath("runc"); err != nil {
			t.Skip("neither crun nor runc is installed")
		}
	}
	rootfs := testRootfs(t)
	r, err := NewCrun("", filepath.Join(t.TempDir(), "crun-root"))
	if err != nil {
		t.Fatalf("NewCrun: %v", err)
	}
	if r.Name() != "crun" && r.Name() != "runc" {
		t.Fatalf("driver name = %q", r.Name())
	}
	if r.Version() == "" {
		t.Error("the driver did not record a version")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	spec := e2eSpec(rootfs, []string{"/bin/true"})
	// crun needs an absolute cgroups path it can actually create; on a
	// hybrid-cgroup host it copes with none at all.
	spec.Linux.CgroupsPath = ""
	bundle := writeE2EBundle(t, spec)

	id := "cruntest"
	st, err := r.Create(ctx, id, bundle, CreateOptions{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if st.Status != StatusCreated {
		t.Fatalf("status = %q, want %q", st.Status, StatusCreated)
	}
	defer r.Delete(context.Background(), id, true)
	if err := r.Start(ctx, id); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		s, serr := r.State(ctx, id)
		if serr != nil {
			t.Fatalf("State: %v", serr)
		}
		if s.Status == StatusStopped {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := r.Delete(ctx, id, false); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.State(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("State after Delete = %v, want ErrNotFound", err)
	}
	// Features must answer even when the binary predates the subcommand.
	f, err := r.Features(ctx)
	if err != nil {
		t.Fatalf("Features: %v", err)
	}
	if f.Name != r.Name() || len(f.Namespaces) == 0 {
		t.Fatalf("features = %+v", f)
	}
}

func waitStopped(t *testing.T, ctx context.Context, r *NativeRuntime, id string) *Status {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		st, err := r.State(ctx, id)
		if err != nil {
			t.Fatalf("State: %v", err)
		}
		if st.Exited {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("container %s did not exit within 30s", id)
	return nil
}

// lockedWriter serialises writes from the runtime's stdout and stderr copy
// goroutines onto one buffer.
type lockedWriter struct {
	w  *strings.Builder
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// chownTree gives every entry under dir to uid:gid, the way a layer extracted
// into a container's own id range would already be owned.
func chownTree(t *testing.T, dir string, uid, gid int) {
	t.Helper()
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
	if err != nil {
		t.Fatalf("chown %s: %v", dir, err)
	}
}

// openParents makes dir and its ancestors *inside the test temp tree*
// traversable, because Go's t.TempDir creates 0700 directories and the
// container runs as a different uid. It stops at os.TempDir so it can never
// touch a real system directory such as /tmp itself.
func openParents(t *testing.T, dir string) {
	t.Helper()
	stop := filepath.Clean(os.TempDir())
	for p := filepath.Clean(dir); p != stop && p != "/" && p != "."; p = filepath.Dir(p) {
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatalf("chmod %s: %v", p, err)
		}
	}
}

// TestExitCodeOf lives with the Linux tests because syscall.WaitStatus is an
// integer here and a struct on Windows; the function itself is portable.
func TestExitCodeOf(t *testing.T) {
	tests := []struct {
		name string
		ws   syscall.WaitStatus
		want int
	}{
		{name: "exit 0", ws: syscall.WaitStatus(0), want: 0},
		{name: "exit 3", ws: syscall.WaitStatus(3 << 8), want: 3},
		{name: "exit 255", ws: syscall.WaitStatus(255 << 8), want: 255},
		{name: "killed by SIGKILL", ws: syscall.WaitStatus(9), want: 137},
		{name: "killed by SIGTERM", ws: syscall.WaitStatus(15), want: 143},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCodeOf(tc.ws); got != tc.want {
				t.Fatalf("ExitCodeOf = %d, want %d", got, tc.want)
			}
		})
	}
}
