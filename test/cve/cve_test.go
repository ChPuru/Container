//go:build cve && linux

// Package cve holds hull's container-escape regression suite.
//
// Each test reproduces the *shape* of a published runc breakout against hull's
// native runtime and asserts that hull either refuses the container outright
// or contains it. They are build-tagged because they need root and a real
// kernel:
//
//	go test -tags cve ./test/cve/...
//
// ARCHITECTURE.md names crun as hull's documented default runtime until this
// suite passes against the native one, so a failure here is a release blocker,
// not a flaky test.
package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
	"github.com/rahuldhali/hull/internal/runtime"
	"github.com/rahuldhali/hull/internal/runtime/initspec"
)

// ---------- harness ----------

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

var (
	initOnce sync.Once
	initPath string
	initErr  error
)

// hullInit builds (once) the hull-init binary the native runtime seals into a
// memfd.
func hullInit(t *testing.T) string {
	t.Helper()
	initOnce.Do(func() {
		if p := os.Getenv(runtime.InitBinaryEnv); p != "" {
			if _, err := os.Stat(p); err == nil {
				initPath = p
				return
			}
		}
		goBin, err := exec.LookPath("go")
		if err != nil {
			initErr = err
			return
		}
		dir, err := os.MkdirTemp("", "hull-cve-init")
		if err != nil {
			initErr = err
			return
		}
		out := filepath.Join(dir, "hull-init")
		cmd := exec.Command(goBin, "build", "-o", out, "github.com/rahuldhali/hull/cmd/hull-init")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, berr := cmd.CombinedOutput(); berr != nil {
			initErr = fmt.Errorf("%v: %s", berr, b)
			return
		}
		initPath = out
	})
	if initErr != nil {
		t.Skipf("cannot build hull-init: %v", initErr)
	}
	return initPath
}

// fixtureRootfs copies the busybox test rootfs into a private directory the
// test may vandalise, which is the point: these tests model a *malicious
// image*, so they need to be able to plant symlinks in it.
func fixtureRootfs(t *testing.T) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "fixtures", "rootfs"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(src, "bin", "busybox")); err != nil {
		t.Skip("no busybox fixture; run test/fixtures/make-rootfs.sh")
	}
	dst := filepath.Join(t.TempDir(), "rootfs")
	if err := copyTree(src, dst); err != nil {
		t.Fatalf("copy the rootfs fixture: %v", err)
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
			return nil
		}
	})
}

func newRuntime(t *testing.T) *runtime.NativeRuntime {
	t.Helper()
	feat, err := runtime.ProbeFeatures(context.Background())
	if err != nil {
		t.Fatalf("ProbeFeatures: %v", err)
	}
	r, err := runtime.NewNative(filepath.Join(t.TempDir(), "state"), feat)
	if err != nil {
		t.Fatalf("NewNative: %v", err)
	}
	b, err := os.ReadFile(hullInit(t))
	if err != nil {
		t.Fatalf("read hull-init: %v", err)
	}
	if err := r.SetInitBinary(b); err != nil {
		t.Fatalf("SetInitBinary: %v", err)
	}
	return r
}

// baseSpec is the bundle these tests start from: the OCI defaults minus the
// cgroup view (the WSL 5.15 kernel delegates no v2 controllers) plus the
// standard device nodes.
func baseSpec(rootfs string, args ...string) *runtimespec.Spec {
	spec := runtimespec.DefaultSpec()
	spec.Root = &runtimespec.Root{Path: rootfs}
	spec.Process.Args = args
	spec.Process.Cwd = "/"
	spec.Hostname = "hull-cve"

	var mounts []runtimespec.Mount
	for _, m := range spec.Mounts {
		if m.Destination == "/sys/fs/cgroup" {
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

// dropMount removes a mount from the bundle, so a test can let the image's own
// version of that directory show through.
func dropMount(spec *runtimespec.Spec, dest string) {
	var out []runtimespec.Mount
	for _, m := range spec.Mounts {
		if m.Destination == dest {
			continue
		}
		out = append(out, m)
	}
	spec.Mounts = out
}

func writeBundle(t *testing.T, spec *runtimespec.Spec) string {
	t.Helper()
	dir := t.TempDir()
	b, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

type result struct {
	created   bool
	exitCode  int
	output    string
	createErr error
}

// run creates, starts and waits for one container, returning everything the
// test needs to judge it. A Create failure is a result, not a test failure:
// refusing to build the container is one of the two acceptable outcomes.
func run(t *testing.T, r *runtime.NativeRuntime, id string, spec *runtimespec.Spec,
	opts runtime.CreateOptions) result {
	t.Helper()
	bundle := writeBundle(t, spec)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var buf strings.Builder
	var mu sync.Mutex
	w := &lockedWriter{w: &buf, mu: &mu}
	if opts.Stdout == nil {
		opts.Stdout = w
	}
	if opts.Stderr == nil {
		opts.Stderr = w
	}

	if _, err := r.Create(ctx, id, bundle, opts); err != nil {
		return result{createErr: err}
	}
	t.Cleanup(func() { _ = r.Delete(context.Background(), id, true) })

	if err := r.Start(ctx, id); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		st, err := r.State(ctx, id)
		if err != nil {
			t.Fatalf("State: %v", err)
		}
		if st.Exited {
			mu.Lock()
			out := buf.String()
			mu.Unlock()
			return result{created: true, exitCode: st.ExitCode, output: out}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("container %s did not exit", id)
	return result{}
}

type lockedWriter struct {
	w  *strings.Builder
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// ---------- CVE-2019-5736: overwriting the runtime through /proc/self/exe ----------

// TestCVE2019_5736_InitBinaryIsNotWritable is the original runc breakout: the
// container is exec'd from the runtime's own binary, so a container that opens
// /proc/self/exe for writing overwrites the host's runc and owns every later
// container.
//
// hull's defence is structural: the binary a container is exec'd from is a
// sealed memfd holding hull-init, not the daemon, and the seals make it
// immutable even to hull itself.
func TestCVE2019_5736_InitBinaryIsNotWritable(t *testing.T) {
	requireRoot(t)
	rootfs := fixtureRootfs(t)
	r := newRuntime(t)

	// Every probe is written so that a refusal cannot abort the shell: an
	// "exec" redirection failure is fatal in POSIX sh, which would hide
	// everything after it.
	script := `
		# Each probe runs in a subshell: a redirection failure on a special
		# builtin is fatal to a POSIX shell, and an aborted shell would hide
		# every later probe behind a passing test.
		if ( echo owned > /proc/self/exe ) 2>/dev/null; then
			echo ESCAPED-WROTE-TO-EXE
		else
			echo write-refused
		fi
		if ( true > /proc/self/exe ) 2>/dev/null; then
			echo ESCAPED-TRUNCATED-EXE
		else
			echo truncate-refused
		fi
		if ( echo owned >> /proc/self/exe ) 2>/dev/null; then
			echo ESCAPED-APPENDED-EXE
		else
			echo append-refused
		fi
		# And it must not be the daemon: hull execs from an anonymous memfd.
		readlink /proc/self/exe
	`
	res := run(t, r, "cve20195736", baseSpec(rootfs, "/bin/sh", "-c", script), runtime.CreateOptions{})
	if res.createErr != nil {
		t.Fatalf("Create: %v", res.createErr)
	}
	if strings.Contains(res.output, "ESCAPED") {
		t.Fatalf("the container could write to /proc/self/exe:\n%s", res.output)
	}
	for _, want := range []string{"write-refused", "truncate-refused", "append-refused"} {
		if !strings.Contains(res.output, want) {
			t.Fatalf("expected %q in the output; every write to /proc/self/exe must be refused:\n%s",
				want, res.output)
		}
	}
	// After the final execve, /proc/self/exe is the container's own binary,
	// which is the point: the only executable a container can reach is one
	// from its own image. It must never be a host path.
	for _, forbidden := range []string{"hulld", "hull-init", "/usr/bin/crun", "/usr/bin/runc"} {
		if strings.Contains(res.output, forbidden) {
			t.Fatalf("the container was exec'd from %q, a host binary:\n%s", forbidden, res.output)
		}
	}
	if !strings.Contains(res.output, "busybox") {
		t.Errorf("expected /proc/self/exe to be the container's own binary:\n%s", res.output)
	}
}

// TestCVE2019_5736_InitStageRunsFromMemfd proves the structural claim
// directly: with the init annotation set, hull-init stays resident as the
// container's PID 1, so /proc/1/exe is visible from inside - and it names an
// anonymous memfd, not any file the container could open for writing.
func TestCVE2019_5736_InitStageRunsFromMemfd(t *testing.T) {
	requireRoot(t)
	rootfs := fixtureRootfs(t)
	r := newRuntime(t)

	probe := "readlink /proc/1/exe; " +
		"if ( echo owned > /proc/1/exe ) 2>/dev/null; then echo ESCAPED; else echo pid1-write-refused; fi"
	spec := baseSpec(rootfs, "/bin/sh", "-c", probe)
	if spec.Annotations == nil {
		spec.Annotations = map[string]string{}
	}
	spec.Annotations[runtime.AnnotationInit] = "true"

	res := run(t, r, "memfdinit", spec, runtime.CreateOptions{})
	if res.createErr != nil {
		t.Fatalf("Create: %v", res.createErr)
	}
	if strings.Contains(res.output, "ESCAPED") {
		t.Fatalf("the container wrote to PID 1's executable:\n%s", res.output)
	}
	if !strings.Contains(res.output, "memfd") {
		t.Fatalf("PID 1's executable is not a memfd; hull must never exec a container "+
			"from a file on disk:\n%s", res.output)
	}
	if !strings.Contains(res.output, "pid1-write-refused") {
		t.Fatalf("the write probe did not run:\n%s", res.output)
	}
	// The reaper must still relay the entrypoint's exit status.
	if res.exitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.exitCode)
	}
}

// TestCVE2019_5736_HostBinaryUnchanged proves the host-side half: whatever the
// container did, the hull-init image on disk is byte-identical afterwards.
func TestCVE2019_5736_HostBinaryUnchanged(t *testing.T) {
	requireRoot(t)
	rootfs := fixtureRootfs(t)
	initBin := hullInit(t)
	before, err := os.ReadFile(initBin)
	if err != nil {
		t.Fatal(err)
	}
	r := newRuntime(t)

	script := `
		for target in /proc/self/exe /proc/1/exe /proc/self/root/proc/self/exe; do
			echo "x" > "$target" 2>/dev/null && echo "WROTE $target"
		done
		echo done
	`
	res := run(t, r, "cve20195736b", baseSpec(rootfs, "/bin/sh", "-c", script), runtime.CreateOptions{})
	if res.createErr != nil {
		t.Fatalf("Create: %v", res.createErr)
	}
	if strings.Contains(res.output, "WROTE") {
		t.Fatalf("a write to an exe link succeeded:\n%s", res.output)
	}
	after, err := os.ReadFile(initBin)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the hull-init binary on disk changed while a container ran")
	}
}

// TestSealedMemfdCannotBeReopenedWritable checks the seal set directly, so a
// regression in SealedMemfd is caught even without a container.
func TestSealedMemfdCannotBeReopenedWritable(t *testing.T) {
	f, err := initspec.SealedMemfd("hull-init", []byte("\x7fELFxxxx"))
	if err != nil {
		t.Fatalf("SealedMemfd: %v", err)
	}
	defer f.Close()
	seals, err := initspec.MemfdSeals(f.Fd())
	if err != nil {
		t.Fatalf("MemfdSeals: %v", err)
	}
	if seals != initspec.AllSeals {
		t.Fatalf("seals = %#x, want %#x (F_SEAL_SEAL|SHRINK|GROW|WRITE)", seals, initspec.AllSeals)
	}
	if _, err := f.WriteAt([]byte("owned"), 0); err == nil {
		t.Fatal("the sealed memfd accepted a write")
	}
	// The kernel allows a write-sealed memfd to be *opened* O_WRONLY; the
	// seal is enforced on the write itself. That is what must fail, because
	// reopening through /proc/self/fd is exactly how CVE-2019-5736 turned a
	// read-only handle into a writable one.
	if w, oerr := os.OpenFile(initspec.ProcFD(int(f.Fd())), os.O_WRONLY, 0); oerr == nil {
		defer w.Close()
		if _, werr := w.Write([]byte("owned")); werr == nil {
			t.Fatal("a write through a reopened handle succeeded; F_SEAL_WRITE is not in force")
		}
	}
}

// ---------- CVE-2024-21626: a leaked file descriptor as the working directory ----------

// TestCVE2024_21626_NoLeakedDescriptors is the "leaky vessels" breakout: runc
// left an open directory descriptor on the host filesystem inherited into the
// container, and a container whose working directory was /proc/self/fd/<n>
// started life with its cwd on the host.
//
// hull closes every descriptor above stderr with close_range(2) immediately
// before execve, so there is nothing for such a cwd to name.
func TestCVE2024_21626_NoLeakedDescriptors(t *testing.T) {
	requireRoot(t)
	rootfs := fixtureRootfs(t)
	r := newRuntime(t)

	// Deliberately hand the runtime a directory descriptor on the host root.
	// A driver that forwarded ExtraFiles into the container would be handing
	// the container a way out; hull must close it.
	hostRoot, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer hostRoot.Close()

	t.Run("nothing above stderr survives", func(t *testing.T) {
		// The entrypoint is a single busybox applet, so the descriptor set
		// is deterministic: 0, 1, 2 and the one ls opens to read the
		// directory. Anything else came from hull.
		res := run(t, r, "fdscan", baseSpec(rootfs, "/bin/ls", "-l", "/proc/self/fd"),
			runtime.CreateOptions{ExtraFiles: []*os.File{hostRoot}})
		if res.createErr != nil {
			t.Fatalf("Create: %v", res.createErr)
		}
		var leaked []string
		for _, line := range strings.Split(res.output, "\n") {
			name, target, ok := strings.Cut(line, " -> ")
			if !ok {
				// ls prints a diagnostic rather than a link for its own
				// directory handle, which it has already closed.
				continue
			}
			fields := strings.Fields(name)
			if len(fields) == 0 {
				continue
			}
			fd := fields[len(fields)-1]
			n, cerr := strconv.Atoi(fd)
			if cerr != nil || n < 3 {
				continue
			}
			target = strings.TrimSpace(target)
			if strings.HasSuffix(target, "/fd") {
				continue // ls's own handle on the directory it is listing
			}
			leaked = append(leaked, fd+" -> "+target)
		}
		if len(leaked) > 0 {
			t.Fatalf("descriptors above stderr survived into the container: %v\n%s",
				leaked, res.output)
		}
	})

	t.Run("nothing survives the PID 1 supervisor either", func(t *testing.T) {
		// The init path cannot use close_range - the Go runtime is still
		// running - so it closes the handshake descriptors and re-arms
		// close-on-exec instead. The entrypoint must see the same thing.
		spec := baseSpec(rootfs, "/bin/ls", "-l", "/proc/self/fd")
		if spec.Annotations == nil {
			spec.Annotations = map[string]string{}
		}
		spec.Annotations[runtime.AnnotationInit] = "true"
		res := run(t, r, "fdscaninit", spec,
			runtime.CreateOptions{ExtraFiles: []*os.File{hostRoot}})
		if res.createErr != nil {
			t.Fatalf("Create: %v", res.createErr)
		}
		for _, line := range strings.Split(res.output, "\n") {
			name, target, ok := strings.Cut(line, " -> ")
			if !ok {
				continue
			}
			fields := strings.Fields(name)
			if len(fields) == 0 {
				continue
			}
			n, cerr := strconv.Atoi(fields[len(fields)-1])
			if cerr != nil || n < 3 {
				continue
			}
			if strings.HasSuffix(strings.TrimSpace(target), "/fd") {
				continue
			}
			t.Fatalf("fd %d survived the supervisor: %s\n%s", n, target, res.output)
		}
	})

	t.Run("no descriptor path reaches the host", func(t *testing.T) {
		script := `
			for n in 3 4 5 6 7 8 9 10 11 12; do
				p=/proc/$$/fd/$n
				[ -e "$p" ] || continue
				if cd "$p" 2>/dev/null; then
					if [ -e /etc/shadow ] && ! [ -e /.hull-marker ]; then
						echo "ESCAPED via fd $n"
					fi
				fi
			done
			echo exploit-done
		`
		res := run(t, r, "fdexploit", baseSpec(rootfs, "/bin/sh", "-c", script),
			runtime.CreateOptions{ExtraFiles: []*os.File{hostRoot}})
		if res.createErr != nil {
			t.Fatalf("Create: %v", res.createErr)
		}
		if strings.Contains(res.output, "ESCAPED") {
			t.Fatalf("a leaked descriptor gave the container a path out:\n%s", res.output)
		}
		if !strings.Contains(res.output, "exploit-done") {
			t.Fatalf("the probe did not run to completion:\n%s", res.output)
		}
	})
}

// TestCVE2024_21626_CwdOnLeakedFDIsRefused checks the other half: a bundle
// whose process.cwd names a descriptor path must be refused rather than
// silently landing somewhere useful to the attacker.
func TestCVE2024_21626_CwdOnLeakedFDIsRefused(t *testing.T) {
	requireRoot(t)
	rootfs := fixtureRootfs(t)
	r := newRuntime(t)

	spec := baseSpec(rootfs, "/bin/sh", "-c", "pwd; ls /etc/shadow 2>/dev/null && echo ESCAPED")
	spec.Process.Cwd = "/proc/self/fd/7"
	res := run(t, r, "cve202421626b", spec, runtime.CreateOptions{})
	if res.createErr != nil {
		// Refusing the container is the preferred outcome.
		if !strings.Contains(res.createErr.Error(), "working directory") &&
			!strings.Contains(res.createErr.Error(), "no such file") {
			t.Fatalf("Create failed for an unexpected reason: %v", res.createErr)
		}
		return
	}
	if strings.Contains(res.output, "ESCAPED") {
		t.Fatalf("the container started on the host filesystem:\n%s", res.output)
	}
	if !strings.Contains(res.output, "/") {
		t.Fatalf("unexpected output:\n%s", res.output)
	}
}

// ---------- CVE-2025-31133 / 52565 / 52881: device and console path swaps ----------

// TestCVE2025_31133_DevNullSwappedForSymlink models the 2025 runc family: the
// runtime masks a path by bind-mounting /dev/null over it, and resolves
// /dev/null *by path* inside a rootfs the image controls. An image that ships
// /dev/null as a symlink to something else turns the mask into a mount of the
// attacker's choosing.
//
// hull opens /dev/null fd-relative inside the container root and confirms with
// fstat that it is character device 1:3 before it is used as a mount source,
// so a swapped /dev/null makes the container fail to start.
func TestCVE2025_31133_DevNullSwappedForSymlink(t *testing.T) {
	requireRoot(t)
	rootfs := fixtureRootfs(t)
	r := newRuntime(t)

	// A malicious image: /dev is the image's own (no tmpfs over it) and
	// /dev/null is a symlink to a file the attacker wants mounted.
	bait := filepath.Join(rootfs, "bait")
	if err := os.WriteFile(bait, []byte("attacker-controlled\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	devDir := filepath.Join(rootfs, "dev")
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(devDir, "null"))
	if err := os.Symlink("/bait", filepath.Join(devDir, "null")); err != nil {
		t.Fatal(err)
	}

	spec := baseSpec(rootfs, "/bin/sh", "-c", "cat /proc/kcore | head -c 32; echo READ-MASKED")
	// Let the image's own /dev show through, and do not recreate the node.
	dropMount(spec, "/dev")
	dropMount(spec, "/dev/pts")
	dropMount(spec, "/dev/shm")
	dropMount(spec, "/dev/mqueue")
	spec.Linux.Devices = nil
	// A masked *file* is what forces the runtime to reach for /dev/null.
	spec.Linux.MaskedPaths = []string{"/proc/kcore"}

	res := run(t, r, "cve202531133", spec, runtime.CreateOptions{})
	if res.createErr != nil {
		if !strings.Contains(res.createErr.Error(), "character device") &&
			!strings.Contains(res.createErr.Error(), "/dev/null") {
			t.Fatalf("Create failed, but not because the device check caught it: %v", res.createErr)
		}
		return // refused, which is the correct outcome
	}
	if strings.Contains(res.output, "attacker-controlled") {
		t.Fatalf("the swapped /dev/null was mounted over the masked path:\n%s", res.output)
	}
	t.Fatalf("the container started with a symlinked /dev/null; hull must refuse it.\noutput: %s", res.output)
}

// TestDevNullVerificationRejectsNonDevices exercises the same check directly,
// so a regression is caught without needing a container.
func TestDevNullVerificationRejectsNonDevices(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "not-a-device"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := initspec.VerifyCharDevice(int(f.Fd()), 1, 3); err == nil {
		t.Fatal("VerifyCharDevice accepted a regular file as /dev/null")
	}
	if err := initspec.VerifyConsoleFD(int(f.Fd())); err == nil {
		t.Fatal("VerifyConsoleFD accepted a regular file as a console")
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Skip("no /dev/null")
	}
	defer null.Close()
	if err := initspec.VerifyCharDevice(int(null.Fd()), 1, 3); err != nil {
		t.Fatalf("VerifyCharDevice rejected the real /dev/null: %v", err)
	}
	// The real /dev/null is a character device but not a terminal, so it
	// must still be refused as a console.
	if err := initspec.VerifyConsoleFD(int(null.Fd())); err == nil {
		t.Fatal("VerifyConsoleFD accepted /dev/null as a console")
	}
}

// ---------- CVE-2019-16884 / CVE-2021-30465: symlink swaps on mount targets ----------

// TestMountTargetSymlinkCannotEscape models the mount-target races: an image
// whose mount destination is a symlink pointing at a host path. hull resolves
// every destination with openat2(RESOLVE_IN_ROOT), so the symlink resolves
// inside the container and the host directory is untouched.
func TestMountTargetSymlinkCannotEscape(t *testing.T) {
	requireRoot(t)
	rootfs := fixtureRootfs(t)
	r := newRuntime(t)

	// A directory on the host the image would like something mounted over.
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(victim, "canary")
	if err := os.WriteFile(canary, []byte("host-file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The image ships /target as an absolute symlink to that host path.
	if err := os.Symlink(victim, filepath.Join(rootfs, "target")); err != nil {
		t.Fatal(err)
	}

	spec := baseSpec(rootfs, "/bin/sh", "-c", "mount | grep -c ' /target ' || true; ls /target")
	spec.Mounts = append(spec.Mounts, runtimespec.Mount{
		Destination: "/target",
		Type:        "tmpfs",
		Source:      "tmpfs",
		Options:     []string{"nosuid", "nodev", "mode=0755", "size=1m"},
	})
	res := run(t, r, "mounttarget", spec, runtime.CreateOptions{})
	if res.createErr != nil {
		// Refusing is acceptable: the re-rooted destination does not exist.
		t.Logf("Create refused the container: %v", res.createErr)
	}
	// Whatever happened inside, the host directory must be untouched.
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("the host canary file is gone; a mount landed on the host: %v", err)
	}
	entries, err := os.ReadDir(victim)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "canary" {
		t.Fatalf("the host victim directory changed: %v", entries)
	}
}

// ---------- confinement invariants ----------

// TestNoNewPrivsAndSeccompAreLive checks the two settings the whole security
// model rests on, from inside a running container.
func TestNoNewPrivsAndSeccompAreLive(t *testing.T) {
	requireRoot(t)
	rootfs := fixtureRootfs(t)
	r := newRuntime(t)

	errno := uint(7) // E2BIG, distinctive enough to attribute to the filter
	spec := baseSpec(rootfs, "/bin/sh", "-c", "grep -E 'NoNewPrivs|Seccomp:' /proc/self/status; mkdir /tmp/probe; echo mkdir=$?")
	spec.Process.NoNewPrivileges = true
	spec.Linux.Seccomp = &runtimespec.LinuxSeccomp{
		DefaultAction: runtimespec.ActAllow,
		Architectures: []runtimespec.Arch{runtimespec.ArchX86_64, runtimespec.ArchAARCH64},
		Syscalls: []runtimespec.LinuxSyscall{
			{Names: []string{"mkdir", "mkdirat"}, Action: runtimespec.ActErrno, ErrnoRet: &errno},
		},
	}
	res := run(t, r, "confinement", spec, runtime.CreateOptions{})
	if res.createErr != nil {
		t.Fatalf("Create: %v", res.createErr)
	}
	if !strings.Contains(res.output, "NoNewPrivs:\t1") {
		t.Errorf("no_new_privs is not set inside the container:\n%s", res.output)
	}
	// Seccomp mode 2 is SECCOMP_MODE_FILTER.
	if !strings.Contains(res.output, "Seccomp:\t2") {
		t.Errorf("no seccomp filter is loaded inside the container:\n%s", res.output)
	}
	if strings.Contains(res.output, "mkdir=0") {
		t.Errorf("the seccomp filter did not deny mkdir:\n%s", res.output)
	}
}

// TestContainerCannotSeeHostProcesses confirms the pid namespace really is
// new: a container that can see host pids can signal them.
func TestContainerCannotSeeHostProcesses(t *testing.T) {
	requireRoot(t)
	rootfs := fixtureRootfs(t)
	r := newRuntime(t)

	res := run(t, r, "pidns", baseSpec(rootfs, "/bin/sh", "-c",
		"ls /proc | grep -E '^[0-9]+$' | wc -l; cat /proc/1/comm"), runtime.CreateOptions{})
	if res.createErr != nil {
		t.Fatalf("Create: %v", res.createErr)
	}
	fields := strings.Fields(res.output)
	if len(fields) == 0 {
		t.Fatalf("no output:\n%s", res.output)
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatalf("unexpected output %q", res.output)
	}
	if n > 4 {
		t.Fatalf("the container can see %d processes; /proc is not the container's own:\n%s", n, res.output)
	}
}

// TestContainerRootIsTheBundleRoot confirms pivot_root actually happened and
// the old root was detached, not merely chrooted away from.
func TestContainerRootIsTheBundleRoot(t *testing.T) {
	requireRoot(t)
	rootfs := fixtureRootfs(t)
	r := newRuntime(t)

	script := `
		cat /.hull-marker
		# The old root must be gone, not just moved aside.
		ls -a / | grep -c hull-put-old || true
		# Nothing outside the container may be reachable.
		[ -e /etc/shadow ] && echo HOST-SHADOW-VISIBLE
		echo checks-done
	`
	res := run(t, r, "pivot", baseSpec(rootfs, "/bin/sh", "-c", script), runtime.CreateOptions{})
	if res.createErr != nil {
		t.Fatalf("Create: %v", res.createErr)
	}
	if !strings.Contains(res.output, "hull-test-rootfs") {
		t.Fatalf("the container is not in the bundle root:\n%s", res.output)
	}
	if strings.Contains(res.output, "HOST-SHADOW-VISIBLE") {
		t.Fatalf("the host filesystem is visible inside the container:\n%s", res.output)
	}
	if !strings.Contains(res.output, "checks-done") {
		t.Fatalf("the probe did not finish:\n%s", res.output)
	}
	// The put_old directory must not survive.
	if _, err := os.Stat(filepath.Join(rootfs, initspec.PutOldName)); err == nil {
		t.Fatalf("%s was left behind in the container root", initspec.PutOldName)
	}
}

// TestSeccompProfileTooLargeIsRefused checks hull fails a container at create
// time with an actionable message rather than letting the kernel reject the
// filter with a bare EINVAL after the container has been half built.
func TestSeccompProfileTooLargeIsRefused(t *testing.T) {
	args := make([]runtimespec.LinuxSeccompArg, 6)
	for i := range args {
		args[i] = runtimespec.LinuxSeccompArg{Index: uint(i), Value: 1, Op: runtimespec.OpEqualTo}
	}
	var rules []runtimespec.LinuxSyscall
	for i := 0; i < 400; i++ {
		rules = append(rules, runtimespec.LinuxSyscall{
			Names:  []string{"read", "write", "openat", "close"},
			Action: runtimespec.ActAllow,
			Args:   args,
		})
	}
	_, err := initspec.CompileSeccomp(&runtimespec.LinuxSeccomp{
		DefaultAction: runtimespec.ActErrno,
		Architectures: []runtimespec.Arch{runtimespec.ArchX86_64},
		Syscalls:      rules,
	})
	if err == nil {
		t.Fatal("an oversized profile compiled")
	}
	if !strings.Contains(err.Error(), "4096") {
		t.Fatalf("the error should name BPF_MAXINSNS: %v", err)
	}
}
