package initspec

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

// helperEnv names the environment variable that turns the test binary into a
// helper. Some of what initspec does - closing every descriptor, installing a
// seccomp filter, setting no_new_privs - is irreversible, so it cannot be
// exercised inside the test process itself.
const helperEnv = "HULL_INITSPEC_HELPER"

// TestMain dispatches helper invocations before the normal test run.
func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(m.Run())
	case "fdsanitize":
		os.Exit(helperFDSanitize())
	case "nnp-then-seccomp":
		os.Exit(helperNoNewPrivsThenSeccomp())
	case "seccomp-without-nnp":
		os.Exit(helperSeccompWithoutNoNewPrivs())
	default:
		fmt.Fprintf(os.Stderr, "unknown helper %q\n", os.Getenv(helperEnv))
		os.Exit(2)
	}
}

// runHelper re-runs the test binary in helper mode and returns its combined
// output.
func runHelper(t *testing.T, mode string, extra ...string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locate the test binary: %v", err)
	}
	cmd := exec.Command(exe, extra...)
	cmd.Env = append(os.Environ(), helperEnv+"="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper %s failed: %v\n%s", mode, err, out)
	}
	return string(out)
}

// runHelperExpectFail is runHelper for a helper that is meant to fail.
func runHelperExpectFail(t *testing.T, mode string) (string, error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locate the test binary: %v", err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), helperEnv+"="+mode)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// helperFDSanitize opens a handful of descriptors, sanitises, and reports what
// is left. Anything above stderr that was not explicitly kept is a leak into
// the container (CVE-2024-21626).
func helperFDSanitize() int {
	var keep []int
	// Open five descriptors; keep the second and the fourth.
	var opened []*os.File
	for i := 0; i < 5; i++ {
		f, err := os.Open(os.DevNull)
		if err != nil {
			fmt.Printf("open: %v\n", err)
			return 1
		}
		opened = append(opened, f)
	}
	keep = append(keep, int(opened[1].Fd()), int(opened[3].Fd()))

	// A directory descriptor on "/" is the classic leak: with it, a
	// container walks out through /proc/self/fd/<n>.
	leak, err := os.Open("/")
	if err != nil {
		fmt.Printf("open /: %v\n", err)
		return 1
	}
	leakFD := int(leak.Fd())

	if err := SanitizeFDs(keep...); err != nil {
		fmt.Printf("SanitizeFDs: %v\n", err)
		return 1
	}

	live := liveFDs()
	for _, fd := range keep {
		if !contains(live, fd) {
			fmt.Printf("kept fd %d was closed; live=%v\n", fd, live)
			return 1
		}
	}
	if contains(live, leakFD) {
		fmt.Printf("leaked directory fd %d survived SanitizeFDs; live=%v\n", leakFD, live)
		return 1
	}
	for _, fd := range live {
		if fd < 3 {
			continue
		}
		if !contains(keep, fd) {
			fmt.Printf("unexpected fd %d survived; live=%v keep=%v\n", fd, live, keep)
			return 1
		}
	}

	// Now close everything: after this nothing above stderr may remain.
	if err := CloseRangeFrom(3); err != nil {
		fmt.Printf("CloseRangeFrom: %v\n", err)
		return 1
	}
	for _, fd := range liveFDs() {
		if fd >= 3 {
			fmt.Printf("fd %d survived CloseRangeFrom(3)\n", fd)
			return 1
		}
	}
	fmt.Println("OK")
	return 0
}

// helperNoNewPrivsThenSeccomp does it in the right order and then proves the
// filter is live by making a syscall the filter denies.
func helperNoNewPrivsThenSeccomp() int {
	if !SeccompSupported() {
		fmt.Println("SKIP: no seccomp")
		return 0
	}
	tg, ok := NativeTarget()
	if !ok {
		fmt.Println("SKIP: no syscall table for this architecture")
		return 0
	}
	// Allow everything, but make mkdir fail with a distinctive errno so the
	// test can tell the filter apart from a real failure.
	prog, err := CompileSeccompFor(seccompAllowExcept("mkdirat", 7 /* E2BIG */), tg)
	if err != nil {
		fmt.Printf("compile: %v\n", err)
		return 1
	}
	if err := SetNoNewPrivs(); err != nil {
		fmt.Printf("SetNoNewPrivs: %v\n", err)
		return 1
	}
	if err := prog.Install(); err != nil {
		fmt.Printf("Install: %v\n", err)
		return 1
	}
	err = unix.Mkdirat(unix.AT_FDCWD, "/tmp/hull-seccomp-probe", 0o700)
	if err != unix.E2BIG {
		fmt.Printf("mkdirat returned %v, want E2BIG from the filter\n", err)
		return 1
	}
	nnp, perr := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if perr != nil || nnp != 1 {
		fmt.Printf("no_new_privs = %d (%v)\n", nnp, perr)
		return 1
	}
	fmt.Println("OK")
	return 0
}

// helperSeccompWithoutNoNewPrivs must be refused: a filter installed without
// no_new_privs can be escaped through a setuid binary.
func helperSeccompWithoutNoNewPrivs() int {
	tg, ok := NativeTarget()
	if !ok {
		fmt.Println("SKIP: no syscall table for this architecture")
		return 0
	}
	prog, err := CompileSeccompFor(seccompAllowExcept("mkdirat", 7), tg)
	if err != nil {
		fmt.Printf("compile: %v\n", err)
		return 1
	}
	if err := prog.Install(); err == nil {
		fmt.Println("Install succeeded without no_new_privs")
		return 1
	} else if !strings.Contains(err.Error(), "no_new_privs") {
		fmt.Printf("Install failed for the wrong reason: %v\n", err)
		return 1
	}
	fmt.Println("OK")
	return 0
}

func liveFDs() []int {
	d, err := os.Open("/proc/self/fd")
	if err != nil {
		return nil
	}
	self := int(d.Fd())
	names, _ := d.Readdirnames(-1)
	d.Close()
	var out []int
	for _, n := range names {
		v, err := strconv.Atoi(n)
		if err != nil || v == self {
			continue
		}
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestNoNewPrivsBeforeSeccomp is the security-critical ordering test: the
// filter must install after no_new_privs and must refuse to install before it.
func TestNoNewPrivsBeforeSeccomp(t *testing.T) {
	out := runHelper(t, "nnp-then-seccomp")
	if !strings.Contains(out, "OK") && !strings.Contains(out, "SKIP") {
		t.Fatalf("helper said: %s", out)
	}
	out = runHelper(t, "seccomp-without-nnp")
	if !strings.Contains(out, "OK") && !strings.Contains(out, "SKIP") {
		t.Fatalf("helper said: %s", out)
	}
}

// seccompAllowExcept builds a profile that allows everything except one
// syscall, which fails with a distinctive errno.
func seccompAllowExcept(name string, errno uint) *runtimespec.LinuxSeccomp {
	return &runtimespec.LinuxSeccomp{
		DefaultAction: runtimespec.ActAllow,
		Architectures: []runtimespec.Arch{runtimespec.ArchX86_64, runtimespec.ArchAARCH64},
		Syscalls: []runtimespec.LinuxSyscall{
			{Names: []string{name}, Action: runtimespec.ActErrno, ErrnoRet: &errno},
		},
	}
}
