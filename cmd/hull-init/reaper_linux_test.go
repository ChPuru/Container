package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/runtime/initspec"
)

// helperEnv turns the test binary into one of the helpers below. The reaper
// can only be exercised in a process that owns its own children, which the
// test runner does not.
const helperEnv = "HULL_INIT_TEST_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(m.Run())
	case "supervise":
		os.Exit(runPID1(os.Args[1:]))
	case "orphans":
		os.Exit(helperOrphans())
	default:
		fmt.Fprintf(os.Stderr, "unknown helper %q\n", os.Getenv(helperEnv))
		os.Exit(2)
	}
}

func helperCmd(t *testing.T, mode string, args ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locate the test binary: %v", err)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), helperEnv+"="+mode)
	return cmd
}

func shell(t *testing.T) string {
	t.Helper()
	for _, c := range []string{"/bin/sh", "/usr/bin/sh"} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("no /bin/sh")
	return ""
}

// TestSuperviseExitStatus checks the status relay: hull-init must exit with
// exactly what the container's entrypoint exited with, including the 128+N
// convention for a signalled process, because that is what Docker records and
// what a shell reports.
func TestSuperviseExitStatus(t *testing.T) {
	sh := shell(t)
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "exit 0", args: []string{sh, "-c", "exit 0"}, want: 0},
		{name: "exit 42", args: []string{sh, "-c", "exit 42"}, want: 42},
		{name: "exit 255", args: []string{sh, "-c", "exit 255"}, want: 255},
		{name: "killed by SIGKILL", args: []string{sh, "-c", "kill -9 $$"}, want: 137},
		{name: "killed by SIGQUIT", args: []string{sh, "-c", "kill -QUIT $$"}, want: 131},
		{name: "not a command", args: []string{"hull-no-such-binary"}, want: 127},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := helperCmd(t, "supervise", tc.args...)
			out, err := cmd.CombinedOutput()
			got := cmd.ProcessState.ExitCode()
			if got != tc.want {
				t.Fatalf("exit code = %d, want %d (err %v, output %q)", got, tc.want, err, out)
			}
		})
	}
}

// TestSuperviseForwardsSignals proves the other half of a container init's
// job: a signal sent to PID 1 has no default action, so unless init forwards
// it the entrypoint can only ever be SIGKILLed.
func TestSuperviseForwardsSignals(t *testing.T) {
	sh := shell(t)
	tests := []struct {
		name string
		sig  syscall.Signal
		trap string
		want int
	}{
		{name: "SIGTERM is forwarded", sig: unix.SIGTERM, trap: "TERM", want: 42},
		{name: "SIGINT is forwarded", sig: unix.SIGINT, trap: "INT", want: 43},
		{name: "SIGHUP is forwarded", sig: unix.SIGHUP, trap: "HUP", want: 44},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			script := fmt.Sprintf("trap 'exit %d' %s; echo ready; while :; do sleep 0.05; done",
				tc.want, tc.trap)
			cmd := helperCmd(t, "supervise", sh, "-c", script)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			// Wait until the trap is installed before signalling.
			buf := make([]byte, 16)
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				n, rerr := stdout.Read(buf)
				if n > 0 && strings.Contains(string(buf[:n]), "ready") {
					break
				}
				if rerr != nil {
					break
				}
			}
			if err := cmd.Process.Signal(tc.sig); err != nil {
				t.Fatalf("signal the supervisor: %v", err)
			}
			_ = cmd.Wait()
			if got := cmd.ProcessState.ExitCode(); got != tc.want {
				t.Fatalf("exit code = %d, want %d - signal %d was not forwarded to the child",
					got, tc.want, tc.sig)
			}
			_ = i
		})
	}
}

// helperOrphans proves the reaper really does adopt and reap processes that
// are not its own children. It makes itself a child subreaper, which is what
// being PID 1 of a pid namespace does for free, then orphans three processes
// and checks they are collected.
func helperOrphans() int {
	sh := "/bin/sh"
	if _, err := os.Stat(sh); err != nil {
		fmt.Println("SKIP: no /bin/sh")
		return 0
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		fmt.Printf("SKIP: no PR_SET_CHILD_SUBREAPER: %v\n", err)
		return 0
	}

	sigs := make(chan os.Signal, 32)
	signal.Notify(sigs, unix.SIGCHLD)

	// The shell exits at once, orphaning three sleepers onto this process.
	pid, err := syscall.ForkExec(sh, []string{sh, "-c",
		"(sleep 0.3)& (sleep 0.3)& (sleep 0.3)& exit 5"},
		&syscall.ProcAttr{Env: os.Environ(), Files: []uintptr{0, 1, 2}, Sys: &syscall.SysProcAttr{Setpgid: true}})
	if err != nil {
		fmt.Printf("fork: %v\n", err)
		return 1
	}

	// Collect the direct child first, exactly as supervise does.
	code := -1
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && code < 0 {
		select {
		case <-sigs:
		case <-time.After(100 * time.Millisecond):
		}
		if done, c := reap(pid); done {
			code = c
		}
	}
	if code != 5 {
		fmt.Printf("direct child exit code = %d, want 5\n", code)
		return 1
	}

	// Let the orphans finish, then confirm they really did reparent here
	// before reapAll collects them.
	time.Sleep(700 * time.Millisecond)
	zombies := countZombieChildren()
	if err := reapAll(); err != nil {
		fmt.Printf("reapAll: %v\n", err)
		return 1
	}
	var ws unix.WaitStatus
	_, werr := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
	if werr != unix.ECHILD {
		fmt.Printf("after reapAll, wait4 returned %v, want ECHILD - something was left unreaped\n", werr)
		return 1
	}
	fmt.Printf("orphans=%d OK\n", zombies)
	return 0
}

// countZombieChildren counts the processes in state Z whose parent is this
// process.
func countZombieChildren() int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return -1
	}
	self := os.Getpid()
	n := 0
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// The comm field can contain spaces and parentheses, so parse
		// from the last ')'.
		i := strings.LastIndexByte(string(b), ')')
		if i < 0 {
			continue
		}
		fields := strings.Fields(string(b)[i+1:])
		if len(fields) < 2 {
			continue
		}
		state, ppid := fields[0], fields[1]
		if state == "Z" && ppid == strconv.Itoa(self) && pid != self {
			n++
		}
	}
	return n
}

// TestReaperAdoptsOrphans is the zombie test: processes whose parent died are
// reparented onto the container's init and must be collected, or the pid
// namespace fills up with zombies until it hits pids.max.
func TestReaperAdoptsOrphans(t *testing.T) {
	cmd := helperCmd(t, "orphans")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	s := string(out)
	if strings.Contains(s, "SKIP") {
		t.Skip(strings.TrimSpace(s))
	}
	if !strings.Contains(s, "OK") {
		t.Fatalf("helper said: %s", s)
	}
	if !strings.Contains(s, "orphans=3") {
		t.Errorf("expected three adopted orphans, helper said: %s", strings.TrimSpace(s))
	}
}

func TestStripStageFlag(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "nothing to strip", in: []string{"/bin/sh", "-c", "true"}, want: []string{"/bin/sh", "-c", "true"}},
		{
			name: "the stage flag is removed",
			in:   []string{initspec.StageFlagPrefix + "pid1", "/bin/sh"},
			want: []string{"/bin/sh"},
		},
		{name: "empty", in: nil, want: []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stripStageFlag(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestRunPID1WithNoCommand checks the usage path rather than leaving it to
// fail obscurely at execve.
func TestRunPID1WithNoCommand(t *testing.T) {
	cmd := helperCmd(t, "supervise")
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 127 {
		t.Fatalf("exit code = %d, want 127", cmd.ProcessState.ExitCode())
	}
	if !strings.Contains(string(out), "nothing to run") {
		t.Errorf("output = %q, want a usage message", out)
	}
}
