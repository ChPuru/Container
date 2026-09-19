package debugshell

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahuldhali/hull/internal/explain"
)

func TestNamespaceFlags(t *testing.T) {
	tests := []struct {
		name  string
		in    []string
		want  int
		fails bool
	}{
		{
			name: "default set",
			in:   nil,
			want: unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS,
		},
		{name: "net alias", in: []string{"net"}, want: unix.CLONE_NEWNET},
		{name: "network spelled out", in: []string{"network"}, want: unix.CLONE_NEWNET},
		{name: "pid only", in: []string{"pid"}, want: unix.CLONE_NEWPID},
		{name: "ipc and uts", in: []string{"ipc", "uts"}, want: unix.CLONE_NEWIPC | unix.CLONE_NEWUTS},
		{name: "cgroup", in: []string{"cgroup"}, want: unix.CLONE_NEWCGROUP},
		{name: "time", in: []string{"time"}, want: unix.CLONE_NEWTIME},
		{name: "duplicates fold", in: []string{"net", "network", "NET"}, want: unix.CLONE_NEWNET},
		{name: "mount refused", in: []string{"mount"}, fails: true},
		{name: "user refused", in: []string{"user"}, fails: true},
		{name: "unknown refused", in: []string{"widget"}, fails: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NamespaceFlags(tc.in)
			if tc.fails {
				if err == nil {
					t.Fatalf("want an error, got %#x", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("NamespaceFlags(%q) = %#x, want %#x", tc.in, got, tc.want)
			}
			// The flags must never contain the two kinds Attach refuses,
			// whatever the caller asked for.
			if got&(unix.CLONE_NEWNS|unix.CLONE_NEWUSER) != 0 {
				t.Errorf("NamespaceFlags(%q) = %#x, which includes NEWNS or NEWUSER", tc.in, got)
			}
		})
	}
}

func TestNamespaceFlagsMatchTheTraceRendering(t *testing.T) {
	// The banner and the trace render the same set the kernel is handed, so a
	// reader can check one against the other.
	o, err := Options{ContainerID: "c1", DataRoot: t.TempDir()}.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	flags, err := NamespaceFlags(o.Namespaces)
	if err != nil {
		t.Fatalf("NamespaceFlags: %v", err)
	}
	rendered := explain.CloneFlags(o.Namespaces...)
	for name, flag := range map[string]int{
		"CLONE_NEWPID": unix.CLONE_NEWPID,
		"CLONE_NEWNET": unix.CLONE_NEWNET,
		"CLONE_NEWIPC": unix.CLONE_NEWIPC,
		"CLONE_NEWUTS": unix.CLONE_NEWUTS,
	} {
		if strings.Contains(rendered, name) != (flags&flag != 0) {
			t.Errorf("%s: rendered %q but flags %#x", name, rendered, flags)
		}
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct{ in, want string }{
		{in: "", want: "''"},
		{in: "plain", want: "'plain'"},
		{in: "two words", want: "'two words'"},
		{in: "it's", want: `'it'\''s'`},
		{in: "a\nb", want: "'a\nb'"},
		{in: "$PATH `id`", want: "'$PATH `id`'"},
	}
	for _, tc := range tests {
		if got := shellQuote(tc.in); got != tc.want {
			t.Errorf("shellQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestArgv(t *testing.T) {
	base := Options{ContainerID: "abcdef0123456789", DataRoot: t.TempDir(), ToolboxMount: "/tools"}

	o, err := base.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	argv := o.argv(4812)
	if argv[0] != "/tools/bin/sh" {
		t.Errorf("argv[0] = %q, want the toolbox shell", argv[0])
	}
	if argv[1] != "-c" {
		t.Errorf("argv[1] = %q, want -c", argv[1])
	}
	if argv[3] != "hull-debug" {
		t.Errorf("argv[3] = %q, want the $0 placeholder", argv[3])
	}
	if want := "/tools/bin/sh"; argv[4] != want {
		t.Errorf("argv[4] = %q, want the default command %q", argv[4], want)
	}
	prelude := argv[2]
	for _, want := range []string{
		"mount -t proc -o nosuid,nodev,noexec proc /proc",
		"printf '%s'",
		"/proc/1/root",
		`exec "$@"`,
	} {
		if !strings.Contains(prelude, want) {
			t.Errorf("prelude is missing %q:\n%s", want, prelude)
		}
	}

	quiet := base
	quiet.NoBanner = true
	quiet.Command = []string{"ps", "aux"}
	q, err := quiet.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	qargv := q.argv(4812)
	if strings.Contains(qargv[2], "printf") {
		t.Errorf("NoBanner must remove the banner:\n%s", qargv[2])
	}
	if want := []string{"ps", "aux"}; !equal(qargv[4:], want) {
		t.Errorf("argv tail = %q, want %q", qargv[4:], want)
	}
}

func TestAttachRejectsAMissingToolbox(t *testing.T) {
	root := t.TempDir()
	err := Attach(context.Background(), Options{
		ContainerID: "c1",
		DataRoot:    root,
		Resolve:     func(context.Context, string) (int, error) { return os.Getpid(), nil },
	})
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "no toolbox has been embedded") {
		t.Fatalf("error %q does not name the missing toolbox", err)
	}
	if !strings.Contains(err.Error(), "EmbedToolbox") {
		t.Errorf("error %q does not say how to fix it", err)
	}
}

// TestAttachJoinsNamespacesAndStagesTheToolbox drives the whole Attach path
// against this test process's own namespaces, which setns(2) accepts and which
// leaves nothing to clean up.
//
// It needs root - every step is a CAP_SYS_ADMIN operation - and a static
// busybox to stage, so it skips rather than fails without either.
func TestAttachJoinsNamespacesAndStagesTheToolbox(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("joining namespaces and mounting a tmpfs need root")
	}
	busybox := findStaticBusybox(t)
	root := t.TempDir()
	t.Setenv("HULL_DATA_ROOT", root)
	if err := EmbedToolbox(busybox); err != nil {
		t.Fatalf("EmbedToolbox(%s): %v", busybox, err)
	}

	var out bytes.Buffer
	var trace bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	toolboxMount := filepath.Join(root, "toolbox-mnt")
	hostRoot := filepath.Join(root, "host-root")
	// The canary is written to the literal mountpoint, never to
	// $HULL_DEBUG_HOST_ROOT: if the bind had been refused that variable would
	// name /proc/1/root, and this test process's root really is writable.
	script := "echo PATH=$PATH; ls $HULL_DEBUG_TOOLBOX/ps >/dev/null && echo applets-ok; " +
		"test -d " + hostRoot + "/etc && echo host-root-ok; " +
		"touch " + hostRoot + "/hull-debug-canary 2>/dev/null && echo WRITABLE || echo read-only-ok; " +
		"test -r /proc/1/root && echo proc1-ok"

	err := Attach(ctx, Options{
		ContainerID:  "self",
		DataRoot:     root,
		ToolboxMount: toolboxMount,
		HostRoot:     hostRoot,
		Resolve:      func(context.Context, string) (int, error) { return os.Getpid(), nil },
		Command:      []string{"sh", "-c", script},
		Attach:       &readWriter{r: strings.NewReader(""), w: &out},
		Tracer:       explain.New(&trace, explain.Options{Verbose: true}),
	})
	if err != nil {
		t.Fatalf("Attach: %v\ntrace:\n%s\noutput:\n%s", err, trace.String(), out.String())
	}

	got := out.String()
	for _, want := range []string{
		"hull debug: busybox toolbox attached",
		"PATH=" + toolboxMount + "/bin:",
		"applets-ok",
		"host-root-ok",
		"read-only-ok",
		"proc1-ok",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("session output is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "WRITABLE") {
		t.Error("the target's filesystem was writable through the host-root bind")
	}
	if _, err := os.Stat(filepath.Join(hostRoot, "hull-debug-canary")); err == nil {
		t.Error("the session wrote through the host-root bind")
	}

	tr := trace.String()
	for _, want := range []string{
		"setns(pidfd of ",
		"CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWUTS",
		"unshare(CLONE_NEWNS)",
		"open_tree(",
		"MOUNT_ATTR_RDONLY",
		"move_mount(",
		"applet symlinks",
		"execve(",
	} {
		if !strings.Contains(tr, want) {
			t.Errorf("trace is missing %q:\n%s", want, tr)
		}
	}

	// Nothing the session mounted may survive it, and nothing may have been
	// left behind in this process's own mount namespace.
	mounts, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		t.Fatalf("read /proc/self/mounts: %v", err)
	}
	if strings.Contains(string(mounts), toolboxMount) {
		t.Errorf("the toolbox tmpfs leaked into the daemon's mount namespace:\n%s", mounts)
	}
}

// TestAttachReportsANonZeroExit proves the session's exit status reaches the
// caller, which is what "hull debug ctr -- cmd" needs.
func TestAttachReportsANonZeroExit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("joining namespaces and mounting a tmpfs need root")
	}
	busybox := findStaticBusybox(t)
	root := t.TempDir()
	t.Setenv("HULL_DATA_ROOT", root)
	if err := EmbedToolbox(busybox); err != nil {
		t.Fatalf("EmbedToolbox: %v", err)
	}

	var out bytes.Buffer
	err := Attach(context.Background(), Options{
		ContainerID:  "self",
		DataRoot:     root,
		ToolboxMount: filepath.Join(root, "toolbox-mnt"),
		HostRoot:     filepath.Join(root, "host-root"),
		NoBanner:     true,
		Resolve:      func(context.Context, string) (int, error) { return os.Getpid(), nil },
		Command:      []string{"sh", "-c", "exit 42"},
		Attach:       &readWriter{r: strings.NewReader(""), w: &out},
	})
	var exit *ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("err = %v, want *ExitError", err)
	}
	if exit.Code != 42 {
		t.Errorf("exit code = %d, want 42", exit.Code)
	}
}

// findStaticBusybox returns a statically linked busybox to use as a toolbox,
// skipping the test when the machine has none.
func findStaticBusybox(t *testing.T) string {
	t.Helper()
	candidates := []string{
		os.Getenv("HULL_TEST_BUSYBOX"),
		"/bin/busybox",
		"/usr/bin/busybox",
		"/sbin/busybox",
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err != nil || !st.Mode().IsRegular() {
			continue
		}
		if err := verifyStaticELF(c); err != nil {
			continue
		}
		return c
	}
	t.Skip("no static busybox on this machine; set HULL_TEST_BUSYBOX to one")
	return ""
}

// readWriter joins a reader and a writer into the io.ReadWriter Options.Attach
// takes.
type readWriter struct {
	r io.Reader
	w io.Writer
}

func (rw *readWriter) Read(p []byte) (int, error)  { return rw.r.Read(p) }
func (rw *readWriter) Write(p []byte) (int, error) { return rw.w.Write(p) }

// equal reports whether two string slices match.
func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
