package debugshell

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/explain"
	"github.com/rahuldhali/hull/internal/types"
)

func TestNormalizeDefaults(t *testing.T) {
	root := t.TempDir()
	o, err := Options{ContainerID: "abc123def456789", DataRoot: root}.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if want := filepath.Join(root, ToolboxDir, ToolboxName); o.Toolbox != want {
		t.Errorf("Toolbox = %q, want %q", o.Toolbox, want)
	}
	if o.ToolboxMount != DefaultToolboxMount {
		t.Errorf("ToolboxMount = %q, want %q", o.ToolboxMount, DefaultToolboxMount)
	}
	if o.HostRoot != DefaultHostRoot {
		t.Errorf("HostRoot = %q, want %q", o.HostRoot, DefaultHostRoot)
	}
	if want := []string{"pid", "network", "ipc", "uts"}; !reflect.DeepEqual(o.Namespaces, want) {
		t.Errorf("Namespaces = %q, want the canonicalised default %q", o.Namespaces, want)
	}
	if want := []string{DefaultToolboxMount + "/bin/sh"}; !reflect.DeepEqual(o.Command, want) {
		t.Errorf("Command = %q, want %q", o.Command, want)
	}
	if o.Resolve == nil {
		t.Error("Resolve must default to the state resolver")
	}
	if o.Tracer == nil || explain.Enabled(o.Tracer) {
		t.Errorf("Tracer = %v, want the no-op tracer", o.Tracer)
	}
}

func TestNormalizeDoesNotMutateTheCaller(t *testing.T) {
	orig := Options{
		ContainerID: "c1",
		DataRoot:    t.TempDir(),
		Namespaces:  []string{"net"},
		Command:     []string{"ps", "aux"},
		Env:         []string{"A=1"},
	}
	before := Options{
		ContainerID: orig.ContainerID,
		DataRoot:    orig.DataRoot,
		Namespaces:  append([]string(nil), orig.Namespaces...),
		Command:     append([]string(nil), orig.Command...),
		Env:         append([]string(nil), orig.Env...),
	}
	if _, err := orig.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !reflect.DeepEqual(orig.Namespaces, before.Namespaces) ||
		!reflect.DeepEqual(orig.Command, before.Command) ||
		!reflect.DeepEqual(orig.Env, before.Env) ||
		orig.Toolbox != before.Toolbox {
		t.Fatalf("normalize mutated the caller's Options: %+v", orig)
	}
}

func TestNormalizeOverrides(t *testing.T) {
	o, err := Options{
		ContainerID:  "c1",
		DataRoot:     t.TempDir(),
		Toolbox:      "/opt/busybox",
		ToolboxMount: "/tools",
		HostRoot:     "/target",
		Namespaces:   []string{"NET", "uts", "net"},
		Command:      []string{"ps", "aux"},
	}.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if o.Toolbox != "/opt/busybox" {
		t.Errorf("Toolbox = %q", o.Toolbox)
	}
	if want := []string{"network", "uts"}; !reflect.DeepEqual(o.Namespaces, want) {
		t.Errorf("Namespaces = %q, want %q", o.Namespaces, want)
	}
	if want := []string{"ps", "aux"}; !reflect.DeepEqual(o.Command, want) {
		t.Errorf("Command = %q, want %q", o.Command, want)
	}
}

func TestNormalizeRejects(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{name: "no container", opts: Options{}, want: "ContainerID is empty"},
		{name: "blank container", opts: Options{ContainerID: "   "}, want: "ContainerID is empty"},
		{
			name: "mount namespace",
			opts: Options{ContainerID: "c", Namespaces: []string{"pid", "mnt"}},
			want: "will not join the mount namespace",
		},
		{
			name: "user namespace",
			opts: Options{ContainerID: "c", Namespaces: []string{"user"}},
			want: "will not join the user namespace",
		},
		{
			name: "unknown namespace",
			opts: Options{ContainerID: "c", Namespaces: []string{"nvme"}},
			want: `unknown namespace "nvme"`,
		},
		{
			name: "namespaces name nothing",
			opts: Options{ContainerID: "c", Namespaces: []string{"", "  "}},
			want: "named no namespace",
		},
		{
			name: "relative toolbox mount",
			opts: Options{ContainerID: "c", ToolboxMount: "tools"},
			want: "is not an absolute path",
		},
		{
			name: "unclean host root",
			opts: Options{ContainerID: "c", HostRoot: "/a/../b"},
			want: "must be a clean absolute path",
		},
		{
			name: "root as host root",
			opts: Options{ContainerID: "c", HostRoot: "/"},
			want: "must be a clean absolute path",
		},
		{
			name: "colliding mountpoints",
			opts: Options{ContainerID: "c", ToolboxMount: "/x", HostRoot: "/x"},
			want: "are both",
		},
		{
			name: "empty argv0",
			opts: Options{ContainerID: "c", Command: []string{""}},
			want: "Command[0] is empty",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.opts.normalize()
			if err == nil {
				t.Fatal("want an error")
			}
			if !errors.Is(err, ErrInvalidOptions) {
				t.Errorf("error %v does not wrap ErrInvalidOptions", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestCanonicalNamespaces(t *testing.T) {
	tests := []struct {
		name  string
		in    []string
		want  []string
		fails bool
	}{
		{name: "default", in: nil, want: []string{"pid", "network", "ipc", "uts"}},
		{name: "empty slice", in: []string{}, want: []string{"pid", "network", "ipc", "uts"}},
		{name: "net alias", in: []string{"net"}, want: []string{"network"}},
		{name: "network spelled out", in: []string{"network"}, want: []string{"network"}},
		{name: "case folded", in: []string{"PID", "Uts"}, want: []string{"pid", "uts"}},
		{name: "padded", in: []string{" ipc "}, want: []string{"ipc"}},
		{name: "dedupe keeps order", in: []string{"net", "pid", "network"}, want: []string{"network", "pid"}},
		{name: "cgroup and time", in: []string{"cgroup", "time"}, want: []string{"cgroup", "time"}},
		{name: "mount refused", in: []string{"mount"}, fails: true},
		{name: "mnt refused", in: []string{"mnt"}, fails: true},
		{name: "user refused", in: []string{"userns"}, fails: true},
		{name: "unknown", in: []string{"widget"}, fails: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalNamespaces(tc.in)
			if tc.fails {
				if err == nil {
					t.Fatalf("want an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDefaultNamespacesExcludeMount(t *testing.T) {
	// The whole design rests on this: joining the mount namespace would
	// replace the filesystem with the one that has no tools in it.
	for _, n := range DefaultNamespaces {
		if n == "mount" || n == "mnt" || n == "user" {
			t.Fatalf("DefaultNamespaces must not contain %q: %q", n, DefaultNamespaces)
		}
	}
	if want := []string{"pid", "net", "ipc", "uts"}; !reflect.DeepEqual(DefaultNamespaces, want) {
		t.Errorf("DefaultNamespaces = %q, want %q", DefaultNamespaces, want)
	}
}

func TestEnvironPutsTheToolboxFirst(t *testing.T) {
	o, err := Options{
		ContainerID:  "abcdef0123456789",
		DataRoot:     t.TempDir(),
		ToolboxMount: "/tools",
		Env:          []string{"EDITOR=vi"},
	}.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	env := o.environ()
	if want := "PATH=/tools/bin:" + DefaultPath; env[0] != want {
		t.Errorf("env[0] = %q, want %q", env[0], want)
	}
	if got := env[len(env)-1]; got != "EDITOR=vi" {
		t.Errorf("caller env must come last, got %q", got)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"HULL_DEBUG_CONTAINER=abcdef0123456789",
		"HULL_DEBUG_TOOLBOX=/tools/bin",
		"HULL_DEBUG_HOST_ROOT=" + DefaultHostRoot,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("environment is missing %q:\n%s", want, joined)
		}
	}
}

func TestBannerNamesEveryLocation(t *testing.T) {
	o, err := Options{ContainerID: "abcdef0123456789abcdef", DataRoot: t.TempDir()}.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	b := o.banner(4812)
	for _, want := range []string{
		"abcdef012345",               // the short id, not the full one
		DefaultHostRoot,              // where the filesystem went
		"/proc/1/root",               // the live view
		DefaultToolboxMount + "/bin", // where the tools are
		"4812",                       // the host pid
		"CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWUTS",
		"not modified",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("banner is missing %q:\n%s", want, b)
		}
	}
}

func TestShortID(t *testing.T) {
	tests := []struct{ in, want string }{
		{in: "", want: ""},
		{in: "web", want: "web"},
		{in: "0123456789ab", want: "0123456789ab"},
		{in: "0123456789abcdef", want: "0123456789ab"},
	}
	for _, tc := range tests {
		if got := shortID(tc.in); got != tc.want {
			t.Errorf("shortID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestToolboxPathFollowsTheDataRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HULL_DATA_ROOT", root)
	if got, want := DataRoot(), root; got != want {
		t.Fatalf("DataRoot() = %q, want %q", got, want)
	}
	if got, want := ToolboxPath(), filepath.Join(root, ToolboxDir, ToolboxName); got != want {
		t.Fatalf("ToolboxPath() = %q, want %q", got, want)
	}
	if ToolboxPresent() {
		t.Fatal("an empty data root must not report a toolbox")
	}
}

func TestEmbedToolbox(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HULL_DATA_ROOT", root)
	src := filepath.Join(t.TempDir(), "busybox")
	writeELF(t, src, false)

	if err := EmbedToolbox(src); err != nil {
		t.Fatalf("EmbedToolbox: %v", err)
	}
	if !ToolboxPresent() {
		t.Fatal("ToolboxPresent is false after EmbedToolbox")
	}
	got, err := os.ReadFile(ToolboxPath())
	if err != nil {
		t.Fatalf("read embedded toolbox: %v", err)
	}
	want, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Error("the embedded toolbox differs from the source")
	}
	st, err := os.Stat(ToolboxPath())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm()&0o111 == 0 {
		t.Errorf("embedded toolbox mode = %v, want an executable bit", st.Mode())
	}
	// The atomic install must leave no temporary behind.
	entries, err := os.ReadDir(filepath.Join(root, ToolboxDir))
	if err != nil {
		t.Fatalf("read toolbox dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != ToolboxName {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("toolbox directory holds %q, want only %q", names, ToolboxName)
	}

	// Embedding again must overwrite rather than fail.
	if err := EmbedToolbox(src); err != nil {
		t.Fatalf("second EmbedToolbox: %v", err)
	}
}

func TestEmbedToolboxRejects(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HULL_DATA_ROOT", root)
	dir := t.TempDir()

	script := filepath.Join(dir, "not-elf")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	dynamic := filepath.Join(dir, "dynamic")
	writeELF(t, dynamic, true)

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "empty path", path: "", want: "needs a path"},
		{name: "missing", path: filepath.Join(dir, "nope"), want: "stat toolbox"},
		{name: "a directory", path: dir, want: "not a regular file"},
		{name: "a shell script", path: script, want: "not an ELF binary"},
		{name: "dynamically linked", path: dynamic, want: "dynamically linked"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := EmbedToolbox(tc.path)
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
	if ToolboxPresent() {
		t.Error("a rejected toolbox must not be installed")
	}
}

func TestStateResolver(t *testing.T) {
	root := t.TempDir()
	write := func(c types.Container) {
		t.Helper()
		dir := filepath.Join(root, "containers", c.ID)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "state.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(types.Container{
		ID: "aaaa1111bbbb2222", Name: "web", State: types.StateRunning, Pid: 4812,
		Created: time.Now(),
	})
	write(types.Container{ID: "aaaa9999cccc3333", Name: "api", State: types.StateRunning, Pid: 4813})
	write(types.Container{ID: "dddd4444eeee5555", Name: "done", State: types.StateExited, Pid: 0})
	write(types.Container{ID: "ffff6666aaaa7777", Name: "nopid", State: types.StateRunning, Pid: 0})

	resolve := StateResolver(root)
	ctx := context.Background()

	tests := []struct {
		name    string
		id      string
		wantPid int
		wantErr string
	}{
		{name: "full id", id: "aaaa1111bbbb2222", wantPid: 4812},
		{name: "by name", id: "web", wantPid: 4812},
		{name: "unambiguous prefix", id: "aaaa1111", wantPid: 4812},
		{name: "ambiguous prefix", id: "aaaa", wantErr: "matches 2 containers"},
		{name: "unknown", id: "zzzz", wantErr: "no such container"},
		{name: "not running", id: "done", wantErr: "is not running"},
		{name: "running without a pid", id: "nopid", wantErr: "no recorded pid"},
		{name: "path traversal", id: "../../etc", wantErr: "is not a container id"},
		{name: "empty", id: "", wantErr: "no container given"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pid, err := resolve(ctx, tc.id)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want an error, got pid %d", pid)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pid != tc.wantPid {
				t.Errorf("pid = %d, want %d", pid, tc.wantPid)
			}
		})
	}
}

func TestStateResolverHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := StateResolver(t.TempDir())(ctx, "web"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestAttachValidatesBeforeTouchingAnything(t *testing.T) {
	// On every platform, a bad Options must be reported as a bad Options and
	// must never reach a resolver or a namespace.
	called := false
	err := Attach(context.Background(), Options{
		ContainerID: "c1",
		Namespaces:  []string{"mount"},
		DataRoot:    t.TempDir(),
		Resolve: func(context.Context, string) (int, error) {
			called = true
			return 1, nil
		},
	})
	if err == nil {
		t.Fatal("want an error")
	}
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
	if called {
		t.Error("Attach resolved the container despite invalid options")
	}
}

// writeELF writes a minimal 64-bit x86-64 ELF executable, optionally with a
// PT_INTERP program header, so the toolbox validation can be exercised without
// shipping a binary in the test tree.
func writeELF(t *testing.T, path string, dynamic bool) {
	t.Helper()
	const (
		ehsize      = 64
		phentsize   = 56
		ptLoad      = 1
		ptInterp    = 3
		etExec      = 2
		emX8664     = 62
		elfClass64  = 2
		elfData2LSB = 1
	)
	phnum := 1
	if dynamic {
		phnum = 2
	}

	var b bytes.Buffer
	ident := make([]byte, 16)
	copy(ident, []byte{0x7f, 'E', 'L', 'F'})
	ident[4] = elfClass64
	ident[5] = elfData2LSB
	ident[6] = 1 // EI_VERSION
	b.Write(ident)

	le := binary.LittleEndian
	w16 := func(v uint16) { _ = binary.Write(&b, le, v) }
	w32 := func(v uint32) { _ = binary.Write(&b, le, v) }
	w64 := func(v uint64) { _ = binary.Write(&b, le, v) }

	w16(etExec)   // e_type
	w16(emX8664)  // e_machine
	w32(1)        // e_version
	w64(0x400000) // e_entry
	w64(ehsize)   // e_phoff
	w64(0)        // e_shoff
	w32(0)        // e_flags
	w16(ehsize)   // e_ehsize
	w16(phentsize)
	w16(uint16(phnum))
	w16(64) // e_shentsize
	w16(0)  // e_shnum
	w16(0)  // e_shstrndx

	prog := func(typ uint32) {
		w32(typ)
		w32(4) // p_flags: PF_R
		w64(0) // p_offset
		w64(0x400000)
		w64(0x400000)
		w64(0) // p_filesz
		w64(0) // p_memsz
		w64(8) // p_align
	}
	prog(ptLoad)
	if dynamic {
		prog(ptInterp)
	}

	if err := os.WriteFile(path, b.Bytes(), 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
