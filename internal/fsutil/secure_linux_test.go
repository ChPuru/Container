package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// resolvers runs fn twice: once on whatever the kernel offers (openat2 on WSL)
// and once with openat2 forced off, so the fd-relative fallback walk is covered
// by every single case below.
func resolvers(t *testing.T, fn func(t *testing.T)) {
	t.Helper()
	t.Run("openat2", func(t *testing.T) {
		setOpenat2Disabled(false)
		if !ProbeOpenat2() {
			t.Skip("kernel has no usable openat2")
		}
		fn(t)
	})
	t.Run("fallback", func(t *testing.T) {
		setOpenat2Disabled(true)
		defer setOpenat2Disabled(false)
		if ProbeOpenat2() {
			t.Fatal("setOpenat2Disabled(true) did not disable openat2")
		}
		fn(t)
	})
}

// secureTree builds a root with the whole zoo of hostile and benign paths and
// returns (root, outsideDir).
func secureTree(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{root, outside, filepath.Join(root, "sub", "deep")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, data string) {
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "in.txt"), "inside")
	write(filepath.Join(root, "sub", "deep", "leaf.txt"), "leaf")
	write(filepath.Join(outside, "secret.txt"), "SECRET")

	link := func(target, name string) {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	link("in.txt", "good-rel")                               // stays inside
	link("/in.txt", "good-abs")                              // absolute, re-anchored at root
	link("../outside/secret.txt", "escape-rel")              // climbs out
	link(filepath.Join(outside, "secret.txt"), "escape-abs") // absolute host path
	link(outside, "escape-dir")                              // directory escape
	link("loop-b", "loop-a")                                 // mutual loop
	link("loop-a", "loop-b")                                 //
	link("self", "self")                                     // self loop
	link("sub", "sub-link")                                  // benign directory symlink
	link("../../../../../../etc/passwd", "many-dotdot")      // deep climb
	return root, outside
}

func readAll(t *testing.T, f *os.File) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/fd/" + itoa(int(f.Fd())))
	if err == nil {
		return string(b)
	}
	buf := make([]byte, 4096)
	n, rerr := f.Read(buf)
	if rerr != nil && n == 0 {
		t.Fatalf("read: %v", rerr)
	}
	return string(buf[:n])
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

func TestSecureOpenAllowsInRootPaths(t *testing.T) {
	resolvers(t, func(t *testing.T) {
		root, _ := secureTree(t)
		tests := []struct {
			name, path, want string
		}{
			{"plain file", "in.txt", "inside"},
			{"nested file", "sub/deep/leaf.txt", "leaf"},
			{"inner dotdot stays inside", "sub/../in.txt", "inside"},
			{"relative symlink", "good-rel", "inside"},
			{"absolute symlink re-anchored", "good-abs", "inside"},
			{"through a directory symlink", "sub-link/deep/leaf.txt", "leaf"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f, err := SecureOpen(root, tt.path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatalf("SecureOpen(%q) error = %v", tt.path, err)
				}
				defer f.Close()
				buf := make([]byte, 64)
				n, _ := f.Read(buf)
				if got := string(buf[:n]); got != tt.want {
					t.Fatalf("SecureOpen(%q) content = %q, want %q", tt.path, got, tt.want)
				}
			})
		}
	})
}

func TestSecureOpenRejectsEscapes(t *testing.T) {
	resolvers(t, func(t *testing.T) {
		root, outside := secureTree(t)
		tests := []struct {
			name     string
			path     string
			wantKind string // "unsafe" for a lexical rejection, "err" for any failure
		}{
			{"bare dotdot", "..", "unsafe"},
			{"dotdot climb", "../outside/secret.txt", "unsafe"},
			{"deep dotdot climb", "sub/../../outside/secret.txt", "unsafe"},
			{"absolute path", "/etc/passwd", "unsafe"},
			{"absolute path to the real secret", filepath.Join(outside, "secret.txt"), "unsafe"},
			{"symlink climbing out", "escape-rel", "err"},
			{"symlink to an absolute host path", "escape-abs", "err"},
			{"file under an escaping directory symlink", "escape-dir/secret.txt", "err"},
			{"symlink with many dotdots", "many-dotdot", "err"},
			{"mutual symlink loop", "loop-a", "err"},
			{"self symlink loop", "self", "err"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f, err := SecureOpen(root, tt.path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
				if err == nil {
					content := readAll(t, f)
					f.Close()
					t.Fatalf("SecureOpen(%q) succeeded and read %q, want refusal", tt.path, content)
				}
				if strings.Contains(err.Error(), "SECRET") {
					t.Fatalf("error text leaks content: %v", err)
				}
				if tt.wantKind == "unsafe" && !errors.Is(err, ErrUnsafePath) {
					t.Fatalf("SecureOpen(%q) error = %v, want ErrUnsafePath", tt.path, err)
				}
			})
		}
	})
}

func TestSecureOpenSymlinkLoopIsELOOP(t *testing.T) {
	resolvers(t, func(t *testing.T) {
		root, _ := secureTree(t)
		for _, p := range []string{"loop-a", "loop-b", "self"} {
			_, err := SecureOpen(root, p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if !errors.Is(err, unix.ELOOP) {
				t.Fatalf("SecureOpen(%q) error = %v, want ELOOP", p, err)
			}
		}
	})
}

func TestSecureOpenNoFollowKeepsTheLink(t *testing.T) {
	resolvers(t, func(t *testing.T) {
		root, _ := secureTree(t)
		_, err := SecureOpen(root, "good-rel", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if !errors.Is(err, unix.ELOOP) {
			t.Fatalf("SecureOpen(O_NOFOLLOW on a symlink) error = %v, want ELOOP", err)
		}
	})
}

func TestSecureOpenCreate(t *testing.T) {
	resolvers(t, func(t *testing.T) {
		root, _ := secureTree(t)
		f, err := SecureOpen(root, "sub/created.txt", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o640)
		if err != nil {
			t.Fatalf("SecureOpen(O_CREAT) error = %v", err)
		}
		if _, err := f.WriteString("made"); err != nil {
			t.Fatalf("write: %v", err)
		}
		f.Close()

		fi, err := os.Stat(filepath.Join(root, "sub", "created.txt"))
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if fi.Mode().Perm() != 0o640 {
			t.Fatalf("mode = %v, want 0640", fi.Mode().Perm())
		}

		// A second exclusive create must fail.
		if _, err := SecureOpen(root, "sub/created.txt", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o640); !errors.Is(err, unix.EEXIST) {
			t.Fatalf("second O_EXCL create error = %v, want EEXIST", err)
		}
		// Creating through an escaping symlink must not create outside root.
		if _, err := SecureOpen(root, "escape-dir/new.txt", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600); err == nil {
			t.Fatal("create through an escaping directory symlink succeeded")
		}
	})
}

func TestSecureOpenRootItself(t *testing.T) {
	resolvers(t, func(t *testing.T) {
		root, _ := secureTree(t)
		for _, p := range []string{"", "."} {
			f, err := SecureOpen(root, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatalf("SecureOpen(root, %q) error = %v", p, err)
			}
			names, err := f.Readdirnames(-1)
			f.Close()
			if err != nil {
				t.Fatalf("Readdirnames: %v", err)
			}
			if len(names) == 0 {
				t.Fatal("root directory listed as empty")
			}
		}
	})
}

func TestSecureOpenBadRoot(t *testing.T) {
	if _, err := SecureOpen("", "x", unix.O_RDONLY, 0); err == nil {
		t.Fatal("SecureOpen with an empty root = nil, want error")
	}
	if _, err := SecureOpen("relative/root", "x", unix.O_RDONLY, 0); err == nil {
		t.Fatal("SecureOpen with a relative root = nil, want error")
	}
}

func TestSecureStat(t *testing.T) {
	resolvers(t, func(t *testing.T) {
		root, _ := secureTree(t)
		tests := []struct {
			name    string
			path    string
			wantDir bool
			wantErr bool
		}{
			{"file", "in.txt", false, false},
			{"dir", "sub", true, false},
			{"symlink follows to file", "good-rel", false, false},
			{"symlink follows to dir", "sub-link", true, false},
			{"escaping symlink", "escape-rel", false, true},
			{"missing", "nope", false, true},
			{"lexical escape", "../outside", false, true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fi, err := SecureStat(root, tt.path)
				if tt.wantErr {
					if err == nil {
						t.Fatalf("SecureStat(%q) = %v, want error", tt.path, fi.Mode())
					}
					return
				}
				if err != nil {
					t.Fatalf("SecureStat(%q) error = %v", tt.path, err)
				}
				if fi.IsDir() != tt.wantDir {
					t.Fatalf("SecureStat(%q).IsDir() = %v, want %v", tt.path, fi.IsDir(), tt.wantDir)
				}
				if fi.Mode()&os.ModeSymlink != 0 {
					t.Fatalf("SecureStat(%q) returned the symlink itself", tt.path)
				}
			})
		}
	})
}

func TestSecureMkdirAll(t *testing.T) {
	resolvers(t, func(t *testing.T) {
		root, outside := secureTree(t)

		if err := SecureMkdirAll(root, "a/b/c", 0o750); err != nil {
			t.Fatalf("SecureMkdirAll() error = %v", err)
		}
		for _, p := range []string{"a", "a/b", "a/b/c"} {
			fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(p)))
			if err != nil {
				t.Fatalf("Stat(%s): %v", p, err)
			}
			if !fi.IsDir() {
				t.Fatalf("%s is not a directory", p)
			}
			if fi.Mode().Perm() != 0o750 {
				t.Fatalf("%s mode = %v, want 0750", p, fi.Mode().Perm())
			}
		}

		// Idempotent.
		if err := SecureMkdirAll(root, "a/b/c", 0o750); err != nil {
			t.Fatalf("second SecureMkdirAll() error = %v", err)
		}
		// Through a benign directory symlink.
		if err := SecureMkdirAll(root, "sub-link/made", 0o755); err != nil {
			t.Fatalf("SecureMkdirAll through a symlinked dir error = %v", err)
		}
		if !IsDir(filepath.Join(root, "sub", "made")) {
			t.Fatal("directory was not created behind the symlink")
		}

		bad := []string{"../escaped", "..", "/abs/dir", "escape-dir/pwned"}
		for _, p := range bad {
			if err := SecureMkdirAll(root, p, 0o755); err == nil {
				t.Fatalf("SecureMkdirAll(%q) = nil, want error", p)
			}
		}
		if Exists(filepath.Join(outside, "pwned")) {
			t.Fatal("SecureMkdirAll created a directory outside root")
		}
		if Exists(filepath.Join(filepath.Dir(root), "escaped")) {
			t.Fatal("SecureMkdirAll escaped the root")
		}
		// A regular file in the way must be reported, not silently accepted.
		if err := SecureMkdirAll(root, "in.txt/sub", 0o755); err == nil {
			t.Fatal("SecureMkdirAll through a regular file = nil, want error")
		}
	})
}

func TestProbeOpenat2(t *testing.T) {
	setOpenat2Disabled(false)
	if !ProbeOpenat2() {
		t.Log("kernel reports no openat2; fallback walk is the only resolver here")
	}
	setOpenat2Disabled(true)
	if ProbeOpenat2() {
		t.Fatal("ProbeOpenat2() ignored the test hook")
	}
	setOpenat2Disabled(false)
	if !ProbeOpenat2() {
		t.Log("openat2 unavailable after restore (expected only on old kernels)")
	}
}

func TestFreeSpace(t *testing.T) {
	free, total, err := FreeSpace(t.TempDir())
	if err != nil {
		t.Fatalf("FreeSpace() error = %v", err)
	}
	if total == 0 {
		t.Fatal("FreeSpace() total = 0")
	}
	if free > total {
		t.Fatalf("FreeSpace() free %d > total %d", free, total)
	}
	if _, _, err := FreeSpace("/definitely/not/here"); err == nil {
		t.Fatal("FreeSpace() on a missing path = nil, want error")
	}
}

func TestIsMountpoint(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    bool
		wantErr bool
	}{
		{"root", "/", true, false},
		{"temp dir", t.TempDir(), false, false},
		{"missing", "/definitely/not/here", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsMountpoint(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("IsMountpoint(%s) = %v, want error", tt.path, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("IsMountpoint(%s) error = %v", tt.path, err)
			}
			if got != tt.want {
				t.Fatalf("IsMountpoint(%s) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestUnescapeMountinfo(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/mnt/wsl", "/mnt/wsl"},
		{`/mnt/with\040space`, "/mnt/with space"},
		{`/a\011b`, "/a\tb"},
		{`/trailing\`, `/trailing\`},
	}
	for _, tt := range tests {
		if got := unescapeMountinfo(tt.in); got != tt.want {
			t.Fatalf("unescapeMountinfo(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
