package client

import (
	"runtime"
	"testing"
)

func TestParseHost(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantScheme Scheme
		wantAddr   string
		wantSocket string
		wantTLS    bool
		wantErr    bool
	}{
		{
			name:       "unix socket",
			in:         "unix:///var/lib/hull/run/hull.sock",
			wantScheme: SchemeUnix,
			wantAddr:   "/var/lib/hull/run/hull.sock",
		},
		{
			name:       "unix socket shared into /mnt/wsl",
			in:         "unix:///mnt/wsl/hull/hull.sock",
			wantScheme: SchemeUnix,
			wantAddr:   "/mnt/wsl/hull/hull.sock",
		},
		{
			name:       "bare absolute path is a unix socket",
			in:         "/var/run/docker.sock",
			wantScheme: SchemeUnix,
			wantAddr:   "/var/run/docker.sock",
		},
		{
			name:       "named pipe, four slashes",
			in:         "npipe:////./pipe/hull_engine",
			wantScheme: SchemeNamedPipe,
			wantAddr:   `\\.\pipe\hull_engine`,
		},
		{
			name:       "named pipe, two slashes and a dot",
			in:         "npipe://./pipe/hull_engine",
			wantScheme: SchemeNamedPipe,
			wantAddr:   `\\.\pipe\hull_engine`,
		},
		{
			name:       "named pipe, bare name gets the pipe prefix",
			in:         "npipe:////./pipe/docker_engine",
			wantScheme: SchemeNamedPipe,
			wantAddr:   `\\.\pipe\docker_engine`,
		},
		{
			name:       "bare windows pipe path",
			in:         `\\.\pipe\hull_engine`,
			wantScheme: SchemeNamedPipe,
			wantAddr:   `\\.\pipe\hull_engine`,
		},
		{
			name:       "tcp with an explicit port",
			in:         "tcp://127.0.0.1:2375",
			wantScheme: SchemeTCP,
			wantAddr:   "127.0.0.1:2375",
		},
		{
			name:       "tcp without a port takes the default",
			in:         "tcp://127.0.0.1",
			wantScheme: SchemeTCP,
			wantAddr:   "127.0.0.1:2375",
		},
		{
			name:       "http is tcp",
			in:         "http://localhost:2375",
			wantScheme: SchemeTCP,
			wantAddr:   "localhost:2375",
		},
		{
			name:       "https is tcp with TLS and its own default port",
			in:         "https://engine.local",
			wantScheme: SchemeTCP,
			wantAddr:   "engine.local:2376",
			wantTLS:    true,
		},
		{
			name:       "tcp trailing path is dropped",
			in:         "tcp://127.0.0.1:2375/v1.43",
			wantScheme: SchemeTCP,
			wantAddr:   "127.0.0.1:2375",
		},
		{
			name:       "ipv6 literal keeps its brackets",
			in:         "tcp://[::1]:2375",
			wantScheme: SchemeTCP,
			wantAddr:   "[::1]:2375",
		},
		{
			name:       "ipv6 literal without a port",
			in:         "tcp://[::1]",
			wantScheme: SchemeTCP,
			wantAddr:   "[::1]:2375",
		},
		{
			name:       "wsl distro with the default socket",
			in:         "wsl://hull-engine",
			wantScheme: SchemeWSL,
			wantAddr:   "hull-engine",
			wantSocket: DefaultUnixSocket,
		},
		{
			name:       "wsl distro with an explicit socket",
			in:         "wsl://other/var/run/hull.sock",
			wantScheme: SchemeWSL,
			wantAddr:   "other",
			wantSocket: "/var/run/hull.sock",
		},
		{name: "empty", in: "", wantErr: true},
		{name: "no scheme", in: "hull-engine", wantErr: true},
		{name: "unknown scheme", in: "vsock://3:2375", wantErr: true},
		{name: "socket activation is refused", in: "fd://3", wantErr: true},
		{name: "ssh is refused with advice", in: "ssh://host", wantErr: true},
		{name: "tcp with no host", in: "tcp://", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseHost(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseHost(%q) = %+v, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", tc.in, err)
			}
			if got.Scheme != tc.wantScheme {
				t.Errorf("scheme = %q, want %q", got.Scheme, tc.wantScheme)
			}
			if got.Addr != tc.wantAddr {
				t.Errorf("addr = %q, want %q", got.Addr, tc.wantAddr)
			}
			if tc.wantSocket != "" && got.SocketPath != tc.wantSocket {
				t.Errorf("socket = %q, want %q", got.SocketPath, tc.wantSocket)
			}
			if got.TLS != tc.wantTLS {
				t.Errorf("tls = %v, want %v", got.TLS, tc.wantTLS)
			}
		})
	}
}

func TestHostString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "unix", in: "unix:///var/lib/hull/run/hull.sock", want: "unix:///var/lib/hull/run/hull.sock"},
		{name: "npipe", in: "npipe:////./pipe/hull_engine", want: "npipe://./pipe/hull_engine"},
		{name: "tcp", in: "tcp://127.0.0.1:2375", want: "tcp://127.0.0.1:2375"},
		{name: "https", in: "https://engine.local:2376", want: "https://engine.local:2376"},
		{name: "wsl default socket", in: "wsl://hull-engine", want: "wsl://hull-engine"},
		{name: "wsl custom socket", in: "wsl://d/tmp/x.sock", want: "wsl://d/tmp/x.sock"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ParseHost(tc.in)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", tc.in, err)
			}
			if got := h.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveHostOrder(t *testing.T) {
	t.Run("explicit wins over both variables", func(t *testing.T) {
		t.Setenv("HULL_HOST", "tcp://10.0.0.1:2375")
		t.Setenv("DOCKER_HOST", "tcp://10.0.0.2:2375")
		h, err := ResolveHost("unix:///tmp/explicit.sock")
		if err != nil {
			t.Fatal(err)
		}
		if h.Addr != "/tmp/explicit.sock" {
			t.Errorf("addr = %q, want the explicit socket", h.Addr)
		}
	})
	t.Run("HULL_HOST wins over DOCKER_HOST", func(t *testing.T) {
		t.Setenv("HULL_HOST", "tcp://10.0.0.1:2375")
		t.Setenv("DOCKER_HOST", "tcp://10.0.0.2:2375")
		h, err := ResolveHost("")
		if err != nil {
			t.Fatal(err)
		}
		if h.Addr != "10.0.0.1:2375" {
			t.Errorf("addr = %q, want HULL_HOST", h.Addr)
		}
	})
	t.Run("DOCKER_HOST is honoured", func(t *testing.T) {
		t.Setenv("HULL_HOST", "")
		t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
		h, err := ResolveHost("")
		if err != nil {
			t.Fatal(err)
		}
		if h.Scheme != SchemeUnix || h.Addr != "/var/run/docker.sock" {
			t.Errorf("host = %+v, want the DOCKER_HOST socket", h)
		}
	})
	t.Run("platform default when nothing is set", func(t *testing.T) {
		t.Setenv("HULL_HOST", "")
		t.Setenv("DOCKER_HOST", "")
		h, err := ResolveHost("")
		if err != nil {
			t.Fatal(err)
		}
		want := SchemeUnix
		if runtime.GOOS == "windows" {
			want = SchemeNamedPipe
		}
		if h.Scheme != want {
			t.Errorf("scheme = %q, want %q on %s", h.Scheme, want, runtime.GOOS)
		}
	})
	t.Run("a malformed variable is an error, not a silent fallback", func(t *testing.T) {
		t.Setenv("HULL_HOST", "nonsense")
		t.Setenv("DOCKER_HOST", "")
		if _, err := ResolveHost(""); err == nil {
			t.Fatal("ResolveHost with a malformed HULL_HOST returned no error")
		}
	})
}

func TestCompareAPIVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.43", "1.43", 0},
		{"1.24", "1.43", -1},
		{"1.43", "1.24", 1},
		{"1.9", "1.10", -1},
		{"v1.43", "1.43", 0},
		{"2.0", "1.99", 1},
		{"1.43", "1", 1},
	}
	for _, tc := range tests {
		if got := CompareAPIVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareAPIVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
