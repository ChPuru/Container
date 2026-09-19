// Package client is hull's Go client for the engine's HTTP API.
//
// The engine serves the Docker Engine API (docs/COMPAT.md) plus a hull-only
// namespace under /hull/v1 for the verbs Docker has no equivalent for —
// doctor, checkpoints, the lockfile, folder sync and engine control. Every
// Docker endpoint here speaks Docker's documented wire shapes, so this client
// works unchanged against a real dockerd too; the hull-only endpoints speak
// hull's own internal/types model.
//
// Four transports reach the engine, selected by the address string:
//
//	unix:///var/lib/hull/run/hull.sock   the engine's own socket, and the
//	                                     /mnt/wsl bind of it seen from a
//	                                     sibling distro
//	npipe:////./pipe/hull_engine         the Windows named pipe the relay
//	                                     agent serves
//	tcp://127.0.0.1:2375                 plain TCP; https:// adds TLS
//	wsl://hull-engine                    a stdio relay spawned with wsl.exe,
//	                                     which needs no relay agent at all
//
// With no explicit address the client reads $HULL_HOST, then $DOCKER_HOST,
// then the platform default.
package client

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// Scheme names one of the transports hull's client can speak.
type Scheme string

// The transports the client understands.
const (
	// SchemeUnix is an AF_UNIX socket, the engine's native endpoint.
	SchemeUnix Scheme = "unix"
	// SchemeNamedPipe is a Windows named pipe, served by the relay.
	SchemeNamedPipe Scheme = "npipe"
	// SchemeTCP is a plain or TLS TCP endpoint.
	SchemeTCP Scheme = "tcp"
	// SchemeWSL dials the engine by running a relay command inside a WSL
	// distro over wsl.exe's stdio, which is hull's fallback Windows transport
	// when no named pipe is being served.
	SchemeWSL Scheme = "wsl"
)

// DefaultUnixSocket is where hulld listens inside the engine distro.
const DefaultUnixSocket = "/var/lib/hull/run/hull.sock"

// SharedUnixSocket is the /mnt/wsl bind of DefaultUnixSocket, which any
// sibling WSL distro can reach without going through Windows.
const SharedUnixSocket = "/mnt/wsl/hull/hull.sock"

// DefaultPipeName is the Windows named pipe the relay serves. It is
// deliberately not Docker's pipe name so hull and Docker Desktop coexist.
const DefaultPipeName = `\\.\pipe\hull_engine`

// DefaultDistro is the WSL distro that holds the engine.
const DefaultDistro = "hull-engine"

// DefaultTCPPort is the port a plain TCP engine endpoint uses.
const DefaultTCPPort = "2375"

// DefaultTLSPort is the port a TLS engine endpoint uses.
const DefaultTLSPort = "2376"

// EnvHost is the environment variable hull reads for the engine address.
const EnvHost = "HULL_HOST"

// EnvDockerHost is honoured too, so hull drops into scripts that already
// export DOCKER_HOST.
const EnvDockerHost = "DOCKER_HOST"

// EnvDistro names the WSL distro a wsl:// address defaults to.
const EnvDistro = "HULL_DISTRO"

// Host is a parsed engine address.
type Host struct {
	// Scheme is the transport to use.
	Scheme Scheme
	// Addr is the dial target: a socket path, a pipe path in Windows form, a
	// "host:port" pair, or a WSL distro name.
	Addr string
	// SocketPath is the unix socket the WSL relay should connect to inside
	// the distro. It is only meaningful for SchemeWSL.
	SocketPath string
	// TLS reports that the TCP endpoint expects https.
	TLS bool
	// Raw is the string the address was parsed from, for error messages.
	Raw string
}

// String renders the host back into its canonical URL form.
func (h Host) String() string {
	switch h.Scheme {
	case SchemeUnix:
		return "unix://" + h.Addr
	case SchemeNamedPipe:
		return "npipe://" + strings.ReplaceAll(strings.TrimPrefix(h.Addr, `\\`), `\`, "/")
	case SchemeWSL:
		if h.SocketPath != "" && h.SocketPath != DefaultUnixSocket {
			return "wsl://" + h.Addr + h.SocketPath
		}
		return "wsl://" + h.Addr
	default:
		if h.TLS {
			return "https://" + h.Addr
		}
		return "tcp://" + h.Addr
	}
}

// DefaultHost returns the engine address to use when nothing is configured.
// It is the named pipe on Windows and the unix socket everywhere else.
func DefaultHost() string {
	if runtime.GOOS == "windows" {
		return "npipe:////./pipe/hull_engine"
	}
	return "unix://" + DefaultUnixSocket
}

// ResolveHost picks an engine address in hull's documented order: the explicit
// argument, then $HULL_HOST, then $DOCKER_HOST, then the platform default. The
// first non-empty candidate that parses wins; a candidate that does not parse
// is an error rather than a silent fallthrough, because a typo in DOCKER_HOST
// must not send traffic somewhere unexpected.
func ResolveHost(explicit string) (Host, error) {
	for _, candidate := range []string{explicit, os.Getenv(EnvHost), os.Getenv(EnvDockerHost)} {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		return ParseHost(candidate)
	}
	return ParseHost(DefaultHost())
}

// ParseHost turns an engine address into a [Host].
//
// The accepted forms are:
//
//	unix:///var/lib/hull/run/hull.sock
//	npipe:////./pipe/hull_engine
//	tcp://127.0.0.1:2375        (also http:// and https://)
//	wsl://hull-engine           (optionally wsl://distro/path/to/hull.sock)
//
// A bare absolute path is read as a unix socket, and a bare \\.\pipe\ path as
// a named pipe, so a value copied out of a shell prompt still works.
func ParseHost(s string) (Host, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Host{}, fmt.Errorf("client: empty engine address")
	}
	if strings.HasPrefix(raw, `\\`) {
		return Host{Scheme: SchemeNamedPipe, Addr: pipePath(raw), Raw: raw}, nil
	}
	if strings.HasPrefix(raw, "/") {
		return Host{Scheme: SchemeUnix, Addr: raw, Raw: raw}, nil
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return Host{}, fmt.Errorf("client: %q is not a supported engine address: want unix://, npipe://, tcp:// or wsl://", raw)
	}
	switch strings.ToLower(scheme) {
	case "unix":
		if rest == "" {
			rest = DefaultUnixSocket
		}
		if !strings.HasPrefix(rest, "/") {
			rest = "/" + rest
		}
		return Host{Scheme: SchemeUnix, Addr: rest, Raw: raw}, nil
	case "npipe":
		return Host{Scheme: SchemeNamedPipe, Addr: pipePath(rest), Raw: raw}, nil
	case "wsl":
		distro, sock := splitDistro(rest)
		if distro == "" {
			distro = defaultDistro()
		}
		return Host{Scheme: SchemeWSL, Addr: distro, SocketPath: sock, Raw: raw}, nil
	case "tcp", "http":
		addr, err := hostPort(rest, DefaultTCPPort)
		if err != nil {
			return Host{}, err
		}
		return Host{Scheme: SchemeTCP, Addr: addr, Raw: raw}, nil
	case "https":
		addr, err := hostPort(rest, DefaultTLSPort)
		if err != nil {
			return Host{}, err
		}
		return Host{Scheme: SchemeTCP, Addr: addr, TLS: true, Raw: raw}, nil
	case "fd":
		return Host{}, fmt.Errorf("client: socket activation (%q) is not supported; use unix://", raw)
	case "ssh":
		return Host{}, fmt.Errorf("client: ssh:// engine addresses are not supported; forward the socket yourself and use unix://")
	default:
		return Host{}, fmt.Errorf("client: unsupported engine address scheme %q in %q", scheme, raw)
	}
}

// pipePath normalises the tail of an npipe:// address into the Windows
// \\.\pipe\name form. Both npipe:////./pipe/x and npipe://./pipe/x are seen in
// the wild, and url parsing splits them differently, so this works on the raw
// remainder instead. The leading \\ is load-bearing: CreateFile rejects a
// single-backslash pipe path.
func pipePath(rest string) string {
	p := strings.ReplaceAll(rest, "/", `\`)
	p = strings.TrimLeft(p, `\`)
	p = strings.TrimPrefix(p, `.\`)
	if !strings.HasPrefix(strings.ToLower(p), `pipe\`) {
		p = `pipe\` + p
	}
	return `\\.\` + p
}

// splitDistro separates a WSL distro name from an optional socket path.
func splitDistro(rest string) (distro, socket string) {
	rest = strings.TrimPrefix(rest, "/")
	distro, tail, ok := strings.Cut(rest, "/")
	if !ok || tail == "" {
		return distro, DefaultUnixSocket
	}
	return distro, "/" + strings.TrimPrefix(tail, "/")
}

// defaultDistro reads $HULL_DISTRO, falling back to the built-in name.
func defaultDistro() string {
	if v := strings.TrimSpace(os.Getenv(EnvDistro)); v != "" {
		return v
	}
	return DefaultDistro
}

// hostPort fills in a default port and strips any trailing path, which curl
// habits tend to add.
func hostPort(rest, defaultPort string) (string, error) {
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", fmt.Errorf("client: tcp engine address has no host")
	}
	// An IPv6 literal must stay bracketed; only add a port when there is none.
	if strings.HasPrefix(rest, "[") {
		if strings.Contains(rest, "]:") {
			return rest, nil
		}
		return rest + ":" + defaultPort, nil
	}
	if strings.Contains(rest, ":") {
		return rest, nil
	}
	return rest + ":" + defaultPort, nil
}
