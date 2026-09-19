package wslbridge

import (
	"log/slog"
	"net"
)

// Buffer sizes for a pipe instance. These are advisory: Windows grows a pipe's
// buffers on demand, but a sensible starting size keeps a busy `docker pull`
// from round-tripping the kernel for every few kilobytes.
const (
	// DefaultPipeInBuffer is the suggested inbound buffer per pipe instance.
	DefaultPipeInBuffer = 64 * 1024
	// DefaultPipeOutBuffer is the suggested outbound buffer per pipe instance.
	DefaultPipeOutBuffer = 64 * 1024
)

// PipeConfig configures a named-pipe listener.
type PipeConfig struct {
	// Name is the full pipe name, e.g. \\.\pipe\hull_engine.
	Name string

	// SDDL is the security descriptor in string form. Empty means the
	// descriptor PipeSDDL builds for the current user.
	SDDL string

	// InBufferSize and OutBufferSize are the per-instance buffer hints. Zero
	// means the DefaultPipe*Buffer constants.
	InBufferSize  uint32
	OutBufferSize uint32

	// RequireFirstInstance creates the first instance with
	// FILE_FLAG_FIRST_PIPE_INSTANCE, so claiming a name another process already
	// owns fails with ErrPipeInUse instead of silently adding an instance to
	// somebody else's pipe. It is how hull decides whether \\.\pipe\docker_engine
	// is free, and it defaults to on for exactly that reason.
	RequireFirstInstance bool

	// Logger receives listener diagnostics. Zero means a discarding logger.
	Logger *slog.Logger
}

// withDefaults fills in the zero fields.
func (p PipeConfig) withDefaults() PipeConfig {
	if p.Name == "" {
		p.Name = DefaultPipeName
	}
	if p.InBufferSize == 0 {
		p.InBufferSize = DefaultPipeInBuffer
	}
	if p.OutBufferSize == 0 {
		p.OutBufferSize = DefaultPipeOutBuffer
	}
	if p.Logger == nil {
		p.Logger = discardLogger()
	}
	return p
}

// PipeSDDL builds the security descriptor hull's named pipes are created with.
//
//	D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;<user SID>)
//
// Read it left to right: a protected DACL (P) that inherits nothing, then
// generic-all for SYSTEM (SY) and the local Administrators group (BA) so the
// pipe is manageable, then generic read plus generic write for the user hull is
// running as. Nothing else is named, and because the DACL is protected, nothing
// is inherited either.
//
// The omission is the point. The default descriptor on a named pipe grants
// everyone read access, and this pipe is the Docker Engine API: whoever reaches
// it can start a privileged container inside the engine distro. An empty SID
// yields the SYSTEM-and-Administrators half alone, which is strictly more
// restrictive, so a failure to look the SID up can never widen access.
func PipeSDDL(userSID string) string {
	base := "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if userSID == "" {
		return base
	}
	return base + "(A;;GRGW;;;" + userSID + ")"
}

// pipeAddr is the net.Addr a named-pipe listener and its connections report.
type pipeAddr string

// Network implements net.Addr.
func (a pipeAddr) Network() string { return "npipe" }

// String implements net.Addr.
func (a pipeAddr) String() string { return string(a) }

// ListenPipe serves a Windows named pipe as an ordinary net.Listener.
//
// It is declared here and implemented per platform: on Windows against
// kernel32's CreateNamedPipe and ConnectNamedPipe, and everywhere else as a
// function that returns ErrUnsupportedPlatform, so the code that builds a bridge
// compiles and can be reasoned about on Linux.
func ListenPipe(cfg PipeConfig) (net.Listener, error) {
	return listenPipe(cfg.withDefaults())
}
