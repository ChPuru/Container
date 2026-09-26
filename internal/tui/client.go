package tui

import (
	"context"
	"time"

	"github.com/ChPuru/hull/internal/types"
)

// Client is the engine-facing surface the dashboard consumes.
//
// It is an interface, and a deliberately narrow one, for two reasons. The
// dashboard has to build for windows as well as linux, so it cannot reach into
// the engine or any package that touches a namespace; and a dashboard that
// depended on the concrete transport could not be tested without one.
// [EngineClient] implements it over hull's HTTP client, which is what [Run]
// installs; a test implements it directly.
//
// Every method takes a context and must return when it is cancelled. The three
// streaming methods - [Client.Logs], [Client.Stats] and [Client.Events] -
// deliver through a callback rather than a channel, matching the engine's own
// stats and log APIs, and return nil when the context ends. A callback that
// returns an error stops the stream and that error is returned.
type Client interface {
	// Info reports engine identity, container counts and host warnings.
	// The dashboard polls it, so it must be cheap.
	Info(ctx context.Context) (Info, error)

	// Containers lists every container, running or not.
	Containers(ctx context.Context) ([]types.Container, error)

	// Inspect returns the full record for one container, by id or name.
	Inspect(ctx context.Context, idOrName string) (types.Container, error)

	// Logs streams a container's log to fn. With Follow set it runs until
	// the context is cancelled.
	Logs(ctx context.Context, idOrName string, opts LogOptions, fn func(LogLine) error) error

	// Stats streams resource samples for one container to fn until the
	// context is cancelled.
	Stats(ctx context.Context, idOrName string, fn func(types.Stats) error) error

	// Events streams the engine event bus to fn until the context is
	// cancelled.
	Events(ctx context.Context, fn func(types.Event) error) error

	// Start starts a created or exited container.
	Start(ctx context.Context, idOrName string) error
	// Stop sends the stop signal and then kills after the container's own
	// timeout.
	Stop(ctx context.Context, idOrName string) error
	// Restart stops and starts a container.
	Restart(ctx context.Context, idOrName string) error
	// Pause freezes a running container.
	Pause(ctx context.Context, idOrName string) error
	// Unpause thaws a paused container.
	Unpause(ctx context.Context, idOrName string) error
	// Remove deletes a container, killing it first when force is set.
	Remove(ctx context.Context, idOrName string, force bool) error
}

// DiskReporter is an optional capability: a [Client] that can report free
// space on the engine's data root implements it, and the status bar shows the
// figure. Without it the status bar says so rather than guessing, because on
// Windows the data root lives inside the WSL distro and is not something the
// client process can stat.
type DiskReporter interface {
	// DiskUsage reports free and total bytes on the engine's data root.
	DiskUsage(ctx context.Context) (DiskUsage, error)
}

// WarningReporter is an optional capability: a [Client] that can report the
// per-container warnings the engine recorded at create time implements it.
//
// These are not cosmetic. bundle.Generate returns warnings instead of failing
// when a resource limit cannot be enforced on this host's hybrid cgroups, so a
// container with --memory 512m may be running with no memory limit at all. The
// dashboard marks such a container in the list and prints the warnings at the
// top of its inspect tab; a user who never sees them silently gets unlimited
// containers.
type WarningReporter interface {
	// Warnings returns the warnings recorded for one container.
	Warnings(ctx context.Context, idOrName string) ([]string, error)
}

// Info is what the status bar needs to describe the engine and the host. It
// mirrors the engine's own info payload; a client adapter copies the fields
// across.
type Info struct {
	// Version is the engine's version string.
	Version string
	// APIVersion is the Docker Engine API version the engine serves.
	APIVersion string
	// Name is the engine host's name.
	Name string
	// DataRoot is the engine's data directory.
	DataRoot string
	// Containers and the three per-state counters describe the container
	// population.
	Containers        int
	ContainersRunning int
	ContainersPaused  int
	ContainersStopped int
	// Images is how many images the local store holds.
	Images int
	// Runtime is the default runtime, and OCIVersion the runtime-spec
	// version hull writes into bundles after negotiating with it.
	Runtime    string
	OCIVersion string
	// CgroupVersion is the host's cgroup mode, and CgroupV2Delegated
	// reports whether the unified hierarchy actually offers the controllers
	// hull needs. False is the normal answer on a stock WSL host and is the
	// single most important thing on the status bar.
	CgroupVersion     string
	CgroupV2Delegated bool
	// KernelVersion and OperatingSystem describe the host.
	KernelVersion   string
	OperatingSystem string
	// Warnings are the host problems hull doctor would report.
	Warnings []string
}

// DiskUsage is free and total space on a filesystem.
type DiskUsage struct {
	// Path is the directory the figures are for.
	Path string
	// Free and Total are in bytes. A zero Total means the figure is not
	// available, and the status bar prints a dash rather than "0B free".
	Free, Total uint64
}

// Known reports whether the usage figures carry any information.
func (d DiskUsage) Known() bool { return d.Total > 0 }

// LogOptions selects which part of a container's log to read. It mirrors the
// options the engine's log tailer takes.
type LogOptions struct {
	// Tail is how many existing lines to replay before following; zero
	// means none and a negative value means all of them.
	Tail int
	// Follow keeps the stream open and delivers new lines as they arrive.
	Follow bool
	// Since and Until bound the range; zero values mean unbounded.
	Since, Until time.Time
}

// LogLine is one line of container output.
type LogLine struct {
	// Time is when the line was written.
	Time time.Time
	// Stream is "stdout" or "stderr".
	Stream string
	// Line is the text, without its trailing newline.
	Line string
}

// ExecFunc opens an interactive shell in a container. The dashboard suspends
// itself - cooked mode, cursor back, alternate screen left - calls this with
// the terminal handed back to the user, and restores itself when it returns,
// so the function may run a child process on the real stdin and stdout.
//
// It is a hook rather than a [Client] method because handing a child process
// the real terminal has nothing to do with talking to the engine, and because
// a caller with its own exec plumbing - the CLI's "hull exec -it", with its
// detach keys - should be able to reuse it rather than meet a second
// implementation here. [ExecShell] is the default, installed by [Run].
type ExecFunc func(ctx context.Context, c types.Container) error
