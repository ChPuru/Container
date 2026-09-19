// Package foldersync keeps a Windows folder and a hull volume in step, in both
// directions, so that hot reload works against an engine that lives inside
// WSL2.
//
// It exists because of two measured facts about the WSL2 file boundary.
//
//   - Reaching a Windows folder from Linux through /mnt/c goes over the 9p
//     (or virtio-fs) redirector. Writes run roughly 7x slower than the same
//     work on the VM's own ext4 disk, and metadata operations - the stat storm
//     every bundler, compiler and test watcher performs - roughly 60x slower.
//     Bind-mounting /mnt/c/... into a container is therefore the single
//     biggest source of "why is this so slow" on a WSL-hosted engine.
//   - Edits made on the *Windows* side of that boundary raise no inotify
//     events inside WSL at all. Nothing in the VM is told that the file
//     changed, so every watcher in every dev server - nodemon, vite, air,
//     webpack, pytest-watch - simply never fires. Hot reload does not
//     degrade; it stops existing.
//
// So hull does not bind /mnt/c. It copies the project into a volume on the
// VM's own disk, where the container gets native ext4 speed and real inotify
// events, and keeps the two sides reconciled: the volume side with inotify
// (see the Linux watcher), the Windows side by polling, because there is
// nothing else to poll with.
//
// The polling side is deliberately cheap when nothing is happening: the
// interval backs off exponentially from PollInterval to MaxPollInterval while
// the tree is quiet, and snaps back the moment anything moves. An idle project
// costs one directory walk every few seconds.
//
// Conflicts - the same path changed on both sides since the last pass - are
// resolved by newest mtime, but never silently: a Conflict event names both
// sides and their timestamps, and the losing copy is kept beside the winner as
// "<name>.hull-conflict-<timestamp>" whenever it had anything in it.
//
// Ignore patterns are gitignore-shaped and seeded with the directories that
// make the difference between usable and unusable - .git, node_modules,
// target, vendor, __pycache__, .venv, dist, build - plus anything in a
// .hullignore or .gitignore at either root.
//
// Paths are always given to this package as the engine sees them. A Windows
// spelling such as C:\Users\me\proj must be translated to /mnt/c/Users/me/proj
// first (internal/volume.TranslateWindowsPath does exactly that); New refuses
// the untranslated form with a message saying so rather than reporting a
// missing directory.
package foldersync

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Defaults for the tunable halves of Config. PollInterval is the floor and
// MaxPollInterval the ceiling of the Windows-side poll backoff.
const (
	// DefaultPollInterval is how often the Windows side is walked while the
	// tree is changing.
	DefaultPollInterval = 500 * time.Millisecond

	// DefaultMaxPollInterval is the longest the backoff will stretch the poll
	// interval to once a tree has gone quiet.
	DefaultMaxPollInterval = 5 * time.Second

	// DefaultDebounce is how long a burst of change notifications is allowed
	// to coalesce before a reconciliation pass runs, so a save that rewrites
	// forty files produces one pass and not forty.
	DefaultDebounce = 150 * time.Millisecond

	// DefaultMTimeTolerance is the slack allowed when comparing the
	// modification times of the two *sides*. DrvFs and ext4 do not agree to
	// the nanosecond about a copied file, and a stricter comparison would copy
	// the same bytes back and forth forever.
	DefaultMTimeTolerance = time.Second
)

// conflictStamp is the timestamp format in a ".hull-conflict-" name. It is
// UTC, sorts lexicographically, and contains no character that is illegal in a
// Windows filename.
const conflictStamp = "20060102T150405.000"

// tmpPrefix names the temporary file a copy lands in before it is renamed into
// place. It is matched by one of the default ignore patterns so the syncer
// never tries to propagate its own debris.
const tmpPrefix = ".hull-sync-tmp-"

// Sentinel errors. Callers should test them with errors.Is.
var (
	// ErrInvalidConfig means New was handed a Config it cannot work with: an
	// empty path, an unknown Direction, or a bad ignore pattern.
	ErrInvalidConfig = errors.New("foldersync: invalid configuration")

	// ErrNotDirectory means one of the two endpoints exists but is not a
	// directory, or does not exist at all.
	ErrNotDirectory = errors.New("foldersync: endpoint is not a directory")

	// ErrOverlap means the two endpoints are the same directory or one
	// contains the other, which would make every copy feed itself.
	ErrOverlap = errors.New("foldersync: host and volume paths overlap")

	// ErrWindowsPath means a path was given in its Windows spelling
	// (C:\Users\me\proj). The engine lives inside the VM and can only see the
	// translated form.
	ErrWindowsPath = errors.New("foldersync: path is a Windows path, not a path the engine can see")

	// ErrUnsupported means the platform cannot provide something this package
	// wanted - in practice, inotify on a non-Linux build. It is never fatal:
	// the volume side falls back to polling.
	ErrUnsupported = errors.New("foldersync: not supported on this platform")
)

// Direction says which of the two endpoints a Syncer is allowed to write.
type Direction int

// The three sync directions.
const (
	// Bidirectional reconciles both ways: whichever side changed wins, and
	// when both changed the newest mtime wins.
	Bidirectional Direction = iota

	// HostToVolume makes the Windows folder the source of truth. The volume is
	// written, never read back. Files that exist only on the volume and were
	// never seen on the host are left alone.
	HostToVolume

	// VolumeToHost makes the volume the source of truth, for the build-output
	// case: the container writes, Windows reads.
	VolumeToHost
)

// String implements fmt.Stringer.
func (d Direction) String() string {
	switch d {
	case Bidirectional:
		return "bidirectional"
	case HostToVolume:
		return "host-to-volume"
	case VolumeToHost:
		return "volume-to-host"
	default:
		return fmt.Sprintf("direction(%d)", int(d))
	}
}

// valid reports whether d is one of the three defined directions.
func (d Direction) valid() bool { return d >= Bidirectional && d <= VolumeToHost }

// Side names one end of the pair.
type Side string

// The two sides.
const (
	// SideHost is the Windows folder, as the engine sees it (/mnt/c/...).
	SideHost Side = "host"

	// SideVolume is the volume directory on the VM's own disk.
	SideVolume Side = "volume"
)

// other returns the opposite side.
func other(s Side) Side {
	if s == SideHost {
		return SideVolume
	}
	return SideHost
}

// Config describes one sync pair.
type Config struct {
	// HostPath is the Windows folder as the engine sees it, e.g.
	// /mnt/c/Users/me/proj. It must exist and be a directory.
	HostPath string

	// VolumePath is the volume's data directory, e.g.
	// /var/lib/hull/volumes/proj/_data. It must exist and be a directory.
	VolumePath string

	// Ignore holds extra gitignore-style patterns, applied after the built-in
	// defaults and after any .hullignore/.gitignore at either root, so a
	// negation here can re-include something the defaults excluded.
	Ignore []string

	// PollInterval is how often the host side is walked while it is changing.
	// Zero selects DefaultPollInterval.
	PollInterval time.Duration

	// Direction selects which sides may be written. The zero value is
	// Bidirectional.
	Direction Direction

	// OnEvent, if set, is called synchronously for every copy, delete,
	// conflict and error. It must not block for long and must not call back
	// into the Syncer.
	OnEvent func(Event)

	// MaxPollInterval caps the idle backoff. Zero selects
	// DefaultMaxPollInterval.
	MaxPollInterval time.Duration

	// Debounce is how long change notifications coalesce before a pass runs.
	// Zero selects DefaultDebounce.
	Debounce time.Duration

	// MTimeTolerance is the slack allowed when comparing the two sides'
	// modification times. Zero selects DefaultMTimeTolerance; a negative value
	// means exact comparison.
	MTimeTolerance time.Duration

	// NoIgnoreFiles suppresses reading .hullignore and .gitignore from the two
	// roots. The built-in defaults and Config.Ignore still apply.
	NoIgnoreFiles bool
}

// EventKind classifies an Event.
type EventKind string

// The kinds of event a Syncer reports.
const (
	// EventCopy is one file, directory or symlink written to Side, read from
	// From.
	EventCopy EventKind = "copy"

	// EventDelete is one path removed from Side because the other side lost
	// it.
	EventDelete EventKind = "delete"

	// EventConflict is one path that changed on both sides since the last
	// pass. Side is the winner, LoserSide the loser, and Kept names the
	// preserved copy when there was one.
	EventConflict EventKind = "conflict"

	// EventSync marks the end of a reconciliation pass; Result carries the
	// totals.
	EventSync EventKind = "sync"

	// EventOverflow means the kernel dropped inotify events (IN_Q_OVERFLOW)
	// and the syncer fell back to a full scan.
	EventOverflow EventKind = "overflow"

	// EventError is a per-path failure. The pass continues; the error is also
	// in Result.Errors.
	EventError EventKind = "error"
)

// Event is one thing a Syncer did, delivered to Config.OnEvent as it happens.
type Event struct {
	// Kind says which of the fields below are meaningful.
	Kind EventKind

	// Time is when the event was produced.
	Time time.Time

	// Path is the slash-separated path relative to both roots. It is empty
	// for EventSync.
	Path string

	// Side is the side written (copy, delete) or the side that won (conflict).
	Side Side

	// From is the side read, for EventCopy.
	From Side

	// Size is the number of bytes copied, for EventCopy of a regular file.
	Size int64

	// HostMTime and VolumeMTime are the two competing timestamps, for
	// EventConflict.
	HostMTime, VolumeMTime time.Time

	// LoserSide is the side that lost a conflict.
	LoserSide Side

	// Kept is the relative path the losing copy was preserved at, on
	// LoserSide. It is empty when the loser was empty and nothing was kept.
	Kept string

	// Result carries the pass totals, for EventSync.
	Result Result

	// Err is the failure, for EventError.
	Err error

	// Message is a short human-readable note; it is always set by the time the
	// event reaches Config.OnEvent.
	Message string
}

// String renders an event as one line, which is what the CLI prints.
func (e Event) String() string {
	switch e.Kind {
	case EventCopy:
		return fmt.Sprintf("copy   %s -> %s  %s", e.From, e.Side, e.Path)
	case EventDelete:
		return fmt.Sprintf("delete %s  %s", e.Side, e.Path)
	case EventConflict:
		if e.Kept != "" {
			return fmt.Sprintf("conflict %s: %s wins (host %s, volume %s); %s copy kept as %s",
				e.Path, e.Side,
				e.HostMTime.Format(time.RFC3339Nano), e.VolumeMTime.Format(time.RFC3339Nano),
				e.LoserSide, e.Kept)
		}
		return fmt.Sprintf("conflict %s: %s wins (host %s, volume %s)",
			e.Path, e.Side,
			e.HostMTime.Format(time.RFC3339Nano), e.VolumeMTime.Format(time.RFC3339Nano))
	case EventError:
		return fmt.Sprintf("error  %s: %v", e.Path, e.Err)
	case EventSync:
		r := e.Result
		return fmt.Sprintf("sync   %d->volume %d->host %d deleted %d conflicts in %s",
			r.ToVolume, r.ToHost, r.DeletedHost+r.DeletedVolume, r.Conflicts, r.Duration.Round(time.Millisecond))
	default:
		return fmt.Sprintf("%-6s %s", string(e.Kind), e.Message)
	}
}

// Result is the tally of one reconciliation pass.
type Result struct {
	// Started is when the pass began, Duration how long it took.
	Started  time.Time
	Duration time.Duration

	// Scanned is the number of entries examined across both trees.
	Scanned int

	// Ignored is the number of entries skipped by the ignore patterns.
	Ignored int

	// ToVolume and ToHost count paths written to each side.
	ToVolume, ToHost int

	// DeletedVolume and DeletedHost count paths removed from each side.
	DeletedVolume, DeletedHost int

	// Conflicts is the number of paths that had changed on both sides.
	Conflicts int

	// Bytes is the number of file bytes copied.
	Bytes int64

	// Errors holds per-path failures. A pass with errors still completes.
	Errors []error
}

// Changed reports whether the pass did anything at all, which is what drives
// the poll backoff.
func (r Result) Changed() bool {
	return r.ToVolume+r.ToHost+r.DeletedVolume+r.DeletedHost+r.Conflicts > 0
}

// Status is a snapshot of a Syncer, safe to read while Run is going.
type Status struct {
	// HostPath and VolumePath are the resolved absolute endpoints.
	HostPath, VolumePath string

	// Direction is the configured direction.
	Direction Direction

	// Running is true between the start and the end of Run.
	Running bool

	// Watching is true when the volume side has a live inotify watch. When it
	// is false the volume side is being polled too.
	Watching bool

	// PollInterval is the host-side interval right now, after backoff.
	PollInterval time.Duration

	// LastSync is when the last pass finished, LastResult its tally.
	LastSync   time.Time
	LastResult Result

	// Syncs, Conflicts and Errors are cumulative since New.
	Syncs, Conflicts, Errors uint64

	// Overflows counts how many times the kernel dropped inotify events and
	// the syncer fell back to a full scan.
	Overflows uint64

	// LastError is the most recent error's text, for a one-line status
	// display.
	LastError string
}

// Syncer reconciles one host/volume pair. It is safe for concurrent use: Sync
// serialises passes against itself and against Run, and Status may be read at
// any time.
type Syncer struct {
	cfg    Config
	host   string
	volume string
	ig     *Ignorer
	tol    time.Duration

	// syncMu serialises reconciliation passes.
	syncMu sync.Mutex

	// prev is the per-side baseline from the end of the last pass. It is what
	// lets the syncer tell "created here" from "deleted there", and it is only
	// touched under syncMu.
	prev map[string]pairState

	// hostPoll walks the host side. It is only touched from Run.
	hostPoll *poller

	// volPoll is the volume-side fallback, used only when inotify is
	// unavailable. It is only touched from Run.
	volPoll *poller

	// watchMu guards watcher, which Run installs and onOverflow re-arms.
	watchMu sync.Mutex
	watcher treeWatcher

	mu     sync.Mutex
	status Status
}

// New validates cfg and returns a Syncer. Both endpoints must already exist
// and be directories; neither may contain the other. The ignore set is built
// here: the built-in defaults, then .hullignore and .gitignore from each root
// (unless Config.NoIgnoreFiles), then Config.Ignore, so later patterns - and
// their negations - win.
func New(cfg Config) (*Syncer, error) {
	host, err := resolveEndpoint(cfg.HostPath, "host")
	if err != nil {
		return nil, err
	}
	volume, err := resolveEndpoint(cfg.VolumePath, "volume")
	if err != nil {
		return nil, err
	}
	if contains(host, volume) || contains(volume, host) {
		return nil, fmt.Errorf("%w: %s and %s", ErrOverlap, host, volume)
	}
	if !cfg.Direction.valid() {
		return nil, fmt.Errorf("%w: unknown direction %d", ErrInvalidConfig, int(cfg.Direction))
	}

	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.MaxPollInterval <= 0 {
		cfg.MaxPollInterval = DefaultMaxPollInterval
	}
	if cfg.MaxPollInterval < cfg.PollInterval {
		cfg.MaxPollInterval = cfg.PollInterval
	}
	if cfg.Debounce <= 0 {
		cfg.Debounce = DefaultDebounce
	}
	tol := cfg.MTimeTolerance
	switch {
	case tol == 0:
		tol = DefaultMTimeTolerance
	case tol < 0:
		tol = 0
	}

	pats := DefaultIgnores()
	if !cfg.NoIgnoreFiles {
		for _, root := range []string{host, volume} {
			for _, name := range []string{".gitignore", ".hullignore"} {
				lines, err := LoadIgnoreFile(filepath.Join(root, name))
				if err != nil {
					return nil, err
				}
				pats = append(pats, lines...)
			}
		}
	}
	pats = append(pats, cfg.Ignore...)
	ig, err := NewIgnorer(pats...)
	if err != nil {
		return nil, err
	}

	s := &Syncer{
		cfg:    cfg,
		host:   host,
		volume: volume,
		ig:     ig,
		tol:    tol,
		prev:   make(map[string]pairState),
	}
	s.hostPoll = newPoller(host, ig, cfg.PollInterval, cfg.MaxPollInterval)
	s.status = Status{
		HostPath:     host,
		VolumePath:   volume,
		Direction:    cfg.Direction,
		PollInterval: cfg.PollInterval,
	}
	return s, nil
}

// Status returns a snapshot of the syncer's state.
func (s *Syncer) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status
	if s.hostPoll != nil {
		st.PollInterval = s.hostPoll.currentInterval()
	}
	return st
}

// HostPath returns the resolved host endpoint.
func (s *Syncer) HostPath() string { return s.host }

// VolumePath returns the resolved volume endpoint.
func (s *Syncer) VolumePath() string { return s.volume }

// Ignorer returns the compiled ignore set, so a caller can explain why a path
// is not being synced.
func (s *Syncer) Ignorer() *Ignorer { return s.ig }

// root returns the absolute root of one side.
func (s *Syncer) root(side Side) string {
	if side == SideHost {
		return s.host
	}
	return s.volume
}

// abs maps a slash-relative path onto one side's real filesystem path.
func (s *Syncer) abs(side Side, rel string) string {
	return filepath.Join(s.root(side), filepath.FromSlash(rel))
}

// canWrite reports whether the configured direction allows writing side.
func (s *Syncer) canWrite(side Side) bool {
	switch s.cfg.Direction {
	case HostToVolume:
		return side == SideVolume
	case VolumeToHost:
		return side == SideHost
	default:
		return true
	}
}

// emit delivers one event to the callback, if there is one.
func (s *Syncer) emit(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if e.Message == "" {
		e.Message = e.String()
	}
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(e)
	}
}

// fail records a per-path error: it goes into the pass result, into the
// cumulative counters and out as an EventError.
func (s *Syncer) fail(res *Result, rel string, err error) {
	res.Errors = append(res.Errors, err)
	s.mu.Lock()
	s.status.Errors++
	s.status.LastError = err.Error()
	s.mu.Unlock()
	s.emit(Event{Kind: EventError, Path: rel, Err: err})
}

// resolveEndpoint cleans, absolutises and checks one endpoint.
func resolveEndpoint(p, what string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("%w: %s path is empty", ErrInvalidConfig, what)
	}
	if looksLikeWindowsPath(p) {
		return "", fmt.Errorf("%w: %s path %q; translate it first (C:\\Users\\me\\proj -> /mnt/c/Users/me/proj)",
			ErrWindowsPath, what, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("%w: %s path %q: %w", ErrInvalidConfig, what, p, err)
	}
	if resolved, rerr := filepath.EvalSymlinks(abs); rerr == nil {
		abs = resolved
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("%w: %s path %q: %w", ErrNotDirectory, what, p, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%w: %s path %q", ErrNotDirectory, what, p)
	}
	return filepath.Clean(abs), nil
}

// looksLikeWindowsPath reports whether p is spelled the Windows way: a
// drive-letter prefix or a UNC path. The check is lexical and exists only to
// produce a better error than "no such directory"; internal/volume owns the
// real translation.
func looksLikeWindowsPath(p string) bool {
	if len(p) >= 2 && p[1] == ':' {
		c := p[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return len(p) == 2 || p[2] == '\\' || p[2] == '/'
		}
	}
	return strings.HasPrefix(p, "\\\\")
}

// contains reports whether parent is child's ancestor, or the same directory.
func contains(parent, child string) bool {
	if parent == child {
		return true
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(child, strings.TrimSuffix(parent, sep)+sep)
}
