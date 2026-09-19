// Package explain narrates every kernel-level step hull takes while it pulls,
// unpacks, mounts, confines and wires up a container.
//
// It exists because the interesting part of a container engine is invisible.
// "docker run" either works or prints a sentence that names none of the four
// syscalls that actually failed. hull's --explain prints the real operation
// and its real arguments, in the order the kernel sees them:
//
//	namespace  clone3(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET)
//	namespace    wrote /proc/4812/uid_map: "0 100000 65536"
//	mount      pivot_root("/var/lib/hull/containers/ab12/merged", ".put_old")
//	cgroup     cpu.max <- "50000 100000"   (--cpus 0.5)
//	seccomp    loaded 342-rule filter, default SCMP_ACT_ERRNO(EPERM)
//
// That makes hull a teaching tool as well as an engine, and it is the fastest
// way to find out why a container will not start.
//
// The tracer travels on a context.Context so no subsystem needs a new
// parameter, and the default - Nop - costs an interface call into four empty
// method bodies. Tracing is a diagnostic, never a dependency: a Tracer never
// returns an error, never blocks on anything but its writer, and a failed
// write is dropped rather than propagated into the engine.
//
// A Tracer is safe for concurrent use. Lines are assembled in full and written
// with a single Write call under a mutex, so two goroutines can never splice
// one line into another.
package explain

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Kind labels a step with the kernel subsystem it belongs to. It is printed as
// the first column of every line, so the eye can follow one subsystem down the
// page without reading the prose.
type Kind string

// The subsystems hull narrates. They are deliberately the kernel's own
// vocabulary rather than Docker's: a reader who follows an --explain trace
// should be able to reproduce it with strace.
const (
	// KindImage covers registry and content-store work: manifests, blobs,
	// digest verification.
	KindImage Kind = "image"
	// KindSnapshot covers the overlayfs snapshotter: ChainIDs, layer
	// extraction, commits.
	KindSnapshot Kind = "snapshot"
	// KindMount covers mount(2), the fd-based mount API, pivot_root and
	// umount2.
	KindMount Kind = "mount"
	// KindNamespace covers clone3, unshare, setns and the id maps written
	// through /proc.
	KindNamespace Kind = "namespace"
	// KindCgroup covers cgroup v2 directory creation and controller writes.
	KindCgroup Kind = "cgroup"
	// KindSeccomp covers the compiled BPF filter and its default action.
	KindSeccomp Kind = "seccomp"
	// KindCap covers capability set arithmetic and no_new_privs.
	KindCap Kind = "cap"
	// KindNetwork covers netlink, nftables, veth pairs, IPAM and the
	// userland port proxy.
	KindNetwork Kind = "network"
	// KindProcess covers execve, the process spec, rlimits and the pty.
	KindProcess Kind = "process"
	// KindSignal covers pidfd_send_signal, stop timeouts and cgroup.kill.
	KindSignal Kind = "signal"
)

// String returns the kind as it is printed.
func (k Kind) String() string { return string(k) }

// Tracer receives the narration. Every method is a no-op on the tracer
// returned by Nop, which is what an untraced engine uses, so call sites never
// need to test for nil.
type Tracer interface {
	// Step records one kernel-level operation. format and args are
	// fmt.Sprintf's, and the line is printed at the current Enter depth.
	Step(kind Kind, format string, args ...any)
	// Detail records a supporting key/value under the previous step. It is
	// printed only when Options.Verbose is set, so a call site may narrate
	// as finely as it likes without drowning the default output.
	Detail(k, v string)
	// Enter opens a named scope: everything traced until the returned
	// function is called is indented one level further. The returned
	// function is idempotent, so "defer tr.Enter(name)()" is safe even on a
	// path that also closes the scope explicitly.
	Enter(name string) func()
	// Err records a failure. A nil error prints nothing, so a call site can
	// hand it any error value unconditionally.
	Err(error)
}

// Options configure a Tracer created by New.
type Options struct {
	// Color wraps the kind column in ANSI colour. Callers should set it
	// only for a terminal; hull's CLI drops it for a non-TTY stdout.
	Color bool
	// Timestamps prefixes every line with a wall-clock stamp, which is what
	// you want when correlating a trace against dmesg or a packet capture.
	Timestamps bool
	// Verbose prints the Detail lines and the elapsed time of every scope
	// closed by Enter. Without it the trace is one line per real operation.
	Verbose bool
}

// New returns a Tracer writing to w. A nil w yields Nop, so a caller that has
// not opened its output yet can still pass the result around.
//
// Write errors are dropped: a trace must never turn a working container into a
// failed one.
func New(w io.Writer, opts Options) Tracer {
	if w == nil {
		return Nop()
	}
	return &tracer{w: w, opts: opts, now: time.Now}
}

// Nop returns the tracer that narrates nothing. It is the default everywhere,
// allocates nothing, and is the value FromContext hands back when no tracer
// was installed.
func Nop() Tracer { return nopTracer }

// OrNop returns t, or Nop when t is nil. It exists so a struct field of type
// Tracer can be left unset by callers that do not want a trace and still be
// used at the call site in one expression.
func OrNop(t Tracer) Tracer {
	if t == nil {
		return Nop()
	}
	return t
}

// Enabled reports whether t will actually print anything. Use it to guard an
// argument that is expensive to compute - reading a proc file purely to
// narrate it - never to guard an ordinary Step.
func Enabled(t Tracer) bool {
	if t == nil {
		return false
	}
	_, isNop := t.(nop)
	return !isNop
}

// ctxKey is the unexported context key type, so no other package can collide
// with it or overwrite the tracer.
type ctxKey struct{}

// WithTracer returns a context carrying t. A nil t installs Nop, so the
// context always answers FromContext with a usable value.
func WithTracer(ctx context.Context, t Tracer) context.Context {
	return context.WithValue(ctx, ctxKey{}, OrNop(t))
}

// FromContext returns the Tracer installed by WithTracer, or Nop. It never
// returns nil, which is what lets every instrumented call site be a single
// unguarded line.
func FromContext(ctx context.Context) Tracer {
	if ctx == nil {
		return Nop()
	}
	if t, ok := ctx.Value(ctxKey{}).(Tracer); ok && t != nil {
		return t
	}
	return Nop()
}

// ---------- the no-op tracer ----------

// nop narrates nothing. It is a zero-width struct so Nop's return value is a
// constant interface value rather than an allocation.
type nop struct{}

// noopExit is returned by nop.Enter. It is a package-level value so entering a
// scope on an untraced engine allocates nothing at all.
var noopExit = func() {}

// Step implements Tracer by doing nothing.
func (nop) Step(Kind, string, ...any) {}

// Detail implements Tracer by doing nothing.
func (nop) Detail(string, string) {}

// Enter implements Tracer by returning a shared empty closure.
func (nop) Enter(string) func() { return noopExit }

// Err implements Tracer by doing nothing.
func (nop) Err(error) {}

// nopTracer is the single shared no-op value.
var nopTracer Tracer = nop{}

// ---------- the writing tracer ----------

// kindWidth is the width of the first column. It is the length of the longest
// Kind ("namespace"), so every line's text starts in the same place and a
// trace reads as a table.
const kindWidth = 9

// Layout constants for one line.
const (
	// gutter separates the kind column from the indented text.
	gutter = "  "
	// indentUnit is one level of Enter depth.
	indentUnit = "  "
	// stampFmt is the Options.Timestamps prefix.
	stampFmt = "15:04:05.000"
)

// Markers for the scope lines Enter writes, and the label Err writes. They are
// ASCII because a trace is read as often through a Windows console and a piped
// log file as through a modern terminal.
const (
	enterMarker = "+ "
	exitMarker  = "- "
	errLabel    = "error"
)

// ANSI colours. Only the first column, the scope lines and the error text are
// coloured: the operations themselves are quoted kernel arguments and must
// survive being copied out of the terminal.
const (
	ansiReset = "\x1b[0m"
	ansiDim   = "\x1b[2m"
	ansiBold  = "\x1b[1m"
	ansiRed   = "\x1b[31m"
)

// kindColor maps a kind to its ANSI colour. A kind with no entry prints
// uncoloured, so an unknown kind degrades to plain text rather than to an
// escape sequence nobody meant.
var kindColor = map[Kind]string{
	KindImage:     "\x1b[36m", // cyan
	KindSnapshot:  "\x1b[36m",
	KindMount:     "\x1b[34m", // blue
	KindNamespace: "\x1b[35m", // magenta
	KindCgroup:    "\x1b[33m", // yellow
	KindSeccomp:   ansiRed,    // red: this is the confinement column
	KindCap:       ansiRed,
	KindNetwork:   "\x1b[32m", // green
	KindProcess:   ansiBold,
	KindSignal:    "\x1b[33m",
}

// tracer is the writing implementation. w, opts and now are fixed at
// construction; depth is guarded by mu, and mu also serialises the writes.
type tracer struct {
	w    io.Writer
	opts Options
	now  func() time.Time

	mu    sync.Mutex
	depth int
}

// Step implements Tracer.
func (t *tracer) Step(kind Kind, format string, args ...any) {
	text := format
	if len(args) > 0 {
		text = fmt.Sprintf(format, args...)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.emit(string(kind), kindColor[kind], 0, text)
}

// Detail implements Tracer. It prints nothing unless Options.Verbose is set.
func (t *tracer) Detail(k, v string) {
	if !t.opts.Verbose {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.emit("", ansiDim, 1, k+" = "+v)
}

// Enter implements Tracer. The exit line, with the elapsed time, is printed
// only when Options.Verbose is set.
func (t *tracer) Enter(name string) func() {
	t.mu.Lock()
	t.emit("", ansiBold, 0, enterMarker+name)
	t.depth++
	t.mu.Unlock()

	started := t.now()
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.depth > 0 {
				t.depth--
			}
			if t.opts.Verbose {
				elapsed := t.now().Sub(started).Round(time.Microsecond)
				t.emit("", ansiDim, 0, exitMarker+name+" ("+elapsed.String()+")")
			}
		})
	}
}

// Err implements Tracer.
func (t *tracer) Err(err error) {
	if err == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.emit(errLabel, ansiRed, 0, err.Error())
}

// emit assembles one whole line and writes it with a single Write. The caller
// must hold t.mu.
//
// A line is: the optional timestamp, the kind column padded to kindWidth, the
// gutter, two spaces per level of Enter depth (plus extra), then the text. A
// line with an empty label - a Detail or a scope marker - keeps the same
// column, which is what makes a trace line up.
func (t *tracer) emit(label, color string, extra int, text string) {
	var b strings.Builder
	b.Grow(len(label) + len(text) + 32)
	if t.opts.Timestamps {
		b.WriteString(t.now().Format(stampFmt))
		b.WriteByte(' ')
	}
	colored := t.opts.Color && color != ""
	if colored && label != "" {
		b.WriteString(color)
		b.WriteString(label)
		b.WriteString(ansiReset)
	} else {
		b.WriteString(label)
	}
	for i := len(label); i < kindWidth; i++ {
		b.WriteByte(' ')
	}
	b.WriteString(gutter)
	for i := 0; i < t.depth+extra; i++ {
		b.WriteString(indentUnit)
	}
	if colored && label == "" {
		b.WriteString(color)
		b.WriteString(text)
		b.WriteString(ansiReset)
	} else {
		b.WriteString(text)
	}
	b.WriteByte('\n')
	_, _ = io.WriteString(t.w, b.String())
}
