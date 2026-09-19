package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rahuldhali/hull/internal/client"
	"github.com/rahuldhali/hull/internal/types"
)

// ErrNotTerminal is returned by [Run] when standard input or standard output
// is not a terminal. Piping the dashboard somewhere is a mistake worth
// naming: "hull ps" and "hull events" are the commands for that.
var ErrNotTerminal = errors.New("tui: stdin and stdout must be a terminal")

// Default timings. They are the ones that make the dashboard feel live without
// making it expensive: the engine is polled once a second, and the screen is
// diffed and flushed at most twenty times a second so a burst of log lines
// coalesces into one frame instead of twenty.
const (
	// DefaultPollInterval is how often the container list and engine info
	// are re-read.
	DefaultPollInterval = time.Second
	// DefaultFrameInterval is the shortest gap between two frames.
	DefaultFrameInterval = 50 * time.Millisecond
	// DefaultLogTail is how many existing log lines are replayed when the
	// logs tab follows a container.
	DefaultLogTail = 200
	// commandTimeout bounds a lifecycle action taken from the dashboard, so
	// a container that will not stop cannot wedge the key that asked.
	commandTimeout = 2 * time.Minute
)

// Options configures [Run]. The zero value is valid and uses the defaults
// above with the process's own standard input and output.
type Options struct {
	// In and Out are the terminal. Both default to the process's own and
	// both must be a terminal.
	In  *os.File
	Out *os.File
	// PollInterval is how often the container list is refreshed.
	PollInterval time.Duration
	// FrameInterval is the shortest gap between two frames.
	FrameInterval time.Duration
	// StatsHistory is how many samples the sparklines keep; it defaults to
	// [DefaultStatsHistory], which is one minute at one sample a second.
	StatsHistory int
	// LogTail is how many existing log lines to replay per container.
	LogTail int
	// NoColor selects the monochrome theme, for a terminal without colour
	// or a user who asked for none.
	NoColor bool
	// Theme overrides the style set entirely.
	Theme *Theme
	// Filter is the initial container filter.
	Filter string
	// Tab is the detail tab to open on.
	Tab DetailTab
	// Exec opens an interactive shell in a container, for the "e" key. The
	// dashboard suspends itself around the call. When it is nil the key
	// says so rather than doing nothing.
	Exec ExecFunc
	// Now returns the current time; tests substitute it.
	Now func() time.Time
}

// withDefaults fills in the unset fields.
func (o Options) withDefaults() Options {
	if o.In == nil {
		o.In = os.Stdin
	}
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.PollInterval <= 0 {
		o.PollInterval = DefaultPollInterval
	}
	if o.FrameInterval <= 0 {
		o.FrameInterval = DefaultFrameInterval
	}
	if o.StatsHistory <= 0 {
		o.StatsHistory = DefaultStatsHistory
	}
	if o.LogTail == 0 {
		o.LogTail = DefaultLogTail
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Run draws the dashboard against a hull engine until the user quits, the
// context is cancelled or the terminal breaks. It returns nil for all three:
// quitting is not an error, and neither is a cancelled context.
//
// It is the entry point "hull ui" calls. With no [Options.Exec] set it
// installs [ExecShell], so the "e" key opens a shell in the selected container
// without the caller wiring anything up.
func Run(ctx context.Context, c *client.Client, opts Options) error {
	if c == nil {
		return errors.New("tui: nil client")
	}
	if opts.Exec == nil {
		opts.Exec = ExecShell(c)
	}
	return RunWith(ctx, NewEngineClient(c), opts)
}

// RunWith draws the dashboard against any [Client]. It is what [Run] is built
// on, and it is the seam a test - or an in-process engine that has no reason
// to speak HTTP to itself - uses instead of the HTTP client.
//
// RunWith owns the terminal for its lifetime. It switches to the alternate
// screen buffer, so the user's scrollback comes back untouched, and it
// restores cooked mode, the cursor and the primary buffer from three places -
// the deferred cleanup, a SIGINT/SIGTERM handler and a panic recovery -
// because there is no acceptable path out of here that leaves a wrecked
// terminal.
func RunWith(ctx context.Context, c Client, opts Options) error {
	if c == nil {
		return errors.New("tui: nil client")
	}
	opts = opts.withDefaults()

	t, err := newTerminal(opts.In, opts.Out)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The signal handler restores the terminal itself rather than only
	// cancelling: a second signal, or a render loop wedged on a write to a
	// terminal that has gone away, must not be able to leave the user in
	// raw mode.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		select {
		case <-sigs:
			t.leave()
			cancel()
		case <-ctx.Done():
		}
	}()

	if err := t.enter(); err != nil {
		return err
	}
	defer t.leave()
	defer func() {
		if p := recover(); p != nil {
			t.leave()
			panic(p)
		}
	}()

	r := &runner{client: c, opts: opts, term: t, msgs: make(chan msg, 512)}
	return r.loop(ctx)
}

// runner is one dashboard session: the model, the renderer, the terminal and
// the single channel every data source feeds.
type runner struct {
	client Client
	opts   Options
	term   *terminal

	model  *Model
	render *Renderer
	buf    Buffer
	msgs   chan msg
	keys   *keyReader

	watchID     string
	watchCancel context.CancelFunc

	lastPaint time.Time
}

// loop starts the data sources and runs the render loop.
func (r *runner) loop(ctx context.Context) error {
	w, h, err := r.term.size()
	if err != nil || w <= 0 || h <= 0 {
		// A terminal that will not report its size is still usable at
		// the classic default, and saying so beats refusing to start.
		w, h = 80, 24
	}

	r.model = NewModel()
	r.model.Now = r.opts.Now
	r.model.StatsHistory = r.opts.StatsHistory
	switch {
	case r.opts.Theme != nil:
		r.model.Theme = *r.opts.Theme
	case r.opts.NoColor:
		r.model.Theme = MonoTheme()
	}
	r.model.SetTab(r.opts.Tab)
	r.model.SetFilter(r.opts.Filter)
	r.model.SetSize(w, h)

	r.render = NewRenderer(r.term.out)
	if r.opts.NoColor {
		r.render.SetNoColor(true)
	}
	r.buf = NewBuffer(w, h)

	r.keys = newKeyReader(r.term.in, r.msgs)
	go r.keys.run(ctx)
	go watchResize(ctx, r.term, r.msgs)
	go pollContainers(ctx, r.client, r.opts.PollInterval, r.msgs)
	go streamEvents(ctx, r.client, r.msgs)
	defer func() {
		if r.watchCancel != nil {
			r.watchCancel()
		}
	}()

	frame := time.NewTicker(r.opts.FrameInterval)
	defer frame.Stop()

	dirty := true
	for {
		select {
		case <-ctx.Done():
			return nil
		case m := <-r.msgs:
			quit := r.handle(ctx, m)
			if quit {
				return nil
			}
			r.watchSelection(ctx)
			dirty = true
		case <-frame.C:
			// Uptimes and the toast expiry move with the clock, so
			// repaint at least once a second even when the engine
			// has said nothing.
			if !dirty && r.opts.Now().Sub(r.lastPaint) < time.Second {
				continue
			}
			if err := r.paint(); err != nil {
				return err
			}
			dirty = false
		}
	}
}

// handle folds one message into the model and reports whether the dashboard
// should quit.
func (r *runner) handle(ctx context.Context, m msg) bool {
	switch m.kind {
	case msgContainers:
		r.model.SetContainers(m.containers)
	case msgInfo:
		r.model.SetInfo(m.info)
	case msgDisk:
		r.model.SetDiskUsage(m.disk)
	case msgEvent:
		r.model.AddEvent(m.event)
		// An event about the selected container means its record has
		// changed, so refresh the inspect tab rather than showing a
		// state the engine has already moved past.
		if m.event.Actor.ID != "" && m.event.Actor.ID == r.watchID {
			go inspectContainer(ctx, r.client, r.watchID, r.msgs)
		}
	case msgStats:
		r.model.AddStats(m.id, m.stats)
	case msgLog:
		r.model.AddLog(m.id, m.log)
	case msgLogReset:
		r.model.ClearLogs(m.id)
	case msgInspect:
		// A reply for a container the user has already moved off would
		// leave the pane saying "inspecting..." until the new one lands.
		if m.id == r.watchID {
			r.model.SetInspect(m.id, m.container)
		}
	case msgWarnings:
		r.model.SetWarnings(m.id, m.warnings)
	case msgToast:
		r.model.Toast(m.text, r.model.Theme.Base)
	case msgError:
		r.model.Error(m.err)
	case msgResize:
		r.resize(m.w, m.h)
	case msgKey:
		return r.key(ctx, m.key)
	}
	return false
}

// resize re-lays out for a new terminal size and forces a full repaint, since
// nothing is known about what the terminal did with the old frame.
func (r *runner) resize(w, h int) {
	if w <= 0 || h <= 0 {
		return
	}
	r.model.SetSize(w, h)
	r.buf = NewBuffer(w, h)
	r.render.Reset()
}

// key applies one keystroke and carries out whatever the model asked for.
func (r *runner) key(ctx context.Context, k Key) bool {
	cmd := r.model.Apply(k)
	switch cmd.Kind {
	case CmdNone:
	case CmdQuit:
		return true
	case CmdRedraw:
		r.render.Reset()
	case CmdExec:
		r.runExec(ctx, cmd.Container)
	default:
		go r.execute(ctx, cmd)
	}
	return false
}

// execute runs one lifecycle command against the engine, off the render loop,
// and reports the outcome back through the message channel.
func (r *runner) execute(ctx context.Context, cmd Command) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	id := cmd.Container.ID
	name := cmd.Container.Name
	var (
		err  error
		verb string
	)
	switch cmd.Kind {
	case CmdStart:
		verb, err = "started", r.client.Start(ctx, id)
	case CmdStop:
		verb, err = "stopped", r.client.Stop(ctx, id)
	case CmdRestart:
		verb, err = "restarted", r.client.Restart(ctx, id)
	case CmdPause:
		verb, err = "paused", r.client.Pause(ctx, id)
	case CmdUnpause:
		verb, err = "unpaused", r.client.Unpause(ctx, id)
	case CmdRemove:
		verb, err = "removed", r.client.Remove(ctx, id, cmd.Force)
	default:
		return
	}
	if err != nil {
		send(ctx, r.msgs, msg{kind: msgError, err: fmt.Errorf("%s: %w", name, err)})
		return
	}
	send(ctx, r.msgs, msg{kind: msgToast, text: verb + " " + name})
}

// runExec suspends the dashboard, hands the terminal to an interactive shell
// in the container, and takes it back afterwards.
//
// It runs on the render loop rather than in a goroutine on purpose: while the
// child owns the terminal nothing else may draw on it, and the loop blocking
// here is exactly the behaviour that guarantees that.
func (r *runner) runExec(ctx context.Context, c types.Container) {
	if r.opts.Exec == nil {
		r.model.Toast("no exec handler: run hull exec -it "+c.Name+" sh", r.model.Theme.Warn)
		return
	}
	r.keys.pause()
	r.term.suspend()

	err := r.opts.Exec(ctx, c)

	if rerr := r.term.resume(); rerr != nil {
		// The terminal could not be taken back. Report it upward rather
		// than drawing into a terminal that is not in the state the
		// renderer assumes.
		r.model.Error(rerr)
	}
	r.keys.resume()
	r.render.Reset()
	if err != nil && !errors.Is(err, context.Canceled) {
		r.model.Error(fmt.Errorf("exec %s: %w", c.Name, err))
	}
}

// watchSelection restarts the per-container streams when the selection moves.
// One stats stream, one log tail and one inspect per selected container is the
// whole cost, and the previous container's goroutines are cancelled before the
// new ones start.
func (r *runner) watchSelection(ctx context.Context) {
	id := r.model.SelectedID()
	if id == r.watchID {
		return
	}
	if r.watchCancel != nil {
		r.watchCancel()
		r.watchCancel = nil
	}
	r.watchID = id
	if id == "" {
		return
	}
	wctx, cancel := context.WithCancel(ctx)
	r.watchCancel = cancel
	go streamStats(wctx, r.client, id, r.msgs)
	go tailLogs(wctx, r.client, id, r.opts.LogTail, r.msgs)
	go inspectContainer(wctx, r.client, id, r.msgs)
}

// paint renders one frame and flushes the difference to the terminal.
func (r *runner) paint() error {
	r.model.Refresh()
	r.model.Render(r.buf)
	if err := r.render.Render(r.buf); err != nil {
		return err
	}
	r.lastPaint = r.opts.Now()
	return nil
}
