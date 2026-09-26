package tui

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/ChPuru/hull/internal/types"
)

// msgKind tags a message on the single channel the render loop consumes.
type msgKind int

// The message kinds. One goroutine per data source produces them and exactly
// one goroutine - the render loop - consumes them, which is the rule that
// keeps the screen single-threaded.
const (
	msgNone msgKind = iota
	msgContainers
	msgInfo
	msgDisk
	msgEvent
	msgStats
	msgLog
	msgLogReset
	msgInspect
	msgWarnings
	msgKey
	msgResize
	msgToast
	msgError
)

// msg is one item from a data source. It is a tagged struct rather than an
// interface so the render loop can switch on a value and the hot path - a
// stats sample every second per container - allocates nothing.
type msg struct {
	kind       msgKind
	containers []types.Container
	info       Info
	disk       DiskUsage
	event      types.Event
	stats      types.Stats
	log        LogLine
	container  types.Container
	warnings   []string
	id         string
	key        Key
	w, h       int
	text       string
	err        error
}

// send delivers m on out unless the context ends first. Every source uses it,
// so no goroutine can outlive its context by blocking on a full channel.
func send(ctx context.Context, out chan<- msg, m msg) bool {
	select {
	case out <- m:
		return true
	case <-ctx.Done():
		return false
	}
}

// retryDelay is how long a stream waits before reconnecting after the engine
// drops it. It is deliberately short: the engine restarting is the common
// cause, and the dashboard should come back on its own.
const retryDelay = 2 * time.Second

// pollContainers polls the container list and the engine info on an interval,
// and free space on the data root every tenth poll, since that moves slowly
// and may cost a round trip into the WSL distro.
func pollContainers(ctx context.Context, c Client, interval time.Duration, out chan<- msg) {
	if interval <= 0 {
		interval = time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for n := 0; ; n++ {
		if cs, err := c.Containers(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			send(ctx, out, msg{kind: msgError, err: err})
		} else if !send(ctx, out, msg{kind: msgContainers, containers: cs}) {
			return
		}

		if info, err := c.Info(ctx); err == nil {
			if !send(ctx, out, msg{kind: msgInfo, info: info}) {
				return
			}
			if n%10 == 0 {
				if d, ok := diskUsage(ctx, c, info.DataRoot); ok {
					if !send(ctx, out, msg{kind: msgDisk, disk: d}) {
						return
					}
				}
			}
		} else if ctx.Err() == nil {
			send(ctx, out, msg{kind: msgError, err: err})
		}

		select {
		case <-tick.C:
		case <-ctx.Done():
			return
		}
	}
}

// diskUsage asks the client for free space, falling back to a local statfs of
// the data root when the client cannot answer and the path exists on this
// machine - which it does when hull runs inside the distro and does not when
// the client is the Windows binary talking down the relay.
func diskUsage(ctx context.Context, c Client, root string) (DiskUsage, bool) {
	if r, ok := c.(DiskReporter); ok {
		if d, err := r.DiskUsage(ctx); err == nil && d.Known() {
			if d.Path == "" {
				d.Path = root
			}
			return d, true
		}
	}
	if root == "" {
		return DiskUsage{}, false
	}
	free, total, err := localDiskUsage(root)
	if err != nil || total == 0 {
		return DiskUsage{}, false
	}
	return DiskUsage{Path: root, Free: free, Total: total}, true
}

// streamEvents follows the engine event bus, reconnecting when it drops.
func streamEvents(ctx context.Context, c Client, out chan<- msg) {
	for ctx.Err() == nil {
		err := c.Events(ctx, func(e types.Event) error {
			if !send(ctx, out, msg{kind: msgEvent, event: e}) {
				return context.Canceled
			}
			return nil
		})
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return
		}
		if err != nil {
			send(ctx, out, msg{kind: msgError, err: err})
		}
		if !sleepCtx(ctx, retryDelay) {
			return
		}
	}
}

// streamStats follows one container's resource samples. It is restarted by the
// render loop whenever the selection changes, and it keeps retrying while the
// selection stands, because a container that is not running yet has no stats
// and will have some the moment it starts.
func streamStats(ctx context.Context, c Client, id string, out chan<- msg) {
	for ctx.Err() == nil {
		err := c.Stats(ctx, id, func(s types.Stats) error {
			if !send(ctx, out, msg{kind: msgStats, id: id, stats: s}) {
				return context.Canceled
			}
			return nil
		})
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return
		}
		if !sleepCtx(ctx, retryDelay) {
			return
		}
	}
}

// tailLogs replays the tail of one container's log and then follows it.
func tailLogs(ctx context.Context, c Client, id string, tail int, out chan<- msg) {
	if !send(ctx, out, msg{kind: msgLogReset, id: id}) {
		return
	}
	for ctx.Err() == nil {
		err := c.Logs(ctx, id, LogOptions{Tail: tail, Follow: true}, func(l LogLine) error {
			if !send(ctx, out, msg{kind: msgLog, id: id, log: l}) {
				return context.Canceled
			}
			return nil
		})
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return
		}
		if err != nil && !errors.Is(err, io.EOF) {
			send(ctx, out, msg{kind: msgLog, id: id, log: LogLine{
				Stream: "stderr",
				Line:   "logs: " + err.Error(),
			}})
		}
		if !sleepCtx(ctx, retryDelay) {
			return
		}
		// A reconnect replays the tail, so drop what is on screen first.
		if !send(ctx, out, msg{kind: msgLogReset, id: id}) {
			return
		}
	}
}

// inspectContainer fetches the full record and the engine's create-time
// warnings for one container, once per selection change.
func inspectContainer(ctx context.Context, c Client, id string, out chan<- msg) {
	full, err := c.Inspect(ctx, id)
	if err != nil {
		if ctx.Err() == nil {
			send(ctx, out, msg{kind: msgError, err: err})
		}
		return
	}
	if !send(ctx, out, msg{kind: msgInspect, id: id, container: full}) {
		return
	}
	if wr, ok := c.(WarningReporter); ok {
		if warns, err := wr.Warnings(ctx, id); err == nil {
			send(ctx, out, msg{kind: msgWarnings, id: id, warnings: warns})
		}
	}
}

// sleepCtx waits for d, returning false if the context ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
