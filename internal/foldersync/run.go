package foldersync

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Run keeps the two sides reconciled until ctx is cancelled.
//
// It does one full reconciliation pass first, so a freshly started sync is
// correct before it is incremental, then drives two very different change
// sources:
//
//   - the volume side is watched with inotify, which is instant and costs
//     nothing while idle. If a watch cannot be opened at all - a non-Linux
//     build, or a kernel out of watch descriptors - the volume side is polled
//     instead and Status().Watching reports false, rather than the sync
//     silently doing half its job.
//   - the Windows side is polled, because nothing on that side of the 9p
//     boundary raises an event inside the VM. The interval backs off while the
//     tree is quiet.
//
// Bursts are debounced: a save that rewrites forty files produces one pass.
// Run returns nil when ctx is cancelled; any other error is fatal to the sync.
func (s *Syncer) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup

	s.mu.Lock()
	s.status.Running = true
	s.mu.Unlock()

	defer func() {
		cancel()
		wg.Wait()
		s.watchMu.Lock()
		w := s.watcher
		s.watcher = nil
		s.watchMu.Unlock()
		if w != nil {
			_ = w.close()
		}
		s.mu.Lock()
		s.status.Running = false
		s.status.Watching = false
		s.mu.Unlock()
	}()

	if _, err := s.runSync(runCtx); err != nil {
		if isDone(err) {
			return nil
		}
		return err
	}

	// The volume-side watcher. Failing to open one is a degradation, not an
	// error: polling both sides still works, it just costs a walk.
	trigger := make(chan struct{}, 1)
	var overflowed atomic.Bool

	w, werr := newTreeWatcher(s.volume, s.ig)
	if werr != nil {
		s.volPoll = newPoller(s.volume, s.ig, s.cfg.PollInterval, s.cfg.MaxPollInterval)
		s.volPoll.setBaseline(volumeBaseline(s.prevSnapshot()))
		s.emit(Event{
			Kind:    EventError,
			Err:     werr,
			Message: fmt.Sprintf("watching %s is unavailable (%v); polling it instead", s.volume, werr),
		})
	} else {
		s.watchMu.Lock()
		s.watcher = w
		s.watchMu.Unlock()
		s.mu.Lock()
		s.status.Watching = true
		s.mu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				r, err := w.wait(runCtx)
				if err != nil {
					if !isDone(err) && runCtx.Err() == nil {
						s.emit(Event{Kind: EventError, Err: err, Message: fmt.Sprintf("volume watch failed: %v", err)})
					}
					return
				}
				if r.overflow {
					overflowed.Store(true)
				}
				select {
				case trigger <- struct{}{}:
				default:
					// A pass is already pending; it will see everything.
				}
			}
		}()
	}

	timer := time.NewTimer(s.hostPoll.currentInterval())
	defer timer.Stop()

	for {
		select {
		case <-runCtx.Done():
			return nil

		case <-trigger:
			if !s.coalesce(runCtx, trigger) {
				return nil
			}
			if overflowed.Swap(false) {
				if _, err := s.onOverflow(runCtx); err != nil && !isDone(err) {
					return err
				}
			} else if _, err := s.runSync(runCtx); err != nil && !isDone(err) {
				return err
			}
			resetTimer(timer, s.hostPoll.currentInterval())

		case <-timer.C:
			changed, err := s.pollSides(runCtx)
			if err != nil {
				if isDone(err) {
					return nil
				}
				return err
			}
			if changed {
				if _, err := s.runSync(runCtx); err != nil && !isDone(err) {
					return err
				}
			}
			resetTimer(timer, s.hostPoll.currentInterval())
		}
	}
}

// coalesce waits out a burst: it keeps draining triggers until the tree has
// been quiet for Debounce. It reports false if the context ended first.
func (s *Syncer) coalesce(ctx context.Context, trigger <-chan struct{}) bool {
	t := time.NewTimer(s.cfg.Debounce)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-trigger:
			resetTimer(t, s.cfg.Debounce)
		case <-t.C:
			return true
		}
	}
}

// pollSides walks whichever sides have to be polled and reports whether either
// moved.
func (s *Syncer) pollSides(ctx context.Context) (bool, error) {
	hostChanges, err := s.hostPoll.poll(ctx)
	if err != nil {
		return false, err
	}
	changed := !hostChanges.empty()
	if s.volPoll != nil {
		volChanges, err := s.volPoll.poll(ctx)
		if err != nil {
			return changed, err
		}
		changed = changed || !volChanges.empty()
	}
	return changed, nil
}

// runSync runs a pass and hands the resulting baselines to the pollers, so
// that the syncer's own writes are never mistaken for user edits on the next
// walk.
func (s *Syncer) runSync(ctx context.Context) (Result, error) {
	res, err := s.Sync(ctx)
	if err != nil {
		return res, err
	}
	prev := s.prevSnapshot()
	if s.hostPoll != nil {
		s.hostPoll.setBaseline(hostBaseline(prev))
		s.hostPoll.backoff(res.Changed())
	}
	if s.volPoll != nil {
		s.volPoll.setBaseline(volumeBaseline(prev))
		s.volPoll.backoff(res.Changed())
	}
	return res, nil
}

// onOverflow is what happens when the kernel reports IN_Q_OVERFLOW: the event
// queue was dropped, so there is no way to know what was missed. The watch set
// is re-armed first - directories created during the gap never produced the
// IN_CREATE that would have added their watches - and then the whole tree is
// reconciled, which is the only recovery that cannot be wrong.
func (s *Syncer) onOverflow(ctx context.Context) (Result, error) {
	s.mu.Lock()
	s.status.Overflows++
	s.mu.Unlock()

	s.watchMu.Lock()
	w := s.watcher
	s.watchMu.Unlock()
	if w != nil {
		if err := w.rearm(); err != nil {
			s.emit(Event{Kind: EventError, Err: err, Message: fmt.Sprintf("re-arming watches after overflow: %v", err)})
		}
	}
	s.emit(Event{
		Kind:    EventOverflow,
		Message: "inotify queue overflowed; falling back to a full scan",
	})
	return s.runSync(ctx)
}

// prevSnapshot copies the baseline under the sync lock, so a caller can read
// it without racing a pass.
func (s *Syncer) prevSnapshot() map[string]pairState {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	out := make(map[string]pairState, len(s.prev))
	for k, v := range s.prev {
		out[k] = v
	}
	return out
}

// resetTimer restarts a timer that may or may not have fired.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// isDone reports whether an error is just the context ending.
func isDone(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
