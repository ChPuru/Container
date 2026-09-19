// Package events implements hull's engine event bus.
//
// Every lifecycle change in the engine is published here as a types.Event.
// The Docker Engine API /events endpoint, the TUI and "hull events" all
// subscribe. Two properties are non-negotiable:
//
//   - Publish never blocks. A subscriber that stops reading is charged a
//     dropped-event counter and everybody else carries on; one slow
//     /events client must never stall container startup.
//   - A subscriber that keeps up never loses an event, and may replay the
//     recent past through the bus's ring buffer using "since".
package events

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

const (
	// DefaultHistory is the ring-buffer size used when NewBus is given a
	// non-positive history length.
	DefaultHistory = 1024

	// DefaultSubscriberBuffer is the per-subscriber live-event buffer used
	// by NewBus. Events that arrive while a subscriber's buffer is full are
	// dropped for that subscriber only.
	DefaultSubscriberBuffer = 256
)

// Bus is the engine event bus. The zero value is not usable; call NewBus.
// All methods are safe for concurrent use.
type Bus struct {
	mu      sync.Mutex
	closed  bool
	subBuf  int
	ring    []types.Event // fixed-size ring; len(ring) == capacity
	next    int           // index of the next slot to write
	count   int           // number of valid entries (<= len(ring))
	subs    map[*subscriber]struct{}
	dropped atomic.Uint64
}

// NewBus returns a bus that retains the last history events so that a
// subscriber using "since" can replay them. A history of zero or less selects
// DefaultHistory (1024).
func NewBus(history int) *Bus {
	return NewBusWithBuffer(history, DefaultSubscriberBuffer)
}

// NewBusWithBuffer is NewBus with an explicit per-subscriber live buffer size.
// It exists so tests (and an operator who wants a tighter back-pressure
// window) can pick the point at which a slow subscriber starts losing events.
// A buffer of zero or less selects DefaultSubscriberBuffer.
func NewBusWithBuffer(history, buffer int) *Bus {
	if history <= 0 {
		history = DefaultHistory
	}
	if buffer <= 0 {
		buffer = DefaultSubscriberBuffer
	}
	return &Bus{
		subBuf: buffer,
		ring:   make([]types.Event, history),
		subs:   make(map[*subscriber]struct{}),
	}
}

// subscriber is one live consumer. live is the bounded mailbox Publish writes
// into without ever blocking; the pump goroutine drains it into out, which is
// what the caller of Subscribe holds.
type subscriber struct {
	bus     *Bus
	filter  Filter
	until   time.Time
	live    chan types.Event
	out     chan types.Event
	done    chan struct{}
	stopOne sync.Once
	dropped atomic.Uint64
}

// SubscriberStats is a point-in-time view of one subscriber's health.
type SubscriberStats struct {
	// Dropped counts events discarded because this subscriber's buffer was
	// full when they were published.
	Dropped uint64
	// Pending is the number of events sitting in this subscriber's buffer.
	Pending int
	// Filter is the filter the subscriber registered with.
	Filter Filter
}

// Publish delivers e to every matching subscriber.
//
// Time and TimeNano are stamped from the current clock when zero, and Scope
// defaults to "local". Delivery to each subscriber is a non-blocking send on
// its buffered channel: if that buffer is full the event is dropped for that
// subscriber only, its Dropped counter is incremented, and delivery continues
// to the rest. Publish therefore completes in bounded time regardless of how
// badly any consumer is behaving.
func (b *Bus) Publish(e types.Event) {
	e = stamp(e)

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}

	// Record in the ring buffer first so a subscriber registering
	// concurrently either replays this event or receives it live, never both
	// and never neither: Subscribe snapshots history under the same lock.
	b.ring[b.next] = e
	b.next = (b.next + 1) % len(b.ring)
	if b.count < len(b.ring) {
		b.count++
	}

	when := eventTime(e)
	for s := range b.subs {
		if !s.until.IsZero() && when.After(s.until) {
			continue
		}
		if !s.filter.Match(e) {
			continue
		}
		select {
		case s.live <- e:
		default:
			s.dropped.Add(1)
			b.dropped.Add(1)
		}
	}
}

// Subscribe registers a consumer and returns its event channel plus an
// unsubscribe function.
//
// Matching history newer than since is replayed first, then live events are
// streamed. When until is non-zero the channel closes once that instant has
// passed (immediately after the replay, if until is already in the past). The
// returned function unsubscribes and closes the channel; cancelling ctx does
// the same. It is safe to call the returned function more than once.
//
// The channel is always closed exactly once, so a reader may range over it.
func (b *Bus) Subscribe(ctx context.Context, filter Filter, since, until time.Time) (<-chan types.Event, func()) {
	s := &subscriber{
		bus:    b,
		filter: filter,
		until:  until,
		live:   make(chan types.Event, b.subBuf),
		out:    make(chan types.Event),
		done:   make(chan struct{}),
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		dead := make(chan types.Event)
		close(dead)
		return dead, func() {}
	}
	replay := b.historyLocked(since, until, filter)
	if until.IsZero() || !time.Now().After(until) {
		b.subs[s] = struct{}{}
	}
	b.mu.Unlock()

	go s.pump(ctx, replay)
	return s.out, s.stop
}

// History returns the retained events matching filter whose timestamps fall in
// the half-open window (since, until]. A zero since means "from the oldest
// retained event" and a zero until means "up to now". The result is ordered
// oldest first.
func (b *Bus) History(since, until time.Time, filter Filter) []types.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.historyLocked(since, until, filter)
}

func (b *Bus) historyLocked(since, until time.Time, filter Filter) []types.Event {
	if b.count == 0 {
		return nil
	}
	var out []types.Event
	start := (b.next - b.count + len(b.ring)) % len(b.ring)
	for i := 0; i < b.count; i++ {
		e := b.ring[(start+i)%len(b.ring)]
		when := eventTime(e)
		if !since.IsZero() && !when.After(since) {
			continue
		}
		if !until.IsZero() && when.After(until) {
			continue
		}
		if !filter.Match(e) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Close shuts the bus down: every subscriber channel is closed and further
// Publish calls are discarded. Close is idempotent.
func (b *Bus) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	subs := make([]*subscriber, 0, len(b.subs))
	for s := range b.subs {
		subs = append(subs, s)
	}
	b.subs = make(map[*subscriber]struct{})
	b.mu.Unlock()

	for _, s := range subs {
		s.stopOne.Do(func() { close(s.done) })
	}
}

// Subscribers reports how many live subscribers are attached.
func (b *Bus) Subscribers() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

// Dropped reports the total number of per-subscriber deliveries skipped
// because a subscriber's buffer was full. It is a health signal, not a count
// of distinct events.
func (b *Bus) Dropped() uint64 { return b.dropped.Load() }

// Stats returns a snapshot of every live subscriber's health, in unspecified
// order.
func (b *Bus) Stats() []SubscriberStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]SubscriberStats, 0, len(b.subs))
	for s := range b.subs {
		out = append(out, SubscriberStats{
			Dropped: s.dropped.Load(),
			Pending: len(s.live),
			Filter:  s.filter,
		})
	}
	return out
}

// stop unsubscribes and makes the pump close the output channel.
func (s *subscriber) stop() {
	s.stopOne.Do(func() { close(s.done) })
	s.bus.remove(s)
}

func (b *Bus) remove(s *subscriber) {
	b.mu.Lock()
	delete(b.subs, s)
	b.mu.Unlock()
}

// pump writes the replay window and then forwards live events until the
// subscription ends. It is the sole writer to s.out and closes it on exit.
func (s *subscriber) pump(ctx context.Context, replay []types.Event) {
	defer close(s.out)
	defer s.bus.remove(s)

	for _, e := range replay {
		select {
		case s.out <- e:
		case <-ctx.Done():
			return
		case <-s.done:
			return
		}
	}

	var untilC <-chan time.Time
	if !s.until.IsZero() {
		d := time.Until(s.until)
		if d <= 0 {
			return
		}
		t := time.NewTimer(d)
		defer t.Stop()
		untilC = t.C
	}

	for {
		select {
		case e := <-s.live:
			select {
			case s.out <- e:
			case <-ctx.Done():
				return
			case <-s.done:
				return
			}
		case <-untilC:
			return
		case <-ctx.Done():
			return
		case <-s.done:
			return
		}
	}
}

// stamp fills in Time/TimeNano and Scope when the caller left them zero.
func stamp(e types.Event) types.Event {
	switch {
	case e.Time == 0 && e.TimeNano == 0:
		now := time.Now()
		e.Time = now.Unix()
		e.TimeNano = now.UnixNano()
	case e.TimeNano == 0:
		e.TimeNano = e.Time * int64(time.Second)
	case e.Time == 0:
		e.Time = e.TimeNano / int64(time.Second)
	}
	if e.Scope == "" {
		e.Scope = ScopeLocal
	}
	return e
}

// eventTime is the wall-clock instant of an event, preferring nanosecond
// precision when it is present.
func eventTime(e types.Event) time.Time {
	if e.TimeNano != 0 {
		return time.Unix(0, e.TimeNano)
	}
	return time.Unix(e.Time, 0)
}
