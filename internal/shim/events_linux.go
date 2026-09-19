package shim

import "sync"

// eventHistory is how many past events a late subscriber is replayed. The
// important one is the container's exit: a daemon that restarts after the
// container died must still see it, so the shim never drops it on the floor.
const eventHistory = 32

// eventBus fans shim events out to every subscribed client and replays recent
// history to a client that arrives late.
type eventBus struct {
	mu      sync.Mutex
	subs    map[chan Event]struct{}
	history []Event
	closed  bool
}

// newEventBus returns an empty bus.
func newEventBus() *eventBus {
	return &eventBus{subs: make(map[chan Event]struct{})}
}

// Subscribe returns a channel carrying the replayed history followed by every
// new event. The caller must Unsubscribe.
func (b *eventBus) Subscribe() chan Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan Event, len(b.history)+16)
	for _, ev := range b.history {
		ch <- ev
	}
	if b.closed {
		close(ch)
		return ch
	}
	b.subs[ch] = struct{}{}
	return ch
}

// Unsubscribe removes ch.
func (b *eventBus) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subs[ch]; ok {
		delete(b.subs, ch)
	}
}

// Publish records ev and delivers it to every subscriber without blocking.
func (b *eventBus) Publish(ev Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.history = append(b.history, ev)
	if len(b.history) > eventHistory {
		b.history = b.history[len(b.history)-eventHistory:]
	}
	for ch := range b.subs {
		select {
		case ch <- ev:
		default: // a wedged subscriber must not stall the supervisor
		}
	}
}

// Close ends every subscription.
func (b *eventBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for ch := range b.subs {
		delete(b.subs, ch)
		close(ch)
	}
}
