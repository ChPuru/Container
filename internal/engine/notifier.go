package engine

import "sync"

// Lifecycle notification kinds published on the internal notifier. They are
// the events Wait's conditions are expressed in.
const (
	// notifyExit means the container's init process was reaped.
	notifyExit = "exit"
	// notifyRemoved means the container record is gone.
	notifyRemoved = "removed"
)

// lifecycleEvent is one transition of one container.
type lifecycleEvent struct {
	// kind is notifyExit or notifyRemoved.
	kind string
	// exitCode is the container's exit code for notifyExit.
	exitCode int
}

// notifier is a per-container publish/subscribe channel used by Wait and by
// the restart worker. It is separate from the public event bus because a
// waiter must never miss a transition to a slow consumer, and the bus
// deliberately drops events for subscribers that fall behind.
type notifier struct {
	mu   sync.Mutex
	subs map[string]map[chan lifecycleEvent]struct{}
}

// newNotifier returns an empty notifier.
func newNotifier() *notifier {
	return &notifier{subs: make(map[string]map[chan lifecycleEvent]struct{})}
}

// subscribe registers interest in one container's transitions and returns the
// channel plus a cancel function that must be called exactly once.
//
// The channel is buffered, so a publisher never blocks on a subscriber that
// has not got round to reading yet.
func (n *notifier) subscribe(id string) (<-chan lifecycleEvent, func()) {
	ch := make(chan lifecycleEvent, 8)
	n.mu.Lock()
	m, ok := n.subs[id]
	if !ok {
		m = make(map[chan lifecycleEvent]struct{})
		n.subs[id] = m
	}
	m[ch] = struct{}{}
	n.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			n.mu.Lock()
			if m, ok := n.subs[id]; ok {
				delete(m, ch)
				if len(m) == 0 {
					delete(n.subs, id)
				}
			}
			n.mu.Unlock()
		})
	}
}

// publish delivers ev to every subscriber of id. A subscriber whose buffer is
// full is skipped rather than blocking the lifecycle; eight pending
// transitions means nobody is reading.
func (n *notifier) publish(id string, ev lifecycleEvent) {
	n.mu.Lock()
	subs := make([]chan lifecycleEvent, 0, len(n.subs[id]))
	for ch := range n.subs[id] {
		subs = append(subs, ch)
	}
	n.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}
