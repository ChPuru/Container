package events

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

// recv reads one event or fails the test after a generous timeout.
func recv(t *testing.T, ch <-chan types.Event) types.Event {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("channel closed, wanted an event")
		}
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for an event")
		return types.Event{}
	}
}

// expectClosed asserts the channel closes, draining anything still queued.
func expectClosed(t *testing.T, ch <-chan types.Event) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for the channel to close")
		}
	}
}

func TestPublishStampsAndDelivers(t *testing.T) {
	b := NewBus(16)
	defer b.Close()

	ch, cancel := b.Subscribe(context.Background(), Filter{}, time.Time{}, time.Time{})
	defer cancel()

	b.Publish(types.Event{Type: TypeContainer, Action: ActionStart, Actor: types.EventActor{ID: "c1"}})
	got := recv(t, ch)

	if got.Time == 0 || got.TimeNano == 0 {
		t.Fatalf("Publish must stamp Time/TimeNano, got %+v", got)
	}
	if got.Time != got.TimeNano/int64(time.Second) {
		t.Fatalf("Time (%d) and TimeNano (%d) disagree", got.Time, got.TimeNano)
	}
	if got.Scope != ScopeLocal {
		t.Fatalf("Scope = %q, want %q", got.Scope, ScopeLocal)
	}

	// An explicit timestamp is preserved.
	when := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	b.Publish(types.Event{Type: TypeDaemon, Action: ActionReload, Time: when.Unix(), TimeNano: when.UnixNano()})
	got = recv(t, ch)
	if got.TimeNano != when.UnixNano() {
		t.Fatalf("TimeNano = %d, want %d", got.TimeNano, when.UnixNano())
	}
}

func TestSubscribeFiltersLiveStream(t *testing.T) {
	b := NewBus(16)
	defer b.Close()

	ch, cancel := b.Subscribe(context.Background(), Filter{Actions: []string{ActionDie}}, time.Time{}, time.Time{})
	defer cancel()

	b.Publish(ev(TypeContainer, ActionStart, "c1", nil))
	b.Publish(ev(TypeContainer, ActionDie, "c1", nil))

	got := recv(t, ch)
	if got.Action != ActionDie {
		t.Fatalf("got action %q, want die", got.Action)
	}
}

func TestReplayFromSince(t *testing.T) {
	b := NewBus(64)
	defer b.Close()

	base := time.Now().Add(-time.Hour)
	for i := 0; i < 6; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		e := ev(TypeContainer, ActionStart, fmt.Sprintf("c%d", i), nil)
		e.Time, e.TimeNano = at.Unix(), at.UnixNano()
		b.Publish(e)
	}

	since := base.Add(2*time.Minute + 30*time.Second)
	ch, cancel := b.Subscribe(context.Background(), Filter{}, since, time.Time{})
	defer cancel()

	for i := 3; i < 6; i++ {
		got := recv(t, ch)
		if want := fmt.Sprintf("c%d", i); got.Actor.ID != want {
			t.Fatalf("replay[%d] = %q, want %q", i, got.Actor.ID, want)
		}
	}

	// Live events keep flowing after the replay window.
	b.Publish(ev(TypeContainer, ActionStop, "c9", nil))
	if got := recv(t, ch); got.Actor.ID != "c9" {
		t.Fatalf("live event after replay = %q", got.Actor.ID)
	}
}

func TestReplayRespectsFilterAndRingWraparound(t *testing.T) {
	b := NewBus(4) // deliberately smaller than the number of events
	defer b.Close()

	base := time.Now().Add(-time.Hour)
	for i := 0; i < 10; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		action := ActionStart
		if i%2 == 1 {
			action = ActionDie
		}
		e := ev(TypeContainer, action, fmt.Sprintf("c%d", i), nil)
		e.Time, e.TimeNano = at.Unix(), at.UnixNano()
		b.Publish(e)
	}

	hist := b.History(time.Time{}, time.Time{}, Filter{})
	if len(hist) != 4 {
		t.Fatalf("history length = %d, want 4", len(hist))
	}
	if hist[0].Actor.ID != "c6" || hist[3].Actor.ID != "c9" {
		t.Fatalf("history window = %s..%s, want c6..c9", hist[0].Actor.ID, hist[3].Actor.ID)
	}

	filtered := b.History(time.Time{}, time.Time{}, Filter{Actions: []string{ActionDie}})
	if len(filtered) != 2 || filtered[0].Actor.ID != "c7" || filtered[1].Actor.ID != "c9" {
		t.Fatalf("filtered history = %+v", filtered)
	}
}

func TestUntilInThePastReplaysThenCloses(t *testing.T) {
	b := NewBus(16)
	defer b.Close()

	base := time.Now().Add(-time.Hour)
	for i := 0; i < 4; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		e := ev(TypeContainer, ActionStart, fmt.Sprintf("c%d", i), nil)
		e.Time, e.TimeNano = at.Unix(), at.UnixNano()
		b.Publish(e)
	}

	until := base.Add(time.Minute + time.Second)
	ch, cancel := b.Subscribe(context.Background(), Filter{}, time.Time{}, until)
	defer cancel()

	var ids []string
	for e := range ch {
		ids = append(ids, e.Actor.ID)
	}
	if len(ids) != 2 || ids[0] != "c0" || ids[1] != "c1" {
		t.Fatalf("replayed %v, want [c0 c1]", ids)
	}
	if n := b.Subscribers(); n != 0 {
		t.Fatalf("subscriber count = %d after until expired, want 0", n)
	}
}

func TestUntilInTheFutureClosesLater(t *testing.T) {
	b := NewBus(16)
	defer b.Close()

	until := time.Now().Add(150 * time.Millisecond)
	ch, cancel := b.Subscribe(context.Background(), Filter{}, time.Time{}, until)
	defer cancel()

	b.Publish(ev(TypeContainer, ActionStart, "c1", nil))
	if got := recv(t, ch); got.Actor.ID != "c1" {
		t.Fatalf("got %q, want c1", got.Actor.ID)
	}
	expectClosed(t, ch)
}

func TestSlowSubscriberDropsWithoutBlockingPublisher(t *testing.T) {
	const events = 10000

	b := NewBusWithBuffer(16, 1) // size-1 live buffer
	defer b.Close()

	// A subscriber that never reads from its channel.
	_, cancel := b.Subscribe(context.Background(), Filter{}, time.Time{}, time.Time{})
	defer cancel()

	// A subscriber that keeps up, to prove the slow one is isolated.
	fast, cancelFast := b.Subscribe(context.Background(), Filter{}, time.Time{}, time.Time{})
	defer cancelFast()
	var fastCount int
	fastDone := make(chan struct{})
	go func() {
		defer close(fastDone)
		for range fast {
			fastCount++
		}
	}()

	var worst time.Duration
	start := time.Now()
	for i := 0; i < events; i++ {
		e := ev(TypeContainer, ActionStart, fmt.Sprintf("c%d", i), nil)
		t0 := time.Now()
		b.Publish(e)
		if d := time.Since(t0); d > worst {
			worst = d
		}
	}
	total := time.Since(start)

	if worst > 50*time.Millisecond {
		t.Fatalf("slowest Publish took %v; a slow subscriber must never block the publisher", worst)
	}
	if total > 5*time.Second {
		t.Fatalf("publishing %d events took %v", events, total)
	}
	if b.Dropped() == 0 {
		t.Fatal("expected the slow subscriber to have dropped events")
	}

	stats := b.Stats()
	if len(stats) != 2 {
		t.Fatalf("stats length = %d, want 2", len(stats))
	}
	var maxDropped uint64
	for _, s := range stats {
		if s.Dropped > maxDropped {
			maxDropped = s.Dropped
		}
	}
	if maxDropped == 0 {
		t.Fatal("no subscriber recorded a drop")
	}

	cancelFast()
	select {
	case <-fastDone:
	case <-time.After(3 * time.Second):
		t.Fatal("fast subscriber goroutine did not finish")
	}
	if fastCount == 0 {
		t.Fatal("the fast subscriber should have received events")
	}
}

func TestUnsubscribeIsCleanAndIdempotent(t *testing.T) {
	b := NewBus(16)
	defer b.Close()

	ch, cancel := b.Subscribe(context.Background(), Filter{}, time.Time{}, time.Time{})
	if n := b.Subscribers(); n != 1 {
		t.Fatalf("subscriber count = %d, want 1", n)
	}

	cancel()
	cancel() // must not panic
	expectClosed(t, ch)

	deadline := time.Now().Add(3 * time.Second)
	for b.Subscribers() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("subscriber was never removed from the bus")
		}
		time.Sleep(time.Millisecond)
	}

	// Publishing after everyone left is harmless.
	b.Publish(ev(TypeContainer, ActionStart, "c1", nil))
}

func TestContextCancelUnsubscribes(t *testing.T) {
	b := NewBus(16)
	defer b.Close()

	ctx, cancelCtx := context.WithCancel(context.Background())
	ch, cancel := b.Subscribe(ctx, Filter{}, time.Time{}, time.Time{})
	defer cancel()

	b.Publish(ev(TypeContainer, ActionStart, "c1", nil))
	recv(t, ch)

	cancelCtx()
	expectClosed(t, ch)
}

func TestCloseClosesEverySubscriber(t *testing.T) {
	b := NewBus(16)

	var chans []<-chan types.Event
	for i := 0; i < 4; i++ {
		ch, _ := b.Subscribe(context.Background(), Filter{}, time.Time{}, time.Time{})
		chans = append(chans, ch)
	}

	b.Close()
	b.Close() // idempotent

	for _, ch := range chans {
		expectClosed(t, ch)
	}

	// Subscribe on a closed bus yields an already-closed channel.
	ch, cancel := b.Subscribe(context.Background(), Filter{}, time.Time{}, time.Time{})
	cancel()
	expectClosed(t, ch)

	// Publish on a closed bus is a no-op, not a panic.
	b.Publish(ev(TypeContainer, ActionStart, "c1", nil))
}

func TestConcurrentPublishSubscribeUnsubscribe(t *testing.T) {
	b := NewBusWithBuffer(256, 8)
	defer b.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for p := 0; p < 4; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				b.Publish(Container(ActionStart, &types.Container{
					ID:       fmt.Sprintf("%d-%d", p, i),
					Name:     "web",
					ImageRef: "alpine:3.20",
					Config:   types.ContainerConfig{Labels: map[string]string{"tier": "front"}},
				}, nil))
			}
		}(p)
	}

	for s := 0; s < 8; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				ctx, cancelCtx := context.WithCancel(context.Background())
				ch, cancel := b.Subscribe(ctx, Filter{Labels: []string{"tier"}}, time.Time{}, time.Time{})
				n := 0
				for range ch {
					n++
					if n >= 3 {
						break
					}
				}
				if i%2 == 0 {
					cancel()
				} else {
					cancelCtx()
				}
				cancel()
				cancelCtx()
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}
