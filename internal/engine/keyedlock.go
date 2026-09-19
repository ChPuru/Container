package engine

import (
	"context"
	"sync"
)

// keyedLock is a map of one mutex per key, created on demand and dropped when
// the last holder releases it.
//
// It exists because a single global engine lock would make `hull ps` wait
// behind a multi-gigabyte image pull. The map itself is guarded by an RWMutex,
// which is held only for the microseconds it takes to find or create an entry;
// the per-key mutex is what the slow work is done under.
type keyedLock struct {
	mu    sync.Mutex
	locks map[string]*keyedEntry
}

// keyedEntry is one key's mutex plus the number of goroutines that hold or are
// waiting for it, so the entry can be freed when it falls to zero.
type keyedEntry struct {
	ch   chan struct{}
	refs int
}

// newKeyedLock returns an empty keyed lock.
func newKeyedLock() *keyedLock {
	return &keyedLock{locks: make(map[string]*keyedEntry)}
}

// entry finds or creates the entry for key and takes a reference on it.
func (k *keyedLock) entry(key string) *keyedEntry {
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.locks[key]
	if !ok {
		e = &keyedEntry{ch: make(chan struct{}, 1)}
		k.locks[key] = e
	}
	e.refs++
	return e
}

// release drops one reference and forgets the entry when nobody else wants it.
func (k *keyedLock) release(key string, e *keyedEntry) {
	k.mu.Lock()
	defer k.mu.Unlock()
	e.refs--
	if e.refs <= 0 {
		delete(k.locks, key)
	}
}

// Lock blocks until key is free or ctx is cancelled. On success it returns an
// unlock function; on cancellation it returns ctx.Err() and the caller holds
// nothing.
func (k *keyedLock) Lock(ctx context.Context, key string) (func(), error) {
	e := k.entry(key)
	select {
	case e.ch <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-e.ch
				k.release(key, e)
			})
		}, nil
	case <-ctx.Done():
		k.release(key, e)
		return nil, ctx.Err()
	}
}

// TryLock takes key's lock if it is free right now. The second result reports
// whether it was taken.
func (k *keyedLock) TryLock(key string) (func(), bool) {
	e := k.entry(key)
	select {
	case e.ch <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-e.ch
				k.release(key, e)
			})
		}, true
	default:
		k.release(key, e)
		return nil, false
	}
}

// Held reports how many keys currently have a live entry. It is used by tests
// and by the shutdown path to check that nothing is leaked.
func (k *keyedLock) Held() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.locks)
}
