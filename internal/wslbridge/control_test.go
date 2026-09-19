package wslbridge

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// releasableTransport is a transport that records whether its hold on the
// distro was dropped, standing in for the stdio transport's relay child.
type releasableTransport struct {
	mu       sync.Mutex
	released int
}

// Name implements Transport.
func (r *releasableTransport) Name() string { return "releasable" }

// Probe implements Transport.
func (r *releasableTransport) Probe(context.Context) error { return nil }

// Dial implements Transport.
func (r *releasableTransport) Dial(context.Context) (net.Conn, error) {
	return nil, errors.New("this transport is never dialled in these tests")
}

// Release implements Releaser.
func (r *releasableTransport) Release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.released++
}

// count reports how many times Release was called.
func (r *releasableTransport) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.released
}

// TestControlReleaseDropsEveryHold is the scale-to-zero requirement. The
// keep-alive holder is not the only Windows-side client of the distro: the
// stdio transport's relay child is one too, and leaving it running means WSL
// reclaims nothing however idle the engine is.
func TestControlReleaseDropsEveryHold(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	spawner := &fakeKeepAliveSpawner{}
	keep, err := StartKeepAliveWith(ctx, KeepAliveOptions{
		Config:  Config{Distro: "hull-engine"},
		Spawner: spawner,
	})
	if err != nil {
		t.Fatalf("StartKeepAliveWith: %v", err)
	}
	defer keep.Close()
	waitFor(t, "the first holder to start", keep.Alive)

	transport := &releasableTransport{}
	runner := &fakeRunner{handler: func(string, []string) ([]byte, error) { return nil, nil }}
	control := &Control{
		cfg:       Config{Distro: "hull-engine", Runner: runner}.WithDefaults(),
		keep:      keep,
		transport: transport,
	}

	if control.Released() {
		t.Fatal("Released() = true before anything was released")
	}
	control.Release()

	if !control.Released() {
		t.Error("Released() = false after Release")
	}
	if n := transport.count(); n != 1 {
		t.Errorf("transport released %d times, want 1: the relay child holds the distro too", n)
	}
	waitFor(t, "the holder to stop", func() bool { return !keep.Alive() })

	// A client arriving afterwards must bring everything back.
	before := spawner.count()
	if err := control.Hold(ctx); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if control.Released() {
		t.Error("Released() = true after Hold")
	}
	waitFor(t, "a new holder", func() bool { return spawner.count() > before && keep.Alive() })
}

// TestControlHoldStartsTheEngine checks the wake path does more than re-acquire
// the distro: the engine died with it, so it has to be started again before the
// first request is dialled.
func TestControlHoldStartsTheEngine(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu     sync.Mutex
		booted bool
	)
	runner := &fakeRunner{handler: func(_ string, args []string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		for _, a := range args {
			if a == "/bin/sh" {
				continue
			}
			if strings.Contains(a, BootBinary) {
				booted = true
				return nil, nil
			}
			if strings.Contains(a, "test -S") && !booted {
				return nil, errors.New("exit status 1")
			}
		}
		return nil, nil
	}}

	keep, err := StartKeepAliveWith(ctx, KeepAliveOptions{
		Config:  Config{Distro: "hull-engine"},
		Spawner: &fakeKeepAliveSpawner{},
	})
	if err != nil {
		t.Fatalf("StartKeepAliveWith: %v", err)
	}
	defer keep.Close()

	control := &Control{
		cfg:       Config{Distro: "hull-engine", Runner: runner, EngineStartTimeout: 5 * time.Second}.WithDefaults(),
		keep:      keep,
		transport: &releasableTransport{},
	}
	control.Release()
	if err := control.Hold(ctx); err != nil {
		t.Fatalf("Hold: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !booted {
		t.Error("Hold did not start the engine after the distro had been reclaimed")
	}
}

// TestControlWithoutAKeepAlive keeps the no-keep-alive configuration usable:
// Release still drops the transport's hold and Hold is a no-op.
func TestControlWithoutAKeepAlive(t *testing.T) {
	t.Parallel()

	transport := &releasableTransport{}
	control := &Control{cfg: Config{}.WithDefaults(), transport: transport}

	if control.Released() {
		t.Error("Released() = true with no keep-alive")
	}
	control.Release()
	if n := transport.count(); n != 1 {
		t.Errorf("transport released %d times, want 1", n)
	}
	if err := control.Hold(context.Background()); err != nil {
		t.Errorf("Hold with no keep-alive = %v, want nil", err)
	}
}

// TestReleaseTransportIgnoresATransportWithNoHold covers the vsock and TCP
// transports, which hold nothing and must not be required to say so.
func TestReleaseTransportIgnoresATransportWithNoHold(t *testing.T) {
	t.Parallel()
	var order []string
	var mu sync.Mutex
	releaseTransport(&fakeTransport{name: "holds-nothing", order: &order, mu: &mu})
}
