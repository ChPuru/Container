package wslbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Transport is a way for Windows to reach hulld's API socket inside the engine
// distro. Every transport hands back an ordinary net.Conn that speaks the Docker
// Engine API, so nothing above this interface knows or cares whether the bytes
// travelled over a relay child's stdio, an AF_HYPERV socket or loopback TCP.
type Transport interface {
	// Dial opens one connection to the engine.
	Dial(ctx context.Context) (net.Conn, error)

	// Name is the short identifier used in logs and in "hull doctor" output.
	Name() string

	// Probe reports whether this transport can reach the engine right now. It
	// must be cheap enough to run on every bridge start and must not leave a
	// connection behind.
	Probe(ctx context.Context) error
}

// TransportOrder is the order SelectTransport probes in, and the order is the
// whole point.
//
// "stdio" is first because it is the only transport that always works: it needs
// nothing but wsl.exe, which is the one interface Microsoft actually supports.
// "vsock" is faster when it works, but it needs the VM's runtime ID, which has
// no documented discovery route -- the registry key Rancher Desktop reads has
// disappeared across WSL updates before -- so it is opportunistic and off by
// default. "tcp" is last because a loopback port is reachable by anything
// running as the user, so it is only safe behind the shared secret and only
// when the user asked for it.
var TransportOrder = []string{"stdio", "vsock", "tcp"}

// SelectTransport builds the candidate transports a configuration allows and
// returns the first one that probes successfully, logging which won and why the
// earlier ones did not.
//
// The returned Transport owns resources -- the stdio transport holds a live
// wsl.exe child -- so the caller must Close it when it is finished. Candidates
// that lost the race are closed here.
func SelectTransport(ctx context.Context, cfg Config) (Transport, error) {
	cfg = cfg.WithDefaults()

	candidates := cfg.Transports
	if candidates == nil {
		var err error
		candidates, err = buildTransports(ctx, cfg)
		if err != nil {
			return nil, err
		}
	}
	return Select(ctx, cfg, candidates...)
}

// buildTransports instantiates the transports cfg enables, in TransportOrder.
func buildTransports(ctx context.Context, cfg Config) ([]Transport, error) {
	var out []Transport
	for _, name := range TransportOrder {
		switch name {
		case "stdio":
			out = append(out, NewStdioTransport(ctx, cfg))
		case "vsock":
			if !cfg.EnableVsock {
				continue
			}
			out = append(out, NewVsockTransport(cfg))
		case "tcp":
			if !cfg.EnableTCP {
				continue
			}
			t, err := NewTCPTransport(cfg)
			if err != nil {
				// A missing or unreadable token is a configuration mistake, not
				// a reason to fail the whole bridge: the stdio transport in
				// front of it still works.
				cfg.Logger.Warn("wslbridge: tcp transport unavailable", "error", err)
				continue
			}
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no transports are enabled", ErrNoTransport)
	}
	return out, nil
}

// Select probes candidates in order and returns the first that answers. Losing
// candidates are closed, so a transport that spawned a child process during
// construction does not leak one.
func Select(ctx context.Context, cfg Config, candidates ...Transport) (Transport, error) {
	cfg = cfg.WithDefaults()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w: no candidates", ErrNoTransport)
	}

	var failures []error
	for i, t := range candidates {
		probeCtx, cancel := context.WithTimeout(ctx, cfg.ProbeTimeout)
		err := t.Probe(probeCtx)
		cancel()
		if err == nil {
			cfg.Logger.Info("wslbridge: transport selected", "transport", t.Name(), "distro", cfg.Distro)
			closeTransports(candidates[i+1:])
			return t, nil
		}
		cfg.Logger.Debug("wslbridge: transport probe failed", "transport", t.Name(), "error", err)
		failures = append(failures, fmt.Errorf("%s: %w", t.Name(), err))
		closeTransport(t)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("%w: %w", ErrNoTransport, errors.Join(failures...))
}

// Releaser is implemented by a transport that holds something keeping the
// engine distro alive -- in practice the stdio transport's relay child, which
// is a Windows-side client of the distro exactly like the keep-alive holder is.
// Releasing is not closing: the transport stays usable and re-acquires what it
// needs on the next Dial.
type Releaser interface {
	Release()
}

// releaseTransport drops a transport's hold on the distro, if it has one.
func releaseTransport(t Transport) {
	if r, ok := t.(Releaser); ok {
		r.Release()
	}
}

// closeTransport closes a transport that implements io.Closer.
func closeTransport(t Transport) {
	if c, ok := t.(io.Closer); ok {
		_ = c.Close()
	}
}

// closeTransports closes every transport in the slice that implements io.Closer.
func closeTransports(ts []Transport) {
	for _, t := range ts {
		closeTransport(t)
	}
}

// dialWithRetry dials the transport, retrying once after a short pause. The
// retry is not decoration: WSL tears the VM down about fifteen seconds after the
// last Windows-side client goes away, so the first dial after an idle period can
// land exactly while the distro is coming back, and the multiplexed transports
// respawn their relay on the second attempt.
func dialWithRetry(ctx context.Context, t Transport, cfg Config) (net.Conn, error) {
	var lastErr error
	for attempt := range 2 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
		dialCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
		conn, err := t.Dial(dialCtx)
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
		cfg.Logger.Debug("wslbridge: dial failed", "transport", t.Name(), "attempt", attempt+1, "error", err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("wslbridge: dial engine over %s: %w", t.Name(), lastErr)
}
