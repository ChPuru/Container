package client

import (
	"context"
	"fmt"
	"net"
	"time"
)

// dialerFor returns the dial function for a parsed host. The returned function
// ignores its network and address arguments: the target is fixed by the host,
// and net/http only passes the synthetic values the client puts in the URL.
func dialerFor(h Host, relay []string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	switch h.Scheme {
	case SchemeUnix:
		return func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", h.Addr)
		}, nil
	case SchemeTCP:
		return func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
			return d.DialContext(ctx, "tcp", h.Addr)
		}, nil
	case SchemeNamedPipe:
		return func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialNamedPipe(ctx, h.Addr)
		}, nil
	case SchemeWSL:
		return func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialWSL(ctx, h, relay)
		}, nil
	default:
		return nil, fmt.Errorf("client: no dialer for scheme %q", h.Scheme)
	}
}

// pipeAddr is the net.Addr a non-socket transport reports.
type pipeAddr struct {
	network string
	addr    string
}

// Network names the transport.
func (a pipeAddr) Network() string { return a.network }

// String renders the endpoint.
func (a pipeAddr) String() string { return a.addr }
