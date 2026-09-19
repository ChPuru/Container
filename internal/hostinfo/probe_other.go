//go:build !linux

package hostinfo

import "context"

// DefaultDataRoot is where hull keeps its data inside the engine distro. It is
// declared on every platform so the Windows CLI can name it in help text, but
// only the Linux build ever reads it.
const DefaultDataRoot = "/var/lib/hull"

// Probe is not implemented outside Linux and always returns [ErrUnsupported].
//
// The Windows hull CLI does not probe locally: it asks hulld inside the engine
// distro for a [Report] over the relay and renders the result with
// [Report.Text] or [Report.JSON], both of which are portable.
func Probe(ctx context.Context) (*Report, error) {
	_ = ctx
	return nil, ErrUnsupported
}
