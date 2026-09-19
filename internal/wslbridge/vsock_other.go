//go:build !windows

package wslbridge

import (
	"context"
	"fmt"
	"net"
	"time"
)

// DiscoverVMIDs has nothing to discover off Windows: AF_HYPERV is a Windows
// host-side address family, and the engine distro itself never dials it.
func DiscoverVMIDs(ctx context.Context) ([]string, error) {
	_ = ctx
	return nil, fmt.Errorf("%w: %w", ErrVsockUnavailable, ErrUnsupportedPlatform)
}

// dialHVSock is unavailable off Windows.
func dialHVSock(ctx context.Context, vmID string, port uint32, timeout time.Duration) (net.Conn, error) {
	_, _, _, _ = ctx, vmID, port, timeout
	return nil, ErrUnsupportedPlatform
}
