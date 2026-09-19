//go:build !linux

package layer

import (
	"context"
	"io"
)

// Apply is not implemented on this platform. Layer application depends on
// openat2, mknodat, xattrs and fd-relative ownership changes, none of which
// exist outside Linux; the hull CLI cross-compiles for Windows and must still
// link, so the call fails loudly instead of being absent.
func Apply(ctx context.Context, dest string, r io.Reader, opts ApplyOptions) (Result, error) {
	return Result{}, ErrUnsupportedPlatform
}

// Diff is not implemented on this platform. See Apply.
func Diff(ctx context.Context, upper, lower string, w io.Writer) (Result, error) {
	return Result{}, ErrUnsupportedPlatform
}
