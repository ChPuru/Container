//go:build !linux

package content

import (
	"context"
	"errors"
)

// fileLock is the non-Linux stand-in for the flock-based store lock.
type fileLock struct{}

// acquireLock reports, loudly, that the store lock is unavailable. The content
// store is only ever garbage-collected by hulld, which runs on Linux; anything
// else must not silently proceed without mutual exclusion.
func acquireLock(ctx context.Context, path string) (*fileLock, error) {
	_ = ctx
	_ = path
	return nil, errors.New("content: the content-store lock requires flock(2) and is only supported on Linux")
}

// release is a no-op; a lock is never handed out on this platform.
func (l *fileLock) release() error { return nil }
