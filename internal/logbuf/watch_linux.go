//go:build linux

package logbuf

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// inotifyWatcher wakes a follower as soon as the log directory changes, so
// `hull logs -f` is not bound by the poll interval. It watches the directory
// rather than the file because rotation replaces the inode behind the name.
type inotifyWatcher struct {
	fd  int
	buf []byte
}

// newChangeWatcher returns an inotify-backed watcher for path's directory,
// degrading to plain polling when inotify is unavailable (fd exhaustion, or a
// filesystem that does not support it). Polling still guarantees liveness, so
// this fallback loses latency, not correctness.
func newChangeWatcher(path string) changeWatcher {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return pollWatcher{}
	}
	const mask = unix.IN_MODIFY | unix.IN_CREATE | unix.IN_MOVED_FROM |
		unix.IN_MOVED_TO | unix.IN_DELETE | unix.IN_ATTRIB
	if _, err := unix.InotifyAddWatch(fd, filepath.Dir(path), mask); err != nil {
		unix.Close(fd)
		return pollWatcher{}
	}
	return &inotifyWatcher{fd: fd, buf: make([]byte, 4096)}
}

// wait blocks until the watched directory changes, timeout elapses, or ctx is
// done. The timeout doubles as the ctx-cancellation granularity.
func (w *inotifyWatcher) wait(ctx context.Context, timeout time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ms := int(timeout / time.Millisecond)
	if ms <= 0 {
		ms = 1
	}
	pfd := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, ms)
	if err != nil && !errors.Is(err, unix.EINTR) {
		return nil // a broken watcher degrades to the caller's poll loop
	}
	if n > 0 {
		for {
			if _, err := unix.Read(w.fd, w.buf); err != nil {
				break
			}
		}
	}
	return ctx.Err()
}

// Close releases the inotify descriptor.
func (w *inotifyWatcher) Close() error {
	return unix.Close(w.fd)
}
