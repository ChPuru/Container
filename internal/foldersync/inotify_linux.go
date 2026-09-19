//go:build linux

package foldersync

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// watchMask is what the volume side subscribes to.
//
// IN_CLOSE_WRITE rather than IN_MODIFY alone is what makes a write from a
// container observable exactly once, after the writer has finished; IN_MODIFY
// is kept anyway because a process that never closes its fd (a log, a
// database) still has to be noticed. IN_EXCL_UNLINK stops a deleted-but-open
// file from generating events nobody can act on.
const watchMask = unix.IN_CREATE |
	unix.IN_DELETE |
	unix.IN_DELETE_SELF |
	unix.IN_MODIFY |
	unix.IN_ATTRIB |
	unix.IN_CLOSE_WRITE |
	unix.IN_MOVED_FROM |
	unix.IN_MOVED_TO |
	unix.IN_MOVE_SELF |
	unix.IN_EXCL_UNLINK

// inotifyBufSize holds a few hundred events, which keeps the number of read(2)
// calls down during a burst without making the kernel's own queue any deeper.
const inotifyBufSize = 64 * 1024

// pollTimeoutMS is how long a wait blocks in poll(2) before looking at the
// context again. It is the upper bound on how long Run takes to notice a
// cancellation, and it costs one wakeup per quarter second per sync pair.
const pollTimeoutMS = 250

// inotifyWatcher is the Linux volume-side watcher: one inotify instance, one
// watch per directory in the tree, re-added as directories appear.
//
// inotify is not recursive and never will be, so the recursion is here:
// creating a directory adds a watch for it (and, because a whole tree can be
// renamed in with one event, for everything already inside it), and losing one
// drops its watch.
type inotifyWatcher struct {
	root string
	ig   *Ignorer
	fd   int
	buf  []byte

	mu     sync.Mutex
	byWD   map[int32]string
	byPath map[string]int32
	closed bool
}

// newTreeWatcher opens an inotify instance over root and watches every
// directory the ignore set admits.
func newTreeWatcher(root string, ig *Ignorer) (treeWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("foldersync: inotify_init1: %w", err)
	}
	w := &inotifyWatcher{
		root:   root,
		ig:     ig,
		fd:     fd,
		buf:    make([]byte, inotifyBufSize),
		byWD:   make(map[int32]string),
		byPath: make(map[string]int32),
	}
	if err := w.addTree(""); err != nil {
		w.close()
		return nil, err
	}
	return w, nil
}

// addTree adds a watch for rel and, recursively, for every directory beneath
// it that the ignore set admits.
func (w *inotifyWatcher) addTree(rel string) error {
	if err := w.add(rel); err != nil {
		return err
	}
	dir := w.root
	if rel != "" {
		dir = filepath.Join(w.root, filepath.FromSlash(rel))
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("foldersync: read directory %s: %w", dir, err)
	}
	for _, de := range ents {
		if !de.IsDir() {
			continue
		}
		child := de.Name()
		if rel != "" {
			child = path.Join(rel, de.Name())
		}
		if w.ig.Match(child, true) {
			continue
		}
		if err := w.addTree(child); err != nil {
			return err
		}
	}
	return nil
}

// add installs one watch. Adding a watch for a path that already has one is
// how inotify updates a mask, and it returns the same descriptor, so this is
// idempotent.
func (w *inotifyWatcher) add(rel string) error {
	dir := w.root
	if rel != "" {
		dir = filepath.Join(w.root, filepath.FromSlash(rel))
	}
	wd, err := unix.InotifyAddWatch(w.fd, dir, watchMask)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			// The directory went away between the readdir and here. The next
			// reconciliation pass will see that for itself.
			return nil
		}
		if errors.Is(err, unix.ENOSPC) {
			return fmt.Errorf("foldersync: watch %s: %w (raise fs.inotify.max_user_watches)", dir, err)
		}
		return fmt.Errorf("foldersync: watch %s: %w", dir, err)
	}
	w.mu.Lock()
	w.byWD[int32(wd)] = rel
	w.byPath[rel] = int32(wd)
	w.mu.Unlock()
	return nil
}

// forget drops the bookkeeping for a watch the kernel has retired.
func (w *inotifyWatcher) forget(wd int32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if rel, ok := w.byWD[wd]; ok {
		delete(w.byPath, rel)
		delete(w.byWD, wd)
	}
}

// pathFor maps a watch descriptor back to its relative directory.
func (w *inotifyWatcher) pathFor(wd int32) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	rel, ok := w.byWD[wd]
	return rel, ok
}

// watchCount implements treeWatcher.
func (w *inotifyWatcher) watchCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.byWD)
}

// rearm implements treeWatcher: re-walk the tree and add whatever is missing.
func (w *inotifyWatcher) rearm() error {
	w.mu.Lock()
	closed := w.closed
	w.mu.Unlock()
	if closed {
		return nil
	}
	return w.addTree("")
}

// close implements treeWatcher.
func (w *inotifyWatcher) close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.byWD = map[int32]string{}
	w.byPath = map[string]int32{}
	w.mu.Unlock()
	if err := unix.Close(w.fd); err != nil {
		return fmt.Errorf("foldersync: close inotify: %w", err)
	}
	return nil
}

// wait implements treeWatcher. It blocks in poll(2) with a short timeout so a
// cancelled context is noticed without needing a second wakeup fd, and it
// keeps going until an event arrives that is actually worth a pass - an event
// inside an ignored directory is not.
func (w *inotifyWatcher) wait(ctx context.Context) (watchResult, error) {
	for {
		if err := ctx.Err(); err != nil {
			return watchResult{}, err
		}
		w.mu.Lock()
		closed := w.closed
		w.mu.Unlock()
		if closed {
			return watchResult{}, os.ErrClosed
		}

		fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, pollTimeoutMS)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return watchResult{}, fmt.Errorf("foldersync: poll inotify: %w", err)
		}
		if n == 0 {
			continue
		}

		nread, err := unix.Read(w.fd, w.buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return watchResult{}, fmt.Errorf("foldersync: read inotify: %w", err)
		}
		if nread <= 0 {
			continue
		}
		r := w.process(decodeInotify(w.buf[:nread]))
		if r.changed || r.overflow {
			return r, nil
		}
	}
}

// inotifyEvent is one decoded record from the inotify stream.
type inotifyEvent struct {
	wd     int32
	mask   uint32
	cookie uint32
	name   string
}

// decodeInotify splits a read(2) buffer into records. It is a pure function
// over bytes - no unsafe pointer arithmetic over a possibly-misaligned
// buffer - so a synthetic buffer can be fed to it in a test, which is the only
// practical way to exercise the overflow path without filling the kernel's
// 16384-event queue for real.
func decodeInotify(buf []byte) []inotifyEvent {
	const hdr = 16 // wd int32, mask uint32, cookie uint32, len uint32
	var out []inotifyEvent
	for off := 0; off+hdr <= len(buf); {
		wd := int32(binary.NativeEndian.Uint32(buf[off:]))
		mask := binary.NativeEndian.Uint32(buf[off+4:])
		cookie := binary.NativeEndian.Uint32(buf[off+8:])
		nameLen := int(binary.NativeEndian.Uint32(buf[off+12:]))
		if nameLen < 0 || off+hdr+nameLen > len(buf) {
			break
		}
		name := ""
		if nameLen > 0 {
			name = strings.TrimRight(string(buf[off+hdr:off+hdr+nameLen]), "\x00")
		}
		out = append(out, inotifyEvent{wd: wd, mask: mask, cookie: cookie, name: name})
		off += hdr + nameLen
	}
	return out
}

// process applies a batch of decoded events: it keeps the watch set in step
// with the tree and reports whether anything worth a reconciliation pass
// happened.
func (w *inotifyWatcher) process(evs []inotifyEvent) watchResult {
	var r watchResult
	for _, ev := range evs {
		if ev.mask&unix.IN_Q_OVERFLOW != 0 {
			// The kernel dropped events. Whatever was in the queue is
			// unknowable now, so the caller must fall back to a full scan.
			r.overflow = true
			continue
		}
		dir, ok := w.pathFor(ev.wd)
		if !ok {
			continue
		}
		rel := dir
		if ev.name != "" {
			rel = path.Join(dir, ev.name)
		}
		isDir := ev.mask&unix.IN_ISDIR != 0

		if ev.mask&(unix.IN_IGNORED|unix.IN_DELETE_SELF) != 0 {
			w.forget(ev.wd)
		}
		if ev.mask&^uint32(unix.IN_IGNORED) == 0 {
			// Bookkeeping only: the watch was removed, nothing changed.
			continue
		}
		if rel != "" && w.ig.Match(rel, isDir) {
			continue
		}
		if isDir && ev.mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 {
			// A directory appeared. inotify does not watch it for us, and
			// anything already inside it (a renamed-in tree) has produced no
			// events at all, so the whole subtree needs watches now.
			_ = w.addTree(rel)
		}
		r.changed = true
		if rel != "" {
			r.paths = append(r.paths, rel)
		}
	}
	return r
}
