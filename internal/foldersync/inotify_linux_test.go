//go:build linux

package foldersync

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// inotifyRecord builds one on-the-wire inotify record, the way the kernel
// writes it: a fixed 16-byte header followed by a NUL-terminated, NUL-padded
// name.
func inotifyRecord(wd int32, mask, cookie uint32, name string) []byte {
	var nameBuf []byte
	if name != "" {
		nameBuf = make([]byte, (len(name)+1+15)/16*16)
		copy(nameBuf, name)
	}
	rec := make([]byte, 16+len(nameBuf))
	binary.NativeEndian.PutUint32(rec[0:], uint32(wd))
	binary.NativeEndian.PutUint32(rec[4:], mask)
	binary.NativeEndian.PutUint32(rec[8:], cookie)
	binary.NativeEndian.PutUint32(rec[12:], uint32(len(nameBuf)))
	copy(rec[16:], nameBuf)
	return rec
}

func TestDecodeInotify(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want []inotifyEvent
	}{
		{
			name: "empty buffer",
			buf:  nil,
		},
		{
			name: "one named event",
			buf:  inotifyRecord(1, unix.IN_CLOSE_WRITE, 0, "app.js"),
			want: []inotifyEvent{{wd: 1, mask: unix.IN_CLOSE_WRITE, name: "app.js"}},
		},
		{
			name: "event without a name",
			buf:  inotifyRecord(3, unix.IN_DELETE_SELF, 0, ""),
			want: []inotifyEvent{{wd: 3, mask: unix.IN_DELETE_SELF}},
		},
		{
			name: "rename pair carries the cookie",
			buf: append(
				inotifyRecord(1, unix.IN_MOVED_FROM, 42, "old.js"),
				inotifyRecord(1, unix.IN_MOVED_TO, 42, "new.js")...,
			),
			want: []inotifyEvent{
				{wd: 1, mask: unix.IN_MOVED_FROM, cookie: 42, name: "old.js"},
				{wd: 1, mask: unix.IN_MOVED_TO, cookie: 42, name: "new.js"},
			},
		},
		{
			name: "overflow record, which has wd -1 and no name",
			buf:  inotifyRecord(-1, unix.IN_Q_OVERFLOW, 0, ""),
			want: []inotifyEvent{{wd: -1, mask: unix.IN_Q_OVERFLOW}},
		},
		{
			name: "overflow at the end of a batch",
			buf: append(
				inotifyRecord(1, unix.IN_CREATE, 0, "a.txt"),
				inotifyRecord(-1, unix.IN_Q_OVERFLOW, 0, "")...,
			),
			want: []inotifyEvent{
				{wd: 1, mask: unix.IN_CREATE, name: "a.txt"},
				{wd: -1, mask: unix.IN_Q_OVERFLOW},
			},
		},
		{
			name: "truncated header is dropped",
			buf:  []byte{1, 2, 3},
		},
		{
			name: "truncated name is dropped",
			buf:  inotifyRecord(1, unix.IN_CREATE, 0, "app.js")[:20],
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeInotify(tt.buf)
			if len(got) != len(tt.want) {
				t.Fatalf("decodeInotify() = %+v, want %+v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("decodeInotify()[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestInotifyWatcherProcess(t *testing.T) {
	root := t.TempDir()
	ig, err := NewIgnorer(DefaultIgnores()...)
	if err != nil {
		t.Fatalf("NewIgnorer() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	w, err := newTreeWatcher(root, ig)
	if err != nil {
		t.Fatalf("newTreeWatcher() error = %v", err)
	}
	defer w.close()
	iw := w.(*inotifyWatcher)

	rootWD := int32(0)
	iw.mu.Lock()
	for wd, rel := range iw.byWD {
		if rel == "" {
			rootWD = wd
		}
	}
	iw.mu.Unlock()
	if rootWD == 0 {
		t.Fatalf("the root directory has no watch")
	}

	tests := []struct {
		name         string
		evs          []inotifyEvent
		wantChanged  bool
		wantOverflow bool
		wantPaths    []string
	}{
		{
			name:        "a write is a change",
			evs:         []inotifyEvent{{wd: rootWD, mask: unix.IN_CLOSE_WRITE, name: "app.js"}},
			wantChanged: true,
			wantPaths:   []string{"app.js"},
		},
		{
			name: "a write to an ignored file is not",
			evs:  []inotifyEvent{{wd: rootWD, mask: unix.IN_CLOSE_WRITE, name: ".app.js.swp"}},
		},
		{
			name: "an ignored directory appearing is not",
			evs:  []inotifyEvent{{wd: rootWD, mask: unix.IN_CREATE | unix.IN_ISDIR, name: "node_modules"}},
		},
		{
			name: "an unknown descriptor is ignored",
			evs:  []inotifyEvent{{wd: 9999, mask: unix.IN_CREATE, name: "x"}},
		},
		{
			name: "a bare IN_IGNORED is bookkeeping, not a change",
			evs:  []inotifyEvent{{wd: rootWD, mask: unix.IN_IGNORED}},
		},
		{
			name:         "overflow is reported on its own",
			evs:          []inotifyEvent{{wd: -1, mask: unix.IN_Q_OVERFLOW}},
			wantOverflow: true,
		},
		{
			name: "overflow alongside a real event",
			evs: []inotifyEvent{
				{wd: rootWD, mask: unix.IN_CREATE, name: "a.txt"},
				{wd: -1, mask: unix.IN_Q_OVERFLOW},
			},
			wantChanged:  true,
			wantOverflow: true,
			wantPaths:    []string{"a.txt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The bare IN_IGNORED case retires the root watch, so re-arm
			// between cases.
			defer func() {
				if err := iw.rearm(); err != nil {
					t.Fatalf("rearm() error = %v", err)
				}
			}()
			got := iw.process(tt.evs)
			if got.changed != tt.wantChanged {
				t.Errorf("changed = %v, want %v", got.changed, tt.wantChanged)
			}
			if got.overflow != tt.wantOverflow {
				t.Errorf("overflow = %v, want %v", got.overflow, tt.wantOverflow)
			}
			if !equalPaths(got.paths, tt.wantPaths) {
				t.Errorf("paths = %q, want %q", got.paths, tt.wantPaths)
			}
		})
	}
}

func TestInotifyWatcherWatchesNewDirectoriesRecursively(t *testing.T) {
	root := t.TempDir()
	ig, err := NewIgnorer(DefaultIgnores()...)
	if err != nil {
		t.Fatalf("NewIgnorer() error = %v", err)
	}
	w, err := newTreeWatcher(root, ig)
	if err != nil {
		t.Fatalf("newTreeWatcher() error = %v", err)
	}
	defer w.close()

	if got := w.watchCount(); got != 1 {
		t.Fatalf("watchCount() = %d over an empty tree, want 1 (the root)", got)
	}

	// A whole tree renamed in raises exactly one event for the top directory,
	// so the watcher has to walk into it itself or everything below is
	// invisible from then on.
	staging := t.TempDir()
	if err := os.MkdirAll(filepath.Join(staging, "pkg", "deep"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Rename(filepath.Join(staging, "pkg"), filepath.Join(root, "pkg")); err != nil {
		t.Skipf("cannot rename across temp dirs here: %v", err)
	}

	iw := w.(*inotifyWatcher)
	rootWD := int32(0)
	iw.mu.Lock()
	for wd, rel := range iw.byWD {
		if rel == "" {
			rootWD = wd
		}
	}
	iw.mu.Unlock()

	r := iw.process([]inotifyEvent{{wd: rootWD, mask: unix.IN_MOVED_TO | unix.IN_ISDIR, name: "pkg"}})
	if !r.changed {
		t.Fatalf("a directory appearing is a change")
	}
	if got := w.watchCount(); got != 3 {
		t.Fatalf("watchCount() = %d, want 3 (root, pkg, pkg/deep)", got)
	}

	// An ignored directory must never consume a watch descriptor; on a real
	// project node_modules would eat tens of thousands of them.
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "react"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	r = iw.process([]inotifyEvent{{wd: rootWD, mask: unix.IN_CREATE | unix.IN_ISDIR, name: "node_modules"}})
	if r.changed {
		t.Fatalf("an ignored directory must not be reported as a change")
	}
	if got := w.watchCount(); got != 3 {
		t.Fatalf("watchCount() = %d after an ignored directory appeared, want 3", got)
	}
}

func TestInotifyWatcherSeesARealWrite(t *testing.T) {
	root := t.TempDir()
	ig, err := NewIgnorer(DefaultIgnores()...)
	if err != nil {
		t.Fatalf("NewIgnorer() error = %v", err)
	}
	w, err := newTreeWatcher(root, ig)
	if err != nil {
		t.Fatalf("newTreeWatcher() error = %v", err)
	}
	defer w.close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	type waited struct {
		r   watchResult
		err error
	}
	ch := make(chan waited, 1)
	go func() {
		r, err := w.wait(ctx)
		ch <- waited{r, err}
	}()

	// Give the waiter a moment to reach poll(2), then write.
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	select {
	case got := <-ch:
		if got.err != nil {
			t.Fatalf("wait() error = %v", got.err)
		}
		if !got.r.changed {
			t.Fatalf("wait() = %+v, want a change", got.r)
		}
		if len(got.r.paths) == 0 || got.r.paths[0] != "app.js" {
			t.Fatalf("wait() paths = %q, want app.js", got.r.paths)
		}
	case <-ctx.Done():
		t.Fatalf("no inotify event arrived for a real write")
	}
}

func TestInotifyWatcherWaitHonoursCancellation(t *testing.T) {
	root := t.TempDir()
	ig, err := NewIgnorer()
	if err != nil {
		t.Fatalf("NewIgnorer() error = %v", err)
	}
	w, err := newTreeWatcher(root, ig)
	if err != nil {
		t.Fatalf("newTreeWatcher() error = %v", err)
	}
	defer w.close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := w.wait(ctx); !isDone(err) {
		t.Fatalf("wait() error = %v, want a context error", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("wait() took %v to notice cancellation", elapsed)
	}
}
