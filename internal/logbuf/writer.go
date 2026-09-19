package logbuf

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// WriterOptions configures a json-file log Writer.
type WriterOptions struct {
	// MaxSize is the size in bytes at which the active log file is rotated.
	// Zero means the file grows without bound.
	MaxSize int64
	// MaxFiles is the total number of log files kept, the active one included,
	// matching Docker's max-file. Values below 1 are treated as 1, which means
	// "no rotation history": the active file is truncated when it overflows.
	MaxFiles int
	// Compress gzips each file as it is rotated out, producing <path>.N.gz.
	Compress bool
}

// pending is one stream's not-yet-terminated fragment.
type pending struct {
	buf   []byte
	since time.Time
}

// Writer appends container output to a Docker-compatible json-file log,
// rotating it when it grows past WriterOptions.MaxSize.
//
// A Writer is safe for concurrent use; the shim writes stdout and stderr from
// two goroutines. Records are only ever emitted whole: a write that ends
// mid-line is buffered until the line is completed, until the idle timer
// fires, or until Close.
type Writer struct {
	path          string
	opts          WriterOptions
	flushInterval time.Duration

	mu     sync.Mutex
	f      *os.File
	size   int64
	closed bool
	pend   map[string]*pending
	now    func() time.Time

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// streamOrder fixes the order in which buffered fragments are flushed so the
// file is deterministic.
var streamOrder = [...]string{StreamStdout, StreamStderr}

// NewWriter opens (creating if needed) the json-file log at path and returns a
// Writer appending to it. The caller must Close it to flush the last fragment.
func NewWriter(path string, opts WriterOptions) (*Writer, error) {
	if path == "" {
		return nil, errors.New("logbuf: NewWriter: empty log path")
	}
	if opts.MaxSize < 0 {
		return nil, fmt.Errorf("logbuf: NewWriter: negative MaxSize %d", opts.MaxSize)
	}
	if opts.MaxFiles < 1 {
		opts.MaxFiles = 1
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("logbuf: open log %s: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("logbuf: stat log %s: %w", path, err)
	}
	w := &Writer{
		path:          path,
		opts:          opts,
		flushInterval: DefaultFlushInterval,
		f:             f,
		size:          st.Size(),
		pend:          make(map[string]*pending, 2),
		now:           time.Now,
		stop:          make(chan struct{}),
	}
	for _, s := range streamOrder {
		w.pend[s] = &pending{}
	}
	w.wg.Add(1)
	go w.flushLoop()
	return w, nil
}

// Path returns the path of the active log file.
func (w *Writer) Path() string { return w.path }

// Write appends p to the log as the named stream, which must be "stdout" or
// "stderr". It returns len(p) on success: every byte is either written out as
// one or more records or buffered as an unterminated fragment.
//
// A logical line longer than MaxRecordPayload is split into several records,
// each but the last marked partial, which is what Docker does and what
// `docker logs` re-joins.
func (w *Writer) Write(stream string, p []byte) (int, error) {
	if stream != StreamStdout && stream != StreamStderr {
		return 0, fmt.Errorf("%w (got %q)", ErrBadStream, stream)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	pd := w.pend[stream]
	ts := w.now()
	if len(pd.buf) == 0 {
		pd.since = ts
	}
	pd.buf = append(pd.buf, p...)
	if err := w.drain(stream, pd, ts); err != nil {
		return 0, err
	}
	return len(p), nil
}

// drain emits every complete record available in pd, leaving any trailing
// fragment shorter than MaxRecordPayload buffered. w.mu must be held.
func (w *Writer) drain(stream string, pd *pending, ts time.Time) error {
	for len(pd.buf) > 0 {
		idx := bytes.IndexByte(pd.buf, '\n')
		switch {
		case idx >= 0 && idx < MaxRecordPayload:
			if err := w.writeRecord(Entry{Log: pd.buf[:idx+1], Stream: stream, Time: ts}); err != nil {
				return err
			}
			pd.buf = pd.buf[idx+1:]
		case len(pd.buf) >= MaxRecordPayload:
			if err := w.writeRecord(Entry{Log: pd.buf[:MaxRecordPayload], Stream: stream, Time: ts, Partial: true}); err != nil {
				return err
			}
			pd.buf = pd.buf[MaxRecordPayload:]
		default:
			return nil
		}
	}
	pd.buf = pd.buf[:0]
	return nil
}

// Flush emits any buffered fragment immediately, marking it partial because
// more of the line may still arrive.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	return w.flushPending(true, time.Time{})
}

// flushPending emits each stream's buffered fragment. When older is non-zero
// only fragments that have been waiting since at or before that instant are
// emitted. w.mu must be held.
func (w *Writer) flushPending(partial bool, older time.Time) error {
	for _, stream := range streamOrder {
		pd := w.pend[stream]
		if len(pd.buf) == 0 {
			continue
		}
		if !older.IsZero() && pd.since.After(older) {
			continue
		}
		if err := w.writeRecord(Entry{Log: pd.buf, Stream: stream, Time: pd.since, Partial: partial}); err != nil {
			return err
		}
		pd.buf = pd.buf[:0]
	}
	return nil
}

// flushLoop emits fragments that have been idle for a whole flush interval.
func (w *Writer) flushLoop() {
	defer w.wg.Done()
	t := time.NewTicker(w.flushInterval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			w.mu.Lock()
			if !w.closed {
				// Errors here have nowhere to go; the next Write or Close
				// surfaces the same failure to the caller.
				_ = w.flushPending(true, w.now().Add(-w.flushInterval))
			}
			w.mu.Unlock()
		}
	}
}

// writeRecord marshals e, rotating first if it would overflow MaxSize, and
// appends it to the active file. w.mu must be held.
func (w *Writer) writeRecord(e Entry) error {
	b, err := marshalRecord(e)
	if err != nil {
		return err
	}
	if err := w.maybeRotate(int64(len(b))); err != nil {
		return err
	}
	n, err := w.f.Write(b)
	w.size += int64(n)
	if err != nil {
		return fmt.Errorf("logbuf: append to %s: %w", w.path, err)
	}
	return nil
}

// maybeRotate rotates the log if appending n more bytes would push it past
// MaxSize. A single record larger than MaxSize is still written whole, to an
// otherwise empty file. w.mu must be held.
func (w *Writer) maybeRotate(n int64) error {
	if w.opts.MaxSize <= 0 || w.size == 0 || w.size+n <= w.opts.MaxSize {
		return nil
	}
	return w.rotate()
}

// rotate shifts <path>.N to <path>.N+1, moves the active file to <path>.1
// (gzipping it when configured) and opens a fresh active file. It holds an
// exclusive flock on the outgoing file throughout so a concurrent tailer never
// observes a half-shifted set. w.mu must be held.
func (w *Writer) rotate() error {
	old := w.f
	if err := lockFile(old, true); err != nil {
		return err
	}
	defer func() {
		_ = unlockFile(old)
	}()

	if w.opts.MaxFiles <= 1 {
		if err := old.Truncate(0); err != nil {
			return fmt.Errorf("logbuf: truncate %s: %w", w.path, err)
		}
		if _, err := old.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("logbuf: rewind %s: %w", w.path, err)
		}
		w.size = 0
		return nil
	}

	last := w.opts.MaxFiles - 1
	if err := removeIndexed(w.path, last); err != nil {
		return err
	}
	for i := last - 1; i >= 1; i-- {
		if err := renameIndexed(w.path, i, i+1); err != nil {
			return err
		}
	}
	first := rotatedName(w.path, 1, false)
	if err := os.Rename(w.path, first); err != nil {
		return fmt.Errorf("logbuf: rotate %s: %w", w.path, err)
	}
	if w.opts.Compress {
		if err := compressFile(first, rotatedName(w.path, 1, true)); err != nil {
			return err
		}
	}
	nf, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("logbuf: reopen %s after rotation: %w", w.path, err)
	}
	w.f = nf
	w.size = 0
	// The outgoing handle is unlocked by the deferred call, then closed here,
	// so a tailer blocked on a shared lock wakes with a consistent tree.
	defer old.Close()
	return nil
}

// Close flushes the last fragment of each stream as a final, non-partial
// record and closes the underlying file. It is safe to call twice.
func (w *Writer) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.mu.Unlock()

	w.stopOnce.Do(func() { close(w.stop) })
	w.wg.Wait()

	w.mu.Lock()
	defer w.mu.Unlock()
	// At Close there is no continuation, so the trailing fragment is a whole
	// (if newline-less) line, exactly as Docker's copier treats EOF.
	ferr := w.flushPending(false, time.Time{})
	cerr := w.f.Close()
	if ferr != nil {
		return ferr
	}
	if cerr != nil {
		return fmt.Errorf("logbuf: close %s: %w", w.path, cerr)
	}
	return nil
}

// setClock replaces the Writer's clock. Tests only.
func (w *Writer) setClock(fn func() time.Time) {
	w.mu.Lock()
	w.now = fn
	w.mu.Unlock()
}

// rotatedName builds the <path>.<n> or <path>.<n>.gz name.
func rotatedName(path string, n int, gz bool) string {
	s := path + "." + strconv.Itoa(n)
	if gz {
		s += ".gz"
	}
	return s
}

// removeIndexed deletes generation n in either its plain or gzipped form.
func removeIndexed(path string, n int) error {
	for _, gz := range []bool{false, true} {
		name := rotatedName(path, n, gz)
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("logbuf: drop oldest log %s: %w", name, err)
		}
	}
	return nil
}

// renameIndexed shifts generation from to generation to, preserving whether
// the file is gzipped.
func renameIndexed(path string, from, to int) error {
	for _, gz := range []bool{false, true} {
		src := rotatedName(path, from, gz)
		if _, err := os.Lstat(src); err != nil {
			continue
		}
		dst := rotatedName(path, to, gz)
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("logbuf: shift %s to %s: %w", src, dst, err)
		}
	}
	return nil
}

// compressFile gzips src to dst and removes src. The gzip header keeps src's
// modification time so tooling can still order generations by age.
func compressFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("logbuf: open %s for compression: %w", src, err)
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return fmt.Errorf("logbuf: stat %s: %w", src, err)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("logbuf: create %s: %w", dst, err)
	}
	zw := gzip.NewWriter(out)
	zw.Name = filepath.Base(src)
	zw.ModTime = st.ModTime()
	if _, err := io.Copy(zw, in); err != nil {
		zw.Close()
		out.Close()
		os.Remove(dst)
		return fmt.Errorf("logbuf: compress %s: %w", src, err)
	}
	if err := zw.Close(); err != nil {
		out.Close()
		os.Remove(dst)
		return fmt.Errorf("logbuf: finish %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return fmt.Errorf("logbuf: close %s: %w", dst, err)
	}
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("logbuf: remove %s after compression: %w", src, err)
	}
	return nil
}
