package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/rahuldhali/hull/internal/client"
	"github.com/rahuldhali/hull/internal/logbuf"
	"github.com/rahuldhali/hull/internal/types"
)

// maxPendingLine bounds how much of an unterminated line the splitter will
// hold before flushing it anyway. A container that writes a gigabyte with no
// newline is not a reason for the dashboard to grow without limit.
const maxPendingLine = 64 << 10

// Logs streams a container's log to fn, one whole line at a time.
//
// Three things have to be got right here and none of them are visible from the
// endpoint's signature. The stream is multiplexed with Docker's eight-byte
// frame header unless the container has a TTY, so which it is has to be known
// before the first byte is read. A frame is a write, not a line: one frame may
// carry several lines or half of one, so lines are reassembled per stream.
// And the timestamps are requested and parsed rather than stamped on arrival,
// because the replayed tail is historic and stamping it "now" would make every
// container look as though it had just spoken.
func (e *EngineClient) Logs(ctx context.Context, idOrName string, opts LogOptions, fn func(LogLine) error) error {
	copts := client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Timestamps: true,
		Follow:     opts.Follow,
		Tail:       tailParam(opts.Tail),
	}
	if !opts.Since.IsZero() {
		copts.Since = strconv.FormatInt(opts.Since.Unix(), 10)
	}
	if !opts.Until.IsZero() {
		copts.Until = strconv.FormatInt(opts.Until.Unix(), 10)
	}

	tty := e.containerTTY(ctx, idOrName)

	rc, err := e.c.ContainerLogs(ctx, idOrName, copts)
	if err != nil {
		return fmt.Errorf("tui: logs for %s: %w", idOrName, err)
	}
	defer func() { _ = rc.Close() }()

	// The request carries ctx, so cancelling it aborts the transport; this
	// closes the body as well, which is what unblocks a read that is
	// already parked inside a relay that does not watch the context.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = rc.Close()
		case <-done:
		}
	}()

	sp := &logSplitter{fn: fn, pending: map[string][]byte{}}
	if tty {
		err = copyTTYLog(rc, sp)
	} else {
		err = logbuf.DemuxFramed(rc, sp.writer(logbuf.StreamStdout), sp.writer(logbuf.StreamStderr))
	}
	if ferr := sp.flush(); err == nil {
		err = ferr
	}
	switch {
	case err == nil, ctx.Err() != nil, errors.Is(err, context.Canceled),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return nil
	default:
		return fmt.Errorf("tui: logs for %s: %w", idOrName, err)
	}
}

// tailParam renders a tail count the way the API wants it: a number, or "all".
func tailParam(n int) string {
	switch {
	case n < 0:
		return "all"
	case n == 0:
		return "0"
	default:
		return strconv.Itoa(n)
	}
}

// containerTTY reports whether a container was created with a pseudo-terminal,
// which decides whether its log stream is framed. A container that cannot be
// inspected is assumed not to have one, which is the common case and the shape
// hull's own json-file driver writes.
func (e *EngineClient) containerTTY(ctx context.Context, idOrName string) bool {
	if rec, ok := e.cachedAny(idOrName); ok {
		return rec.Config.Tty
	}
	in, err := e.c.ContainerInspect(ctx, idOrName, false)
	if err != nil || in == nil {
		return false
	}
	return in.Tty()
}

// cachedAny returns the cached record for a container whatever state it was
// taken in, for the questions whose answer cannot change over a container's
// life.
func (e *EngineClient) cachedAny(id string) (types.Container, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	got, ok := e.cache[id]
	if !ok {
		return types.Container{}, false
	}
	return got.rec, true
}

// copyTTYLog reads an unframed stream, which is what a container with a
// pseudo-terminal produces: one interleaved stream, all of it stdout.
func copyTTYLog(r io.Reader, sp *logSplitter) error {
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if werr := sp.write(logbuf.StreamStdout, buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("tui: read log stream: %w", err)
		}
	}
}

// logSplitter reassembles whole lines from the arbitrary chunks a log stream
// delivers, and hands each one to the dashboard as a [LogLine].
//
// It keeps one pending buffer per stream rather than one overall, because
// stdout and stderr are independent writers: a half-written stdout line must
// not be completed by the next stderr frame.
type logSplitter struct {
	fn      func(LogLine) error
	pending map[string][]byte
}

// writer returns an io.Writer that feeds one stream of the splitter, which is
// the shape [logbuf.DemuxFramed] wants.
func (l *logSplitter) writer(stream string) io.Writer {
	return writerFunc(func(p []byte) (int, error) {
		if err := l.write(stream, p); err != nil {
			return 0, err
		}
		return len(p), nil
	})
}

// write folds one chunk in and emits every complete line it produced.
func (l *logSplitter) write(stream string, p []byte) error {
	buf := append(l.pending[stream], p...)
	for {
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			break
		}
		if err := l.emit(stream, buf[:i]); err != nil {
			l.pending[stream] = nil
			return err
		}
		buf = buf[i+1:]
	}
	if len(buf) > maxPendingLine {
		if err := l.emit(stream, buf); err != nil {
			l.pending[stream] = nil
			return err
		}
		buf = nil
	}
	l.pending[stream] = append([]byte(nil), buf...)
	return nil
}

// flush emits whatever is left over when the stream ends, so a final line with
// no newline is not lost.
func (l *logSplitter) flush() error {
	for _, stream := range []string{logbuf.StreamStdout, logbuf.StreamStderr} {
		rest := l.pending[stream]
		if len(rest) == 0 {
			continue
		}
		l.pending[stream] = nil
		if err := l.emit(stream, rest); err != nil {
			return err
		}
	}
	return nil
}

// emit parses one line's timestamp prefix and delivers it.
func (l *logSplitter) emit(stream string, line []byte) error {
	text := string(bytes.TrimSuffix(line, []byte("\r")))
	ts, rest := splitLogTimestamp(text)
	return l.fn(LogLine{Time: ts, Stream: stream, Line: rest})
}

// splitLogTimestamp peels the RFC3339 nanosecond prefix the engine writes when
// timestamps are requested. A line that does not start with one - anything a
// TTY container wrote before the engine got involved, or a daemon that ignored
// the parameter - is returned whole with a zero time, and the view then simply
// does not print a clock in front of it.
func splitLogTimestamp(line string) (time.Time, string) {
	sp := bytes.IndexByte([]byte(line), ' ')
	if sp <= 0 {
		return time.Time{}, line
	}
	ts, err := time.Parse(logbuf.TimestampFormat, line[:sp])
	if err != nil {
		if ts, err = time.Parse(time.RFC3339Nano, line[:sp]); err != nil {
			return time.Time{}, line
		}
	}
	return ts, line[sp+1:]
}

// writerFunc adapts a function to io.Writer.
type writerFunc func(p []byte) (int, error)

// Write calls the function.
func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
