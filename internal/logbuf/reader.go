package logbuf

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ReadOptions selects which part of a container's log Read delivers.
type ReadOptions struct {
	// Follow keeps Read blocked after the end of the log, delivering records
	// as they are written, until ctx is cancelled.
	Follow bool
	// Tail delivers only the last N records; -1 delivers everything. Zero
	// delivers no history at all, which is only useful together with Follow.
	Tail int
	// Since drops records written strictly before this instant.
	Since time.Time
	// Until drops records written strictly after this instant.
	Until time.Time
	// Stdout and Stderr select which streams are delivered. At least one must
	// be set, or Read fails with ErrNoStreams.
	Stdout bool
	Stderr bool
	// Timestamps is carried for the caller's benefit: Read always populates
	// Entry.Time, and it is WriteFramed that renders the timestamp prefix.
	Timestamps bool
}

// changeWatcher wakes a follower when the log directory changes.
type changeWatcher interface {
	wait(ctx context.Context, timeout time.Duration) error
	Close() error
}

// pollWatcher is the portable fallback: a plain timed wait.
type pollWatcher struct{}

func (pollWatcher) wait(ctx context.Context, timeout time.Duration) error {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (pollWatcher) Close() error { return nil }

// followPollInterval bounds how long a follower sleeps without a filesystem
// notification, and therefore how quickly it notices ctx cancellation.
const followPollInterval = 100 * time.Millisecond

// maxPendingLine caps the unterminated tail a follower will buffer before
// deciding the file is corrupt rather than merely mid-write.
const maxPendingLine = 8 << 20

// Read delivers the container log at path to fn, oldest record first.
//
// Rotated generations (<path>.N and <path>.N.gz) are read in order whenever
// Tail or the whole-log pass reaches past the start of the active file. Tail
// seeks from the end and scans backwards for newlines instead of reading the
// file through. With Follow, Read blocks for new data, detects rotation by
// inode change and reopens, and returns nil once ctx is cancelled.
//
// An error returned by fn stops the walk and is returned unwrapped. Records
// that fail to parse are skipped: a torn final line is the normal shape of a
// log whose writer was killed.
func Read(ctx context.Context, path string, opts ReadOptions, fn func(Entry) error) error {
	if fn == nil {
		return errors.New("logbuf: Read: nil callback")
	}
	if path == "" {
		return errors.New("logbuf: Read: empty log path")
	}
	if !opts.Stdout && !opts.Stderr {
		return ErrNoStreams
	}
	err := read(ctx, path, opts, filtered(opts, fn))
	if err != nil && ctx.Err() != nil && errors.Is(err, ctx.Err()) {
		// Cancellation is a clean stop, not a failure.
		return nil
	}
	return err
}

// filtered wraps fn with the stream and time-window predicates.
func filtered(opts ReadOptions, fn func(Entry) error) func(Entry) error {
	return func(e Entry) error {
		switch e.Stream {
		case StreamStderr:
			if !opts.Stderr {
				return nil
			}
		default:
			// Treat anything that is not explicitly stderr as stdout, which is
			// how Docker handles records written by older daemons.
			if !opts.Stdout {
				return nil
			}
		}
		if !opts.Since.IsZero() && e.Time.Before(opts.Since) {
			return nil
		}
		if !opts.Until.IsZero() && e.Time.After(opts.Until) {
			return nil
		}
		return fn(e)
	}
}

func read(ctx context.Context, path string, opts ReadOptions, emit func(Entry) error) error {
	cur, err := os.Open(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("logbuf: open %s: %w", path, err)
	}
	if cur != nil {
		defer cur.Close()
	}

	rotated, err := rotatedGenerations(path)
	if err != nil {
		return err
	}
	if cur == nil && len(rotated) == 0 && !opts.Follow {
		return fmt.Errorf("logbuf: no log at %s: %w", path, os.ErrNotExist)
	}

	// Freeze the history boundary before scanning so nothing appended while we
	// work is either missed or delivered twice.
	var end int64
	if cur != nil {
		st, serr := cur.Stat()
		if serr != nil {
			return fmt.Errorf("logbuf: stat %s: %w", path, serr)
		}
		end = st.Size()
	}

	if opts.Tail < 0 {
		for i := len(rotated) - 1; i >= 0; i-- { // oldest generation first
			if err := streamWholeFile(ctx, rotated[i].name, emit); err != nil {
				return err
			}
		}
		if cur != nil && end > 0 {
			if err := streamLines(ctx, io.NewSectionReader(cur, 0, end), emit); err != nil {
				return err
			}
		}
	} else if opts.Tail > 0 {
		entries, err := tailEntries(ctx, cur, end, rotated, opts.Tail)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := emit(e); err != nil {
				return err
			}
		}
	}

	if !opts.Follow {
		return nil
	}
	if cur != nil {
		if _, err := cur.Seek(end, io.SeekStart); err != nil {
			return fmt.Errorf("logbuf: seek %s: %w", path, err)
		}
	}
	return follow(ctx, path, cur, end, emit)
}

// generation is one rotated file and its index; index 1 is the most recent.
type generation struct {
	index int
	name  string
	gzip  bool
}

// rotatedGenerations lists <path>.N and <path>.N.gz, most recent first.
func rotatedGenerations(path string) ([]generation, error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("logbuf: list %s: %w", dir, err)
	}
	var out []generation
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		rest, ok := strings.CutPrefix(name, base+".")
		if !ok {
			continue
		}
		gz := strings.HasSuffix(rest, ".gz")
		rest = strings.TrimSuffix(rest, ".gz")
		idx, err := strconv.Atoi(rest)
		if err != nil || idx < 1 {
			continue
		}
		out = append(out, generation{index: idx, name: filepath.Join(dir, name), gzip: gz})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].index < out[j].index })
	return out, nil
}

// openGeneration opens a rotated file, transparently decompressing it.
func openGeneration(name string) (io.ReadCloser, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("logbuf: open %s: %w", name, err)
	}
	if !strings.HasSuffix(name, ".gz") {
		return f, nil
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("logbuf: decompress %s: %w", name, err)
	}
	return &gzipReadCloser{zr: zr, f: f}, nil
}

type gzipReadCloser struct {
	zr *gzip.Reader
	f  *os.File
}

func (g *gzipReadCloser) Read(p []byte) (int, error) { return g.zr.Read(p) }

func (g *gzipReadCloser) Close() error {
	err := g.zr.Close()
	if cerr := g.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// streamWholeFile delivers every record of one (possibly gzipped) generation.
func streamWholeFile(ctx context.Context, name string, emit func(Entry) error) error {
	rc, err := openGeneration(name)
	if err != nil {
		return err
	}
	defer rc.Close()
	return streamLines(ctx, rc, emit)
}

// streamLines splits r into records and delivers the ones that parse.
func streamLines(ctx context.Context, r io.Reader, emit func(Entry) error) error {
	br := bufio.NewReaderSize(r, 64*1024)
	for n := 0; ; n++ {
		if n%64 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if e, perr := unmarshalRecord(line); perr == nil {
				if eerr := emit(e); eerr != nil {
					return eerr
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("logbuf: read log: %w", err)
		}
	}
}

// tailEntries collects the last n records, walking back through rotated
// generations only as far as it must.
func tailEntries(ctx context.Context, cur *os.File, end int64, rotated []generation, n int) ([]Entry, error) {
	var chunks [][][]byte // newest group first
	need := n

	if cur != nil && end > 0 {
		lines, err := lastLinesAt(cur, end, need)
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, lines)
		need -= len(lines)
	}
	for _, g := range rotated { // index 1 first, i.e. newest first
		if need <= 0 {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lines, err := lastLinesOfFile(g, need)
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, lines)
		need -= len(lines)
	}

	var out []Entry
	for i := len(chunks) - 1; i >= 0; i-- { // oldest group first
		for _, line := range chunks[i] {
			e, err := unmarshalRecord(line)
			if err != nil {
				continue
			}
			out = append(out, e)
		}
	}
	return out, nil
}

// lastLinesOfFile returns up to n trailing lines of a rotated generation,
// seeking backwards for a plain file and streaming for a compressed one.
func lastLinesOfFile(g generation, n int) ([][]byte, error) {
	if !g.gzip {
		f, err := os.Open(g.name)
		if err != nil {
			return nil, fmt.Errorf("logbuf: open %s: %w", g.name, err)
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("logbuf: stat %s: %w", g.name, err)
		}
		return lastLinesAt(f, st.Size(), n)
	}
	rc, err := openGeneration(g.name)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return lastLinesOfStream(rc, n)
}

// lastLinesAt returns up to n trailing lines of the first size bytes of ra by
// scanning backwards for newlines, so a Tail of a huge log touches only its
// last few pages.
func lastLinesAt(ra io.ReaderAt, size int64, n int) ([][]byte, error) {
	if n <= 0 || size <= 0 {
		return nil, nil
	}
	const chunk = 32 * 1024
	var buf []byte
	pos := size
	start := int64(0)
	found := false
	for pos > 0 {
		readSize := int64(chunk)
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize
		b := make([]byte, readSize)
		if _, err := ra.ReadAt(b, pos); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("logbuf: read backwards: %w", err)
		}
		buf = append(b, buf...)
		// Count newline terminators from the end; the (n+1)-th one bounds the
		// n records we want.
		seen := 0
		idx := len(buf)
		for idx > 0 {
			j := bytes.LastIndexByte(buf[:idx], '\n')
			if j < 0 {
				break
			}
			seen++
			idx = j
			if seen == n+1 {
				start = int64(j + 1)
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	tail := buf[start:]
	var out [][]byte
	for len(tail) > 0 {
		i := bytes.IndexByte(tail, '\n')
		if i < 0 {
			out = append(out, tail)
			break
		}
		out = append(out, tail[:i+1])
		tail = tail[i+1:]
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}

// lastLinesOfStream keeps the last n lines of a forward-only reader.
func lastLinesOfStream(r io.Reader, n int) ([][]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	ring := make([][]byte, 0, n)
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			cp := make([]byte, len(line))
			copy(cp, line)
			if len(ring) == n {
				ring = append(ring[1:], cp)
			} else {
				ring = append(ring, cp)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return ring, nil
			}
			return nil, fmt.Errorf("logbuf: read log: %w", err)
		}
	}
}

// follow delivers records as they are appended, reopening the log when the
// writer rotates it. f may be nil when the log does not exist yet.
func follow(ctx context.Context, path string, f *os.File, off int64, emit func(Entry) error) error {
	w := newChangeWatcher(path)
	defer w.Close()

	// The caller owns the handle it passed in; anything we open here is ours.
	owned := false
	defer func() {
		if owned && f != nil {
			f.Close()
		}
	}()

	var rem []byte
	buf := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		progressed := false
		if f != nil {
			n, err := readLocked(f, buf)
			if err != nil {
				return err
			}
			if n > 0 {
				off += int64(n)
				rem, err = consume(rem, buf[:n], emit)
				if err != nil {
					return err
				}
				progressed = true
			}
		}
		if progressed {
			continue
		}

		nf, reopened, newOff, err := checkReopen(path, f)
		if err != nil {
			return err
		}
		if reopened {
			if f != nil {
				// Drain anything the writer appended to the old inode between
				// our last read and the rename.
				for {
					n, rerr := readLocked(f, buf)
					if rerr != nil {
						return rerr
					}
					if n == 0 {
						break
					}
					if rem, err = consume(rem, buf[:n], emit); err != nil {
						return err
					}
				}
				if owned {
					f.Close()
				}
			}
			f, owned, off, rem = nf, true, newOff, nil
			continue
		}
		if err := w.wait(ctx, followPollInterval); err != nil {
			return err
		}
	}
}

// readLocked reads the next chunk under a shared advisory lock so a rotation
// in progress is never observed half-done.
func readLocked(f *os.File, buf []byte) (int, error) {
	if err := lockFile(f, false); err != nil {
		return 0, err
	}
	n, err := f.Read(buf)
	if uerr := unlockFile(f); uerr != nil && err == nil {
		err = uerr
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return n, fmt.Errorf("logbuf: read %s: %w", f.Name(), err)
	}
	return n, nil
}

// checkReopen reports whether the name now refers to a different inode (the
// writer rotated) or the same inode shrank (the writer truncated), and returns
// the handle to continue from.
func checkReopen(path string, f *os.File) (*os.File, bool, int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return f, false, 0, nil
		}
		return f, false, 0, fmt.Errorf("logbuf: stat %s: %w", path, err)
	}
	if f != nil {
		cfi, err := f.Stat()
		if err != nil {
			return f, false, 0, fmt.Errorf("logbuf: stat open log: %w", err)
		}
		if os.SameFile(fi, cfi) {
			if cur, err := f.Seek(0, io.SeekCurrent); err == nil && fi.Size() < cur {
				// Truncated in place (MaxFiles == 1): restart from the top.
				if _, err := f.Seek(0, io.SeekStart); err != nil {
					return f, false, 0, fmt.Errorf("logbuf: rewind %s: %w", path, err)
				}
			}
			return f, false, 0, nil
		}
	}
	nf, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return f, false, 0, nil
		}
		return f, false, 0, fmt.Errorf("logbuf: reopen %s: %w", path, err)
	}
	return nf, true, 0, nil
}

// consume splits newly read bytes into records, returning the unterminated
// remainder so a half-written line is never delivered.
func consume(rem, chunk []byte, emit func(Entry) error) ([]byte, error) {
	buf := append(rem, chunk...)
	for {
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			break
		}
		line := buf[:i+1]
		buf = buf[i+1:]
		if e, err := unmarshalRecord(line); err == nil {
			if eerr := emit(e); eerr != nil {
				return nil, eerr
			}
		}
	}
	if len(buf) > maxPendingLine {
		return nil, fmt.Errorf("logbuf: log line exceeds %d bytes without a terminator; the file is corrupt", maxPendingLine)
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	return out, nil
}
