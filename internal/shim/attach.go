package shim

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// AttachStream is the client side of an attach or exec stream.
//
// For a container with a terminal there is one merged output stream, delivered
// on Stdout, and Stderr is nil; Terminal says which shape the caller got.
// Writing to Stdin sends bytes to the container; closing it half-closes the
// container's stdin, which is how a piped `docker run -i` lets the process see
// EOF. Closing the stream detaches without signalling the container.
type AttachStream struct {
	// Terminal reports that output is a single merged pty stream.
	Terminal bool
	// Stdin writes to the container. It is nil when stdin was not requested.
	Stdin io.WriteCloser
	// Stdout carries container stdout, or the merged pty stream.
	Stdout io.Reader
	// Stderr carries container stderr; nil for a terminal container or when
	// stderr was not requested.
	Stderr io.Reader

	conn net.Conn

	outW *io.PipeWriter
	errW *io.PipeWriter

	once sync.Once
	done chan struct{}

	mu  sync.Mutex
	err error
}

// newAttachStream wraps an upgraded connection and starts demultiplexing it.
func newAttachStream(conn net.Conn, terminal bool, opts AttachOptions) *AttachStream {
	s := &AttachStream{Terminal: terminal, conn: conn, done: make(chan struct{})}

	if opts.Stdout || opts.Stderr || terminal {
		or, ow := io.Pipe()
		s.Stdout, s.outW = or, ow
	}
	if opts.Stderr && !terminal {
		er, ew := io.Pipe()
		s.Stderr, s.errW = er, ew
	}
	if opts.Stdin {
		s.Stdin = &streamWriter{s: s}
	}
	go s.readLoop()
	return s
}

// readLoop demultiplexes frames from the shim into the output pipes.
func (s *AttachStream) readLoop() {
	var cause error
	for {
		kind, body, err := ReadFrame(s.conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				cause = err
			}
			break
		}
		switch kind {
		case KindStdout:
			if s.outW != nil && len(body) > 0 {
				if _, err := s.outW.Write(body); err != nil {
					cause = err
				}
			}
		case KindStderr:
			w := s.errW
			if w == nil {
				// A terminal container merges the two; a caller that asked
				// only for stderr still gets the merged stream.
				w = s.outW
			}
			if w != nil && len(body) > 0 {
				if _, err := w.Write(body); err != nil {
					cause = err
				}
			}
		case KindEOF:
			// The container's output ended; let the readers see EOF.
		case KindResponse:
			// The shim reports why the stream is ending, e.g. ErrDetached.
			var resp Response
			if err := unmarshalJSON(body, &resp); err == nil {
				if rerr := responseError(resp); rerr != nil {
					cause = rerr
				}
			}
		}
		if cause != nil {
			break
		}
	}
	s.finish(cause)
}

// finish closes the stream once, recording the first cause.
func (s *AttachStream) finish(cause error) {
	s.once.Do(func() {
		s.mu.Lock()
		if s.err == nil {
			s.err = cause
		}
		s.mu.Unlock()
		if s.outW != nil {
			_ = s.outW.CloseWithError(cause)
		}
		if s.errW != nil {
			_ = s.errW.CloseWithError(cause)
		}
		_ = s.conn.Close()
		close(s.done)
	})
}

// Done is closed when the stream ends.
func (s *AttachStream) Done() <-chan struct{} { return s.done }

// Err reports why the stream ended: nil for a clean end, ErrDetached when the
// detach sequence was typed, or a transport error.
func (s *AttachStream) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close detaches. The container keeps running.
func (s *AttachStream) Close() error {
	s.finish(nil)
	return nil
}

// streamWriter frames writes to the container's stdin.
type streamWriter struct {
	s  *AttachStream
	mu sync.Mutex
}

// Write sends p to the container's stdin as one or more frames.
func (w *streamWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	select {
	case <-w.s.done:
		if err := w.s.Err(); err != nil {
			return 0, err
		}
		return 0, io.ErrClosedPipe
	default:
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), MaxFrameSize)
		if err := WriteFrame(w.s.conn, KindStdin, p[:n]); err != nil {
			return total, fmt.Errorf("shim: write container stdin: %w", err)
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Close half-closes the container's stdin without ending the stream, so the
// container sees EOF while its output keeps flowing.
func (w *streamWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	select {
	case <-w.s.done:
		return nil
	default:
	}
	return WriteFrame(w.s.conn, KindEOF, nil)
}
