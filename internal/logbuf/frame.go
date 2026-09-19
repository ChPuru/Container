package logbuf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Docker stream-framing types, the first byte of every 8-byte frame header.
const (
	// FrameStdin marks payload destined for the container's stdin.
	FrameStdin byte = 0
	// FrameStdout marks payload from the container's stdout.
	FrameStdout byte = 1
	// FrameStderr marks payload from the container's stderr.
	FrameStderr byte = 2
)

// FrameHeaderSize is the size of the Docker stream frame header:
// [stream type][0][0][0][payload size, uint32 big endian].
const FrameHeaderSize = 8

// maxFrameSize bounds the payload DemuxFramed will allocate for one frame. No
// legitimate producer emits anything close to this; a larger header means the
// stream is desynchronised or hostile.
const maxFrameSize = 32 << 20

// FrameType returns the framing stream byte for a json-file stream name.
func FrameType(stream string) byte {
	switch stream {
	case StreamStderr:
		return FrameStderr
	case StreamStdin:
		return FrameStdin
	default:
		return FrameStdout
	}
}

// WriteFramed writes one log entry to w in Docker's multiplexed stream format,
// which is what the /containers/{id}/logs and /attach endpoints return when
// the container has no TTY. When timestamps is set the payload is prefixed
// with the entry's time in Docker's fixed-width RFC3339Nano layout followed by
// a space, exactly as `docker logs -t` renders it.
//
// The header and payload are emitted in a single Write so a frame is never
// interleaved with another goroutine's frame at the transport layer.
func WriteFramed(w io.Writer, e Entry, timestamps bool) error {
	var prefix []byte
	if timestamps {
		prefix = append(e.Time.UTC().AppendFormat(nil, TimestampFormat), ' ')
	}
	size := len(prefix) + len(e.Log)
	if size > maxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, size)
	}
	frame := make([]byte, FrameHeaderSize, FrameHeaderSize+size)
	frame[0] = FrameType(e.Stream)
	binary.BigEndian.PutUint32(frame[4:], uint32(size))
	frame = append(frame, prefix...)
	frame = append(frame, e.Log...)
	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("logbuf: write frame: %w", err)
	}
	return nil
}

// framedWriter turns each Write into one Docker stream frame.
type framedWriter struct {
	mu     sync.Mutex
	w      io.Writer
	stream byte
}

// NewFramedWriter wraps w so that every Write is emitted as one Docker stream
// frame tagged with the given stream byte (FrameStdout or FrameStderr). It is
// what the attach path uses to multiplex a live container's output.
//
// The returned writer serialises its own concurrent writers. Two writers built
// over the same underlying io.Writer do not know about each other, so the
// caller must not let them race.
func NewFramedWriter(w io.Writer, stream byte) io.Writer {
	return &framedWriter{w: w, stream: stream}
}

// Write emits p as a single frame and reports len(p) consumed.
func (fw *framedWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > maxFrameSize {
		return 0, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(p))
	}
	frame := make([]byte, FrameHeaderSize, FrameHeaderSize+len(p))
	frame[0] = fw.stream
	binary.BigEndian.PutUint32(frame[4:], uint32(len(p)))
	frame = append(frame, p...)

	fw.mu.Lock()
	defer fw.mu.Unlock()
	if _, err := fw.w.Write(frame); err != nil {
		return 0, fmt.Errorf("logbuf: write frame: %w", err)
	}
	return len(p), nil
}

// DemuxFramed is the client side of the framing: it reads a multiplexed stream
// and copies each frame's payload to stdout or stderr. A nil destination
// discards that stream. It returns nil at a clean end of stream.
func DemuxFramed(r io.Reader, stdout, stderr io.Writer) error {
	var hdr [FrameHeaderSize]byte
	var buf []byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("logbuf: truncated frame header: %w", err)
			}
			return fmt.Errorf("logbuf: read frame header: %w", err)
		}
		var dst io.Writer
		switch hdr[0] {
		case FrameStdin, FrameStdout:
			dst = stdout
		case FrameStderr:
			dst = stderr
		default:
			return fmt.Errorf("%w: %d", ErrBadFrameType, hdr[0])
		}
		size := int(binary.BigEndian.Uint32(hdr[4:]))
		if size > maxFrameSize {
			return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, size)
		}
		if size == 0 {
			continue
		}
		if cap(buf) < size {
			buf = make([]byte, size)
		}
		payload := buf[:size]
		if _, err := io.ReadFull(r, payload); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("logbuf: truncated frame payload: %w", io.ErrUnexpectedEOF)
			}
			return fmt.Errorf("logbuf: read frame payload: %w", err)
		}
		if dst == nil {
			continue
		}
		if _, err := dst.Write(payload); err != nil {
			return fmt.Errorf("logbuf: demux write: %w", err)
		}
	}
}
