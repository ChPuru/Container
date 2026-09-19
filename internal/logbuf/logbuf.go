// Package logbuf implements hull's "json-file" log driver: the Writer a
// container shim uses to persist a process's stdout/stderr, the Read tailer the
// API and CLI use to replay and follow it, and the 8-byte Docker stream framing
// used by the /attach and /logs endpoints.
//
// The on-disk format is byte-compatible with Docker's json-file driver: one
// JSON object per line, newline terminated, for example
//
//	{"log":"hello\n","stream":"stdout","time":"2026-09-19T09:51:02.123456789Z"}
//
// so `docker logs` against hull, and any tool that reads the raw
// <id>-json.log file, behaves exactly as it does against Docker. Timestamps are
// RFC3339Nano in UTC. Records that continue into the next record carry
// "partial":true, which is how Docker splits logical lines longer than
// MaxRecordPayload and how it marks a fragment flushed by the idle timer.
package logbuf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Stream names as they appear in the "stream" field of a json-file record.
const (
	// StreamStdin is only ever seen in stream framing, never in a log file.
	StreamStdin = "stdin"
	// StreamStdout is the container's standard output.
	StreamStdout = "stdout"
	// StreamStderr is the container's standard error.
	StreamStderr = "stderr"
)

// MaxRecordPayload is the largest amount of log data carried by a single
// record. A logical line longer than this is split across several records, all
// but the last marked partial, exactly as Docker does.
const MaxRecordPayload = 16 * 1024

// DefaultFlushInterval is how long an unterminated fragment may sit in the
// Writer before it is emitted as a partial record.
const DefaultFlushInterval = 100 * time.Millisecond

// TimestampFormat is the fixed-width RFC3339 nanosecond layout Docker uses when
// it prefixes log lines with a timestamp (`docker logs -t`). Unlike
// time.RFC3339Nano it does not trim trailing zeros, so columns line up.
const TimestampFormat = "2006-01-02T15:04:05.000000000Z07:00"

// Errors reported by this package.
var (
	// ErrClosed is returned by Writer.Write after Writer.Close.
	ErrClosed = errors.New("logbuf: writer is closed")
	// ErrNoStreams is returned by Read when neither ReadOptions.Stdout nor
	// ReadOptions.Stderr is set, which would select no output at all.
	ErrNoStreams = errors.New("logbuf: no stream selected: set ReadOptions.Stdout and/or ReadOptions.Stderr")
	// ErrBadStream is returned by Writer.Write for a stream name that is
	// neither "stdout" nor "stderr".
	ErrBadStream = errors.New(`logbuf: stream must be "stdout" or "stderr"`)
	// ErrFrameTooLarge is returned by DemuxFramed when a frame header declares
	// a payload larger than maxFrameSize, which means the stream is corrupt or
	// hostile rather than merely long.
	ErrFrameTooLarge = errors.New("logbuf: framed stream declares an implausibly large frame")
	// ErrBadFrameType is returned by DemuxFramed for a stream byte that is not
	// 0 (stdin), 1 (stdout) or 2 (stderr).
	ErrBadFrameType = errors.New("logbuf: framed stream carries an unknown stream type")
)

var errEmptyLine = errors.New("logbuf: empty record")

// Entry is one decoded log record.
//
// Log holds the raw bytes of the line, including its trailing newline when the
// record ends one. Partial reports that the logical line continues in the next
// record with the same stream; consumers that need whole lines (a TUI, say)
// must concatenate until they see a record with Partial false.
type Entry struct {
	Log     []byte
	Stream  string
	Time    time.Time
	Partial bool
}

// jsonRecord is the wire shape of one line. Field order matches Docker's
// hand-rolled marshaller so the bytes are identical; encoding/json applies the
// same HTML escaping (< and friends) that Docker's ffjson helper does.
type jsonRecord struct {
	Log     string `json:"log,omitempty"`
	Stream  string `json:"stream,omitempty"`
	Time    string `json:"time"`
	Partial bool   `json:"partial,omitempty"`
}

// marshalRecord encodes e as one newline-terminated json-file record.
func marshalRecord(e Entry) ([]byte, error) {
	rec := jsonRecord{
		Log:     string(e.Log),
		Stream:  e.Stream,
		Time:    e.Time.UTC().Format(time.RFC3339Nano),
		Partial: e.Partial,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("logbuf: marshal record: %w", err)
	}
	return append(b, '\n'), nil
}

// unmarshalRecord decodes one json-file line, with or without its terminator.
func unmarshalRecord(line []byte) (Entry, error) {
	line = bytes.TrimRight(line, "\r\n")
	if len(bytes.TrimSpace(line)) == 0 {
		return Entry{}, errEmptyLine
	}
	var rec jsonRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return Entry{}, fmt.Errorf("logbuf: parse record: %w", err)
	}
	e := Entry{
		Log:     []byte(rec.Log),
		Stream:  rec.Stream,
		Partial: rec.Partial,
	}
	if rec.Time != "" {
		t, err := time.Parse(time.RFC3339Nano, rec.Time)
		if err != nil {
			return Entry{}, fmt.Errorf("logbuf: parse record time %q: %w", rec.Time, err)
		}
		e.Time = t.UTC()
	}
	return e, nil
}
