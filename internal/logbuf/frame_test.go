package logbuf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestWriteFramedAndDemux(t *testing.T) {
	ts := time.Date(2026, 9, 19, 9, 51, 2, 123456789, time.UTC)
	tests := []struct {
		name       string
		entries    []Entry
		timestamps bool
		wantOut    string
		wantErr    string
	}{
		{
			name:    "stdout only",
			entries: []Entry{{Log: []byte("hello\n"), Stream: StreamStdout, Time: ts}},
			wantOut: "hello\n",
		},
		{
			name: "interleaved streams",
			entries: []Entry{
				{Log: []byte("a\n"), Stream: StreamStdout, Time: ts},
				{Log: []byte("b\n"), Stream: StreamStderr, Time: ts},
				{Log: []byte("c\n"), Stream: StreamStdout, Time: ts},
			},
			wantOut: "a\nc\n",
			wantErr: "b\n",
		},
		{
			name:       "timestamps are prefixed",
			entries:    []Entry{{Log: []byte("hello\n"), Stream: StreamStdout, Time: ts}},
			timestamps: true,
			wantOut:    "2026-09-19T09:51:02.123456789Z hello\n",
		},
		{
			name:    "empty payload",
			entries: []Entry{{Log: nil, Stream: StreamStdout, Time: ts}},
			wantOut: "",
		},
		{
			name:    "binary payload",
			entries: []Entry{{Log: []byte{0x00, 0x01, 0xff, 0xfe}, Stream: StreamStderr, Time: ts}},
			wantErr: "\x00\x01\xff\xfe",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var wire bytes.Buffer
			for _, e := range tc.entries {
				if err := WriteFramed(&wire, e, tc.timestamps); err != nil {
					t.Fatalf("WriteFramed: %v", err)
				}
			}
			var out, errb bytes.Buffer
			if err := DemuxFramed(&wire, &out, &errb); err != nil {
				t.Fatalf("DemuxFramed: %v", err)
			}
			if out.String() != tc.wantOut {
				t.Errorf("stdout = %q, want %q", out.String(), tc.wantOut)
			}
			if errb.String() != tc.wantErr {
				t.Errorf("stderr = %q, want %q", errb.String(), tc.wantErr)
			}
		})
	}
}

func TestFrameHeaderLayout(t *testing.T) {
	var wire bytes.Buffer
	e := Entry{Log: []byte("hi"), Stream: StreamStderr, Time: time.Unix(0, 0).UTC()}
	if err := WriteFramed(&wire, e, false); err != nil {
		t.Fatalf("WriteFramed: %v", err)
	}
	b := wire.Bytes()
	if len(b) != FrameHeaderSize+2 {
		t.Fatalf("frame is %d bytes, want %d", len(b), FrameHeaderSize+2)
	}
	if b[0] != FrameStderr {
		t.Errorf("stream byte = %d, want %d", b[0], FrameStderr)
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		t.Errorf("header padding = %v, want zeros", b[1:4])
	}
	if got := binary.BigEndian.Uint32(b[4:8]); got != 2 {
		t.Errorf("size = %d, want 2", got)
	}
	if string(b[8:]) != "hi" {
		t.Errorf("payload = %q, want %q", b[8:], "hi")
	}
}

func TestNewFramedWriterRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	out := NewFramedWriter(&wire, FrameStdout)
	errw := NewFramedWriter(&wire, FrameStderr)

	if n, err := out.Write([]byte("one")); err != nil || n != 3 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if n, err := errw.Write([]byte("two")); err != nil || n != 3 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if n, err := out.Write(nil); err != nil || n != 0 {
		t.Fatalf("empty Write = %d, %v", n, err)
	}

	var o, e bytes.Buffer
	if err := DemuxFramed(&wire, &o, &e); err != nil {
		t.Fatalf("DemuxFramed: %v", err)
	}
	if o.String() != "one" || e.String() != "two" {
		t.Fatalf("stdout=%q stderr=%q, want %q / %q", o.String(), e.String(), "one", "two")
	}
}

func TestDemuxFramedDiscardsNilWriters(t *testing.T) {
	var wire bytes.Buffer
	ts := time.Unix(0, 0).UTC()
	for _, e := range []Entry{
		{Log: []byte("out\n"), Stream: StreamStdout, Time: ts},
		{Log: []byte("err\n"), Stream: StreamStderr, Time: ts},
	} {
		if err := WriteFramed(&wire, e, false); err != nil {
			t.Fatalf("WriteFramed: %v", err)
		}
	}
	var o bytes.Buffer
	if err := DemuxFramed(&wire, &o, nil); err != nil {
		t.Fatalf("DemuxFramed: %v", err)
	}
	if o.String() != "out\n" {
		t.Fatalf("stdout = %q, want %q", o.String(), "out\n")
	}
}

func TestDemuxFramedErrors(t *testing.T) {
	big := make([]byte, FrameHeaderSize)
	big[0] = FrameStdout
	binary.BigEndian.PutUint32(big[4:], uint32(maxFrameSize+1))

	tests := []struct {
		name  string
		wire  []byte
		check func(error) bool
	}{
		{
			name:  "truncated header",
			wire:  []byte{1, 0, 0},
			check: func(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) },
		},
		{
			name:  "truncated payload",
			wire:  append([]byte{1, 0, 0, 0, 0, 0, 0, 4}, 'a', 'b'),
			check: func(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) },
		},
		{
			name:  "unknown stream type",
			wire:  []byte{7, 0, 0, 0, 0, 0, 0, 1, 'x'},
			check: func(err error) bool { return errors.Is(err, ErrBadFrameType) },
		},
		{
			name:  "implausible size",
			wire:  big,
			check: func(err error) bool { return errors.Is(err, ErrFrameTooLarge) },
		},
		{
			name:  "clean end of stream",
			wire:  nil,
			check: func(err error) bool { return err == nil },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := DemuxFramed(bytes.NewReader(tc.wire), io.Discard, io.Discard)
			if !tc.check(err) {
				t.Fatalf("DemuxFramed error = %v", err)
			}
		})
	}
}

func TestDemuxFramedLargePayload(t *testing.T) {
	payload := strings.Repeat("z", 200*1024)
	var wire bytes.Buffer
	if err := WriteFramed(&wire, Entry{Log: []byte(payload), Stream: StreamStdout}, false); err != nil {
		t.Fatalf("WriteFramed: %v", err)
	}
	var o bytes.Buffer
	if err := DemuxFramed(&wire, &o, nil); err != nil {
		t.Fatalf("DemuxFramed: %v", err)
	}
	if o.String() != payload {
		t.Fatalf("payload round trip failed: %d bytes back, want %d", o.Len(), len(payload))
	}
}

func TestFrameType(t *testing.T) {
	tests := []struct {
		stream string
		want   byte
	}{
		{StreamStdout, FrameStdout},
		{StreamStderr, FrameStderr},
		{StreamStdin, FrameStdin},
		{"", FrameStdout},
		{"weird", FrameStdout},
	}
	for _, tc := range tests {
		if got := FrameType(tc.stream); got != tc.want {
			t.Errorf("FrameType(%q) = %d, want %d", tc.stream, got, tc.want)
		}
	}
}
