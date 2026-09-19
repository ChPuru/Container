package shim

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		kind byte
		body []byte
	}{
		{"empty body", KindEOF, nil},
		{"one byte", KindStdin, []byte{0x00}},
		{"text", KindStdout, []byte("hello, container\n")},
		{"json", KindRequest, []byte(`{"op":"state"}`)},
		{"binary with newlines", KindStderr, []byte{0x1b, '[', '2', 'J', '\n', 0xff, 0x00}},
		{"64 KiB", KindStdout, bytes.Repeat([]byte("x"), 64<<10)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := WriteFrame(&buf, tt.kind, tt.body); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			if got, want := buf.Len(), 5+len(tt.body); got != want {
				t.Fatalf("encoded length = %d, want %d", got, want)
			}
			kind, body, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if kind != tt.kind {
				t.Errorf("kind = 0x%02x, want 0x%02x", kind, tt.kind)
			}
			if !bytes.Equal(body, tt.body) {
				t.Errorf("body = %q, want %q", body, tt.body)
			}
			if buf.Len() != 0 {
				t.Errorf("%d bytes left over after decoding one frame", buf.Len())
			}
		})
	}
}

func TestFrameHeaderLayout(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := WriteFrame(&buf, KindStdout, []byte("abc")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	raw := buf.Bytes()
	if raw[0] != KindStdout {
		t.Errorf("kind byte = 0x%02x, want 0x%02x", raw[0], KindStdout)
	}
	if n := binary.BigEndian.Uint32(raw[1:5]); n != 3 {
		t.Errorf("length prefix = %d, want 3 (big endian)", n)
	}
	if string(raw[5:]) != "abc" {
		t.Errorf("body = %q, want %q", raw[5:], "abc")
	}
}

func TestFrameStreamsBackToBack(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	want := []struct {
		kind byte
		body string
	}{
		{KindStdout, "one"},
		{KindStderr, "two"},
		{KindEOF, ""},
		{KindStdout, "three"},
	}
	for _, w := range want {
		if err := WriteFrame(&buf, w.kind, []byte(w.body)); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}
	for i, w := range want {
		kind, body, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("frame %d: ReadFrame: %v", i, err)
		}
		if kind != w.kind || string(body) != w.body {
			t.Errorf("frame %d = (0x%02x, %q), want (0x%02x, %q)", i, kind, body, w.kind, w.body)
		}
	}
	if _, _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Errorf("after the last frame err = %v, want io.EOF", err)
	}
}

func TestReadFrameErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input []byte
		check func(error) bool
	}{
		{
			name:  "clean close between frames",
			input: nil,
			check: func(err error) bool { return errors.Is(err, io.EOF) },
		},
		{
			name:  "truncated header",
			input: []byte{KindStdout, 0x00, 0x00},
			check: func(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) },
		},
		{
			name:  "truncated body",
			input: []byte{KindStdout, 0x00, 0x00, 0x00, 0x08, 'a', 'b'},
			check: func(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) },
		},
		{
			name:  "absurd length",
			input: []byte{KindStdout, 0xff, 0xff, 0xff, 0xff},
			check: func(err error) bool { return errors.Is(err, ErrProtocol) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := ReadFrame(bytes.NewReader(tt.input))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !tt.check(err) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestWriteFrameRejectsOversizedBody(t *testing.T) {
	t.Parallel()
	err := WriteFrame(io.Discard, KindStdout, make([]byte, MaxFrameSize+1))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want an over-the-limit error", err)
	}
}

func TestReadRequestAndResponse(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	want := Request{Op: OpKill, Signal: 15, All: true}
	if err := WriteJSONFrame(&buf, KindRequest, want); err != nil {
		t.Fatalf("WriteJSONFrame: %v", err)
	}
	got, err := ReadRequest(&buf)
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if got.Op != want.Op || got.Signal != want.Signal || got.All != want.All {
		t.Errorf("request = %+v, want %+v", got, want)
	}

	buf.Reset()
	code := 137
	st := State{Pid: 0, Status: StatusStopped, ExitCode: code, Exited: true, FinishedAt: time.Unix(1, 0).UTC()}
	if err := WriteJSONFrame(&buf, KindResponse, Response{State: &st, ExitCode: &code}); err != nil {
		t.Fatalf("WriteJSONFrame: %v", err)
	}
	resp, err := ReadResponse(&buf)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.State == nil || resp.State.ExitCode != 137 || !resp.State.Exited {
		t.Errorf("state = %+v, want the stopped state back", resp.State)
	}
	if resp.ExitCode == nil || *resp.ExitCode != 137 {
		t.Errorf("exit code = %v, want 137", resp.ExitCode)
	}
}

func TestReadRequestRejectsWrongKind(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := WriteJSONFrame(&buf, KindResponse, Response{}); err != nil {
		t.Fatalf("WriteJSONFrame: %v", err)
	}
	if _, err := ReadRequest(&buf); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err = %v, want ErrProtocol", err)
	}

	buf.Reset()
	if err := WriteFrame(&buf, KindRequest, []byte("{not json")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if _, err := ReadRequest(&buf); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err = %v, want ErrProtocol for a malformed body", err)
	}

	buf.Reset()
	if err := WriteFrame(&buf, KindRequest, []byte(`{}`)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if _, err := ReadRequest(&buf); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err = %v, want ErrProtocol for a request with no op", err)
	}
}

func TestErrorCodesSurviveTheWire(t *testing.T) {
	t.Parallel()
	sentinels := []error{
		ErrStdinInUse, ErrStdinUnavailable, ErrNotRunning,
		ErrAlreadyStarted, ErrNoTerminal, ErrNoSuchExec, ErrDetached,
	}
	for _, sentinel := range sentinels {
		t.Run(sentinel.Error(), func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := WriteJSONFrame(&buf, KindResponse, errorResponse(sentinel)); err != nil {
				t.Fatalf("WriteJSONFrame: %v", err)
			}
			resp, err := ReadResponse(&buf)
			if err != nil {
				t.Fatalf("ReadResponse: %v", err)
			}
			got := responseError(resp)
			if !errors.Is(got, sentinel) {
				t.Fatalf("rebuilt error %v does not match sentinel %v", got, sentinel)
			}
		})
	}
}

func TestErrorResponseWrapsContext(t *testing.T) {
	t.Parallel()
	wrapped := errors.New("shim: crun exec failed: no such file")
	resp := errorResponse(wrapped)
	if resp.Code != "" {
		t.Errorf("code = %q, want empty for an unclassified error", resp.Code)
	}
	got := responseError(resp)
	if got == nil || got.Error() != wrapped.Error() {
		t.Fatalf("rebuilt error = %v, want %v", got, wrapped)
	}

	// A sentinel with extra context keeps both.
	detail := errors.Join(ErrNotRunning, errors.New("container 7f3 already exited"))
	rebuilt := responseError(errorResponse(detail))
	if !errors.Is(rebuilt, ErrNotRunning) {
		t.Fatalf("rebuilt error %v lost the ErrNotRunning sentinel", rebuilt)
	}
	if !strings.Contains(rebuilt.Error(), "already exited") {
		t.Fatalf("rebuilt error %v lost its context", rebuilt)
	}

	if responseError(Response{}) != nil {
		t.Error("an empty response should rebuild to a nil error")
	}
}
