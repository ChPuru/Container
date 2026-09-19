package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// ProgressDetail is the byte counter inside a progress message.
type ProgressDetail struct {
	// Current is how many bytes have transferred.
	Current int64 `json:"current,omitempty"`
	// Total is the expected size, zero when unknown.
	Total int64 `json:"total,omitempty"`
}

// JSONError is the error half of a progress message.
type JSONError struct {
	// Code is an optional numeric code; hull never sets one.
	Code int `json:"code,omitempty"`
	// Message is the failure.
	Message string `json:"message"`
}

// JSONMessage is one newline-delimited object in a chunked progress stream.
//
// /images/create, /images/load, /images/{name}/push and /build all speak this
// format. Once the first object has gone out the HTTP status is fixed at 200,
// so a later failure has to be reported *inside* the stream as a final object
// carrying ErrorDetail and Error. A client that sees a truncated stream with
// no error object hangs on its progress bar forever.
type JSONMessage struct {
	// Stream is free text, used by /build for build output.
	Stream string `json:"stream,omitempty"`
	// Status is the step, e.g. "Downloading" or "Pull complete".
	Status string `json:"status,omitempty"`
	// ID scopes the status to one layer.
	ID string `json:"id,omitempty"`
	// From names the source image.
	From string `json:"from,omitempty"`
	// Time and TimeNano stamp the message.
	Time     int64 `json:"time,omitempty"`
	TimeNano int64 `json:"timeNano,omitempty"`
	// Progress is the rendered bar, and ProgressDetail its numbers.
	Progress       string          `json:"progress,omitempty"`
	ProgressDetail *ProgressDetail `json:"progressDetail,omitempty"`
	// ErrorDetail and Error report a failure inside a 200 stream.
	ErrorDetail *JSONError `json:"errorDetail,omitempty"`
	Error       string     `json:"error,omitempty"`
	// Aux carries endpoint-specific structured data, such as the built
	// image's id.
	Aux json.RawMessage `json:"aux,omitempty"`
}

// progressWriter encodes newline-delimited JSON progress objects and flushes
// after each one, which is what keeps a client's progress display alive.
//
// It is safe for concurrent use because a pull delivers progress from several
// blob goroutines at once.
type progressWriter struct {
	mu      sync.Mutex
	w       io.Writer
	flush   func()
	enc     *json.Encoder
	started bool
	failed  bool
}

// newProgressWriter starts a chunked JSON progress stream on w.
//
// The 200 and the content type go out immediately: a client blocks on the
// response header, and Docker's own daemon answers before the first byte of
// work is done.
func newProgressWriter(w http.ResponseWriter) *progressWriter {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	pw := &progressWriter{
		w:     w,
		flush: func() { _ = rc.Flush() },
		enc:   json.NewEncoder(w),
	}
	pw.flush()
	return pw
}

// newProgressWriterTo is newProgressWriter for a plain io.Writer, used by the
// code paths that buffer a stream rather than serving one.
func newProgressWriterTo(w io.Writer) *progressWriter {
	return &progressWriter{w: w, flush: func() {}, enc: json.NewEncoder(w)}
}

// Write emits one progress object and flushes.
func (p *progressWriter) Write(msg JSONMessage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started = true
	if err := p.enc.Encode(msg); err != nil {
		// The client hung up. There is nothing useful left to do with the
		// stream, and the caller finds out when its own context is cancelled.
		return
	}
	p.flush()
}

// Status emits a bare status line.
func (p *progressWriter) Status(format string, args ...any) {
	p.Write(JSONMessage{Status: fmt.Sprintf(format, args...)})
}

// Fail emits the terminal error object.
//
// The HTTP status stays 200 because the header went out with the first
// object; the error lives in the stream, which is exactly what Docker's
// clients look for.
func (p *progressWriter) Fail(err error) {
	if err == nil {
		return
	}
	msg := errorMessage(err)
	p.mu.Lock()
	p.failed = true
	p.mu.Unlock()
	p.Write(JSONMessage{
		ErrorDetail: &JSONError{Message: msg},
		Error:       msg,
	})
}

// Started reports whether anything has been written yet, which tells a handler
// whether it may still answer with a plain HTTP error.
func (p *progressWriter) Started() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.started
}

// formatBytes renders a byte count the way Docker's progress bars do.
func formatBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.3g%cB", float64(n)/float64(div), "kMGTPE"[exp])
}

// progressBar renders the "[====>   ]  3.6MB/12MB" string clients display.
func progressBar(current, total int64) string {
	if total <= 0 {
		return formatBytes(current)
	}
	const width = 50
	filled := int(float64(width) * float64(current) / float64(total))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	bar := make([]byte, 0, width+2)
	bar = append(bar, '[')
	for i := 0; i < width; i++ {
		switch {
		case i < filled-1:
			bar = append(bar, '=')
		case i == filled-1:
			bar = append(bar, '>')
		default:
			bar = append(bar, ' ')
		}
	}
	bar = append(bar, ']')
	return fmt.Sprintf("%s %s/%s", bar, formatBytes(current), formatBytes(total))
}
