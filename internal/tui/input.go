package tui

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"time"
)

// inputPollInterval is the read deadline the key reader uses where the
// platform supports one. It is the granularity at which the reader notices it
// has been paused, and it is short enough that resuming after an interactive
// exec feels instant.
const inputPollInterval = 50 * time.Millisecond

// keyReader decodes keystrokes from the terminal and feeds them to the render
// loop, and can be paused so a child process gets the keyboard to itself.
//
// The pause matters more than it looks. When the dashboard suspends itself to
// run "hull exec -it", the child reads the same terminal; a reader goroutine
// still parked in Read would steal the user's first keystroke from their
// shell. Where the platform lets an *os.File carry a read deadline - Linux
// does for a tty - the reader wakes up regularly and simply does not read
// while paused, so the child gets every byte. Where it does not, Windows being
// the case that matters, the reader may consume one keystroke at the moment of
// suspension and nothing after it, which is a visible hiccup rather than a
// broken shell.
type keyReader struct {
	in  *os.File
	out chan<- msg

	paused    atomic.Bool
	deadlines bool
}

// newKeyReader returns a reader for in, probing once whether read deadlines
// work on this file.
func newKeyReader(in *os.File, out chan<- msg) *keyReader {
	kr := &keyReader{in: in, out: out}
	if err := in.SetReadDeadline(time.Now().Add(time.Hour)); err == nil {
		kr.deadlines = true
	}
	_ = in.SetReadDeadline(time.Time{})
	return kr
}

// pause stops the reader consuming input.
func (k *keyReader) pause() { k.paused.Store(true) }

// resume lets the reader consume input again.
func (k *keyReader) resume() { k.paused.Store(false) }

// run reads and decodes until the context ends or the terminal closes.
//
// Without deadline support the final Read is not interruptible, so this
// goroutine can outlive the context until the next keystroke. It holds nothing
// but itself and the process is on its way out by then.
func (k *keyReader) run(ctx context.Context) {
	buf := make([]byte, 0, 64)
	chunk := make([]byte, 64)
	for {
		if ctx.Err() != nil {
			return
		}
		if k.paused.Load() {
			if !sleepCtx(ctx, inputPollInterval) {
				return
			}
			continue
		}
		if k.deadlines {
			_ = k.in.SetReadDeadline(time.Now().Add(inputPollInterval))
		}
		n, err := k.in.Read(chunk)
		if n > 0 && !k.paused.Load() {
			buf = append(buf, chunk[:n]...)
			var ok bool
			if buf, ok = k.drain(ctx, buf); !ok {
				return
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return
		}
	}
}

// drain decodes every complete keystroke in buf and returns what is left.
func (k *keyReader) drain(ctx context.Context, buf []byte) ([]byte, bool) {
	for len(buf) > 0 {
		key, used, ok := DecodeKey(buf)
		if !ok {
			break
		}
		buf = buf[used:]
		if key.Type == KeyUnknown {
			continue
		}
		if !send(ctx, k.out, msg{kind: msgKey, key: key}) {
			return buf, false
		}
	}
	if len(buf) > 32 {
		// Longer than any escape sequence: this is paste or line noise,
		// so drop it rather than grow the buffer for ever.
		buf = buf[:0]
	}
	return buf, true
}
