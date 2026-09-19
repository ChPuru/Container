package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/rahuldhali/hull/internal/events"
	"github.com/rahuldhali/hull/internal/logbuf"
	"github.com/rahuldhali/hull/internal/shim"
	"github.com/rahuldhali/hull/internal/types"
)

// Attach connects a client's streams to a running container.
//
// Any number of clients may attach at once and all of them see the output.
// Standard input is granted to the first attacher that asks for it; a later
// one is told so rather than having its keystrokes silently interleaved into
// the same pty.
func (e *Engine) Attach(ctx context.Context, idOrName string, opts AttachConfig) error {
	if err := e.checkOpen(); err != nil {
		return err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	if !opts.wantsAnyStream() {
		return fmt.Errorf("%w: attach was asked for with no streams", ErrInvalid)
	}
	if c.State != types.StateRunning && c.State != types.StatePaused {
		return fmt.Errorf("%w: %s is %s", ErrNotRunning, idShort(id), c.State)
	}
	sup, err := e.supervisorFor(id)
	if err != nil {
		return err
	}

	if opts.Logs {
		// Replay what the container has already said, then switch to live
		// output, which is what `docker attach --logs` does.
		if rerr := e.Logs(ctx, id, logbuf.ReadOptions{
			Tail:   -1,
			Stdout: opts.UseStdout && opts.Stdout != nil,
			Stderr: opts.UseStderr && opts.Stderr != nil,
		}, attachLogWriter{opts: opts}, opts.Framed && !c.Config.Tty); rerr != nil {
			return rerr
		}
	}

	stream, err := sup.Attach(ctx, shim.AttachOptions{
		Stdin:      opts.UseStdin && opts.Stdin != nil,
		Stdout:     opts.UseStdout && opts.Stdout != nil,
		Stderr:     opts.UseStderr && opts.Stderr != nil,
		DetachKeys: opts.DetachKeys,
	})
	if err != nil {
		if errors.Is(err, shim.ErrStdinInUse) || errors.Is(err, shim.ErrStdinUnavailable) {
			return fmt.Errorf("%w: %w", ErrConflict, err)
		}
		return fmt.Errorf("engine: attach to %s: %w", idShort(id), err)
	}
	e.emit(events.ActionAttach, c, nil)
	return e.runAttachment(ctx, id, stream, opts, c.Config.Tty)
}

// runAttachment pumps one attachment to completion and keeps the container out
// of the idle watcher's reach while it lasts.
func (e *Engine) runAttachment(ctx context.Context, id string, stream Stream, opts AttachConfig, tty bool) error {
	e.trackAttachment(id, 1)
	defer e.trackAttachment(id, -1)
	defer stream.Close()

	if opts.Started != nil {
		close(opts.Started)
		opts.Started = nil
	}
	err := pumpStream(ctx, stream, opts, tty)
	if errors.Is(err, shim.ErrDetached) {
		// Detaching is a clean end: the container keeps running, which is the
		// entire point of the detach sequence.
		return nil
	}
	return err
}

// attachLogWriter adapts an AttachConfig to the io.Writer Logs wants, sending
// everything to the attachment's stdout.
type attachLogWriter struct {
	opts AttachConfig
}

// Write forwards replayed log bytes to the attachment's stdout.
func (w attachLogWriter) Write(p []byte) (int, error) {
	if w.opts.Stdout == nil {
		return len(p), nil
	}
	return w.opts.Stdout.Write(p)
}

// pumpStream copies a container stream to and from the client's own streams,
// returning when the container's output ends, the client detaches or ctx is
// cancelled.
func pumpStream(ctx context.Context, s Stream, opts AttachConfig, tty bool) error {
	var wg sync.WaitGroup

	if in := s.Stdin(); in != nil && opts.Stdin != nil && opts.UseStdin {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A half-close is what lets a piped `hull run -i` let the process
			// see EOF without tearing the whole stream down.
			_, _ = io.Copy(in, opts.Stdin)
			_ = in.Close()
		}()
	}

	out := clientWriter(opts.Stdout, opts.UseStdout, opts.Framed && !tty, logbuf.StreamStdout)
	errw := clientWriter(opts.Stderr, opts.UseStderr, opts.Framed && !tty, logbuf.StreamStderr)
	if s.Terminal() {
		// A terminal container merges its streams, so everything goes to
		// stdout even for a client that only asked for stderr.
		if out == nil {
			out = errw
		}
		errw = nil
	}

	copyErr := make(chan error, 2)
	if r := s.Stdout(); r != nil && out != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := io.Copy(out, r)
			copyErr <- err
		}()
	}
	if r := s.Stderr(); r != nil && errw != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := io.Copy(errw, r)
			copyErr <- err
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-s.Done():
	case <-ctx.Done():
		_ = s.Close()
		<-done
		return ctx.Err()
	}
	_ = s.Close()
	<-done

	if err := s.Err(); err != nil {
		return err
	}
	select {
	case err := <-copyErr:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			return err
		}
	default:
	}
	return nil
}

// clientWriter returns the writer one stream should be copied into, wrapping
// it in the Docker stream framing when the client asked for a multiplexed
// connection.
func clientWriter(w io.Writer, use, framed bool, stream string) io.Writer {
	if w == nil || !use {
		return nil
	}
	if !framed {
		return w
	}
	return logbuf.NewFramedWriter(w, logbuf.FrameType(stream))
}

// Logs delivers a container's log to w.
//
// With opts.Follow the call blocks, streaming new records until ctx is
// cancelled. framed selects the 8-byte Docker stream header the API uses for a
// non-tty container; a tty container's log is a single merged stream and is
// always written raw.
func (e *Engine) Logs(ctx context.Context, idOrName string, opts logbuf.ReadOptions, w io.Writer, framed bool) error {
	if w == nil {
		return fmt.Errorf("%w: logs need somewhere to be written", ErrInvalid)
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return err
	}
	c, err := e.lookup(id)
	if err != nil {
		return err
	}
	if c.HostConfig.LogConfig.Type == "none" {
		return fmt.Errorf("%w: %s uses the \"none\" log driver, so there is nothing to read",
			ErrConflict, idShort(id))
	}
	if !opts.Stdout && !opts.Stderr {
		opts.Stdout, opts.Stderr = true, true
	}
	if c.Config.Tty {
		framed = false
	}

	err = logbuf.Read(ctx, e.logPath(id), opts, func(entry logbuf.Entry) error {
		if framed {
			return logbuf.WriteFramed(w, entry, opts.Timestamps)
		}
		if opts.Timestamps {
			if _, werr := io.WriteString(w, entry.Time.Format(logbuf.TimestampFormat)+" "); werr != nil {
				return werr
			}
		}
		_, werr := w.Write(entry.Log)
		return werr
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("engine: read the log of %s: %w", idShort(id), err)
	}
	return nil
}
