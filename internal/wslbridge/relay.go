package wslbridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// RelayMode selects the protocol the relay speaks on its byte stream.
type RelayMode int

const (
	// RelayModeAuto picks the protocol from the first byte the peer sends. It
	// is the zero value and what `hull __relay` uses.
	RelayModeAuto RelayMode = iota

	// RelayModeMux always speaks the multiplexed frame protocol, which is what
	// the Windows bridge opens.
	RelayModeMux

	// RelayModeRaw pipes the byte stream straight onto the engine socket, one
	// connection per relay process.
	RelayModeRaw
)

// String names a relay mode, for logs.
func (m RelayMode) String() string {
	switch m {
	case RelayModeMux:
		return "mux"
	case RelayModeRaw:
		return "raw"
	default:
		return "auto"
	}
}

// RelayOptions configures the Linux end of the stdio transport -- the hidden
// `hull __relay` subcommand that runs inside the engine distro.
type RelayOptions struct {
	// Mode selects the protocol. Zero means RelayModeAuto.
	Mode RelayMode

	// Config supplies the socket path, window size and logger. Only SocketPath,
	// Window and Logger are consulted.
	Config Config

	// In and Out are the byte stream carrying multiplexed frames. Zero means
	// os.Stdin and os.Stdout, which is what wsl.exe wires up.
	In  io.Reader
	Out io.Writer

	// Dial opens one connection to the engine. Zero dials Config.SocketPath as a
	// unix socket.
	//
	// The relay deliberately takes the target from its own configuration rather
	// than from the open frame. The Windows side is the same user, but a relay
	// that dialled whatever the wire told it to would be a confused deputy
	// running as root inside the engine distro, and there is no reason to build
	// one.
	Dial func(ctx context.Context) (net.Conn, error)

	// DialTimeout bounds a single engine dial. Zero means 10s.
	DialTimeout time.Duration
}

// RunRelay runs the Linux end of the stdio transport: it reads multiplexed
// frames from In, connects each stream the Windows side opens to hulld's API
// socket, and copies bytes both ways with proper half-close.
//
// It also answers a caller that speaks no protocol at all. hull's own client
// dials one `wsl.exe --exec hull __relay` per connection and writes raw HTTP
// into it, and that is a perfectly good way to reach the engine from a script
// or from another distro. One byte tells the two apart: a multiplexed session
// opens with a control frame on stream 0, so its first byte on the wire is
// always 0x00, while an HTTP request begins with a printable method letter.
// RelayModeAuto reads that byte, decides, and pushes it back.
//
// It returns when the byte stream ends -- normally because hull.exe on Windows
// exited and wsl.exe closed the child's stdin -- or when ctx is cancelled.
func RunRelay(ctx context.Context, opts RelayOptions) error {
	cfg := opts.Config.WithDefaults()
	in := opts.In
	if in == nil {
		in = os.Stdin
	}
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = cfg.DialTimeout
	}
	dial := opts.Dial
	if dial == nil {
		socket := cfg.SocketPath
		dial = func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// A relay whose context is already finished has nothing to do, and must
	// not block reading a first byte that nobody is going to send.
	if ctx.Err() != nil {
		return nil
	}

	mode := opts.Mode
	if mode == RelayModeAuto {
		first, rest, err := sniffRelayMode(in)
		switch {
		case errors.Is(err, io.EOF):
			// The peer opened the relay and went away without sending
			// anything. That is how a cancelled dial looks from here, and it
			// is not a failure.
			return nil
		case err != nil:
			return fmt.Errorf("wslbridge: relay: read the first byte: %w", err)
		}
		in = rest
		mode = RelayModeMux
		if first != muxFirstByte {
			mode = RelayModeRaw
		}
		cfg.Logger.Debug("wslbridge: relay mode selected", "mode", mode, "first_byte", first)
	}

	if mode == RelayModeRaw {
		return relayRaw(ctx, cfg, in, out, dial, dialTimeout)
	}

	sess := NewSession(readWriteCloser{r: in, w: out}, cfg.sessionOptions(true))
	defer func() { _ = sess.Close() }()

	var wg sync.WaitGroup
	defer wg.Wait()

	cfg.Logger.Debug("wslbridge: relay started", "socket", cfg.SocketPath)
	for {
		st, err := sess.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, ErrSessionClosed) {
				// The Windows side went away. That is the normal end of a
				// relay's life, not a failure.
				return nil
			}
			return fmt.Errorf("wslbridge: relay accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			relayStream(ctx, cfg, st, dial, dialTimeout)
		}()
	}
}

// muxFirstByte is the first byte of a multiplexed session: the high byte of the
// control stream's id, which is zero. No HTTP request can begin with it, which
// is what makes the auto-detection in RunRelay sound rather than lucky.
const muxFirstByte = 0x00

// sniffRelayMode reads one byte and returns a reader that still begins with it.
func sniffRelayMode(in io.Reader) (byte, io.Reader, error) {
	var b [1]byte
	if _, err := io.ReadFull(in, b[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF
		}
		return 0, in, err
	}
	return b[0], io.MultiReader(bytes.NewReader(b[:]), in), nil
}

// relayRaw pipes one unframed byte stream onto the engine socket. This is the
// shape hull's own client uses: one relay process per connection, no framing at
// all, so the process exits when the engine closes the connection.
func relayRaw(ctx context.Context, cfg Config, in io.Reader, out io.Writer, dial func(context.Context) (net.Conn, error), timeout time.Duration) error {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	conn, err := dial(dialCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("wslbridge: relay: dial %s: %w", cfg.SocketPath, err)
	}
	defer func() { _ = conn.Close() }()

	// Client to engine ends at end-of-stdin; half-closing rather than closing
	// keeps the engine's response coming, which is what a request body
	// followed by a wait needs.
	go func() {
		_, _ = io.Copy(conn, in)
		if !closeWrite(conn) {
			_ = conn.Close()
		}
	}()

	// Engine to client is the direction that decides when the relay is done:
	// the process owns its stdout and exits once the engine has finished.
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(out, conn)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil && !isExpectedClose(err) {
			return fmt.Errorf("wslbridge: relay: copy from %s: %w", cfg.SocketPath, err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// relayStream connects one accepted stream to the engine socket.
func relayStream(ctx context.Context, cfg Config, st *Stream, dial func(context.Context) (net.Conn, error), timeout time.Duration) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	conn, err := dial(dialCtx)
	cancel()
	if err != nil {
		// Reset rather than close: the reason travels back to Windows as a
		// ResetError, so "hull ps" prints why the engine could not be reached
		// instead of an unexplained EOF.
		cfg.Logger.Warn("wslbridge: relay dial failed", "stream", st.ID(), "socket", cfg.SocketPath, "error", err)
		_ = st.Reset(fmt.Errorf("dial %s: %w", cfg.SocketPath, err))
		return
	}
	if err := st.Confirm(); err != nil {
		_ = conn.Close()
		return
	}
	if err := proxy(ctx, st, conn); err != nil {
		cfg.Logger.Debug("wslbridge: relay stream ended", "stream", st.ID(), "error", err)
	}
}

// readWriteCloser glues a separate reader and writer into one duplex stream, so
// a process's stdin and stdout can back a multiplexer session.
type readWriteCloser struct {
	r io.Reader
	w io.Writer
}

// Read implements io.Reader.
func (s readWriteCloser) Read(p []byte) (int, error) { return s.r.Read(p) }

// Write implements io.Writer.
func (s readWriteCloser) Write(p []byte) (int, error) { return s.w.Write(p) }

// Close closes whichever half is closable. Closing os.Stdin and os.Stdout is
// deliberately avoided: the relay's parent owns them.
func (s readWriteCloser) Close() error {
	var err error
	if c, ok := s.r.(io.Closer); ok && s.r != os.Stdin {
		err = c.Close()
	}
	if c, ok := s.w.(io.Closer); ok && s.w != os.Stdout {
		if cerr := c.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// proxy copies bytes between two connections until both directions are done,
// half-closing each side as its source runs out rather than tearing the whole
// connection down.
//
// The half-close is not a nicety. A Docker API client that has finished sending
// a request body signals it by closing its write half and then waits for the
// response; a proxy that closed the whole connection instead would truncate
// every `docker build` and every `docker cp`.
func proxy(ctx context.Context, a, b net.Conn) error {
	errc := make(chan error, 2)
	copyOne := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if !closeWrite(dst) {
			// Nothing to half-close with -- a named pipe, for instance -- so
			// the only way to signal the end is to close outright.
			_ = dst.Close()
		}
		errc <- err
	}
	go copyOne(a, b)
	go copyOne(b, a)

	var first error
	for range 2 {
		select {
		case err := <-errc:
			if first == nil && err != nil && !isExpectedClose(err) {
				first = err
			}
		case <-ctx.Done():
			_ = a.Close()
			_ = b.Close()
			return ctx.Err()
		}
	}
	_ = a.Close()
	_ = b.Close()
	return first
}

// isExpectedClose reports whether err is one of the ordinary ways a proxied
// connection ends, which should not be logged as a fault.
func isExpectedClose(err error) bool {
	switch {
	case err == nil,
		errors.Is(err, io.EOF),
		errors.Is(err, net.ErrClosed),
		errors.Is(err, ErrStreamClosed),
		errors.Is(err, ErrSessionClosed),
		errors.Is(err, os.ErrClosed):
		return true
	}
	var reset *ResetError
	return errors.As(err, &reset)
}
