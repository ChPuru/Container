package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rahuldhali/hull/internal/engine"
	"github.com/rahuldhali/hull/internal/version"
)

// Options configures a [Server]. The zero value is usable: every field falls
// back to a documented default.
type Options struct {
	// Version is the newest Docker Engine API version this server claims.
	// Default: version.APIVersion ("1.43").
	Version string
	// MinVersion is the oldest version it will serve. A request outside
	// [MinVersion, Version] is refused with 400. Default: version.MinAPIVersion.
	MinVersion string
	// CORS is the value of Access-Control-Allow-Origin. Empty disables CORS
	// entirely, which is the right default for a daemon socket.
	CORS string
	// AccessLog logs one line per request at debug level.
	AccessLog bool
	// Debug adds the request id and timing to the access log and includes
	// stack traces in 500 responses' server-side log.
	Debug bool
	// Logger receives the server's diagnostics. Nil means slog.Default.
	Logger *slog.Logger
	// BuildKitAddr is where a bundled buildkitd listens, e.g.
	// "unix:///run/buildkit/buildkitd.sock". Empty means probe the usual
	// places; see buildKitAvailable.
	BuildKitAddr string
	// DataRoot is hull's state directory, used to derive the per-container
	// file paths the inspect document reports. Empty means ask the backend.
	DataRoot string
}

// Server is the Docker Engine API v1.43 HTTP server.
//
// One Server may back any number of listeners: [Server.ServeUnix] for the
// daemon socket, [Server.ServeTCP] for the loopback transport the Windows
// bridge uses, and [Server.Serve] for a listener the caller made itself.
type Server struct {
	backend    Backend
	opts       Options
	log        *slog.Logger
	version    Version
	minVersion Version
	router     *router
	handler    http.Handler
	dataRoot   string

	// Whether a buildkitd is reachable decides both what /build does and what
	// Builder-Version /_ping advertises, and a client reads the latter before
	// it ever calls the former. The answer is cached briefly rather than
	// resolved once, so installing buildkit does not require a daemon
	// restart, and so /_ping does not dial a socket on every call.
	buildkitMu      sync.Mutex
	buildkitAddr    string
	buildkitUp      bool
	buildkitChecked time.Time
}

// New builds a server over a live engine.
func New(e *engine.Engine, opts Options) (*Server, error) {
	if e == nil {
		return nil, errors.New("api: a server needs an engine")
	}
	return newServer(e, opts)
}

// NewWithBackend builds a server over any [Backend]. It is what the tests use,
// and it is the seam that lets the whole HTTP surface be exercised without a
// kernel.
func NewWithBackend(b Backend, opts Options) (*Server, error) { return newServer(b, opts) }

// newServer is the shared constructor.
func newServer(b Backend, opts Options) (*Server, error) {
	if b == nil {
		return nil, errors.New("api: a server needs a backend")
	}
	if opts.Version == "" {
		opts.Version = version.APIVersion
	}
	if opts.MinVersion == "" {
		opts.MinVersion = version.MinAPIVersion
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	maxV, err := ParseVersion(opts.Version)
	if err != nil {
		return nil, fmt.Errorf("api: bad Version option: %w", err)
	}
	minV, err := ParseVersion(opts.MinVersion)
	if err != nil {
		return nil, fmt.Errorf("api: bad MinVersion option: %w", err)
	}
	if minV.Compare(maxV) > 0 {
		return nil, fmt.Errorf("api: MinVersion %s is newer than Version %s", minV, maxV)
	}

	s := &Server{
		backend:    b,
		opts:       opts,
		log:        opts.Logger,
		version:    maxV,
		minVersion: minV,
		router:     &router{},
		dataRoot:   opts.DataRoot,
	}
	if s.dataRoot == "" {
		s.dataRoot = b.DataRoot()
	}
	s.registerRoutes()
	s.handler = s.middleware(http.HandlerFunc(s.dispatch))
	return s, nil
}

// Handler returns the server's http.Handler, which is what a caller wraps or
// mounts. It is safe for concurrent use and may be served on many listeners at
// once.
func (s *Server) Handler() http.Handler { return s.handler }

// Serve serves ln until ctx is cancelled, then drains gracefully.
//
// "Gracefully" means in-flight requests are given time to finish and the
// listener stops accepting; it emphatically does not mean stopping containers,
// which outlive the daemon by design.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler: s.handler,
		// Hijacked streams (attach, exec, logs -f, events, stats) are
		// long-lived by nature, so no read or write deadline may be set here.
		ReadHeaderTimeout: 30 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
		ErrorLog:          nil,
	}

	errc := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gracefulDrain)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		// A hijacked connection never returns to the server, so Shutdown
		// times out whenever somebody is attached. Closing is then the
		// correct end of the drain, not a failure.
		_ = srv.Close()
	}
	if err := <-errc; err != nil {
		return fmt.Errorf("api: serve: %w", err)
	}
	return nil
}

// gracefulDrain is how long Serve lets in-flight requests finish before it
// closes the listener's connections outright.
const gracefulDrain = 10 * time.Second

// ServeUnix listens on a unix socket at path with the given mode and serves it
// until ctx is cancelled.
//
// The socket's parent directory is created if missing. A stale socket left by
// a crashed daemon is removed, but only after [Probe] has confirmed that
// nothing answers on it: removing a live daemon's socket would leave two
// daemons fighting over the same state directory.
func (s *Server) ServeUnix(ctx context.Context, path string, mode os.FileMode) error {
	if path == "" {
		return errors.New("api: ServeUnix needs a socket path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("api: create socket directory for %s: %w", path, err)
	}
	if err := ClearStaleSocket(path); err != nil {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("api: listen on %s: %w", path, err)
	}
	if mode != 0 {
		if err := os.Chmod(path, mode); err != nil {
			_ = ln.Close()
			return fmt.Errorf("api: chmod %s: %w", path, err)
		}
	}
	defer func() { _ = os.Remove(path) }()
	s.log.Info("hull: Docker API listening", "socket", path)
	return s.Serve(ctx, ln)
}

// ServeTCP listens on addr and serves it until ctx is cancelled.
//
// token is a required shared secret: every request must carry it in the
// Authorization header, as "Bearer <token>" or bare. A TCP listener with no
// authentication is a DNS-rebinding hole — any web page the user visits can
// POST to 127.0.0.1 and start a privileged container — so an empty token is
// refused rather than quietly accepted.
func (s *Server) ServeTCP(ctx context.Context, addr string, token string) error {
	if addr == "" {
		return errors.New("api: ServeTCP needs an address")
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("api: ServeTCP needs a shared-secret token: " +
			"an unauthenticated TCP listener lets any web page in the browser drive the daemon")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("api: listen on %s: %w", addr, err)
	}
	guarded := &http.Server{
		Handler:           s.tokenGuard(token, s.handler),
		ReadHeaderTimeout: 30 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}
	errc := make(chan error, 1)
	go func() {
		err := guarded.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()
	s.log.Info("hull: Docker API listening", "tcp", addr, "auth", "shared secret")

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gracefulDrain)
	defer cancel()
	if err := guarded.Shutdown(shutdownCtx); err != nil {
		_ = guarded.Close()
	}
	if err := <-errc; err != nil {
		return fmt.Errorf("api: serve tcp: %w", err)
	}
	return nil
}

// tokenGuard rejects any request that does not present the shared secret. The
// comparison is constant time so the socket cannot be used as an oracle.
func (s *Server) tokenGuard(token string, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimSpace(r.Header.Get("Authorization"))
		got = strings.TrimPrefix(got, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"authorization required: set the Authorization header to hull's TCP token"}` + "\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClearStaleSocket removes a unix socket only after confirming nothing answers
// on it.
//
// This is the re-exec-safe path: a daemon restarting into the same data root
// must reclaim its socket, but must never unlink the socket of a daemon that
// is still alive. Dialling is the only honest test — a pid file can be stale,
// a lock can be inherited, but a socket that accepts a connection has a
// listener behind it.
func ClearStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("api: stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("api: %s exists and is not a socket; refusing to remove it", path)
	}
	conn, derr := net.DialTimeout("unix", path, 2*time.Second)
	if derr == nil {
		_ = conn.Close()
		return fmt.Errorf("api: %s is already being served by a live daemon", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("api: remove the stale socket %s: %w", path, err)
	}
	return nil
}
