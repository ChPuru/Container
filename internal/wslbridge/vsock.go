package wslbridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// The AF_HYPERV transport is the fast path that hull must never depend on.
//
// Connecting to a service inside the WSL2 utility VM needs the VM's *runtime
// ID*, and Microsoft exposes no supported way to discover it. Every known route
// is an implementation detail someone found by reading the registry: the
// HostComputeService volatile store, and the GUID WSLg leaves behind for its RDP
// client. Rancher Desktop shipped on the first of those and it vanished under a
// WSL update. So this transport probes quietly, races every candidate it can
// find with a one-second budget, and gives up without complaint.

// ErrVsockUnavailable means no usable AF_HYPERV route to the VM was found.
var ErrVsockUnavailable = errors.New("wslbridge: no AF_HYPERV route to the WSL VM")

// vsockDialTimeout bounds a single candidate dial during the race. One second is
// generous for a hypervisor-local socket and short enough that probing three
// dead GUIDs costs nothing noticeable at startup.
const vsockDialTimeout = time.Second

// HVServiceGUID returns the Hyper-V socket service GUID for a port, using the
// Linux-compatibility template Microsoft reserved for AF_VSOCK interop:
//
//	<port as 8 hex digits>-facb-11e6-bd58-64006a7986d3
//
// A Linux program inside the VM that binds AF_VSOCK port N is reachable from the
// host at exactly this service id.
func HVServiceGUID(port uint32) string {
	return fmt.Sprintf("%08x-facb-11e6-bd58-64006a7986d3", port)
}

// VsockTransport reaches the engine over AF_HYPERV. It is opportunistic: it is
// only built when the configuration enables it, and it fails its probe quietly
// when the VM's runtime ID cannot be found.
type VsockTransport struct {
	cfg  Config
	port uint32

	mu      sync.Mutex
	vmID    string // the candidate that won a previous race
	checked bool
}

var _ Transport = (*VsockTransport)(nil)

// NewVsockTransport returns an AF_HYPERV transport for the configured port.
func NewVsockTransport(cfg Config) *VsockTransport {
	cfg = cfg.WithDefaults()
	return &VsockTransport{cfg: cfg, port: cfg.VsockPort}
}

// Name implements Transport.
func (t *VsockTransport) Name() string { return "vsock" }

// Dial implements Transport. Each call is one AF_HYPERV connection; there is no
// multiplexing, because unlike a relay child a socket is cheap.
func (t *VsockTransport) Dial(ctx context.Context) (net.Conn, error) {
	t.mu.Lock()
	known := t.vmID
	t.mu.Unlock()

	if known != "" {
		conn, err := dialHVSock(ctx, known, t.port, vsockDialTimeout)
		if err == nil {
			return conn, nil
		}
		// The VM was restarted and got a new runtime ID. Fall through and
		// rediscover rather than failing.
		t.mu.Lock()
		t.vmID = ""
		t.mu.Unlock()
	}

	ids, err := DiscoverVMIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVsockUnavailable, err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: no candidate VM runtime IDs found", ErrVsockUnavailable)
	}
	conn, id, err := raceHVSock(ctx, ids, t.port)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.vmID = id
	t.mu.Unlock()
	t.cfg.Logger.Debug("wslbridge: hvsock route found", "vmid", id, "port", t.port)
	return conn, nil
}

// Probe implements Transport.
func (t *VsockTransport) Probe(ctx context.Context) error {
	conn, err := t.Dial(ctx)
	if err != nil {
		return err
	}
	return conn.Close()
}

// raceHVSock dials every candidate concurrently and keeps the first that
// answers, closing the rest. Racing rather than trying in turn matters because a
// dead GUID can take the full timeout to fail and there may be several.
func raceHVSock(ctx context.Context, ids []string, port uint32) (net.Conn, string, error) {
	type result struct {
		conn net.Conn
		id   string
		err  error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan result, len(ids))
	for _, id := range ids {
		go func(id string) {
			conn, err := dialHVSock(ctx, id, port, vsockDialTimeout)
			results <- result{conn: conn, id: id, err: err}
		}(id)
	}

	var (
		winner  net.Conn
		winID   string
		errs    []error
		pending = len(ids)
	)
	for pending > 0 {
		r := <-results
		pending--
		switch {
		case r.err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", r.id, r.err))
		case winner == nil:
			winner, winID = r.conn, r.id
			cancel()
		default:
			_ = r.conn.Close()
		}
	}
	if winner != nil {
		return winner, winID, nil
	}
	return nil, "", fmt.Errorf("%w: %w", ErrVsockUnavailable, errors.Join(errs...))
}

// normaliseGUID lowercases a GUID and strips the braces the registry sometimes
// wraps them in, so candidates from different discovery routes compare equal.
func normaliseGUID(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	return strings.ToLower(s)
}

// dedupeGUIDs removes duplicates and anything that is not GUID-shaped, keeping
// the input order so the most likely candidate is dialled first.
func dedupeGUIDs(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = normaliseGUID(s)
		if !looksLikeGUID(s) {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// looksLikeGUID reports whether s has the 8-4-4-4-12 hex shape.
func looksLikeGUID(s string) bool {
	groups := strings.Split(s, "-")
	if len(groups) != 5 {
		return false
	}
	for i, want := range []int{8, 4, 4, 4, 12} {
		if len(groups[i]) != want {
			return false
		}
		for _, r := range groups[i] {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
				return false
			}
		}
	}
	return true
}
