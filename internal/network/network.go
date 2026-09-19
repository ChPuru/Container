// Package network implements hull's container networking: Linux bridges, IPAM,
// veth pairs, nftables NAT, an embedded DNS server and the userland port proxy.
//
// # Netlink, not scripts
//
// Every link, address and route operation is performed over a raw
// AF_NETLINK/NETLINK_ROUTE socket built by hand in netlink_linux.go: bridge and
// veth creation, MTU, MAC, master, moving a peer into another network
// namespace, address assignment and the default route. Nothing shells out to
// ip(8). That is deliberate — an engine owns its kernel interfaces.
//
// The one exception is nftables. hull renders its whole ruleset into a single
// `nft -f -` script and lets nft(8) compile it, because writing a complete
// netfilter expression encoder (immediate/payload/meta/cmp/nat/masq
// expressions, set descriptors, batch transactions) is a separate project and
// would not make the rules any more atomic: `nft -f -` already applies the
// whole script in one netlink transaction. The generated script is a pure
// function of the manager's state (see Ruleset.Script), so it is unit tested
// against a golden string. The iptables-nft compatibility shim required by
// Docker Desktop's FORWARD DROP policy likewise runs iptables(8).
//
// # Why there is always a real listening socket
//
// WSL's NAT-mode localhost forwarding discovers ports by polling sock_diag once
// a second for TCP sockets in LISTEN state *in the root network namespace*. A
// port published only with a DNAT rule has no such socket and is therefore
// invisible from Windows. hull consequently opens a real listening socket in
// the root netns for every published port (the userland proxy in proxy.go) and
// uses DNAT only for LAN-originated traffic, plus a hairpin masquerade so a
// container can reach its own published port.
//
// # Shared netfilter state
//
// All WSL distros share one kernel, one netfilter ruleset and one port space.
// Everything hull creates therefore lives in its own table, `inet hull`, with
// prefixed chain names, so `nft delete table inet hull` is a complete and safe
// uninstall that cannot disturb Docker Desktop's rules.
//
// The Manager, IPAM, DNS server, port proxies and the ruleset generator all
// build on every GOOS so the CLI can reference the types; the netlink backend
// is Linux-only and New reports ErrUnsupported elsewhere.
package network

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Errors returned by this package. They are sentinel values; callers should
// test with errors.Is because the concrete errors wrap them with context.
var (
	// ErrUnsupported is returned when the package is built for a GOOS other
	// than linux, or the running kernel lacks a facility hull requires.
	ErrUnsupported = errors.New("network: not supported on this platform")

	// ErrNotFound is returned when a network, endpoint or container is unknown.
	ErrNotFound = errors.New("network: not found")

	// ErrExists is returned when a network name or address is already taken.
	ErrExists = errors.New("network: already exists")

	// ErrInUse is returned by Remove when endpoints are still attached.
	ErrInUse = errors.New("network: has active endpoints")

	// ErrPoolExhausted is returned when no address or subnet is left to hand out.
	ErrPoolExhausted = errors.New("network: address pool exhausted")

	// ErrSubnetConflict is returned when a requested or candidate subnet
	// overlaps something already routed on the host. ConflictError wraps it and
	// names the specific conflict.
	ErrSubnetConflict = errors.New("network: subnet conflict")

	// ErrInvalidConfig is returned for malformed user input: a bad CIDR, a
	// gateway outside its subnet, an unparsable port specification.
	ErrInvalidConfig = errors.New("network: invalid configuration")
)

// Defaults for ManagerOptions. They are exported so `hull doctor` and the CLI
// can print what the engine will do before it does it.
const (
	// DefaultPool is the address space hull carves container subnets out of.
	// It deliberately avoids Docker's 172.17-172.31/16 and 192.168.0.0/16
	// pools and the WSL NAT subnet.
	DefaultPool = "10.66.0.0/16"

	// DefaultSubnetSize is the prefix length of each carved subnet.
	DefaultSubnetSize = 24

	// DefaultDNSPort is the port the embedded DNS server binds on each bridge
	// gateway address.
	DefaultDNSPort = 53

	// DefaultNetworkName is the name of the network containers join when
	// --network is not given.
	DefaultNetworkName = "bridge"

	// DefaultBridgeName is the Linux interface name of the default network's
	// bridge. Other networks get "hb-<12 hex>".
	DefaultBridgeName = "hull0"

	// TableName is the nftables table hull owns, in the inet family.
	TableName = "hull"

	// InternalDomain is the search domain hull answers for host and gateway
	// pseudo-names.
	InternalDomain = "hull.internal"
)

// ConflictError reports that a subnet cannot be used because it overlaps
// something already present on the host. It names the conflicting range and why
// it is reserved, so the user can pick a different one instead of debugging an
// unroutable network.
type ConflictError struct {
	// Subnet is the CIDR hull wanted to use.
	Subnet string
	// Conflict is the CIDR already in use.
	Conflict string
	// Reason describes who holds Conflict, e.g. "host route via eth0".
	Reason string
}

// Error implements error.
func (e *ConflictError) Error() string {
	return fmt.Sprintf("network: subnet %s conflicts with %s (%s)", e.Subnet, e.Conflict, e.Reason)
}

// Is makes errors.Is(err, ErrSubnetConflict) true for a *ConflictError.
func (e *ConflictError) Is(target error) bool { return target == ErrSubnetConflict }

// Reservation is one address range that must not be handed out, together with a
// human-readable explanation of who holds it.
type Reservation struct {
	// Subnet is the reserved range.
	Subnet *net.IPNet
	// Reason names the holder, e.g. "docker default pool" or "host route".
	Reason string
}

// String renders the reservation as "CIDR (reason)".
func (r Reservation) String() string {
	if r.Subnet == nil {
		return "<nil>"
	}
	return r.Subnet.String() + " (" + r.Reason + ")"
}

// DockerReservations returns the address pools Docker Engine and Docker Desktop
// allocate from by default. hull must skip them even when no Docker bridge
// exists yet, because Docker will happily create one later and the collision
// would only surface as intermittently unreachable containers.
func DockerReservations() []Reservation {
	out := make([]Reservation, 0, 16)
	for b := 17; b <= 31; b++ {
		_, n, err := net.ParseCIDR(fmt.Sprintf("172.%d.0.0/16", b))
		if err != nil {
			continue
		}
		out = append(out, Reservation{Subnet: n, Reason: "docker default bridge pool"})
	}
	if _, n, err := net.ParseCIDR("192.168.0.0/16"); err == nil {
		out = append(out, Reservation{Subnet: n, Reason: "docker default address pool"})
	}
	return out
}

// AllocateSubnet returns the first subnet of the given prefix length inside pool
// that does not overlap any reservation. Candidates are walked in ascending
// order so allocation is deterministic and a restarted engine re-derives the
// same layout.
//
// It returns a *ConflictError only when pool itself is unusable; when every
// candidate is taken it returns an error wrapping ErrPoolExhausted that lists
// what got in the way.
func AllocateSubnet(pool string, size int, used []Reservation) (*net.IPNet, error) {
	_, poolNet, err := net.ParseCIDR(pool)
	if err != nil {
		return nil, fmt.Errorf("%w: pool %q: %w", ErrInvalidConfig, pool, err)
	}
	ones, bits := poolNet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("%w: pool %q: only IPv4 pools are supported", ErrInvalidConfig, pool)
	}
	if size < ones || size > 30 {
		return nil, fmt.Errorf("%w: subnet size /%d is not inside pool %s (/%d..%d)",
			ErrInvalidConfig, size, pool, ones, 30)
	}
	base, ok := ipToU32(poolNet.IP)
	if !ok {
		return nil, fmt.Errorf("%w: pool %q is not IPv4", ErrInvalidConfig, pool)
	}

	step := uint32(1) << uint(32-size)
	count := uint64(1) << uint(size-ones)
	var blockers []string
	for i := uint64(0); i < count; i++ {
		cand := &net.IPNet{IP: u32ToIP(base + uint32(i)*step), Mask: net.CIDRMask(size, 32)}
		if c := firstConflict(cand, used); c != nil {
			if len(blockers) < 4 {
				blockers = append(blockers, c.String())
			}
			continue
		}
		return cand, nil
	}
	detail := "no candidates"
	if len(blockers) > 0 {
		detail = "blocked by " + strings.Join(blockers, ", ")
	}
	return nil, fmt.Errorf("%w: no free /%d in %s: %s", ErrPoolExhausted, size, pool, detail)
}

// CheckSubnet validates an operator-supplied subnet against the reservations,
// returning a *ConflictError naming the conflict rather than creating a network
// that cannot route.
func CheckSubnet(subnet *net.IPNet, used []Reservation) error {
	if subnet == nil {
		return fmt.Errorf("%w: nil subnet", ErrInvalidConfig)
	}
	if c := firstConflict(subnet, used); c != nil {
		return &ConflictError{Subnet: subnet.String(), Conflict: c.Subnet.String(), Reason: c.Reason}
	}
	return nil
}

// firstConflict returns the first reservation overlapping n, or nil.
func firstConflict(n *net.IPNet, used []Reservation) *Reservation {
	for i := range used {
		if used[i].Subnet == nil {
			continue
		}
		if netsOverlap(n, used[i].Subnet) {
			r := used[i]
			return &r
		}
	}
	return nil
}

// netsOverlap reports whether two CIDRs share any address. Two ranges overlap
// exactly when one contains the other's base address, because CIDRs are
// power-of-two aligned blocks.
func netsOverlap(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// ipToU32 converts an IPv4 address to its big-endian numeric form.
func ipToU32(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), true
}

// u32ToIP converts a numeric IPv4 address back to a 4-byte net.IP.
func u32ToIP(v uint32) net.IP {
	return net.IP{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// FirstUsable returns the first address of a subnet that may be assigned to an
// interface: the network address plus one. It is the gateway hull uses when the
// caller does not supply one.
func FirstUsable(n *net.IPNet) net.IP {
	base, ok := ipToU32(n.IP.Mask(n.Mask))
	if !ok {
		return nil
	}
	return u32ToIP(base + 1)
}

// LastAddr returns the broadcast (all-ones host part) address of a subnet.
func LastAddr(n *net.IPNet) net.IP {
	base, ok := ipToU32(n.IP.Mask(n.Mask))
	if !ok {
		return nil
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return nil
	}
	return u32ToIP(base | (uint32(1)<<uint(32-ones) - 1))
}

// ParsePortSpec splits a Docker-style "port/proto" key such as "80/tcp" into its
// parts. A missing protocol defaults to tcp. Only tcp, udp and sctp are
// accepted; anything else is rejected rather than silently published as tcp.
func ParsePortSpec(spec string) (port int, proto string, err error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return 0, "", fmt.Errorf("%w: empty port specification", ErrInvalidConfig)
	}
	proto = "tcp"
	if i := strings.LastIndex(s, "/"); i >= 0 {
		proto = strings.ToLower(s[i+1:])
		s = s[:i]
	}
	switch proto {
	case "tcp", "udp", "sctp":
	default:
		return 0, "", fmt.Errorf("%w: unknown protocol %q in %q", ErrInvalidConfig, proto, spec)
	}
	p, convErr := strconv.Atoi(s)
	if convErr != nil {
		return 0, "", fmt.Errorf("%w: port %q in %q: %w", ErrInvalidConfig, s, spec, convErr)
	}
	if p < 1 || p > 65535 {
		return 0, "", fmt.Errorf("%w: port %d in %q is out of range", ErrInvalidConfig, p, spec)
	}
	return p, proto, nil
}

// PortSpec formats a port and protocol back into the "80/tcp" form the Docker
// API uses as a map key.
func PortSpec(port int, proto string) string {
	return strconv.Itoa(port) + "/" + proto
}

// bridgeNameFor derives the Linux interface name for a network. The default
// network keeps the stable, recognisable "hull0"; every other network gets
// "hb-" plus the first 12 hex characters of its ID, which fits inside IFNAMSIZ
// (16 bytes including the NUL).
func bridgeNameFor(name, id string) string {
	if name == DefaultNetworkName {
		return DefaultBridgeName
	}
	h := id
	if len(h) > 12 {
		h = h[:12]
	}
	return "hb-" + h
}

// validNetworkName reports whether a user-supplied network name is acceptable.
// The rules match Docker's so compose files port over unchanged.
func validNetworkName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	c := s[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}
