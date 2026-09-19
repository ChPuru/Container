package network

import (
	"context"
	"net"
)

// IfaceConfig describes how the container end of a veth pair must look once it
// is inside the container's network namespace.
type IfaceConfig struct {
	// From is the temporary name the peer carries while it is still in the
	// host namespace. A veth peer cannot be created directly as "eth0" because
	// that name already exists on the host.
	From string
	// To is the final name inside the container, normally "eth0".
	To string
	// Addr is the address and prefix to assign.
	Addr *net.IPNet
	// MAC is the hardware address to set. It is random, never derived from
	// Addr — see idutil.NewMAC.
	MAC net.HardwareAddr
	// Gateway is the next hop for the container's default route.
	Gateway net.IP
	// MTU is the interface MTU, normally copied from the host's uplink.
	MTU int
}

// linkOps is the kernel-facing surface the Manager needs: links, addresses,
// routes and network namespaces. The production implementation speaks netlink
// directly (netlink_linux.go); tests substitute a recorder so the whole Manager
// is exercised without root or a real kernel.
type linkOps interface {
	// EnsureBridge creates a bridge if it is absent and brings its MTU into
	// line. It is idempotent so Manager.Init can re-attach after a restart.
	EnsureBridge(ctx context.Context, name string, mtu int) error

	// DeleteLink removes an interface. Deleting a veth host side also removes
	// its peer, wherever that peer currently lives.
	DeleteLink(ctx context.Context, name string) error

	// LinkExists reports whether an interface is present in the host namespace.
	LinkExists(ctx context.Context, name string) (bool, error)

	// InterfaceMTU returns an interface's MTU.
	InterfaceMTU(ctx context.Context, name string) (int, error)

	// AddAddress assigns an address to an interface, treating an address that
	// is already present as success.
	AddAddress(ctx context.Context, link string, addr *net.IPNet) error

	// SetUp brings an interface up.
	SetUp(ctx context.Context, link string) error

	// CreateVeth creates a veth pair with both ends in the host namespace.
	CreateVeth(ctx context.Context, host, peer string, mtu int) error

	// AttachToBridge enslaves an interface to a bridge.
	AttachToBridge(ctx context.Context, link, bridge string) error

	// MoveToNetNS moves an interface into another network namespace, named
	// either by nsPath or, when that is empty, by pid.
	MoveToNetNS(ctx context.Context, link string, pid int, nsPath string) error

	// ConfigureInNetNS enters a network namespace and finishes the container
	// side: rename, MAC, MTU, address, loopback up, link up, default route.
	ConfigureInNetNS(ctx context.Context, pid int, nsPath string, cfg IfaceConfig) error

	// HostReservations returns every address range already routed or assigned
	// on the host, so subnet allocation can avoid it.
	HostReservations(ctx context.Context) ([]Reservation, error)

	// EnableForwarding turns on IPv4 (and, when asked, IPv6) forwarding.
	EnableForwarding(ctx context.Context, ipv6 bool) error

	// UplinkName returns the interface carrying the default route, which is
	// where hull copies its MTU from.
	UplinkName(ctx context.Context) (string, error)

	// Close releases any kernel resources the implementation holds.
	Close() error
}
