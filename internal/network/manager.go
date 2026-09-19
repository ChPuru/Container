package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rahuldhali/hull/internal/fsutil"
	"github.com/rahuldhali/hull/internal/idutil"
	"github.com/rahuldhali/hull/internal/types"
)

// defaultMTU is used only when the host's uplink MTU cannot be read.
const defaultMTU = 1500

// ManagerOptions configures a Manager. The zero value is valid: every field
// falls back to the documented default.
type ManagerOptions struct {
	// DefaultPool is the CIDR container subnets are carved out of.
	// Default: DefaultPool ("10.66.0.0/16").
	DefaultPool string
	// SubnetSize is the prefix length of each carved subnet. Default: 24.
	SubnetSize int
	// DNSPort is the port the embedded resolver binds on each gateway.
	// Default: 53.
	DNSPort int
	// MTU overrides the bridge MTU. When zero hull copies the uplink's MTU, so
	// a VPN with a smaller MTU does not silently break large packets.
	MTU int
	// EnableIPv6 turns on IPv6 forwarding. IPv6 subnets are not allocated yet.
	EnableIPv6 bool
	// IPTablesCompat controls the iptables FORWARD ACCEPT shim that works
	// around Docker Desktop's FORWARD DROP policy. nil means the default, true.
	IPTablesCompat *bool
	// DNSUpstreams overrides the resolvers read from ResolvConfPath.
	DNSUpstreams []string
	// ResolvConfPath is the host resolv.conf. Default: /etc/resolv.conf.
	ResolvConfPath string
	// DNSSearch is the default search domain list written into containers.
	DNSSearch []string
}

// DefaultManagerOptions returns the options hull uses when the operator says
// nothing. It is the honest place to read the defaults from.
func DefaultManagerOptions() ManagerOptions {
	yes := true
	return ManagerOptions{
		DefaultPool:    DefaultPool,
		SubnetSize:     DefaultSubnetSize,
		DNSPort:        DefaultDNSPort,
		IPTablesCompat: &yes,
		ResolvConfPath: "/etc/resolv.conf",
	}
}

// CreateConfig is the user-supplied half of a network definition.
type CreateConfig struct {
	// Driver must be "bridge"; "host" and "none" are pseudo-networks handled
	// by the runtime, not by this package.
	Driver string
	// Subnet is an explicit CIDR. When empty one is allocated from the pool.
	Subnet string
	// Gateway is an explicit gateway address. Default: the first usable
	// address of Subnet.
	Gateway string
	// IPRange narrows the part of Subnet that IPAM may allocate from.
	IPRange string
	// Internal removes the masquerade rule and blocks traffic crossing the
	// bridge boundary in either direction.
	Internal bool
	// Attachable is recorded for Docker API compatibility.
	Attachable bool
	// IPv6 is recorded; IPv6 subnet allocation is not implemented.
	IPv6 bool
	// Options are driver options, recorded verbatim. "com.hull.mtu" overrides
	// the bridge MTU for this network.
	Options map[string]string
	// Labels are user labels.
	Labels map[string]string
}

// EndpointConfig is the per-attachment configuration for Connect.
type EndpointConfig struct {
	// IPv4Address requests a specific address instead of the next free one.
	IPv4Address string
	// Aliases are extra names the container answers to on this network.
	Aliases []string
	// DNSNames are additional resolvable names.
	DNSNames []string
	// MacAddress requests a specific MAC. When empty a random locally
	// administered address is generated (never derived from the IP).
	MacAddress string
	// IfName is the interface name inside the container. Default: "eth0".
	IfName string
	// SandboxPID is the container process whose network namespace to join.
	// When zero, Container.Pid is used.
	SandboxPID int
	// SandboxPath overrides the namespace path, normally /proc/<pid>/ns/net.
	SandboxPath string
}

// endpoint is the manager's in-memory record of one attachment. It is the table
// the DNS server and the port publisher resolve against.
type endpoint struct {
	containerID   string
	containerName string
	networkID     string
	endpointID    string
	ip            net.IP
	names         []string
	hostIfname    string
}

// networkIndex is the on-disk form of networks/networks.json.
type networkIndex struct {
	Version  int                       `json:"version"`
	Networks map[string]*types.Network `json:"networks"`
}

// Manager owns hull's networks: bridges, IPAM, endpoints, the firewall ruleset,
// the embedded DNS server and the published-port proxies.
//
// It is safe for concurrent use. External commands and netlink calls are made
// outside the lock wherever a slow syscall would otherwise block DNS lookups.
type Manager struct {
	root  string
	opts  ManagerOptions
	links linkOps
	fw    *Firewall
	ipam  *IPAM
	dns   *DNSServer

	mu        sync.RWMutex
	nets      map[string]*types.Network
	endpoints map[string]*endpoint
	ports     map[string][]PublishedPort
	hostMTU   int
	started   bool
}

// newLinkOpsFn is the constructor New uses for the kernel backend. It is a
// variable so tests can substitute a recorder and exercise the whole Manager
// without root, a bridge or a namespace.
var newLinkOpsFn = newLinkOps

// New builds a Manager rooted at hull's state directory (normally
// /var/lib/hull). It opens the netlink socket and loads persisted networks but
// touches no kernel state; call Init for that.
func New(root string, opts ManagerOptions) (*Manager, error) {
	if root == "" {
		return nil, fmt.Errorf("%w: empty state root", ErrInvalidConfig)
	}
	if opts.DefaultPool == "" {
		opts.DefaultPool = DefaultPool
	}
	if opts.SubnetSize == 0 {
		opts.SubnetSize = DefaultSubnetSize
	}
	if opts.DNSPort == 0 {
		opts.DNSPort = DefaultDNSPort
	}
	if opts.ResolvConfPath == "" {
		opts.ResolvConfPath = "/etc/resolv.conf"
	}
	if opts.IPTablesCompat == nil {
		yes := true
		opts.IPTablesCompat = &yes
	}
	if _, _, err := net.ParseCIDR(opts.DefaultPool); err != nil {
		return nil, fmt.Errorf("%w: default pool %q: %w", ErrInvalidConfig, opts.DefaultPool, err)
	}

	links, err := newLinkOpsFn()
	if err != nil {
		return nil, err
	}
	for _, d := range []string{filepath.Join(root, "networks"), filepath.Join(root, "networks", "ipam")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			links.Close()
			return nil, fmt.Errorf("network: create %s: %w", d, err)
		}
	}
	ipam, err := NewIPAM(filepath.Join(root, "networks", "ipam"))
	if err != nil {
		links.Close()
		return nil, err
	}

	m := &Manager{
		root:      root,
		opts:      opts,
		links:     links,
		fw:        NewFirewall(TableName, *opts.IPTablesCompat),
		ipam:      ipam,
		nets:      make(map[string]*types.Network),
		endpoints: make(map[string]*endpoint),
		ports:     make(map[string][]PublishedPort),
		hostMTU:   opts.MTU,
	}
	m.dns = NewDNSServer(m, DNSOptions{
		Port:           opts.DNSPort,
		Upstreams:      opts.DNSUpstreams,
		ResolvConfPath: opts.ResolvConfPath,
		Search:         opts.DNSSearch,
	})
	if err := m.load(); err != nil {
		links.Close()
		return nil, err
	}
	return m, nil
}

// DNS returns the embedded resolver.
func (m *Manager) DNS() *DNSServer { return m.dns }

// Root returns the state directory the manager was built with.
func (m *Manager) Root() string { return m.root }

// indexPath is where the network index lives.
func (m *Manager) indexPath() string { return filepath.Join(m.root, "networks", "networks.json") }

// load reads the persisted network index and rebuilds the endpoint table.
func (m *Manager) load() error {
	idx := networkIndex{}
	err := fsutil.ReadJSON(m.indexPath(), &idx)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("network: read %s: %w", m.indexPath(), err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, n := range idx.Networks {
		if n == nil {
			continue
		}
		n.ID = id
		m.nets[id] = n
		for cid, ep := range n.Containers {
			ip := net.ParseIP(ep.IPAddress)
			if ip == nil {
				continue
			}
			m.endpoints[ip.String()] = &endpoint{
				containerID:   cid,
				containerName: primaryName(ep),
				networkID:     id,
				endpointID:    ep.EndpointID,
				ip:            ip,
				names:         append([]string(nil), ep.DNSNames...),
				hostIfname:    ep.HostIfname,
			}
		}
	}
	return nil
}

// primaryName picks the name a reverse lookup should report for an endpoint.
func primaryName(ep types.EndpointSettings) string {
	if len(ep.DNSNames) > 0 {
		return ep.DNSNames[0]
	}
	if len(ep.Aliases) > 0 {
		return ep.Aliases[0]
	}
	return ""
}

// save writes the network index atomically. The caller must hold m.mu.
func (m *Manager) saveLocked() error {
	idx := networkIndex{Version: 1, Networks: m.nets}
	if err := fsutil.WriteJSONAtomic(m.indexPath(), idx, 0o600); err != nil {
		return fmt.Errorf("network: persist %s: %w", m.indexPath(), err)
	}
	return nil
}

// Init brings the kernel and netfilter state into line with the persisted
// configuration: IP forwarding on, hull's nftables table created, every known
// bridge present with its gateway address, the default network created if it is
// missing, and the DNS server bound to every gateway.
//
// It is idempotent and is also the restart path: a daemon that comes back finds
// its bridges and endpoints already there and simply re-attaches.
func (m *Manager) Init(ctx context.Context) error {
	if err := m.fw.Check(ctx); err != nil {
		return err
	}
	if err := m.links.EnableForwarding(ctx, m.opts.EnableIPv6); err != nil {
		return err
	}
	if err := m.resolveHostMTU(ctx); err != nil {
		return err
	}
	if len(m.opts.DNSUpstreams) == 0 {
		if err := m.dns.LoadUpstreamsFromResolvConf(); err != nil {
			return err
		}
	}

	m.mu.RLock()
	existing := make([]*types.Network, 0, len(m.nets))
	for _, n := range m.nets {
		existing = append(existing, n)
	}
	m.mu.RUnlock()
	sort.Slice(existing, func(i, j int) bool { return existing[i].Name < existing[j].Name })

	for _, n := range existing {
		if err := m.realise(ctx, n); err != nil {
			return err
		}
	}

	if _, err := m.Get(DefaultNetworkName); errors.Is(err, ErrNotFound) {
		if _, err := m.Create(ctx, DefaultNetworkName, CreateConfig{Driver: "bridge"}); err != nil {
			return fmt.Errorf("network: create the default %q network: %w", DefaultNetworkName, err)
		}
	} else if err != nil {
		return err
	}

	if err := m.applyRules(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	m.started = true
	m.mu.Unlock()
	return nil
}

// resolveHostMTU fills in the bridge MTU from the uplink when not overridden.
func (m *Manager) resolveHostMTU(ctx context.Context) error {
	if m.opts.MTU > 0 {
		m.mu.Lock()
		m.hostMTU = m.opts.MTU
		m.mu.Unlock()
		return nil
	}
	mtu := defaultMTU
	if up, err := m.links.UplinkName(ctx); err == nil {
		if v, err := m.links.InterfaceMTU(ctx, up); err == nil && v > 0 {
			mtu = v
		}
	}
	m.mu.Lock()
	m.hostMTU = mtu
	m.mu.Unlock()
	return nil
}

// realise makes one network's kernel state match its record: bridge present,
// MTU set, gateway assigned, bridge up, IPAM pool registered, DNS bound.
func (m *Manager) realise(ctx context.Context, n *types.Network) error {
	if n.Driver != "" && n.Driver != "bridge" {
		return nil
	}
	_, subnet, err := net.ParseCIDR(n.IPAM.Subnet)
	if err != nil {
		return fmt.Errorf("%w: network %s has subnet %q: %w", ErrInvalidConfig, n.Name, n.IPAM.Subnet, err)
	}
	gw := net.ParseIP(n.IPAM.Gateway)
	if gw == nil {
		return fmt.Errorf("%w: network %s has gateway %q", ErrInvalidConfig, n.Name, n.IPAM.Gateway)
	}
	mtu := m.networkMTU(n)
	if err := m.links.EnsureBridge(ctx, n.BridgeName, mtu); err != nil {
		return err
	}
	ones, _ := subnet.Mask.Size()
	if err := m.links.AddAddress(ctx, n.BridgeName, &net.IPNet{IP: gw, Mask: net.CIDRMask(ones, 32)}); err != nil {
		return err
	}
	if err := m.links.SetUp(ctx, n.BridgeName); err != nil {
		return err
	}
	var ipRange *net.IPNet
	if n.IPAM.IPRange != "" {
		if _, r, err := net.ParseCIDR(n.IPAM.IPRange); err == nil {
			ipRange = r
		}
	}
	if err := m.ipam.AddPool(n.ID, subnet, gw, ipRange); err != nil {
		return err
	}
	if err := m.dns.Listen(ctx, gw); err != nil {
		return err
	}
	return nil
}

// networkMTU returns the MTU for a network: its own option, else the host MTU.
func (m *Manager) networkMTU(n *types.Network) int {
	if v, ok := n.Options["com.hull.mtu"]; ok {
		if mtu, err := strconv.Atoi(v); err == nil && mtu > 0 {
			return mtu
		}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.hostMTU > 0 {
		return m.hostMTU
	}
	return defaultMTU
}

// Shutdown stops the DNS server, closes every published-port proxy and removes
// hull's netfilter table and its iptables shim. Bridges and persisted state are
// left in place so the next Init re-attaches instead of renumbering.
func (m *Manager) Shutdown(ctx context.Context) error {
	var errs []error
	m.mu.Lock()
	for cid, list := range m.ports {
		for _, p := range list {
			if err := p.Close(); err != nil {
				errs = append(errs, fmt.Errorf("network: close published port %s of %s: %w", p, cid, err))
			}
		}
		delete(m.ports, cid)
	}
	m.started = false
	if err := m.saveLocked(); err != nil {
		errs = append(errs, err)
	}
	m.mu.Unlock()

	if err := m.dns.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := m.fw.Teardown(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := m.links.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ---------- networks ----------

// reservations gathers everything a new subnet must avoid: the host's routes
// and interface addresses (which on WSL includes the NAT subnet), Docker's
// default pools, and hull's own existing networks.
func (m *Manager) reservations(ctx context.Context) ([]Reservation, error) {
	host, err := m.links.HostReservations(ctx)
	if err != nil {
		return nil, err
	}
	out := append(host, DockerReservations()...)
	m.mu.RLock()
	for _, n := range m.nets {
		if _, sn, err := net.ParseCIDR(n.IPAM.Subnet); err == nil {
			out = append(out, Reservation{Subnet: sn, Reason: "hull network " + n.Name})
		}
	}
	m.mu.RUnlock()
	return out, nil
}

// Create defines a new bridge network and brings it up.
//
// With no Subnet, one is allocated from the pool while skipping every range
// already in use. A requested Subnet that collides produces a *ConflictError
// naming the conflict rather than an unroutable network.
func (m *Manager) Create(ctx context.Context, name string, cfg CreateConfig) (*types.Network, error) {
	if !validNetworkName(name) {
		return nil, fmt.Errorf("%w: network name %q must be 1-64 characters of [a-zA-Z0-9][a-zA-Z0-9_.-]", ErrInvalidConfig, name)
	}
	if cfg.Driver == "" {
		cfg.Driver = "bridge"
	}
	if cfg.Driver != "bridge" {
		return nil, fmt.Errorf("%w: driver %q; hull only implements the bridge driver", ErrInvalidConfig, cfg.Driver)
	}
	m.mu.RLock()
	for _, n := range m.nets {
		if n.Name == name {
			m.mu.RUnlock()
			return nil, fmt.Errorf("%w: network %q", ErrExists, name)
		}
	}
	m.mu.RUnlock()

	used, err := m.reservations(ctx)
	if err != nil {
		return nil, err
	}

	var subnet *net.IPNet
	if cfg.Subnet != "" {
		_, subnet, err = net.ParseCIDR(cfg.Subnet)
		if err != nil {
			return nil, fmt.Errorf("%w: subnet %q: %w", ErrInvalidConfig, cfg.Subnet, err)
		}
		if err := CheckSubnet(subnet, used); err != nil {
			return nil, err
		}
	} else {
		subnet, err = AllocateSubnet(m.opts.DefaultPool, m.opts.SubnetSize, used)
		if err != nil {
			return nil, err
		}
	}

	gw := FirstUsable(subnet)
	if cfg.Gateway != "" {
		gw = net.ParseIP(cfg.Gateway)
		if gw == nil || !subnet.Contains(gw) {
			return nil, fmt.Errorf("%w: gateway %q is not inside subnet %s", ErrInvalidConfig, cfg.Gateway, subnet)
		}
	}
	var ipRange *net.IPNet
	if cfg.IPRange != "" {
		if _, ipRange, err = net.ParseCIDR(cfg.IPRange); err != nil {
			return nil, fmt.Errorf("%w: ipRange %q: %w", ErrInvalidConfig, cfg.IPRange, err)
		}
		if !subnet.Contains(ipRange.IP) {
			return nil, fmt.Errorf("%w: ipRange %s is outside subnet %s", ErrInvalidConfig, ipRange, subnet)
		}
	}

	id := idutil.NewID()
	n := &types.Network{
		ID:         id,
		Name:       name,
		Driver:     "bridge",
		Scope:      "local",
		Created:    time.Now().UTC(),
		Internal:   cfg.Internal,
		Attachable: cfg.Attachable,
		EnableIPv6: cfg.IPv6,
		IPAM: types.IPAMConfig{
			Driver:  "default",
			Subnet:  subnet.String(),
			Gateway: gw.String(),
			IPRange: cfg.IPRange,
		},
		Options:    cfg.Options,
		Labels:     cfg.Labels,
		BridgeName: bridgeNameFor(name, id),
		Containers: make(map[string]types.EndpointSettings),
	}

	if err := m.realise(ctx, n); err != nil {
		// Leave nothing half-built behind.
		_ = m.links.DeleteLink(ctx, n.BridgeName)
		_ = m.ipam.RemovePool(n.ID)
		return nil, err
	}

	m.mu.Lock()
	m.nets[id] = n
	saveErr := m.saveLocked()
	m.mu.Unlock()
	if saveErr != nil {
		return nil, saveErr
	}
	if err := m.applyRules(ctx); err != nil {
		return nil, err
	}
	return copyNetwork(n), nil
}

// Remove deletes a network. It refuses while endpoints are attached, because
// tearing the bridge out from under a running container would leave it with a
// veth pointing nowhere.
func (m *Manager) Remove(ctx context.Context, idOrName string) error {
	m.mu.Lock()
	n := m.findLocked(idOrName)
	if n == nil {
		m.mu.Unlock()
		return fmt.Errorf("%w: network %q", ErrNotFound, idOrName)
	}
	if n.Name == DefaultNetworkName {
		m.mu.Unlock()
		return fmt.Errorf("%w: the default %q network is predefined and cannot be removed",
			ErrInvalidConfig, DefaultNetworkName)
	}
	if len(n.Containers) > 0 {
		names := make([]string, 0, len(n.Containers))
		for cid := range n.Containers {
			names = append(names, idutil.TruncateID(cid))
		}
		sort.Strings(names)
		m.mu.Unlock()
		return fmt.Errorf("%w: network %s still has %d endpoint(s): %s",
			ErrInUse, n.Name, len(names), strings.Join(names, ", "))
	}
	bridge, gw, id := n.BridgeName, net.ParseIP(n.IPAM.Gateway), n.ID
	delete(m.nets, id)
	saveErr := m.saveLocked()
	m.mu.Unlock()
	if saveErr != nil {
		return saveErr
	}

	var errs []error
	if err := m.dns.Stop(gw); err != nil {
		errs = append(errs, err)
	}
	if err := m.links.DeleteLink(ctx, bridge); err != nil {
		errs = append(errs, err)
	}
	if err := m.ipam.RemovePool(id); err != nil {
		errs = append(errs, err)
	}
	if err := m.fw.RemoveForwardAccept(ctx, []string{bridge}); err != nil {
		errs = append(errs, err)
	}
	if err := m.applyRules(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// findLocked resolves a network by ID, ID prefix or name. The caller must hold
// m.mu in at least read mode.
func (m *Manager) findLocked(idOrName string) *types.Network {
	if idOrName == "" {
		return nil
	}
	if n, ok := m.nets[idOrName]; ok {
		return n
	}
	for _, n := range m.nets {
		if n.Name == idOrName {
			return n
		}
	}
	var hit *types.Network
	for id, n := range m.nets {
		if len(idOrName) >= 4 && strings.HasPrefix(id, idOrName) {
			if hit != nil {
				return nil // ambiguous prefix
			}
			hit = n
		}
	}
	return hit
}

// Get returns a network by ID, ID prefix or name.
func (m *Manager) Get(idOrName string) (*types.Network, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := m.findLocked(idOrName)
	if n == nil {
		return nil, fmt.Errorf("%w: network %q", ErrNotFound, idOrName)
	}
	return copyNetwork(n), nil
}

// Inspect is Get under the name the Docker API uses.
func (m *Manager) Inspect(idOrName string) (*types.Network, error) { return m.Get(idOrName) }

// List returns every network, sorted by name.
func (m *Manager) List() []*types.Network {
	m.mu.RLock()
	out := make([]*types.Network, 0, len(m.nets))
	for _, n := range m.nets {
		out = append(out, copyNetwork(n))
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// copyNetwork deep-copies a network so callers cannot mutate manager state.
func copyNetwork(n *types.Network) *types.Network {
	c := *n
	c.Options = copyStringMap(n.Options)
	c.Labels = copyStringMap(n.Labels)
	if n.Containers != nil {
		c.Containers = make(map[string]types.EndpointSettings, len(n.Containers))
		for k, v := range n.Containers {
			v.Aliases = append([]string(nil), v.Aliases...)
			v.DNSNames = append([]string(nil), v.DNSNames...)
			c.Containers[k] = v
		}
	}
	return &c
}

// copyStringMap copies a map, preserving nil.
func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// ---------- endpoints ----------

// Connect attaches a container to a network: it allocates an address, creates a
// veth pair, enslaves the host side to the bridge, moves the peer into the
// container's network namespace, and configures the interface, MAC, address and
// default route there. The names the container answers to are registered with
// the embedded DNS server.
//
// The container must already have a network namespace, i.e. it must be created
// and its pid known.
func (m *Manager) Connect(ctx context.Context, netID string, c *types.Container, cfg EndpointConfig) (*types.EndpointSettings, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil container", ErrInvalidConfig)
	}
	m.mu.RLock()
	n := m.findLocked(netID)
	m.mu.RUnlock()
	if n == nil {
		return nil, fmt.Errorf("%w: network %q", ErrNotFound, netID)
	}
	if _, ok := n.Containers[c.ID]; ok {
		return nil, fmt.Errorf("%w: container %s is already attached to network %s",
			ErrExists, idutil.TruncateID(c.ID), n.Name)
	}

	pid := cfg.SandboxPID
	if pid == 0 {
		pid = c.Pid
	}
	nsPath := cfg.SandboxPath
	if nsPath == "" {
		if pid <= 0 {
			return nil, fmt.Errorf("%w: container %s has no pid, so it has no network namespace to attach to",
				ErrInvalidConfig, idutil.TruncateID(c.ID))
		}
		nsPath = "/proc/" + strconv.Itoa(pid) + "/ns/net"
	}

	_, subnet, err := net.ParseCIDR(n.IPAM.Subnet)
	if err != nil {
		return nil, fmt.Errorf("%w: network %s subnet %q: %w", ErrInvalidConfig, n.Name, n.IPAM.Subnet, err)
	}
	gw := net.ParseIP(n.IPAM.Gateway)

	var want net.IP
	if cfg.IPv4Address != "" {
		want = net.ParseIP(cfg.IPv4Address)
		if want == nil {
			return nil, fmt.Errorf("%w: requested address %q is not an IP", ErrInvalidConfig, cfg.IPv4Address)
		}
	}
	ip, err := m.ipam.Allocate(n.ID, want)
	if err != nil {
		return nil, err
	}

	mac := idutil.NewMAC(ip)
	if cfg.MacAddress != "" {
		parsed, err := net.ParseMAC(cfg.MacAddress)
		if err != nil {
			_ = m.ipam.Release(n.ID, ip)
			return nil, fmt.Errorf("%w: mac address %q: %w", ErrInvalidConfig, cfg.MacAddress, err)
		}
		mac = parsed
	}
	ifName := cfg.IfName
	if ifName == "" {
		ifName = "eth0"
	}

	suffix := idutil.NewShortID()[:6]
	hostIf := "hv-" + suffix
	peerIf := "hp-" + suffix
	mtu := m.networkMTU(n)

	cleanup := func() {
		_ = m.links.DeleteLink(ctx, hostIf)
		_ = m.ipam.Release(n.ID, ip)
	}

	if err := m.links.CreateVeth(ctx, hostIf, peerIf, mtu); err != nil {
		_ = m.ipam.Release(n.ID, ip)
		return nil, err
	}
	if err := m.links.AttachToBridge(ctx, hostIf, n.BridgeName); err != nil {
		cleanup()
		return nil, err
	}
	if err := m.links.SetUp(ctx, hostIf); err != nil {
		cleanup()
		return nil, err
	}
	if err := m.links.MoveToNetNS(ctx, peerIf, pid, nsPath); err != nil {
		cleanup()
		return nil, err
	}
	ones, _ := subnet.Mask.Size()
	err = m.links.ConfigureInNetNS(ctx, pid, nsPath, IfaceConfig{
		From:    peerIf,
		To:      ifName,
		Addr:    &net.IPNet{IP: ip, Mask: net.CIDRMask(ones, 32)},
		MAC:     mac,
		Gateway: gw,
		MTU:     mtu,
	})
	if err != nil {
		cleanup()
		return nil, err
	}

	names := endpointNames(c, n, cfg)
	ep := types.EndpointSettings{
		NetworkID:   n.ID,
		EndpointID:  idutil.NewEndpointID(),
		Gateway:     n.IPAM.Gateway,
		IPAddress:   ip.String(),
		IPPrefixLen: ones,
		MacAddress:  mac.String(),
		Aliases:     append([]string(nil), cfg.Aliases...),
		DNSNames:    names,
		HostIfname:  hostIf,
	}

	m.mu.Lock()
	live := m.nets[n.ID]
	if live == nil {
		m.mu.Unlock()
		cleanup()
		return nil, fmt.Errorf("%w: network %s disappeared while attaching", ErrNotFound, n.Name)
	}
	if live.Containers == nil {
		live.Containers = make(map[string]types.EndpointSettings)
	}
	live.Containers[c.ID] = ep
	m.endpoints[ip.String()] = &endpoint{
		containerID:   c.ID,
		containerName: c.Name,
		networkID:     n.ID,
		endpointID:    ep.EndpointID,
		ip:            ip,
		names:         names,
		hostIfname:    hostIf,
	}
	saveErr := m.saveLocked()
	m.mu.Unlock()
	if saveErr != nil {
		return nil, saveErr
	}
	if err := m.applyRules(ctx); err != nil {
		return nil, err
	}
	out := ep
	return &out, nil
}

// endpointNames builds the lowercase name list a container answers to on one
// network: its name, its short and full IDs, its hostname, every alias, and the
// network-qualified form "<name>.<network>".
func endpointNames(c *types.Container, n *types.Network, cfg EndpointConfig) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(s, "/")))
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	add(c.Name)
	if c.Name != "" && n.Name != "" {
		add(c.Name + "." + n.Name)
	}
	add(c.Config.Hostname)
	add(idutil.TruncateID(c.ID))
	add(c.ID)
	for _, a := range cfg.Aliases {
		add(a)
	}
	for _, d := range cfg.DNSNames {
		add(d)
	}
	return out
}

// Disconnect detaches a container from a network, removing its veth and
// returning its address to the pool. With force set, kernel-level teardown
// failures are tolerated so a half-gone container can still be cleaned up.
func (m *Manager) Disconnect(ctx context.Context, netID, containerID string, force bool) error {
	m.mu.Lock()
	n := m.findLocked(netID)
	if n == nil {
		m.mu.Unlock()
		if force {
			return nil
		}
		return fmt.Errorf("%w: network %q", ErrNotFound, netID)
	}
	ep, ok := n.Containers[containerID]
	if !ok {
		m.mu.Unlock()
		if force {
			return nil
		}
		return fmt.Errorf("%w: container %s on network %s", ErrNotFound, idutil.TruncateID(containerID), n.Name)
	}
	delete(n.Containers, containerID)
	delete(m.endpoints, ep.IPAddress)
	netIDResolved := n.ID
	saveErr := m.saveLocked()
	m.mu.Unlock()

	var errs []error
	if saveErr != nil {
		errs = append(errs, saveErr)
	}
	if ep.HostIfname != "" {
		if err := m.links.DeleteLink(ctx, ep.HostIfname); err != nil && !force {
			errs = append(errs, err)
		}
	}
	if ip := net.ParseIP(ep.IPAddress); ip != nil {
		if err := m.ipam.Release(netIDResolved, ip); err != nil && !force {
			errs = append(errs, err)
		}
	}
	if err := m.applyRules(ctx); err != nil && !force {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ---------- registry (DNS view) ----------

// NetworksForSource implements Registry: it maps a querying container's address
// to the networks it may resolve names on, and to the gateway serving it. This
// is what scopes DNS to a network instead of leaking every container's name to
// every other container.
func (m *Manager) NetworksForSource(src net.IP) ([]string, net.IP) {
	if src == nil {
		return nil, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	if ep, ok := m.endpoints[src.String()]; ok {
		if n, ok := m.nets[ep.networkID]; ok {
			return []string{ep.networkID}, net.ParseIP(n.IPAM.Gateway)
		}
		return []string{ep.networkID}, nil
	}
	// Not a known endpoint: fall back to the network whose subnet contains it,
	// which covers a container that set its own address inside its subnet.
	for id, n := range m.nets {
		if _, sn, err := net.ParseCIDR(n.IPAM.Subnet); err == nil && sn.Contains(src) {
			return []string{id}, net.ParseIP(n.IPAM.Gateway)
		}
	}
	return nil, nil
}

// LookupName implements Registry.
func (m *Manager) LookupName(name string, networks []string) []net.IP {
	if name == "" || len(networks) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(networks))
	for _, id := range networks {
		want[id] = struct{}{}
	}
	name = strings.ToLower(name)

	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []net.IP
	for _, ep := range m.endpoints {
		if _, ok := want[ep.networkID]; !ok {
			continue
		}
		for _, n := range ep.names {
			if n == name {
				out = append(out, ep.ip)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// LookupAddr implements Registry.
func (m *Manager) LookupAddr(addr net.IP) string {
	if addr == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ep, ok := m.endpoints[addr.String()]; ok {
		if ep.containerName != "" {
			return strings.TrimPrefix(ep.containerName, "/")
		}
		if len(ep.names) > 0 {
			return ep.names[0]
		}
	}
	return ""
}

// ---------- sandbox files ----------

// ConfigureSandbox writes the container's /etc/hostname, /etc/hosts and
// /etc/resolv.conf into its state directory. The bundle bind-mounts them into
// the container, which is why they are ordinary files here rather than writes
// through the container's own rootfs — hull never resolves a path inside an
// attacker-controlled filesystem.
//
// resolv.conf points at the bridge gateway, where the embedded DNS server
// listens. --dns, --dns-search and --add-host are honoured, and the
// "host-gateway" magic value in --add-host resolves to the bridge gateway.
func (m *Manager) ConfigureSandbox(ctx context.Context, pid int, c *types.Container) error {
	if c == nil || c.ID == "" {
		return fmt.Errorf("%w: nil container", ErrInvalidConfig)
	}
	dir := filepath.Join(m.root, "containers", c.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("network: create %s: %w", dir, err)
	}

	hostname := c.Config.Hostname
	if hostname == "" {
		hostname = idutil.TruncateID(c.ID)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, "hostname"), []byte(hostname+"\n"), 0o644); err != nil {
		return fmt.Errorf("network: write hostname for %s: %w", idutil.TruncateID(c.ID), err)
	}

	gw, eps := m.sandboxView(c)
	hosts, err := m.renderHosts(hostname, eps, gw, c.HostConfig.ExtraHosts)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, "hosts"), hosts, 0o644); err != nil {
		return fmt.Errorf("network: write hosts for %s: %w", idutil.TruncateID(c.ID), err)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, "resolv.conf"), m.renderResolvConf(c, gw), 0o644); err != nil {
		return fmt.Errorf("network: write resolv.conf for %s: %w", idutil.TruncateID(c.ID), err)
	}

	if pid > 0 {
		c.NetworkSettings.SandboxKey = "/proc/" + strconv.Itoa(pid) + "/ns/net"
	}
	return nil
}

// sandboxView returns the container's gateway and its endpoints, preferring the
// manager's live table and falling back to the container record so the call
// works before Connect has run.
func (m *Manager) sandboxView(c *types.Container) (net.IP, []types.EndpointSettings) {
	var eps []types.EndpointSettings
	m.mu.RLock()
	for _, n := range m.nets {
		if ep, ok := n.Containers[c.ID]; ok {
			eps = append(eps, ep)
		}
	}
	m.mu.RUnlock()
	if len(eps) == 0 {
		for _, ep := range c.NetworkSettings.Networks {
			eps = append(eps, ep)
		}
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].IPAddress < eps[j].IPAddress })
	var gw net.IP
	for _, ep := range eps {
		if g := net.ParseIP(ep.Gateway); g != nil {
			gw = g
			break
		}
	}
	if gw == nil {
		m.mu.RLock()
		if n := m.findLocked(DefaultNetworkName); n != nil {
			gw = net.ParseIP(n.IPAM.Gateway)
		}
		m.mu.RUnlock()
	}
	return gw, eps
}

// renderHosts builds /etc/hosts.
func (m *Manager) renderHosts(hostname string, eps []types.EndpointSettings, gw net.IP, extra []string) ([]byte, error) {
	var b strings.Builder
	b.WriteString("127.0.0.1\tlocalhost\n")
	b.WriteString("::1\tlocalhost ip6-localhost ip6-loopback\n")
	b.WriteString("fe00::0\tip6-localnet\n")
	b.WriteString("ff00::0\tip6-mcastprefix\n")
	b.WriteString("ff02::1\tip6-allnodes\n")
	b.WriteString("ff02::2\tip6-allrouters\n")
	for _, ep := range eps {
		if ep.IPAddress == "" {
			continue
		}
		names := hostname
		for _, d := range ep.DNSNames {
			if d != hostname {
				names += " " + d
			}
		}
		fmt.Fprintf(&b, "%s\t%s\n", ep.IPAddress, names)
	}
	for _, e := range extra {
		host, addr, ok := strings.Cut(e, ":")
		if !ok {
			return nil, fmt.Errorf("%w: --add-host %q must be host:ip", ErrInvalidConfig, e)
		}
		host, addr = strings.TrimSpace(host), strings.TrimSpace(addr)
		if addr == "host-gateway" {
			if gw == nil {
				return nil, fmt.Errorf("%w: --add-host %s:host-gateway needs a bridge gateway, "+
					"but this container is not attached to a bridge network", ErrInvalidConfig, host)
			}
			addr = gw.String()
		}
		if net.ParseIP(addr) == nil {
			return nil, fmt.Errorf("%w: --add-host %q: %q is not an IP address", ErrInvalidConfig, e, addr)
		}
		fmt.Fprintf(&b, "%s\t%s\n", addr, host)
	}
	if gw != nil {
		fmt.Fprintf(&b, "%s\thost.%s gateway.%s host.docker.internal\n", gw, InternalDomain, InternalDomain)
	}
	return []byte(b.String()), nil
}

// renderResolvConf builds /etc/resolv.conf.
//
// resolv.conf has no syntax for a port, so when the embedded server is not on
// 53 the file still names the gateway and a comment records the real port: the
// alternative would be handing the container a nameserver line that silently
// does not work.
func (m *Manager) renderResolvConf(c *types.Container, gw net.IP) []byte {
	var b strings.Builder
	b.WriteString("# generated by hull\n")
	servers := c.HostConfig.DNS
	if len(servers) == 0 && gw != nil {
		servers = []string{gw.String()}
		if m.opts.DNSPort != DefaultDNSPort {
			fmt.Fprintf(&b, "# hull's embedded resolver listens on %s:%d\n", gw, m.opts.DNSPort)
		}
	}
	if len(servers) == 0 {
		servers = m.dns.Upstreams()
		for i, s := range servers {
			if host, _, err := net.SplitHostPort(s); err == nil {
				servers[i] = host
			}
		}
	}
	for _, s := range servers {
		fmt.Fprintf(&b, "nameserver %s\n", s)
	}
	search := c.HostConfig.DNSSearch
	if len(search) == 0 {
		search = m.opts.DNSSearch
	}
	if len(search) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(search, " "))
	}
	// ndots:0 makes a single-label lookup go out as-is, which is what lets
	// "web" resolve against hull's embedded server on the first try.
	b.WriteString("options ndots:0\n")
	return []byte(b.String())
}

// ---------- published ports ----------

// PublishPorts publishes a container's ports.
//
// Each binding gets both halves of the WSL-correct implementation: a real
// listening socket in the root network namespace, which is the only thing WSL's
// localhost relay can see, and an nftables DNAT rule with a matching hairpin
// masquerade for LAN-originated traffic.
//
// A HostPort of "" or "0" asks the kernel for a free port; the port actually
// bound is reported in the result.
func (m *Manager) PublishPorts(ctx context.Context, c *types.Container, bindings map[string][]types.PortBinding) ([]PublishedPort, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil container", ErrInvalidConfig)
	}
	containerIP, err := m.containerIP(c)
	if err != nil {
		return nil, err
	}

	specs := make([]string, 0, len(bindings))
	for k := range bindings {
		specs = append(specs, k)
	}
	sort.Strings(specs)

	var published []PublishedPort
	fail := func(err error) ([]PublishedPort, error) {
		for _, p := range published {
			_ = p.Close()
		}
		return nil, err
	}

	for _, spec := range specs {
		cPort, proto, err := ParsePortSpec(spec)
		if err != nil {
			return fail(err)
		}
		list := bindings[spec]
		if len(list) == 0 {
			list = []types.PortBinding{{}}
		}
		for _, b := range list {
			hostIP := strings.TrimSpace(b.HostIP)
			if hostIP == "" {
				hostIP = "0.0.0.0"
			}
			if net.ParseIP(hostIP) == nil {
				return fail(fmt.Errorf("%w: host ip %q in binding for %s", ErrInvalidConfig, b.HostIP, spec))
			}
			hostPort := 0
			if hp := strings.TrimSpace(b.HostPort); hp != "" && hp != "0" {
				hostPort, err = strconv.Atoi(hp)
				if err != nil || hostPort < 1 || hostPort > 65535 {
					return fail(fmt.Errorf("%w: host port %q in binding for %s", ErrInvalidConfig, b.HostPort, spec))
				}
			}
			bound, closer, err := startProxy(ctx, proto, hostIP, hostPort, containerIP, cPort)
			if err != nil {
				return fail(fmt.Errorf("network: publish %s for %s: %w", spec, idutil.TruncateID(c.ID), err))
			}
			published = append(published, PublishedPort{
				Proto:         proto,
				HostIP:        hostIP,
				HostPort:      bound,
				ContainerPort: cPort,
				ContainerIP:   containerIP,
				ContainerID:   c.ID,
				closer:        closer,
			})
		}
	}

	m.mu.Lock()
	m.ports[c.ID] = append(m.ports[c.ID], published...)
	m.mu.Unlock()

	if err := m.applyRules(ctx); err != nil {
		return fail(err)
	}
	return append([]PublishedPort(nil), published...), nil
}

// UnpublishPorts closes every proxy a container owns and drops its DNAT rules.
func (m *Manager) UnpublishPorts(ctx context.Context, containerID string) error {
	m.mu.Lock()
	list := m.ports[containerID]
	delete(m.ports, containerID)
	m.mu.Unlock()

	var errs []error
	for _, p := range list {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Errorf("network: close %s: %w", p, err))
		}
	}
	if err := m.applyRules(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// UsedPorts returns every published port, sorted, across all containers.
func (m *Manager) UsedPorts() []PublishedPort {
	m.mu.RLock()
	out := make([]PublishedPort, 0, len(m.ports))
	for _, list := range m.ports {
		out = append(out, list...)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].HostPort != out[j].HostPort {
			return out[i].HostPort < out[j].HostPort
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

// containerIP finds the address published traffic must be forwarded to.
func (m *Manager) containerIP(c *types.Container) (string, error) {
	m.mu.RLock()
	for _, n := range m.nets {
		if ep, ok := n.Containers[c.ID]; ok && ep.IPAddress != "" {
			m.mu.RUnlock()
			return ep.IPAddress, nil
		}
	}
	m.mu.RUnlock()
	for _, ep := range c.NetworkSettings.Networks {
		if ep.IPAddress != "" {
			return ep.IPAddress, nil
		}
	}
	return "", fmt.Errorf("%w: container %s has no address; attach it to a network before publishing ports",
		ErrNotFound, idutil.TruncateID(c.ID))
}

// ---------- firewall ----------

// ruleset builds the declarative firewall state from the manager's networks and
// published ports.
func (m *Manager) ruleset() Ruleset {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rs := Ruleset{Table: TableName}
	for _, n := range m.nets {
		if n.Driver != "" && n.Driver != "bridge" {
			continue
		}
		rs.Bridges = append(rs.Bridges, BridgeRule{
			Name:     n.BridgeName,
			Subnet:   n.IPAM.Subnet,
			Internal: n.Internal,
		})
	}
	for _, list := range m.ports {
		for _, p := range list {
			rs.DNAT = append(rs.DNAT, DNATRule{
				Proto:         p.Proto,
				HostIP:        p.HostIP,
				HostPort:      p.HostPort,
				ContainerIP:   p.ContainerIP,
				ContainerPort: p.ContainerPort,
			})
		}
	}
	return rs
}

// applyRules pushes the current ruleset into the kernel. The ruleset is built
// under the lock and applied outside it, so a slow nft invocation never blocks
// a DNS lookup.
func (m *Manager) applyRules(ctx context.Context) error {
	return m.fw.Apply(ctx, m.ruleset())
}

// ensureRules is the documented name for the firewall step; it is a thin alias
// over applyRules so callers and tests have one obvious entry point.
func (m *Manager) ensureRules(ctx context.Context) error { return m.applyRules(ctx) }
