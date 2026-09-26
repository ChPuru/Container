package network

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ChPuru/hull/internal/types"
)

// fakeLink is one interface in the fake kernel.
type fakeLink struct {
	mtu    int
	up     bool
	master string
	addrs  []string
	inNS   string
}

// fakeOps is an in-memory stand-in for the netlink backend, so the whole
// Manager can be exercised without root, a bridge or a namespace.
type fakeOps struct {
	mu           sync.Mutex
	links        map[string]*fakeLink
	configured   []IfaceConfig
	reservations []Reservation
	uplink       string
	uplinkMTU    int
	forwarding   bool
	closed       bool
	failCreate   error
}

func newFakeOps() *fakeOps {
	return &fakeOps{
		links:     map[string]*fakeLink{"eth0": {mtu: 1280, up: true}},
		uplink:    "eth0",
		uplinkMTU: 1280,
	}
}

func (f *fakeOps) EnsureBridge(ctx context.Context, name string, mtu int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l, ok := f.links[name]; ok {
		l.mtu = mtu
		return nil
	}
	f.links[name] = &fakeLink{mtu: mtu}
	return nil
}

func (f *fakeOps) DeleteLink(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.links, name)
	return nil
}

func (f *fakeOps) LinkExists(ctx context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.links[name]
	return ok, nil
}

func (f *fakeOps) InterfaceMTU(ctx context.Context, name string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.links[name]
	if !ok {
		return 0, ErrNotFound
	}
	return l.mtu, nil
}

func (f *fakeOps) AddAddress(ctx context.Context, link string, addr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.links[link]
	if !ok {
		return ErrNotFound
	}
	l.addrs = append(l.addrs, addr.String())
	return nil
}

func (f *fakeOps) SetUp(ctx context.Context, link string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.links[link]
	if !ok {
		return ErrNotFound
	}
	l.up = true
	return nil
}

func (f *fakeOps) CreateVeth(ctx context.Context, host, peer string, mtu int) error {
	if f.failCreate != nil {
		return f.failCreate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.links[host] = &fakeLink{mtu: mtu}
	f.links[peer] = &fakeLink{mtu: mtu}
	return nil
}

func (f *fakeOps) AttachToBridge(ctx context.Context, link, bridge string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.links[link]
	if !ok {
		return ErrNotFound
	}
	if _, ok := f.links[bridge]; !ok {
		return ErrNotFound
	}
	l.master = bridge
	return nil
}

func (f *fakeOps) MoveToNetNS(ctx context.Context, link string, pid int, nsPath string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.links[link]
	if !ok {
		return ErrNotFound
	}
	l.inNS = nsPath
	return nil
}

func (f *fakeOps) ConfigureInNetNS(ctx context.Context, pid int, nsPath string, cfg IfaceConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.links[cfg.From]
	if !ok {
		return ErrNotFound
	}
	delete(f.links, cfg.From)
	l.up = true
	if cfg.Addr != nil {
		l.addrs = append(l.addrs, cfg.Addr.String())
	}
	f.links[cfg.To+"@"+nsPath] = l
	f.configured = append(f.configured, cfg)
	return nil
}

func (f *fakeOps) HostReservations(ctx context.Context) ([]Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Reservation(nil), f.reservations...), nil
}

func (f *fakeOps) EnableForwarding(ctx context.Context, ipv6 bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forwarding = true
	return nil
}

func (f *fakeOps) UplinkName(ctx context.Context) (string, error) {
	if f.uplink == "" {
		return "", ErrNotFound
	}
	return f.uplink, nil
}

func (f *fakeOps) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeOps) link(name string) *fakeLink {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.links[name]
}

func (f *fakeOps) lastConfig() (IfaceConfig, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.configured) == 0 {
		return IfaceConfig{}, false
	}
	return f.configured[len(f.configured)-1], true
}

// newTestManager wires a Manager over fakes. The pool lives in 127.66/16 so
// every gateway the DNS server binds is a real local address on Linux, which
// keeps these tests root-free.
func newTestManager(t *testing.T, ops *fakeOps) (*Manager, *fakeRunner, string) {
	t.Helper()
	if ops == nil {
		ops = newFakeOps()
	}
	prev := newLinkOpsFn
	newLinkOpsFn = func() (linkOps, error) { return ops, nil }
	t.Cleanup(func() { newLinkOpsFn = prev })

	root := t.TempDir()
	m, err := New(root, ManagerOptions{
		DefaultPool:  "127.66.0.0/16",
		SubnetSize:   24,
		DNSPort:      freePort(t),
		DNSUpstreams: []string{"127.0.0.1:65"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newFakeRunner()
	m.fw.SetRunner(r)
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return m, r, root
}

// testContainer builds a minimal container record.
func testContainer(id, name string) *types.Container {
	return &types.Container{
		ID:     id,
		Name:   name,
		Pid:    4242,
		Config: types.ContainerConfig{Hostname: name},
	}
}

func TestManagerCreateBringsUpABridge(t *testing.T) {
	ops := newFakeOps()
	m, _, _ := newTestManager(t, ops)
	ctx := context.Background()

	n, err := m.Create(ctx, "frontend", CreateConfig{Subnet: "127.66.9.0/24"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n.IPAM.Gateway != "127.66.9.1" {
		t.Fatalf("gateway = %s, want the first usable address", n.IPAM.Gateway)
	}
	if !strings.HasPrefix(n.BridgeName, "hb-") {
		t.Fatalf("bridge name = %q", n.BridgeName)
	}
	l := ops.link(n.BridgeName)
	if l == nil {
		t.Fatal("bridge was not created")
	}
	if !l.up {
		t.Fatal("bridge was not brought up")
	}
	if len(l.addrs) != 1 || l.addrs[0] != "127.66.9.1/24" {
		t.Fatalf("bridge addresses = %v", l.addrs)
	}
	if l.mtu != ops.uplinkMTU {
		t.Fatalf("bridge MTU = %d, want the uplink's %d", l.mtu, ops.uplinkMTU)
	}
	if !m.ipam.HasPool(n.ID) {
		t.Fatal("no IPAM pool registered")
	}

	if _, err := m.Create(ctx, "frontend", CreateConfig{Subnet: "127.66.10.0/24"}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate name: want ErrExists, got %v", err)
	}
	if _, err := m.Create(ctx, "bad name", CreateConfig{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("bad name: want ErrInvalidConfig, got %v", err)
	}
	if _, err := m.Create(ctx, "overlaynet", CreateConfig{Driver: "overlay"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unsupported driver: want ErrInvalidConfig, got %v", err)
	}
}

func TestManagerCreateSkipsConflictingSubnets(t *testing.T) {
	ops := newFakeOps()
	ops.reservations = []Reservation{
		{Subnet: mustCIDR(t, "127.66.0.0/24"), Reason: "host route"},
		{Subnet: mustCIDR(t, "127.66.1.0/24"), Reason: "docker0"},
	}
	m, _, _ := newTestManager(t, ops)
	ctx := context.Background()

	n, err := m.Create(ctx, "auto", CreateConfig{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n.IPAM.Subnet != "127.66.2.0/24" {
		t.Fatalf("subnet = %s, want 127.66.2.0/24 (the first free block)", n.IPAM.Subnet)
	}

	// A second automatic network must skip the one just created too.
	n2, err := m.Create(ctx, "auto2", CreateConfig{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n2.IPAM.Subnet != "127.66.3.0/24" {
		t.Fatalf("second subnet = %s", n2.IPAM.Subnet)
	}

	// An explicit conflicting subnet must be named, not silently accepted.
	_, err = m.Create(ctx, "clash", CreateConfig{Subnet: "127.66.0.128/25"})
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConflictError, got %v", err)
	}
	if ce.Conflict != "127.66.0.0/24" || ce.Reason != "host route" {
		t.Fatalf("conflict not described: %+v", ce)
	}
}

func TestManagerConnectAndDisconnect(t *testing.T) {
	ops := newFakeOps()
	m, r, _ := newTestManager(t, ops)
	ctx := context.Background()

	n, err := m.Create(ctx, "frontend", CreateConfig{Subnet: "127.66.9.0/24"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	c := testContainer(strings.Repeat("a", 64), "web")

	ep, err := m.Connect(ctx, n.ID, c, EndpointConfig{Aliases: []string{"www"}})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if ep.IPAddress != "127.66.9.2" {
		t.Fatalf("address = %s, want the first allocatable address", ep.IPAddress)
	}
	if ep.Gateway != "127.66.9.1" || ep.IPPrefixLen != 24 {
		t.Fatalf("endpoint = %+v", ep)
	}
	if !strings.HasPrefix(ep.HostIfname, "hv-") || len(ep.HostIfname) != 9 {
		t.Fatalf("host ifname = %q, want hv-<6 hex>", ep.HostIfname)
	}
	mac, err := net.ParseMAC(ep.MacAddress)
	if err != nil {
		t.Fatalf("mac %q: %v", ep.MacAddress, err)
	}
	if mac[0]&0x02 == 0 || mac[0]&0x01 != 0 {
		t.Fatalf("mac %s is not a locally administered unicast address", mac)
	}
	// The MAC must not be the 02:42:<ip> trick.
	if mac[2] == 127 && mac[3] == 66 && mac[4] == 9 && mac[5] == 2 {
		t.Fatalf("mac %s appears to be derived from the IP", mac)
	}

	host := ops.link(ep.HostIfname)
	if host == nil || host.master != n.BridgeName || !host.up {
		t.Fatalf("host veth not enslaved and up: %+v", host)
	}
	cfg, ok := ops.lastConfig()
	if !ok {
		t.Fatal("container side was never configured")
	}
	if cfg.To != "eth0" || cfg.Gateway.String() != "127.66.9.1" || cfg.Addr.String() != "127.66.9.2/24" {
		t.Fatalf("container interface config = %+v", cfg)
	}
	if !strings.HasPrefix(cfg.From, "hp-") {
		t.Fatalf("the peer must be created under a temporary name, got %q", cfg.From)
	}

	// DNS now resolves the container on its own network.
	nets, gw := m.NetworksForSource(net.ParseIP("127.66.9.2"))
	if len(nets) != 1 || nets[0] != n.ID || gw.String() != "127.66.9.1" {
		t.Fatalf("NetworksForSource = %v, %v", nets, gw)
	}
	for _, name := range []string{"web", "web.frontend", "www", c.ID[:12], c.ID} {
		if ips := m.LookupName(name, nets); len(ips) != 1 || ips[0].String() != "127.66.9.2" {
			t.Fatalf("LookupName(%q) = %v", name, ips)
		}
	}
	if got := m.LookupAddr(net.ParseIP("127.66.9.2")); got != "web" {
		t.Fatalf("LookupAddr = %q", got)
	}

	// Attaching twice is refused.
	if _, err := m.Connect(ctx, n.ID, c, EndpointConfig{}); !errors.Is(err, ErrExists) {
		t.Fatalf("double attach: want ErrExists, got %v", err)
	}
	// So is removing a network that still has endpoints.
	if err := m.Remove(ctx, n.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("Remove with endpoints: want ErrInUse, got %v", err)
	}

	if err := m.Disconnect(ctx, n.ID, c.ID, false); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if ops.link(ep.HostIfname) != nil {
		t.Fatal("host veth was not deleted")
	}
	if ips := m.LookupName("web", nets); len(ips) != 0 {
		t.Fatalf("name still resolvable after disconnect: %v", ips)
	}
	if err := m.Disconnect(ctx, n.ID, c.ID, true); err != nil {
		t.Fatalf("forced Disconnect must be idempotent: %v", err)
	}

	if err := m.Remove(ctx, n.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if ops.link(n.BridgeName) != nil {
		t.Fatal("bridge was not deleted")
	}
	if m.ipam.HasPool(n.ID) {
		t.Fatal("IPAM pool was not removed")
	}
	if !r.sawPrefix("/usr/sbin/nft -f -") {
		t.Fatal("the firewall was never programmed")
	}
}

func TestManagerConnectHonoursARequestedAddress(t *testing.T) {
	m, _, _ := newTestManager(t, nil)
	ctx := context.Background()
	n, err := m.Create(ctx, "frontend", CreateConfig{Subnet: "127.66.9.0/24"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	c := testContainer(strings.Repeat("b", 64), "db")
	ep, err := m.Connect(ctx, n.ID, c, EndpointConfig{IPv4Address: "127.66.9.40"})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if ep.IPAddress != "127.66.9.40" {
		t.Fatalf("address = %s", ep.IPAddress)
	}
	// The restart case: disconnect and ask for it again.
	if err := m.Disconnect(ctx, n.ID, c.ID, false); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	ep, err = m.Connect(ctx, n.ID, c, EndpointConfig{IPv4Address: "127.66.9.40"})
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if ep.IPAddress != "127.66.9.40" {
		t.Fatalf("restarted container did not keep its address: %s", ep.IPAddress)
	}
}

func TestManagerConnectCleansUpOnFailure(t *testing.T) {
	ops := newFakeOps()
	m, _, _ := newTestManager(t, ops)
	ctx := context.Background()
	n, err := m.Create(ctx, "frontend", CreateConfig{Subnet: "127.66.9.0/24"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ops.failCreate = errors.New("simulated veth failure")
	c := testContainer(strings.Repeat("c", 64), "web")
	if _, err := m.Connect(ctx, n.ID, c, EndpointConfig{}); err == nil {
		t.Fatal("Connect should have failed")
	}
	ops.failCreate = nil
	// The address must have gone back to the pool, so the next attach reuses it.
	ep, err := m.Connect(ctx, n.ID, c, EndpointConfig{})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if ep.IPAddress != "127.66.9.2" {
		t.Fatalf("address %s: the failed attempt leaked an address", ep.IPAddress)
	}
}

func TestManagerPublishPorts(t *testing.T) {
	m, r, _ := newTestManager(t, nil)
	ctx := context.Background()
	n, err := m.Create(ctx, "frontend", CreateConfig{Subnet: "127.66.9.0/24"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	c := testContainer(strings.Repeat("d", 64), "web")
	if _, err := m.Connect(ctx, n.ID, c, EndpointConfig{}); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// 80/tcp binds every address, so it gets a DNAT rule for LAN traffic;
	// 53/udp binds loopback only, which is the userland proxy's job alone.
	ports, err := m.PublishPorts(ctx, c, map[string][]types.PortBinding{
		"80/tcp": {{HostPort: "0"}},
		"53/udp": {{HostIP: "127.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("PublishPorts: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("published %d ports, want 2", len(ports))
	}
	for _, p := range ports {
		if p.HostPort == 0 {
			t.Fatalf("%s: ephemeral host port was not resolved", p)
		}
		if p.ContainerIP != "127.66.9.2" {
			t.Fatalf("%s: forwards to %s", p, p.ContainerIP)
		}
		// The whole point: a real listening socket exists in the root netns.
		switch p.Proto {
		case "tcp":
			l, err := net.Listen("tcp", net.JoinHostPort(p.HostIP, itoa(p.HostPort)))
			if err == nil {
				l.Close()
				t.Fatalf("%s: nothing is actually listening, so WSL's localhost relay would never see it", p)
			}
		case "udp":
			pc, err := net.ListenPacket("udp", net.JoinHostPort(p.HostIP, itoa(p.HostPort)))
			if err == nil {
				pc.Close()
				t.Fatalf("%s: udp socket not bound", p)
			}
		}
	}
	if got := m.UsedPorts(); len(got) != 2 {
		t.Fatalf("UsedPorts = %v", got)
	}

	// The DNAT rules must have reached the firewall.
	r.mu.Lock()
	var last string
	for i, call := range r.calls {
		if strings.HasPrefix(call, "/usr/sbin/nft -f -") {
			last = r.stdins[i]
		}
	}
	r.mu.Unlock()
	if !strings.Contains(last, "dnat ip to 127.66.9.2:80") {
		t.Fatalf("tcp dnat rule missing from:\n%s", last)
	}
	if strings.Contains(last, "dnat ip to 127.66.9.2:53") {
		t.Fatalf("a loopback-only binding must not get a DNAT rule:\n%s", last)
	}
	if !strings.Contains(last, "ip saddr 127.66.9.2 ip daddr 127.66.9.2 tcp dport 80 masquerade") {
		t.Fatalf("hairpin masquerade missing from:\n%s", last)
	}

	tcpPort := 0
	for _, p := range ports {
		if p.Proto == "tcp" {
			tcpPort = p.HostPort
		}
	}
	if err := m.UnpublishPorts(ctx, c.ID); err != nil {
		t.Fatalf("UnpublishPorts: %v", err)
	}
	if got := m.UsedPorts(); len(got) != 0 {
		t.Fatalf("UsedPorts after unpublish = %v", got)
	}
	l, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", itoa(tcpPort)))
	if err != nil {
		t.Fatalf("host port %d was not released: %v", tcpPort, err)
	}
	l.Close()
}

func TestManagerPublishPortsRejectsBadInput(t *testing.T) {
	m, _, _ := newTestManager(t, nil)
	ctx := context.Background()
	n, err := m.Create(ctx, "frontend", CreateConfig{Subnet: "127.66.9.0/24"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	c := testContainer(strings.Repeat("e", 64), "web")

	if _, err := m.PublishPorts(ctx, c, map[string][]types.PortBinding{"80/tcp": nil}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("publishing for an unattached container: want ErrNotFound, got %v", err)
	}
	if _, err := m.Connect(ctx, n.ID, c, EndpointConfig{}); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	bad := []map[string][]types.PortBinding{
		{"80/icmp": {{HostIP: "127.0.0.1"}}},
		{"80/tcp": {{HostIP: "not-an-ip"}}},
		{"80/tcp": {{HostIP: "127.0.0.1", HostPort: "70000"}}},
	}
	for _, b := range bad {
		if _, err := m.PublishPorts(ctx, c, b); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%v: want ErrInvalidConfig, got %v", b, err)
		}
	}
	if got := m.UsedPorts(); len(got) != 0 {
		t.Fatalf("a failed publish left ports behind: %v", got)
	}
}

func TestManagerConfigureSandbox(t *testing.T) {
	m, _, root := newTestManager(t, nil)
	ctx := context.Background()
	n, err := m.Create(ctx, "frontend", CreateConfig{Subnet: "127.66.9.0/24"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	c := testContainer(strings.Repeat("f", 64), "web")
	c.HostConfig.ExtraHosts = []string{"registry.local:10.1.2.3", "windows:host-gateway"}
	c.HostConfig.DNSSearch = []string{"svc.local"}
	if _, err := m.Connect(ctx, n.ID, c, EndpointConfig{}); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := m.ConfigureSandbox(ctx, 4242, c); err != nil {
		t.Fatalf("ConfigureSandbox: %v", err)
	}

	dir := filepath.Join(root, "containers", c.ID)
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(b)
	}
	if got := read("hostname"); got != "web\n" {
		t.Fatalf("hostname = %q", got)
	}

	hosts := read("hosts")
	for _, want := range []string{
		"127.0.0.1\tlocalhost\n",
		"::1\tlocalhost ip6-localhost ip6-loopback\n",
		"127.66.9.2\tweb",
		"10.1.2.3\tregistry.local\n",
		"127.66.9.1\twindows\n", // host-gateway resolved to the bridge gateway
		"127.66.9.1\thost.hull.internal gateway.hull.internal host.docker.internal\n",
	} {
		if !strings.Contains(hosts, want) {
			t.Fatalf("hosts missing %q:\n%s", want, hosts)
		}
	}

	resolv := read("resolv.conf")
	if !strings.Contains(resolv, "nameserver 127.66.9.1\n") {
		t.Fatalf("resolv.conf must point at the bridge gateway:\n%s", resolv)
	}
	if !strings.Contains(resolv, "search svc.local\n") {
		t.Fatalf("--dns-search not honoured:\n%s", resolv)
	}
	if !strings.Contains(resolv, "options ndots:0\n") {
		t.Fatalf("ndots:0 missing, single-label lookups would not reach hull:\n%s", resolv)
	}
	if c.NetworkSettings.SandboxKey != "/proc/4242/ns/net" {
		t.Fatalf("sandbox key = %q", c.NetworkSettings.SandboxKey)
	}

	// --dns overrides the embedded resolver.
	c.HostConfig.DNS = []string{"9.9.9.9"}
	if err := m.ConfigureSandbox(ctx, 4242, c); err != nil {
		t.Fatalf("ConfigureSandbox: %v", err)
	}
	if got := read("resolv.conf"); !strings.Contains(got, "nameserver 9.9.9.9\n") ||
		strings.Contains(got, "nameserver 127.66.9.1") {
		t.Fatalf("--dns not honoured:\n%s", got)
	}
}

func TestManagerConfigureSandboxRejectsBadExtraHosts(t *testing.T) {
	m, _, _ := newTestManager(t, nil)
	ctx := context.Background()
	c := testContainer(strings.Repeat("9", 64), "web")
	c.HostConfig.ExtraHosts = []string{"missing-colon"}
	if err := m.ConfigureSandbox(ctx, 1, c); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
	c.HostConfig.ExtraHosts = []string{"host:not-an-ip"}
	if err := m.ConfigureSandbox(ctx, 1, c); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
	// host-gateway with no bridge attachment must say so instead of writing a
	// silently broken hosts file.
	c.HostConfig.ExtraHosts = []string{"windows:host-gateway"}
	if err := m.ConfigureSandbox(ctx, 1, c); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestManagerReattachesAfterRestart(t *testing.T) {
	ops := newFakeOps()
	prev := newLinkOpsFn
	newLinkOpsFn = func() (linkOps, error) { return ops, nil }
	defer func() { newLinkOpsFn = prev }()

	root := t.TempDir()
	port := freePort(t)
	opts := ManagerOptions{
		DefaultPool:  "127.66.0.0/16",
		SubnetSize:   24,
		DNSPort:      port,
		DNSUpstreams: []string{"127.0.0.1:65"},
	}

	m1, err := New(root, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m1.fw.SetRunner(newFakeRunner())
	ctx := context.Background()
	n, err := m1.Create(ctx, "frontend", CreateConfig{Subnet: "127.66.9.0/24"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	c := testContainer(strings.Repeat("1", 64), "web")
	ep, err := m1.Connect(ctx, n.ID, c, EndpointConfig{})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := m1.dns.Shutdown(ctx); err != nil {
		t.Fatalf("release the DNS sockets before restarting: %v", err)
	}

	m2, err := New(root, opts)
	if err != nil {
		t.Fatalf("New after restart: %v", err)
	}
	m2.fw.SetRunner(newFakeRunner())
	defer func() { _ = m2.Shutdown(context.Background()) }()

	got, err := m2.Get("frontend")
	if err != nil {
		t.Fatalf("network not reloaded: %v", err)
	}
	if got.IPAM.Subnet != "127.66.9.0/24" || got.BridgeName != n.BridgeName {
		t.Fatalf("reloaded network = %+v", got)
	}
	if len(got.Containers) != 1 {
		t.Fatalf("endpoints not reloaded: %+v", got.Containers)
	}
	nets, _ := m2.NetworksForSource(net.ParseIP(ep.IPAddress))
	if len(nets) != 1 {
		t.Fatalf("endpoint table not rebuilt: %v", nets)
	}
	if ips := m2.LookupName("web", nets); len(ips) != 1 || ips[0].String() != ep.IPAddress {
		t.Fatalf("DNS table not rebuilt: %v", ips)
	}

	if err := m2.Init(ctx); err != nil {
		t.Fatalf("Init after restart: %v", err)
	}
	if !ops.forwarding {
		t.Fatal("Init did not enable IP forwarding")
	}
	// Init must also materialise the default network.
	def, err := m2.Get(DefaultNetworkName)
	if err != nil {
		t.Fatalf("default network missing after Init: %v", err)
	}
	if def.BridgeName != DefaultBridgeName {
		t.Fatalf("default bridge = %q, want %q", def.BridgeName, DefaultBridgeName)
	}
	if l := ops.link(DefaultBridgeName); l == nil || !l.up {
		t.Fatalf("default bridge not up: %+v", l)
	}
	// The existing container's address must survive: IPAM must not re-issue it.
	c2 := testContainer(strings.Repeat("2", 64), "other")
	ep2, err := m2.Connect(ctx, n.ID, c2, EndpointConfig{})
	if err != nil {
		t.Fatalf("Connect after restart: %v", err)
	}
	if ep2.IPAddress == ep.IPAddress {
		t.Fatalf("restart re-issued a live address %s", ep.IPAddress)
	}

	if err := m2.Remove(ctx, DefaultNetworkName); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("the default network must be undeletable, got %v", err)
	}
}

func TestManagerListAndGet(t *testing.T) {
	m, _, _ := newTestManager(t, nil)
	ctx := context.Background()
	a, err := m.Create(ctx, "alpha", CreateConfig{Subnet: "127.66.1.0/24"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.Create(ctx, "beta", CreateConfig{Subnet: "127.66.2.0/24"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	list := m.List()
	if len(list) != 2 || list[0].Name != "alpha" || list[1].Name != "beta" {
		t.Fatalf("List = %v", list)
	}
	for _, key := range []string{a.ID, a.ID[:8], "alpha"} {
		got, err := m.Get(key)
		if err != nil {
			t.Fatalf("Get(%q): %v", key, err)
		}
		if got.ID != a.ID {
			t.Fatalf("Get(%q) returned %s", key, got.ID)
		}
	}
	if _, err := m.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := m.Inspect("alpha"); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	// The returned value must be a copy.
	got, _ := m.Get("alpha")
	got.Name = "mutated"
	again, _ := m.Get(a.ID)
	if again.Name != "alpha" {
		t.Fatal("Get returned a reference into manager state")
	}
}

func TestManagerRulesetReflectsState(t *testing.T) {
	m, _, _ := newTestManager(t, nil)
	ctx := context.Background()
	pub, err := m.Create(ctx, "pub", CreateConfig{Subnet: "127.66.1.0/24"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.Create(ctx, "priv", CreateConfig{Subnet: "127.66.2.0/24", Internal: true}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rs := m.ruleset()
	if len(rs.Bridges) != 2 {
		t.Fatalf("bridges = %+v", rs.Bridges)
	}
	script := rs.Script()
	if !strings.Contains(script, "ip saddr 127.66.1.0/24") {
		t.Fatalf("public network is not masqueraded:\n%s", script)
	}
	if strings.Contains(script, "ip saddr 127.66.2.0/24 oifname") {
		t.Fatalf("internal network must not masquerade:\n%s", script)
	}
	// Isolation between the two bridges.
	if !strings.Contains(script, `iifname "`+pub.BridgeName+`" oifname { "`) {
		t.Fatalf("cross-bridge isolation missing:\n%s", script)
	}
	if err := m.ensureRules(ctx); err != nil {
		t.Fatalf("ensureRules: %v", err)
	}
}

func TestNewRejectsBadRoot(t *testing.T) {
	ops := newFakeOps()
	prev := newLinkOpsFn
	newLinkOpsFn = func() (linkOps, error) { return ops, nil }
	defer func() { newLinkOpsFn = prev }()

	if _, err := New("", ManagerOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
	if _, err := New(t.TempDir(), ManagerOptions{DefaultPool: "nonsense"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestDefaultManagerOptions(t *testing.T) {
	o := DefaultManagerOptions()
	if o.DefaultPool != DefaultPool || o.SubnetSize != DefaultSubnetSize || o.DNSPort != DefaultDNSPort {
		t.Fatalf("defaults = %+v", o)
	}
	if o.IPTablesCompat == nil || !*o.IPTablesCompat {
		t.Fatal("the iptables compatibility shim must default to on")
	}
}
