//go:build linux

package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// requireRoot skips a test that needs CAP_NET_ADMIN.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

// newTestNetNS creates a fresh network namespace held open by a parked thread
// and returns its /proc path. The thread is never unlocked, so the Go runtime
// retires it when the holding goroutine exits rather than returning a thread in
// the wrong namespace to the pool.
func newTestNetNS(t *testing.T) string {
	t.Helper()
	type result struct {
		path string
		err  error
	}
	ready := make(chan result, 1)
	release := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ready <- result{err: err}
			return
		}
		ready <- result{path: fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())}
		<-release
	}()
	r := <-ready
	if r.err != nil {
		t.Fatalf("unshare netns: %v", r.err)
	}
	t.Cleanup(func() { close(release) })
	return r.path
}

// addrsIn reports the addresses assigned to an interface inside a namespace.
func addrsIn(t *testing.T, nsPath, ifname string) []string {
	t.Helper()
	var out []string
	err := withNetNS(nsPath, func() error {
		c, err := dialNetlink()
		if err != nil {
			return err
		}
		defer c.Close()
		idx, err := linkIndex(c, ifname)
		if err != nil {
			return err
		}
		msgs, err := c.execute(unix.RTM_GETADDR, unix.NLM_F_DUMP, ifAddrMsg(unix.AF_INET, 0, 0, 0))
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if len(m) < unix.SizeofIfAddrmsg || m[0] != unix.AF_INET {
				continue
			}
			if nativeEndian.Uint32(m[4:8]) != uint32(idx) {
				continue
			}
			attrs := parseAttrs(m[unix.SizeofIfAddrmsg:])
			raw, ok := attrs[unix.IFA_LOCAL]
			if !ok {
				raw, ok = attrs[unix.IFA_ADDRESS]
			}
			if !ok || len(raw) < 4 {
				continue
			}
			out = append(out, fmt.Sprintf("%s/%d", net.IP(raw[:4]), m[1]))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read addresses in %s: %v", nsPath, err)
	}
	return out
}

// defaultRouteIn reports the default gateway inside a namespace.
func defaultRouteIn(t *testing.T, nsPath string) string {
	t.Helper()
	var gw string
	err := withNetNS(nsPath, func() error {
		c, err := dialNetlink()
		if err != nil {
			return err
		}
		defer c.Close()
		msgs, err := c.execute(unix.RTM_GETROUTE, unix.NLM_F_DUMP,
			rtMsg(unix.AF_INET, 0, unix.RT_SCOPE_UNIVERSE))
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if len(m) < unix.SizeofRtMsg || m[0] != unix.AF_INET || m[1] != 0 {
				continue
			}
			attrs := parseAttrs(m[unix.SizeofRtMsg:])
			if raw, ok := attrs[unix.RTA_GATEWAY]; ok && len(raw) >= 4 {
				gw = net.IP(raw[:4]).String()
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read routes in %s: %v", nsPath, err)
	}
	return gw
}

func TestNetlinkBridgeVethAndNamespaceRoundTrip(t *testing.T) {
	requireRoot(t)
	ctx := context.Background()

	ops, err := newLinkOps()
	if err != nil {
		t.Fatalf("newLinkOps: %v", err)
	}
	defer ops.Close()

	const (
		bridge = "hulltestbr0"
		hostIf = "hulltestv0"
		peerIf = "hulltestp0"
	)
	// Clean up first in case an earlier run died half way.
	_ = ops.DeleteLink(ctx, hostIf)
	_ = ops.DeleteLink(ctx, bridge)
	t.Cleanup(func() {
		_ = ops.DeleteLink(ctx, hostIf)
		_ = ops.DeleteLink(ctx, bridge)
	})

	if err := ops.EnsureBridge(ctx, bridge, 1400); err != nil {
		t.Fatalf("EnsureBridge: %v", err)
	}
	exists, err := ops.LinkExists(ctx, bridge)
	if err != nil || !exists {
		t.Fatalf("LinkExists(%s) = %v, %v", bridge, exists, err)
	}
	if err := ops.EnsureBridge(ctx, bridge, 1400); err != nil {
		t.Fatalf("EnsureBridge must be idempotent: %v", err)
	}
	if mtu, err := ops.InterfaceMTU(ctx, bridge); err != nil || mtu != 1400 {
		t.Fatalf("InterfaceMTU = %d, %v; want 1400", mtu, err)
	}

	gw := &net.IPNet{IP: net.ParseIP("10.199.77.1"), Mask: net.CIDRMask(24, 32)}
	if err := ops.AddAddress(ctx, bridge, gw); err != nil {
		t.Fatalf("AddAddress: %v", err)
	}
	if err := ops.AddAddress(ctx, bridge, gw); err != nil {
		t.Fatalf("AddAddress must tolerate an address that is already there: %v", err)
	}
	if err := ops.SetUp(ctx, bridge); err != nil {
		t.Fatalf("SetUp: %v", err)
	}
	if ifi, err := net.InterfaceByName(bridge); err != nil {
		t.Fatalf("InterfaceByName: %v", err)
	} else if ifi.Flags&net.FlagUp == 0 {
		t.Fatal("bridge is not up")
	}

	if err := ops.CreateVeth(ctx, hostIf, peerIf, 1400); err != nil {
		t.Fatalf("CreateVeth: %v", err)
	}
	if err := ops.AttachToBridge(ctx, hostIf, bridge); err != nil {
		t.Fatalf("AttachToBridge: %v", err)
	}
	if err := ops.SetUp(ctx, hostIf); err != nil {
		t.Fatalf("SetUp veth: %v", err)
	}

	nsPath := newTestNetNS(t)
	if err := ops.MoveToNetNS(ctx, peerIf, 0, nsPath); err != nil {
		t.Fatalf("MoveToNetNS: %v", err)
	}
	if exists, err := ops.LinkExists(ctx, peerIf); err != nil || exists {
		t.Fatalf("the peer is still in the host namespace (%v, %v)", exists, err)
	}

	mac, err := net.ParseMAC("02:aa:bb:cc:dd:ee")
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	cfg := IfaceConfig{
		From:    peerIf,
		To:      "eth0",
		Addr:    &net.IPNet{IP: net.ParseIP("10.199.77.42"), Mask: net.CIDRMask(24, 32)},
		MAC:     mac,
		Gateway: net.ParseIP("10.199.77.1"),
		MTU:     1400,
	}
	if err := ops.ConfigureInNetNS(ctx, 0, nsPath, cfg); err != nil {
		t.Fatalf("ConfigureInNetNS: %v", err)
	}

	addrs := addrsIn(t, nsPath, "eth0")
	if len(addrs) != 1 || addrs[0] != "10.199.77.42/24" {
		t.Fatalf("addresses inside the namespace = %v, want [10.199.77.42/24]", addrs)
	}
	if gw := defaultRouteIn(t, nsPath); gw != "10.199.77.1" {
		t.Fatalf("default route inside the namespace = %q, want 10.199.77.1", gw)
	}

	// Deleting the host side must take the peer with it.
	if err := ops.DeleteLink(ctx, hostIf); err != nil {
		t.Fatalf("DeleteLink: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := withNetNS(nsPath, func() error {
			c, err := dialNetlink()
			if err != nil {
				return err
			}
			defer c.Close()
			_, err = linkIndex(c, "eth0")
			return err
		}); err != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := ops.DeleteLink(ctx, bridge); err != nil {
		t.Fatalf("DeleteLink bridge: %v", err)
	}
	if err := ops.DeleteLink(ctx, bridge); err != nil {
		t.Fatalf("deleting a missing link must be a no-op: %v", err)
	}
	if exists, err := ops.LinkExists(ctx, bridge); err != nil || exists {
		t.Fatalf("bridge survived teardown (%v, %v)", exists, err)
	}
}

func TestNetlinkHostReservationsAndUplink(t *testing.T) {
	requireRoot(t)
	ctx := context.Background()
	ops, err := newLinkOps()
	if err != nil {
		t.Fatalf("newLinkOps: %v", err)
	}
	defer ops.Close()

	res, err := ops.HostReservations(ctx)
	if err != nil {
		t.Fatalf("HostReservations: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("a WSL host always has at least the eth0 route")
	}
	for _, r := range res {
		if r.Subnet == nil || r.Reason == "" {
			t.Fatalf("reservation is not usable in an error message: %+v", r)
		}
	}

	up, err := ops.UplinkName(ctx)
	if err != nil {
		t.Fatalf("UplinkName: %v", err)
	}
	if _, err := net.InterfaceByName(up); err != nil {
		t.Fatalf("UplinkName returned %q, which is not an interface: %v", up, err)
	}
	mtu, err := ops.InterfaceMTU(ctx, up)
	if err != nil || mtu <= 0 {
		t.Fatalf("InterfaceMTU(%s) = %d, %v", up, mtu, err)
	}
}

func TestNetlinkEnableForwarding(t *testing.T) {
	requireRoot(t)
	ops, err := newLinkOps()
	if err != nil {
		t.Fatalf("newLinkOps: %v", err)
	}
	defer ops.Close()
	if err := ops.EnableForwarding(context.Background(), false); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		t.Fatalf("read ip_forward: %v", err)
	}
	if len(b) == 0 || b[0] != '1' {
		t.Fatalf("ip_forward = %q", b)
	}
}

func TestWithNetNSRestoresTheThread(t *testing.T) {
	requireRoot(t)
	nsPath := newTestNetNS(t)

	before, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	var inside string
	if err := withNetNS(nsPath, func() error {
		var err error
		inside, err = os.Readlink("/proc/thread-self/ns/net")
		return err
	}); err != nil {
		t.Fatalf("withNetNS: %v", err)
	}
	if inside == before {
		t.Fatalf("withNetNS did not enter a different namespace (%s)", inside)
	}
	after, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if after != before {
		t.Fatalf("the calling thread's namespace changed: %s -> %s", before, after)
	}
}

func TestWithNetNSPropagatesErrors(t *testing.T) {
	requireRoot(t)
	nsPath := newTestNetNS(t)
	wantErr := fmt.Errorf("boom")
	if err := withNetNS(nsPath, func() error { return wantErr }); err != wantErr {
		t.Fatalf("withNetNS swallowed the callback error: %v", err)
	}
	if err := withNetNS("/proc/self/ns/nonexistent", func() error { return nil }); err == nil {
		t.Fatal("entering a missing namespace must fail")
	}
}

func TestParseNetlinkMessagesRejectsTruncation(t *testing.T) {
	// A header claiming more bytes than the datagram holds.
	buf := make([]byte, unix.SizeofNlMsghdr)
	nativeEndian.PutUint32(buf[0:4], 1<<20)
	if _, err := parseNetlinkMessages(buf); err == nil {
		t.Fatal("expected an error for an over-long netlink message")
	}
	// A well-formed ACK.
	ack := make([]byte, unix.SizeofNlMsghdr+4)
	nativeEndian.PutUint32(ack[0:4], uint32(len(ack)))
	nativeEndian.PutUint16(ack[4:6], unix.NLMSG_ERROR)
	nativeEndian.PutUint32(ack[8:12], 7)
	msgs, err := parseNetlinkMessages(ack)
	if err != nil {
		t.Fatalf("parseNetlinkMessages: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Type != unix.NLMSG_ERROR || msgs[0].Seq != 7 {
		t.Fatalf("parsed = %+v", msgs)
	}
}

func TestAttrBufNesting(t *testing.T) {
	var a attrBuf
	top := a.begin(unix.IFLA_LINKINFO)
	a.putString(unix.IFLA_INFO_KIND, "veth")
	inner := a.begin(unix.IFLA_INFO_DATA)
	peer := a.begin(vethInfoPeer)
	a.b = append(a.b, ifInfoMsg(0, 0, 0)...)
	a.putString(unix.IFLA_IFNAME, "hp-abc")
	a.end(peer)
	a.end(inner)
	a.end(top)

	attrs := parseAttrs(a.bytes())
	li, ok := attrs[unix.IFLA_LINKINFO]
	if !ok {
		t.Fatal("IFLA_LINKINFO missing")
	}
	sub := parseAttrs(li)
	kind, ok := sub[unix.IFLA_INFO_KIND]
	if !ok || string(kind) != "veth\x00" {
		t.Fatalf("kind = %q", kind)
	}
	data, ok := sub[unix.IFLA_INFO_DATA]
	if !ok {
		t.Fatal("IFLA_INFO_DATA missing")
	}
	peerAttr, ok := parseAttrs(data)[vethInfoPeer]
	if !ok {
		t.Fatal("VETH_INFO_PEER missing")
	}
	name, ok := parseAttrs(peerAttr[unix.SizeofIfInfomsg:])[unix.IFLA_IFNAME]
	if !ok || string(name) != "hp-abc\x00" {
		t.Fatalf("peer name = %q", name)
	}
}
