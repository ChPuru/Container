//go:build linux

package network

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// vethInfoPeer is VETH_INFO_PEER from linux/veth.h. It is the only netlink
// constant hull needs that x/sys/unix does not export.
const vethInfoPeer = 1

// netlinkRecvBuf is the receive buffer for one netlink datagram. Dumps arrive
// as several datagrams, so this bounds one message, not one dump.
const netlinkRecvBuf = 1 << 16

// nativeEndian is the byte order netlink uses: the host's.
var nativeEndian = func() binary.ByteOrder {
	var x uint16 = 1
	if *(*byte)(unsafe.Pointer(&x)) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}()

// nlConn is one NETLINK_ROUTE socket. It belongs to whichever network namespace
// the creating thread was in, which is what makes ConfigureInNetNS work: the
// socket is opened after setns, so it talks to the container's namespace.
type nlConn struct {
	fd  int
	seq uint32
}

// dialNetlink opens a NETLINK_ROUTE socket in the caller's current namespace.
func dialNetlink() (*nlConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("network: open netlink socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20); err != nil {
		// Not fatal: a smaller buffer only means more datagrams per dump.
		_ = err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("network: bind netlink socket: %w", err)
	}
	return &nlConn{fd: fd}, nil
}

// Close releases the socket.
func (c *nlConn) Close() error {
	if c == nil || c.fd < 0 {
		return nil
	}
	err := unix.Close(c.fd)
	c.fd = -1
	return err
}

// execute sends one request and collects the reply. NLMSG_ERROR with a zero
// errno is the ACK that terminates a non-dump request; NLMSG_DONE terminates a
// dump.
func (c *nlConn) execute(msgType uint16, flags uint16, body []byte) ([][]byte, error) {
	c.seq++
	seq := c.seq
	total := unix.SizeofNlMsghdr + len(body)
	req := make([]byte, unix.SizeofNlMsghdr, total)
	nativeEndian.PutUint32(req[0:4], uint32(total))
	nativeEndian.PutUint16(req[4:6], msgType)
	nativeEndian.PutUint16(req[6:8], flags|unix.NLM_F_REQUEST)
	nativeEndian.PutUint32(req[8:12], seq)
	nativeEndian.PutUint32(req[12:16], 0)
	req = append(req, body...)

	if err := unix.Sendto(c.fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("network: send netlink message type %d: %w", msgType, err)
	}

	var out [][]byte
	buf := make([]byte, netlinkRecvBuf)
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, fmt.Errorf("network: receive netlink reply: %w", err)
		}
		msgs, err := parseNetlinkMessages(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Seq != seq {
				continue
			}
			switch m.Type {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return nil, errors.New("network: truncated netlink error")
				}
				errno := int32(nativeEndian.Uint32(m.Data[0:4]))
				if errno == 0 {
					return out, nil
				}
				return nil, unix.Errno(-errno)
			default:
				out = append(out, append([]byte(nil), m.Data...))
				if m.Flags&unix.NLM_F_MULTI == 0 {
					return out, nil
				}
			}
		}
	}
}

// nlMessage is one netlink message split out of a received datagram.
type nlMessage struct {
	// Type is the nlmsghdr message type.
	Type uint16
	// Flags is the nlmsghdr flag word.
	Flags uint16
	// Seq is the sequence number the request carried.
	Seq uint32
	// Data is the payload after the header.
	Data []byte
}

// parseNetlinkMessages splits a received datagram into messages. x/sys/unix has
// no equivalent, and the stdlib syscall package's version is deprecated, so
// hull walks the headers itself with explicit bounds checks.
func parseNetlinkMessages(b []byte) ([]nlMessage, error) {
	var out []nlMessage
	for len(b) >= unix.SizeofNlMsghdr {
		l := int(nativeEndian.Uint32(b[0:4]))
		if l < unix.SizeofNlMsghdr || l > len(b) {
			return nil, fmt.Errorf("network: netlink message claims %d bytes of %d available", l, len(b))
		}
		out = append(out, nlMessage{
			Type:  nativeEndian.Uint16(b[4:6]),
			Flags: nativeEndian.Uint16(b[6:8]),
			Seq:   nativeEndian.Uint32(b[8:12]),
			Data:  b[unix.SizeofNlMsghdr:l],
		})
		adv := (l + 3) &^ 3
		if adv >= len(b) {
			break
		}
		b = b[adv:]
	}
	return out, nil
}

// ---------- attribute encoding ----------

// attrBuf builds a netlink attribute stream with the 4-byte alignment the
// kernel requires.
type attrBuf struct{ b []byte }

// put appends one attribute with raw payload.
func (a *attrBuf) put(typ uint16, data []byte) {
	hdr := [4]byte{}
	nativeEndian.PutUint16(hdr[0:2], uint16(unix.SizeofRtAttr+len(data)))
	nativeEndian.PutUint16(hdr[2:4], typ)
	a.b = append(a.b, hdr[:]...)
	a.b = append(a.b, data...)
	for len(a.b)%4 != 0 {
		a.b = append(a.b, 0)
	}
}

// putString appends a NUL-terminated string attribute.
func (a *attrBuf) putString(typ uint16, s string) { a.put(typ, append([]byte(s), 0)) }

// putU32 appends a 32-bit attribute in host byte order.
func (a *attrBuf) putU32(typ uint16, v uint32) {
	var b [4]byte
	nativeEndian.PutUint32(b[:], v)
	a.put(typ, b[:])
}

// begin opens a nested attribute and returns the offset to close later.
func (a *attrBuf) begin(typ uint16) int {
	idx := len(a.b)
	a.b = append(a.b, 0, 0, 0, 0)
	nativeEndian.PutUint16(a.b[idx+2:idx+4], typ)
	return idx
}

// end closes the nested attribute opened at idx.
func (a *attrBuf) end(idx int) {
	nativeEndian.PutUint16(a.b[idx:idx+2], uint16(len(a.b)-idx))
}

// bytes returns the encoded attributes.
func (a *attrBuf) bytes() []byte { return a.b }

// parseAttrs splits an attribute stream into a type-indexed map. Malformed
// input stops the walk rather than panicking.
func parseAttrs(b []byte) map[uint16][]byte {
	out := make(map[uint16][]byte, 8)
	for len(b) >= unix.SizeofRtAttr {
		l := int(nativeEndian.Uint16(b[0:2]))
		t := nativeEndian.Uint16(b[2:4])
		if l < unix.SizeofRtAttr || l > len(b) {
			break
		}
		out[t] = b[unix.SizeofRtAttr:l]
		adv := (l + 3) &^ 3
		if adv >= len(b) {
			break
		}
		b = b[adv:]
	}
	return out
}

// ifInfoMsg builds a struct ifinfomsg.
func ifInfoMsg(index int32, flags, change uint32) []byte {
	b := make([]byte, unix.SizeofIfInfomsg)
	b[0] = unix.AF_UNSPEC
	nativeEndian.PutUint32(b[4:8], uint32(index))
	nativeEndian.PutUint32(b[8:12], flags)
	nativeEndian.PutUint32(b[12:16], change)
	return b
}

// ifAddrMsg builds a struct ifaddrmsg.
func ifAddrMsg(family uint8, prefixLen uint8, scope uint8, index uint32) []byte {
	b := make([]byte, unix.SizeofIfAddrmsg)
	b[0] = family
	b[1] = prefixLen
	b[2] = 0 // flags
	b[3] = scope
	nativeEndian.PutUint32(b[4:8], index)
	return b
}

// rtMsg builds a struct rtmsg for a unicast route in the main table.
func rtMsg(family uint8, dstLen uint8, scope uint8) []byte {
	b := make([]byte, unix.SizeofRtMsg)
	b[0] = family
	b[1] = dstLen
	b[2] = 0 // src_len
	b[3] = 0 // tos
	b[4] = unix.RT_TABLE_MAIN
	b[5] = unix.RTPROT_BOOT
	b[6] = scope
	b[7] = unix.RTN_UNICAST
	return b
}

// ---------- link operations ----------

// linuxLinkOps is the netlink-backed linkOps.
type linuxLinkOps struct {
	mu   sync.Mutex
	conn *nlConn
}

// newLinkOps opens the host-namespace netlink socket hull uses for every link,
// address and route operation.
func newLinkOps() (linkOps, error) {
	c, err := dialNetlink()
	if err != nil {
		return nil, err
	}
	return &linuxLinkOps{conn: c}, nil
}

// Close releases the netlink socket.
func (o *linuxLinkOps) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.conn.Close()
}

// do runs one request on the shared host socket under the mutex.
func (o *linuxLinkOps) do(msgType uint16, flags uint16, body []byte) ([][]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.conn.execute(msgType, flags, body)
}

// linkIndex resolves an interface name to its index on the given connection.
func linkIndex(c *nlConn, name string) (int32, error) {
	var a attrBuf
	a.putString(unix.IFLA_IFNAME, name)
	body := append(ifInfoMsg(0, 0, 0), a.bytes()...)
	msgs, err := c.execute(unix.RTM_GETLINK, unix.NLM_F_ACK, body)
	if err != nil {
		if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
			return 0, fmt.Errorf("%w: interface %s", ErrNotFound, name)
		}
		return 0, fmt.Errorf("network: look up interface %s: %w", name, err)
	}
	if len(msgs) == 0 || len(msgs[0]) < unix.SizeofIfInfomsg {
		return 0, fmt.Errorf("%w: interface %s", ErrNotFound, name)
	}
	return int32(nativeEndian.Uint32(msgs[0][4:8])), nil
}

// linkAttrs returns the attributes of one interface.
func linkAttrs(c *nlConn, name string) (map[uint16][]byte, error) {
	var a attrBuf
	a.putString(unix.IFLA_IFNAME, name)
	body := append(ifInfoMsg(0, 0, 0), a.bytes()...)
	msgs, err := c.execute(unix.RTM_GETLINK, unix.NLM_F_ACK, body)
	if err != nil {
		if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("%w: interface %s", ErrNotFound, name)
		}
		return nil, fmt.Errorf("network: look up interface %s: %w", name, err)
	}
	if len(msgs) == 0 || len(msgs[0]) < unix.SizeofIfInfomsg {
		return nil, fmt.Errorf("%w: interface %s", ErrNotFound, name)
	}
	return parseAttrs(msgs[0][unix.SizeofIfInfomsg:]), nil
}

// LinkExists reports whether an interface is present.
func (o *linuxLinkOps) LinkExists(ctx context.Context, name string) (bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, err := linkIndex(o.conn, name)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

// InterfaceMTU returns an interface's MTU.
func (o *linuxLinkOps) InterfaceMTU(ctx context.Context, name string) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	attrs, err := linkAttrs(o.conn, name)
	if err != nil {
		return 0, err
	}
	raw, ok := attrs[unix.IFLA_MTU]
	if !ok || len(raw) < 4 {
		return 0, fmt.Errorf("network: interface %s reported no MTU", name)
	}
	return int(nativeEndian.Uint32(raw)), nil
}

// EnsureBridge creates the bridge if needed and aligns its MTU.
func (o *linuxLinkOps) EnsureBridge(ctx context.Context, name string, mtu int) error {
	exists, err := o.LinkExists(ctx, name)
	if err != nil {
		return err
	}
	if exists {
		if mtu > 0 {
			if cur, err := o.InterfaceMTU(ctx, name); err == nil && cur != mtu {
				if err := o.setMTU(name, mtu); err != nil {
					return err
				}
			}
		}
		return nil
	}
	var a attrBuf
	a.putString(unix.IFLA_IFNAME, name)
	if mtu > 0 {
		a.putU32(unix.IFLA_MTU, uint32(mtu))
	}
	li := a.begin(unix.IFLA_LINKINFO)
	a.putString(unix.IFLA_INFO_KIND, "bridge")
	a.end(li)

	body := append(ifInfoMsg(0, 0, 0), a.bytes()...)
	flags := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK)
	if _, err := o.do(unix.RTM_NEWLINK, flags, body); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return fmt.Errorf("network: create bridge %s: %w", name, err)
	}
	return nil
}

// CreateVeth creates a veth pair with both ends still in the host namespace.
func (o *linuxLinkOps) CreateVeth(ctx context.Context, host, peer string, mtu int) error {
	var a attrBuf
	a.putString(unix.IFLA_IFNAME, host)
	if mtu > 0 {
		a.putU32(unix.IFLA_MTU, uint32(mtu))
	}
	li := a.begin(unix.IFLA_LINKINFO)
	a.putString(unix.IFLA_INFO_KIND, "veth")
	data := a.begin(unix.IFLA_INFO_DATA)
	peerIdx := a.begin(vethInfoPeer)
	a.b = append(a.b, ifInfoMsg(0, 0, 0)...)
	a.putString(unix.IFLA_IFNAME, peer)
	if mtu > 0 {
		a.putU32(unix.IFLA_MTU, uint32(mtu))
	}
	a.end(peerIdx)
	a.end(data)
	a.end(li)

	body := append(ifInfoMsg(0, 0, 0), a.bytes()...)
	flags := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK)
	if _, err := o.do(unix.RTM_NEWLINK, flags, body); err != nil {
		return fmt.Errorf("network: create veth %s<->%s: %w", host, peer, err)
	}
	return nil
}

// DeleteLink removes an interface; a missing interface is not an error.
func (o *linuxLinkOps) DeleteLink(ctx context.Context, name string) error {
	o.mu.Lock()
	idx, err := linkIndex(o.conn, name)
	o.mu.Unlock()
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	if _, err := o.do(unix.RTM_DELLINK, unix.NLM_F_ACK, ifInfoMsg(idx, 0, 0)); err != nil {
		if errors.Is(err, unix.ENODEV) {
			return nil
		}
		return fmt.Errorf("network: delete interface %s: %w", name, err)
	}
	return nil
}

// SetUp brings an interface up.
func (o *linuxLinkOps) SetUp(ctx context.Context, link string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return setUpOn(o.conn, link)
}

// setUpOn brings an interface up on a specific netlink connection.
func setUpOn(c *nlConn, link string) error {
	idx, err := linkIndex(c, link)
	if err != nil {
		return err
	}
	body := ifInfoMsg(idx, unix.IFF_UP, unix.IFF_UP)
	if _, err := c.execute(unix.RTM_SETLINK, unix.NLM_F_ACK, body); err != nil {
		return fmt.Errorf("network: bring %s up: %w", link, err)
	}
	return nil
}

// setMTU changes an interface's MTU on the host socket.
func (o *linuxLinkOps) setMTU(link string, mtu int) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return setMTUOn(o.conn, link, mtu)
}

// setMTUOn changes an interface's MTU on a specific connection.
func setMTUOn(c *nlConn, link string, mtu int) error {
	idx, err := linkIndex(c, link)
	if err != nil {
		return err
	}
	var a attrBuf
	a.putU32(unix.IFLA_MTU, uint32(mtu))
	body := append(ifInfoMsg(idx, 0, 0), a.bytes()...)
	if _, err := c.execute(unix.RTM_SETLINK, unix.NLM_F_ACK, body); err != nil {
		return fmt.Errorf("network: set MTU %d on %s: %w", mtu, link, err)
	}
	return nil
}

// AttachToBridge enslaves an interface to a bridge.
func (o *linuxLinkOps) AttachToBridge(ctx context.Context, link, bridge string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	idx, err := linkIndex(o.conn, link)
	if err != nil {
		return err
	}
	bidx, err := linkIndex(o.conn, bridge)
	if err != nil {
		return err
	}
	var a attrBuf
	a.putU32(unix.IFLA_MASTER, uint32(bidx))
	body := append(ifInfoMsg(idx, 0, 0), a.bytes()...)
	if _, err := o.conn.execute(unix.RTM_SETLINK, unix.NLM_F_ACK, body); err != nil {
		return fmt.Errorf("network: attach %s to bridge %s: %w", link, bridge, err)
	}
	return nil
}

// MoveToNetNS moves an interface into another network namespace. A namespace
// path is preferred over a pid because the path is stable: a pid can be reused
// between the lookup and the syscall.
func (o *linuxLinkOps) MoveToNetNS(ctx context.Context, link string, pid int, nsPath string) error {
	if nsPath == "" && pid <= 0 {
		return fmt.Errorf("%w: moving %s needs a namespace path or a pid", ErrInvalidConfig, link)
	}
	var a attrBuf
	if nsPath != "" {
		f, err := os.Open(nsPath)
		if err != nil {
			return fmt.Errorf("network: open netns %s: %w", nsPath, err)
		}
		defer f.Close()
		a.putU32(unix.IFLA_NET_NS_FD, uint32(f.Fd()))
	} else {
		a.putU32(unix.IFLA_NET_NS_PID, uint32(pid))
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	idx, err := linkIndex(o.conn, link)
	if err != nil {
		return err
	}
	body := append(ifInfoMsg(idx, 0, 0), a.bytes()...)
	if _, err := o.conn.execute(unix.RTM_SETLINK, unix.NLM_F_ACK, body); err != nil {
		return fmt.Errorf("network: move %s into the container namespace: %w", link, err)
	}
	return nil
}

// AddAddress assigns an address to an interface on the host socket.
func (o *linuxLinkOps) AddAddress(ctx context.Context, link string, addr *net.IPNet) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return addAddressOn(o.conn, link, addr)
}

// addAddressOn assigns an address on a specific connection. EEXIST is success:
// re-attaching to an existing bridge must not fail.
func addAddressOn(c *nlConn, link string, addr *net.IPNet) error {
	if addr == nil || addr.IP == nil {
		return fmt.Errorf("%w: nil address for %s", ErrInvalidConfig, link)
	}
	idx, err := linkIndex(c, link)
	if err != nil {
		return err
	}
	ones, _ := addr.Mask.Size()
	var family uint8 = unix.AF_INET
	ip := addr.IP.To4()
	if ip == nil {
		family = unix.AF_INET6
		ip = addr.IP.To16()
		if ip == nil {
			return fmt.Errorf("%w: %s is not an IP address", ErrInvalidConfig, addr.IP)
		}
	}
	var a attrBuf
	a.put(unix.IFA_LOCAL, ip)
	a.put(unix.IFA_ADDRESS, ip)
	if family == unix.AF_INET {
		if b := LastAddr(addr); b != nil {
			a.put(unix.IFA_BROADCAST, b.To4())
		}
	}
	body := append(ifAddrMsg(family, uint8(ones), unix.RT_SCOPE_UNIVERSE, uint32(idx)), a.bytes()...)
	flags := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK)
	if _, err := c.execute(unix.RTM_NEWADDR, flags, body); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return fmt.Errorf("network: add address %s to %s: %w", addr, link, err)
	}
	return nil
}

// addDefaultRouteOn installs a default route via gw out of link.
func addDefaultRouteOn(c *nlConn, link string, gw net.IP) error {
	idx, err := linkIndex(c, link)
	if err != nil {
		return err
	}
	v4 := gw.To4()
	if v4 == nil {
		return fmt.Errorf("%w: gateway %s is not IPv4", ErrInvalidConfig, gw)
	}
	var a attrBuf
	a.put(unix.RTA_GATEWAY, v4)
	a.putU32(unix.RTA_OIF, uint32(idx))
	body := append(rtMsg(unix.AF_INET, 0, unix.RT_SCOPE_UNIVERSE), a.bytes()...)
	flags := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK)
	if _, err := c.execute(unix.RTM_NEWROUTE, flags, body); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return fmt.Errorf("network: add default route via %s: %w", gw, err)
	}
	return nil
}

// renameOn renames an interface. The kernel only allows this while the
// interface is down, which is always true for a peer just moved into a fresh
// namespace.
func renameOn(c *nlConn, from, to string) error {
	if from == to {
		return nil
	}
	idx, err := linkIndex(c, from)
	if err != nil {
		return err
	}
	var a attrBuf
	a.putString(unix.IFLA_IFNAME, to)
	body := append(ifInfoMsg(idx, 0, 0), a.bytes()...)
	if _, err := c.execute(unix.RTM_SETLINK, unix.NLM_F_ACK, body); err != nil {
		return fmt.Errorf("network: rename %s to %s: %w", from, to, err)
	}
	return nil
}

// setMACOn sets an interface's hardware address.
func setMACOn(c *nlConn, link string, mac net.HardwareAddr) error {
	if len(mac) == 0 {
		return nil
	}
	idx, err := linkIndex(c, link)
	if err != nil {
		return err
	}
	var a attrBuf
	a.put(unix.IFLA_ADDRESS, mac)
	body := append(ifInfoMsg(idx, 0, 0), a.bytes()...)
	if _, err := c.execute(unix.RTM_SETLINK, unix.NLM_F_ACK, body); err != nil {
		return fmt.Errorf("network: set MAC %s on %s: %w", mac, link, err)
	}
	return nil
}

// ConfigureInNetNS finishes the container side of the veth pair from inside the
// container's network namespace.
func (o *linuxLinkOps) ConfigureInNetNS(ctx context.Context, pid int, nsPath string, cfg IfaceConfig) error {
	if nsPath == "" {
		if pid <= 0 {
			return fmt.Errorf("%w: configuring %s needs a namespace path or a pid", ErrInvalidConfig, cfg.To)
		}
		nsPath = "/proc/" + strconv.Itoa(pid) + "/ns/net"
	}
	return withNetNS(nsPath, func() error {
		c, err := dialNetlink()
		if err != nil {
			return err
		}
		defer c.Close()

		if err := renameOn(c, cfg.From, cfg.To); err != nil {
			return err
		}
		if err := setMACOn(c, cfg.To, cfg.MAC); err != nil {
			return err
		}
		if cfg.MTU > 0 {
			if err := setMTUOn(c, cfg.To, cfg.MTU); err != nil {
				return err
			}
		}
		if cfg.Addr != nil {
			if err := addAddressOn(c, cfg.To, cfg.Addr); err != nil {
				return err
			}
		}
		if err := setUpOn(c, "lo"); err != nil {
			return err
		}
		if err := setUpOn(c, cfg.To); err != nil {
			return err
		}
		if cfg.Gateway != nil {
			if err := addDefaultRouteOn(c, cfg.To, cfg.Gateway); err != nil {
				return err
			}
		}
		return nil
	})
}

// HostReservations dumps the host's routes and interface addresses so subnet
// allocation can avoid everything already reachable — including WSL's own NAT
// subnet and any bridge Docker Desktop has created.
func (o *linuxLinkOps) HostReservations(ctx context.Context) ([]Reservation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	var out []Reservation
	routes, err := o.conn.execute(unix.RTM_GETROUTE, unix.NLM_F_DUMP,
		rtMsg(unix.AF_INET, 0, unix.RT_SCOPE_UNIVERSE))
	if err != nil {
		return nil, fmt.Errorf("network: dump routes: %w", err)
	}
	for _, m := range routes {
		if len(m) < unix.SizeofRtMsg || m[0] != unix.AF_INET {
			continue
		}
		dstLen := int(m[1])
		if dstLen == 0 || dstLen > 32 {
			continue // the default route reserves nothing
		}
		attrs := parseAttrs(m[unix.SizeofRtMsg:])
		raw, ok := attrs[unix.RTA_DST]
		if !ok || len(raw) < net.IPv4len {
			continue
		}
		n := &net.IPNet{IP: net.IP(append([]byte(nil), raw[:4]...)), Mask: net.CIDRMask(dstLen, 32)}
		out = append(out, Reservation{Subnet: n, Reason: "host route"})
	}

	addrs, err := o.conn.execute(unix.RTM_GETADDR, unix.NLM_F_DUMP,
		ifAddrMsg(unix.AF_INET, 0, 0, 0))
	if err != nil {
		return nil, fmt.Errorf("network: dump addresses: %w", err)
	}
	for _, m := range addrs {
		if len(m) < unix.SizeofIfAddrmsg || m[0] != unix.AF_INET {
			continue
		}
		prefix := int(m[1])
		attrs := parseAttrs(m[unix.SizeofIfAddrmsg:])
		raw, ok := attrs[unix.IFA_LOCAL]
		if !ok {
			raw, ok = attrs[unix.IFA_ADDRESS]
		}
		if !ok || len(raw) < net.IPv4len {
			continue
		}
		ip := net.IP(append([]byte(nil), raw[:4]...))
		if ip.IsLoopback() {
			continue
		}
		mask := net.CIDRMask(prefix, 32)
		out = append(out, Reservation{
			Subnet: &net.IPNet{IP: ip.Mask(mask), Mask: mask},
			Reason: "address assigned on this host",
		})
	}
	return out, nil
}

// UplinkName returns the interface carrying the IPv4 default route. hull copies
// its MTU so a VPN's smaller MTU does not silently black-hole large packets.
func (o *linuxLinkOps) UplinkName(ctx context.Context) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	routes, err := o.conn.execute(unix.RTM_GETROUTE, unix.NLM_F_DUMP,
		rtMsg(unix.AF_INET, 0, unix.RT_SCOPE_UNIVERSE))
	if err != nil {
		return "", fmt.Errorf("network: dump routes: %w", err)
	}
	for _, m := range routes {
		if len(m) < unix.SizeofRtMsg || m[0] != unix.AF_INET || m[1] != 0 {
			continue
		}
		attrs := parseAttrs(m[unix.SizeofRtMsg:])
		raw, ok := attrs[unix.RTA_OIF]
		if !ok || len(raw) < 4 {
			continue
		}
		idx := int(nativeEndian.Uint32(raw))
		ifi, err := net.InterfaceByIndex(idx)
		if err != nil {
			continue
		}
		return ifi.Name, nil
	}
	return "", fmt.Errorf("%w: no IPv4 default route, so hull cannot tell which interface is the uplink", ErrNotFound)
}

// EnableForwarding turns on IP forwarding, without which a bridge is a dead
// end. The error names the exact sysctl so the user can fix it by hand.
func (o *linuxLinkOps) EnableForwarding(ctx context.Context, ipv6 bool) error {
	paths := []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv4/conf/all/forwarding",
	}
	if ipv6 {
		paths = append(paths, "/proc/sys/net/ipv6/conf/all/forwarding")
	}
	for _, p := range paths {
		cur, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("network: read %s: %w", p, err)
		}
		if len(cur) > 0 && cur[0] == '1' {
			continue
		}
		if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
			return fmt.Errorf("network: enable IP forwarding: write 1 to %s: %w", p, err)
		}
	}
	return nil
}

// withNetNS runs fn on a dedicated OS thread that has been moved into the
// network namespace at nsPath, and moves it back afterwards.
//
// The thread is locked for the whole operation. If the restore fails the thread
// is deliberately left locked so the Go runtime destroys it when the goroutine
// exits, rather than returning a thread in the wrong namespace to the pool —
// that would silently corrupt every later network operation in the process.
func withNetNS(nsPath string, fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		restored := false
		defer func() {
			if restored {
				runtime.UnlockOSThread()
			}
		}()

		cur, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			done <- fmt.Errorf("network: open current netns: %w", err)
			return
		}
		defer cur.Close()

		target, err := os.Open(nsPath)
		if err != nil {
			done <- fmt.Errorf("network: open netns %s: %w", nsPath, err)
			return
		}
		defer target.Close()

		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("network: enter netns %s: %w", nsPath, err)
			return
		}
		fnErr := fn()
		if err := unix.Setns(int(cur.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("network: restore netns after %s: %w (thread retired)", nsPath, err)
			return
		}
		restored = true
		done <- fnErr
	}()
	return <-done
}
