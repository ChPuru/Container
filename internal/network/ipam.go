package network

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/rahuldhali/hull/internal/fsutil"
)

// maxPoolAddresses caps the size of a single allocation bitmap. A /12 is
// 1048576 addresses, which is a 128 KiB bitmap — already far larger than any
// sane container network. Anything bigger is rejected instead of quietly
// allocating hundreds of megabytes of state.
const maxPoolAddresses = 1 << 20

// IPAM hands out container addresses out of one subnet per network and
// remembers them across daemon restarts.
//
// Each network gets a bitmap file at <root>/networks/ipam/<netID>.json. A set
// bit means the address is either in use or waiting in the reuse queue, so the
// bitmap alone never hands the same address to two containers.
//
// Allocation order is deliberate: a fresh, never-used address is preferred, and
// released addresses are reused last, in the order they were released (FIFO).
// Combined with honouring a requested address, that means a container that is
// stopped and started again asks for the address recorded in its endpoint and
// gets it back, because nothing else will have taken it while untouched space
// remained.
//
// IPAM is safe for concurrent use.
type IPAM struct {
	dir string

	mu    sync.Mutex
	pools map[string]*addrPool
}

// addrPool is one network's address plan. The exported fields are the on-disk
// format; the lowercase ones are derived on load.
type addrPool struct {
	NetworkID string   `json:"networkId"`
	Subnet    string   `json:"subnet"`
	Gateway   string   `json:"gateway"`
	IPRange   string   `json:"ipRange,omitempty"`
	Bitmap    []byte   `json:"bitmap"`
	Cursor    uint32   `json:"cursor"`
	Freed     []uint32 `json:"freed,omitempty"`

	subnet *net.IPNet
	base   uint32
	count  uint32
	lo, hi uint32 // inclusive offsets that may be allocated
	gw     uint32 // gateway offset, never allocated
}

// PoolInfo is a read-only summary of one network's address plan.
type PoolInfo struct {
	// NetworkID is the network the pool belongs to.
	NetworkID string
	// Subnet is the CIDR the pool allocates from.
	Subnet string
	// Gateway is the address reserved for the bridge itself.
	Gateway string
	// Capacity is the number of addresses that may ever be handed out.
	Capacity int
	// InUse is the number currently allocated.
	InUse int
	// Queued is the number of released addresses waiting to be reused.
	Queued int
}

// NewIPAM opens (creating if needed) the IPAM state directory and loads every
// pool file already present, so a restarted daemon does not re-issue addresses
// that live containers still hold.
func NewIPAM(dir string) (*IPAM, error) {
	if dir == "" {
		return nil, fmt.Errorf("%w: empty IPAM directory", ErrInvalidConfig)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("network: create ipam dir %s: %w", dir, err)
	}
	a := &IPAM{dir: dir, pools: make(map[string]*addrPool)}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("network: read ipam dir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		p := &addrPool{}
		if err := fsutil.ReadJSON(filepath.Join(dir, e.Name()), p); err != nil {
			return nil, fmt.Errorf("network: load ipam pool %s: %w", e.Name(), err)
		}
		if err := p.derive(); err != nil {
			return nil, fmt.Errorf("network: load ipam pool %s: %w", e.Name(), err)
		}
		a.pools[p.NetworkID] = p
	}
	return a, nil
}

// AddPool registers a network's address plan. Calling it again for a network
// that already has a pool with the same subnet and gateway is a no-op, which is
// what makes Manager.Init idempotent; a different subnet is an error, because
// silently re-planning would strand every live endpoint.
//
// ipRange, when non-nil, narrows the range that may be allocated while the
// bitmap still covers the whole subnet.
func (a *IPAM) AddPool(netID string, subnet *net.IPNet, gateway net.IP, ipRange *net.IPNet) error {
	if err := safeFileKey(netID); err != nil {
		return err
	}
	if subnet == nil {
		return fmt.Errorf("%w: nil subnet for network %s", ErrInvalidConfig, netID)
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	rangeStr := ""
	if ipRange != nil {
		rangeStr = ipRange.String()
	}
	if p, ok := a.pools[netID]; ok {
		if p.Subnet != subnet.String() || p.Gateway != gateway.String() || p.IPRange != rangeStr {
			return fmt.Errorf("%w: network %s already has pool %s gw %s, cannot re-plan as %s gw %s",
				ErrExists, netID, p.Subnet, p.Gateway, subnet.String(), gateway.String())
		}
		return nil
	}

	p := &addrPool{
		NetworkID: netID,
		Subnet:    subnet.String(),
		Gateway:   gateway.String(),
		IPRange:   rangeStr,
	}
	if err := p.derive(); err != nil {
		return err
	}
	p.Cursor = p.lo
	a.pools[netID] = p
	return a.save(p)
}

// RemovePool forgets a network's addresses and deletes its state file. It is
// called from Manager.Remove once every endpoint is gone.
func (a *IPAM) RemovePool(netID string) error {
	if err := safeFileKey(netID); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.pools, netID)
	if err := os.Remove(a.path(netID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("network: remove ipam pool %s: %w", netID, err)
	}
	return nil
}

// HasPool reports whether a pool is registered for netID.
func (a *IPAM) HasPool(netID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.pools[netID]
	return ok
}

// Info returns a summary of one pool.
func (a *IPAM) Info(netID string) (PoolInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.pools[netID]
	if !ok {
		return PoolInfo{}, fmt.Errorf("%w: ipam pool for network %s", ErrNotFound, netID)
	}
	capacity, inUse := 0, 0
	for off := p.lo; off <= p.hi; off++ {
		if off == p.gw {
			continue
		}
		capacity++
		if p.get(off) {
			inUse++
		}
	}
	return PoolInfo{
		NetworkID: p.NetworkID,
		Subnet:    p.Subnet,
		Gateway:   p.Gateway,
		Capacity:  capacity,
		InUse:     inUse - len(p.Freed),
		Queued:    len(p.Freed),
	}, nil
}

// Allocate hands out an address on netID. When req is non-nil that exact
// address is requested: it is returned if it is inside the range and free (or
// merely queued for reuse), and an error wrapping ErrExists is returned if
// another endpoint holds it. When req is nil a never-used address is preferred
// and the oldest released address is used only once fresh space runs out.
//
// The pool file is written before the address is returned, so a crash between
// allocating and attaching leaks an address rather than double-assigning one.
func (a *IPAM) Allocate(netID string, req net.IP) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.pools[netID]
	if !ok {
		return nil, fmt.Errorf("%w: ipam pool for network %s", ErrNotFound, netID)
	}

	if req != nil {
		off, err := p.offsetOf(req)
		if err != nil {
			return nil, err
		}
		if p.get(off) {
			if !p.unqueue(off) {
				return nil, fmt.Errorf("%w: address %s on network %s is already allocated",
					ErrExists, req.String(), netID)
			}
			// It was only waiting in the reuse queue: hand it straight back.
			if err := a.save(p); err != nil {
				return nil, err
			}
			return p.ipAt(off), nil
		}
		p.set(off)
		if err := a.save(p); err != nil {
			return nil, err
		}
		return p.ipAt(off), nil
	}

	// Prefer fresh space, scanning forward from the cursor and wrapping once.
	span := p.hi - p.lo + 1
	cur := p.Cursor
	if cur < p.lo || cur > p.hi {
		cur = p.lo
	}
	for i := uint32(0); i < span; i++ {
		off := p.lo + (cur-p.lo+i)%span
		if off == p.gw || p.get(off) {
			continue
		}
		p.set(off)
		p.Cursor = p.lo + (off-p.lo+1)%span
		if err := a.save(p); err != nil {
			return nil, err
		}
		return p.ipAt(off), nil
	}

	// Nothing fresh: take the address released longest ago.
	if len(p.Freed) > 0 {
		off := p.Freed[0]
		p.Freed = append(p.Freed[:0:0], p.Freed[1:]...)
		if err := a.save(p); err != nil {
			return nil, err
		}
		return p.ipAt(off), nil
	}
	return nil, fmt.Errorf("%w: network %s subnet %s has no free address", ErrPoolExhausted, netID, p.Subnet)
}

// Release returns an address to the pool. It goes to the back of the reuse
// queue rather than becoming immediately available, so a restarted container
// can reclaim it. Releasing an address that is not allocated is not an error —
// teardown paths must be safe to run twice.
func (a *IPAM) Release(netID string, ip net.IP) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.pools[netID]
	if !ok {
		return fmt.Errorf("%w: ipam pool for network %s", ErrNotFound, netID)
	}
	off, err := p.offsetOf(ip)
	if err != nil {
		return err
	}
	if !p.get(off) {
		return nil
	}
	for _, q := range p.Freed {
		if q == off {
			return nil
		}
	}
	p.Freed = append(p.Freed, off)
	return a.save(p)
}

// Free returns an address to the pool immediately, as if it had never been
// handed out. It is the rollback path: Connect calls it when an attach fails
// part way, because an address that never reached a container has no owner to
// preserve it for. Release is the graceful counterpart.
func (a *IPAM) Free(netID string, ip net.IP) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.pools[netID]
	if !ok {
		return fmt.Errorf("%w: ipam pool for network %s", ErrNotFound, netID)
	}
	off, err := p.offsetOf(ip)
	if err != nil {
		return err
	}
	p.unqueue(off)
	p.clear(off)
	if off < p.Cursor {
		p.Cursor = off
	}
	return a.save(p)
}

// path returns the on-disk location of a pool file.
func (a *IPAM) path(netID string) string { return filepath.Join(a.dir, netID+".json") }

// save writes a pool atomically. The caller must hold a.mu.
func (a *IPAM) save(p *addrPool) error {
	if err := fsutil.WriteJSONAtomic(a.path(p.NetworkID), p, 0o600); err != nil {
		return fmt.Errorf("network: persist ipam pool %s: %w", p.NetworkID, err)
	}
	return nil
}

// derive computes the numeric bounds of a pool from its string fields and
// validates them. It is called both on creation and after loading from disk.
func (p *addrPool) derive() error {
	_, sn, err := net.ParseCIDR(p.Subnet)
	if err != nil {
		return fmt.Errorf("%w: subnet %q: %w", ErrInvalidConfig, p.Subnet, err)
	}
	ones, bits := sn.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("%w: subnet %q: only IPv4 is supported", ErrInvalidConfig, p.Subnet)
	}
	count := uint64(1) << uint(32-ones)
	if count > maxPoolAddresses {
		return fmt.Errorf("%w: subnet %s has %d addresses, more than the %d supported",
			ErrInvalidConfig, p.Subnet, count, maxPoolAddresses)
	}
	if count < 4 {
		return fmt.Errorf("%w: subnet %s is too small to host containers", ErrInvalidConfig, p.Subnet)
	}
	base, ok := ipToU32(sn.IP)
	if !ok {
		return fmt.Errorf("%w: subnet %q is not IPv4", ErrInvalidConfig, p.Subnet)
	}
	p.subnet = sn
	p.base = base
	p.count = uint32(count)
	// Skip the network address (.0) and the broadcast address (.255 on a /24).
	p.lo, p.hi = 1, p.count-2

	if p.IPRange != "" {
		_, rn, err := net.ParseCIDR(p.IPRange)
		if err != nil {
			return fmt.Errorf("%w: ipRange %q: %w", ErrInvalidConfig, p.IPRange, err)
		}
		if !sn.Contains(rn.IP) {
			return fmt.Errorf("%w: ipRange %s is outside subnet %s", ErrInvalidConfig, p.IPRange, p.Subnet)
		}
		rbase, _ := ipToU32(rn.IP.Mask(rn.Mask))
		rlast, _ := ipToU32(LastAddr(rn))
		lo, hi := rbase-base, rlast-base
		if lo > p.lo {
			p.lo = lo
		}
		if hi < p.hi {
			p.hi = hi
		}
		if p.lo > p.hi {
			return fmt.Errorf("%w: ipRange %s leaves no usable address in %s",
				ErrInvalidConfig, p.IPRange, p.Subnet)
		}
	}

	gwIP := net.ParseIP(p.Gateway)
	if gwIP == nil {
		return fmt.Errorf("%w: gateway %q is not an IP address", ErrInvalidConfig, p.Gateway)
	}
	gw, ok := ipToU32(gwIP)
	if !ok || !sn.Contains(gwIP) {
		return fmt.Errorf("%w: gateway %s is not inside subnet %s", ErrInvalidConfig, p.Gateway, p.Subnet)
	}
	p.gw = gw - base

	if want := (int(p.count) + 7) / 8; len(p.Bitmap) != want {
		if p.Bitmap == nil {
			p.Bitmap = make([]byte, want)
		} else if len(p.Bitmap) < want {
			return fmt.Errorf("%w: bitmap for %s is %d bytes, want %d",
				ErrInvalidConfig, p.Subnet, len(p.Bitmap), want)
		}
	}
	// The gateway is permanently taken.
	p.set(p.gw)
	return nil
}

// offsetOf converts an address into its bitmap offset, rejecting anything
// outside the allocatable range.
func (p *addrPool) offsetOf(ip net.IP) (uint32, error) {
	v, ok := ipToU32(ip)
	if !ok {
		return 0, fmt.Errorf("%w: %q is not an IPv4 address", ErrInvalidConfig, ip.String())
	}
	if !p.subnet.Contains(ip) {
		return 0, fmt.Errorf("%w: address %s is outside subnet %s", ErrInvalidConfig, ip.String(), p.Subnet)
	}
	off := v - p.base
	if off < p.lo || off > p.hi {
		return 0, fmt.Errorf("%w: address %s is outside the allocatable range of %s",
			ErrInvalidConfig, ip.String(), p.Subnet)
	}
	if off == p.gw {
		return 0, fmt.Errorf("%w: address %s is the gateway of %s", ErrExists, ip.String(), p.Subnet)
	}
	return off, nil
}

// ipAt renders a bitmap offset back into an address.
func (p *addrPool) ipAt(off uint32) net.IP { return u32ToIP(p.base + off) }

// get reports whether the bit for off is set.
func (p *addrPool) get(off uint32) bool {
	i := int(off / 8)
	if i >= len(p.Bitmap) {
		return true
	}
	return p.Bitmap[i]&(1<<(off%8)) != 0
}

// set marks off as taken.
func (p *addrPool) set(off uint32) {
	i := int(off / 8)
	if i >= len(p.Bitmap) {
		return
	}
	p.Bitmap[i] |= 1 << (off % 8)
}

// clear marks off as free again.
func (p *addrPool) clear(off uint32) {
	i := int(off / 8)
	if i >= len(p.Bitmap) || off == p.gw {
		return
	}
	p.Bitmap[i] &^= 1 << (off % 8)
}

// unqueue removes off from the reuse queue, reporting whether it was there.
// The bit stays set because the address simply changes owner.
func (p *addrPool) unqueue(off uint32) bool {
	for i, q := range p.Freed {
		if q == off {
			p.Freed = append(p.Freed[:i], p.Freed[i+1:]...)
			return true
		}
	}
	return false
}

// safeFileKey rejects any identifier that could escape the state directory when
// used as a file name. Network IDs are hex, but the check is explicit because
// this value reaches the filesystem.
func safeFileKey(s string) error {
	if s == "" || len(s) > 64 {
		return fmt.Errorf("%w: identifier %q must be 1..64 characters", ErrInvalidConfig, s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return fmt.Errorf("%w: identifier %q contains %q, which is not allowed in a state file name",
				ErrInvalidConfig, s, string(c))
		}
	}
	return nil
}
