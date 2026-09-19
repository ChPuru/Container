package network

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// newTestIPAM builds an IPAM over a temporary directory with one pool.
func newTestIPAM(t *testing.T, subnet, gateway string) (*IPAM, string) {
	t.Helper()
	dir := t.TempDir()
	a, err := NewIPAM(dir)
	if err != nil {
		t.Fatalf("NewIPAM: %v", err)
	}
	netID := "abc123"
	if err := a.AddPool(netID, mustCIDR(t, subnet), net.ParseIP(gateway), nil); err != nil {
		t.Fatalf("AddPool: %v", err)
	}
	return a, netID
}

func TestIPAMAllocatesInOrderSkippingReservedAddresses(t *testing.T) {
	a, id := newTestIPAM(t, "10.66.0.0/29", "10.66.0.1")
	// A /29 is .0-.7: .0 network, .7 broadcast, .1 gateway, leaving .2-.6.
	want := []string{"10.66.0.2", "10.66.0.3", "10.66.0.4", "10.66.0.5", "10.66.0.6"}
	for _, w := range want {
		got, err := a.Allocate(id, nil)
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		if got.String() != w {
			t.Fatalf("got %s, want %s", got, w)
		}
	}
	if _, err := a.Allocate(id, nil); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("want ErrPoolExhausted, got %v", err)
	}
}

func TestIPAMReusesReleasedAddressesLast(t *testing.T) {
	a, id := newTestIPAM(t, "10.66.0.0/29", "10.66.0.1")
	first, err := a.Allocate(id, nil) // .2
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if err := a.Release(id, first); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// Fresh space remains, so the released address must not come back yet.
	next, err := a.Allocate(id, nil)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if next.Equal(first) {
		t.Fatalf("released address %s was handed straight back", first)
	}
	// Drain the rest; only then does the released one reappear.
	for {
		ip, err := a.Allocate(id, nil)
		if errors.Is(err, ErrPoolExhausted) {
			t.Fatalf("pool exhausted before the released address was reused")
		}
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		if ip.Equal(first) {
			break
		}
	}
	if _, err := a.Allocate(id, nil); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("want ErrPoolExhausted after reuse, got %v", err)
	}
}

func TestIPAMRequestedAddressWins(t *testing.T) {
	a, id := newTestIPAM(t, "10.66.0.0/24", "10.66.0.1")

	got, err := a.Allocate(id, net.ParseIP("10.66.0.50"))
	if err != nil {
		t.Fatalf("Allocate requested: %v", err)
	}
	if got.String() != "10.66.0.50" {
		t.Fatalf("got %s, want 10.66.0.50", got)
	}
	if _, err := a.Allocate(id, net.ParseIP("10.66.0.50")); !errors.Is(err, ErrExists) {
		t.Fatalf("second request for a live address should fail with ErrExists, got %v", err)
	}

	// The restart case: release then ask for the same address back.
	if err := a.Release(id, got); err != nil {
		t.Fatalf("Release: %v", err)
	}
	again, err := a.Allocate(id, net.ParseIP("10.66.0.50"))
	if err != nil {
		t.Fatalf("re-request after release: %v", err)
	}
	if again.String() != "10.66.0.50" {
		t.Fatalf("restarted container did not get its address back, got %s", again)
	}
}

func TestIPAMRejectsAddressesOutsideTheRange(t *testing.T) {
	a, id := newTestIPAM(t, "10.66.0.0/24", "10.66.0.1")
	tests := []struct {
		name string
		ip   string
		want error
	}{
		{"outside the subnet", "10.67.0.5", ErrInvalidConfig},
		{"the network address", "10.66.0.0", ErrInvalidConfig},
		{"the broadcast address", "10.66.0.255", ErrInvalidConfig},
		{"the gateway", "10.66.0.1", ErrExists},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := a.Allocate(id, net.ParseIP(tc.ip)); !errors.Is(err, tc.want) {
				t.Fatalf("Allocate(%s) = %v, want %v", tc.ip, err, tc.want)
			}
		})
	}
}

func TestIPAMPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	a, err := NewIPAM(dir)
	if err != nil {
		t.Fatalf("NewIPAM: %v", err)
	}
	id := "net01"
	if err := a.AddPool(id, mustCIDR(t, "10.66.0.0/24"), net.ParseIP("10.66.0.1"), nil); err != nil {
		t.Fatalf("AddPool: %v", err)
	}
	var taken []string
	for i := 0; i < 5; i++ {
		ip, err := a.Allocate(id, nil)
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		taken = append(taken, ip.String())
	}
	if _, err := os.Stat(filepath.Join(dir, id+".json")); err != nil {
		t.Fatalf("pool file not written: %v", err)
	}

	b, err := NewIPAM(dir)
	if err != nil {
		t.Fatalf("reopen NewIPAM: %v", err)
	}
	if !b.HasPool(id) {
		t.Fatal("pool not reloaded")
	}
	next, err := b.Allocate(id, nil)
	if err != nil {
		t.Fatalf("Allocate after restart: %v", err)
	}
	for _, old := range taken {
		if next.String() == old {
			t.Fatalf("restart re-issued a live address %s", old)
		}
	}
	info, err := b.Info(id)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.InUse != 6 {
		t.Fatalf("InUse = %d, want 6", info.InUse)
	}
	if info.Capacity != 253 {
		t.Fatalf("Capacity = %d, want 253 (a /24 minus network, broadcast and gateway)", info.Capacity)
	}
}

func TestIPAMIPRangeNarrowsAllocation(t *testing.T) {
	dir := t.TempDir()
	a, err := NewIPAM(dir)
	if err != nil {
		t.Fatalf("NewIPAM: %v", err)
	}
	id := "ranged"
	if err := a.AddPool(id, mustCIDR(t, "10.66.0.0/24"), net.ParseIP("10.66.0.1"), mustCIDR(t, "10.66.0.128/25")); err != nil {
		t.Fatalf("AddPool: %v", err)
	}
	ip, err := a.Allocate(id, nil)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if ip.String() != "10.66.0.128" {
		t.Fatalf("got %s, want the first address of the narrowed range", ip)
	}
	if _, err := a.Allocate(id, net.ParseIP("10.66.0.10")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("an address outside ipRange must be refused, got %v", err)
	}
}

func TestIPAMRejectsRePlanningAPool(t *testing.T) {
	a, id := newTestIPAM(t, "10.66.0.0/24", "10.66.0.1")
	if err := a.AddPool(id, mustCIDR(t, "10.66.0.0/24"), net.ParseIP("10.66.0.1"), nil); err != nil {
		t.Fatalf("re-adding an identical pool must be a no-op: %v", err)
	}
	if err := a.AddPool(id, mustCIDR(t, "10.67.0.0/24"), net.ParseIP("10.67.0.1"), nil); !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
}

func TestIPAMRemovePool(t *testing.T) {
	dir := t.TempDir()
	a, err := NewIPAM(dir)
	if err != nil {
		t.Fatalf("NewIPAM: %v", err)
	}
	id := "gone"
	if err := a.AddPool(id, mustCIDR(t, "10.66.0.0/24"), net.ParseIP("10.66.0.1"), nil); err != nil {
		t.Fatalf("AddPool: %v", err)
	}
	if err := a.RemovePool(id); err != nil {
		t.Fatalf("RemovePool: %v", err)
	}
	if a.HasPool(id) {
		t.Fatal("pool still present")
	}
	if _, err := os.Stat(filepath.Join(dir, id+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pool file still on disk: %v", err)
	}
	if err := a.RemovePool(id); err != nil {
		t.Fatalf("removing twice must be safe: %v", err)
	}
	if _, err := a.Allocate(id, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestSafeFileKeyRejectsTraversal(t *testing.T) {
	bad := []string{"", "../escape", "a/b", "UPPER", "with space", "dot.dot"}
	for _, s := range bad {
		if err := safeFileKey(s); err == nil {
			t.Errorf("safeFileKey(%q) should have failed", s)
		}
	}
	for _, s := range []string{"abc123", "net-01", "net_01"} {
		if err := safeFileKey(s); err != nil {
			t.Errorf("safeFileKey(%q): %v", s, err)
		}
	}
}

func TestIPAMRejectsOversizedSubnet(t *testing.T) {
	dir := t.TempDir()
	a, err := NewIPAM(dir)
	if err != nil {
		t.Fatalf("NewIPAM: %v", err)
	}
	err = a.AddPool("big", mustCIDR(t, "10.0.0.0/8"), net.ParseIP("10.0.0.1"), nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig for an oversized subnet, got %v", err)
	}
}
