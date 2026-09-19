package network

import (
	"errors"
	"net"
	"testing"
)

// mustCIDR parses a CIDR or fails the test.
func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return n
}

// reserve builds a reservation list from CIDR strings.
func reserve(t *testing.T, cidrs ...string) []Reservation {
	t.Helper()
	out := make([]Reservation, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, Reservation{Subnet: mustCIDR(t, c), Reason: "test"})
	}
	return out
}

func TestAllocateSubnetSkipsConflicts(t *testing.T) {
	tests := []struct {
		name string
		pool string
		size int
		used []string
		want string
	}{
		{
			name: "empty pool gives the first block",
			pool: "10.66.0.0/16",
			size: 24,
			want: "10.66.0.0/24",
		},
		{
			name: "skips an exactly matching block",
			pool: "10.66.0.0/16",
			size: 24,
			used: []string{"10.66.0.0/24"},
			want: "10.66.1.0/24",
		},
		{
			name: "skips a larger enclosing range",
			pool: "10.66.0.0/16",
			size: 24,
			used: []string{"10.66.0.0/20"},
			want: "10.66.16.0/24",
		},
		{
			name: "skips several scattered blocks",
			pool: "10.66.0.0/16",
			size: 24,
			used: []string{"10.66.0.0/24", "10.66.1.0/24", "10.66.2.128/25"},
			want: "10.66.3.0/24",
		},
		{
			name: "docker pools do not touch hull's pool",
			pool: "10.66.0.0/16",
			size: 24,
			used: []string{"172.17.0.0/16", "192.168.0.0/16", "172.31.0.0/16"},
			want: "10.66.0.0/24",
		},
		{
			name: "wsl nat subnet is avoided when it lands in the pool",
			pool: "10.0.0.0/8",
			size: 24,
			used: []string{"10.0.0.0/16", "10.1.0.0/16"},
			want: "10.2.0.0/24",
		},
		{
			name: "a /28 inside a /24 pool",
			pool: "10.66.5.0/24",
			size: 28,
			used: []string{"10.66.5.0/28"},
			want: "10.66.5.16/28",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AllocateSubnet(tc.pool, tc.size, reserve(t, tc.used...))
			if err != nil {
				t.Fatalf("AllocateSubnet: %v", err)
			}
			if got.String() != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestAllocateSubnetExhausted(t *testing.T) {
	_, err := AllocateSubnet("10.66.0.0/24", 26, reserve(t, "10.66.0.0/24"))
	if !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("want ErrPoolExhausted, got %v", err)
	}
	if want := "10.66.0.0/24 (test)"; !contains(err.Error(), want) {
		t.Fatalf("error %q should name the blocker %q", err, want)
	}
}

func TestAllocateSubnetRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		pool string
		size int
	}{
		{"unparsable pool", "not-a-cidr", 24},
		{"size smaller than the pool", "10.66.0.0/16", 8},
		{"size beyond /30", "10.66.0.0/16", 31},
		{"ipv6 pool", "fd00::/48", 64},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := AllocateSubnet(tc.pool, tc.size, nil); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("want ErrInvalidConfig, got %v", err)
			}
		})
	}
}

func TestCheckSubnetNamesTheConflict(t *testing.T) {
	used := []Reservation{{Subnet: mustCIDR(t, "172.17.0.0/16"), Reason: "docker default bridge pool"}}
	err := CheckSubnet(mustCIDR(t, "172.17.5.0/24"), used)
	if !errors.Is(err, ErrSubnetConflict) {
		t.Fatalf("want ErrSubnetConflict, got %v", err)
	}
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConflictError, got %T", err)
	}
	if ce.Conflict != "172.17.0.0/16" || ce.Reason != "docker default bridge pool" {
		t.Fatalf("conflict not described: %+v", ce)
	}

	if err := CheckSubnet(mustCIDR(t, "10.66.0.0/24"), used); err != nil {
		t.Fatalf("non-conflicting subnet rejected: %v", err)
	}
}

func TestDockerReservationsCoverTheDocumentedPools(t *testing.T) {
	res := DockerReservations()
	if len(res) != 16 {
		t.Fatalf("want 16 reservations (172.17-172.31 plus 192.168.0.0/16), got %d", len(res))
	}
	for _, probe := range []string{"172.17.0.1", "172.31.255.254", "192.168.1.1"} {
		ip := net.ParseIP(probe)
		found := false
		for _, r := range res {
			if r.Subnet.Contains(ip) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s is not covered by the docker reservations", probe)
		}
	}
	if net.ParseIP("10.66.0.1") == nil {
		t.Fatal("bad probe")
	}
	for _, r := range res {
		if r.Subnet.Contains(net.ParseIP("10.66.0.1")) {
			t.Fatalf("hull's own pool must not be reserved: %s", r)
		}
	}
}

func TestSubnetArithmetic(t *testing.T) {
	tests := []struct {
		cidr, first, last string
	}{
		{"10.66.0.0/24", "10.66.0.1", "10.66.0.255"},
		{"10.66.4.0/22", "10.66.4.1", "10.66.7.255"},
		{"192.168.1.0/30", "192.168.1.1", "192.168.1.3"},
	}
	for _, tc := range tests {
		n := mustCIDR(t, tc.cidr)
		if got := FirstUsable(n).String(); got != tc.first {
			t.Errorf("FirstUsable(%s) = %s, want %s", tc.cidr, got, tc.first)
		}
		if got := LastAddr(n).String(); got != tc.last {
			t.Errorf("LastAddr(%s) = %s, want %s", tc.cidr, got, tc.last)
		}
	}
}

func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		in      string
		port    int
		proto   string
		wantErr bool
	}{
		{in: "80/tcp", port: 80, proto: "tcp"},
		{in: "53/udp", port: 53, proto: "udp"},
		{in: "8080", port: 8080, proto: "tcp"},
		{in: "  443/TCP ", port: 443, proto: "tcp"},
		{in: "80/icmp", wantErr: true},
		{in: "0/tcp", wantErr: true},
		{in: "70000/tcp", wantErr: true},
		{in: "", wantErr: true},
		{in: "abc/tcp", wantErr: true},
	}
	for _, tc := range tests {
		port, proto, err := ParsePortSpec(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParsePortSpec(%q) should have failed", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortSpec(%q): %v", tc.in, err)
			continue
		}
		if port != tc.port || proto != tc.proto {
			t.Errorf("ParsePortSpec(%q) = %d/%s, want %d/%s", tc.in, port, proto, tc.port, tc.proto)
		}
		if got := PortSpec(port, proto); got != PortSpec(tc.port, tc.proto) {
			t.Errorf("PortSpec round trip mismatch for %q", tc.in)
		}
	}
}

func TestBridgeNameFor(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if got := bridgeNameFor(DefaultNetworkName, id); got != DefaultBridgeName {
		t.Fatalf("default network bridge = %q, want %q", got, DefaultBridgeName)
	}
	got := bridgeNameFor("frontend", id)
	if got != "hb-0123456789ab" {
		t.Fatalf("bridge name = %q", got)
	}
	// IFNAMSIZ is 16 including the NUL, so names must stay at 15 or fewer.
	if len(got) > 15 {
		t.Fatalf("bridge name %q is %d bytes, longer than IFNAMSIZ-1", got, len(got))
	}
}

func TestValidNetworkName(t *testing.T) {
	ok := []string{"bridge", "my-net", "my_net", "net.1", "a"}
	bad := []string{"", "-lead", "_lead", ".lead", "has space", "has/slash", "has:colon"}
	for _, s := range ok {
		if !validNetworkName(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range bad {
		if validNetworkName(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

// contains is a tiny substring helper so the tests read without importing
// strings for one call.
func contains(haystack, needle string) bool {
	return len(needle) == 0 || len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
