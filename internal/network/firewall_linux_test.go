//go:build linux

package network

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestFirewallAppliesToTheRealKernel proves the generated script is not just
// well-formed text: nft parses it, the kernel accepts every expression, and
// `nft delete table inet hull` removes all of it. The table is hull's own, so
// this cannot disturb Docker Desktop's rules in the shared WSL netfilter state.
func TestFirewallAppliesToTheRealKernel(t *testing.T) {
	requireRoot(t)
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft(8) is not installed")
	}
	ctx := context.Background()

	// Use a distinct table so a concurrently running engine is untouched.
	const table = "hulltest"
	fw := NewFirewall(table, false)
	if err := fw.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", table).Run() })

	rs := Ruleset{
		Bridges: []BridgeRule{
			{Name: "hulltestbr0", Subnet: "10.199.77.0/24"},
			{Name: "hulltestbr1", Subnet: "10.199.78.0/24", Internal: true},
		},
		DNAT: []DNATRule{
			{Proto: "tcp", HostPort: 18080, ContainerIP: "10.199.77.42", ContainerPort: 80},
			{Proto: "udp", HostIP: "127.0.0.1", HostPort: 18053, ContainerIP: "10.199.77.42", ContainerPort: 53},
		},
	}
	if err := fw.Apply(ctx, rs); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Applying twice must be a clean replace, not an error or a duplicate.
	if err := fw.Apply(ctx, rs); err != nil {
		t.Fatalf("Apply is not idempotent: %v", err)
	}

	out, err := exec.Command("nft", "list", "table", "inet", table).CombinedOutput()
	if err != nil {
		t.Fatalf("list table: %v: %s", err, out)
	}
	dump := string(out)
	for _, want := range []string{
		"chain hull-prerouting",
		"chain hull-postrouting",
		"chain hull-forward",
		"chain hull-output",
		"masquerade",
		"dnat",
	} {
		if !strings.Contains(dump, want) {
			t.Fatalf("ruleset missing %q:\n%s", want, dump)
		}
	}
	// The tcp binding gets a dnat rule in prerouting and one in output; the
	// loopback-only udp binding gets none, because only the userland proxy can
	// serve an address WSL's localhost relay watches.
	if n := strings.Count(dump, "dnat ip to"); n != 2 {
		t.Fatalf("expected 2 dnat rules (prerouting + output), found %d:\n%s", n, dump)
	}
	if strings.Contains(dump, "dnat ip to 10.199.77.42:53") {
		t.Fatalf("a loopback-only binding must not reach netfilter:\n%s", dump)
	}

	if err := fw.Teardown(ctx); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if out, err := exec.Command("nft", "list", "table", "inet", table).CombinedOutput(); err == nil {
		t.Fatalf("table survived teardown:\n%s", out)
	}
	if err := fw.Teardown(ctx); err != nil {
		t.Fatalf("Teardown must tolerate a missing table: %v", err)
	}
}

// TestFirewallForwardShimAgainstRealIPTables exercises the Docker Desktop
// workaround against the real binary: the ACCEPT rule must appear in the
// filter FORWARD chain and be removed again, leaving nothing behind.
func TestFirewallForwardShimAgainstRealIPTables(t *testing.T) {
	requireRoot(t)
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables(8) is not installed")
	}
	if _, err := os.Stat("/proc/net/ip_tables_names"); err != nil {
		// iptables-nft still works without the legacy module, so this is only
		// informational; the -C/-I/-D cycle below is the real check.
		t.Log("legacy ip_tables module not loaded; using whatever backend iptables picks")
	}
	ctx := context.Background()
	fw := NewFirewall("hulltest", true)
	if err := fw.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}
	const br = "hulltestbr9"
	t.Cleanup(func() { _ = fw.RemoveForwardAccept(context.Background(), []string{br}) })

	if err := fw.EnsureForwardAccept(ctx, []string{br}); err != nil {
		t.Fatalf("EnsureForwardAccept: %v", err)
	}
	if err := exec.Command("iptables", "-C", "FORWARD", "-i", br, "-j", "ACCEPT").Run(); err != nil {
		t.Fatalf("the FORWARD ACCEPT shim was not installed: %v", err)
	}
	if err := fw.EnsureForwardAccept(ctx, []string{br}); err != nil {
		t.Fatalf("EnsureForwardAccept is not idempotent: %v", err)
	}
	if err := fw.RemoveForwardAccept(ctx, []string{br}); err != nil {
		t.Fatalf("RemoveForwardAccept: %v", err)
	}
	if err := exec.Command("iptables", "-C", "FORWARD", "-i", br, "-j", "ACCEPT").Run(); err == nil {
		t.Fatal("the FORWARD shim was left behind")
	}
}
