package network

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// goldenRuleset is the exact nft script two bridges and one published port must
// produce. It is compared verbatim, because a silent change in this output is a
// silent change in the host's firewall.
const goldenRuleset = `# hull netfilter ruleset - generated, do not edit
# remove everything hull installed with: nft delete table inet hull
table inet hull
delete table inet hull
table inet hull {
	chain hull-prerouting {
		type nat hook prerouting priority -100; policy accept;
		tcp dport 8080 dnat ip to 10.66.0.2:80
	}
	chain hull-output {
		type nat hook output priority -100; policy accept;
		ip daddr != 127.0.0.0/8 tcp dport 8080 dnat ip to 10.66.0.2:80
	}
	chain hull-postrouting {
		type nat hook postrouting priority 100; policy accept;
		ip saddr 10.66.1.0/24 oifname != "hb-abc123456789" masquerade
		ip saddr 10.66.0.0/24 oifname != "hull0" masquerade
		ip saddr 10.66.0.2 ip daddr 10.66.0.2 tcp dport 80 masquerade
	}
	chain hull-forward {
		type filter hook forward priority 0; policy accept;
		ct state established,related accept
		iifname "hb-abc123456789" oifname "hb-abc123456789" accept
		iifname "hb-abc123456789" oifname { "hull0" } drop
		iifname "hb-abc123456789" accept
		oifname "hb-abc123456789" accept
		iifname "hull0" oifname "hull0" accept
		iifname "hull0" oifname { "hb-abc123456789" } drop
		iifname "hull0" accept
		oifname "hull0" accept
	}
}
`

func TestRulesetScriptGolden(t *testing.T) {
	rs := Ruleset{
		Table: "hull",
		// Deliberately out of order: Script must sort.
		Bridges: []BridgeRule{
			{Name: "hull0", Subnet: "10.66.0.0/24"},
			{Name: "hb-abc123456789", Subnet: "10.66.1.0/24"},
		},
		DNAT: []DNATRule{
			{Proto: "tcp", HostIP: "0.0.0.0", HostPort: 8080, ContainerIP: "10.66.0.2", ContainerPort: 80},
		},
	}
	got := rs.Script()
	if got != goldenRuleset {
		t.Fatalf("ruleset mismatch\n--- got ---\n%s\n--- want ---\n%s", got, goldenRuleset)
	}
}

func TestRulesetScriptIsDeterministic(t *testing.T) {
	rs := Ruleset{
		Bridges: []BridgeRule{{Name: "b", Subnet: "10.0.1.0/24"}, {Name: "a", Subnet: "10.0.0.0/24"}},
		DNAT: []DNATRule{
			{Proto: "udp", HostPort: 53, ContainerIP: "10.0.0.5", ContainerPort: 53},
			{Proto: "tcp", HostPort: 53, ContainerIP: "10.0.0.5", ContainerPort: 53},
			{Proto: "tcp", HostPort: 8, ContainerIP: "10.0.0.6", ContainerPort: 8},
		},
	}
	first := rs.Script()
	for i := 0; i < 5; i++ {
		if rs.Script() != first {
			t.Fatal("Script is not deterministic")
		}
	}
	// tcp/8 sorts before tcp/53 which sorts before udp/53.
	pre := section(t, first, "hull-prerouting")
	wantOrder := []string{"dport 8 ", "tcp dport 53", "udp dport 53"}
	at := 0
	for _, w := range wantOrder {
		i := strings.Index(pre[at:], w)
		if i < 0 {
			t.Fatalf("%q missing or out of order in:\n%s", w, pre)
		}
		at += i
	}
}

func TestRulesetInternalNetworkHasNoMasqueradeAndIsSealed(t *testing.T) {
	rs := Ruleset{Bridges: []BridgeRule{{Name: "hb-int", Subnet: "10.66.2.0/24", Internal: true}}}
	script := rs.Script()
	if strings.Contains(script, "masquerade") {
		t.Fatalf("an internal network must not masquerade:\n%s", script)
	}
	fwd := section(t, script, "hull-forward")
	for _, want := range []string{
		`iifname "hb-int" oifname "hb-int" accept`,
		`iifname "hb-int" oifname != "hb-int" drop`,
		`iifname != "hb-int" oifname "hb-int" drop`,
	} {
		if !strings.Contains(fwd, want) {
			t.Fatalf("missing %q in:\n%s", want, fwd)
		}
	}
	if strings.Contains(fwd, `iifname "hb-int" accept`) {
		t.Fatalf("an internal network must not have a blanket egress accept:\n%s", fwd)
	}
}

func TestRulesetLoopbackBindingGetsNoDNAT(t *testing.T) {
	rs := Ruleset{
		Bridges: []BridgeRule{{Name: "hull0", Subnet: "10.66.0.0/24"}},
		DNAT: []DNATRule{
			{Proto: "tcp", HostIP: "127.0.0.1", HostPort: 8080, ContainerIP: "10.66.0.2", ContainerPort: 80},
		},
	}
	script := rs.Script()
	if strings.Contains(script, "dnat") {
		t.Fatalf("a loopback-only binding is served by the userland proxy, not DNAT:\n%s", script)
	}
	// The hairpin masquerade still applies.
	if !strings.Contains(script, "ip saddr 10.66.0.2 ip daddr 10.66.0.2 tcp dport 80 masquerade") {
		t.Fatalf("hairpin masquerade missing:\n%s", script)
	}
}

func TestRulesetSpecificHostIPIsMatched(t *testing.T) {
	rs := Ruleset{
		Bridges: []BridgeRule{{Name: "hull0", Subnet: "10.66.0.0/24"}},
		DNAT: []DNATRule{
			{Proto: "tcp", HostIP: "192.168.1.5", HostPort: 443, ContainerIP: "10.66.0.9", ContainerPort: 8443},
		},
	}
	want := "ip daddr 192.168.1.5 tcp dport 443 dnat ip to 10.66.0.9:8443"
	if !strings.Contains(rs.Script(), want) {
		t.Fatalf("missing %q in:\n%s", want, rs.Script())
	}
}

// section extracts one chain block from a script for focused assertions.
func section(t *testing.T, script, chain string) string {
	t.Helper()
	start := strings.Index(script, "chain "+chain+" {")
	if start < 0 {
		t.Fatalf("chain %s not found in:\n%s", chain, script)
	}
	rest := script[start:]
	end := strings.Index(rest, "\n\t}")
	if end < 0 {
		t.Fatalf("chain %s not terminated", chain)
	}
	return rest[:end]
}

// fakeRunner records every command instead of running it, and models enough of
// iptables for the shim logic to be exercised honestly: -C succeeds only when
// the rule is present, -I adds it and -D removes it.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []string
	stdins  []string
	missing map[string]bool
	fail    map[string]error
	rules   map[string]int
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{missing: map[string]bool{}, fail: map[string]error{}, rules: map[string]int{}}
}

func (r *fakeRunner) Run(ctx context.Context, name string, args []string, stdin string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	r.stdins = append(r.stdins, stdin)
	for prefix, err := range r.fail {
		if strings.HasPrefix(line, prefix) {
			return "simulated failure", err
		}
	}
	if strings.HasSuffix(name, "iptables") && len(args) > 1 {
		key := strings.Join(args[1:], " ")
		switch args[0] {
		case "-C":
			if r.rules[key] == 0 {
				return "iptables: Bad rule (does a matching rule exist in that chain?).",
					errors.New("exit status 1")
			}
		case "-I", "-A":
			r.rules[key]++
		case "-D":
			if r.rules[key] == 0 {
				return "iptables: Bad rule.", errors.New("exit status 1")
			}
			r.rules[key]--
		}
	}
	return "", nil
}

// countPrefix reports how many recorded calls start with p.
func (r *fakeRunner) countPrefix(p string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if strings.HasPrefix(c, p) {
			n++
		}
	}
	return n
}

// ruleCount reports how many copies of an iptables rule the fake holds.
func (r *fakeRunner) ruleCount(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rules[key]
}

func (r *fakeRunner) LookPath(name string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.missing[name] {
		return "", fmt.Errorf("exec: %q not found", name)
	}
	return "/usr/sbin/" + name, nil
}

func (r *fakeRunner) sawPrefix(p string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}

func TestFirewallApplyFeedsOneAtomicScript(t *testing.T) {
	r := newFakeRunner()
	fw := NewFirewall("hull", true)
	fw.SetRunner(r)
	rs := Ruleset{Bridges: []BridgeRule{{Name: "hull0", Subnet: "10.66.0.0/24"}}}
	if err := fw.Apply(context.Background(), rs); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !r.sawPrefix("/usr/sbin/nft -f -") {
		t.Fatalf("nft -f - was not invoked: %v", r.calls)
	}
	r.mu.Lock()
	var script string
	for i, c := range r.calls {
		if strings.HasPrefix(c, "/usr/sbin/nft -f -") {
			script = r.stdins[i]
		}
	}
	r.mu.Unlock()
	if !strings.Contains(script, "delete table inet hull") || !strings.Contains(script, "chain hull-forward") {
		t.Fatalf("script fed to nft looks wrong:\n%s", script)
	}
	// The iptables FORWARD shim must be inserted for the bridge.
	if !r.sawPrefix("/usr/sbin/iptables -I FORWARD -i hull0 -j ACCEPT") {
		t.Fatalf("iptables ingress shim missing: %v", r.calls)
	}
	if !r.sawPrefix("/usr/sbin/iptables -I FORWARD -o hull0 -j ACCEPT") {
		t.Fatalf("iptables egress shim missing: %v", r.calls)
	}
}

func TestFirewallShimIsIdempotent(t *testing.T) {
	r := newFakeRunner()
	fw := NewFirewall("hull", true)
	fw.SetRunner(r)
	if err := fw.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := fw.EnsureForwardAccept(context.Background(), []string{"hull0"}); err != nil {
			t.Fatalf("EnsureForwardAccept: %v", err)
		}
	}
	if got := r.countPrefix("/usr/sbin/iptables -I"); got != 2 {
		t.Fatalf("inserted %d rules over three calls, want 2 (one -i, one -o)", got)
	}
	if got := r.ruleCount("FORWARD -i hull0 -j ACCEPT"); got != 1 {
		t.Fatalf("rule present %d times, want 1", got)
	}
	if err := fw.RemoveForwardAccept(context.Background(), []string{"hull0"}); err != nil {
		t.Fatalf("RemoveForwardAccept: %v", err)
	}
	if got := r.ruleCount("FORWARD -i hull0 -j ACCEPT"); got != 0 {
		t.Fatalf("rule still present %d times after removal", got)
	}
}

func TestFirewallRemovesDuplicateShimRulesLeftByACrash(t *testing.T) {
	r := newFakeRunner()
	fw := NewFirewall("hull", true)
	fw.SetRunner(r)
	if err := fw.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	// Pretend three earlier engine lifetimes each inserted the rule.
	r.mu.Lock()
	r.rules["FORWARD -i hull0 -j ACCEPT"] = 3
	r.rules["FORWARD -o hull0 -j ACCEPT"] = 3
	r.mu.Unlock()
	if err := fw.RemoveForwardAccept(context.Background(), []string{"hull0"}); err != nil {
		t.Fatalf("RemoveForwardAccept: %v", err)
	}
	if got := r.ruleCount("FORWARD -i hull0 -j ACCEPT"); got != 0 {
		t.Fatalf("%d duplicate rules left behind", got)
	}
}

func TestFirewallWithoutIPTablesIsNotAnError(t *testing.T) {
	r := newFakeRunner()
	r.missing["iptables"] = true
	fw := NewFirewall("hull", true)
	fw.SetRunner(r)
	if err := fw.Apply(context.Background(), Ruleset{Bridges: []BridgeRule{{Name: "hull0"}}}); err != nil {
		t.Fatalf("a host without iptables has no FORWARD policy to fight: %v", err)
	}
}

func TestFirewallWithoutNftIsAClearError(t *testing.T) {
	r := newFakeRunner()
	r.missing["nft"] = true
	fw := NewFirewall("hull", true)
	fw.SetRunner(r)
	err := fw.Check(context.Background())
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
	if !strings.Contains(err.Error(), "nftables package") {
		t.Fatalf("error should tell the user what to install: %v", err)
	}
}

func TestFirewallTeardownRemovesTableAndShim(t *testing.T) {
	r := newFakeRunner()
	fw := NewFirewall("hull", true)
	fw.SetRunner(r)
	if err := fw.Apply(context.Background(), Ruleset{Bridges: []BridgeRule{{Name: "hull0", Subnet: "10.66.0.0/24"}}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := fw.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if !r.sawPrefix("/usr/sbin/nft delete table inet hull") {
		t.Fatalf("table not deleted: %v", r.calls)
	}
	if !r.sawPrefix("/usr/sbin/iptables -D FORWARD -i hull0 -j ACCEPT") {
		t.Fatalf("iptables shim not removed: %v", r.calls)
	}
}

func TestFirewallTeardownToleratesAMissingTable(t *testing.T) {
	r := newFakeRunner()
	r.fail["/usr/sbin/nft delete table"] = errors.New("exit status 1")
	fw := NewFirewall("hull", false)
	fw.SetRunner(r)
	// The runner returns "simulated failure", which does not contain
	// "no such file", so this must surface as an error.
	if err := fw.Teardown(context.Background()); err == nil {
		t.Fatal("a real nft failure must not be swallowed")
	}
}
