package network

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// chainPrefix is prepended to every chain hull creates. The table already
// isolates hull from Docker Desktop's rules, but all WSL distros share one
// netfilter ruleset and a prefixed name makes an `nft list ruleset` dump
// unambiguous about who owns what.
const chainPrefix = "hull-"

// commandTimeout bounds one nft or iptables invocation.
const commandTimeout = 15 * time.Second

// BridgeRule is the firewall's view of one hull bridge.
type BridgeRule struct {
	// Name is the Linux interface name, e.g. "hull0".
	Name string
	// Subnet is the CIDR behind the bridge.
	Subnet string
	// Internal marks a network with no route off the bridge: no masquerade and
	// traffic may not cross the bridge boundary in either direction.
	Internal bool
}

// DNATRule is one published port's LAN-facing translation. The userland proxy
// handles loopback; this covers traffic arriving from the rest of the network
// and the hairpin case of a container reaching its own published port.
type DNATRule struct {
	// Proto is "tcp" or "udp".
	Proto string
	// HostIP restricts the rule to one host address. Empty or "0.0.0.0" means
	// any address. A loopback address produces no rule at all, because only the
	// userland proxy can serve it.
	HostIP string
	// HostPort is the published port.
	HostPort int
	// ContainerIP is the destination address.
	ContainerIP string
	// ContainerPort is the destination port.
	ContainerPort int
}

// Ruleset is the complete, declarative state of hull's netfilter table. It is a
// pure value: Script renders it to an nft script and nothing else about the
// process influences the output, which is what makes it testable.
type Ruleset struct {
	// Table is the nftables table name inside the inet family.
	Table string
	// Bridges are every hull bridge, in any order; Script sorts them.
	Bridges []BridgeRule
	// DNAT are the published-port translations, in any order; Script sorts them.
	DNAT []DNATRule
}

// Script renders the whole ruleset as a single `nft -f -` program.
//
// The script starts by declaring the table and immediately deleting it. That is
// the standard idempotent-replace idiom: declaring first makes the delete
// succeed even on a fresh kernel, and because nft applies a whole -f script in
// one netlink transaction, the ruleset is replaced atomically — there is no
// window in which containers have no rules.
func (rs Ruleset) Script() string {
	table := rs.Table
	if table == "" {
		table = TableName
	}

	bridges := append([]BridgeRule(nil), rs.Bridges...)
	sort.Slice(bridges, func(i, j int) bool { return bridges[i].Name < bridges[j].Name })
	dnat := append([]DNATRule(nil), rs.DNAT...)
	sort.Slice(dnat, func(i, j int) bool {
		if dnat[i].HostPort != dnat[j].HostPort {
			return dnat[i].HostPort < dnat[j].HostPort
		}
		if dnat[i].Proto != dnat[j].Proto {
			return dnat[i].Proto < dnat[j].Proto
		}
		if dnat[i].HostIP != dnat[j].HostIP {
			return dnat[i].HostIP < dnat[j].HostIP
		}
		return dnat[i].ContainerIP < dnat[j].ContainerIP
	})

	var b strings.Builder
	b.WriteString("# hull netfilter ruleset - generated, do not edit\n")
	b.WriteString("# remove everything hull installed with: nft delete table inet " + table + "\n")
	fmt.Fprintf(&b, "table inet %s\n", table)
	fmt.Fprintf(&b, "delete table inet %s\n", table)
	fmt.Fprintf(&b, "table inet %s {\n", table)

	// prerouting: LAN-facing DNAT.
	fmt.Fprintf(&b, "\tchain %sprerouting {\n", chainPrefix)
	b.WriteString("\t\ttype nat hook prerouting priority -100; policy accept;\n")
	for _, d := range dnat {
		if line := dnatLine(d); line != "" {
			b.WriteString("\t\t" + line + "\n")
		}
	}
	b.WriteString("\t}\n")

	// output: locally generated traffic to a published port, except loopback,
	// which belongs to the userland proxy WSL's relay watches for.
	fmt.Fprintf(&b, "\tchain %soutput {\n", chainPrefix)
	b.WriteString("\t\ttype nat hook output priority -100; policy accept;\n")
	for _, d := range dnat {
		if line := dnatLine(d); line != "" {
			b.WriteString("\t\tip daddr != 127.0.0.0/8 " + line + "\n")
		}
	}
	b.WriteString("\t}\n")

	// postrouting: masquerade out of each bridge plus the hairpin case.
	fmt.Fprintf(&b, "\tchain %spostrouting {\n", chainPrefix)
	b.WriteString("\t\ttype nat hook postrouting priority 100; policy accept;\n")
	for _, br := range bridges {
		if br.Internal || br.Subnet == "" {
			continue
		}
		fmt.Fprintf(&b, "\t\tip saddr %s oifname != %q masquerade\n", br.Subnet, br.Name)
	}
	for _, d := range dnat {
		if d.ContainerIP == "" {
			continue
		}
		fmt.Fprintf(&b, "\t\tip saddr %s ip daddr %s %s dport %d masquerade\n",
			d.ContainerIP, d.ContainerIP, d.Proto, d.ContainerPort)
	}
	b.WriteString("\t}\n")

	// forward: conntrack, intra-bridge, isolation, then egress/ingress.
	fmt.Fprintf(&b, "\tchain %sforward {\n", chainPrefix)
	b.WriteString("\t\ttype filter hook forward priority 0; policy accept;\n")
	b.WriteString("\t\tct state established,related accept\n")
	for _, br := range bridges {
		fmt.Fprintf(&b, "\t\tiifname %q oifname %q accept\n", br.Name, br.Name)
		if br.Internal {
			fmt.Fprintf(&b, "\t\tiifname %q oifname != %q drop\n", br.Name, br.Name)
			fmt.Fprintf(&b, "\t\tiifname != %q oifname %q drop\n", br.Name, br.Name)
			continue
		}
		if others := otherBridges(bridges, br.Name); others != "" {
			fmt.Fprintf(&b, "\t\tiifname %q oifname { %s } drop\n", br.Name, others)
		}
		fmt.Fprintf(&b, "\t\tiifname %q accept\n", br.Name)
		fmt.Fprintf(&b, "\t\toifname %q accept\n", br.Name)
	}
	b.WriteString("\t}\n")

	b.WriteString("}\n")
	return b.String()
}

// dnatLine renders one DNAT match, or "" when the binding is loopback-only and
// therefore served purely by the userland proxy.
func dnatLine(d DNATRule) string {
	if d.ContainerIP == "" || d.HostPort == 0 || d.ContainerPort == 0 {
		return ""
	}
	if isLoopbackSpec(d.HostIP) {
		return ""
	}
	var sb strings.Builder
	if d.HostIP != "" && d.HostIP != "0.0.0.0" && d.HostIP != "::" {
		sb.WriteString("ip daddr " + d.HostIP + " ")
	}
	fmt.Fprintf(&sb, "%s dport %d dnat ip to %s:%d", d.Proto, d.HostPort, d.ContainerIP, d.ContainerPort)
	return sb.String()
}

// isLoopbackSpec reports whether a host IP names the loopback interface.
func isLoopbackSpec(s string) bool {
	return s == "127.0.0.1" || s == "localhost" || strings.HasPrefix(s, "127.")
}

// otherBridges renders the nft set of every bridge except self.
func otherBridges(all []BridgeRule, self string) string {
	var names []string
	for _, b := range all {
		if b.Name != self {
			names = append(names, strconv.Quote(b.Name))
		}
	}
	return strings.Join(names, ", ")
}

// CommandRunner runs an external command with optional stdin. The firewall
// drives nft and iptables through it so tests can record invocations instead of
// touching the host's netfilter state.
type CommandRunner interface {
	// Run executes name with args, feeding stdin, and returns combined output.
	Run(ctx context.Context, name string, args []string, stdin string) (string, error)
	// LookPath resolves a binary, returning an error when it is absent.
	LookPath(name string) (string, error)
}

// execRunner is the production CommandRunner.
type execRunner struct{}

// Run executes the command with a bounded timeout.
func (execRunner) Run(ctx context.Context, name string, args []string, stdin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// LookPath resolves a binary on PATH.
func (execRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

// Firewall applies a Ruleset with nft(8) and maintains the iptables FORWARD
// compatibility shim.
//
// The shim exists because Docker Desktop shares the WSL VM and sets the
// iptables filter FORWARD policy to DROP. iptables-legacy and nftables are
// different hooks at the same priority: an accept in hull's nftables forward
// chain does not stop the iptables chain from dropping the packet afterwards.
// hull therefore also inserts an explicit ACCEPT for each of its bridges at the
// top of the iptables FORWARD chain, and removes it on teardown.
type Firewall struct {
	table  string
	compat bool
	runner CommandRunner

	mu      sync.Mutex
	shimmed map[string]struct{}
	nftPath string
	iptPath string
	probed  bool
}

// NewFirewall builds a firewall driver for a table. compat enables the iptables
// FORWARD shim; it should be on unless the operator knows Docker Desktop is not
// present.
func NewFirewall(table string, compat bool) *Firewall {
	if table == "" {
		table = TableName
	}
	return &Firewall{table: table, compat: compat, runner: execRunner{}, shimmed: make(map[string]struct{})}
}

// SetRunner replaces the command runner. It exists for tests.
func (f *Firewall) SetRunner(r CommandRunner) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runner = r
	f.probed = false
}

// Check verifies that nft(8) is usable, returning an actionable error when it
// is not. hull refuses to start rather than running containers with no NAT and
// no isolation.
func (f *Firewall) Check(ctx context.Context) error {
	if err := f.probe(); err != nil {
		return err
	}
	if _, err := f.runner.Run(ctx, f.nftPath, []string{"list", "ruleset"}, ""); err != nil {
		return fmt.Errorf("network: %s cannot read the netfilter ruleset "+
			"(are you root, and is nf_tables loaded?): %w", f.nftPath, err)
	}
	return nil
}

// probe resolves the external binaries once.
func (f *Firewall) probe() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.probed {
		if f.nftPath == "" {
			return fmt.Errorf("%w: nft(8) is not installed; hull needs it to program NAT. "+
				"Install the nftables package in the engine distro", ErrUnsupported)
		}
		return nil
	}
	f.probed = true
	p, err := f.runner.LookPath("nft")
	if err != nil {
		return fmt.Errorf("%w: nft(8) is not installed; hull needs it to program NAT. "+
			"Install the nftables package in the engine distro: %w", ErrUnsupported, err)
	}
	f.nftPath = p
	if f.compat {
		if ip, err := f.runner.LookPath("iptables"); err == nil {
			f.iptPath = ip
		}
	}
	return nil
}

// Apply replaces hull's whole table with rs in a single atomic transaction.
func (f *Firewall) Apply(ctx context.Context, rs Ruleset) error {
	if err := f.probe(); err != nil {
		return err
	}
	rs.Table = f.table
	script := rs.Script()
	if out, err := f.runner.Run(ctx, f.nftPath, []string{"-f", "-"}, script); err != nil {
		return fmt.Errorf("network: apply nftables ruleset: %w: %s", err, strings.TrimSpace(out))
	}
	if !f.compat {
		return nil
	}
	names := make([]string, 0, len(rs.Bridges))
	for _, b := range rs.Bridges {
		names = append(names, b.Name)
	}
	return f.EnsureForwardAccept(ctx, names)
}

// Teardown removes hull's table entirely. A missing table is not an error, so
// the call is safe on a cold start and on a second shutdown.
func (f *Firewall) Teardown(ctx context.Context) error {
	if err := f.probe(); err != nil {
		return err
	}
	out, err := f.runner.Run(ctx, f.nftPath, []string{"delete", "table", "inet", f.table}, "")
	if err != nil && !strings.Contains(strings.ToLower(out), "no such file") {
		return fmt.Errorf("network: delete nftables table inet %s: %w: %s", f.table, err, strings.TrimSpace(out))
	}
	f.mu.Lock()
	bridges := make([]string, 0, len(f.shimmed))
	for b := range f.shimmed {
		bridges = append(bridges, b)
	}
	f.mu.Unlock()
	return f.RemoveForwardAccept(ctx, bridges)
}

// EnsureForwardAccept inserts the iptables FORWARD ACCEPT shim for each bridge,
// if iptables is present. A missing iptables binary is not an error: a host
// without iptables has no legacy FORWARD policy to work around.
func (f *Firewall) EnsureForwardAccept(ctx context.Context, bridges []string) error {
	f.mu.Lock()
	ipt := f.iptPath
	f.mu.Unlock()
	if ipt == "" || !f.compat {
		return nil
	}
	for _, br := range bridges {
		if br == "" {
			continue
		}
		for _, dir := range []string{"-i", "-o"} {
			rule := []string{"FORWARD", dir, br, "-j", "ACCEPT"}
			if _, err := f.runner.Run(ctx, ipt, append([]string{"-C"}, rule...), ""); err == nil {
				continue // already present
			}
			if out, err := f.runner.Run(ctx, ipt, append([]string{"-I"}, rule...), ""); err != nil {
				return fmt.Errorf("network: insert iptables FORWARD accept for %s: %w: %s",
					br, err, strings.TrimSpace(out))
			}
		}
		f.mu.Lock()
		f.shimmed[br] = struct{}{}
		f.mu.Unlock()
	}
	return nil
}

// RemoveForwardAccept deletes the iptables FORWARD shim for each bridge. It
// deletes repeatedly until the rule is gone, because an engine that crashed and
// restarted may have inserted it more than once.
func (f *Firewall) RemoveForwardAccept(ctx context.Context, bridges []string) error {
	f.mu.Lock()
	ipt := f.iptPath
	f.mu.Unlock()
	if ipt == "" {
		return nil
	}
	for _, br := range bridges {
		if br == "" {
			continue
		}
		for _, dir := range []string{"-i", "-o"} {
			rule := []string{"FORWARD", dir, br, "-j", "ACCEPT"}
			for i := 0; i < 8; i++ {
				if _, err := f.runner.Run(ctx, ipt, append([]string{"-C"}, rule...), ""); err != nil {
					break
				}
				if _, err := f.runner.Run(ctx, ipt, append([]string{"-D"}, rule...), ""); err != nil {
					break
				}
			}
		}
		f.mu.Lock()
		delete(f.shimmed, br)
		f.mu.Unlock()
	}
	return nil
}
