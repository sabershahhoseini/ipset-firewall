package ipsetfw

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/sshclients"
	"golang.org/x/sys/unix"
)

// The allow-only chain sees inbound traffic to this host only: table filter, jumped from INPUT.
// It runs after connection tracking, so replies to the host's own connections are accepted.
const (
	onlyTable  = "filter"
	onlyChain  = "IPSET_ONLY"
	onlyNew    = "IPSET_ONLY_NEW"
	onlyParent = "INPUT"
)

// OnlyUnattended (-unattended) skips the interactive confirmation of a first allow-only install.
// OnlyTimeout (-only-timeout) is how long that confirmation waits.
var (
	OnlyUnattended bool
	OnlyTimeout    = 60 * time.Second
)

// onlyListRule is the ACCEPT rule for a list in the allow-only chain. Traffic there is inbound,
// so a list matches the source; a port list also matches the destination port.
func onlyListRule(l list) []string {
	if l.entry.IsPort() {
		return []string{"-p", l.entry.ProtoOrDefault(), "-m", "set", "--match-set", l.setName(), "src,dst", "-j", "ACCEPT"}
	}
	return []string{"-m", "set", "--match-set", l.setName(), "src", "-j", "ACCEPT"}
}

// onlyRules is the whole allow-only chain, in order: loopback, replies, allowed addresses,
// allow lists, only lists, and then the action for everything else.
func onlyRules(inv file.Inventory) ([][]string, error) {
	rules := [][]string{
		{"-i", "lo", "-j", "ACCEPT"},
		{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	allows, err := canonicalAllows(inv.AllowAddresses())
	if err != nil {
		return nil, err
	}
	for _, a := range allows {
		rules = append(rules, []string{"-s", a, "-j", "ACCEPT"})
	}
	for _, l := range allowListsOf(inv) {
		rules = append(rules, onlyListRule(l))
	}
	for _, l := range onlyListsOf(inv) {
		rules = append(rules, onlyListRule(l))
	}
	if inv.OnlyActionOrDefault() == "reject" {
		// A TCP reset refuses a connection at once; for other protocols, an ICMP error.
		rules = append(rules,
			[]string{"-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"},
			[]string{"-j", "REJECT", "--reject-with", "icmp-port-unreachable"})
	} else {
		rules = append(rules, []string{"-j", "DROP"})
	}
	return rules, nil
}

// onlyInstalled reports whether INPUT jumps to the allow-only chain.
func onlyInstalled(ipt *iptables.IPTables) (bool, error) {
	exists, err := ipt.ChainExists(onlyTable, onlyChain)
	if err != nil || !exists {
		return false, err
	}
	return ipt.Exists(onlyTable, onlyParent, "-j", onlyChain)
}

// destroyChain removes INPUT's jump to a chain, then the chain itself. A missing chain is fine.
func destroyChain(ipt *iptables.IPTables, chain string) error {
	exists, err := ipt.ChainExists(onlyTable, chain)
	if err != nil || !exists {
		return err
	}
	if err := ipt.DeleteIfExists(onlyTable, onlyParent, "-j", chain); err != nil {
		return err
	}
	if err := ipt.ClearChain(onlyTable, chain); err != nil {
		return err
	}
	return ipt.DeleteChain(onlyTable, chain)
}

// removeOnly turns allow-only off: the jump and the chain go; the sets are kept.
func removeOnly(ipt *iptables.IPTables) error {
	if err := destroyChain(ipt, onlyNew); err != nil {
		return err
	}
	return destroyChain(ipt, onlyChain)
}

// clientAllowed reports whether an inbound connection from c would be accepted by the
// allow-only chain. inSet answers whether c is in one list's set.
func clientAllowed(inv file.Inventory, c sshclients.Client, inSet func(l list, c sshclients.Client) bool) bool {
	allows, _ := canonicalAllows(inv.AllowAddresses())
	for _, a := range allows {
		if _, n, err := net.ParseCIDR(a); err == nil && n.Contains(c.IP) {
			return true
		}
	}
	for _, l := range append(allowListsOf(inv), onlyListsOf(inv)...) {
		if l.entry.IsPort() && (l.entry.ProtoOrDefault() != "tcp" || !hasPort(l.entry.Ports, c.LocalPort)) {
			continue
		}
		if inSet(l, c) {
			return true
		}
	}
	return false
}

func hasPort(ports []int, p int) bool {
	for _, q := range ports {
		if q == p {
			return true
		}
	}
	return false
}

// kernelInSet tests membership with the ipset command, against the sets just built.
func kernelInSet(l list, c sshclients.Client) bool {
	entry := c.IP.String()
	if l.entry.IsPort() {
		entry = fmt.Sprintf("%s,tcp:%d", c.IP, c.LocalPort)
	}
	return exec.Command("ipset", "test", l.setName(), entry).Run() == nil
}

// cutOffClients returns the SSH clients the allow-only chain would refuse.
func cutOffClients(inv file.Inventory, inSet func(l list, c sshclients.Client) bool) []sshclients.Client {
	var bad []sshclients.Client
	for _, c := range sshclients.Find() {
		if !clientAllowed(inv, c, inSet) {
			bad = append(bad, c)
		}
	}
	return bad
}

func describeClients(cs []sshclients.Client) string {
	var parts []string
	for _, c := range cs {
		parts = append(parts, fmt.Sprintf("%s (to port %d)", c.IP, c.LocalPort))
	}
	return strings.Join(parts, ", ")
}

// stdinIsTerminal reports whether someone can answer the confirmation prompt. /dev/null is also
// a character device, so this asks the terminal driver rather than looking at the file mode.
func stdinIsTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}

// confirmOnly asks the operator to check a new connection and type yes within the timeout.
func confirmOnly(timeout time.Duration) bool {
	fmt.Fprintf(os.Stderr, "\nAllow-only is now active. Open a NEW connection to this host (for example a second SSH\n"+
		"session) and check that it works. Type yes within %s to keep it. Anything else, or no\n"+
		"answer, removes it.\n> ", timeout)
	answer := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		answer <- strings.TrimSpace(line)
	}()
	select {
	case a := <-answer:
		return strings.EqualFold(a, "yes")
	case <-time.After(timeout):
		fmt.Fprintln(os.Stderr, "\nno answer")
		return false
	}
}

// onlyPrecheck runs before anything is changed: a first install needs a terminal to confirm.
func onlyPrecheck(ipt *iptables.IPTables, inv file.Inventory) error {
	if len(inv.Only) == 0 || OnlyUnattended {
		return nil
	}
	installed, err := onlyInstalled(ipt)
	if err != nil {
		return err
	}
	if !installed && !stdinIsTerminal() {
		return errors.New("the first allow-only install must be confirmed at a terminal; run it by hand, or pass -unattended to skip the confirmation")
	}
	return nil
}

// applyOnly installs, updates or removes the allow-only chain. The new chain is built in full
// and INPUT is pointed at it before the old one is removed, so there is no moment without it.
// It refuses when a current SSH client would be cut off. A first install must be confirmed
// unless -unattended is set; if it is not confirmed, it is removed again.
func applyOnly(ipt *iptables.IPTables, inv file.Inventory) error {
	installed, err := onlyInstalled(ipt)
	if err != nil {
		return err
	}
	if len(inv.Only) == 0 {
		if installed {
			fmt.Println("Allow-only removed (no longer in config)")
		}
		return removeOnly(ipt)
	}
	if bad := cutOffClients(inv, kernelInSet); len(bad) > 0 {
		return fmt.Errorf("refusing allow-only: it would cut off SSH client %s; add it to allow or only", describeClients(bad))
	}
	rules, err := onlyRules(inv)
	if err != nil {
		return err
	}

	if err := destroyChain(ipt, onlyNew); err != nil {
		return err
	}
	if err := ipt.NewChain(onlyTable, onlyNew); err != nil {
		return err
	}
	for _, r := range rules {
		if err := ipt.Append(onlyTable, onlyNew, r...); err != nil {
			_ = destroyChain(ipt, onlyNew)
			return fmt.Errorf("building %s: %w", onlyChain, err)
		}
	}
	// Point INPUT at the new chain first, then remove the old chain, then rename.
	if err := ipt.Insert(onlyTable, onlyParent, 1, "-j", onlyNew); err != nil {
		_ = destroyChain(ipt, onlyNew)
		return err
	}
	if err := destroyChain(ipt, onlyChain); err != nil {
		return err
	}
	if err := ipt.RenameChain(onlyTable, onlyNew, onlyChain); err != nil {
		return err
	}

	if !installed && !OnlyUnattended && !confirmOnly(OnlyTimeout) {
		if err := removeOnly(ipt); err != nil {
			return fmt.Errorf("allow-only was not confirmed, and removing it failed: %w", err)
		}
		return errors.New("allow-only was not confirmed and has been removed")
	}
	fmt.Printf("Allow-only active: inbound connections not allowed are %s\n", onlyActionPast(inv))
	return nil
}

// onlyActionPast is the action in past tense, for messages: "dropped" or "rejected".
func onlyActionPast(inv file.Inventory) string {
	if inv.OnlyActionOrDefault() == "reject" {
		return "rejected"
	}
	return "dropped"
}

// expectedOnlyLines is the allow-only chain as iptables -S prints it.
func expectedOnlyLines(inv file.Inventory) ([]string, error) {
	rules, err := onlyRules(inv)
	if err != nil {
		return nil, err
	}
	lines := []string{"-N " + onlyChain}
	for _, r := range rules {
		lines = append(lines, "-A "+onlyChain+" "+strings.Join(r, " "))
	}
	return lines, nil
}
