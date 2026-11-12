package ipsetfw

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"github.com/lrh3321/ipset-go"
	"github.com/sabershahhoseini/ipset-firewall/models"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/logger"
	"github.com/sabershahhoseini/ipset-firewall/util/netutils"
	"github.com/sabershahhoseini/ipset-firewall/util/usermgmt"
)

// newFormat reports whether the config uses block/allow instead of rules.
func newFormat(inv file.Inventory) bool {
	return len(inv.Block) > 0 || len(inv.Allow) > 0
}

// baseRule is where every entry lives: table raw, chain IPSET_FW, jump from PREROUTING.
func baseRule() models.Rule {
	r := models.Rule{Table: "raw", Chain: "IPSET_FW"}
	applyRuleDefaults(&r)
	return r
}

// blockRule is the drop rule for one block entry. insert is its position in the chain.
func blockRule(b file.BlockEntry, insert int) models.Rule {
	dir := b.Direction
	if dir == "" {
		dir = "src"
	}
	r := baseRule()
	r.Policy = "drop"
	r.Insert = insert
	r.Type = []string{dir}
	return r
}

// blockSources gathers the addresses for one block entry without changing the system.
func blockSources(b file.BlockEntry, verbose bool, logFilePath string) ([]string, error) {
	var list []string
	if b.Country != "" {
		fetched, err := netutils.FetchIPPool(b.Country, verbose, "", logFilePath)
		if err != nil {
			return nil, err
		}
		list = append(list, fetched...)
	}
	for _, path := range b.File {
		lines, err := file.ReadListFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		list = append(list, lines...)
	}
	return append(list, b.IPs...), nil
}

// allowRule is one ACCEPT rule in the chain: flag is "-s" or "-d".
type allowRule struct {
	flag string
	addr string
}

// allowRulesIn returns the ACCEPT rules currently in the chain.
func allowRulesIn(ipt *iptables.IPTables, r models.Rule) ([]allowRule, error) {
	lines, err := ipt.List(r.Table, r.Chain)
	if err != nil {
		return nil, err
	}
	var found []allowRule
	for _, line := range lines {
		// Expected form: -A IPSET_FW -s 10.0.0.0/8 -j ACCEPT (or -d)
		f := strings.Fields(line)
		if len(f) == 6 && (f[2] == "-s" || f[2] == "-d") && f[4] == "-j" && f[5] == "ACCEPT" {
			found = append(found, allowRule{flag: f[2], addr: f[3]})
		}
	}
	return found, nil
}

// deleteAllowRules removes every allow rule from the chain.
func deleteAllowRules(ipt *iptables.IPTables, r models.Rule) error {
	found, err := allowRulesIn(ipt, r)
	if err != nil {
		return err
	}
	for _, a := range found {
		if err := ipt.Delete(r.Table, r.Chain, a.flag, a.addr, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("removing allow %s %s: %w", a.flag, a.addr, err)
		}
	}
	return nil
}

// dedupe returns the unique allow entries in order.
func dedupe(allows []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range allows {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// allowRuleCount is how many chain entries the allow list takes: one -s and one -d per address.
func allowRuleCount(allows []string) int {
	return 2 * len(dedupe(allows))
}

// setAllowRules makes the chain's allow rules exactly the given list, at the top of the chain.
// Each address is allowed as source and as destination.
// Earlier allow rules are removed first, so the order is always allows, then blocks.
func setAllowRules(allows []string, logFilePath string, verbose bool) error {
	r := baseRule()
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	if err := createDefaultChain(r.Chain, r.Table); err != nil {
		return err
	}
	if err := addDefaultChainIptableRule(r.Chain, r.Table, r.Parent, logFilePath, verbose); err != nil {
		return err
	}
	if err := deleteAllowRules(ipt, r); err != nil {
		return err
	}
	pos := 1
	for _, a := range dedupe(allows) {
		logger.Log("Allowing "+a+" as source and destination", logFilePath, verbose)
		for _, flag := range []string{"-s", "-d"} {
			if err := ipt.Insert(r.Table, r.Chain, pos, flag, a, "-j", "ACCEPT"); err != nil {
				return fmt.Errorf("allow %s %s: %w", flag, a, err)
			}
			pos++
		}
	}
	return nil
}

// removeStaleBlockRules deletes drop rules for "-block" sets that are no longer in the config.
// It works on the rule text, so it finds net and port rules alike. The sets themselves are kept.
func removeStaleBlockRules(ipt *iptables.IPTables, r models.Rule, keep map[string]bool) ([]string, error) {
	lines, err := ipt.List(r.Table, r.Chain)
	if err != nil {
		return nil, err
	}
	var stale []string
	for _, line := range lines {
		// Expected form: -A IPSET_FW [-p tcp] -m set --match-set ir-block src -j DROP
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "-A" || f[1] != r.Chain || f[len(f)-2] != "-j" || f[len(f)-1] != "DROP" {
			continue
		}
		name := matchSetName(f)
		if name == "" || !strings.HasSuffix(name, "-block") || keep[name] {
			continue
		}
		if err := ipt.Delete(r.Table, r.Chain, f[2:]...); err != nil {
			return nil, fmt.Errorf("removing stale rule for %s: %w", name, err)
		}
		stale = append(stale, name)
	}
	return stale, nil
}

// matchSetName returns the set named by --match-set in a rule's fields, or "".
func matchSetName(f []string) string {
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "--match-set" {
			return f[i+1]
		}
	}
	return ""
}

// destroySet deletes a set, ignoring "does not exist".
func destroySet(name string) error {
	if err := ipset.Destroy(name); err != nil && !errors.Is(err, syscall.ENOENT) {
		return err
	}
	return nil
}

// applyBlockAllow applies a block/allow config: allow rules first, then one set and drop rule per block entry.
func applyBlockAllow(inv file.Inventory, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	if err := inv.Validate(); err != nil {
		return err
	}
	if err := configureSources(inv, false); err != nil {
		return err
	}
	logFilePath := inv.LogFilePath
	var mattermost file.Mattermost
	if inv.Mattermost.Token != "" && inv.Mattermost.URL != "" {
		mattermost = inv.Mattermost
	}

	if err := setAllowRules(inv.Allow, logFilePath, verbose); err != nil {
		return fmt.Errorf("allow rules: %w", err)
	}
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, b := range inv.Block {
		keep[b.SetName()] = true
	}
	stale, err := removeStaleBlockRules(ipt, baseRule(), keep)
	if err != nil {
		return err
	}
	for _, name := range stale {
		fmt.Fprintln(os.Stderr, "removed rule for "+name+" (no longer in config); set kept, destroy it with: ipset destroy "+name)
	}

	var failed []string
	for k, b := range inv.Block {
		if b.IsPort() {
			if err := applyPortBlock(b, allowRuleCount(inv.Allow)+k+1, mattermost, logFilePath, verbose); err != nil {
				fmt.Fprintln(os.Stderr, "block "+b.Name+" not updated: "+err.Error())
				failed = append(failed, b.Name)
			}
			continue
		}
		list, err := blockSources(b, verbose, logFilePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "block "+b.Name+" not updated: "+err.Error())
			failed = append(failed, b.Name)
			continue
		}
		country := b.Country
		if country == "" {
			country = b.Name
		}
		set := models.Set{Country: country, SetName: b.SetName()}
		rule := blockRule(b, allowRuleCount(inv.Allow)+k+1)
		if err := IPsetfw(list, set, true, rule, mattermost, logFilePath, verbose); err != nil {
			fmt.Fprintln(os.Stderr, "block "+b.Name+" not updated: "+err.Error())
			failed = append(failed, b.Name)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d block(s) not updated: %s", len(failed), strings.Join(failed, ", "))
	}
	return nil
}

// clearBlockAllow removes everything applyBlockAllow created: allow rules, block rules and sets, the jump and the chain.
func clearBlockAllow(inv file.Inventory, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	r := baseRule()
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	// IPSET_FW belongs to this tool, so clearing the whole chain is safe.
	if err := ipt.ClearChain(r.Table, r.Chain); err != nil {
		return fmt.Errorf("clearing %s: %w", r.Chain, err)
	}
	for _, b := range inv.Block {
		if b.IsPort() {
			if err := deletePortBlockRule(b, r.Chain); err != nil {
				return err
			}
		} else if err := removeIptableRule(blockRule(b, 1), b.SetName(), r.Chain, "", verbose, true); err != nil {
			return err
		}
		if err := destroySet(b.SetName()); err != nil {
			return err
		}
		if err := destroySet(b.SetName() + "-bak"); err != nil {
			return err
		}
	}
	if err := removeDefaultChainIptableRule(r.Chain, r.Table, r.Parent, "", verbose, true); err != nil {
		return err
	}
	return removeDefaultChain(r.Chain, r.Table, "", verbose)
}

// PlanConfig prints what applying a block/allow config would do. It changes no sets or iptables rules.
func PlanConfig(path string, verbose bool) error {
	inv := file.DecodeConfig(file.ReadConfigFile(path))
	if !newFormat(inv) {
		return fmt.Errorf("-plan supports the block/allow format only")
	}
	if err := inv.Validate(); err != nil {
		return err
	}
	if err := configureSources(inv, true); err != nil {
		return err
	}
	r := baseRule()
	fmt.Printf("chain %s (table %s, from %s): allow rules first, then block rules\n", r.Chain, r.Table, r.Parent)
	for _, a := range inv.Allow {
		fmt.Printf("  allow   %-18s ACCEPT as source and destination\n", a)
	}
	var failed []string
	for k, b := range inv.Block {
		dir := b.Direction
		if dir == "" {
			dir = "src"
		}
		list, err := blockSources(b, verbose, inv.LogFilePath)
		if err != nil {
			fmt.Printf("  block   %-14s ERROR: %v\n", b.Name, err)
			failed = append(failed, b.Name)
			continue
		}
		merged := netutils.MergeIPsToCIDRs(list)
		entries := len(merged)
		if b.IsPort() {
			entries = len(merged) * len(b.Ports)
			fmt.Printf("  block   %-14s %s  drop  %d entries  set %s (hash:net,port, %s %s)  rule %d\n",
				b.Name, dir, entries, b.SetName(), joinPorts(b.Ports), b.ProtoOrDefault(), allowRuleCount(inv.Allow)+k+1)
		} else {
			fmt.Printf("  block   %-14s %s  drop  %d entries  set %s  rule %d\n",
				b.Name, dir, entries, b.SetName(), allowRuleCount(inv.Allow)+k+1)
		}
		if dir == "dst" {
			fmt.Printf("          warning: dst matches packets addressed TO these networks; make sure this host is not in them\n")
		}
	}
	fmt.Println("nothing applied (-plan)")
	if len(failed) > 0 {
		return fmt.Errorf("%d block(s) could not be planned: %s", len(failed), strings.Join(failed, ", "))
	}
	return nil
}
