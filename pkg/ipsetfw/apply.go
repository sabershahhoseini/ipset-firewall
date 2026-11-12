package ipsetfw

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

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

// allowRulesIn returns the ACCEPT rules currently in the chain, addresses as iptables prints them.
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

// canonicalAllows returns the allow entries in the form iptables prints them, without duplicates.
func canonicalAllows(allows []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, a := range allows {
		c, err := file.CanonicalAddr(a)
		if err != nil {
			return nil, err
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// setAllowRules makes the chain's allow rules match the config. Each address is allowed as
// source and destination. Missing rules are added at the top first, and only then are rules
// that left the config removed, so a configured address is never without its allow rule.
func setAllowRules(ipt *iptables.IPTables, allows []string, logFilePath string, verbose bool) error {
	r := baseRule()
	want, err := canonicalAllows(allows)
	if err != nil {
		return err
	}
	wantSet := map[string]bool{}
	for _, a := range want {
		wantSet["-s "+a] = true
		wantSet["-d "+a] = true
	}
	have, err := allowRulesIn(ipt, r)
	if err != nil {
		return err
	}
	haveSet := map[string]bool{}
	for _, h := range have {
		haveSet[h.flag+" "+h.addr] = true
	}

	for _, a := range want {
		for _, flag := range []string{"-s", "-d"} {
			if haveSet[flag+" "+a] {
				continue
			}
			logger.Log("Allowing "+flag+" "+a, logFilePath, verbose)
			if err := ipt.Insert(r.Table, r.Chain, 1, flag, a, "-j", "ACCEPT"); err != nil {
				return fmt.Errorf("allow %s %s: %w", flag, a, err)
			}
		}
	}
	for _, h := range have {
		if wantSet[h.flag+" "+h.addr] {
			continue
		}
		logger.Log("Removing allow "+h.flag+" "+h.addr, logFilePath, verbose)
		if err := ipt.Delete(r.Table, r.Chain, h.flag, h.addr, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("removing allow %s %s: %w", h.flag, h.addr, err)
		}
	}
	return nil
}

// dropRules returns, for every DROP rule in the chain, the set it matches and its rule
// arguments (without "-A CHAIN"), so the rule can be deleted by its own text.
func dropRules(ipt *iptables.IPTables, r models.Rule) ([][]string, error) {
	lines, err := ipt.List(r.Table, r.Chain)
	if err != nil {
		return nil, err
	}
	var out [][]string
	for _, line := range lines {
		// Expected form: -A IPSET_FW [-p tcp] -m set --match-set ir-block src -j DROP
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "-A" || f[1] != r.Chain || f[len(f)-2] != "-j" || f[len(f)-1] != "DROP" {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// removeStaleBlockRules deletes drop rules for "-block" sets that are no longer in the config.
// The sets themselves are kept.
func removeStaleBlockRules(ipt *iptables.IPTables, r models.Rule, keep map[string]bool) ([]string, error) {
	rules, err := dropRules(ipt, r)
	if err != nil {
		return nil, err
	}
	var stale []string
	for _, f := range rules {
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

// deleteRulesForSet deletes every drop rule in the chain that matches setName.
func deleteRulesForSet(ipt *iptables.IPTables, r models.Rule, setName string) error {
	rules, err := dropRules(ipt, r)
	if err != nil {
		return err
	}
	for _, f := range rules {
		if matchSetName(f) != setName {
			continue
		}
		if err := ipt.Delete(r.Table, r.Chain, f[2:]...); err != nil {
			return fmt.Errorf("removing rule for %s: %w", setName, err)
		}
	}
	return nil
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

// msgPrefix starts every notification: time and host name.
func msgPrefix() string {
	host, _ := os.Hostname()
	return time.Now().Format("2006-01-02 15:04:05") + " HOST: " + host + " --- "
}

// blockEntries builds the set entries for one block entry from its merged networks.
func blockEntries(b file.BlockEntry, nets []string) []ipset.Entry {
	if b.IsPort() {
		return portEntries(nets, b.Ports, b.ProtoOrDefault())
	}
	return netEntries(nets)
}

// applyBlock updates one block's set and makes sure its drop rule is in the chain. The rule is
// appended, so it always comes after the allow rules and does not depend on other blocks.
func applyBlock(ipt *iptables.IPTables, b file.BlockEntry, mattermost file.Mattermost, logFilePath string, verbose bool) error {
	r := baseRule()
	name := b.SetName()
	notifyOn := mattermost.Token != "" && mattermost.URL != ""
	fail := func(msg string, err error) error {
		if notifyOn {
			notify(mattermost, msgPrefix()+"ERROR: "+msg+": "+err.Error())
		}
		return fmt.Errorf("%s: %w", msg, err)
	}

	list, err := blockSources(b, verbose, logFilePath)
	if err != nil {
		return fail("block "+b.Name, err)
	}
	nets := netutils.MergeIPsToCIDRs(list)
	if len(nets) == 0 {
		return fail("block "+b.Name, errors.New("no valid networks"))
	}
	entries := blockEntries(b, nets)
	onTypeChange := func() error { return deleteRulesForSet(ipt, r, name) }
	if err := replaceSet(name, setTypeOf(b), entries, onTypeChange, logFilePath, verbose); err != nil {
		return fail("could not update set "+name, err)
	}
	if err := ipt.AppendUnique(r.Table, r.Chain, blockMatchArgs(b, name)...); err != nil {
		return fail("could not add drop rule for "+name, err)
	}

	msg := fmt.Sprintf("%sUpdated set %s (%s, %d entries) from %s", msgPrefix(), name, setTypeOf(b), len(entries), sourceText(b))
	fmt.Println(msg)
	if notifyOn {
		notify(mattermost, msg)
	}
	return nil
}

// applyBlockAllow applies a block/allow config: allow rules at the top, then one set and drop rule
// per block entry. A failing block is reported and skipped; the others still run.
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
	if err := setAllowRules(ipt, inv.Allow, logFilePath, verbose); err != nil {
		return fmt.Errorf("allow rules: %w", err)
	}

	keep := map[string]bool{}
	for _, b := range inv.Block {
		keep[b.SetName()] = true
	}
	stale, err := removeStaleBlockRules(ipt, r, keep)
	if err != nil {
		return err
	}
	for _, name := range stale {
		fmt.Fprintln(os.Stderr, "removed rule for "+name+" (no longer in config); set kept, destroy it with: ipset destroy "+name)
	}

	var failed []string
	applied := map[string]bool{}
	for _, b := range inv.Block {
		if err := applyBlock(ipt, b, mattermost, logFilePath, verbose); err != nil {
			fmt.Fprintln(os.Stderr, "block "+b.Name+" not updated: "+err.Error())
			failed = append(failed, b.Name)
			continue
		}
		applied[b.SetName()] = true
	}
	if err := recordBlocks(inv, applied); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not write state file: "+err.Error())
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d block(s) not updated: %s", len(failed), strings.Join(failed, ", "))
	}
	return nil
}

// clearBlockAllow removes everything applyBlockAllow created: the rules in IPSET_FW, the block
// sets and their backups, the jump and the chain.
func clearBlockAllow(inv file.Inventory, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	r := baseRule()
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	// IPSET_FW belongs to this tool, so clearing the whole chain is safe. It also drops every
	// reference to the block sets, so they can be destroyed.
	if exists, err := ipt.ChainExists(r.Table, r.Chain); err != nil {
		return err
	} else if exists {
		if err := ipt.ClearChain(r.Table, r.Chain); err != nil {
			return fmt.Errorf("clearing %s: %w", r.Chain, err)
		}
	}
	for _, b := range inv.Block {
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
	if err := removeDefaultChain(r.Chain, r.Table, "", verbose); err != nil {
		return err
	}
	return forgetBlocks(inv)
}

// PlanConfig prints what applying a block/allow config would do. It changes no sets, iptables
// rules or cache files. It uses the mirror and cached copies like a real run does.
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
	allows, err := canonicalAllows(inv.Allow)
	if err != nil {
		return err
	}
	for _, a := range allows {
		fmt.Printf("  allow   %-18s ACCEPT as source and destination\n", a)
	}
	var failed []string
	for _, b := range inv.Block {
		dir := b.DirectionOrDefault()
		list, err := blockSources(b, verbose, inv.LogFilePath)
		if err != nil {
			fmt.Printf("  block   %-14s ERROR: %v\n", b.Name, err)
			failed = append(failed, b.Name)
			continue
		}
		nets := netutils.MergeIPsToCIDRs(list)
		entries := len(blockEntries(b, nets))
		if b.IsPort() {
			fmt.Printf("  block   %-14s %s  drop  %d entries  set %s (hash:net,port, %s %s)\n",
				b.Name, dir, entries, b.SetName(), joinPorts(b.Ports), b.ProtoOrDefault())
		} else {
			fmt.Printf("  block   %-14s %s  drop  %d entries  set %s\n", b.Name, dir, entries, b.SetName())
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
