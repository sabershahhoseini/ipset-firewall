package ipsetfw

import (
	"errors"
	"fmt"
	"net"
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
	"github.com/sabershahhoseini/ipset-firewall/util/sshclients"
	"github.com/sabershahhoseini/ipset-firewall/util/usermgmt"
)

// newFormat reports whether the config uses block/allow instead of rules.
func newFormat(inv file.Inventory) bool {
	return len(inv.Block) > 0 || len(inv.Allow) > 0 || len(inv.Only) > 0
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

// setRules returns every ACCEPT or DROP rule in the chain that matches a set, as fields
// ("-A CHAIN ..."), so a rule can be deleted by its own text.
func setRules(ipt *iptables.IPTables, r models.Rule) ([][]string, error) {
	lines, err := ipt.List(r.Table, r.Chain)
	if err != nil {
		return nil, err
	}
	var out [][]string
	for _, line := range lines {
		// Expected form: -A IPSET_FW [-p tcp] -m set --match-set ir-block src -j DROP
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "-A" || f[1] != r.Chain || f[len(f)-2] != "-j" {
			continue
		}
		if t := f[len(f)-1]; t != "DROP" && t != "ACCEPT" {
			continue
		}
		if matchSetName(f) == "" {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// isListSet reports whether a set name is one of ours: <name>-allow or <name>-block.
func isListSet(name string) bool {
	return strings.HasSuffix(name, "-"+kindBlock) || strings.HasSuffix(name, "-"+kindAllow)
}

// removeStaleListRules deletes rules for allow and block sets that are no longer in the config.
// The sets themselves are kept.
func removeStaleListRules(ipt *iptables.IPTables, r models.Rule, keep map[string]bool) ([]string, error) {
	rules, err := setRules(ipt, r)
	if err != nil {
		return nil, err
	}
	var stale []string
	seen := map[string]bool{}
	for _, f := range rules {
		name := matchSetName(f)
		if !isListSet(name) || keep[name] {
			continue
		}
		if err := ipt.Delete(r.Table, r.Chain, f[2:]...); err != nil {
			return nil, fmt.Errorf("removing stale rule for %s: %w", name, err)
		}
		if !seen[name] {
			seen[name] = true
			stale = append(stale, name)
		}
	}
	return stale, nil
}

// deleteRulesForSet deletes every rule in the chain that matches setName.
func deleteRulesForSet(ipt *iptables.IPTables, r models.Rule, setName string) error {
	rules, err := setRules(ipt, r)
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

// applyList updates one list's set and makes sure its rules are in the chain, and reports what
// changed. Allow rules are inserted at the top; block rules are appended, so they always come
// after every allow rule and do not depend on other lists. Mattermost hears about a list only
// when its contents changed or it failed.
func applyList(ipt *iptables.IPTables, l list, maxPercent int, mattermost file.Mattermost, logFilePath string, verbose bool) (listReport, error) {
	r := baseRule()
	b := l.entry
	name := l.setName()
	rep := listReport{Kind: l.kind, Name: b.Name, Set: name, Source: sourceText(b), Type: setTypeOf(b)}
	notifyOn := mattermost.Token != "" && mattermost.URL != ""
	fail := func(msg string, err error) (listReport, error) {
		e := fmt.Errorf("%s: %w", msg, err)
		rep.Status, rep.Error = "failed", e.Error()
		if notifyOn {
			notify(mattermost, msgPrefix()+"ERROR: "+e.Error())
		}
		return rep, e
	}

	list, err := blockSources(b, verbose, logFilePath)
	if err != nil {
		return fail(l.kind+" "+b.Name, err)
	}
	nets := netutils.MergeIPsToCIDRs(list)
	if len(nets) == 0 {
		return fail(l.kind+" "+b.Name, errors.New("no valid networks"))
	}
	entries := blockEntries(b, nets)
	onTypeChange := func() error { return deleteRulesForSet(ipt, r, name) }
	change, err := replaceSet(name, setTypeOf(b), entries, onTypeChange, maxPercent, logFilePath, verbose)
	if err != nil {
		return fail("could not update set "+name, err)
	}
	for _, args := range l.rules() {
		if l.kind == kindOnly {
			break // the allow-only chain is built as a whole by applyOnly
		}
		if l.kind == kindAllow {
			err = ipt.InsertUnique(r.Table, r.Chain, 1, args...)
		} else {
			err = ipt.AppendUnique(r.Table, r.Chain, args...)
		}
		if err != nil {
			return fail("could not add rule for "+name, err)
		}
	}

	rep.Entries, rep.Added, rep.Removed = change.Total, change.Added, change.Removed
	rep.Status = "unchanged"
	if change.changed() {
		rep.Status = "updated"
		msg := fmt.Sprintf("%sUpdated %s set %s (%s, %d entries, +%d -%d) from %s",
			msgPrefix(), l.kind, name, setTypeOf(b), change.Total, change.Added, change.Removed, sourceText(b))
		fmt.Println(msg)
		if notifyOn {
			notify(mattermost, msg)
		}
	} else {
		logger.Log(fmt.Sprintf("Set %s unchanged (%d entries)", name, change.Total), logFilePath, verbose)
	}
	return rep, nil
}

// skipped marks lists that were not attempted because an earlier list failed.
func skipped(lists []list, why string) []listReport {
	var out []listReport
	for _, l := range lists {
		out = append(out, listReport{Kind: l.kind, Name: l.entry.Name, Set: l.setName(), Source: sourceText(l.entry),
			Type: setTypeOf(l.entry), Status: "skipped", Error: why})
	}
	return out
}

// applyBlockAllow applies a block/allow config: allowed addresses and allow lists at the top, then
// allow-only, then one set and drop rule per block list. A failing block list is reported and
// skipped; the others still run. A failing allow or only list stops the run before allow-only
// and the block lists are changed. Every run ends with a summary and a saved report.
func applyBlockAllow(path string, inv file.Inventory, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	if err := inv.Validate(); err != nil {
		return err
	}
	rep := newReport("apply", path)
	hooks := newHookRunner(inv)
	if err := hooks.runBefore(rep); err != nil {
		rep.finish(err)
		hooks.onError(rep)
		if serr := rep.save(reportPath(inv)); serr != nil {
			fmt.Fprintln(os.Stderr, "warning: could not save report: "+serr.Error())
		}
		return err
	}
	runErr := applyBlockAllowRun(inv, rep, verbose)
	if inv.Persist {
		if ipt, err := iptables.New(); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not save snapshot: "+err.Error())
		} else if err := saveSnapshot(ipt, inv); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not save snapshot: "+err.Error())
		}
	}
	rep.finish(runErr)
	runErr = hooks.afterRun(inv, rep, runErr)
	hooks.onError(rep)
	fmt.Println(msgPrefix() + "Summary: " + rep.summary())
	logger.Log("Summary: "+rep.summary(), inv.LogFilePath, false)
	if err := rep.save(reportPath(inv)); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not save report: "+err.Error())
	}
	return runErr
}

// applyBlockAllowRun does the work of applyBlockAllow and fills in rep.
func applyBlockAllowRun(inv file.Inventory, rep *runReport, verbose bool) error {
	if err := configureSources(inv, false); err != nil {
		return err
	}
	if err := checkCodes(inv); err != nil {
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
	if err := onlyPrecheck(ipt, inv); err != nil {
		return err
	}
	if err := createDefaultChain(r.Chain, r.Table); err != nil {
		return err
	}
	if err := addDefaultChainIptableRule(r.Chain, r.Table, r.Parent, logFilePath, verbose); err != nil {
		return err
	}
	if err := setAllowRules(ipt, inv.AllowAddresses(), logFilePath, verbose); err != nil {
		return fmt.Errorf("allow rules: %w", err)
	}

	var failed []string
	applied := map[string]bool{}
	run := func(l list) {
		lr, err := applyList(ipt, l, maxChangeFor(inv, l), mattermost, logFilePath, verbose)
		rep.Lists = append(rep.Lists, lr)
		if err != nil {
			fmt.Fprintln(os.Stderr, l.kind+" "+l.entry.Name+" not updated: "+err.Error())
			failed = append(failed, l.kind+" "+l.entry.Name)
			return
		}
		applied[l.setName()] = true
	}
	stop := func(why string, rest ...[]list) error {
		for _, ls := range rest {
			rep.Lists = append(rep.Lists, skipped(ls, why)...)
		}
		if err := recordBlocks(inv, applied); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not write state file: "+err.Error())
		}
		return fmt.Errorf("%d list(s) not updated: %s; %s", len(failed), strings.Join(failed, ", "), why)
	}

	for _, l := range allowListsOf(inv) {
		run(l)
	}
	// A failed allow list could leave traffic meant to be allowed exposed to new rules, so
	// allow-only and the block lists are only changed when every allow list is in place.
	if len(failed) > 0 {
		return stop("allow-only and block lists left unchanged", onlyListsOf(inv), blockListsOf(inv))
	}
	for _, l := range onlyListsOf(inv) {
		run(l)
	}
	if len(failed) > 0 {
		return stop("allow-only and block lists left unchanged", blockListsOf(inv))
	}
	state, changed, err := applyOnly(ipt, inv)
	if err != nil {
		rep.Lists = append(rep.Lists, skipped(blockListsOf(inv), "allow-only failed")...)
		if rerr := recordBlocks(inv, applied); rerr != nil {
			fmt.Fprintln(os.Stderr, "warning: could not write state file: "+rerr.Error())
		}
		return fmt.Errorf("%w; block lists left unchanged", err)
	}
	rep.AllowOnly, rep.AllowOnlyChanged = state, changed

	keep := map[string]bool{}
	for _, l := range listsOf(inv) {
		keep[l.setName()] = true
	}
	stale, err := removeStaleListRules(ipt, r, keep)
	if err != nil {
		return err
	}
	rep.StaleRemoved = stale
	for _, name := range stale {
		fmt.Fprintln(os.Stderr, "removed rules for "+name+" (no longer in config); set kept, destroy it with: ipset destroy "+name)
	}

	for _, l := range blockListsOf(inv) {
		run(l)
	}
	if err := recordBlocks(inv, applied); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not write state file: "+err.Error())
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d list(s) not updated: %s", len(failed), strings.Join(failed, ", "))
	}
	return nil
}

// clearBlockAllow removes everything applyBlockAllow created, running the before and after hooks
// around it (the report is only given to hooks; last-run.json keeps describing the last apply):
// the rules in IPSET_FW, the block
// sets and their backups, the jump and the chain.
func clearBlockAllow(path string, inv file.Inventory, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	rep := newReport("clear", path)
	hooks := newHookRunner(inv)
	if err := hooks.runBefore(rep); err != nil {
		rep.finish(err)
		hooks.onError(rep)
		return err
	}
	runErr := clearBlockAllowRun(inv, verbose)
	rep.finish(runErr)
	runErr = hooks.afterRun(inv, rep, runErr)
	hooks.onError(rep)
	return runErr
}

// clearBlockAllowRun does the work of clearBlockAllow.
func clearBlockAllowRun(inv file.Inventory, verbose bool) error {
	r := baseRule()
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	if err := removeOnly(ipt); err != nil {
		return fmt.Errorf("removing allow-only: %w", err)
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
	for _, l := range allListsOf(inv) {
		if err := destroySet(l.setName()); err != nil {
			return err
		}
		if err := destroySet(l.setName() + "-bak"); err != nil {
			return err
		}
	}
	if err := removeDefaultChainIptableRule(r.Chain, r.Table, r.Parent, "", verbose, true); err != nil {
		return err
	}
	if err := removeDefaultChain(r.Chain, r.Table, "", verbose); err != nil {
		return err
	}
	if err := removeSnapshot(inv); err != nil {
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
	if err := checkCodes(inv); err != nil {
		return err
	}
	r := baseRule()
	fmt.Printf("chain %s (table %s, from %s): allow rules first, then block rules\n", r.Chain, r.Table, r.Parent)
	allows, err := canonicalAllows(inv.AllowAddresses())
	if err != nil {
		return err
	}
	for _, a := range allows {
		fmt.Printf("  allow   %-18s ACCEPT as source and destination\n", a)
	}
	var failed []string
	nets := map[string][]*net.IPNet{}
	for _, l := range allListsOf(inv) {
		b := l.entry
		list, err := blockSources(b, verbose, inv.LogFilePath)
		if err != nil {
			fmt.Printf("  %-7s %-14s ERROR: %v\n", l.kind, b.Name, err)
			failed = append(failed, l.kind+" "+b.Name)
			continue
		}
		merged := netutils.MergeIPsToCIDRs(list)
		for _, m := range merged {
			if _, n, err := net.ParseCIDR(m); err == nil {
				nets[l.setName()] = append(nets[l.setName()], n)
			}
		}
		entries := len(blockEntries(b, merged))
		dirs := strings.Join(l.directions(), "+")
		detail := ""
		if b.IsPort() {
			detail = fmt.Sprintf(" (hash:net,port, %s %s)", joinPorts(b.Ports), b.ProtoOrDefault())
		}
		fmt.Printf("  %-7s %-14s %s  %s  %d entries  set %s%s\n",
			l.kind, b.Name, dirs, strings.ToLower(l.target()), entries, l.setName(), detail)
		if l.kind == kindBlock && b.DirectionOrDefault() == "dst" {
			fmt.Printf("          warning: dst matches packets addressed TO these networks; make sure this host is not in them\n")
		}
	}
	if len(inv.Only) > 0 {
		fmt.Printf("allow-only (table %s, from %s): inbound connections not allowed by allow or only are %s\n",
			onlyTable, onlyParent, onlyActionPast(inv))
		fmt.Println("          warning: anything not listed in allow or only can no longer connect to this host")
		inPlan := func(l list, c sshclients.Client) bool {
			for _, n := range nets[l.setName()] {
				if n.Contains(c.IP) {
					return true
				}
			}
			return false
		}
		if bad := cutOffClients(inv, inPlan); len(bad) > 0 {
			fmt.Printf("          PROBLEM: SSH client %s would be cut off; apply will refuse\n", describeClients(bad))
			failed = append(failed, "allow-only")
		} else if cs := sshclients.Find(); len(cs) > 0 {
			fmt.Printf("          ok: current SSH client %s stays allowed\n", describeClients(cs))
		}
	}
	if n := describeHooks(inv); n > 0 {
		failed = append(failed, fmt.Sprintf("%d hook problem(s)", n))
	}
	fmt.Println("nothing applied (-plan)")
	if len(failed) > 0 {
		return fmt.Errorf("%d block(s) could not be planned: %s", len(failed), strings.Join(failed, ", "))
	}
	return nil
}
