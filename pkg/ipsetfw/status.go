package ipsetfw

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/lrh3321/ipset-go"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/usermgmt"
)

// readBlockAllowConfig loads a config that uses the block/allow format.
func readBlockAllowConfig(path string) (file.Inventory, error) {
	inv := file.DecodeConfig(file.ReadConfigFile(path))
	if !newFormat(inv) {
		return inv, fmt.Errorf("status and verify support the block/allow format only")
	}
	return inv, inv.Validate()
}

// rulesPresent reports whether every rule of a list is in the chain.
func rulesPresent(ipt *iptables.IPTables, l list) bool {
	for _, args := range l.rules() {
		if ok, err := ipt.Exists(l.table(), l.chain(), args...); err != nil || !ok {
			return false
		}
	}
	return true
}

// StatusConfig shows the live state of each list and the allowed addresses. It changes nothing
// and downloads nothing.
func StatusConfig(path string, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	inv, err := readBlockAllowConfig(path)
	if err != nil {
		return err
	}
	st, err := loadState(statePath(inv))
	if err != nil {
		return err
	}
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	r := baseRule()
	allows, err := allowRulesIn(ipt, r)
	if err != nil {
		return err
	}
	fmt.Printf("chain %s (table %s, from %s): %d allowed-address rule(s)\n", r.Chain, r.Table, r.Parent, len(allows))
	if len(inv.Only) > 0 {
		state := "NOT installed"
		if installed, err := onlyInstalled(ipt); err == nil && installed {
			state = "active, others " + onlyActionPast(inv)
		}
		fmt.Printf("allow-only %s (table %s, from %s): %s\n", onlyChain, onlyTable, onlyParent, state)
	}
	for _, l := range allListsOf(inv) {
		name := l.setName()
		live := "set missing"
		if info, err := ipset.List(name); err == nil {
			live = fmt.Sprintf("%d entries, %s", info.NumEntries, info.TypeName)
		}
		rule := "missing"
		if rulesPresent(ipt, l) {
			rule = "ok"
		}
		updated := "never"
		if bs, ok := st.Blocks[name]; ok {
			updated = bs.Updated.Local().Format("2006-01-02 15:04") + " (" + bs.Source + ")"
		}
		fmt.Printf("%-6s %-14s %-18s %-26s rule %-8s updated %s\n", l.kind, l.entry.Name, name, live, rule, updated)
	}
	return nil
}

// VerifyConfig compares the live firewall with the config and reports every difference.
// It returns an error if anything differs. It downloads nothing.
func VerifyConfig(path string, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	inv, err := readBlockAllowConfig(path)
	if err != nil {
		return err
	}
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	r := baseRule()
	var problems int
	ok := func(msg string) { fmt.Println("ok       " + msg) }
	bad := func(msg string) { problems++; fmt.Println("PROBLEM  " + msg) }

	if jumped, err := ipt.Exists(r.Table, r.Parent, "-j", r.Chain); err != nil || !jumped {
		bad(fmt.Sprintf("jump from %s to %s missing", r.Parent, r.Chain))
	} else {
		ok(fmt.Sprintf("jump from %s to %s", r.Parent, r.Chain))
	}
	lines, err := ipt.List(r.Table, r.Chain)
	if err != nil {
		bad("chain " + r.Chain + " missing")
		return fmt.Errorf("%d problem(s) found", problems)
	}

	// Allowed addresses: exactly the configured ones, as source and destination.
	allows, err := canonicalAllows(inv.AllowAddresses())
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, a := range allows {
		want["-s "+a] = true
		want["-d "+a] = true
	}
	have, err := allowRulesIn(ipt, r)
	if err != nil {
		return err
	}
	haveSet := map[string]bool{}
	for _, a := range have {
		haveSet[a.flag+" "+a.addr] = true
	}
	for k := range want {
		if haveSet[k] {
			ok("allow " + k)
		} else {
			bad("allow " + k + " missing")
		}
	}
	for k := range haveSet {
		if !want[k] {
			bad("unexpected allow " + k)
		}
	}

	// Ordering: every ACCEPT rule must come before the first DROP rule.
	lastAccept, firstDrop := -1, -1
	for i, line := range lines {
		if strings.HasSuffix(line, "-j ACCEPT") {
			lastAccept = i
		}
		if strings.HasSuffix(line, "-j DROP") && firstDrop < 0 {
			firstDrop = i
		}
	}
	if firstDrop >= 0 && lastAccept > firstDrop {
		bad("an allow rule comes after a drop rule")
	} else {
		ok("allow rules come before drop rules")
	}

	// Lists: set type and rules.
	keep := map[string]bool{}
	for _, l := range allListsOf(inv) {
		name := l.setName()
		keep[name] = true
		info, err := ipset.List(name)
		if err != nil {
			bad(l.kind + " set " + name + " missing")
		} else if info.TypeName != setTypeOf(l.entry) {
			bad(fmt.Sprintf("%s set %s is %s, config wants %s", l.kind, name, info.TypeName, setTypeOf(l.entry)))
		} else {
			ok(fmt.Sprintf("%s set %s (%s, %d entries)", l.kind, name, info.TypeName, info.NumEntries))
		}
		for _, args := range l.rules() {
			if exists, err := ipt.Exists(l.table(), l.chain(), args...); err != nil || !exists {
				bad(l.kind + " rule missing: " + strings.Join(args, " "))
			} else {
				ok(l.kind + " rule " + strings.Join(args, " "))
			}
		}
	}

	// Allow-only: installed exactly as the config describes it, or not at all.
	if len(inv.Only) > 0 {
		if installed, err := onlyInstalled(ipt); err != nil || !installed {
			bad(fmt.Sprintf("allow-only is in the config but %s does not jump to %s", onlyParent, onlyChain))
		} else {
			ok(fmt.Sprintf("jump from %s to %s", onlyParent, onlyChain))
			want, err := expectedOnlyLines(inv)
			if err != nil {
				return err
			}
			got, err := ipt.List(onlyTable, onlyChain)
			if err != nil {
				return err
			}
			if strings.Join(got, "\n") == strings.Join(want, "\n") {
				ok(fmt.Sprintf("allow-only chain matches the config (%d rules)", len(want)-1))
			} else {
				bad("allow-only chain differs from the config")
				for i := 0; i < len(want) || i < len(got); i++ {
					var w, g string
					if i < len(want) {
						w = want[i]
					}
					if i < len(got) {
						g = got[i]
					}
					if w != g {
						fmt.Printf("           want: %s\n           have: %s\n", w, g)
						break
					}
				}
			}
		}
	} else if exists, err := ipt.ChainExists(onlyTable, onlyChain); err == nil && exists {
		bad("allow-only chain " + onlyChain + " exists but the config has no only")
	}

	// Rules for allow or block sets that are no longer in the config.
	rules, err := setRules(ipt, r)
	if err != nil {
		return err
	}
	for _, f := range rules {
		name := matchSetName(f)
		if isListSet(name) && !keep[name] {
			bad("stale rule for " + name + " (not in config)")
		}
	}

	if problems > 0 {
		return fmt.Errorf("%d problem(s) found", problems)
	}
	fmt.Println("all checks passed")
	return nil
}
