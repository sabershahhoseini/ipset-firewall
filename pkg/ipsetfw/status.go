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

// StatusConfig shows the live state of each block and the allow rules. It changes nothing and downloads nothing.
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
	fmt.Printf("chain %s (table %s, from %s): %d allow rule(s)\n", r.Chain, r.Table, r.Parent, len(allows))
	for _, b := range inv.Block {
		name := b.SetName()
		live := "set missing"
		if info, err := ipset.List(name); err == nil {
			live = fmt.Sprintf("%d entries, %s", info.NumEntries, info.TypeName)
		}
		rule := "missing"
		if ok, err := ipt.Exists(r.Table, r.Chain, blockMatchArgs(b, name)...); err == nil && ok {
			rule = "ok"
		}
		updated := "never"
		if bs, ok := st.Blocks[name]; ok {
			updated = bs.Updated.Local().Format("2006-01-02 15:04") + " (" + bs.Source + ")"
		}
		fmt.Printf("block  %-14s %-18s %-26s rule %-8s updated %s\n", b.Name, name, live, rule, updated)
	}
	return nil
}

// normalizeAddr writes a host address as iptables prints it: 1.2.3.4 becomes 1.2.3.4/32.
func normalizeAddr(a string) string {
	if !strings.Contains(a, "/") {
		return a + "/32"
	}
	return a
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

	// Allow rules: exactly the configured addresses, as source and destination.
	want := map[string]bool{}
	for _, a := range dedupe(inv.Allow) {
		want["-s "+normalizeAddr(a)] = true
		want["-d "+normalizeAddr(a)] = true
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

	// Ordering: every allow must come before the first drop.
	lastAllow, firstDrop := -1, -1
	for i, line := range lines {
		if strings.HasSuffix(line, "-j ACCEPT") {
			lastAllow = i
		}
		if strings.HasSuffix(line, "-j DROP") && firstDrop < 0 {
			firstDrop = i
		}
	}
	if firstDrop >= 0 && lastAllow > firstDrop {
		bad("an allow rule comes after a drop rule")
	} else {
		ok("allow rules come before drop rules")
	}

	// Block entries: set type and drop rule.
	keep := map[string]bool{}
	for _, b := range inv.Block {
		name := b.SetName()
		keep[name] = true
		info, err := ipset.List(name)
		if err != nil {
			bad("set " + name + " missing")
		} else if info.TypeName != setTypeOf(b) {
			bad(fmt.Sprintf("set %s is %s, config wants %s", name, info.TypeName, setTypeOf(b)))
		} else {
			ok(fmt.Sprintf("set %s (%s, %d entries)", name, info.TypeName, info.NumEntries))
		}
		if exists, err := ipt.Exists(r.Table, r.Chain, blockMatchArgs(b, name)...); err != nil || !exists {
			bad("drop rule for " + name + " missing")
		} else {
			ok("drop rule for " + name)
		}
	}

	// Stale drop rules for block sets no longer in the config.
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "-A" || f[len(f)-2] != "-j" || f[len(f)-1] != "DROP" {
			continue
		}
		name := matchSetName(f)
		if strings.HasSuffix(name, "-block") && !keep[name] {
			bad("stale drop rule for " + name + " (not in config)")
		}
	}

	if problems > 0 {
		return fmt.Errorf("%d problem(s) found", problems)
	}
	fmt.Println("all checks passed")
	return nil
}
