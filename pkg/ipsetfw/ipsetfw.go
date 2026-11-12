package ipsetfw

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/sabershahhoseini/ipset-firewall/error/checkerr"
	"github.com/sabershahhoseini/ipset-firewall/models"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/logger"
	"github.com/sabershahhoseini/ipset-firewall/util/netutils"
	"github.com/sabershahhoseini/ipset-firewall/util/notif"
	"github.com/sabershahhoseini/ipset-firewall/util/usermgmt"

	"github.com/lrh3321/ipset-go"
)

func removeDefaultChain(chainName string, tableName string, logFilePath string, verbose bool) error {
	if isBuiltinChain(chainName) {
		return nil
	}
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	chainExists, err := ipt.ChainExists(tableName, chainName)
	if err != nil {
		return err
	}
	if !chainExists {
		logger.Log("Chain "+chainName+" does not exist. Already cleared?", logFilePath, verbose)
		return nil
	}
	logger.Log("Removing chain "+chainName, logFilePath, verbose)
	if err := ipt.DeleteChain(tableName, chainName); err != nil {
		return err
	}
	logger.Log("Removed chain "+chainName, logFilePath, verbose)
	return nil
}

// removeDefaultChainIptableRule removes the jump from parentChain to chainName.
func removeDefaultChainIptableRule(chainName string, tableName string, parentChain string, logFilePath string, verbose bool, clear bool) error {
	if isBuiltinChain(chainName) {
		return nil
	}
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	logger.Log("Removing jump from "+parentChain+" to chain "+chainName, logFilePath, verbose)
	err = ipt.Delete(tableName, parentChain, "-j", chainName)
	if err != nil {
		if strings.Contains(err.Error(), "does a matching rule exist in that chain") {
			if clear {
				logger.Log("Jump from "+parentChain+" to "+chainName+" not found. Already cleared?", logFilePath, verbose)
			}
			return nil
		}
		return err
	}
	logger.Log("Removed iptables rule", logFilePath, verbose)
	return nil
}

func createDefaultChain(chainName string, tableName string) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	chainExists, err := ipt.ChainExists(tableName, chainName)
	if err != nil {
		return err
	}
	if !chainExists {
		err = ipt.NewChain(tableName, chainName)
		if err != nil {
			return err
		}
	}
	return nil
}

// isBuiltinChain reports whether c is a chain that always exists and must never be created or deleted.
func isBuiltinChain(c string) bool {
	switch c {
	case "INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING":
		return true
	}
	return false
}

// applyRuleDefaults fills in the table, chain, insert position and parent chain of a rule.
func applyRuleDefaults(r *models.Rule) {
	if r.Table == "" {
		r.Table = "raw"
	}
	if r.Chain == "" {
		r.Chain = "IPSET_FW"
	}
	if r.Insert < 1 {
		r.Insert = 1
	}
	if r.Parent == "" {
		if r.Table == "raw" {
			r.Parent = "PREROUTING"
		} else {
			r.Parent = "INPUT"
		}
	}
}

// addDefaultChainIptableRule adds a jump from parentChain to chainName. It does nothing for builtin chains.
func addDefaultChainIptableRule(chainName string, tableName string, parentChain string, logFilePath string, verbose bool) error {
	if isBuiltinChain(chainName) {
		return nil
	}
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	logger.Log("Adding iptables rule to jump from "+parentChain+" to chain "+chainName, logFilePath, verbose)
	return ipt.InsertUnique(tableName, parentChain, 1, "-j", chainName)
}

// addIptableRule adds the set match rule to rule.Chain in rule.Table.
func addIptableRule(rule models.Rule, setName string, logFilePath string, verbose bool) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	rulePolicy := strings.ToUpper(rule.Policy)

	if len(rule.Type) == 0 {
		rule.Type = append(rule.Type, "src")
	}
	for _, ruleType := range rule.Type {

		if rule.Not {
			err = ipt.InsertUnique(rule.Table, rule.Chain, rule.Insert, "-m", "set", "!", "--match-set", setName, ruleType, "-j", rulePolicy)
		} else {
			err = ipt.InsertUnique(rule.Table, rule.Chain, rule.Insert, "-m", "set", "--match-set", setName, ruleType, "-j", rulePolicy)
		}
		logger.Log("Adding iptables rule to chain "+rule.Chain+" and set "+setName, logFilePath, verbose)
		if err != nil {
			return err
		}
	}
	return nil
}

func removeIptableRule(rule models.Rule, setName string, chainName string, logFilePath string, verbose bool, clear bool) error {
	actions := []string{"DROP", "ACCEPT"}
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	if len(rule.Type) == 0 {
		rule.Type = append(rule.Type, "src")
	}

	logger.Log("Removing iptables rule to chain "+chainName+" and set "+setName, logFilePath, verbose)

	for _, ruleType := range rule.Type {
		for _, terminateAction := range actions {
			var delErr error
			if rule.Not {
				delErr = ipt.Delete(rule.Table, chainName, "-m", "set", "!", "--match-set", setName, ruleType, "-j", terminateAction)
			} else {
				delErr = ipt.Delete(rule.Table, chainName, "-m", "set", "--match-set", setName, ruleType, "-j", terminateAction)
			}
			if delErr == nil {
				continue
			}
			// Not found: this action/type was never added (or is already gone). Keep trying the rest.
			if strings.Contains(delErr.Error(), "does a matching rule exist in that chain") ||
				strings.Contains(delErr.Error(), "Set "+setName+" doesn't exist") {
				if clear {
					logger.Log("Rule not found. Already cleared?", logFilePath, verbose)
				}
				continue
			}
			return delErr
		}
	}
	logger.Log("Removed iptables rule", logFilePath, verbose)
	return nil
}

func parseIPAndCIDR(ip string) (net.IP, uint8) {
	parsedIP, _, _ := net.ParseCIDR(ip)
	cidr := strings.Split(string(ip), "/")
	cidrInt, _ := strconv.Atoi(cidr[1])
	cidr8 := uint8(cidrInt)
	return parsedIP, cidr8
}

func convertIPToEntry(ip string) ipset.Entry {
	ipNet, cidr := parseIPAndCIDR(ip)
	entry := ipset.Entry{
		IP:   ipNet,
		CIDR: cidr,
	}
	return entry
}
func RollbackSet(setName string) {
	backupSetName := setName + "-bak"
	if _, err := ipset.List(backupSetName); err != nil {
		fmt.Fprintln(os.Stderr, "no backup for "+setName+" yet: a backup is kept from the second update on")
		os.Exit(1)
	}
	err := ipset.Swap(backupSetName, setName)
	checkerr.Fatal(err)
	fmt.Println("Successfully rolled back set " + setName + " with backup set " + backupSetName)
}

func ListAllSets(verbose bool) {
	sets, err := ipset.ListAll()
	checkerr.Fatal(err)
	for _, s := range sets {
		if s.NumEntries == 0 {
			continue
		}
		set, err := ipset.List(s.SetName)
		checkerr.Fatal(err)
		fmt.Printf("Set Name: %v\n", set.SetName)
		fmt.Printf("Entries: %v\n", set.NumEntries)
		fmt.Printf("References: %v\n", set.References)
		if verbose {
			fmt.Printf("\nEntries list:\n")
			for _, entry := range set.Entries {
				fmt.Println(entry.IP.String() + "/" + strconv.Itoa(int(entry.CIDR)))
			}
		}
		fmt.Println()
	}
}

func ListSet(setName string, verbose bool) {
	set, err := ipset.List(setName)
	if err != nil {
		if !strings.Contains(err.Error(), "no such file or directory") {
			checkerr.Fatal(err)
		}
		fmt.Println("Set " + setName + " does not exist")
		return
	}
	fmt.Printf("Set Name: %v\n", set.SetName)
	fmt.Printf("Entries: %v\n", set.NumEntries)
	fmt.Printf("References: %v\n", set.References)
	if verbose {
		fmt.Printf("\nEntries list:\n")
		for _, entry := range set.Entries {
			fmt.Println(entry.IP.String() + "/" + strconv.Itoa(int(entry.CIDR)))
		}
	}
	fmt.Println()

}

func IPsetfw(ipList []string, setModel models.Set, iptables bool,
	rule models.Rule, mattermost file.Mattermost, logFilePath string, verbose bool) error {
	setName := setModel.SetName
	countryCode := setModel.Country

	applyRuleDefaults(&rule)
	if iptables {
		switch strings.ToLower(rule.Policy) {
		case "accept", "drop":
		default:
			return fmt.Errorf("refusing to update set %s: iptables policy must be accept or drop, got %q", setName, rule.Policy)
		}
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	notifyMattermost := mattermost.Token != "" && mattermost.URL != ""
	notifMsgInfo := time.Now().Format("2006-01-02 15:04:05") + " HOST: " + hostname + " --- "

	// fail reports the error to Mattermost (best effort) and returns it.
	fail := func(msg string, err error) error {
		if notifyMattermost {
			notify(mattermost, notifMsgInfo+"ERROR: "+msg)
		}
		return fmt.Errorf("%s: %w", msg, err)
	}

	ipListMerged := netutils.MergeIPsToCIDRs(ipList)
	if len(ipListMerged) == 0 {
		return fail("refusing to update set "+setName, errors.New("no valid networks"))
	}

	if iptables && !isBuiltinChain(rule.Chain) {
		if err := createDefaultChain(rule.Chain, rule.Table); err != nil {
			return fail("could not create chain "+rule.Chain, err)
		}
	}

	if _, err := replaceSet(setName, "hash:net", netEntries(ipListMerged), nil, logFilePath, verbose); err != nil {
		return fail("could not update set "+setName, err)
	}

	if iptables {
		if err := addDefaultChainIptableRule(rule.Chain, rule.Table, rule.Parent, logFilePath, verbose); err != nil {
			return fail("could not add jump from "+rule.Parent+" to chain "+rule.Chain, err)
		}
		if err := addIptableRule(rule, setName, logFilePath, verbose); err != nil {
			return fail("could not add iptables rule for set "+setName+" - chain "+rule.Chain, err)
		}
	}

	msg := notifMsgInfo + "Successfully created set " + setName + " for country " +
		countryCode + " with " + strconv.Itoa(len(ipListMerged)) + " number of entries!"
	fmt.Println(msg)
	notify(mattermost, msg)
	return nil
}

// notify sends a Mattermost message on a best-effort basis; failures are only printed.
func notify(m file.Mattermost, msg string) {
	if err := notif.SendNotificationMattermost(msg, m.URL, m.Token); err != nil {
		fmt.Fprintln(os.Stderr, "warning: "+err.Error())
	}
}

// fetchRuleList returns the combined networks for one config rule, from its files or from GitHub.
func fetchRuleList(r file.Rule, verbose bool, logFilePath string) ([]string, error) {
	if len(r.Path) == 0 {
		return netutils.FetchIPPool(r.Country, verbose, "", logFilePath)
	}
	var ipList []string
	for _, path := range r.Path {
		fetched, err := netutils.FetchIPPool(r.Country, verbose, path, logFilePath)
		if err != nil {
			return nil, err
		}
		ipList = append(ipList, fetched...)
	}
	return ipList, nil
}

// LoopConfigFile applies every rule in the config. A failing rule is reported and skipped;
// the others still run. An error is returned at the end if any rule failed.
func LoopConfigFile(path string, iptables bool, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	configString := file.ReadConfigFile(path)
	inventory := file.DecodeConfig(configString)
	if err := inventory.Validate(); err != nil {
		return err
	}
	if newFormat(inventory) {
		return applyBlockAllow(path, inventory, verbose)
	}
	if err := configureSources(inventory, false); err != nil {
		return err
	}
	logFilePath := inventory.LogFilePath
	var mattermost file.Mattermost
	if inventory.Mattermost.Token != "" && inventory.Mattermost.URL != "" {
		mattermost = inventory.Mattermost
	}

	var failedSets []string
	for _, r := range inventory.IPSetRules {
		set := models.Set{
			Country: r.Country,
			SetName: r.SetName,
		}
		rule := models.Rule{
			Policy: r.IPtables.Policy,
			Insert: r.IPtables.Insert,
			Type:   r.IPtables.Type,
			Chain:  r.IPtables.Chain,
			Parent: r.IPtables.Parent,
			Table:  r.IPtables.Table,
			Not:    r.IPtables.Not,
		}
		// iptables rules are only added for rules that have a policy.
		useIptables := r.IPtables.Policy != ""

		ipList, err := fetchRuleList(r, verbose, logFilePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "set "+set.SetName+" not updated: "+err.Error())
			failedSets = append(failedSets, set.SetName)
			continue
		}
		ipList = append(ipList, r.ExtraIPs...)

		if err := IPsetfw(ipList, set, useIptables, rule, mattermost, logFilePath, verbose); err != nil {
			fmt.Fprintln(os.Stderr, "set "+set.SetName+" not updated: "+err.Error())
			failedSets = append(failedSets, set.SetName)
		}
	}
	if len(failedSets) > 0 {
		return fmt.Errorf("%d set(s) not updated: %s", len(failedSets), strings.Join(failedSets, ", "))
	}
	return nil
}

func LoopConfigFileClear(path string, iptables bool, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	configString := file.ReadConfigFile(path)
	inventory := file.DecodeConfig(configString)
	if newFormat(inventory) {
		return clearBlockAllow(path, inventory, verbose)
	}

	// Each distinct (table, chain, parent) jump is removed once, after all sets are gone.
	type jumpKey struct{ table, chain, parent string }
	seen := map[jumpKey]bool{}
	var jumps []jumpKey

	for _, r := range inventory.IPSetRules {
		setName := r.SetName
		rule := models.Rule{
			Policy: r.IPtables.Policy,
			Insert: r.IPtables.Insert,
			Type:   r.IPtables.Type,
			Chain:  r.IPtables.Chain,
			Table:  r.IPtables.Table,
			Not:    r.IPtables.Not,
			Parent: r.IPtables.Parent,
		}
		applyRuleDefaults(&rule)

		useIptables := iptables || r.IPtables.Policy != ""
		if useIptables {
			if err := removeIptableRule(rule, setName, rule.Chain, "", verbose, true); err != nil {
				return err
			}
			time.Sleep(100 * time.Millisecond)
			k := jumpKey{rule.Table, rule.Chain, rule.Parent}
			if !seen[k] {
				seen[k] = true
				jumps = append(jumps, k)
			}
		}

		// Destroy the set and its backup. Only "does not exist" is ignored.
		if err := ipset.Destroy(setName); err != nil && !errors.Is(err, syscall.ENOENT) {
			return err
		}
		if err := ipset.Destroy(setName + "-bak"); err != nil && !errors.Is(err, syscall.ENOENT) {
			return err
		}
	}

	for _, k := range jumps {
		if err := removeDefaultChainIptableRule(k.chain, k.table, k.parent, "", verbose, true); err != nil {
			return err
		}
		if err := removeDefaultChain(k.chain, k.table, "", verbose); err != nil {
			return err
		}
	}
	return nil
}
