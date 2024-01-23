package ipsetfw

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
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
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	logger.Log("Removing default chain "+chainName, logFilePath, verbose)
	chainExists, err := ipt.ChainExists(tableName, chainName)
	if err != nil {
		return err
	}
	if chainExists {
		err = ipt.DeleteChain(tableName, chainName)
		if err != nil {
			return err
		}
	}
	logger.Log("Chain "+chainName+" does not exist. Already cleared?", logFilePath, verbose)
	return nil
}

func removeDefaultChainIptableRule(chainName string, tableName string, logFilePath string, verbose bool, clear bool) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	logger.Log("Removing iptables rule to for default chain "+chainName, logFilePath, verbose)
	if chainName != "INPUT" {
		err = ipt.Delete(tableName, "INPUT", "-j", chainName)
		if err != nil {
			if strings.Contains(err.Error(), "does a matching rule exist in that chain") {
				if clear {
					logger.Log("Chain "+chainName+" does not exist. Already cleared?", logFilePath, verbose)
				}
				return nil
			}
		}
		if err != nil {
			return err
		}
		logger.Log("Removed iptables rule", logFilePath, verbose)
	}
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
func addDefaultChainIptableRule(chainName string, tableName string, logFilePath string, verbose bool) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	logger.Log("Adding iptables rule to for default chain "+chainName, logFilePath, verbose)
	if chainName != "INPUT" {
		err = ipt.InsertUnique(tableName, "INPUT", 1, "-j", chainName)
		if err != nil {
			return err
		}
	}
	return nil
}

func addIptableRule(rule models.Rule, setName string, chainName string, logFilePath string, verbose bool) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	rulePolicy := strings.ToUpper(rule.Policy)

	for _, ruleType := range rule.Type {
		logger.Log("Adding iptables rule to chain "+chainName+" and set "+setName, logFilePath, verbose)
		err = ipt.InsertUnique(rule.Table, chainName, rule.Insert, "-m", "set", "--match-set", setName, ruleType, "-j", rulePolicy)
		if err != nil {
			return err
		}
	}
	return nil
}

func removeIptableRule(rule models.Rule, setName string, chainName string, logFilePath string, verbose bool, clear bool) error {
	var actions []string
	actions = []string{"DROP", "ACCEPT"}
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	logger.Log("Removing iptables rule to chain "+chainName+" and set "+setName, logFilePath, verbose)

	for _, ruleType := range rule.Type {
		for _, terminateAction := range actions {
			err = ipt.Delete(rule.Table, chainName, "-m", "set", "--match-set", setName, ruleType, "-j", terminateAction)
			if err != nil {
				if strings.Contains(err.Error(), "does a matching rule exist in that chain") {
					return nil
				} else if strings.Contains(err.Error(), "Set "+setName+" doesn't exist") {
					if clear {
						logger.Log("Rule not found. Already cleared?", logFilePath, verbose)
					}
					return nil
				}
				if err != nil {
					return err
				}
			}
		}
	}
	logger.Log("Removed iptables rule", logFilePath, verbose)
	return nil
}

func convertIPListToRestoreFile(ipList []string, prefixString string, logFilePath string, verbose bool) []string {
	var convertedIpList []string
	for _, ip := range ipList {
		tmpIP, isValid := netutils.IsCIDRValid(ip)
		if !isValid {
			continue
		}
		ip = tmpIP
		if verbose {
			logger.Log("Adding "+ip, logFilePath, verbose)
		}
		convertedIpList = append(convertedIpList, prefixString+" "+ip)
	}
	return convertedIpList
}

func includeExtraIPs(ipList []string, extraIPs []string) []string {
	for _, ip := range extraIPs {
		ipList = append(ipList, ip)
	}
	return ipList
}
func parseIPAndCIDR(ip string) (net.IP, uint8) {
	parsedIP, _, _ := net.ParseCIDR(ip)
	cidr := strings.Split(string(ip), "/")
	cidrInt, _ := strconv.Atoi(cidr[0])
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

func IPsetfw(ipList []string, setModel models.Set, iptables bool, chainName string,
	rule models.Rule, mattermost file.Mattermost, logFilePath string, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	var countryCode string
	var setName string
	var notifMsg string
	var notifyMattermost bool = false

	countryCode = setModel.Country
	setName = setModel.SetName
	tmpSetName := setName + "-tmp"
	backupSetName := setName + "-bak"

	if rule.Table == "" {
		rule.Table = "raw"
	}
	if rule.Chain == "" {
		rule.Chain = "IPSET_FW"
	}

	hostname, err := os.Hostname()
	checkerr.Fatal(err)
	currentTime := time.Now()
	timeStampFormatted := currentTime.Format("2006-01-02 15:04:05")

	if mattermost.Token != "" && mattermost.URL != "" {
		notifyMattermost = true
	}

	var notifMsgInfo string = timeStampFormatted + " HOST: " + hostname + " --- "
	checkerr.Fatal(err)

	err = createDefaultChain(rule.Chain, rule.Table)
	if err != nil {
		notifMsg = notifMsgInfo + "ERROR: Could not create chain " + chainName
		if notifyMattermost {
			notif.SendNotificationMattermost(notifMsg, mattermost.URL, mattermost.Token)
		}
		checkerr.Fatal(err)
	}

	// Create a temporary set with new IP pool that we'll swap it with old set later
	ipset.Create(tmpSetName, ipset.TypeHashNet, ipset.CreateOptions{})
	ipset.Create(setName, ipset.TypeHashNet, ipset.CreateOptions{})

	ipListMerged := netutils.MergeIPsToCIDRs(ipList)
	for _, ip := range ipListMerged {
		logger.Log("Adding "+ip, logFilePath, verbose)
		entry := convertIPToEntry(ip)
		ipset.Add(tmpSetName, &entry)
	}

	sets, _ := ipset.List(backupSetName)
	if sets == nil {
		ipset.Create(backupSetName, ipset.TypeHashNet, ipset.CreateOptions{})
		for _, ip := range ipListMerged {
			entry := convertIPToEntry(ip)
			ipset.Add(backupSetName, &entry)
		}
		ipset.Swap(tmpSetName, setName)
	} else {
		ipset.Swap(setName, backupSetName)
		ipset.Swap(tmpSetName, setName)
	}
	err = ipset.Destroy(tmpSetName)
	if err != nil {
		notifMsg = notifMsgInfo + "ERROR: Could not destroy temporary set " + tmpSetName
		if notifyMattermost {
			notif.SendNotificationMattermost(notifMsg, mattermost.URL, mattermost.Token)
		}
		checkerr.Fatal(err)
	}
	if iptables {
		err := addIptableRule(rule, setName, chainName, logFilePath, verbose)
		if err != nil {
			notifMsg = notifMsgInfo + "ERROR: Could not add rule for set: " + setName + " - chain: " + chainName
			if notifyMattermost {
				notif.SendNotificationMattermost(notifMsg, mattermost.URL, mattermost.Token)
			}
			checkerr.Fatal(err)
		}
	}

	currentTime = time.Now()
	timeStampFormatted = currentTime.Format("2006-01-02 15:04:05")

	notifMsg = notifMsgInfo + "Successfully created set " + setName + " for country " +
		countryCode + " with " + strconv.Itoa(len(ipList)) + " number of entries!"

	fmt.Printf(notifMsg + "\n")
	notif.SendNotificationMattermost(notifMsg, mattermost.URL, mattermost.Token)
	return nil
}

func LoopConfigFile(path string, iptables bool, verbose bool) {
	usermgmt.ExitIfNotRoot()
	configString := file.ReadConfigFile(path)
	inventory := file.DecodeConfig(configString)
	var ipListConcatenated []string
	var ipList []string
	var set models.Set
	var rule models.Rule
	var mattermost file.Mattermost
	var logFilePath string = inventory.LogFilePath
	if inventory.Mattermost.Token != "" && inventory.Mattermost.URL != "" {
		mattermost = inventory.Mattermost
	}

	for _, r := range inventory.IPSetRules {
		set = models.Set{
			Country: r.Country,
			SetName: r.SetName,
		}
		rule = models.Rule{
			Policy: r.IPtables.Policy,
			Insert: r.IPtables.Insert,
			Type:   r.IPtables.Type,
			Chain:  r.IPtables.Chain,
			Table:  r.IPtables.Table,
		}
		if r.IPtables.Policy != "" {
			iptables = true
		}
		if len(r.Path) != 0 {
			for _, path := range r.Path {
				ipList = netutils.FetchIPPool(*&set.Country, verbose, path, logFilePath)
				ipList = includeExtraIPs(ipList, r.ExtraIPs)
				ipListConcatenated = append(ipListConcatenated, ipList...)
			}
			IPsetfw(ipListConcatenated, set, iptables, r.IPtables.Chain, rule, mattermost, logFilePath, verbose)
		} else {
			ipList := netutils.FetchIPPool(*&set.Country, verbose, "", logFilePath)
			ipList = includeExtraIPs(ipList, r.ExtraIPs)
			IPsetfw(ipList, set, iptables, r.IPtables.Chain, rule, mattermost, logFilePath, verbose)
		}
	}
}

func LoopConfigFileClear(path string, iptables bool, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	configString := file.ReadConfigFile(path)
	inventory := file.DecodeConfig(configString)
	var rule models.Rule
	for _, r := range inventory.IPSetRules {
		setName := r.SetName
		rule = models.Rule{
			Policy: r.IPtables.Policy,
			Insert: r.IPtables.Insert,
			Type:   r.IPtables.Type,
		}
		if r.IPtables.Policy != "" {
			iptables = true
		}
		if rule.Table == "" {
			rule.Table = "raw"
		}
		if rule.Chain == "" {
			rule.Chain = "IPSET_FW"
		}

		err := createDefaultChain(rule.Chain, rule.Table)
		if err != nil {
			return err
		}
		if iptables {
			err := removeIptableRule(rule, setName, rule.Chain, "", verbose, true)
			if err != nil {
				return err
			}
			time.Sleep(100 * time.Millisecond)
		}
		// Destroy set if it exists
		err = ipset.Destroy(setName)
		err = ipset.Destroy(setName + "-bak")
		if err != nil {
			if !strings.Contains(err.Error(), "The set with the given name does not exist") {
				if err != nil {
					return err
				}
			}
		}
	}
	err := removeDefaultChainIptableRule(rule.Chain, rule.Table, "", verbose, true)
	if err != nil {
		return err
	}
	err = removeDefaultChain(rule.Chain, rule.Table, "", verbose)
	if err != nil {
		return err
	}
	return nil
}
