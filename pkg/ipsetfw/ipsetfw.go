package ipsetfw

import (
	"fmt"
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

	"github.com/gmccue/go-ipset"
)

func removeDefaultChain(chainName string, logFilePath string, verbose bool) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	logger.Log("Removing default chain "+chainName, logFilePath, verbose)
	chainExists, err := ipt.ChainExists("filter", chainName)
	if err != nil {
		return err
	}
	if chainExists {
		err = ipt.DeleteChain("filter", chainName)
		if err != nil {
			return err
		}
	}
	logger.Log("Chain "+chainName+" does not exist. Already cleared?", logFilePath, verbose)
	return nil
}

func removeDefaultChainIptableRule(chainName string, logFilePath string, verbose bool, clear bool) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	logger.Log("Removing iptables rule to for default chain "+chainName, logFilePath, verbose)
	if chainName != "INPUT" {
		err = ipt.Delete("filter", "INPUT", "-j", chainName)
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

func createDefaultChain(chainName string) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	chainExists, err := ipt.ChainExists("filter", chainName)
	if err != nil {
		return err
	}
	if !chainExists {
		err = ipt.NewChain("filter", chainName)
		if err != nil {
			return err
		}
	}
	return nil
}
func addDefaultChainIptableRule(chainName string, logFilePath string, verbose bool) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	logger.Log("Adding iptables rule to for default chain "+chainName, logFilePath, verbose)
	if chainName != "INPUT" {
		err = ipt.InsertUnique("filter", "INPUT", 1, "-j", chainName)
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

	logger.Log("Adding iptables rule to chain "+chainName+" and set "+setName, logFilePath, verbose)
	err = ipt.InsertUnique("filter", chainName, 1, "-m", "set", "--match-set", setName, "src", "-j", rulePolicy)
	if err != nil {
		return err
	}
	return nil
}

func removeIptableRule(rule models.Rule, setName string, chainName string, logFilePath string, verbose bool, clear bool) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	logger.Log("Removing iptables rule to chain "+chainName+" and set "+setName, logFilePath, verbose)

	err = ipt.Delete("filter", chainName, "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT")
	err = ipt.Delete("filter", chainName, "-m", "set", "--match-set", setName, "src", "-j", "DROP")
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
	logger.Log("Removed iptables rule", logFilePath, verbose)
	return nil
}

func convertIPListToRestoreFile(ipList []string, prefixString string, logFilePath string, verbose bool) []string {
	for i, ip := range ipList {
		tmpIP, isValid := netutils.IsCIDRValid(ip)
		if !isValid {
			continue
		}
		ip = tmpIP
		if verbose {
			logger.Log("Adding "+ip, logFilePath, verbose)
		}
		ipList[i] = prefixString + " " + ip
	}
	return ipList
}

func includeExtraIPs(ipList []string, extraIPs []string) []string {
	for _, ip := range extraIPs {
		ipList = append(ipList, ip)
	}
	return ipList
}

func IPsetfw(ipList []string, set models.Set, iptables bool, chainName string, defaultChain string,
	rule models.Rule, mattermost file.Mattermost, logFilePath string, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	var countryCode string
	var setName string
	var notifMsg string
	var notifyMattermost bool = false

	countryCode = set.Country
	setName = set.SetName
	tmpSetName := setName + "-tmp"
	tmpSetFile := "/tmp/" + tmpSetName + ".txt"

	hostname, err := os.Hostname()
	checkerr.Fatal(err)
	currentTime := time.Now()
	timeStampFormatted := currentTime.Format("2006-01-02 15:04:05")

	if mattermost.Token != "" && mattermost.URL != "" {
		notifyMattermost = true
	}

	var notifMsgInfo string = timeStampFormatted + " HOST: " + hostname + " --- "

	// Construct a new ipset instance
	ipset, err := ipset.New()
	checkerr.Fatal(err)

	if chainName == "" {
		chainName = defaultChain
	}
	if defaultChain != "" {
		err := createDefaultChain(defaultChain)
		if err != nil {
			notifMsg = notifMsgInfo + "ERROR: Could not create chain " + chainName
			if notifyMattermost {
				notif.SendNotificationMattermost(notifMsg, mattermost.URL, mattermost.Token)
			}
			checkerr.Fatal(err)
		}
	}

	// Create a temporary set with new IP pool that we'll swap it with old set later
	err = ipset.Create(tmpSetName, "hash:net")
	if err != nil {
		notifMsg = notifMsgInfo + "ERROR: Could not create temporary set " + tmpSetName
		if notifyMattermost {
			notif.SendNotificationMattermost(notifMsg, mattermost.URL, mattermost.Token)
		}
		checkerr.Fatal(err)
	}

	// Convert IP pool to a file acceptable by ipset
	ipList = convertIPListToRestoreFile(ipList, "add "+tmpSetName, logFilePath, verbose)

	file.ExportToFile(tmpSetFile, ipList, verbose)
	ipset.Restore(tmpSetFile)

	// Create a new set
	err = ipset.Create(setName, "hash:net")
	if err != nil {
		if !strings.Contains(err.Error(), "Set cannot be created: set with the same name already exists") {
			notifMsg = notifMsgInfo + "ERROR: Could not create set " + setName
			if notifyMattermost {
				notif.SendNotificationMattermost(notifMsg, mattermost.URL, mattermost.Token)
			}
			checkerr.Fatal(err)
		}
	}

	err = ipset.Swap(tmpSetName, setName)
	if err != nil {
		notifMsg = notifMsgInfo + "ERROR: Could not swap set " + tmpSetName + " with set " + setName
		if notifyMattermost {
			notif.SendNotificationMattermost(notifMsg, mattermost.URL, mattermost.Token)
		}
		checkerr.Fatal(err)
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
	var chainName string
	var defaultChain string
	var set models.Set
	var rule models.Rule
	var mattermost file.Mattermost
	var logFilePath string = inventory.LogFilePath
	if inventory.Mattermost.Token != "" && inventory.Mattermost.URL != "" {
		mattermost = inventory.Mattermost
	}

	if inventory.DefaultChain == "" {
		defaultChain = "INPUT"
	} else {
		defaultChain = inventory.DefaultChain
	}
	for _, r := range inventory.IPSetRules {
		set = models.Set{
			Country: r.Country,
			SetName: r.SetName,
		}
		rule = models.Rule{
			Policy: r.IPtables.Policy,
			Insert: r.IPtables.Insert,
		}
		if r.IPtables.Policy != "" {
			iptables = true
		}
		chainName = r.IPtables.Chain
		if len(r.Path) != 0 {
			for _, path := range r.Path {
				ipList = netutils.FetchIPPool(*&set.Country, verbose, path, logFilePath)
				ipList = includeExtraIPs(ipList, r.ExtraIPs)
				ipListConcatenated = append(ipListConcatenated, ipList...)
			}
			IPsetfw(ipListConcatenated, set, iptables, chainName, defaultChain, rule, mattermost, logFilePath, verbose)
		} else {
			ipList := netutils.FetchIPPool(*&set.Country, verbose, "", logFilePath)
			ipList = includeExtraIPs(ipList, r.ExtraIPs)
			IPsetfw(ipList, set, iptables, chainName, defaultChain, rule, mattermost, logFilePath, verbose)
		}
	}
}

func LoopConfigFileClear(path string, iptables bool, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	configString := file.ReadConfigFile(path)
	inventory := file.DecodeConfig(configString)
	var chainName string
	var defaultChain string
	var rule models.Rule
	if inventory.DefaultChain == "" {
		defaultChain = "INPUT"
	} else {
		defaultChain = inventory.DefaultChain
	}
	for _, r := range inventory.IPSetRules {
		setName := r.SetName
		rule = models.Rule{
			Policy: r.IPtables.Policy,
			Insert: r.IPtables.Insert,
		}
		if r.IPtables.Policy != "" {
			iptables = true
		}
		chainName = r.IPtables.Chain
		ipset, err := ipset.New()

		if chainName == "" {
			chainName = defaultChain
		}
		if defaultChain != "" {
			err := createDefaultChain(defaultChain)
			if err != nil {
				return err
			}
		}
		if iptables {
			err := removeIptableRule(rule, setName, chainName, "", verbose, true)
			if err != nil {
				return err
			}
			time.Sleep(100 * time.Millisecond)
		}
		// Destroy set if it exists
		err = ipset.Destroy(setName)
		if err != nil {
			if !strings.Contains(err.Error(), "The set with the given name does not exist") {
				if err != nil {
					return err
				}
			}
		}
	}
	if defaultChain != "" {
		err := removeDefaultChainIptableRule(defaultChain, "", verbose, true)
		if err != nil {
			return err
		}
		err = removeDefaultChain(defaultChain, "", verbose)
		if err != nil {
			return err
		}
	}
	return nil
}
