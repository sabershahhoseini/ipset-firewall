package ipsetfw

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/sabershahhoseini/ipset-firewall/error/checkerr"
	"github.com/sabershahhoseini/ipset-firewall/models"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/logger"
	"github.com/sabershahhoseini/ipset-firewall/util/netutils"

	"github.com/gmccue/go-ipset"
)

func ExitIfNotRoot() {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Unable to get current user: %s", err)
	}
	if currentUser.Username != "root" {
		fmt.Println("You must be root!")
		os.Exit(1)
	}
}

func removeDefaultChain(chainName string, verbose bool) {
	ipt, err := iptables.New()
	checkerr.Fatal(err)
	logger.Log("Removing default chain "+chainName, verbose)
	chainExists, err := ipt.ChainExists("filter", chainName)
	checkerr.Fatal(err)
	if chainExists {
		err = ipt.DeleteChain("filter", chainName)
		checkerr.Fatal(err)
	}
	logger.Log("Chain "+chainName+" does not exist. Already cleared?", verbose)
}

func removeDefaultChainIptableRule(chainName string, verbose bool, clear bool) {
	ipt, err := iptables.New()
	checkerr.Fatal(err)

	logger.Log("Removing iptables rule to for default chain "+chainName, verbose)
	if chainName != "INPUT" {
		err = ipt.Delete("filter", "INPUT", "-j", chainName)
		if err != nil {
			if strings.Contains(err.Error(), "does a matching rule exist in that chain") {
				if clear {
					logger.Log("Chain "+chainName+" does not exist. Already cleared?", verbose)
				}
				return
			}
		}
		checkerr.Fatal(err)
		logger.Log("Removed iptables rule", verbose)
	}

}

func createDefaultChain(chainName string) {
	ipt, err := iptables.New()
	checkerr.Fatal(err)
	chainExists, err := ipt.ChainExists("filter", chainName)
	checkerr.Fatal(err)
	if !chainExists {
		err = ipt.NewChain("filter", chainName)
		checkerr.Fatal(err)
	}
}
func addDefaultChainIptableRule(chainName string, verbose bool) {
	ipt, err := iptables.New()
	checkerr.Fatal(err)

	logger.Log("Adding iptables rule to for default chain "+chainName, verbose)
	if chainName != "INPUT" {
		err = ipt.InsertUnique("filter", "INPUT", 1, "-j", chainName)
		checkerr.Fatal(err)
		logger.Log("Added iptables rule", verbose)
	}

}

func addIptableRule(rule models.Rule, setName string, chainName string, verbose bool) {
	ipt, err := iptables.New()
	checkerr.Fatal(err)

	rulePolicy := strings.ToUpper(rule.Policy)

	logger.Log("Adding iptables rule to chain "+chainName+" and set "+setName, verbose)
	err = ipt.InsertUnique("filter", chainName, 1, "-m", "set", "--match-set", setName, "src", "-j", rulePolicy)
	checkerr.Fatal(err)

	logger.Log("Added iptables rule", verbose)
}

func removeIptableRule(rule models.Rule, setName string, chainName string, verbose bool, clear bool) {
	ipt, err := iptables.New()
	checkerr.Fatal(err)

	logger.Log("Removing iptables rule to chain "+chainName+" and set "+setName, verbose)

	err = ipt.Delete("filter", chainName, "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT")
	err = ipt.Delete("filter", chainName, "-m", "set", "--match-set", setName, "src", "-j", "DROP")
	if err != nil {
		if strings.Contains(err.Error(), "does a matching rule exist in that chain") {
			return
		} else if strings.Contains(err.Error(), "Set "+setName+" doesn't exist") {
			if clear {
				logger.Log("Rule not found. Already cleared?", verbose)
			}
			return
		}
		checkerr.Fatal(err)
	}
	logger.Log("Removed iptables rule", verbose)
}

func IPsetfw(ipList []string, set models.Set, iptables bool, chainName string, defaultChain string, rule models.Rule, verbose bool) {
	ExitIfNotRoot()
	var countryCode string
	var setName string

	countryCode = set.Country
	setName = set.SetName

	// Construct a new ipset instance
	ipset, err := ipset.New()

	if chainName == "" {
		chainName = defaultChain
	}
	if defaultChain != "" {
		createDefaultChain(defaultChain)
	}

	// If iptables argument is passed, the rule. This step is essential because
	// We need to clear everything. And we can't remove ipset set if we don't
	// Release it from iptables.
	if iptables {
		removeIptableRule(rule, setName, chainName, verbose, false)
		time.Sleep(100 * time.Millisecond)
	}
	// Destroy set if it exists
	err = ipset.Destroy(setName)
	if err != nil {
		if !strings.Contains(err.Error(), "The set with the given name does not exist") {
			checkerr.Fatal(err)
		}
	}

	// Create a new set
	err = ipset.Create(setName, "hash:net")
	checkerr.Fatal(err)

	logger.Log("Adding IPs to set", verbose)
	for _, ip := range ipList {
		if !netutils.IsCIDRValid(ip) {
			continue
		}
		if verbose {
			fmt.Printf("Adding %v\n", ip)
		}
		err := ipset.Add(setName, ip)
		checkerr.Fatal(err)

	}

	logger.Log("Added IPs to set", verbose)

	if iptables {
		addIptableRule(rule, setName, chainName, verbose)
	}

	fmt.Printf("Successfully created set %v for country %v with %v number of entries!\n", setName, countryCode, len(ipList))
}

func LoopConfigFile(path string, iptables bool, verbose bool) {
	ExitIfNotRoot()
	configString := file.ReadConfigFile(path)
	inventory := file.DecodeConfig(configString)
	var ipListConcatenated []string
	var ipList []string
	var chainName string
	var defaultChain string
	var set models.Set
	var rule models.Rule
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
				ipList = netutils.FetchIPPool(*&set.Country, verbose, path)
				// ipsetfw.IPsetfw(ipList, set, *iptables, rule, *verbose)
				ipListConcatenated = append(ipListConcatenated, ipList...)
			}
			IPsetfw(ipListConcatenated, set, iptables, chainName, defaultChain, rule, verbose)
		} else {
			ipList := netutils.FetchIPPool(*&set.Country, verbose, "")
			IPsetfw(ipList, set, iptables, chainName, defaultChain, rule, verbose)
		}
	}
	if defaultChain != "" {
		addDefaultChainIptableRule(defaultChain, verbose)
	}
}

func LoopConfigFileClear(path string, iptables bool, verbose bool) {
	ExitIfNotRoot()
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
			createDefaultChain(defaultChain)
		}
		if iptables {
			removeIptableRule(rule, setName, chainName, verbose, true)
			time.Sleep(100 * time.Millisecond)
		}
		// Destroy set if it exists
		err = ipset.Destroy(setName)
		if err != nil {
			if !strings.Contains(err.Error(), "The set with the given name does not exist") {
				checkerr.Fatal(err)
			}
		}
	}
	if defaultChain != "" {
		removeDefaultChainIptableRule(defaultChain, verbose, true)
		removeDefaultChain(defaultChain, verbose)
	}
}
