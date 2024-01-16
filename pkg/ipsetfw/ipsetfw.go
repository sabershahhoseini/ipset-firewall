package ipsetfw

import (
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/sabershahhoseini/ipset-firewall/error/checkerr"
	"github.com/sabershahhoseini/ipset-firewall/util/logger"
	"github.com/sabershahhoseini/ipset-firewall/util/netutils"

	"github.com/gmccue/go-ipset"
)

func addIptableRule(rule Rule, setName string, verbose bool) {
	ipt, err := iptables.New()
	checkerr.Fatal(err)

	rulePolicy := strings.ToUpper(rule.Policy)

	logger.Log("Adding iptables rule", verbose)
	err = ipt.Insert("filter", "INPUT", 1, "-m", "set", "--match-set", setName, "src", "-j", rulePolicy)
	checkerr.Fatal(err)

	logger.Log("Added iptables rule", verbose)
}

func removeIptableRule(rule Rule, setName string, verbose bool) {
	ipt, err := iptables.New()
	checkerr.Fatal(err)

	logger.Log("Removing iptables rule", verbose)

	err = ipt.Delete("filter", "INPUT", "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT")
	err = ipt.Delete("filter", "INPUT", "-m", "set", "--match-set", setName, "src", "-j", "DROP")
	if err != nil {
		if strings.Contains(err.Error(), "does a matching rule exist in that chain") {
			return
		} else if strings.Contains(err.Error(), "Set "+setName+" doesn't exist") {
			return
		}
		checkerr.Fatal(err)
	}
	logger.Log("Removed iptables rule", verbose)
}

func IPsetfw(ipList []string, set Set, iptables bool, rule Rule, verbose bool) {

	var countryCode string
	var setName string

	countryCode = set.Country
	setName = set.SetName

	// Construct a new ipset instance
	ipset, err := ipset.New()

	// If iptables argument is passed, the rule. This step is essential because
	// We need to clear everything. And we can't remove ipset set if we don't
	// Release it from iptables.
	if iptables {
		removeIptableRule(rule, setName, verbose)
		time.Sleep(500 * time.Millisecond)
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
		addIptableRule(rule, setName, verbose)
	}

	listLen := len(ipList)

	fmt.Printf("Successfully created set %v for country %v with %v number of entries!\n", setName, countryCode, listLen)
}
