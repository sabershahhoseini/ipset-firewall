package ipsetfw

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gmccue/go-ipset"
)

type Set struct {
	Country string
	SetName string
}
type Rule struct {
	Policy string
}

func logger(log string, verbose bool) {
	if verbose {
		fmt.Println(log)
	}
}

func fetchIPPool(url, countryCode string, verbose bool) []string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalln(err)
	}

	client := &http.Client{}

	logger("Trying to get url: "+url, verbose)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	// fmt.Println(string(b))
	list := strings.Split(string(b), "\n")
	logger("Finished fetching list of IPs", verbose)
	return list

}

func isCIDRValid(ip string) bool {
	_, _, err := net.ParseCIDR(ip)
	if err != nil {
		return false
	}
	return true
}

func networkContainsIP(cidr string, ip string) bool {
	network, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic(err)
	}

	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		panic(err)
	}

	b := network.Contains(parsedIP)
	return b
}

func CheckIPExistsInPool(set Set, targetIP string, verbose bool) {
	var url string
	countryCode := set.Country
	countryCode = strings.ToLower(countryCode)
	url = "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/" + countryCode + ".cidr"
	ipList := fetchIPPool(url, countryCode, verbose)

	for _, ip := range ipList {
		if !isCIDRValid(ip) {
			continue
		}
		if networkContainsIP(ip, targetIP) {
			fmt.Printf("%v exists in %v\n", targetIP, ip)
			return
		}
	}
	fmt.Printf("IP %v NOT FOUND in country %v!\n", targetIP, set.Country)
}

func addIptableRule(rule Rule, setName string, verbose bool) {
	ipt, err := iptables.New()
	if err != nil {
		log.Fatalln(err)
	}

	rulePolicy := strings.ToUpper(rule.Policy)

	logger("Adding iptables rule", verbose)
	err = ipt.Insert("filter", "INPUT", 1, "-m", "set", "--match-set", setName, "src", "-j", rulePolicy)
	if err != nil {
		log.Fatalln(err)
	}
	logger("Added iptables rule", verbose)
}

func removeIptableRule(rule Rule, setName string, verbose bool) {
	ipt, err := iptables.New()
	if err != nil {
		log.Fatalln(err)
	}

	// rulePolicy := strings.ToUpper(rule.Policy)

	logger("Removing iptables rule", verbose)

	// err = ipt.Delete("filter", "INPUT", "-m", "set", "--match-set", setName, "src")
	err = ipt.Delete("filter", "INPUT", "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT")
	err = ipt.Delete("filter", "INPUT", "-m", "set", "--match-set", setName, "src", "-j", "DROP")
	if err != nil {
		if strings.Contains(err.Error(), "does a matching rule exist in that chain") {
			return
		}
		log.Fatalln(err)
	}
	logger("Removed iptables rule", verbose)
}

func IPsetfw(set Set, iptables bool, rule Rule, verbose bool) {

	var url string
	countryCode := set.Country
	setName := set.SetName
	countryCode = strings.ToLower(countryCode)
	url = "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/" + countryCode + ".cidr"

	ipList := fetchIPPool(url, countryCode, verbose)

	// Construct a new ipset instance
	ipset, err := ipset.New()
	if err != nil {
		log.Fatalln(err)
	}

	if iptables {
		removeIptableRule(rule, setName, verbose)
		time.Sleep(500 * time.Millisecond)
	}
	// Create a new set
	err = ipset.Destroy(setName)
	if err != nil {
		log.Fatalln(err)
	}
	err = ipset.Create(setName, "hash:net")
	if err != nil {
		log.Fatalln(err)
	}
	logger("Adding IPs to set", verbose)
	for _, ip := range ipList {
		if !isCIDRValid(ip) {
			continue
		}
		if verbose {
			fmt.Printf("Adding %v\n", ip)
		}
		err := ipset.Add(setName, ip)
		if err != nil {
			log.Fatalln(err)
		}
	}
	logger("Added IPs to set", verbose)

	if iptables {
		addIptableRule(rule, setName, verbose)
	}

	listLen := len(ipList)

	fmt.Printf("Successfully created set %v for country %v with %v number of entries!\n", setName, countryCode, listLen)
}
