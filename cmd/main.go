package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sabershahhoseini/ipset-firewall/pkg/ipsetfw"
	"github.com/sabershahhoseini/ipset-firewall/util/netutils"
)

func main() {
	// Required flags
	countryCode := flag.String("country", "", "Specify country code (example: IR)")
	setName := flag.String("set", "", "ipset set name")
	checkIP := flag.String("check", "", "Check IP exists in pool")
	iptablesPolicy := flag.String("policy", "", "iptables policy (accept or drop)")
	file := flag.String("file", "", "Get list from file instead of github")
	iptables := flag.Bool("iptables", false, "Add iptable rules")
	verbose := flag.Bool("v", false, "Verbose mode")
	help := flag.Bool("help", false, "Show help")
	flag.Parse()

	// Print example usage if no arguments are provided
	if len(os.Args) <= 1 || *help {
		fmt.Println(`You must pass an argument. Use -help for more information.

Options:
	-help					show this menu

	-country	{CODE}			set country code
	-set		{NAME}			name of ipset set
	-check		{IP}			check if IP exists in specific country IP pool

	-file		{PATH}			file path to read networks from (by default, it will be fetched from github)

	-iptables				setup iptables rules
	-policy		{POLICY}		works with -iptables and sets default policy

	-v					verbose mode

Example usage:

Create a set of Iran IP pool:
	ipsetfw -country IR -set set

Create a set of Iran IP pool and block IPs from Iran by adding iptables rule:
	ipsetfw -country IR -set set -iptables -policy drop

Create a set of Iran IP pool and accpet IPs from Iran by adding iptable rules with verbose mode:
	ipsetfw -country IR -set set -iptables -policy accept -v

Create a set of Iran IP pool and accpet IPs from Iran from file:
	ipsetfw -country IR -set set -iptables -policy accept -file /opt/ips.txt

Check if IP exists in IR (Iran):
	ipsetfw -country IR -check 1.1.1.1`)
		os.Exit(1)
	}
	set := ipsetfw.Set{
		Country: *countryCode,
		SetName: *setName,
	}
	rule := ipsetfw.Rule{
		Policy: *iptablesPolicy,
	}
	// If type is minio and -p is not passed, read config file from Minio and check state
	if *countryCode != "" && *setName != "" {
		ipList := netutils.FetchIPPool(*countryCode, *verbose, *file)
		ipsetfw.IPsetfw(ipList, set, *iptables, rule, *verbose)
	} else if *countryCode != "" && *checkIP != "" {
		ipList := netutils.FetchIPPool(*countryCode, *verbose, *file)
		netutils.CheckIPExistsInPool(ipList, *checkIP, *verbose)
	}
}
