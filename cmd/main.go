package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sabershahhoseini/ipset-firewall/models"
	"github.com/sabershahhoseini/ipset-firewall/pkg/ipsetfw"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/netutils"
)

func main() {

	// Required flags
	countryCode := flag.String("country", "", "Specify country code (example: IR)")
	setName := flag.String("set", "", "ipset set name")
	checkIP := flag.String("check", "", "Check IP exists in pool")
	iptablesPolicy := flag.String("policy", "", "iptables policy (accept or drop)")
	filePath := flag.String("file", "", "Get list from file instead of github")
	iptables := flag.Bool("iptables", false, "Add iptable rules")
	chain := flag.String("chain", "INPUT", "iptables chain to add rules to")
	verbose := flag.Bool("v", false, "Verbose mode")
	export := flag.Bool("export", false, "Export to file")
	clear := flag.Bool("clear", false, "Clear everything")
	config := flag.String("config", "", "Use yaml config file")
	help := flag.Bool("help", false, "Show help")
	flag.Parse()

	// Print example usage if no arguments are provided
	if len(os.Args) <= 1 || *help {
		fmt.Println(`You must pass an argument. Use -help for more information.

Options:
	-help					show this menu

	-config		{PATH}			Read config from yaml file
	-country	{CODE}			set country code. is not case sensitive.
	-set		{NAME}			name of ipset set
	-check		{IP}			check if IP exists in specific country IP pool

	-file		{PATH}			file path to read networks from (by default, it will be fetched from github)
	-export					export to file. works with -file and -country

	-iptables				setup iptables rules
	-chain		{CHAIN}			iptables chain to add rules to. defaults to INPUT
	-policy		{POLICY}		works with -iptables and sets default policy

	-clear					clear everything

	-v					verbose mode

Example usage:

Read rules from config file:
	ipsetfw -config ipsetfw.yml

Clear rules defined in config file:
	ipsetfw -config ipsetfw.yml -clear

Create a set of Iran IP pool:
	ipsetfw -country ir -set set

Create a set of Iran IP pool:
	ipsetfw -country ir -set set

Create a set of Iran IP pool and block IPs from Iran by adding iptables rule:
	ipsetfw -country IR -set set -iptables -policy drop

Create a set of Iran IP pool and accpet IPs from Iran by adding iptable rules with verbose mode:
	ipsetfw -country IR -set set -iptables -policy accept -v

Fetch github and export Iran IP pool:
	ipsetfw -country ir -export -file /tmp/list-export.txt -v

Create a set of Iran IP pool and accpet IPs from Iran from file:
	ipsetfw -country IR -set set -iptables -policy accept -file /tmp/list-export.txt

Check if IP exists in IR (Iran):
	ipsetfw -country ir -check 1.1.1.1`)
		os.Exit(1)
	}
	set := models.Set{
		Country: *countryCode,
		SetName: *setName,
	}
	rule := models.Rule{
		Policy: *iptablesPolicy,
	}
	// If type is minio and -p is not passed, read config file from Minio and check state
	if *export {
		ipList := netutils.FetchIPPool(*countryCode, *verbose, "")
		file.ExportToFile(*filePath, ipList, *verbose)
	} else if *config != "" && !*clear {
		ipsetfw.LoopConfigFile(*config, *iptables, *verbose)
	} else if *clear {
		ipsetfw.LoopConfigFileClear(*config, *iptables, *verbose)
	} else if *countryCode != "" && *setName != "" {
		ipList := netutils.FetchIPPool(*countryCode, *verbose, *filePath)
		ipsetfw.IPsetfw(ipList, set, *iptables, *chain, "INPUT", rule, *verbose)
	} else if *countryCode != "" && *checkIP != "" {
		ipList := netutils.FetchIPPool(*countryCode, *verbose, *filePath)
		netutils.CheckIPExistsInPool(ipList, *checkIP, *verbose)
	}
}
