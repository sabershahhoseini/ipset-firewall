package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sabershahhoseini/ipset-firewall/error/checkerr"
	"github.com/sabershahhoseini/ipset-firewall/models"
	"github.com/sabershahhoseini/ipset-firewall/pkg/ipsetfw"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/netutils"
	"github.com/sabershahhoseini/ipset-firewall/util/usermgmt"
)

func main() {

	// Required flags
	countryCode := flag.String("country", "", "Specify country code (example: IR)")
	setName := flag.String("set", "", "ipset set name")
	checkIP := flag.String("check", "", "Check IP exists in pool")
	iptablesPolicy := flag.String("policy", "", "iptables policy (accept or drop)")
	filePath := flag.String("file", "", "Get list from file instead of the remote sources")
	iptables := flag.Bool("iptables", false, "Add iptable rules")
	chain := flag.String("chain", "", "iptables chain to add rules to (defaults to IPSET_FW)")
	verbose := flag.Bool("v", false, "Verbose mode")
	export := flag.Bool("export", false, "Export to file")
	clear := flag.Bool("clear", false, "Clear everything")
	rollback := flag.Bool("rollback", false, "rollback set with previous backup set")
	list := flag.Bool("list", false, "List sets")
	config := flag.String("config", "", "Use yaml config file")
	plan := flag.Bool("plan", false, "With -config: show what would be applied, change nothing")
	help := flag.Bool("help", false, "Show help")
	flag.Parse()

	// Print example usage if no arguments are provided
	if len(os.Args) <= 1 || *help {
		fmt.Println(`You must pass an argument. Use -help for more information.

Options:
	-help					show this menu

	-config		{PATH}			Read config from yaml file
	-plan					with -config: show what would be applied, change nothing
	-country	{CODE}			set country code. is not case sensitive.
	-set		{NAME}			name of ipset set
	-check		{IP}			check if IP exists in specific country IP pool

	-file		{PATH}			file path to read networks from (by default, it is fetched from the sources in util/netutils)
	-export					export to file. works with -file and -country

	-iptables				setup iptables rules
	-chain		{CHAIN}			iptables chain to add rules to. defaults to IPSET_FW (table raw)
	-policy		{POLICY}		works with -iptables and sets default policy
	
	-rollback	{SETNAME}		rollback set with previous backup set

	-list					list all sets
	-list		{SETNAME}	list specific set

	-clear					clear everything

	-v					verbose mode

Example usage:

List rules:
	ipsetfw -list -v

List specific rule:
	ipsetfw -list -set ir-block

Read rules from config file and setup ipset:
	ipsetfw -config ipsetfw.yml

Clear rules defined in config file:
	ipsetfw -config ipsetfw.yml -clear

Rollback a broken update to previous working set:
	ipsetfw -rollback -set ir-block

Create a set of Iran IP pool:
	ipsetfw -country ir -set set

Create a set of Iran IP pool:
	ipsetfw -country ir -set set

Create a set of Iran IP pool and block IPs from Iran by adding iptables rule:
	ipsetfw -country IR -set set -iptables -policy drop

Create a set of Iran IP pool and accpet IPs from Iran by adding iptable rules with verbose mode:
	ipsetfw -country IR -set set -iptables -policy accept -v

Fetch the Iran IP pool and export it:
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
		Chain:  *chain,
	}
	if *export {
		if *filePath == "" {
			fmt.Fprintln(os.Stderr, "-export requires -file")
			os.Exit(1)
		}
		ipList, err := netutils.FetchIPPool(*countryCode, *verbose, "", "")
		checkerr.Fatal(err)
		file.ExportToFile(*filePath, ipList, *verbose)
	} else if *config != "" && *plan {
		checkerr.Fatal(ipsetfw.PlanConfig(*config, *verbose))
	} else if *config != "" && !*clear {
		checkerr.Fatal(ipsetfw.LoopConfigFile(*config, *iptables, *verbose))
	} else if *list && *setName != "" {
		ipsetfw.ListSet(*setName, *verbose)
	} else if *list {
		ipsetfw.ListAllSets(*verbose)
	} else if *rollback && *setName != "" {
		ipsetfw.RollbackSet(*setName)
	} else if *clear {
		checkerr.Fatal(ipsetfw.LoopConfigFileClear(*config, *iptables, *verbose))
	} else if *countryCode != "" && *setName != "" {
		ipList, err := netutils.FetchIPPool(*countryCode, *verbose, *filePath, "")
		checkerr.Fatal(err)
		usermgmt.ExitIfNotRoot()
		checkerr.Fatal(ipsetfw.IPsetfw(ipList, set, *iptables, rule, file.Mattermost{}, "", *verbose))
	} else if *countryCode != "" && *checkIP != "" {
		ipList, err := netutils.FetchIPPool(*countryCode, *verbose, *filePath, "")
		checkerr.Fatal(err)
		netutils.CheckIPExistsInPool(ipList, *checkIP, *verbose)
	} else {
		fmt.Fprintln(os.Stderr, "invalid or incomplete arguments, use -help")
		os.Exit(1)
	}
}
