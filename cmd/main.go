package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sabershahhoseini/ipset-firewall/pkg/ipsetfw"
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
	-country	{CODE}			set country code
	-set		{NAME}			name of ipset set
	-check		{IP}			check if IP exists in specific country IP pool

	-iptables				setup iptables rules
	-policy		{POLICY}		works with -iptables and sets default policy

	-v					verbose mode

Example usage:

Create a set of Iran IP pool:
	ipsetfw -country IR -set set

Create a set of Iran IP pool and block IPs from IR (Iran):
	ipsetfw -country IR -set set -iptables -policy drop

Create a set of Iran IP pool and Accpet IPs from Iran:
	ipsetfw -country IR -set set -iptables -policy accept

Check if IP exists in IR (Iran):
	ipsetfw go run main.go -country IR -check 1.1.1.1`)
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
		ipsetfw.IPsetfw(set, *iptables, rule, *verbose, *file)
	} else if *countryCode != "" && *checkIP != "" {
		ipsetfw.CheckIPExistsInPool(set, *checkIP, *verbose)
	}
}
