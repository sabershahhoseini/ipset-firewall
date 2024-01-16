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
	iptables := flag.Bool("iptables", false, "Add iptable rules")
	verbose := flag.Bool("v", false, "Verbose mode")
	flag.Parse()

	// Print example usage if no arguments are provided
	if len(os.Args) <= 1 {
		fmt.Println(`You must pass an argument. Use -help for more information.

Example usage:

Run as worker mode:
	ipsetfw -country IR -iptables
Push config to Minio (Does not check state):
	kookctl -mode standalone -p`)
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
		ipsetfw.IPsetfw(set, *iptables, rule, *verbose)
	} else if *countryCode != "" && *checkIP != "" {
		ipsetfw.CheckIPExistsInPool(set, *checkIP)
	}
}
