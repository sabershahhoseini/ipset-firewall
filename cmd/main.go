package main

import (
	"flag"
	"fmt"
	"ipset-firewall/pkg/ipsetfw"
	"os"
)

func main() {
	// Required flags
	countryCode := flag.String("country", "", "Specify country code (example: IR)")
	iptables := flag.Bool("iptables", true, "Add iptable rules")
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
	// If type is minio and -p is not passed, read config file from Minio and check state
	if *countryCode != "" {
		ipsetfw.IPsetfw(*countryCode, *iptables)
	}
}
