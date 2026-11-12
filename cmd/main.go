package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sabershahhoseini/ipset-firewall/error/checkerr"
	"github.com/sabershahhoseini/ipset-firewall/models"
	"github.com/sabershahhoseini/ipset-firewall/pkg/ipsetfw"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/lock"
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
	status := flag.Bool("status", false, "With -config: show the live state of each block")
	verify := flag.Bool("verify", false, "With -config: check the live firewall matches the config; exit 1 on differences")
	testHook := flag.String("test-hook", "", "With -config: run the before, after or onError hooks against a sample report; changes nothing")
	restore := flag.Bool("restore", false, "Put back the last saved snapshot (persist: true); for boot, no network needed")
	force := flag.Bool("force", false, "Ignore fresh cached lists and maxChange; download again")
	mirror := flag.String("mirror", "", "Directory of <code>.txt lists to use before any download")
	offlineFlag := flag.Bool("offline", false, "Never touch the network; use the mirror and cache only")
	unattended := flag.Bool("unattended", false, "Install allow-only without the interactive confirmation (still checks SSH clients)")
	onlyTimeout := flag.Duration("only-timeout", 60*time.Second, "How long a first allow-only install waits for confirmation")
	help := flag.Bool("help", false, "Show help")
	flag.Parse()
	ipsetfw.ForceRefresh = *force
	ipsetfw.MirrorFlag = *mirror
	ipsetfw.OfflineFlag = *offlineFlag
	ipsetfw.OnlyUnattended = *unattended
	ipsetfw.OnlyTimeout = *onlyTimeout
	netutils.SetCacheOptions(netutils.CacheOptions{Dir: netutils.DefaultCacheDir, MaxAge: netutils.DefaultCacheMaxAge, Force: *force})
	netutils.SetMirror(*mirror, *offlineFlag)

	// Print example usage if no arguments are provided
	if len(os.Args) <= 1 || *help {
		fmt.Println(`You must pass an argument. Use -help for more information.

Options:
	-help					show this menu

	-config		{PATH}			Read config from yaml file
	-plan					with -config: show what would be applied, change nothing
	-test-hook	{EVENT}			with -config: run the before, after or onError hooks against a sample report
	-restore				put back the last saved snapshot (persist: true); used at boot
	-status					with -config: show the live state of each block
	-verify					with -config: check the live firewall matches the config; exit 1 on differences
	-force					ignore fresh cached lists and maxChange; download again
	-mirror		{DIR}			use <code>.txt files in DIR before any download
	-offline				never touch the network; mirror and cache only
	-unattended				install allow-only without the interactive confirmation
	-only-timeout	{DURATION}		how long a first allow-only install waits for "yes" (default 60s)
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
	} else if *config != "" && *testHook != "" {
		unlock := takeLock()
		defer unlock()
		checkerr.Fatal(ipsetfw.TestHooks(*config, *testHook, *verbose))
	} else if *restore {
		unlock := takeLock()
		defer unlock()
		checkerr.Fatal(ipsetfw.RestoreConfig(*config, *verbose))
	} else if *config != "" && *status {
		checkerr.Fatal(ipsetfw.StatusConfig(*config, *verbose))
	} else if *config != "" && *verify {
		checkerr.Fatal(ipsetfw.VerifyConfig(*config, *verbose))
	} else if *config != "" && *plan {
		checkerr.Fatal(ipsetfw.PlanConfig(*config, *verbose))
	} else if *config != "" && !*clear {
		unlock := takeLock()
		defer unlock()
		checkerr.Fatal(ipsetfw.LoopConfigFile(*config, *iptables, *verbose))
	} else if *list && *setName != "" {
		ipsetfw.ListSet(*setName, *verbose)
	} else if *list {
		ipsetfw.ListAllSets(*verbose)
	} else if *rollback && *setName != "" {
		unlock := takeLock()
		defer unlock()
		ipsetfw.RollbackSet(*setName)
	} else if *clear {
		unlock := takeLock()
		defer unlock()
		checkerr.Fatal(ipsetfw.LoopConfigFileClear(*config, *iptables, *verbose))
	} else if *countryCode != "" && *setName != "" {
		ipList, err := netutils.FetchIPPool(*countryCode, *verbose, *filePath, "")
		checkerr.Fatal(err)
		usermgmt.ExitIfNotRoot()
		unlock := takeLock()
		defer unlock()
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

// lockPath is held by every command that changes sets or rules, so timers and manual runs do not overlap.
const lockPath = "/run/ipsetfw.lock"

// takeLock acquires the run lock or exits with a message. The returned func releases it.
func takeLock() func() {
	f, err := lock.Acquire(lockPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return func() { f.Close() }
}
