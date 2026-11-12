package ipsetfw

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/lrh3321/ipset-go"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/netutils"
)

// IP protocol numbers used in hash:net,port sets.
const (
	protoTCP uint8 = 6
	protoUDP uint8 = 17
)

// protoNumber maps "tcp" or "udp" to its IP protocol number.
func protoNumber(proto string) uint8 {
	if proto == "udp" {
		return protoUDP
	}
	return protoTCP
}

// netEntries turns merged networks into hash:net entries.
func netEntries(nets []string) []ipset.Entry {
	entries := make([]ipset.Entry, 0, len(nets))
	for _, n := range nets {
		entries = append(entries, convertIPToEntry(n))
	}
	return entries
}

// portEntries makes one hash:net,port entry for every network and port pair.
func portEntries(nets []string, ports []int, proto string) []ipset.Entry {
	pr := protoNumber(proto)
	entries := make([]ipset.Entry, 0, len(nets)*len(ports))
	for _, n := range nets {
		base := convertIPToEntry(n)
		for _, p := range ports {
			port := uint16(p)
			e := base
			e.Port = &port
			e.Protocol = &pr
			entries = append(entries, e)
		}
	}
	return entries
}

// blockMatchArgs is the iptables rule for one block entry, without the chain name.
// A port block matches protocol and ports through the set: src,dst (or dst,dst for dst).
func blockMatchArgs(b file.BlockEntry, setName string) []string {
	dir := b.Direction
	if dir == "" {
		dir = "src"
	}
	if b.IsPort() {
		return []string{"-p", b.ProtoOrDefault(), "-m", "set", "--match-set", setName, dir + ",dst", "-j", "DROP"}
	}
	return []string{"-m", "set", "--match-set", setName, dir, "-j", "DROP"}
}

// applyPortBlock builds a hash:net,port set for one block entry and adds its drop rule at insert.
func applyPortBlock(b file.BlockEntry, insert int, mattermost file.Mattermost, logFilePath string, verbose bool) error {
	setName := b.SetName()
	fail := func(msg string, err error) error {
		if mattermost.Token != "" && mattermost.URL != "" {
			notify(mattermost, "ERROR: "+msg)
		}
		return fmt.Errorf("%s: %w", msg, err)
	}

	list, err := blockSources(b, verbose, logFilePath)
	if err != nil {
		return fail("block "+b.Name, err)
	}
	nets := netutils.MergeIPsToCIDRs(list)
	if len(nets) == 0 {
		return fail("block "+b.Name, fmt.Errorf("no valid networks"))
	}
	entries := portEntries(nets, b.Ports, b.ProtoOrDefault())
	if err := replaceSet(setName, "hash:net,port", entries, logFilePath, verbose); err != nil {
		return fail("could not update set "+setName, err)
	}

	r := baseRule()
	if err := createDefaultChain(r.Chain, r.Table); err != nil {
		return fail("could not create chain "+r.Chain, err)
	}
	if err := addDefaultChainIptableRule(r.Chain, r.Table, r.Parent, logFilePath, verbose); err != nil {
		return fail("could not add jump from "+r.Parent+" to chain "+r.Chain, err)
	}
	ipt, err := iptables.New()
	if err != nil {
		return fail("iptables", err)
	}
	if err := ipt.InsertUnique(r.Table, r.Chain, insert, blockMatchArgs(b, setName)...); err != nil {
		return fail("could not add rule for set "+setName, err)
	}

	msg := fmt.Sprintf("Successfully created port set %s with %d entries (%d networks, ports %s/%s)",
		setName, len(entries), len(nets), joinPorts(b.Ports), b.ProtoOrDefault())
	fmt.Println(msg)
	if mattermost.Token != "" && mattermost.URL != "" {
		notify(mattermost, msg)
	}
	return nil
}

// joinPorts formats ports for messages, for example "22,443".
func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprint(p))
	}
	return strings.Join(parts, ",")
}

// deletePortBlockRule removes the drop rule of a port block. A missing rule is not an error.
func deletePortBlockRule(b file.BlockEntry, chain string) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	err = ipt.DeleteIfExists(baseRule().Table, chain, blockMatchArgs(b, b.SetName())...)
	// A missing set or rule means there is nothing to remove.
	if err != nil && (strings.Contains(err.Error(), "doesn't exist") || strings.Contains(err.Error(), "does a matching rule exist")) {
		return nil
	}
	return err
}
