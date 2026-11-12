package ipsetfw

import (
	"fmt"
	"strings"

	"github.com/lrh3321/ipset-go"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
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

// blockMatchArgs is the one definition of a block's drop rule, without the chain name. Apply,
// clear, status and verify all use it. A port block matches protocol and ports through the set:
// src,dst (or dst,dst for direction dst).
func blockMatchArgs(b file.BlockEntry, setName string) []string {
	dir := b.DirectionOrDefault()
	if b.IsPort() {
		return []string{"-p", b.ProtoOrDefault(), "-m", "set", "--match-set", setName, dir + ",dst", "-j", "DROP"}
	}
	return []string{"-m", "set", "--match-set", setName, dir, "-j", "DROP"}
}

// joinPorts formats ports for messages, for example "22,443".
func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprint(p))
	}
	return strings.Join(parts, ",")
}
