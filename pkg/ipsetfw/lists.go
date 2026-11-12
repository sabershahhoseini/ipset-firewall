package ipsetfw

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/netutils"
)

var twoLetters = regexp.MustCompile(`^[a-z]{2}$`)

// checkCodes refuses country codes that no source can serve, so a typo is caught before the
// firewall is changed. A code is known if it is two letters, "tor", or has a file in the mirror.
// It must be called after the mirror is configured.
func checkCodes(inv file.Inventory) error {
	for _, l := range allListsOf(inv) {
		c := strings.ToLower(l.entry.Country)
		if c == "" || c == "tor" || twoLetters.MatchString(c) || netutils.MirrorHas(c) {
			continue
		}
		return fmt.Errorf("%s %q: unknown country code %q: use a two-letter code, tor, or put %s.txt in the mirror",
			l.kind, l.entry.Name, l.entry.Country, c)
	}
	return nil
}

// Kinds of list. An allow list's rules ACCEPT and sit above every drop rule; a block list's DROP.
const (
	kindAllow = "allow"
	kindBlock = "block"
	// kindOnly lists are accepted by the allow-only chain; everything else inbound is refused.
	kindOnly = "only"
)

// list is one allow or block list as it is applied.
type list struct {
	entry file.BlockEntry
	kind  string
}

// setName is the ipset name: <name>-allow or <name>-block.
func (l list) setName() string {
	return l.entry.SetNameFor(l.kind)
}

func (l list) target() string {
	if l.kind == kindBlock {
		return "DROP"
	}
	return "ACCEPT"
}

// table and chain are where the list's own rules live: raw IPSET_FW for allow and block lists,
// filter IPSET_ONLY for only lists.
func (l list) table() string {
	if l.kind == kindOnly {
		return onlyTable
	}
	return baseRule().Table
}

func (l list) chain() string {
	if l.kind == kindOnly {
		return onlyChain
	}
	return baseRule().Chain
}

// directions: a block list matches one direction, src unless set. An allow list matches both
// source and destination, like allowed addresses, unless a direction is set.
func (l list) directions() []string {
	if l.kind == kindOnly {
		return []string{"src"}
	}
	if l.kind == kindAllow && l.entry.Direction == "" {
		return []string{"src", "dst"}
	}
	return []string{l.entry.DirectionOrDefault()}
}

// rules returns this list's iptables rules, without the chain name. It is the one definition of
// a list rule, used by apply, clear, status and verify. A port list matches protocol and port
// through the set: <dir>,dst.
func (l list) rules() [][]string {
	if l.kind == kindOnly {
		return [][]string{onlyListRule(l)}
	}
	var out [][]string
	for _, dir := range l.directions() {
		if l.entry.IsPort() {
			out = append(out, []string{"-p", l.entry.ProtoOrDefault(), "-m", "set", "--match-set", l.setName(), dir + ",dst", "-j", l.target()})
		} else {
			out = append(out, []string{"-m", "set", "--match-set", l.setName(), dir, "-j", l.target()})
		}
	}
	return out
}

// allowListsOf and blockListsOf return the lists of each kind in config order.
func allowListsOf(inv file.Inventory) []list {
	var out []list
	for _, e := range inv.AllowLists() {
		out = append(out, list{entry: e, kind: kindAllow})
	}
	return out
}

func blockListsOf(inv file.Inventory) []list {
	var out []list
	for _, e := range inv.BlockLists() {
		out = append(out, list{entry: e, kind: kindBlock})
	}
	return out
}

func onlyListsOf(inv file.Inventory) []list {
	var out []list
	for _, e := range inv.OnlyLists() {
		out = append(out, list{entry: e, kind: kindOnly})
	}
	return out
}

// listsOf returns the allow and block lists (the ones with rules in raw IPSET_FW), allow first.
func listsOf(inv file.Inventory) []list {
	return append(allowListsOf(inv), blockListsOf(inv)...)
}

// allListsOf returns every list in the config: allow, only, then block.
func allListsOf(inv file.Inventory) []list {
	out := allowListsOf(inv)
	out = append(out, onlyListsOf(inv)...)
	return append(out, blockListsOf(inv)...)
}

// maxChangeFor is the change guard in percent for one list: its own maxChange if set, else the
// config's, else 0 (no guard). "off" gives 0.
func maxChangeFor(inv file.Inventory, l list) int {
	v := inv.MaxChange
	if l.entry.MaxChange != "" {
		v = l.entry.MaxChange
	}
	percent, _, err := file.ParseMaxChange(v)
	if err != nil {
		return 0 // Validate has already refused bad values; this never happens for a checked config
	}
	return percent
}
