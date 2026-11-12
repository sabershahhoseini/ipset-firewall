package file

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// CacheConfig controls the list cache. dir "off" disables it; maxAge is a Go duration such as "12h".
type CacheConfig struct {
	Dir    string `yaml:"dir"`
	MaxAge string `yaml:"maxAge"`
}

// maxSetNameLen is ipset's limit on set names.
const maxSetNameLen = 31

// AddressesName is the reserved list name that holds the bare addresses written in block.
const AddressesName = "addresses"

// codePattern is what a country or mirror code may contain. It keeps codes usable as file names.
var codePattern = regexp.MustCompile(`^[a-z0-9_-]{2,20}$`)

// namePattern is what a list name may contain. Its length is limited by the set name check.
var namePattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

// BlockEntry is one entry of a block or allow list. It can be written as:
//   - a bare address or network: "203.0.113.42", "10.0.0.0/8";
//   - a bare country code (or "tor"): "ir";
//   - a map with name, country, file, ips, direction, ports and proto.
type BlockEntry struct {
	Name      string   `yaml:"name"`
	Country   string   `yaml:"country"`
	File      []string `yaml:"file"`
	IPs       []string `yaml:"ips"`
	Direction string   `yaml:"direction"`
	// Ports limits the entry to these destination ports (hash:net,port set).
	Ports []int `yaml:"ports"`
	// Proto is tcp or udp when Ports is set; default tcp.
	Proto string `yaml:"proto"`
	// Address is set when the entry was written as a bare address.
	Address string `yaml:"-"`
}

// IsAddress reports whether the entry is a bare address rather than a list.
func (b BlockEntry) IsAddress() bool {
	return b.Address != ""
}

// IsPort reports whether the entry is limited to ports.
func (b BlockEntry) IsPort() bool {
	return len(b.Ports) > 0
}

// DirectionOrDefault returns the match direction: src unless set.
func (b BlockEntry) DirectionOrDefault() string {
	if b.Direction == "" {
		return "src"
	}
	return b.Direction
}

// ProtoOrDefault returns the protocol for a port entry: tcp unless set.
func (b BlockEntry) ProtoOrDefault() string {
	if b.Proto == "" {
		return "tcp"
	}
	return b.Proto
}

// SetName is the ipset name of a block list: <name>-block.
func (b BlockEntry) SetName() string {
	return b.SetNameFor("block")
}

// SetNameFor is the ipset name of the list for a kind ("block" or "allow"): <name>-<kind>.
func (b BlockEntry) SetNameFor(kind string) string {
	return b.Name + "-" + kind
}

// looksLikeAddress reports whether a bare string is meant as an address rather than a code.
func looksLikeAddress(s string) bool {
	return strings.ContainsAny(s, ".:/")
}

// UnmarshalYAML accepts a bare address, a bare country code, or a full map.
func (b *BlockEntry) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		if looksLikeAddress(s) {
			b.Address = s
			return nil
		}
		b.Country = s
		b.Name = strings.ToLower(s)
		return nil
	}
	type plain BlockEntry
	var p plain
	if err := unmarshal(&p); err != nil {
		return err
	}
	*b = BlockEntry(p)
	if b.Name == "" {
		b.Name = strings.ToLower(b.Country)
	}
	return nil
}

// BlockLists returns the block lists, plus one list named "addresses" holding every bare
// address written in block, if there are any.
func (inv Inventory) BlockLists() []BlockEntry {
	return listsWithAddresses(inv.Block)
}

// OnlyLists returns the allow-only lists, plus one list named "addresses" holding every bare
// address written in only, if there are any.
func (inv Inventory) OnlyLists() []BlockEntry {
	return listsWithAddresses(inv.Only)
}

// OnlyActionOrDefault is the action for inbound connections not allowed by only: drop unless set.
func (inv Inventory) OnlyActionOrDefault() string {
	if inv.OnlyAction == "" {
		return "drop"
	}
	return inv.OnlyAction
}

func listsWithAddresses(entries []BlockEntry) []BlockEntry {
	var lists []BlockEntry
	var addrs []string
	for _, b := range entries {
		if b.IsAddress() {
			addrs = append(addrs, b.Address)
			continue
		}
		lists = append(lists, b)
	}
	if len(addrs) > 0 {
		lists = append(lists, BlockEntry{Name: AddressesName, IPs: addrs})
	}
	return lists
}

// AllowAddresses returns the bare addresses written in allow.
func (inv Inventory) AllowAddresses() []string {
	var addrs []string
	for _, a := range inv.Allow {
		if a.IsAddress() {
			addrs = append(addrs, a.Address)
		}
	}
	return addrs
}

// AllowLists returns the allow entries that are lists.
func (inv Inventory) AllowLists() []BlockEntry {
	var lists []BlockEntry
	for _, a := range inv.Allow {
		if !a.IsAddress() {
			lists = append(lists, a)
		}
	}
	return lists
}

// Validate checks a config before anything is changed. It rejects mixing the old 'rules'
// format with 'block'/'allow', bad addresses and codes, lists with no source, bad directions
// or ports, duplicate or over-long set names, and a list name used in both allow and block.
func (inv Inventory) Validate() error {
	if inv.Cache.MaxAge != "" {
		if _, err := time.ParseDuration(inv.Cache.MaxAge); err != nil {
			return fmt.Errorf("cache.maxAge: %w", err)
		}
	}
	if (len(inv.Block) > 0 || len(inv.Allow) > 0 || len(inv.Only) > 0) && len(inv.IPSetRules) > 0 {
		return fmt.Errorf("config mixes 'rules' with 'block'/'allow'/'only'; use one format")
	}
	if inv.Hooks.Any() || inv.Hooks.Timeout != "" {
		if len(inv.IPSetRules) > 0 {
			return fmt.Errorf("hooks need the block/allow/only format, not 'rules'")
		}
		if err := inv.Hooks.Validate(); err != nil {
			return err
		}
	}
	switch inv.OnlyAction {
	case "", "drop", "reject":
	default:
		return fmt.Errorf("onlyAction must be drop or reject, got %q", inv.OnlyAction)
	}
	if inv.OnlyAction != "" && len(inv.Only) == 0 {
		return fmt.Errorf("onlyAction is set but only is empty")
	}
	allowNames := map[string]bool{}
	seen := map[string]bool{}
	for _, a := range inv.Allow {
		if a.IsAddress() {
			if err := checkAddress(a.Address); err != nil {
				return fmt.Errorf("allow: %w", err)
			}
			continue
		}
		if err := checkList(a, "allow", seen); err != nil {
			return err
		}
		allowNames[a.Name] = true
	}
	onlyNames := map[string]bool{}
	for _, o := range inv.Only {
		if o.IsAddress() {
			if err := checkAddress(o.Address); err != nil {
				return fmt.Errorf("only: %w", err)
			}
			continue
		}
		if o.Name == AddressesName {
			return fmt.Errorf("only: the name %q is reserved for bare addresses", AddressesName)
		}
		if err := checkList(o, "only", seen); err != nil {
			return err
		}
		onlyNames[o.Name] = true
	}
	for _, b := range inv.Block {
		if b.IsAddress() {
			if err := checkAddress(b.Address); err != nil {
				return fmt.Errorf("block: %w", err)
			}
			continue
		}
		if b.Name == AddressesName {
			return fmt.Errorf("block: the name %q is reserved for bare addresses", AddressesName)
		}
		if err := checkList(b, "block", seen); err != nil {
			return err
		}
		if allowNames[b.Name] {
			return fmt.Errorf("list %q is in both allow and block", b.Name)
		}
		if onlyNames[b.Name] {
			return fmt.Errorf("list %q is in both only and block", b.Name)
		}
	}
	return nil
}

// checkList validates one allow or block list and records its set name in seen.
func checkList(b BlockEntry, kind string, seen map[string]bool) error {
	if b.Country == "" && len(b.File) == 0 && len(b.IPs) == 0 {
		return fmt.Errorf("%s %q has no source: set country, file or ips", kind, b.Name)
	}
	if b.Country != "" && !codePattern.MatchString(strings.ToLower(b.Country)) {
		return fmt.Errorf("%s %q: invalid country code %q (use letters, digits, - or _)", kind, b.Name, b.Country)
	}
	if !namePattern.MatchString(b.Name) {
		return fmt.Errorf("%s: invalid name %q (use lowercase letters, digits, - or _)", kind, b.Name)
	}
	switch b.Direction {
	case "", "src", "dst":
	default:
		return fmt.Errorf("%s %q: direction must be src or dst, got %q", kind, b.Name, b.Direction)
	}
	if err := checkPorts(b, kind); err != nil {
		return err
	}
	setName := b.SetNameFor(kind)
	if len(setName) > maxSetNameLen {
		return fmt.Errorf("%s %q: set name %q is longer than %d characters", kind, b.Name, setName, maxSetNameLen)
	}
	if seen[setName] {
		return fmt.Errorf("%s %q: duplicate set name %q", kind, b.Name, setName)
	}
	seen[setName] = true
	for _, ip := range b.IPs {
		if err := checkAddress(ip); err != nil {
			return fmt.Errorf("%s %q: %w", kind, b.Name, err)
		}
	}
	return nil
}

// checkAddress accepts one IPv4 address or IPv4 CIDR.
func checkAddress(s string) error {
	if strings.Contains(s, ":") {
		return fmt.Errorf("%q: IPv6 is not supported", s)
	}
	if strings.Contains(s, "/") {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return fmt.Errorf("%q: invalid network", s)
		}
		return nil
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("%q: invalid address", s)
	}
	return nil
}

// checkPorts validates the ports and proto of a list.
func checkPorts(b BlockEntry, kind string) error {
	if b.Proto != "" && !b.IsPort() {
		return fmt.Errorf("%s %q: proto needs ports", kind, b.Name)
	}
	switch b.Proto {
	case "", "tcp", "udp":
	default:
		return fmt.Errorf("%s %q: proto must be tcp or udp, got %q", kind, b.Name, b.Proto)
	}
	seen := map[int]bool{}
	for _, p := range b.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("%s %q: port %d out of range 1-65535", kind, b.Name, p)
		}
		if seen[p] {
			return fmt.Errorf("%s %q: duplicate port %d", kind, b.Name, p)
		}
		seen[p] = true
	}
	return nil
}

// CanonicalAddr returns an address in the form iptables prints it: a host as a.b.c.d/32 and a
// network as its network address, so 10.1.2.3/8 becomes 10.0.0.0/8.
func CanonicalAddr(s string) (string, error) {
	if err := checkAddress(s); err != nil {
		return "", err
	}
	if !strings.Contains(s, "/") {
		return net.ParseIP(s).String() + "/32", nil
	}
	_, n, _ := net.ParseCIDR(s)
	return n.String(), nil
}
