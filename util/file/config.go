package file

import (
	"fmt"
	"net"
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

// BlockEntry is one block list. It can be written as a bare country code
// ("ir") or as a map with name, country, file, ips and direction.
type BlockEntry struct {
	Name      string   `yaml:"name"`
	Country   string   `yaml:"country"`
	File      []string `yaml:"file"`
	IPs       []string `yaml:"ips"`
	Direction string   `yaml:"direction"`
	// Ports limits the block to these destination ports (hash:net,port set).
	Ports []int `yaml:"ports"`
	// Proto is tcp or udp when Ports is set; default tcp.
	Proto string `yaml:"proto"`
}

// IsPort reports whether the entry is limited to ports.
func (b BlockEntry) IsPort() bool {
	return len(b.Ports) > 0
}

// ProtoOrDefault returns the protocol for a port block: tcp unless set.
func (b BlockEntry) ProtoOrDefault() string {
	if b.Proto == "" {
		return "tcp"
	}
	return b.Proto
}

// SetName is the ipset name for the entry: <name>-block.
func (b BlockEntry) SetName() string {
	return b.Name + "-block"
}

// UnmarshalYAML accepts either a country code string or a full map.
func (b *BlockEntry) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var code string
	if err := unmarshal(&code); err == nil {
		b.Country = code
		b.Name = strings.ToLower(code)
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

// Validate checks a config before anything is changed. It rejects mixing the
// old 'rules' format with 'block'/'allow', duplicate or over-long set names,
// blocks with no source, bad directions, and bad addresses.
func (inv Inventory) Validate() error {
	if inv.Cache.MaxAge != "" {
		if _, err := time.ParseDuration(inv.Cache.MaxAge); err != nil {
			return fmt.Errorf("cache.maxAge: %w", err)
		}
	}
	if (len(inv.Block) > 0 || len(inv.Allow) > 0) && len(inv.IPSetRules) > 0 {
		return fmt.Errorf("config mixes 'rules' with 'block'/'allow'; use one format")
	}
	seen := map[string]bool{}
	for _, a := range inv.Allow {
		if err := checkAddress(a); err != nil {
			return fmt.Errorf("allow: %w", err)
		}
	}
	for _, b := range inv.Block {
		if b.Country == "" && len(b.File) == 0 && len(b.IPs) == 0 {
			return fmt.Errorf("block %q has no source: set country, file or ips", b.Name)
		}
		switch b.Direction {
		case "", "src", "dst":
		default:
			return fmt.Errorf("block %q: direction must be src or dst, got %q", b.Name, b.Direction)
		}
		if err := checkPorts(b); err != nil {
			return err
		}
		setName := b.SetName()
		if len(setName) > maxSetNameLen {
			return fmt.Errorf("block %q: set name %q is longer than %d characters", b.Name, setName, maxSetNameLen)
		}
		if seen[setName] {
			return fmt.Errorf("block %q: duplicate set name %q", b.Name, setName)
		}
		seen[setName] = true
		for _, ip := range b.IPs {
			if err := checkAddress(ip); err != nil {
				return fmt.Errorf("block %q: %w", b.Name, err)
			}
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

// checkPorts validates the ports and proto of a block entry.
func checkPorts(b BlockEntry) error {
	if b.Proto != "" && !b.IsPort() {
		return fmt.Errorf("block %q: proto needs ports", b.Name)
	}
	switch b.Proto {
	case "", "tcp", "udp":
	default:
		return fmt.Errorf("block %q: proto must be tcp or udp, got %q", b.Name, b.Proto)
	}
	seen := map[int]bool{}
	for _, p := range b.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("block %q: port %d out of range 1-65535", b.Name, p)
		}
		if seen[p] {
			return fmt.Errorf("block %q: duplicate port %d", b.Name, p)
		}
		seen[p] = true
	}
	return nil
}
