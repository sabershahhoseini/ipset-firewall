package file

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func parse(t *testing.T, doc string) Inventory {
	t.Helper()
	var inv Inventory
	if err := yaml.Unmarshal([]byte(doc), &inv); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	return inv
}

func TestParseBlockShorthandAndMap(t *testing.T) {
	inv := parse(t, `
allow:
  - 10.0.0.0/8
  - 203.0.113.42
block:
  - ir
  - name: scanners
    file: [/etc/x.txt]
    ips: [192.0.2.0/24]
    direction: dst
`)
	if len(inv.Allow) != 2 || inv.Allow[1] != "203.0.113.42" {
		t.Fatalf("allow = %q", inv.Allow)
	}
	if len(inv.Block) != 2 {
		t.Fatalf("block count = %d", len(inv.Block))
	}
	ir := inv.Block[0]
	if ir.Name != "ir" || ir.Country != "ir" || ir.SetName() != "ir-block" || ir.Direction != "" {
		t.Errorf("shorthand = %+v set=%s", ir, ir.SetName())
	}
	sc := inv.Block[1]
	if sc.Name != "scanners" || sc.Country != "" || sc.SetName() != "scanners-block" || sc.Direction != "dst" {
		t.Errorf("map entry = %+v set=%s", sc, sc.SetName())
	}
	if len(sc.File) != 1 || len(sc.IPs) != 1 {
		t.Errorf("map sources = file %v ips %v", sc.File, sc.IPs)
	}
}

func TestParseMapWithCountryNameDefaults(t *testing.T) {
	inv := parse(t, "block:\n  - country: TOR\n")
	if inv.Block[0].Name != "tor" || inv.Block[0].SetName() != "tor-block" {
		t.Errorf("name default = %q set=%q", inv.Block[0].Name, inv.Block[0].SetName())
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr string // substring; empty means valid
	}{
		{"valid mixed", "allow: [10.0.0.0/8, 1.2.3.4]\nblock: [ir, {name: x, ips: [192.0.2.1]}]\n", ""},
		{"no source", "block:\n  - name: empty\n", "has no source"},
		{"bad direction", "block:\n  - {name: a, ips: [1.2.3.4], direction: both}\n", "direction must be"},
		{"duplicate set", "block: [ir, {name: ir, ips: [1.2.3.4]}]\n", "duplicate set name"},
		{"long name", "block:\n  - {name: " + strings.Repeat("a", 30) + ", ips: [1.2.3.4]}\n", "longer than 31"},
		{"bad allow", "allow: [not-an-ip]\nblock: [ir]\n", "invalid address"},
		{"bad allow cidr", "allow: [10.0.0.0/99]\nblock: [ir]\n", "invalid network"},
		{"ipv6 allow", "allow: ['2001:db8::1']\nblock: [ir]\n", "IPv6 is not supported"},
		{"ipv6 block ip", "block:\n  - {name: a, ips: ['2001:db8::/32']}\n", "IPv6 is not supported"},
		{"mixed with rules", "rules:\n  - country: ir\n    set: ir-block\nblock: [tor]\n", "mixes 'rules'"},
		{"legacy only is fine", "rules:\n  - country: ir\n    set: ir-block\n", ""},
		{"ports ok", "block:\n  - {name: web, ips: [192.0.2.0/24], ports: [22, 443], proto: udp}\n", ""},
		{"port out of range", "block:\n  - {name: web, ips: [192.0.2.0/24], ports: [70000]}\n", "out of range"},
		{"duplicate port", "block:\n  - {name: web, ips: [192.0.2.0/24], ports: [22, 22]}\n", "duplicate port"},
		{"proto without ports", "block:\n  - {name: web, ips: [192.0.2.0/24], proto: tcp}\n", "proto needs ports"},
		{"bad proto", "block:\n  - {name: web, ips: [192.0.2.0/24], ports: [22], proto: icmp}\n", "tcp or udp"},
		{"bad cache maxAge", "cache:\n  maxAge: soon\nblock: [ir]\n", "cache.maxAge"},
		{"good cache maxAge", "cache:\n  dir: /var/cache/x\n  maxAge: 6h\nblock: [ir]\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parse(t, tt.doc).Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
