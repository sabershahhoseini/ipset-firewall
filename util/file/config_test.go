package file

import (
	"strings"
	"testing"
	"time"

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
	if addrs := inv.AllowAddresses(); len(addrs) != 2 || addrs[1] != "203.0.113.42" {
		t.Fatalf("allow addresses = %q", addrs)
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
		{"bad allow address", "allow: [1.2.3]\nblock: [ir]\n", "invalid address"},
		{"bad allow code", "allow: [not/an/ip/really]\nblock: [ir]\n", "invalid network"},
		{"path-like code refused", "block:\n  - {name: x, country: ../etc}\n", "invalid country code"},
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

func TestCanonicalAddr(t *testing.T) {
	tests := map[string]string{
		"203.0.113.42":    "203.0.113.42/32",
		"10.0.0.0/8":      "10.0.0.0/8",
		"10.1.2.3/8":      "10.0.0.0/8",
		"192.0.2.77/24":   "192.0.2.0/24",
		"198.51.100.7/32": "198.51.100.7/32",
	}
	for in, want := range tests {
		got, err := CanonicalAddr(in)
		if err != nil || got != want {
			t.Errorf("CanonicalAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := CanonicalAddr("not-an-ip"); err == nil {
		t.Error("CanonicalAddr accepted an invalid address")
	}
}

func TestAllowAndBlockAcceptTheSameForms(t *testing.T) {
	inv := parse(t, `
allow:
  - 203.0.113.42
  - ir
  - name: partners
    ips: [198.51.100.0/24]
    ports: [443]
block:
  - 192.0.2.7
  - 192.0.2.0/28
  - tor
  - name: scanners
    ips: [198.51.100.128/25]
`)
	if err := inv.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := inv.AllowAddresses(); len(got) != 1 || got[0] != "203.0.113.42" {
		t.Errorf("AllowAddresses = %q", got)
	}
	al := inv.AllowLists()
	if len(al) != 2 || al[0].SetNameFor("allow") != "ir-allow" || al[1].SetNameFor("allow") != "partners-allow" || !al[1].IsPort() {
		t.Errorf("AllowLists = %+v", al)
	}
	bl := inv.BlockLists()
	if len(bl) != 3 {
		t.Fatalf("BlockLists = %+v", bl)
	}
	if bl[0].SetName() != "tor-block" || bl[1].SetName() != "scanners-block" {
		t.Errorf("block list names = %s, %s", bl[0].SetName(), bl[1].SetName())
	}
	if bl[2].SetName() != "addresses-block" || len(bl[2].IPs) != 2 {
		t.Errorf("bare block addresses = %+v", bl[2])
	}
}

func TestListInBothAllowAndBlockRefused(t *testing.T) {
	err := parse(t, "allow: [ir]\nblock: [ir]\n").Validate()
	if err == nil || !strings.Contains(err.Error(), "both allow and block") {
		t.Fatalf("error = %v", err)
	}
}

func TestReservedAddressesName(t *testing.T) {
	err := parse(t, "block:\n  - {name: addresses, ips: [192.0.2.1]}\n").Validate()
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("error = %v", err)
	}
}

func TestOnlyParsesAndValidates(t *testing.T) {
	inv := parse(t, "only:\n  - ir\n  - 203.0.113.42\n  - name: office\n    ips: [198.51.100.0/24]\nonlyAction: reject\n")
	if err := inv.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ol := inv.OnlyLists()
	if len(ol) != 3 || ol[0].SetNameFor("only") != "ir-only" || ol[2].SetNameFor("only") != "addresses-only" {
		t.Errorf("OnlyLists = %+v", ol)
	}
	if inv.OnlyActionOrDefault() != "reject" {
		t.Errorf("action = %q", inv.OnlyActionOrDefault())
	}
	for doc, want := range map[string]string{
		"only: [ir]\nonlyAction: deny\n":   "drop or reject",
		"onlyAction: drop\nblock: [tor]\n": "only is empty",
		"only: [ir]\nblock: [ir]\n":        "both only and block",
	} {
		if err := parse(t, doc).Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error = %v, want %q", doc, err, want)
		}
	}
	if parse(t, "only: [ir]\n").OnlyActionOrDefault() != "drop" {
		t.Error("default action is not drop")
	}
}

func TestHooksValidation(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{"good", "hooks:\n  timeout: 20s\n  before:\n    - run: [/usr/local/bin/a, --x]\n      onFailure: warn\n  after:\n    - run: [/b]\n      when: changed\n      onFailure: rollback\n      timeout: 5s\nblock: [ir]\n", ""},
		{"onError run", "hooks:\n  onError:\n    - run: [/c]\nblock: [ir]\n", ""},
		{"webhooks", "hooks:\n  after:\n    - webhook: https://hooks.example.com/a/SECRET\n      retries: 3\n      timeout: 5s\n      when: changed\n  onError:\n    - webhook: http://127.0.0.1:8080/x\nblock: [ir]\n", ""},
		{"webhook ftp", "hooks:\n  after:\n    - webhook: ftp://x/SECRET\nblock: [ir]\n", "http:// or https://"},
		{"webhook no host", "hooks:\n  after:\n    - webhook: https:///SECRET\nblock: [ir]\n", "http:// or https://"},
		{"webhook garbage", "hooks:\n  after:\n    - webhook: SECRET-TOKEN\nblock: [ir]\n", "http:// or https://"},
		{"defaults only", "hooks:\n  after:\n    - run: [/b]\nblock: [ir]\n", ""},
		{"relative path", "hooks:\n  before:\n    - run: [a.sh]\nblock: [ir]\n", "absolute path"},
		{"neither run nor webhook", "hooks:\n  before:\n    - when: changed\nblock: [ir]\n", "set run"},
		{"both", "hooks:\n  after:\n    - run: [/a]\n      webhook: http://x\nblock: [ir]\n", "not both"},
		{"before with when", "hooks:\n  before:\n    - run: [/a]\n      when: changed\nblock: [ir]\n", "only for after"},
		{"before rollback", "hooks:\n  before:\n    - run: [/a]\n      onFailure: rollback\nblock: [ir]\n", "abort or warn"},
		{"after abort", "hooks:\n  after:\n    - run: [/a]\n      onFailure: abort\nblock: [ir]\n", "warn or rollback"},
		{"after bad when", "hooks:\n  after:\n    - run: [/a]\n      when: never\nblock: [ir]\n", "always or changed"},
		{"onError rollback", "hooks:\n  onError:\n    - run: [/a]\n      onFailure: rollback\nblock: [ir]\n", "must be warn"},
		{"onError with when", "hooks:\n  onError:\n    - run: [/a]\n      when: changed\nblock: [ir]\n", "only for after"},
		{"bad timeout", "hooks:\n  after:\n    - run: [/a]\n      timeout: soon\nblock: [ir]\n", "positive duration"},
		{"zero timeout", "hooks:\n  timeout: 0s\n  after:\n    - run: [/a]\nblock: [ir]\n", "positive duration"},
		{"retries too high", "hooks:\n  after:\n    - run: [/a]\n      retries: 11\nblock: [ir]\n", "0 to 10"},
		{"with legacy rules", "hooks:\n  after:\n    - run: [/a]\nrules:\n  - country: ir\n    set: ir-block\n", "hooks need the block"},
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

func TestHookDefaults(t *testing.T) {
	inv := parse(t, "hooks:\n  timeout: 20s\n  before:\n    - run: [/a]\n  after:\n    - run: [/b]\n      timeout: 5s\n    - run: [/c]\n")
	h := inv.Hooks
	if got := h.TimeoutFor(h.After[0]); got != 5*time.Second {
		t.Errorf("own timeout = %v", got)
	}
	if got := h.TimeoutFor(h.After[1]); got != 20*time.Second {
		t.Errorf("section timeout = %v", got)
	}
	if got := (HooksConfig{}).TimeoutFor(Hook{}); got != DefaultHookTimeout {
		t.Errorf("default timeout = %v", got)
	}
	if h.Before[0].OnFailureOrDefault("before") != "abort" || h.After[0].OnFailureOrDefault("after") != "warn" {
		t.Error("default failure policies wrong")
	}
}

func TestWebhookErrorsAndLabelsNeverShowTheURL(t *testing.T) {
	for _, doc := range []string{
		"hooks:\n  after:\n    - webhook: ftp://host/SECRET-TOKEN\nblock: [ir]\n",
		"hooks:\n  after:\n    - webhook: SECRET-TOKEN\nblock: [ir]\n",
	} {
		if err := parse(t, doc).Validate(); err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("error = %v (must fail and not contain the URL)", err)
		}
	}
	h := Hook{Webhook: "https://user:pw@hooks.example.com:8443/services/T0/B0/SECRET-TOKEN?token=SECRET2"}
	if got := h.Name(); got != "webhook https://hooks.example.com" {
		t.Errorf("Name = %q", got)
	}
	if WebhookLabel("garbage") != "webhook" {
		t.Errorf("label for garbage = %q", WebhookLabel("garbage"))
	}
}

func TestParseMaxChange(t *testing.T) {
	ok := map[string]int{"": 0, "1%": 1, "50%": 50, "1000%": 1000}
	for in, want := range ok {
		got, off, err := ParseMaxChange(in)
		if err != nil || off || got != want {
			t.Errorf("ParseMaxChange(%q) = %d,%v,%v; want %d", in, got, off, err, want)
		}
	}
	if _, off, err := ParseMaxChange("off"); err != nil || !off {
		t.Errorf("off: off=%v err=%v", off, err)
	}
	for _, bad := range []string{"0%", "1001%", "5000%", "abc", "50", "-5%", "%", "5.5%"} {
		if _, _, err := ParseMaxChange(bad); err == nil {
			t.Errorf("ParseMaxChange(%q) accepted", bad)
		}
	}
}

func TestMaxChangeValidation(t *testing.T) {
	if err := parse(t, "maxChange: 50%\nblock:\n  - name: a\n    ips: [192.0.2.1]\n    maxChange: off\n").Validate(); err != nil {
		t.Errorf("valid maxChange rejected: %v", err)
	}
	for _, doc := range []string{
		"maxChange: 0%\nblock: [ir]\n",
		"maxChange: 5000%\nblock: [ir]\n",
		"block:\n  - name: a\n    ips: [192.0.2.1]\n    maxChange: abc\n",
	} {
		if err := parse(t, doc).Validate(); err == nil || !strings.Contains(err.Error(), "maxChange") {
			t.Errorf("%q: error = %v", doc, err)
		}
	}
}
