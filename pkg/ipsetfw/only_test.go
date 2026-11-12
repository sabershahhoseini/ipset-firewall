package ipsetfw

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/lrh3321/ipset-go"

	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/sshclients"
)

func inventory(t *testing.T, doc string) file.Inventory {
	t.Helper()
	inv := file.DecodeConfig(doc)
	if err := inv.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return inv
}

func TestOnlyRulesOrder(t *testing.T) {
	inv := inventory(t, `
allow:
  - 203.0.113.42
  - name: partners
    ips: [198.51.100.0/24]
only:
  - ir
  - name: office
    ips: [192.0.2.0/24]
    ports: [22]
onlyAction: reject
`)
	got, err := onlyRules(inv)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"-i", "lo", "-j", "ACCEPT"},
		{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		{"-s", "203.0.113.42/32", "-j", "ACCEPT"},
		{"-m", "set", "--match-set", "partners-allow", "src", "-j", "ACCEPT"},
		{"-m", "set", "--match-set", "ir-only", "src", "-j", "ACCEPT"},
		{"-p", "tcp", "-m", "set", "--match-set", "office-only", "src,dst", "-j", "ACCEPT"},
		{"-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"},
		{"-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("onlyRules:\n got %q\nwant %q", got, want)
	}
}

func TestOnlyDefaultActionIsDrop(t *testing.T) {
	got, err := onlyRules(inventory(t, "only: [ir]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; strings.Join(last, " ") != "-j DROP" {
		t.Errorf("last rule = %q, want -j DROP", last)
	}
}

func TestClientAllowed(t *testing.T) {
	inv := inventory(t, `
allow: [203.0.113.42]
only:
  - name: office
    ips: [192.0.2.0/24]
    ports: [22]
  - name: web
    ips: [198.51.100.0/24]
    ports: [443]
`)
	// inSet answers from fixed networks, as -plan does.
	nets := map[string]string{"office-only": "192.0.2.0/24", "web-only": "198.51.100.0/24"}
	inSet := func(l list, c sshclients.Client) bool {
		_, n, _ := net.ParseCIDR(nets[l.setName()])
		return n != nil && n.Contains(c.IP)
	}
	cases := []struct {
		ip   string
		port int
		want bool
	}{
		{"203.0.113.42", 22, true},  // allowed address
		{"192.0.2.10", 22, true},    // only list that includes the SSH port
		{"192.0.2.10", 2222, false}, // same network, but sshd on a port the list does not include
		{"198.51.100.5", 22, false}, // only list for 443, not SSH
		{"8.8.8.8", 22, false},      // not listed at all
	}
	for _, c := range cases {
		got := clientAllowed(inv, sshclients.Client{IP: net.ParseIP(c.ip).To4(), LocalPort: c.port}, inSet)
		if got != c.want {
			t.Errorf("clientAllowed(%s:%d) = %v, want %v", c.ip, c.port, got, c.want)
		}
	}
}

func TestZeroNetworkIsSplitInHalves(t *testing.T) {
	for _, entries := range [][]string{
		describeAll(netEntries([]string{"0.0.0.0/0"})),
		describeAll(portEntries([]string{"0.0.0.0/0"}, []int{80}, "tcp")),
	} {
		if len(entries) != 2 || !strings.HasPrefix(entries[0], "0.0.0.0/1") || !strings.HasPrefix(entries[1], "128.0.0.0/1") {
			t.Errorf("entries = %q, want 0.0.0.0/1 and 128.0.0.0/1", entries)
		}
	}
	if got := describeAll(netEntries([]string{"10.0.0.0/8"})); len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Errorf("other networks changed: %q", got)
	}
}

func describeAll(es []ipset.Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, describeEntry(e))
	}
	return out
}
