package ipsetfw

import (
	"errors"
	"net"
	"testing"

	"github.com/lrh3321/ipset-go"
)

func entry(cidr string) ipset.Entry {
	return convertIPToEntry(cidr)
}

func TestDiffEntries(t *testing.T) {
	prev := []ipset.Entry{entry("10.0.0.0/8"), entry("192.0.2.1/32"), entry("198.51.100.0/24")}
	next := []ipset.Entry{entry("10.0.0.0/8"), entry("192.0.2.1/32"), entry("203.0.113.0/24"), entry("203.0.113.9/32")}
	added, removed := diffEntries(prev, next)
	if added != 2 || removed != 1 {
		t.Errorf("added=%d removed=%d, want 2 and 1", added, removed)
	}
	if a, r := diffEntries(next, next); a != 0 || r != 0 {
		t.Errorf("same contents: added=%d removed=%d", a, r)
	}
}

func TestDiffTreatsMissingPrefixAsHost(t *testing.T) {
	// The kernel may list a host entry without its /32.
	fromKernel := ipset.Entry{IP: net.ParseIP("192.0.2.1").To4()}
	if a, r := diffEntries([]ipset.Entry{fromKernel}, []ipset.Entry{entry("192.0.2.1/32")}); a != 0 || r != 0 {
		t.Errorf("host without prefix counted as a change: added=%d removed=%d", a, r)
	}
}

func TestDiffPortEntries(t *testing.T) {
	prev := portEntries([]string{"192.0.2.0/24"}, []int{22, 443}, "tcp")
	next := portEntries([]string{"192.0.2.0/24"}, []int{22, 80}, "tcp")
	if a, r := diffEntries(prev, next); a != 1 || r != 1 {
		t.Errorf("added=%d removed=%d, want 1 and 1", a, r)
	}
	udp := portEntries([]string{"192.0.2.0/24"}, []int{22, 443}, "udp")
	if a, r := diffEntries(prev, udp); a != 2 || r != 2 {
		t.Errorf("tcp vs udp: added=%d removed=%d, want 2 and 2", a, r)
	}
}

func TestReportFinishAndSummary(t *testing.T) {
	r := newReport("apply", "x.yml")
	r.Lists = []listReport{{Status: "unchanged"}, {Status: "unchanged"}}
	r.finish(nil)
	if r.Changed || r.Result != "ok" {
		t.Errorf("unchanged run: changed=%v result=%s", r.Changed, r.Result)
	}
	if got := r.summary(); got != "0 updated, 2 unchanged, 0 failed" {
		t.Errorf("summary = %q", got)
	}
	r = newReport("apply", "x.yml")
	r.Lists = []listReport{{Status: "updated"}, {Kind: "block", Name: "tor", Status: "failed"}, {Status: "skipped"}}
	r.finish(errors.New("boom"))
	if !r.Changed || r.Result != "failed" || len(r.failedNames()) != 1 || r.failedNames()[0] != "block tor" {
		t.Errorf("failed run: %+v", r)
	}
	if got := r.summary(); got != "1 updated, 0 unchanged, 1 failed, 1 skipped" {
		t.Errorf("summary = %q", got)
	}
}
