package sshclients

import (
	"testing"
)

func TestParseProcNetTCP(t *testing.T) {
	// 10.0.0.5:22 <- 203.0.113.42:54321 established; 127.0.0.1:22 listening; 10.0.0.5:80 established.
	data := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0500000A:0016 2A7100CB:D431 01 00000000:00000000 00:00000000 00000000     0        0 1 1
   1: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1
   2: 0500000A:0050 0900000A:C350 01 00000000:00000000 00:00000000 00000000     0        0 3 1
`
	got := ParseProcNetTCP(data, map[int]bool{22: true})
	if len(got) != 1 || got[0].IP.String() != "203.0.113.42" || got[0].LocalPort != 22 {
		t.Fatalf("got %+v", got)
	}
}

func TestParseProcNetTCP6MappedV4(t *testing.T) {
	// sshd on [::]:22 with an IPv4 client 198.51.100.7, shown as ::ffff:198.51.100.7.
	line := "   0: 0000000000000000FFFF00000500000A:0016 0000000000000000FFFF0000076433C6:9C40 01\n"
	got := ParseProcNetTCP(line, map[int]bool{22: true})
	if len(got) != 1 || got[0].IP.String() != "198.51.100.7" || got[0].LocalPort != 22 {
		t.Fatalf("got %+v", got)
	}
}

func TestFromEnv(t *testing.T) {
	c, ok := FromEnv("203.0.113.42 54321 2222")
	if !ok || c.IP.String() != "203.0.113.42" || c.LocalPort != 2222 {
		t.Fatalf("got %+v %v", c, ok)
	}
	if _, ok := FromEnv(""); ok {
		t.Error("empty SSH_CLIENT accepted")
	}
	if _, ok := FromEnv("2001:db8::1 1 22"); ok {
		t.Error("IPv6 SSH_CLIENT accepted")
	}
}
