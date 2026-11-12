// Package sshclients finds the addresses of current SSH sessions, so allow-only rules can be
// refused when they would cut off the person applying them.
package sshclients

import (
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
)

// Client is the remote end of an SSH session and the local port it connected to.
type Client struct {
	IP        net.IP
	LocalPort int
}

// tcpEstablished is the connection state "01" in /proc/net/tcp.
const tcpEstablished = "01"

// v4MappedPrefix is how an IPv4-mapped address starts in /proc/net/tcp6.
const v4MappedPrefix = "0000000000000000FFFF0000"

// parseV4 turns a little-endian hex IPv4 word from /proc/net/tcp into an address.
func parseV4(word string) net.IP {
	b, err := hex.DecodeString(word)
	if err != nil || len(b) != 4 {
		return nil
	}
	return net.IPv4(b[3], b[2], b[1], b[0]).To4()
}

// parseAddr parses "ADDR:PORT" from /proc/net/tcp or /proc/net/tcp6. Only IPv4 and
// IPv4-mapped addresses are returned.
func parseAddr(s string) (net.IP, int, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return nil, 0, false
	}
	port, err := strconv.ParseInt(s[i+1:], 16, 32)
	if err != nil {
		return nil, 0, false
	}
	addr := strings.ToUpper(s[:i])
	var ip net.IP
	switch {
	case len(addr) == 8:
		ip = parseV4(addr)
	case len(addr) == 32 && strings.HasPrefix(addr, v4MappedPrefix):
		ip = parseV4(addr[24:])
	}
	if ip == nil {
		return nil, 0, false
	}
	return ip, int(port), true
}

// ParseProcNetTCP returns the remote ends of established connections whose local port is in
// ports, from the text of /proc/net/tcp or /proc/net/tcp6.
func ParseProcNetTCP(data string, ports map[int]bool) []Client {
	var out []Client
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != tcpEstablished {
			continue
		}
		_, lport, ok := parseAddr(f[1])
		if !ok || !ports[lport] {
			continue
		}
		rip, _, ok := parseAddr(f[2])
		if !ok {
			continue
		}
		out = append(out, Client{IP: rip, LocalPort: lport})
	}
	return out
}

// FromEnv parses SSH_CLIENT ("client-ip client-port server-port").
func FromEnv(v string) (Client, bool) {
	f := strings.Fields(v)
	if len(f) != 3 {
		return Client{}, false
	}
	ip := net.ParseIP(f[0]).To4()
	port, err := strconv.Atoi(f[2])
	if ip == nil || err != nil {
		return Client{}, false
	}
	return Client{IP: ip, LocalPort: port}, true
}

// Find returns the current SSH clients: established connections to port 22, plus SSH_CLIENT
// when it is set (it also covers sshd on another port). Duplicates are removed.
func Find() []Client {
	var all []Client
	ports := map[int]bool{22: true}
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if b, err := os.ReadFile(p); err == nil {
			all = append(all, ParseProcNetTCP(string(b), ports)...)
		}
	}
	if c, ok := FromEnv(os.Getenv("SSH_CLIENT")); ok {
		all = append(all, c)
	}
	seen := map[string]bool{}
	var out []Client
	for _, c := range all {
		k := c.IP.String() + ":" + strconv.Itoa(c.LocalPort)
		if !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	return out
}
