package netutils

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/EvilSuperstars/go-cidrman"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/logger"
)

const GeoURL string = "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/COUNTRY_CODE.cidr"
const TorURL string = "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst"

func IsCIDRValid(ip string) (string, bool) {
	_, _, err := net.ParseCIDR(ip)
	if err != nil {
		tmpIP := net.ParseIP(ip)
		if tmpIP == nil {
			return "", false
		}
		return ip + "/32", true
	}
	return ip, true
}

func NetworkContainsIP(cidr string, ip string) bool {
	network, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic(err)
	}

	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		panic(err)
	}

	b := network.Contains(parsedIP)
	return b
}

func CheckIPExistsInPool(ipList []string, targetIP string, verbose bool) bool {
	for _, ip := range ipList {

		_, isValid := IsCIDRValid(ip)
		if !isValid {
			continue
		}
		if NetworkContainsIP(ip, targetIP) {
			fmt.Printf("%v exists in %v\n", targetIP, ip)
			return true
		}
	}
	fmt.Printf("%v does not exist.\n", targetIP)
	return false
}

// FetchIPPool returns the merged CIDR list for a country (or tor), read either
// from filePath or from GitHub. It returns an error instead of exiting, and
// never returns an empty list without an error.
func FetchIPPool(countryCode string, verbose bool, filePath string, logFilePath string) ([]string, error) {

	var url string
	countryCode = strings.ToLower(countryCode)

	if countryCode == "tor" {
		url = TorURL
	} else {
		url = strings.Replace(GeoURL, "COUNTRY_CODE", countryCode, 1)
	}

	var lines []string
	var source string
	if filePath != "" {
		// If file argument is passed, read file and create set
		logger.Log("Reading file from "+filePath, logFilePath, verbose)
		fileLines, err := file.ReadListFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", filePath, err)
		}
		lines = fileLines
		source = filePath
	} else {
		// Else, go fetch from github
		fetched, err := fetchURL(url, logFilePath, verbose)
		if err != nil {
			return nil, err
		}
		lines = fetched
		source = url
	}

	list := MergeIPsToCIDRs(lines)
	if len(list) == 0 {
		return nil, fmt.Errorf("no valid networks found in %s", source)
	}
	return list, nil
}

// fetchURL downloads a newline-separated list, failing on transport errors,
// timeouts and non-2xx responses.
func fetchURL(url string, logFilePath string, verbose bool) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	logger.Log("Trying to get url: "+url, logFilePath, verbose)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("fetching %s: unexpected status %s", url, resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body of %s: %w", url, err)
	}
	logger.Log("Finished fetching list of IPs", logFilePath, verbose)
	return strings.Split(string(b), "\n"), nil
}

// MergeIPsToCIDRs normalizes and merges a list of IPs/CIDRs. Invalid lines,
// IPv6 entries and blank lines are skipped. It never panics.
func MergeIPsToCIDRs(ipList []string) []string {

	var ipNetList []*net.IPNet
	var ipListMerged []string

	for _, line := range ipList {
		ip := strings.TrimSpace(line)
		if ip == "" || strings.Contains(ip, ":") {
			continue
		}
		normalized, isValid := IsCIDRValid(ip)
		if !isValid {
			continue
		}
		_, ipNet, err := net.ParseCIDR(normalized)
		if err != nil || ipNet == nil {
			continue
		}
		ipNetList = append(ipNetList, ipNet)
	}
	merged, err := cidrman.MergeIPNets(ipNetList)
	if err != nil {
		return nil
	}
	for _, ip := range merged {
		ipListMerged = append(ipListMerged, ip.String())
	}
	return ipListMerged
}
