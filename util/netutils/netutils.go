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

// CountrySources are tried in order for a country code. COUNTRY_CODE is replaced
// with the lowercase code. Both serve one IPv4 network per line (plus comments
// that are skipped as invalid).
var CountrySources = []string{
	"https://www.ipdeny.com/ipblocks/data/countries/COUNTRY_CODE.zone",
	"https://raw.githubusercontent.com/ipverse/rir-ip/master/country/COUNTRY_CODE/ipv4-aggregated.txt",
}

// TorSources are tried in order for the tor exit node list.
var TorSources = []string{
	"https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst",
	"https://check.torproject.org/torbulkexitlist",
}

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
// from filePath or from the first working remote source. It never returns an
// empty list without an error.
func FetchIPPool(countryCode string, verbose bool, filePath string, logFilePath string) ([]string, error) {
	countryCode = strings.ToLower(countryCode)

	if filePath != "" {
		logger.Log("Reading file from "+filePath, logFilePath, verbose)
		fileLines, err := file.ReadListFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", filePath, err)
		}
		list := MergeIPsToCIDRs(fileLines)
		if len(list) == 0 {
			return nil, fmt.Errorf("no valid networks found in %s", filePath)
		}
		return list, nil
	}

	sources := CountrySources
	if countryCode == "tor" {
		sources = TorSources
	}
	urls := make([]string, 0, len(sources))
	for _, src := range sources {
		urls = append(urls, strings.Replace(src, "COUNTRY_CODE", countryCode, 1))
	}
	return fetchFromSources(urls, verbose, logFilePath)
}

// fetchFromSources tries each URL in order and returns the first one that yields
// at least one valid network. A transport error, a non-2xx status or an empty
// result all count as failure and move on to the next URL.
func fetchFromSources(urls []string, verbose bool, logFilePath string) ([]string, error) {
	var errs []string
	for _, url := range urls {
		lines, err := fetchURL(url, logFilePath, verbose)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		list := MergeIPsToCIDRs(lines)
		if len(list) == 0 {
			errs = append(errs, "no valid networks from "+url)
			continue
		}
		logger.Log("Using source "+url, logFilePath, verbose)
		return list, nil
	}
	return nil, fmt.Errorf("all sources failed: %s", strings.Join(errs, "; "))
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
