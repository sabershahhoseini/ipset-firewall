package netutils

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/EvilSuperstars/go-cidrman"
	"github.com/sabershahhoseini/ipset-firewall/error/checkerr"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/logger"
)

const GeoURL string = "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/COUNTRY_CODE.cidr"
const TorURL string = "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst"

func IsCIDRValid(ip string) bool {
	_, _, err := net.ParseCIDR(ip)
	if err != nil {
		return false
	}
	return true
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
		if !IsCIDRValid(ip) {
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

func FetchIPPool(countryCode string, verbose bool, filePath string) []string {

	var ipList []string
	var url string
	countryCode = strings.ToLower(countryCode)

	if countryCode == "tor" {
		url = TorURL
	} else {
		tmpUrl := GeoURL
		url = strings.Replace(tmpUrl, "COUNTRY_CODE", countryCode, 1)
	}

	// If file argument is passed, read file and create set
	if filePath != "" {
		logger.Log("Reading file from "+filePath, verbose)
		ipList = file.ReadListFile(filePath)
		return ipList
	}
	// Else, go fetch from github
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalln(err)
	}

	client := &http.Client{}

	logger.Log("Trying to get url: "+url, verbose)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	list := strings.Split(string(b), "\n")
	logger.Log("Finished fetching list of IPs", verbose)
	return list
}

func MergeIPsToCIDRs(ipList []string) []string {

	var ipNet *net.IPNet
	var ipNetList []*net.IPNet
	var ipListMerged []string

	for _, ip := range ipList {
		if ip == "" || strings.Contains(ip, ":") {
			continue
		}
		if !strings.Contains(ip, "/") {
			_, ipn, err := net.ParseCIDR(ip + "/32")
			checkerr.Fatal(err)
			ipNet = ipn
		}
		ipNetList = append(ipNetList, ipNet)
	}
	merged, _ := cidrman.MergeIPNets(ipNetList)
	for _, ip := range merged {
		ipListMerged = append(ipListMerged, ip.String())
	}
	return ipListMerged
}
