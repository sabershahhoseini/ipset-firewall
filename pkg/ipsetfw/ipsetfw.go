package ipsetfw

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func fetchIPPool(url, countryCode string) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalln(err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	// b, err := ioutil.ReadAll(resp.Body)  Go.1.15 and earlier
	if err != nil {
		log.Fatalln(err)
	}

	return string(b)
}

func IPsetfw(countryCode string, iptables bool) {
	var url string
	url = "https://git.herrbischoff.com/country-ip-blocks-alternative/plain/ipv4/ir.netset"
	ipList := fetchIPPool(url, countryCode)
	fmt.Println(ipList)
	// Construct a new ipset instance
	// ipset, err := ipset.New()
	// if err != nil {
	// 	// Your custom error handling here.
	// }

	// // Create a new set
	// err := ipset.Create("my_set", "hash:ip")
	// if err != nil {
	// 	// Your custom error handling here.
	// }
	// err := ipset.Add("my_set", "127.0.0.1")
	// if err != nil {
	// 	// Your custom error handling here.
	// }
}
