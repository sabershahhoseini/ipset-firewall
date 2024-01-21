package file

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/sabershahhoseini/ipset-firewall/error/checkerr"
	"github.com/sabershahhoseini/ipset-firewall/util/logger"
	"gopkg.in/yaml.v2"
)

type IPtablesRule struct {
	Policy string `yaml:"policy"`
	Insert int    `yaml:"insert"`
	Chain  string `yaml:"chain"`
}

type Rule struct {
	Country  string   `yaml:"country"`
	SetName  string   `yaml:"set"`
	Path     []string `yaml:"file"`
	ExtraIPs []string `yaml:"extraIPs"`
	IPtables IPtablesRule
}
type Mattermost struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

// Inventory of all routes in yaml config
type Inventory struct {
	IPSetRules   []Rule     `yaml:"rules"`
	DefaultChain string     `yaml:"defaultChain"`
	Mattermost   Mattermost `yaml:"mattermost"`
}

func ReadConfigFile(path string) string {
	file, err := os.Open(path)
	checkerr.Fatal(err)
	defer file.Close()

	buf := new(strings.Builder)
	_, err = io.Copy(buf, file)
	checkerr.Fatal(err)

	return buf.String()
}

func ReadListFile(file string) []string {
	b, err := os.ReadFile(file)
	checkerr.Fatal(err)

	ipList := strings.Split(string(b), "\n")
	return ipList
}

func DecodeConfig(config string) Inventory {

	reader := strings.NewReader(config)
	d := yaml.NewDecoder(reader)

	var inv Inventory

	// Decode YAML from the source and store it in the value pointed to by inv.
	err := d.Decode(&inv)
	checkerr.Fatal(err)

	return inv
}

func ExportToFile(filePath string, ipList []string, verbose bool) {
	file, err := os.Create(filePath)

	if err != nil {
		log.Fatalf("Failed creating file: %s", err)
	}

	datawriter := bufio.NewWriter(file)

	for _, data := range ipList {
		if data == "" {
			continue
		}
		_, _ = datawriter.WriteString(data + "\n")
	}
	logger.Log("Successfully created file with "+fmt.Sprint((len(ipList)))+" number of entries", verbose)
	logger.Log("File exported at "+filePath, verbose)

	datawriter.Flush()
	file.Close()
}
