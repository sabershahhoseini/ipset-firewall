package file

import (
	"os"
	"strings"

	"github.com/sabershahhoseini/ipset-firewall/error/checkerr"
)

func ReadListFile(file string) []string {
	b, err := os.ReadFile(file)
	checkerr.Fatal(err)

	ipList := strings.Split(string(b), "\n")
	return ipList
}
