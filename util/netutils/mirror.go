package netutils

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sabershahhoseini/ipset-firewall/util/file"
)

// Local mirror settings. A mirror is a directory holding <code>.txt files (for example
// ir.txt, tor.txt), one address or network per line. Offline mode never touches the network.
var (
	mirrorDir string
	offline   bool
)

// SetMirror sets the mirror directory ("" for none) and offline mode.
func SetMirror(dir string, off bool) {
	mirrorDir = dir
	offline = off
}

// mirrorName is the file name used in the mirror for a country code or tor.
func mirrorName(countryCode string) string {
	return countryCode + ".txt"
}

// fromMirror returns the list from the mirror for a country or tor, if the mirror has one.
func fromMirror(countryCode string) ([]string, bool, error) {
	if mirrorDir == "" {
		return nil, false, nil
	}
	p := filepath.Join(mirrorDir, mirrorName(countryCode))
	if _, err := os.Stat(p); err != nil {
		return nil, false, nil
	}
	lines, err := file.ReadListFile(p)
	if err != nil {
		return nil, false, fmt.Errorf("reading mirror file %s: %w", p, err)
	}
	list := MergeIPsToCIDRs(lines)
	if len(list) == 0 {
		return nil, false, fmt.Errorf("mirror file %s has no valid networks", p)
	}
	return list, true, nil
}
