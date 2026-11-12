// Package ipsetcli creates hash:net sets through the ipset command.
//
// The ipset-go library cannot set maxelem when it creates a set, so sets
// larger than the kernel default of 65536 entries are created with the
// ipset binary instead. Kernel state is shared, so the library can still
// add, list, swap and destroy these sets.
package ipsetcli

import (
	"fmt"
	"os/exec"
	"strconv"
)

// DefaultMaxElem is the kernel default for hash:net.
const DefaultMaxElem = 65536

// MaxElemFor returns the maxelem to use for a set with n entries.
func MaxElemFor(n int) int {
	if n < DefaultMaxElem {
		return DefaultMaxElem
	}
	return n
}

// CreateHashNetSet creates a hash:net set with the given maxelem. If exist is
// true, an existing set with the same name is left alone.
func CreateHashNetSet(name string, maxElem int, exist bool) error {
	return CreateSet(name, "hash:net", maxElem, exist)
}

// CreateSet creates a set of any type with the given maxelem. If exist is true,
// an existing set with the same name is left alone.
func CreateSet(name, typ string, maxElem int, exist bool) error {
	args := []string{"create", name, typ, "maxelem", strconv.Itoa(maxElem)}
	if exist {
		args = append(args, "-exist")
	}
	out, err := exec.Command("ipset", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset create %s: %w: %s", name, err, string(out))
	}
	return nil
}
