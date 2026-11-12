package ipsetfw

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/lrh3321/ipset-go"
	"github.com/sabershahhoseini/ipset-firewall/util/ipsetcli"
	"github.com/sabershahhoseini/ipset-firewall/util/logger"
)

// replaceSet makes setName hold exactly entries, of type typ. The entries are built in a
// temp set, checked, and only then swapped in. The previous contents stay in <name>-bak.
// On any error the live set is left as it was and the temp set is removed.
func replaceSet(setName, typ string, entries []ipset.Entry, logFilePath string, verbose bool) error {
	tmpSetName := setName + "-tmp"
	backupSetName := setName + "-bak"
	maxElem := ipsetcli.MaxElemFor(len(entries))

	// abort removes the temp set and returns the error. The live set is never touched on abort.
	abort := func(msg string, err error) error {
		_ = ipset.Destroy(tmpSetName)
		return fmt.Errorf("%s: %w", msg, err)
	}

	// Remove a temp set left behind by an earlier failed run.
	if err := ipset.Destroy(tmpSetName); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("could not remove stale temp set %s: %w", tmpSetName, err)
	}

	// Build the new contents in the temp set.
	if err := ipsetcli.CreateSet(tmpSetName, typ, maxElem, false); err != nil {
		return fmt.Errorf("could not create temp set %s: %w", tmpSetName, err)
	}
	for i := range entries {
		e := entries[i]
		logger.Log("Adding "+describeEntry(e), logFilePath, verbose)
		if err := ipset.Add(tmpSetName, &e); err != nil {
			return abort("could not add "+describeEntry(e)+" to "+tmpSetName, err)
		}
	}
	tmpInfo, err := ipset.List(tmpSetName)
	if err != nil {
		return abort("could not read back temp set "+tmpSetName, err)
	}
	if int(tmpInfo.NumEntries) != len(entries) {
		return abort("temp set "+tmpSetName+" has wrong entry count",
			fmt.Errorf("got %d, want %d", tmpInfo.NumEntries, len(entries)))
	}

	// An existing live set of another type cannot be swapped with the new one.
	if live, err := ipset.List(setName); err == nil && live.TypeName != typ {
		return abort("set "+setName+" already exists as "+live.TypeName+"; rename the block or run: ipset destroy "+setName,
			fmt.Errorf("cannot replace it with %s", typ))
	}
	if err := ipsetcli.CreateSet(setName, typ, maxElem, true); err != nil {
		return abort("could not create set "+setName, err)
	}

	_, listErr := ipset.List(backupSetName)
	if listErr != nil && !errors.Is(listErr, syscall.ENOENT) {
		return abort("could not inspect backup set "+backupSetName, listErr)
	}
	if listErr != nil {
		// First run: create the backup filled with the new entries, then swap the temp set in.
		if err := ipsetcli.CreateSet(backupSetName, typ, maxElem, false); err != nil {
			return abort("could not create backup set "+backupSetName, err)
		}
		for i := range entries {
			e := entries[i]
			if err := ipset.Add(backupSetName, &e); err != nil {
				_ = ipset.Destroy(backupSetName)
				return abort("could not fill backup set "+backupSetName, err)
			}
		}
		if err := ipset.Swap(tmpSetName, setName); err != nil {
			return abort("could not swap "+tmpSetName+" into "+setName, err)
		}
	} else {
		if err := ipset.Swap(setName, backupSetName); err != nil {
			return abort("could not rotate "+setName+" into "+backupSetName, err)
		}
		if err := ipset.Swap(tmpSetName, setName); err != nil {
			return abort("could not swap "+tmpSetName+" into "+setName, err)
		}
	}

	if err := ipset.Destroy(tmpSetName); err != nil {
		return fmt.Errorf("set %s was updated but temp set %s could not be removed: %w", setName, tmpSetName, err)
	}
	return nil
}

// describeEntry is a short text form of an entry for logs.
func describeEntry(e ipset.Entry) string {
	s := e.IP.String() + "/" + fmt.Sprint(e.CIDR)
	if e.Port != nil {
		proto := "tcp"
		if e.Protocol != nil && *e.Protocol == protoUDP {
			proto = "udp"
		}
		s += fmt.Sprintf(",%s:%d", proto, *e.Port)
	}
	return s
}
