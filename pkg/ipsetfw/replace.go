package ipsetfw

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/lrh3321/ipset-go"
	"github.com/sabershahhoseini/ipset-firewall/util/ipsetcli"
	"github.com/sabershahhoseini/ipset-firewall/util/logger"
)

// replaceSet makes setName hold exactly entries, of type typ.
//
// The entries are built and checked in <name>-tmp. Then a single operation puts them live:
//   - first time (no live set): the temp set is renamed to setName; there is no backup yet;
//   - later: the temp set is swapped with the live set, and the old contents become <name>-bak.
//
// The live set is changed only by that one operation, so an error before it leaves the live set as
// it was. If the live set exists with another type, onTypeChange is called first to remove the
// rules that use it; the old set and its backup are then destroyed and the new set takes its place.
// With onTypeChange nil, a type change is refused.
func replaceSet(setName, typ string, entries []ipset.Entry, onTypeChange func() error, logFilePath string, verbose bool) (setChange, error) {
	change := setChange{Total: len(entries)}
	tmpSetName := setName + "-tmp"
	backupSetName := setName + "-bak"
	maxElem := ipsetcli.MaxElemFor(len(entries))
	logEntries := verbose || logFilePath != ""

	// abort removes the temp set and returns the error. The live set has not been touched.
	abort := func(msg string, err error) error {
		_ = ipset.Destroy(tmpSetName)
		return fmt.Errorf("%s: %w", msg, err)
	}

	// Remove a temp set left behind by an earlier failed run.
	if err := destroySet(tmpSetName); err != nil {
		return change, fmt.Errorf("could not remove stale temp set %s: %w", tmpSetName, err)
	}

	// Build the new contents in the temp set.
	if err := ipsetcli.CreateSet(tmpSetName, typ, maxElem, false); err != nil {
		return change, fmt.Errorf("could not create temp set %s: %w", tmpSetName, err)
	}
	for i := range entries {
		e := entries[i]
		if logEntries {
			logger.Log("Adding "+describeEntry(e), logFilePath, verbose)
		}
		if err := ipset.Add(tmpSetName, &e); err != nil {
			return change, abort("could not add "+describeEntry(e)+" to "+tmpSetName, err)
		}
	}
	tmpInfo, err := ipset.List(tmpSetName)
	if err != nil {
		return change, abort("could not read back temp set "+tmpSetName, err)
	}
	if int(tmpInfo.NumEntries) != len(entries) {
		return change, abort("temp set "+tmpSetName+" has wrong entry count",
			fmt.Errorf("got %d, want %d", tmpInfo.NumEntries, len(entries)))
	}

	live, err := ipset.List(setName)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		return change, abort("could not inspect set "+setName, err)
	}
	exists := err == nil

	if exists && live.TypeName != typ {
		if onTypeChange == nil {
			return change, abort("set "+setName+" already exists as "+live.TypeName+"; rename it or remove it with: ipset destroy "+setName,
				fmt.Errorf("cannot replace it with %s", typ))
		}
		fmt.Printf("Set %s changes type from %s to %s; replacing it\n", setName, live.TypeName, typ)
		if err := onTypeChange(); err != nil {
			return change, abort("could not remove the rules that use "+setName, err)
		}
		change.Removed = int(live.NumEntries)
		if err := ipset.Destroy(setName); err != nil {
			return change, abort("could not remove old set "+setName, err)
		}
		exists = false
	}

	if !exists {
		// A backup without a live set is from an older set of this name; it cannot be rolled back to.
		if err := destroySet(backupSetName); err != nil {
			return change, abort("could not remove old backup "+backupSetName, err)
		}
		if err := ipset.Rename(tmpSetName, setName); err != nil {
			return change, abort("could not rename "+tmpSetName+" to "+setName, err)
		}
		change.Added = len(entries)
		return change, nil
	}

	// One swap puts the new contents live. The temp set then holds the previous contents.
	if err := ipset.Swap(tmpSetName, setName); err != nil {
		return change, abort("could not swap "+tmpSetName+" into "+setName, err)
	}
	// The temp set now holds the previous contents: compare before keeping it as the backup.
	if prev, err := ipset.List(tmpSetName); err == nil {
		change.Added, change.Removed = diffEntries(prev.Entries, entries)
	} else {
		change.Unknown = true
	}
	if err := destroySet(backupSetName); err != nil {
		return change, fmt.Errorf("set %s was updated, but the old backup %s could not be removed: %w", setName, backupSetName, err)
	}
	if err := ipset.Rename(tmpSetName, backupSetName); err != nil {
		return change, fmt.Errorf("set %s was updated, but the backup could not be saved as %s: %w", setName, backupSetName, err)
	}
	return change, nil
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
