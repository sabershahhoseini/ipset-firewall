package ipsetfw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/usermgmt"
)

// DefaultPersistDir holds the snapshot that -restore puts back at boot.
const DefaultPersistDir = "/var/lib/ipsetfw/restore"

// snapshot is this tool's part of the firewall: its sets (in sets.save, as ipset save writes
// them) and the rules of its two chains, as iptables -S prints them. Other rules are not touched.
type snapshot struct {
	Saved    time.Time `json:"saved"`
	Sets     []string  `json:"sets"`
	Raw      []string  `json:"raw"`
	RawJump  bool      `json:"rawJump"`
	Only     []string  `json:"only"`
	OnlyJump bool      `json:"onlyJump"`
}

func persistDir(inv file.Inventory) string {
	if inv.PersistDir != "" {
		return inv.PersistDir
	}
	return DefaultPersistDir
}

// chainRules returns a chain's "-A ..." lines, or nil if the chain does not exist.
func chainRules(ipt *iptables.IPTables, table, chain string) ([]string, error) {
	exists, err := ipt.ChainExists(table, chain)
	if err != nil || !exists {
		return nil, err
	}
	lines, err := ipt.List(table, chain)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, "-A ") {
			out = append(out, l)
		}
	}
	return out, nil
}

func jumpExists(ipt *iptables.IPTables, table, parent, chain string) bool {
	if ok, err := ipt.ChainExists(table, chain); err != nil || !ok {
		return false
	}
	ok, err := ipt.Exists(table, parent, "-j", chain)
	return err == nil && ok
}

// writeAtomic writes a file through a temporary name, so a crash never leaves half a file.
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// saveSnapshot records the live sets and chains of this config for -restore.
func saveSnapshot(ipt *iptables.IPTables, inv file.Inventory) error {
	dir := persistDir(inv)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	var snap snapshot
	var sets bytes.Buffer
	for _, l := range allListsOf(inv) {
		out, err := exec.Command("ipset", "save", l.setName()).Output()
		if err != nil {
			continue // the set does not exist (for example its list failed on the first run)
		}
		sets.Write(out)
		snap.Sets = append(snap.Sets, l.setName())
	}
	r := baseRule()
	var err error
	if snap.Raw, err = chainRules(ipt, r.Table, r.Chain); err != nil {
		return err
	}
	snap.RawJump = jumpExists(ipt, r.Table, r.Parent, r.Chain)
	if snap.Only, err = chainRules(ipt, onlyTable, onlyChain); err != nil {
		return err
	}
	snap.OnlyJump = jumpExists(ipt, onlyTable, onlyParent, onlyChain)
	snap.Saved = time.Now().UTC()

	if err := writeAtomic(filepath.Join(dir, "sets.save"), sets.Bytes()); err != nil {
		return err
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "snapshot.json"), b)
}

// removeSnapshot deletes the saved snapshot (after -clear, so a reboot does not bring it back).
func removeSnapshot(inv file.Inventory) error {
	dir := persistDir(inv)
	for _, f := range []string{"sets.save", "snapshot.json"} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// restoreChain makes a chain hold exactly the saved rules.
func restoreChain(ipt *iptables.IPTables, table, chain string, lines []string) error {
	exists, err := ipt.ChainExists(table, chain)
	if err != nil {
		return err
	}
	if exists {
		err = ipt.ClearChain(table, chain)
	} else {
		err = ipt.NewChain(table, chain)
	}
	if err != nil {
		return err
	}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 || f[0] != "-A" || f[1] != chain {
			return fmt.Errorf("unexpected saved rule %q", l)
		}
		if err := ipt.Append(table, chain, f[2:]...); err != nil {
			return fmt.Errorf("restoring %q: %w", l, err)
		}
	}
	return nil
}

// RestoreConfig puts back the last saved snapshot: sets first, then the chains and their jumps.
// It needs no network and does not read any list source. It is meant for boot, before the
// network starts; while running, a normal apply is the better way to repair things.
func RestoreConfig(path string, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	dir := DefaultPersistDir
	if path != "" {
		inv := file.DecodeConfig(file.ReadConfigFile(path))
		dir = persistDir(inv)
	}
	b, err := os.ReadFile(filepath.Join(dir, "snapshot.json"))
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("no saved snapshot in " + dir + "; nothing to restore")
		return nil
	}
	if err != nil {
		return err
	}
	var snap snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return fmt.Errorf("snapshot %s: %w", dir, err)
	}
	sets, err := os.ReadFile(filepath.Join(dir, "sets.save"))
	if err != nil {
		return err
	}
	cmd := exec.Command("ipset", "restore", "-exist")
	cmd.Stdin = bytes.NewReader(sets)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ipset restore: %w: %s", err, out)
	}

	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	r := baseRule()
	if snap.Raw != nil || snap.RawJump {
		if err := restoreChain(ipt, r.Table, r.Chain, snap.Raw); err != nil {
			return err
		}
		if snap.RawJump {
			if err := ipt.InsertUnique(r.Table, r.Parent, 1, "-j", r.Chain); err != nil {
				return err
			}
		}
	}
	if snap.Only != nil || snap.OnlyJump {
		if err := restoreChain(ipt, onlyTable, onlyChain, snap.Only); err != nil {
			return err
		}
		if snap.OnlyJump {
			if err := ipt.InsertUnique(onlyTable, onlyParent, 1, "-j", onlyChain); err != nil {
				return err
			}
		}
	}
	fmt.Printf("Restored %d set(s), %d rule(s) in %s and %d in %s, saved %s\n",
		len(snap.Sets), len(snap.Raw), r.Chain, len(snap.Only), onlyChain, snap.Saved.Local().Format("2006-01-02 15:04"))
	return nil
}
