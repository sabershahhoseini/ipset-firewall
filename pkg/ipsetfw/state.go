package ipsetfw

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sabershahhoseini/ipset-firewall/util/file"
)

// DefaultStateFile records, for each block, where its list came from and when it was last applied.
const DefaultStateFile = "/var/lib/ipsetfw/state.json"

// blockState is what status and verify remember about one block entry.
type blockState struct {
	Source  string    `json:"source"`
	Type    string    `json:"type"`
	Updated time.Time `json:"updated"`
}

// stateFile is the whole state document.
type stateFile struct {
	Blocks map[string]blockState `json:"blocks"`
}

func statePath(inv file.Inventory) string {
	if inv.StateFile != "" {
		return inv.StateFile
	}
	return DefaultStateFile
}

// loadState reads the state file. A missing file is an empty state.
func loadState(path string) (stateFile, error) {
	st := stateFile{Blocks: map[string]blockState{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("state file %s: %w", path, err)
	}
	if st.Blocks == nil {
		st.Blocks = map[string]blockState{}
	}
	return st, nil
}

// saveState writes the state file atomically.
func saveState(path string, st stateFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// sourceText describes where a block's addresses come from, for status output.
func sourceText(b file.BlockEntry) string {
	var parts []string
	if b.Country != "" {
		parts = append(parts, "country "+b.Country)
	}
	if len(b.File) > 0 {
		parts = append(parts, "file "+strings.Join(b.File, ","))
	}
	if len(b.IPs) > 0 {
		parts = append(parts, fmt.Sprintf("%d address(es) in config", len(b.IPs)))
	}
	return strings.Join(parts, " + ")
}

// setTypeOf is the ipset type a block entry uses.
func setTypeOf(b file.BlockEntry) string {
	if b.IsPort() {
		return "hash:net,port"
	}
	return "hash:net"
}

// recordBlocks stores the state of blocks that were applied successfully, and drops
// entries for blocks that are no longer in the config.
func recordBlocks(inv file.Inventory, applied map[string]bool) error {
	path := statePath(inv)
	st, err := loadState(path)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, b := range inv.Block {
		keep[b.SetName()] = true
	}
	for name := range st.Blocks {
		if !keep[name] {
			delete(st.Blocks, name)
		}
	}
	now := time.Now().UTC()
	for _, b := range inv.Block {
		if !applied[b.SetName()] {
			continue
		}
		st.Blocks[b.SetName()] = blockState{Source: sourceText(b), Type: setTypeOf(b), Updated: now}
	}
	return saveState(path, st)
}

// forgetBlocks removes the state of every block in the config (used by clear).
func forgetBlocks(inv file.Inventory) error {
	path := statePath(inv)
	st, err := loadState(path)
	if err != nil {
		return err
	}
	for _, b := range inv.Block {
		delete(st.Blocks, b.SetName())
	}
	return saveState(path, st)
}
