package ipsetfw

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lrh3321/ipset-go"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
)

// setChange is what one set update changed.
type setChange struct {
	Total   int
	Added   int
	Removed int
	// Unknown is set when the previous contents could not be read; the set counts as changed.
	Unknown bool
}

func (c setChange) changed() bool {
	return c.Unknown || c.Added > 0 || c.Removed > 0
}

// entryKey is an entry as text for comparing old and new contents. A host entry may come back
// from the kernel without its /32, so a missing prefix counts as /32.
func entryKey(e ipset.Entry) string {
	if e.CIDR == 0 {
		e.CIDR = 32
	}
	return describeEntry(e)
}

// diffEntries counts entries in next that are not in prev (added) and the other way (removed).
func diffEntries(prev, next []ipset.Entry) (added, removed int) {
	old := make(map[string]bool, len(prev))
	for _, e := range prev {
		old[entryKey(e)] = true
	}
	now := make(map[string]bool, len(next))
	for _, e := range next {
		k := entryKey(e)
		now[k] = true
		if !old[k] {
			added++
		}
	}
	for k := range old {
		if !now[k] {
			removed++
		}
	}
	return added, removed
}

// listReport is one list's outcome in a run.
type listReport struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Set     string `json:"set"`
	Status  string `json:"status"` // updated, unchanged, failed, skipped or rolledback
	Source  string `json:"source"`
	Type    string `json:"type"`
	Entries int    `json:"entries"`
	Added   int    `json:"added"`
	Removed int    `json:"removed"`
	Error   string `json:"error,omitempty"`
}

// runReport describes a whole run. It is saved as last-run.json and given to hooks.
type runReport struct {
	Action           string       `json:"action"`
	Result           string       `json:"result"` // ok or failed
	Config           string       `json:"config"`
	Host             string       `json:"host"`
	Started          time.Time    `json:"started"`
	Duration         string       `json:"duration"`
	Changed          bool         `json:"changed"`
	Lists            []listReport `json:"lists"`
	AllowOnly        string       `json:"allowOnly"` // off, active, removed or unchanged
	AllowOnlyChanged bool         `json:"allowOnlyChanged"`
	StaleRemoved     []string     `json:"staleRemoved,omitempty"`
	RolledBack       []string     `json:"rolledBack,omitempty"`
	HookFailures     []string     `json:"hookFailures,omitempty"`
	Errors           []string     `json:"errors,omitempty"`
}

func newReport(action, config string) *runReport {
	host, _ := os.Hostname()
	return &runReport{Action: action, Config: config, Host: host, Started: time.Now().UTC(), AllowOnly: "off", Lists: []listReport{}}
}

// finish fills in the result, whether anything changed, and the duration.
func (r *runReport) finish(err error) {
	r.Result = "ok"
	if err != nil {
		r.Result = "failed"
		r.Errors = append(r.Errors, err.Error())
		// Each failed list's own reason, so hooks and the report say why it failed.
		for _, l := range r.Lists {
			if l.Status == "failed" && l.Error != "" {
				r.Errors = append(r.Errors, l.Kind+" "+l.Name+": "+l.Error)
			}
		}
	}
	r.Changed = r.AllowOnlyChanged || len(r.StaleRemoved) > 0 || len(r.RolledBack) > 0 || r.Action == "clear"
	for _, l := range r.Lists {
		if l.Status == "updated" {
			r.Changed = true
		}
	}
	r.Duration = time.Since(r.Started).Round(time.Millisecond).String()
}

// failedNames are the lists that failed, as "kind name".
func (r *runReport) failedNames() []string {
	var out []string
	for _, l := range r.Lists {
		if l.Status == "failed" {
			out = append(out, l.Kind+" "+l.Name)
		}
	}
	return out
}

// summary is a one-line account of the run for the terminal and the log.
func (r *runReport) summary() string {
	var updated, unchanged, failed, skipped, rolledBack int
	for _, l := range r.Lists {
		switch l.Status {
		case "updated":
			updated++
		case "unchanged":
			unchanged++
		case "failed":
			failed++
		case "skipped":
			skipped++
		case "rolledback":
			rolledBack++
		}
	}
	s := fmt.Sprintf("%d updated, %d unchanged, %d failed", updated, unchanged, failed)
	if skipped > 0 {
		s += fmt.Sprintf(", %d skipped", skipped)
	}
	if rolledBack > 0 {
		s += fmt.Sprintf(", %d rolled back", rolledBack)
	}
	if n := len(r.HookFailures); n > 0 {
		s += fmt.Sprintf(", %d hook failure(s)", n)
	}
	if r.AllowOnlyChanged {
		s += ", allow-only " + r.AllowOnly
	}
	return s
}

// reportPath is where the last run's report is kept: next to the state file.
func reportPath(inv file.Inventory) string {
	return filepath.Join(filepath.Dir(statePath(inv)), "last-run.json")
}

// save writes the report to path, atomically.
func (r *runReport) save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, b)
}
