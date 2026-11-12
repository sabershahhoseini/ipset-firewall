package ipsetfw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/lrh3321/ipset-go"
	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/logger"
	"github.com/sabershahhoseini/ipset-firewall/util/usermgmt"
)

// hookPathEnv is the only PATH a hook gets.
const hookPathEnv = "/usr/sbin:/usr/bin:/sbin:/bin"

// checkHookFile refuses a hook program that someone other than root could have changed. Hooks
// run as root, so the file must be a regular file, owned by root, not writable by group or
// others, and executable by its owner. A symbolic link is followed and its target is checked.
func checkHookFile(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("hook %s refused: %w", path, err)
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("hook %s refused: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("hook %s refused: not a regular file", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("hook %s refused: cannot read its owner", path)
	}
	if st.Uid != 0 || fi.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("hook %s refused: must be owned by root and not writable by group or others", path)
	}
	if fi.Mode().Perm()&0100 == 0 {
		return fmt.Errorf("hook %s refused: not executable by its owner", path)
	}
	return nil
}

// hookEnv is the environment of a hook: a fixed PATH and the IPSETFW_ variables.
func hookEnv(event string, rep *runReport, reportFile string) []string {
	return []string{
		"PATH=" + hookPathEnv,
		"IPSETFW_EVENT=" + event,
		"IPSETFW_ACTION=" + rep.Action,
		"IPSETFW_CONFIG=" + rep.Config,
		"IPSETFW_RESULT=" + rep.Result,
		"IPSETFW_CHANGED=" + strconv.FormatBool(rep.Changed),
		"IPSETFW_ERROR=" + strings.Join(rep.Errors, "; "),
		"IPSETFW_FAILED=" + strings.Join(rep.failedNames(), ","),
		"IPSETFW_REPORT=" + reportFile,
	}
}

// writeHookReport writes the report to a private temporary file in dir for a hook to read.
// The caller removes it.
func writeHookReport(dir string, rep *runReport) (string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "hook-report-*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if _, err := f.Write(b); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// hookFailure is a hook that did not succeed.
type hookFailure struct {
	hook  file.Hook
	index int
	err   error
}

// hookRunner runs the hooks of one run.
type hookRunner struct {
	cfg         file.HooksConfig
	reportDir   string
	logFilePath string
}

func newHookRunner(inv file.Inventory) hookRunner {
	return hookRunner{cfg: inv.Hooks, reportDir: filepath.Dir(reportPath(inv)), logFilePath: inv.LogFilePath}
}

// printOutput shows a hook's output line by line, marked with the hook's label, and logs it.
func (r hookRunner) printOutput(label, out string) {
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		msg := "[hook " + label + "] " + line
		fmt.Println(msg)
		logger.Log(msg, r.logFilePath, false)
	}
}

// runProgram runs one hook program with a timeout. The program gets its own process group,
// which is killed on timeout, so nothing it started keeps running.
func (r hookRunner) runProgram(label string, hk file.Hook, env []string) error {
	if err := checkHookFile(hk.Run[0]); err != nil {
		return err
	}
	timeout := r.cfg.TimeoutFor(hk)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, hk.Run[0], hk.Run[1:]...)
	cmd.Env = env
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out

	err := cmd.Run()
	r.printOutput(label, out.String())
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("hook %s timed out after %s", hk.Run[0], timeout)
	}
	if err != nil {
		return fmt.Errorf("hook %s failed: %w", hk.Run[0], err)
	}
	return nil
}

// runEvent runs the hooks of an event in order and returns the ones that failed. After hooks
// with when: changed are skipped when nothing changed. stop is asked after each failure and
// ends the event when it returns true.
func (r hookRunner) runEvent(event string, hooks []file.Hook, rep *runReport, stop func(hookFailure) bool) []hookFailure {
	var failures []hookFailure
	var reportFile string
	for i, hk := range hooks {
		if event == "after" && hk.When == "changed" && !rep.Changed {
			continue
		}
		if reportFile == "" {
			f, err := writeHookReport(r.reportDir, rep)
			if err != nil {
				failures = append(failures, hookFailure{hook: hk, index: i + 1, err: fmt.Errorf("could not write the report for hooks: %w", err)})
				return failures
			}
			reportFile = f
			defer os.Remove(f)
		}
		label := fmt.Sprintf("%s %d", event, i+1)
		started := time.Now()
		err := r.runProgram(label, hk, hookEnv(event, rep, reportFile))
		took := time.Since(started).Round(time.Millisecond)
		if err != nil {
			fmt.Printf("Hook %s (%s): FAILED after %s: %v\n", label, hk.Name(), took, err)
			f := hookFailure{hook: hk, index: i + 1, err: err}
			failures = append(failures, f)
			if stop != nil && stop(f) {
				break
			}
			continue
		}
		fmt.Printf("Hook %s (%s): ok (%s)\n", label, hk.Name(), took)
	}
	return failures
}

// runBefore runs the before hooks. It returns an error when a hook whose failure policy is abort
// failed; hooks after it do not run, and the run must stop before anything is changed.
func (r hookRunner) runBefore(rep *runReport) error {
	var abort error
	r.runEvent("before", r.cfg.Before, rep, func(f hookFailure) bool {
		if f.hook.OnFailureOrDefault("before") == "abort" {
			abort = fmt.Errorf("before hook %d failed, run aborted and nothing changed: %w", f.index, f.err)
			return true
		}
		fmt.Fprintf(os.Stderr, "warning: before hook %d failed, continuing: %v\n", f.index, f.err)
		return false
	})
	return abort
}

// rollbackLists puts every list that this run updated back to its previous contents, by
// swapping it with its backup. It returns a message for each list that could not be rolled back.
func rollbackLists(rep *runReport) []string {
	var problems []string
	for i := range rep.Lists {
		l := &rep.Lists[i]
		if l.Status != "updated" {
			continue
		}
		bak := l.Set + "-bak"
		live, err := ipset.List(l.Set)
		if err != nil {
			problems = append(problems, fmt.Sprintf("could not roll back %s: %v", l.Set, err))
			continue
		}
		prev, err := ipset.List(bak)
		if err != nil {
			why := err.Error()
			if errors.Is(err, syscall.ENOENT) {
				why = "no backup (this was its first update)"
			}
			problems = append(problems, fmt.Sprintf("could not roll back %s: %s", l.Set, why))
			continue
		}
		if prev.TypeName != live.TypeName {
			problems = append(problems, fmt.Sprintf("could not roll back %s: its type changed (%s to %s)", l.Set, prev.TypeName, live.TypeName))
			continue
		}
		if err := ipset.Swap(l.Set, bak); err != nil {
			problems = append(problems, fmt.Sprintf("could not roll back %s: %v", l.Set, err))
			continue
		}
		l.Status, l.Entries, l.Added, l.Removed = "rolledback", int(prev.NumEntries), 0, 0
		rep.RolledBack = append(rep.RolledBack, l.Set)
	}
	return problems
}

// afterRun runs the after hooks of a finished run and returns the run's final error. Nothing runs
// when the run failed. A failing hook is reported; with onFailure: rollback the sets this run
// updated are put back (apply only; iptables rules and allow-only are not rolled back).
// It stops at the first hook that rolled back.
func (r hookRunner) afterRun(inv file.Inventory, rep *runReport, runErr error) error {
	if rep.Result != "ok" || len(r.cfg.After) == 0 {
		return runErr
	}
	failures := r.runEvent("after", r.cfg.After, rep, func(f hookFailure) bool {
		return f.hook.OnFailureOrDefault("after") == "rollback" && rep.Action == "apply"
	})
	for _, f := range failures {
		msg := fmt.Sprintf("after hook %d (%s) failed: %v", f.index, f.hook.Name(), f.err)
		rep.HookFailures = append(rep.HookFailures, msg)
		if f.hook.OnFailureOrDefault("after") != "rollback" {
			fmt.Fprintln(os.Stderr, "warning: "+msg)
			if runErr == nil {
				runErr = errors.New(msg)
			}
			continue
		}
		if rep.Action != "apply" {
			fmt.Fprintln(os.Stderr, "warning: "+msg+" (onFailure: rollback applies to apply only)")
			if runErr == nil {
				runErr = errors.New(msg)
			}
			continue
		}
		problems := rollbackLists(rep)
		fmt.Fprintf(os.Stderr, "%s; rolled back %d set(s)\n", msg, len(rep.RolledBack))
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "warning: "+p)
		}
		fmt.Fprintln(os.Stderr, "note: iptables rules and allow-only are not rolled back")
		rep.Result = "failed"
		rep.Errors = append(rep.Errors, fmt.Sprintf("%s; rolled back %d set(s)", msg, len(rep.RolledBack)))
		rep.Errors = append(rep.Errors, problems...)
		if inv.Persist {
			if ipt, err := iptables.New(); err != nil {
				fmt.Fprintln(os.Stderr, "warning: could not save snapshot: "+err.Error())
			} else if err := saveSnapshot(ipt, inv); err != nil {
				fmt.Fprintln(os.Stderr, "warning: could not save snapshot: "+err.Error())
			}
		}
		return fmt.Errorf("%s; rolled back %d set(s)", msg, len(rep.RolledBack))
	}
	return runErr
}

// sampleReport is a made-up report for -test-hook.
func sampleReport(config, event string) *runReport {
	rep := newReport("apply", config)
	if event != "before" {
		rep.Result = "ok"
		rep.Changed = true
		rep.Lists = []listReport{
			{Kind: "block", Name: "tor", Set: "tor-block", Status: "updated", Source: "country tor", Type: "hash:net", Entries: 702, Added: 15, Removed: 4},
			{Kind: "block", Name: "ir", Set: "ir-block", Status: "unchanged", Source: "country ir", Type: "hash:net", Entries: 1747},
		}
		rep.Duration = "1.2s"
	}
	if event == "onError" {
		rep.Result = "failed"
		rep.Errors = []string{"sample error from -test-hook"}
	}
	return rep
}

// TestHooks runs the hooks of one event (before, after or onError) against a sample report.
// It changes no sets or rules, and never rolls back.
func TestHooks(path, event string, verbose bool) error {
	usermgmt.ExitIfNotRoot()
	inv := file.DecodeConfig(file.ReadConfigFile(path))
	if err := inv.Validate(); err != nil {
		return err
	}
	r := newHookRunner(inv)
	var hooks []file.Hook
	switch event {
	case "before":
		hooks = r.cfg.Before
	case "after":
		hooks = r.cfg.After
	case "onError":
		hooks = r.cfg.OnError
	default:
		return fmt.Errorf("-test-hook takes before, after or onError, got %q", event)
	}
	if len(hooks) == 0 {
		fmt.Printf("no %s hooks configured\n", event)
		return nil
	}
	failures := r.runEvent(event, hooks, sampleReport(path, event), nil)
	for _, f := range failures {
		if f.hook.OnFailureOrDefault(event) == "rollback" {
			fmt.Printf("note: hook %s %d would roll back the sets in a real run\n", event, f.index)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d of %d %s hook(s) failed", len(failures), len(hooks), event)
	}
	return nil
}

// describeHooks lists the configured hooks for -plan, and refuses hooks that would not run.
// It returns the number of problems.
func describeHooks(inv file.Inventory) int {
	h := inv.Hooks
	if !h.Any() {
		return 0
	}
	onlyChanged := 0
	for _, hk := range h.After {
		if hk.When == "changed" {
			onlyChanged++
		}
	}
	fmt.Printf("hooks: before %d, after %d (%d only when changed), onError %d\n", len(h.Before), len(h.After), onlyChanged, len(h.OnError))
	problems := 0
	show := func(event string, hooks []file.Hook) {
		for _, hk := range hooks {
			var opts []string
			if hk.When == "changed" {
				opts = append(opts, "when changed")
			}
			opts = append(opts, "on failure: "+hk.OnFailureOrDefault(event))
			opts = append(opts, "timeout "+h.TimeoutFor(hk).String())
			fmt.Printf("  %-8s %s (%s)\n", event, hk.Name(), strings.Join(opts, ", "))
			if err := checkHookFile(hk.Run[0]); err != nil {
				fmt.Printf("          PROBLEM: %v; apply would refuse to run it\n", err)
				problems++
			}
		}
	}
	show("before", h.Before)
	show("after", h.After)
	show("onError", h.OnError)
	return problems
}
