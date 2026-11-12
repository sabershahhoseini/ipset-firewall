package ipsetfw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sabershahhoseini/ipset-firewall/util/file"
)

// script writes an executable shell script with the given mode and owner (root unless uid set).
func script(t *testing.T, body string, mode os.FileMode, uid int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hook.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	if uid != 0 {
		if err := os.Chown(p, uid, uid); err != nil {
			t.Skipf("cannot chown (not root?): %v", err)
		}
	}
	return p
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("needs root: hooks must be owned by root")
	}
}

func TestCheckHookFile(t *testing.T) {
	requireRoot(t)
	if err := checkHookFile(script(t, "true", 0o755, 0)); err != nil {
		t.Errorf("0755 root-owned refused: %v", err)
	}
	if err := checkHookFile(script(t, "true", 0o700, 0)); err != nil {
		t.Errorf("0700 root-owned refused: %v", err)
	}
	for _, m := range []os.FileMode{0o775, 0o757, 0o777, 0o766} {
		err := checkHookFile(script(t, "true", m, 0))
		if err == nil || !strings.Contains(err.Error(), "not writable by group or others") {
			t.Errorf("mode %o: err = %v, want refusal", m, err)
		}
	}
	if err := checkHookFile(script(t, "true", 0o755, 65534)); err == nil || !strings.Contains(err.Error(), "owned by root") {
		t.Errorf("non-root owner: err = %v, want refusal", err)
	}
	if err := checkHookFile(script(t, "true", 0o644, 0)); err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Errorf("not executable: err = %v", err)
	}
	if err := checkHookFile(t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory: err = %v", err)
	}
	if err := checkHookFile("/nonexistent/hook"); err == nil {
		t.Error("missing file accepted")
	}
}

func TestCheckHookFileFollowsSymlinkToTarget(t *testing.T) {
	requireRoot(t)
	target := script(t, "true", 0o777, 0) // bad target
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := checkHookFile(link); err == nil {
		t.Error("symlink to a world-writable file accepted")
	}
}

func TestHookEnv(t *testing.T) {
	rep := newReport("apply", "/etc/x.yml")
	rep.Result, rep.Changed = "failed", true
	rep.Errors = []string{"boom", "bang"}
	rep.Lists = []listReport{{Kind: "block", Name: "tor", Status: "failed"}, {Kind: "allow", Name: "me", Status: "updated"}}
	env := strings.Join(hookEnv("after", rep, "/tmp/r.json"), "\n")
	for _, want := range []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "IPSETFW_EVENT=after", "IPSETFW_ACTION=apply",
		"IPSETFW_CONFIG=/etc/x.yml", "IPSETFW_RESULT=failed", "IPSETFW_CHANGED=true",
		"IPSETFW_ERROR=boom; bang", "IPSETFW_FAILED=block tor", "IPSETFW_REPORT=/tmp/r.json",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("env missing %q:\n%s", want, env)
		}
	}
}

func runnerFor(t *testing.T, timeout string) hookRunner {
	t.Helper()
	return hookRunner{cfg: file.HooksConfig{Timeout: timeout}, reportDir: t.TempDir()}
}

func TestRunProgramOutputAndExitCode(t *testing.T) {
	requireRoot(t)
	r := runnerFor(t, "5s")
	ok := script(t, `echo "hello $IPSETFW_EVENT"; echo "path=$PATH"; echo "other=${HOME:-unset}"`, 0o755, 0)
	if err := r.runProgram("after 1", file.Hook{Run: []string{ok}}, []string{"PATH=/bin", "IPSETFW_EVENT=after"}); err != nil {
		t.Fatalf("good hook failed: %v", err)
	}
	bad := script(t, "echo nope >&2; exit 3", 0o755, 0)
	err := r.runProgram("after 2", file.Hook{Run: []string{bad}}, []string{"PATH=/bin"})
	if err == nil || !strings.Contains(err.Error(), "failed") {
		t.Errorf("exit 3: err = %v", err)
	}
}

func TestRunProgramEnvironmentIsExactlyWhatWeGive(t *testing.T) {
	requireRoot(t)
	r := runnerFor(t, "5s")
	out := filepath.Join(t.TempDir(), "env.txt")
	p := script(t, `env > "$1"`, 0o755, 0)
	t.Setenv("SECRET_TOKEN", "do-not-leak")
	if err := r.runProgram("x", file.Hook{Run: []string{p, out}}, []string{"PATH=/bin:/usr/bin", "IPSETFW_EVENT=before"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if strings.Contains(string(b), "do-not-leak") {
		t.Errorf("hook saw the parent environment:\n%s", b)
	}
	if !strings.Contains(string(b), "IPSETFW_EVENT=before") {
		t.Errorf("hook did not get IPSETFW_EVENT:\n%s", b)
	}
}

func TestRunProgramTimeoutKillsProcessGroup(t *testing.T) {
	requireRoot(t)
	r := runnerFor(t, "1s")
	marker := filepath.Join(t.TempDir(), "child-survived")
	// The child sleeps in the background and would create the marker after 3s if it survived.
	p := script(t, `(sleep 3; touch "$1") & sleep 10`, 0o755, 0)
	start := time.Now()
	err := r.runProgram("after 1", file.Hook{Run: []string{p, marker}}, []string{"PATH=/bin:/usr/bin"})
	took := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want timeout", err)
	}
	if took > 4*time.Second {
		t.Errorf("timeout took %v, want about 1s", took)
	}
	time.Sleep(3500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Error("a background child of the hook survived the timeout")
	}
}

func TestRunProgramRefusesInsecureHook(t *testing.T) {
	requireRoot(t)
	r := runnerFor(t, "5s")
	marker := filepath.Join(t.TempDir(), "ran")
	p := script(t, `touch "$1"`, 0o777, 0)
	if err := r.runProgram("x", file.Hook{Run: []string{p, marker}}, nil); err == nil {
		t.Fatal("insecure hook ran")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("insecure hook was executed")
	}
}

func TestRunEventWhenChangedAndStop(t *testing.T) {
	requireRoot(t)
	r := runnerFor(t, "5s")
	dir := t.TempDir()
	mk := func(name string) file.Hook {
		return file.Hook{Run: []string{script(t, `echo x >> "$1"`, 0o755, 0), filepath.Join(dir, name)}}
	}
	always, onlyChanged := mk("always"), mk("changed")
	onlyChanged.When = "changed"
	rep := newReport("apply", "x.yml")
	rep.Result = "ok"

	r.runEvent("after", []file.Hook{always, onlyChanged}, rep, nil)
	if _, err := os.Stat(filepath.Join(dir, "always")); err != nil {
		t.Error("always hook did not run")
	}
	if _, err := os.Stat(filepath.Join(dir, "changed")); err == nil {
		t.Error("when: changed hook ran although nothing changed")
	}
	rep.Changed = true
	r.runEvent("after", []file.Hook{onlyChanged}, rep, nil)
	if _, err := os.Stat(filepath.Join(dir, "changed")); err != nil {
		t.Error("when: changed hook did not run after a change")
	}

	// A failing first hook with stop() returning true ends the event.
	fail := file.Hook{Run: []string{script(t, "exit 1", 0o755, 0)}}
	second := mk("second")
	got := r.runEvent("after", []file.Hook{fail, second}, rep, func(hookFailure) bool { return true })
	if len(got) != 1 {
		t.Errorf("failures = %d, want 1", len(got))
	}
	if _, err := os.Stat(filepath.Join(dir, "second")); err == nil {
		t.Error("hook after a stopping failure still ran")
	}
}

func TestRunBeforeAbortAndWarn(t *testing.T) {
	requireRoot(t)
	r := runnerFor(t, "5s")
	dir := t.TempDir()
	failing := file.Hook{Run: []string{script(t, "exit 1", 0o755, 0)}}
	marker := file.Hook{Run: []string{script(t, `touch "$1"`, 0o755, 0), filepath.Join(dir, "second")}}

	r.cfg.Before = []file.Hook{failing, marker}
	if err := r.runBefore(newReport("apply", "x")); err == nil || !strings.Contains(err.Error(), "nothing changed") {
		t.Errorf("abort: err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "second")); err == nil {
		t.Error("a hook after the aborting one still ran")
	}

	failing.OnFailure = "warn"
	r.cfg.Before = []file.Hook{failing, marker}
	if err := r.runBefore(newReport("apply", "x")); err != nil {
		t.Errorf("warn: err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "second")); err != nil {
		t.Error("warn: the next hook did not run")
	}
}

func TestHookReportFileIsPrivateAndRemoved(t *testing.T) {
	requireRoot(t)
	r := runnerFor(t, "5s")
	out := filepath.Join(t.TempDir(), "mode.txt")
	p := script(t, `stat -c %a "$IPSETFW_REPORT" > "$1"; cat "$IPSETFW_REPORT" >> "$1"`, 0o755, 0)
	rep := newReport("apply", "x.yml")
	rep.Result = "ok"
	r.runEvent("after", []file.Hook{{Run: []string{p, out}}}, rep, nil)
	b, _ := os.ReadFile(out)
	if !strings.HasPrefix(string(b), "600\n") {
		t.Errorf("report file mode = %q, want 600", strings.SplitN(string(b), "\n", 2)[0])
	}
	if !strings.Contains(string(b), `"action": "apply"`) {
		t.Errorf("hook could not read the report:\n%s", b)
	}
	if left, _ := filepath.Glob(filepath.Join(r.reportDir, "hook-report-*")); len(left) != 0 {
		t.Errorf("report files left behind: %v", left)
	}
}
