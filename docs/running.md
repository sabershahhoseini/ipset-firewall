# Running and checking

This page covers the commands you run by hand, what they print, and how to check the firewall.

## Commands

With a config file (`-config`):

| Command | What it does |
|---|---|
| `ipsetfw -config x.yml -plan` | Shows what would change. Changes nothing. Doesn't need root. |
| `ipsetfw -config x.yml` | Applies the config. |
| `ipsetfw -config x.yml -status` | Shows each list's set, entries, type, rule, last update and source. |
| `ipsetfw -config x.yml -verify` | Compares the live firewall with the config. Exits 1 on any difference. |
| `ipsetfw -config x.yml -clear` | Removes everything the config created. |
| `ipsetfw -config x.yml -restore` | Puts back the last saved snapshot (see scheduling-and-reboot.md). |
| `ipsetfw -config x.yml -test-hook after` | Runs one event's hooks against a sample report. Changes nothing. |

Flags that go with them:

- `-v`: verbose output.
- `-force`: ignore fresh cached lists and the change guard.
- `-mirror DIR`, `-offline`: use local lists only.
- `-unattended`: skip the allow-only confirmation.
- `-only-timeout 60s`: how long the confirmation waits.

From the command line, without a config file:

```sh
ipsetfw -country IR -set set -iptables -policy drop      # block the Iran list
ipsetfw -country ir -export -file /tmp/list-export.txt   # download and save the list
ipsetfw -country IR -set set -iptables -policy accept -file /tmp/list-export.txt
```

`ipsetfw -help` lists everything.

## The run summary

Every apply ends with one line, for example:

```
Summary: 1 updated, 4 unchanged, 0 failed
```

`skipped` means a list was not tried because an allow or only list failed first. `rolled back` and `hook failure` appear when those happened.

## The run report

The full report is saved as `last-run.json`, next to the state file. For each list it has:

- its status: `updated`, `unchanged`, `failed`, `skipped` or `rolledback`
- the entries, and how many were added and removed
- the source, and any error

It also records the allow-only state and whether anything changed. A list counts as unchanged when its contents are the same as before, even if it was downloaded again. Update messages, and Mattermost notifications, are sent only for lists whose contents changed and for failures.

The state file, `/var/lib/ipsetfw/state.json` by default, records each list's source and last update. Change the path with `stateFile:` in the config.

## Verify

`-verify` makes no downloads. It checks:

- the jump from `PREROUTING` to `IPSET_FW`, and, when allow-only is configured, the jump from `INPUT` to `IPSET_ONLY`
- the allow rules, and their order (all allows before any drop)
- each set's type and entry count
- each drop rule
- any drop rule for a list that is no longer in the config

Run it from a timer, or after a change, to catch drift.

## Updates and rollback

Each update builds the new list in `<set>-tmp`, checks it, and then puts it live in one step. From a set's second update on, the previous list is kept in `<set>-bak`. `ipsetfw -rollback -set <set>` swaps it back. After the first update there is no backup yet.

## Locking

A lock at `/run/ipsetfw.lock` is held by every command that changes sets or rules: apply, clear, `-country -set` and `-rollback`. A timer run and a manual run can't overlap. The second one exits with an error.
