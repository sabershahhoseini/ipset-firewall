# ipset-firewall
Block or allow IP large IP pools of countries using ipset.

## Why ipset-firewall

Simply because [ipset](https://ipset.netfilter.org/) is just designed for it.

Just take a look at below picture. You can clearly see that using only iptables is a pain for your system.

![alt text](https://pchaigno.github.io/assets/egress-filtering-benchmark/udp-throughput-with-jit.svg)

## How it works

The purpose of ipsetfw is for automation. You just give it a yaml file, setup a cronjob and go watch a movie or something.

It works like this:

Takes a list of IPs, either via fetching from github with country code you provided, or a list of IP networks you passed to the binary.

After that, it will create a ipset `set`, and if you choose, it will also add the required iptable rule for it.

Next time you run the same command, it will clear everything and start again from scratch. So, it will:

* Take an IP list
* Create `set`and add IPs to it
* Setup iptable rules (optional)
* Repeat

## Usage

There are two ways of using ipsetfw, either you pass arguments to cli which is a bit limited,
or give it a yaml file for more option.

### CLI
You can use `ipsetfw -help` to see options and example of usage.

Create a set of Iran IP pool and block IPs from Iran by adding iptables rule:
```
ipsetfw -country IR -set set -iptables -policy drop
```

Fetch github and export Iran IP pool:
```
ipsetfw -country ir -export -file /tmp/list-export.txt -v
```

Create a set of Iran IP pool and accpet IPs from Iran from file:
```
ipsetfw -country IR -set set -iptables -policy accept -file /tmp/list-export.txt
```

### Config file

You can use a yaml config file with more options. Here's an example:

```
defaultChain: IPSET_FW

rules:
  - country: ir
    set: ir-block
    iptables:
      policy: drop
      insert: 1

  - file:
    - /tmp/US-list.txt
    - /tmp/DE-list.txt
    country: us
    set: us-block
    iptables:
      policy: drop
      insert: 2
      chain: "IPSET_FW"
      table: "filter"
```

As you can see, you can only give country code to fetch list of IPs from github.

Or you can pass your own files to ipsetfw to create a set with multiple countries, or even add your own IPs.

You can completely ignore `iptables` section. This way, ipsetfw will not take care of iptable rules for you.

### Clear changes

If you want to clear everything setup by config file, just run:

```
ipsetfw -config ipsetfw.yml -clear -v
```

### Example configs

Ready-to-use configs are in [`example-config/`](example-config/). Each one has been planned, applied, verified and cleared in a test VM.

| File | What it does |
|---|---|
| `01-block-countries.yml` | Block a few countries and Tor |
| `02-server-admin.yml` | Public server: block bad sources, never block the admin |
| `03-only-iran.yml` | Only Iran may connect, plus the admin IP |
| `04-only-iran-reject.yml` | Only Iran and the office; others get "connection refused" |
| `05-ssh-only-blocks.yml` | Keep some countries away from SSH only |
| `06-only-iran-web-open.yml` | Only Iran, but the website stays open to everyone |
| `07-airgapped.yml` | No internet: lists from a local mirror |
| `08-handpicked.yml` | Single addresses and a list file, no countries |
| `09-udp-and-router.yml` | Block UDP 53 from a network; stop forwarding to a network |
| `10-everything.yml` | Every option in one file |
| `full-config.yml` | Full reference: every option, with short comments |

Run `ipsetfw -config <file> -plan` before applying any of them, and change the example addresses (203.0.113.42 and so on) to your own.

### Simple config (block / allow)

```yaml
logFile: "/var/log/ipsetfw.log"

# Always inserted first, for source and destination. Nothing in a block list
# can match these.
allow:
  - 10.0.0.0/8
  - 203.0.113.42                # my admin IP

# Block lists. A bare country code is a list fetched from the sources.
# A map adds a file, addresses, or a direction. Sets are named <name>-block.
block:
  - ir                          # set ir-block, source drop
  - tor                         # set tor-block, source drop
  - name: scanners
    file: [/etc/ipsetfw/scanners.txt]
    ips: [192.0.2.0/24]
    direction: dst              # default src
```

* `allow` addresses are accepted as source and as destination, ahead of every block rule.
* `ipsetfw -config x.yml -plan` shows what would be applied and changes nothing.
* `-clear` removes the sets, rules, jump and the `IPSET_FW` chain for this format.
* Removing an entry from `block` removes its drop rule on the next run. The set is kept, and the run prints the `ipset destroy` command to remove it.
* The `-iptables` flag is ignored for this format, because every block entry has a drop rule.
* Invalid configs are refused before anything changes.
* The older `rules:` format still works, but it can't be mixed with `block` or `allow`.

### Allow lists

`allow` takes the same forms as `block`: addresses, country codes, and named lists with `file`, `ips`, `direction`, `ports` and `proto`.

```yaml
allow:
  - 203.0.113.42              # address
  - ir                        # country: traffic from or to Iran is never blocked
  - name: partners
    file: [/etc/ipsetfw/partners.txt]
  - name: web
    ips: [198.51.100.0/24]
    ports: [443]              # these networks may reach this host on 443, even if blocked
block:
  - 192.0.2.7                 # bare addresses go into one set: addresses-block
  - tor
```

* Allow means "never block". It does not drop anything that isn't listed.
* An allow list matches source and destination unless `direction` is set. Its sets are named `<name>-allow`, and its rules sit above every block rule.
* A port allow matches traffic to that port. The rules in `raw` can't track connections, so replies to connections your host opens are not covered by a port allow.
* If an allow list fails to update, the block lists are left unchanged for that run, so nothing you meant to allow gets blocked.
* A list name can't be used in both `allow` and `block`, and the name `addresses` is reserved.
* A country code must be two letters, `tor`, or have a `<code>.txt` file in the mirror. Anything else is refused before the firewall is changed.

### Allow-only (only listed sources may connect)

```yaml
only:                      # inbound: only these may open connections to this host
  - ir
  - name: office
    ips: [198.51.100.0/24]
onlyAction: drop           # drop (default) or reject
allow:
  - 203.0.113.42           # admin IP: always allowed, even when not in only
```

Everything not in `allow` or `only` can no longer connect to this host. Run `-plan` first.

* It lives in the `filter` table, in chain `IPSET_ONLY` jumped from `INPUT`, so it affects inbound traffic to this host only. Outbound connections and their replies keep working, and traffic forwarded through the host is not affected.
* Chain order: loopback, established and related traffic, `allow` addresses and lists, `only` lists, then `onlyAction`.
* `reject` refuses TCP with a reset and other protocols with an ICMP error. `drop` is silent.
* **SSH guard:** a run is refused if a current SSH client would be cut off. Clients are found from established connections to port 22 and from `SSH_CLIENT`. `-plan` reports this too. If sshd runs on another port, check `SSH_CLIENT` is kept (it is not, by default, under `sudo`).
* **First install must be confirmed:** you are asked to open a new connection and type `yes` within 60 seconds (`-only-timeout` changes this). Without an answer, allow-only is removed again. A first install without a terminal is refused unless `-unattended` is given. Do the first install by hand before enabling the systemd timer. Later runs update the lists without asking.
* Each update builds the new chain in full and points `INPUT` at it before removing the old one, so there is no moment without it.
* If an `allow` or `only` list fails to update, allow-only and the block lists are left as they were.
* Removing `only` from the config turns allow-only off on the next run. `-clear` removes it as well.

### Port-scoped blocks

Add `ports` to limit a block to some destination ports. The set is `hash:net,port`.

```yaml
block:
  - name: ssh-scanners
    ips: [192.0.2.0/24]
    ports: [22, 443]
    proto: tcp            # tcp (default) or udp
  - name: web-out
    ips: [198.51.100.0/24]
    ports: [80]
    direction: dst        # dst,dst: traffic to these networks on port 80
```

* `proto` needs `ports`.
* Changing a block between IP-only and ports is handled automatically. The new set is built first, then the old rule and set are removed, and the new set and rule take their place. The block is not enforced for the moment between removing the old rule and adding the new one.

### Lists, cache and offline use

```yaml
cache:
  dir: /var/cache/ipsetfw   # or "off"
  maxAge: 12h               # a copy younger than this is used without downloading
mirror: /srv/ipsetfw/mirror # <code>.txt files (ir.txt, tor.txt) used before any download
offline: false              # true: never touch the network; mirror and cache only
```

* A successful download is stored in the cache. If every source later fails, the cached copy is used and a warning is printed.
* `-force` ignores fresh cached copies and downloads again.
* `-plan` uses the mirror and cached copies like a real run, but never writes the cache.
* For an air-gapped host, put the list files in the mirror directory and set `offline: true`. A list that is in neither the mirror nor the cache is an error.
* Command-line equivalents: `-force`, `-mirror DIR`, `-offline`.

### Running on a schedule (systemd)

Files are in `contrib/systemd/`. As root:

```sh
install -m 0755 ipsetfw /usr/local/bin/ipsetfw
install -d /etc/ipsetfw && install -m 0644 ipsetfw.yml /etc/ipsetfw/ipsetfw.yml
ipsetfw -config /etc/ipsetfw/ipsetfw.yml -plan       # check first
install -m 0644 contrib/systemd/ipsetfw.service contrib/systemd/ipsetfw.timer contrib/systemd/ipsetfw-restore.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ipsetfw.timer
systemctl enable ipsetfw-restore.service      # with persist: true, restores the firewall at boot
```

* The timer runs every 6 hours, 2 minutes after boot, with a random delay of up to 10 minutes. `Persistent=true` runs a missed run after the host was off.
* Each run uses the cache, so a list is downloaded at most once per `cache.maxAge`.
* A lock at `/run/ipsetfw.lock` is held by every command that changes sets or rules (apply, clear, `-country -set`, `-rollback`), so a timer run and a manual run never overlap. The second one exits with an error.
* Logs: `journalctl -u ipsetfw.service`. Next run: `systemctl list-timers ipsetfw.timer`.
* Health check: `ipsetfw -config /etc/ipsetfw/ipsetfw.yml -verify` exits 1 if the live firewall has drifted from the config.

### Hooks

Run your own programs before and after a run.

```yaml
hooks:
  timeout: 30s                       # default for every hook
  before:
    - run: [/etc/ipsetfw/hooks/sync-mirror.sh, internal.example.com]
      onFailure: abort               # abort (default): stop, change nothing | warn: go on
  after:
    - run: [/etc/ipsetfw/hooks/health-check.sh, http://127.0.0.1/health]
      when: changed                  # always (default) | changed
      onFailure: rollback            # warn (default) | rollback
```

* **A hook is a program and its arguments, never a shell string.** `run[0]` must be an absolute path.
* **Hooks run as root, so they are checked first.** The file must be owned by root, not writable by group or others, and executable. Otherwise the hook is refused and counts as failed. `-plan` shows this too.
* **A hook gets a fixed `PATH`** and only these variables: `IPSETFW_EVENT`, `IPSETFW_ACTION` (`apply` or `clear`), `IPSETFW_CONFIG`, `IPSETFW_RESULT`, `IPSETFW_CHANGED`, `IPSETFW_ERROR`, `IPSETFW_FAILED`, and `IPSETFW_REPORT`, the path to the run report as JSON (a private temporary file, removed afterwards). Read it with `jq`.
* **Order:** before hooks, the run, then after hooks. A before hook that fails with `abort` stops the run before anything is changed. After hooks run only when the run succeeded.
* **`when: changed`** runs an after hook only when some list really changed.
* **`onFailure: rollback`** on an after hook puts every list updated by this run back to its previous contents. The firewall rules and allow-only are not rolled back, and a list on its first update has no previous contents; both are reported. Use it with a health check.
* **Timeouts** kill the hook and everything it started. Output is shown with a `[hook after 1]` prefix and written to the log file.
* A failing after hook makes the run exit 1, but the change is kept unless it rolled back.
* **`ipsetfw -config x.yml -test-hook after`** runs the hooks of an event against a sample report and changes nothing. `-plan` lists the hooks.
* Hooks run for apply and `-clear` only, never for `-plan`, `-status`, `-verify` or `-restore`.
* **`webhook: https://...`** on any hook POSTs the run report as JSON (`Content-Type: application/json`, `User-Agent: ipsetfw`). A 2xx answer is success. `retries: N` retries after a failure, waiting 1s, 2s, 4s and so on (at most 30s). `timeout` limits each attempt.
* Messages and logs show only `webhook https://host`, never the path or query, because they often hold a token.
* **`onError`** hooks run when a run failed, after a rollback, or when a before hook aborted the run. They get `IPSETFW_RESULT=failed` and the errors, including each failed list's reason. A failing onError hook only prints a warning; it never changes the exit code.
* `-test-hook` with a webhook sends the sample report to the real URL.

Examples are in `contrib/hooks/`: `health-check.sh` (roll back if your site stops answering) and `save-to-file.sh` (keep every run's report).

### Change guard

`maxChange` refuses an update that would change a list too much, for example when an upstream file breaks and suddenly lists almost nothing.

```yaml
maxChange: 50%          # top level: no list may change by more than half its entries
block:
  - ir
  - name: scanners
    file: [/etc/ipsetfw/scanners.txt]
    maxChange: off      # this list may change by any amount
```

* The change counts entries added plus entries removed, as a percentage of the list's current entries. Replacing 10 entries with 10 different ones is 200%.
* A refused list is reported as `failed` with the reason, and the other lists still run. The live list is kept, and the temporary set is removed.
* The first update of a list is never guarded, and neither is a list whose type changes.
* `-force` accepts the change. It also ignores fresh cached lists.
* Values: `N%` from `1%` to `1000%`, or `off`.

### Run report

Every apply ends with a one-line summary, for example `Summary: 1 updated, 4 unchanged, 0 failed`. The full report is saved as `last-run.json`, next to the state file. For each list it gives the status (`updated`, `unchanged`, `failed` or `skipped`), the entries, how many were added and removed, the source, and any error. It also records the allow-only state and whether anything changed.

* A list counts as unchanged when its contents are the same as before, even if it was downloaded again.
* An update message is printed (and sent to Mattermost) only for lists whose contents changed, and for failures.
* `skipped` means the list was not attempted because an allow or only list failed first.

### Surviving a reboot

ipset sets and iptables rules are lost at reboot. With `persist: true`, every apply saves a snapshot of this tool's sets and of its two chains (`IPSET_FW`, `IPSET_ONLY`) with their jumps. The snapshot goes to `persistDir`, default `/var/lib/ipsetfw/restore`, with mode 600. `ipsetfw -restore` puts it back without any network. `ipsetfw-restore.service` runs it at boot, before the network starts.

* Only this tool's sets and chains are saved and restored. Other software's rules, such as Docker or fail2ban, are not touched.
* `-clear` deletes the snapshot, so a reboot does not bring back a cleared firewall.
* The next timer run updates the restored lists as usual.

### Updates and rollback

Each update builds the new list in `<set>-tmp`, checks it, and then puts it live in one step. From a set's second update on, the previous list is kept in `<set>-bak`, and `ipsetfw -rollback -set <set>` swaps it back. After the first update there is no backup yet.

### Checking the firewall

With the block/allow format:

```
ipsetfw -config x.yml -status    # each block: set, live entries, type, rule, last update and source
ipsetfw -config x.yml -verify    # compare live firewall with config; exit 1 on any difference
```

`-verify` makes no downloads. It checks the jump, the allow rules and their order, each set's type and entry count, each drop rule, and any drop rule for a block that is no longer in the config.

The state file, `/var/lib/ipsetfw/state.json` by default (`stateFile:` in the config changes it), records each block's source and last update.

### Notes

* Country lists come from [ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks) (CC0, updated daily) and fall back to [ipdeny.com](https://www.ipdeny.com/ipblocks/). Tor exit nodes come from the [Tor Project bulk exit list](https://check.torproject.org/torbulkexitlist) and fall back to [SecOps-Institute/Tor-IP-Addresses](https://github.com/SecOps-Institute/Tor-IP-Addresses). Sources are tried in order, and an empty result counts as a failure.
* IPv6 entries are skipped. Only IPv4 addresses and networks are used.
* Invalid lines in a file are skipped, and blank lines are ignored.
* If a list cannot be downloaded, is empty, or has more than 65536 entries, the existing set is left unchanged and the error is reported.
* A config rule can set `parent` under `iptables:` to choose the chain the jump comes from. By default it is `PREROUTING` for table `raw` and `INPUT` otherwise.
* In a config file, a failing rule is reported and the remaining rules still run.
* Sets larger than 65536 entries are created with the `ipset` command, which must be installed. Sets up to that size need only the kernel.
* Every entry in a set is matched the same way. `extraIPs` are added to the set, so listing a private range there blocks it too. Do not add them to a block set unless you mean to block them.
