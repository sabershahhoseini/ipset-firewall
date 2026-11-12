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
install -m 0644 contrib/systemd/ipsetfw.service contrib/systemd/ipsetfw.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ipsetfw.timer
```

* The timer runs every 6 hours, 2 minutes after boot, with a random delay of up to 10 minutes. `Persistent=true` runs a missed run after the host was off.
* Each run uses the cache, so a list is downloaded at most once per `cache.maxAge`.
* A lock at `/run/ipsetfw.lock` is held by every command that changes sets or rules (apply, clear, `-country -set`, `-rollback`), so a timer run and a manual run never overlap. The second one exits with an error.
* Logs: `journalctl -u ipsetfw.service`. Next run: `systemctl list-timers ipsetfw.timer`.
* Health check: `ipsetfw -config /etc/ipsetfw/ipsetfw.yml -verify` exits 1 if the live firewall has drifted from the config.

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
