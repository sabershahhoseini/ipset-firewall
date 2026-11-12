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

### Notes

* Country lists come from [ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks) (CC0, updated daily) and fall back to [ipdeny.com](https://www.ipdeny.com/ipblocks/). Tor exit nodes come from the [Tor Project bulk exit list](https://check.torproject.org/torbulkexitlist) and fall back to [SecOps-Institute/Tor-IP-Addresses](https://github.com/SecOps-Institute/Tor-IP-Addresses). Sources are tried in order, and an empty result counts as a failure.
* IPv6 entries are skipped. Only IPv4 addresses and networks are used.
* Invalid lines in a file are skipped, and blank lines are ignored.
* If a list cannot be downloaded, is empty, or has more than 65536 entries, the existing set is left unchanged and the error is reported.
* A config rule can set `parent` under `iptables:` to choose the chain the jump comes from. By default it is `PREROUTING` for table `raw` and `INPUT` otherwise.
* In a config file, a failing rule is reported and the remaining rules still run.
* Sets larger than 65536 entries are created with the `ipset` command, which must be installed. Sets up to that size need only the kernel.
* Every entry in a set is matched the same way. `extraIPs` are added to the set, so listing a private range there blocks it too. Do not add them to a block set unless you mean to block them.
