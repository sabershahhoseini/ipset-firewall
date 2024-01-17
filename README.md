# ipset-firewall
Block or allow IP large IP pools of countries using ipset.

## Why ipset-firewall

Simply because [ipset](https://ipset.netfilter.org/) is just designed for it.

Just take a look at below picture. You can clearly see that using only iptables is a pain for your system.

![alt text](https://pchaigno.github.io/assets/egress-filtering-benchmark/udp-throughput-with-jit.svg)

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
      chain: INPUT

  - file:
    - /tmp/US-list.txt
    - /tmp/DE-list.txt
    country: us
    set: us-block
    iptables:
      policy: drop
      insert: 2
```

As you can see, you can only give country code to fetch list of IPs from github.

Or you can pass your own files to ipsetfw to create a set with multiple countries, or even add your own IPs.

You can completely ignore `iptables` section. This way, ipsetfw will not take care of iptable rules for you.

### Clear changes

If you want to clear everything setup by config file, just run:

```
ipsetfw -config ipsetfw.yml -clear -v
```
