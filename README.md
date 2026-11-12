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

## Quick start

```sh
ipsetfw -config 01-block-countries.yml -plan      # see what would change; changes nothing
sudo ipsetfw -config 01-block-countries.yml       # apply
sudo ipsetfw -config 01-block-countries.yml -verify
```

Start from the closest of the [example configs](example-config/), then adjust it. See [examples](docs/examples.md) for what each one does.

## Docs

- [Configuration](docs/configuration.md): the file, the entry forms, and the rules it must follow
- [Block and allow](docs/block-and-allow.md): blocking, allow lists and port-scoped blocks
- [Allow-only](docs/allow-only.md): only listed sources may connect
- [Sources, cache and mirror](docs/sources-cache-mirror.md): where country lists come from, and offline use
- [Change guard](docs/change-guard.md): refuse updates that change a list too much
- [Running and checking](docs/running.md): commands, the run report, verify, rollback and locking
- [Scheduling and reboot](docs/scheduling-and-reboot.md): systemd timer, and restoring the firewall at boot
- [Hooks](docs/hooks.md): programs and webhooks before and after a run
- [Example configs](docs/examples.md): ten ready-to-use examples, all tested in a VM

## Legacy format: will be dropped

The `rules:` format is deprecated. It still works, but it will be removed in a future version. Move to the block/allow/only format. See [legacy config](docs/legacy.md) for the old keys and how to rewrite a config.

## Before you use it on a server

- Run `-plan` first, every time.
- Allow-only can lock you out. Read [allow-only](docs/allow-only.md) before you use it.
- A `dst` block drops traffic to those addresses. Make sure your own host is not inside one.
- ipsetfw must run as root.
