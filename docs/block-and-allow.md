# Block and allow

`block` drops traffic. `allow` is never blocked. Both take the forms described in configuration.md.

## Block

```yaml
block:
  - ir                        # set ir-block: the Iran list, source drop
  - tor                       # set tor-block
  - name: scanners
    file: [/etc/ipsetfw/scanners.txt]
    ips: [192.0.2.0/24]
    direction: dst            # default is src
```

- A block list drops packets from its addresses (`src`), or packets to them (`dst`).
- Each list has its own set and one drop rule. The rules are in the `raw` table, in the `IPSET_FW` chain, which is jumped to from `PREROUTING`.
- Removing a list from the config removes its drop rule on the next run. The set is kept, and the run prints the `ipset destroy` command you can use to remove it.

## Allow

```yaml
allow:
  - 203.0.113.42              # address
  - ir                        # country: traffic from or to Iran is never blocked
  - name: partners
    file: [/etc/ipsetfw/partners.txt]
  - name: web
    ips: [198.51.100.0/24]
    ports: [443]              # these networks may reach this host on 443, even if blocked
```

- Allow means "never block". It does not drop anything by itself.
- Allow rules sit above every block rule, so an allowed address is accepted before any drop is checked.
- An allow list matches source and destination unless `direction` is set.
- Allow lists have sets named `<name>-allow`.
- A port allow matches traffic to that port. The `raw` table can't track connections, so a port allow does not cover replies to connections your host opened.

## Order of a run

1. Allowed addresses and allow lists are set up at the top of the chain.
2. Allow-only is set up, if you use it (see allow-only.md).
3. Block lists are updated, and their drop rules are added after the allows.

If an allow list fails to update, the block lists are left unchanged for that run. So nothing you meant to allow gets blocked by a half-finished update.

## Ports

Add `ports` to limit a list to some destination ports. The set type is `hash:net,port`, and each network and port pair is one entry.

```yaml
block:
  - name: ssh-scanners
    ips: [192.0.2.0/24]
    ports: [22, 443]
    proto: tcp            # tcp (default) or udp
  - name: web-out
    ips: [198.51.100.0/24]
    ports: [80]
    direction: dst        # traffic to these networks on port 80
```

- `proto` needs `ports`.
- Changing a list between "whole addresses" and "ports" is handled automatically. The new set is built first, then the old rule and set are removed, then the new ones take their place. For a short moment between those steps the list is not enforced.
