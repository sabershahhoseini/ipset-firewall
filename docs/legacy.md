# Legacy config (rules:) — deprecated

The `rules:` format is the old way to configure ipsetfw. **It will be dropped in a future version.** It still works today. It can't be mixed with `block`, `allow` or `only` in one file.

For new setups, use the block/allow/only format (see configuration.md). To move an old config, rewrite each rule as a `block` entry, and a rule that needs iptables gets a `policy`.

## Example

```yaml
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
      insert: 1
      chain: "IPSET_FW"
      table: "filter"
```

## Keys

- `country`: a country code to download.
- `file`: local files, one address or network per line. Several files are combined into one set.
- `set`: the ipset name.
- `extraIPs`: addresses added to the set. They are blocked too, so don't put private ranges here unless you mean to block them.
- `iptables`: optional. Without it, no iptables rule is added for the rule.
  - `policy`: `drop` or `accept`.
  - `insert`: the position in the chain. The chain must already have that many rules, so `1` is the safe choice on a new host.
  - `type`: `src` (default) or `dst`.
  - `not`: inverts the match. Dangerous with `dst`: it drops all traffic to the host.
  - `table` (default `raw`) and `chain` (default `IPSET_FW`).
  - `parent`: the chain the jump comes from. Default `PREROUTING` for table `raw`, otherwise `INPUT`.

## Behavior

- A failing rule is reported, and the remaining rules still run.
- A rule gets iptables rules only through its own `policy`. The `-iptables` flag does not add them.
- Clear it with `ipsetfw -config x.yml -clear`.
