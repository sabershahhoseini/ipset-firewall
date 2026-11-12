# Configuration

ipsetfw reads a YAML file. This page covers the file's shape and the forms an entry can take. The other docs cover what each part does.

## The file

```yaml
logFile: /var/log/ipsetfw.log
stateFile: /var/lib/ipsetfw/state.json

allow:        # never blocked (see block-and-allow.md)
  - 10.0.0.0/8

block:        # dropped (see block-and-allow.md)
  - ir

only:         # allow-only (see allow-only.md)
  - ir
onlyAction: drop

cache:        # see sources-cache-mirror.md
  dir: /var/cache/ipsetfw
  maxAge: 12h
mirror: /srv/ipsetfw/mirror
offline: false
maxChange: 50%    # see change-guard.md
persist: true     # see scheduling-and-reboot.md
hooks: {}         # see hooks.md
```

`full-config.yml` in `example-config/` lists every key with a short comment. Start from it.

## Entries

`allow`, `block` and `only` take the same forms:

| Form | Example | Meaning |
|---|---|---|
| Address | `203.0.113.42` | One IPv4 address |
| Network | `10.0.0.0/8` | One IPv4 network |
| Country | `ir` | The country's list, downloaded (see sources-cache-mirror.md). `tor` is the Tor exit list. |
| Named list | `name: scanners` with keys below | A list made from files, addresses and countries |

A named list can have these keys:

- `name`: required for a named list. The set is named `<name>-<kind>`, so `scanners` in `block` becomes `scanners-block`.
- `country`: a country code to download.
- `file`: a list of files, one address or network per line. Blank lines and invalid lines are skipped.
- `ips`: addresses written in the config.
- `direction`: `src` or `dst`. Block lists default to `src`. Allow lists match both directions unless you set one.
- `ports` and `proto`: limit the list to some ports (see block-and-allow.md).
- `maxChange`: a per-list change limit (see change-guard.md).

A named list needs a source: `country`, `file` or `ips`.

Bare addresses in `block` are collected into one set, `addresses-block`.

## Rules the file must follow

ipsetfw checks the file before it changes anything. These are refused:

- A list name used in both `allow` and `block`, or in both `only` and `block`.
- The name `addresses`, which is reserved for bare addresses.
- Names and country codes that contain anything but letters, digits, `-` and `_`. A country code is two letters, `tor`, or a code that has a file in the mirror.
- Set names longer than 31 characters (`name` plus `-block` or `-allow`).
- IPv6 addresses. Only IPv4 is supported.
- `proto` without `ports`, a port outside 1 to 65535, or a repeated port.
- A `direction` other than `src` or `dst`.
- A bad `maxChange`, `onlyAction`, `cache.maxAge`, or hook setting.

IPv6 lines in a file are skipped rather than refused.

## Requirements

- Run as root. Nothing changes without it.
- Sets larger than 65536 entries are created with the `ipset` command, so it must be installed. Smaller sets need only the kernel.
