# Allow-only

Allow-only means only the sources you list may open connections to this host. Everything else is refused. This is the strongest setting, and the easiest one to lock yourself out with, so read this page before you use it.

```yaml
only:                      # inbound: only these may open connections to this host
  - ir
  - name: office
    ips: [198.51.100.0/24]
onlyAction: drop           # drop (default) or reject
allow:
  - 203.0.113.42           # admin IP: always allowed, even when not in only
```

Run `ipsetfw -config x.yml -plan` before you apply it.

## What it does

- It lives in the `filter` table, in the chain `IPSET_ONLY`, which is jumped to from `INPUT`. It affects inbound traffic to this host only.
- Outbound connections and their replies keep working. Traffic forwarded through the host is not affected.
- The chain runs in this order: loopback, established and related traffic, the `allow` addresses and lists, the `only` lists, then `onlyAction`.
- `drop` is silent. `reject` refuses TCP with a reset and other protocols with an ICMP error.

## Safety

- **SSH guard.** A run is refused if a current SSH client would be cut off. Clients are found from established connections to port 22, and from `SSH_CLIENT`. `-plan` reports this too. If sshd runs on another port, make sure `SSH_CLIENT` is set for the run. `sudo` clears it by default.
- **First install must be confirmed.** The first time allow-only is installed, you are asked to open a new connection and type `yes` within 60 seconds (`-only-timeout` changes this). If you don't answer, allow-only is removed again. Without a terminal, a first install is refused unless you pass `-unattended`. Do the first install by hand before you turn on the systemd timer. Later runs update the lists without asking.
- **No gap on update.** Each update builds the new chain in full, points `INPUT` at it, and only then removes the old one.
- **A failing list stops the change.** If an `allow` or `only` list fails to update, allow-only and the block lists are left as they were.

## Turning it off

Remove `only` from the config. The next run turns allow-only off. `-clear` removes it too.
