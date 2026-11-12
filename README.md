# ipset-firewall

Block or allow large IP pools, such as whole countries, using [ipset](https://ipset.netfilter.org/). You describe what to block in a YAML file, and ipsetfw keeps the firewall in line with it.

## Quick start

```sh
ipsetfw -config full-config.yml -plan      # see what would change; changes nothing
sudo ipsetfw -config full-config.yml       # apply
sudo ipsetfw -config full-config.yml -verify
```

Start from [`example-config/full-config.yml`](example-config/full-config.yml), which lists every option.

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
