# Example configs

Ready-to-use configs are in [`example-config/`](../example-config/). Each one has been planned, applied, verified and cleared in a test VM.

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
| `11-hooks-health-rollback.yml` | Block Iran; after a change, check the site, and roll back if it is down |
| `12-hooks-report-to-file.yml` | Block Tor; save a copy of every run's report to a file |
| `13-hooks-before-check.yml` | Stop before any change if the mirror directory is missing |
| `14-hooks-webhook.yml` | Block Iran; send the report to a webhook on change, and another on failure |
| `full-config.yml` | Reference, not a starting point: every option, with short comments |

The hook examples (11 to 14) need their scripts installed as described in [hooks](hooks.md). Start from the example closest to what you want, not from `full-config.yml`. Before you apply any of them, run `ipsetfw -config <file> -plan`. Change the example addresses (203.0.113.42 and so on) to your own.
