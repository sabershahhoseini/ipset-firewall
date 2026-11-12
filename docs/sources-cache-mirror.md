# Sources, cache, mirror and offline use

A country code, or `tor`, is a list that ipsetfw downloads. This page covers where the lists come from and how they are kept.

## Sources

- **Countries:** [ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks) (CC0), then [ipdeny.com](https://www.ipdeny.com/ipblocks/) as the fallback.
- **Tor:** the [Tor Project bulk exit list](https://check.torproject.org/torbulkexitlist), then [SecOps-Institute/Tor-IP-Addresses](https://github.com/SecOps-Institute/Tor-IP-Addresses) as the fallback.

Sources are tried in order. A network error, a non-2xx answer, or an empty list counts as a failure, and the next source is tried. Check each source's current terms and update schedule before you depend on it.

## Cache

```yaml
cache:
  dir: /var/cache/ipsetfw   # or "off"
  maxAge: 12h               # a copy younger than this is used without downloading
```

- A successful download is stored in the cache.
- A copy younger than `maxAge` is used without a download. This keeps you well under the sources' rate limits.
- If every source fails, the last cached copy is used, whatever its age, and a warning is printed.
- `-force` ignores fresh copies and downloads again.
- `-plan` reads the cache like a real run would, but never writes to it.

## Mirror and offline use

For a host with no internet access:

```yaml
mirror: /srv/ipsetfw/mirror   # <code>.txt files are used before any download
offline: true                 # never touch the network
```

- Put one file per code in the mirror directory: `ir.txt`, `tor.txt`, and so on. Each file has one address or network per line.
- A mirror file is used before the cache and before any download, even when the host is online.
- With `offline: true`, only the mirror and the cache are used. A list that is in neither is an error.
- Command-line equivalents: `-mirror DIR` and `-offline`.

To fill a mirror, download the list on a machine that has internet access and copy it over. For example:

```sh
curl -o ir.txt https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/ir/ipv4-aggregated.txt
```

Lines starting with `#` are comments and are skipped.
