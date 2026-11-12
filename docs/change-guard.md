# Change guard

`maxChange` refuses an update that would change a list too much. It catches a broken upstream file before it reaches the firewall, for example one that suddenly lists almost nothing.

```yaml
maxChange: 50%          # top level: no list may change by more than half its entries
block:
  - ir
  - name: scanners
    file: [/etc/ipsetfw/scanners.txt]
    maxChange: off      # this list may change by any amount
```

## How it counts

- The change is the entries added plus the entries removed, as a percentage of the list's current entries.
- Replacing 10 entries with 10 different ones is 200%, because 10 were added and 10 removed.
- Values are `N%` from `1%` to `1000%`, or `off`.
- A list's own `maxChange` overrides the top-level one.

## What happens when it trips

- The live list is kept as it was. The temporary set is removed.
- The list is reported as `failed`, with the reason. The other lists still run.
- `-force` accepts the change, and also ignores fresh cached copies.

## What is not guarded

- The first update of a list. There is nothing to compare with yet.
- A list whose type changes, such as from addresses to ports.
