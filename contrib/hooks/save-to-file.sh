#!/bin/sh
# ipsetfw after-hook: keep a copy of every run's report, one file per run.
#
#   hooks:
#     after:
#       - run: [/etc/ipsetfw/hooks/save-to-file.sh, /var/log/ipsetfw/reports]
#
# Install as root: install -o root -g root -m 0755 save-to-file.sh /etc/ipsetfw/hooks/
# The first argument is the directory (default /var/log/ipsetfw/reports). Reports older than
# 30 days are removed. $IPSETFW_REPORT is set by ipsetfw and points at the report for this run.

dir="${1:-/var/log/ipsetfw/reports}"
[ -r "$IPSETFW_REPORT" ] || { echo "IPSETFW_REPORT is not readable" >&2; exit 1; }
mkdir -p "$dir" && chmod 750 "$dir" || exit 1
out="$dir/$(date -u +%Y%m%dT%H%M%SZ)-$IPSETFW_ACTION-$IPSETFW_RESULT.json"
cp "$IPSETFW_REPORT" "$out" && chmod 640 "$out" || exit 1
find "$dir" -name '*.json' -mtime +30 -delete
echo "report saved: $out"
