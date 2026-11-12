#!/bin/sh
# ipsetfw after-hook: check that this host still serves a URL after a firewall change.
#
# Use it with onFailure: rollback, so a change that breaks your site is undone:
#   hooks:
#     after:
#       - run: [/etc/ipsetfw/hooks/health-check.sh, http://127.0.0.1/health]
#         when: changed
#         onFailure: rollback
#
# Install as root: install -o root -g root -m 0755 health-check.sh /etc/ipsetfw/hooks/
# Exit 0 = healthy. Any other exit code = failed.
# Needs curl. Checks 3 times, 2 seconds apart, so one slow answer does not trigger a rollback.

url="${1:?usage: health-check.sh URL}"
for attempt in 1 2 3; do
    if curl -fsS -o /dev/null --max-time 5 "$url"; then
        echo "healthy: $url answered (attempt $attempt)"
        exit 0
    fi
    [ "$attempt" -lt 3 ] && sleep 2
done
echo "UNHEALTHY: $url did not answer 3 times" >&2
exit 1
