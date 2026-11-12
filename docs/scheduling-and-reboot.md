# Scheduling and surviving a reboot

ipset sets and iptables rules are lost at reboot. This page covers running ipsetfw on a timer, and getting the firewall back at boot.

## Systemd

The unit files are in `contrib/systemd/`. As root:

```sh
install -m 0755 ipsetfw /usr/local/bin/ipsetfw
install -d /etc/ipsetfw && install -m 0644 ipsetfw.yml /etc/ipsetfw/ipsetfw.yml
ipsetfw -config /etc/ipsetfw/ipsetfw.yml -plan       # check first
install -m 0644 contrib/systemd/ipsetfw.service contrib/systemd/ipsetfw.timer contrib/systemd/ipsetfw-restore.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ipsetfw.timer
systemctl enable ipsetfw-restore.service      # with persist: true, restores the firewall at boot
```

- The timer runs every 6 hours, 2 minutes after boot, with a random delay of up to 10 minutes. `Persistent=true` runs a missed run after the host was off.
- Each run uses the cache, so each list is downloaded at most once per `cache.maxAge`.
- Logs: `journalctl -u ipsetfw.service`. Next run: `systemctl list-timers ipsetfw.timer`.
- A health check: `ipsetfw -config /etc/ipsetfw/ipsetfw.yml -verify` exits 1 if the live firewall has drifted from the config.

Do the first allow-only install by hand before you enable the timer (see allow-only.md).

## Surviving a reboot

With `persist: true`, every apply saves a snapshot. The snapshot holds this tool's sets, and its two chains (`IPSET_FW` and `IPSET_ONLY`) with their jumps.

- The snapshot goes to `persistDir`, default `/var/lib/ipsetfw/restore`, with mode 600.
- `ipsetfw -config x.yml -restore` puts it back without any network access.
- `ipsetfw-restore.service` runs it at boot, before the network starts.
- Only this tool's sets and chains are saved and restored. Other software's rules, such as Docker's or fail2ban's, are not touched.
- `-clear` deletes the snapshot, so a reboot does not bring back a cleared firewall.
- The next timer run updates the restored lists as usual.
