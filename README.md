# dropshit

Downloads threat intelligence blocklists and loads them into the firewall drop table.

## What it does

- fetches 11 blocklists from Spamhaus and FireHol (Tor exits, DDoS networks, cybercrime, abusers, etc.)
- strips comments, deduplicates, and cleans entries
- optionally merges a local manual blocklist (`~/work/dropshit.txt` by default)
- updates the firewall atomically

## Supported systems

| System | Firewall | Mechanism |
|--------|----------|-----------|
| Linux (Debian 13+) | nftables | manages `table inet dropshit` with IPv4/IPv6 sets and input drop chain |
| FreeBSD | PF | replaces `<dropshit>` table via `pfctl` |

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/zeroznet/dropshit/main/dropshit.sh \
  -o /usr/local/sbin/dropshit && chmod +x /usr/local/sbin/dropshit
```

FreeBSD without `curl`:

```sh
fetch -q -o /usr/local/sbin/dropshit \
  https://raw.githubusercontent.com/zeroznet/dropshit/main/dropshit.sh
chmod +x /usr/local/sbin/dropshit
```

## Cron setup

```
@hourly root /usr/local/sbin/dropshit >/dev/null
```

## FreeBSD prerequisite

Your `pf.conf` must define the table and drop rule before running the script:

```
table <dropshit> persist file "/var/db/dropshit.txt"
block drop in log quick on $ext_if from <dropshit>
```

The script only updates the table data — PF rules stay in `pf.conf`.

## Optional manual blocklist

Set `MANUAL_LIST` in the script (or as an env var) to include custom entries.
Default path: `~/work/dropshit.txt`. Silently skipped if the file does not exist.

## License

Licensed under the BSD-2-Clause license. See LICENSE.
