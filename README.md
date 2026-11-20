# dropshit

<p align="center">
  <a href="https://github.com/zeroznet/dropshit/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/zeroznet/dropshit/ci.yml?branch=main&style=flat-square&label=ci&labelColor=000000" alt="CI"></a>
  <a href="https://github.com/zeroznet/dropshit/commits/main"><img src="https://img.shields.io/github/last-commit/zeroznet/dropshit?style=flat-square&labelColor=000000&color=ff5fff" alt="Last Commit"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/zeroznet/dropshit?style=flat-square&labelColor=000000&color=875fff" alt="License"></a>
  <img src="https://img.shields.io/badge/shell-POSIX%20sh-00ffff?style=flat-square&labelColor=000000" alt="POSIX sh">
</p>

Downloads threat intelligence blocklists and loads them into the firewall drop table.

## What it does

- fetches the Spamhaus and FireHol blocklists listed in `FEEDS` at the top of `dropshit.sh` (Tor exits, DDoS networks, cybercrime, abusers, etc.)
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
