<!-- written by Robert Bopko (github.com/zeroznet) with Boba Bott (Claude Opus 5.5) -->

# CLAUDE.md

## Purpose

`dropshit` fetches public threat-intel blocklists (Spamhaus, FireHol), merges an optional local list, and loads the result into the host firewall's drop table. It runs hourly from root's cron on Robert's servers, with stdout sent to `/dev/null`, so stderr must stay empty unless something failed: cron mails it.

## Targets

| System | Firewall | What the script owns |
|---|---|---|
| Linux (Debian 13+) | nftables | the whole `table inet dropshit` (sets and input drop chain) |
| FreeBSD | PF | only the data of the `<dropshit>` table; the rules stay in `pf.conf` |

Branch on `uname -s`. Never touch firewall state outside what the table above lists.

## Conventions

Inherits everything from `/home/zero/dev/CLAUDE.md`. Project-specific points:
- One self-contained script, installed by copying it to `/usr/local/sbin/dropshit`. No sourced libraries, no config file.
- A failed download aborts the run before the firewall changes. On Linux the table is deleted and reloaded, so a failed `nft -f` leaves the host without it until the next run.
- The feed list lives in the `*_URL` variables at the top of `dropshit.sh`; keep the count in the README in sync.

## Repo

Public at https://github.com/zeroznet/dropshit, BSD-2-Clause. CI (`.github/workflows/ci.yml`) runs shellcheck, a dash parse, and a `--help` / unknown-flag smoke run; it never touches a firewall.
