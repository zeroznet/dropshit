<!-- written by Robert Bopko (github.com/zeroznet) with Boba Bott (Claude Opus 5.5) -->

# CLAUDE.md

## Purpose

`dropshit` fetches public threat-intel blocklists (Spamhaus, FireHol), merges an optional local list, and loads the result into the host firewall's drop table. It runs hourly from root's cron on Robert's servers, with stdout sent to `/dev/null`, so stderr must stay empty unless something failed: cron mails it.

## Targets

Systems and mechanisms: README "Supported systems". Branch on `uname -s`. Touch only `table inet dropshit` on Linux and the data of PF's `<dropshit>` table on FreeBSD; never other firewall state.

## Conventions

Inherits everything from `/home/zero/dev/CLAUDE.md`. Project-specific points:
- One self-contained script, installed by copying it to `/usr/local/sbin/dropshit`. No sourced libraries, no config file.
- A failed download aborts the run before the firewall changes. Both backends swap the table in one step (`nft -f` with create-then-delete, `pfctl -T replace`), so a failed load keeps the previous table.
- The feed list lives in `FEEDS` at the top of `dropshit.sh`, one URL per line; the README points there instead of counting feeds.

## Repo

Public at https://github.com/zeroznet/dropshit, BSD-2-Clause. CI (`.github/workflows/ci.yml`) runs shellcheck, a dash parse, a `--print` run on `test/fixture.txt` checked with `nft -c`, and a `--help` / unknown-flag smoke run; it never loads a firewall.
