#!/usr/bin/env sh
# scripted/written by Robert Bopko (github.com/zeroznet) with Boba Bott (Claude Opus 5.5)

set -eu
# Debian 13 dash accepts pipefail, and the FreeBSD cron runs have used it all along.
# shellcheck disable=SC3040
set -o pipefail

MANUAL_LIST="${MANUAL_LIST:-${HOME}/work/dropshit.txt}"
EXT_IFACE4="ens3"
EXT_IFACE6="ens5"

FEEDS="
https://www.spamhaus.org/drop/dropv6.txt
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webserver.netset
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits.ipset
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dm_tor.ipset
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_abusers_1d.netset
"

log()      { printf '%s\n' "$*"; }
warn()     { printf 'WARN: %s\n' "$*" >&2; }
die()      { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
has_cmd()  { command -v "$1" >/dev/null 2>&1; }
need_cmd() { has_cmd "$1" || die "Missing required command: $1"; }

usage() {
  cat <<EOF
Usage: dropshit.sh [-h|--help]

Downloads threat intelligence blocklists and loads them into the firewall.

Supported systems:
  Linux   — loads a dedicated nftables table (inet dropshit) with drop rules
  FreeBSD — replaces the PF <dropshit> table via pfctl

Optional manual blocklist: set MANUAL_LIST env var or edit the script top.
Default: ${HOME}/work/dropshit.txt (silently skipped if missing)

Cron example (hourly, as root):
  @hourly root dropshit.sh >/dev/null
EOF
  exit 0
}

download() {
  url="$1"
  out="$2"
  if has_cmd curl; then
    curl -fsSL "$url" -o "$out"
  elif has_cmd fetch; then
    fetch -q -o "$out" "$url"
  else
    die "Need curl or fetch"
  fi || die "Failed to download $url"
}

# One bad entry would make nft reject the whole ruleset, so invalid lines are
# skipped with a warning (cron mails it) and the rest still loads.
split_blocklist() {
  awk -v v4out="$2" -v v6out="$3" '
    function prefix_ok(p, max) { return p ~ /^[0-9]+$/ && length(p) <= 3 && p + 0 <= max }
    function is_v4(s,   p, n, a, i) {
      n = split(s, p, "/")
      if (n > 2 || (n == 2 && !prefix_ok(p[2], 32))) return 0
      if (split(p[1], a, ".") != 4) return 0
      for (i = 1; i <= 4; i++)
        if (a[i] !~ /^[0-9]+$/ || length(a[i]) > 3 || a[i] + 0 > 255) return 0
      return 1
    }
    function is_v6(s,   p, n) {
      n = split(s, p, "/")
      if (n > 2 || (n == 2 && !prefix_ok(p[2], 128))) return 0
      return p[1] ~ /^[0-9A-Fa-f:.]+$/ && p[1] ~ /:.*:/
    }
    {
      sub(/[;#].*/, "")
      gsub(/[[:space:]]/, "")
      if ($0 == "") next
      if (index($0, ":") ? is_v6($0) : is_v4($0))
        print > (index($0, ":") ? v6out : v4out)
      else
        printf "WARN: skipping invalid entry: %s\n", $0 | "cat 1>&2"
    }
  ' "$1"
  sort -u -o "$2" "$2"
  sort -u -o "$3" "$3"
}

generate_nft_script() {
  ipv4_file="$1"
  ipv6_file="$2"
  out="$3"
  {
    # Create-then-delete in the same file makes nft -f swap the table in one transaction.
    printf 'table inet dropshit\ndelete table inet dropshit\n'
    printf 'table inet dropshit {\n'

    printf '  set blocklist4 {\n'
    printf '    type ipv4_addr\n'
    printf '    flags interval\n'
    printf '    auto-merge\n'
    if [ -s "$ipv4_file" ]; then
      printf '    elements = {\n'
      awk '{ printf "      %s,\n", $0 }' "$ipv4_file"
      printf '    }\n'
    fi
    printf '  }\n'

    printf '  set blocklist6 {\n'
    printf '    type ipv6_addr\n'
    printf '    flags interval\n'
    printf '    auto-merge\n'
    if [ -s "$ipv6_file" ]; then
      printf '    elements = {\n'
      awk '{ printf "      %s,\n", $0 }' "$ipv6_file"
      printf '    }\n'
    fi
    printf '  }\n'

    printf '  chain input {\n'
    printf '    type filter hook input priority -100; policy accept;\n'
    printf '    iifname "%s" ip saddr @blocklist4 drop\n' "$EXT_IFACE4"
    printf '    iifname "%s" ip6 saddr @blocklist6 drop\n' "$EXT_IFACE6"
    printf '  }\n'

    printf '}\n'
  } > "$out"
}

cleanup() {
  rm -rf "$TMPDIR"
}

main() {
  case "${1:-}" in
    -h|--help) usage ;;
    "") ;;
    *) die "Unknown argument: $1" ;;
  esac

  OS=$(uname -s)
  case "$OS" in
    Linux|FreeBSD) ;;
    *) die "Unsupported OS: $OS" ;;
  esac

  TMPDIR=$(mktemp -d)
  trap cleanup EXIT

  log "Updating dropshit blocklists..."

  n=0
  for url in $FEEDS; do
    [ "$n" -eq 0 ] || sleep 1
    n=$((n + 1))
    download "$url" "$TMPDIR/feed$n.txt"
  done

  cat "$TMPDIR"/*.txt > "$TMPDIR/combined.txt"

  if [ -f "$MANUAL_LIST" ]; then
    cat "$MANUAL_LIST" >> "$TMPDIR/combined.txt"
  fi

  : > "$TMPDIR/ipv4.txt"
  : > "$TMPDIR/ipv6.txt"
  split_blocklist "$TMPDIR/combined.txt" "$TMPDIR/ipv4.txt" "$TMPDIR/ipv6.txt"

  case "$OS" in
    Linux)
      need_cmd nft
      generate_nft_script "$TMPDIR/ipv4.txt" "$TMPDIR/ipv6.txt" "$TMPDIR/dropshit.nft"
      nft -f "$TMPDIR/dropshit.nft" || die "Failed to load nftables rules"
      ;;
    FreeBSD)
      need_cmd pfctl
      cat "$TMPDIR/ipv4.txt" "$TMPDIR/ipv6.txt" > "$TMPDIR/clean.txt"
      mv "$TMPDIR/clean.txt" /var/db/dropshit.txt || die "Failed to write /var/db/dropshit.txt"
      pfctl -q -t dropshit -T replace -f /var/db/dropshit.txt || die "Failed to update pf table"
      ;;
  esac

  log "Done."
}

main "$@"
