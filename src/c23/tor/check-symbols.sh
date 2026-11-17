#!/bin/sh
# Embedded Tor's own archives (libtor.a and the helper archives it needs) keep the
# generic C names Tor uses (tor_*, crypto_*, ed25519_*, ...). They are not renamed:
# this gate proves that none of them is also defined by any other archive that the
# daemon links, so the static link cannot pick one project's function for another's
# caller. The daemon's own Tor support archive (libzcl_tor.a) is held to the
# zcl_tor_* / zcl_keyfile_* prefixes by c23-symbols.stamp.
#
# usage: check-symbols.sh <nm> <tor-lib-dir> <archive>...
#   <tor-lib-dir>  holds libtor.a libed25519_donna.a libed25519_ref10.a libkeccak-tiny.a
#   <archive>...   every other archive the daemon links (depends libs, src/*.a)
# Exit 0: no shared global name. Exit 1: a collision (listed). Exit 2: usage.
set -u
nm=${1:-}; libdir=${2:-}
[ -n "$nm" ] && [ -d "$libdir" ] || { echo "usage: $0 <nm> <tor-lib-dir> <archive>..." >&2; exit 2; }
shift 2
tmp=${TMPDIR:-/tmp}/zcl-tor-syms.$$
trap 'rm -f "$tmp".*' EXIT INT TERM
defs() { $nm -g --defined-only "$@" 2>/dev/null | awk 'NF==3 && $2 ~ /^[A-TV-Z]$/ && substr($3,1,1) != "." {print $3}' | sort -u; }
tor=""
for a in libtor.a libed25519_donna.a libed25519_ref10.a libkeccak-tiny.a; do
    [ -f "$libdir/$a" ] || { echo "check-symbols: missing $libdir/$a" >&2; exit 2; }
    tor="$tor $libdir/$a"
done
defs $tor >"$tmp.tor"
[ -s "$tmp.tor" ] || { echo "check-symbols: no symbols read from the Tor archives" >&2; exit 2; }
fail=0; n=0
for a in "$@"; do
    [ -f "$a" ] || continue
    n=$((n + 1))
    defs "$a" >"$tmp.other"
    c=$(comm -12 "$tmp.tor" "$tmp.other" | head -20 | tr '\n' ' ')
    if [ -n "$c" ]; then echo "check-symbols: FAIL $a also defines: $c" >&2; fail=1; fi
done
[ "$n" -gt 0 ] || { echo "check-symbols: no archive to compare against" >&2; exit 2; }
[ "$fail" -eq 0 ] && echo "check-symbols: OK ($(wc -l <"$tmp.tor" | tr -d ' ') Tor globals, none defined in $n other archives)"
exit $fail
