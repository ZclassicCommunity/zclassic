#!/bin/sh
# Copyright (c) 2026 Rhett Creighton
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Verify the historical-oversize-transaction table (doc/oversize-grandfather.md):
#   - src/consensus/z23/oversize_grandfather_table.inc is byte-identical to the Z23 blob it records,
#   - it holds 413 entries, strictly ascending by internal-order txid (memcmp order), no duplicates,
#   - each entry's byte array is the byte reversal of the display txid in its comment,
#   - its (height, txid, size) set equals src/test/data/oversize_grandfather_txids.txt (Z23 list),
#   - optionally equals a chain scan listing "height size" per line (arg 1; e.g. over102k.txt).
# usage: check-oversize-grandfather.sh [chain-scan-file]
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
inc="$root/src/consensus/z23/oversize_grandfather_table.inc"
lst="$root/src/test/data/oversize_grandfather_txids.txt"
scan=${1:-}
want_inc=1deee007953f53931b5736498c13b1436d64fde3
want_lst=641f7ffdc7544a868f31bf250df8bd63c9570bd0
fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

got=$(git hash-object --no-filters -- "$inc") || exit 2
[ "$got" = "$want_inc" ] || bad "table blob $got != $want_inc"
got=$(git hash-object --no-filters -- "$lst") || exit 2
[ "$got" = "$want_lst" ] || bad "txid list blob $got != $want_lst"

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT

# One record per entry, reading the table: "<internal-hex> <size> <height> <display-txid>".
awk '
    /^    { {0x/ { b = $0; sub(/^    { {/, "", b); sub(/}.*/, "", b); gsub(/0x/, "", b); gsub(/,/, "", b); hex = b }
    /^      [0-9]+ \},  \/\* h=/ { size = $1; h = $0; sub(/.*h=/, "", h); split(h, f, " "); print hex, size, f[1], f[2] }
' "$inc" >"$tmp/entries"

n=$(wc -l <"$tmp/entries" | tr -d ' ')
[ "$n" = 413 ] || bad "entry count $n != 413"
grep -q '^#define OVERSIZE_GRANDFATHER_COUNT 413u$' "$inc" || bad "OVERSIZE_GRANDFATHER_COUNT is not 413u"

# sorted strictly ascending (lowercase hex, equal length: lexical order == memcmp order)
cut -d' ' -f1 "$tmp/entries" >"$tmp/internal"
sort -c -u "$tmp/internal" 2>/dev/null || bad "internal txids not strictly ascending / not unique"

# byte reversal of the internal hex equals the display txid
while read -r internal size height display; do
    rev=$(echo "$internal" | fold -w2 | tac | tr -d '\n')
    [ "$rev" = "$display" ] || bad "entry $display: byte array is not its reversal"
    [ "${#display}" = 64 ] || bad "entry $display: txid length"
done <"$tmp/entries"

# equal to the Z23 provenance list
grep -v '^#' "$lst" | awk 'NF==3 { print $1, $2, $3 }' | sort >"$tmp/list.sorted"
awk '{ print $3, $4, $2 }' "$tmp/entries" | sort >"$tmp/table.sorted"
cmp -s "$tmp/list.sorted" "$tmp/table.sorted" || bad "table (height txid size) != $lst"
[ "$(wc -l <"$tmp/list.sorted" | tr -d ' ')" = 413 ] || bad "txid list does not hold 413 entries"

if [ -n "$scan" ]; then
    awk '{ print $1, $2 }' "$scan" | sort >"$tmp/scan.sorted"
    awk '{ print $3, $2 }' "$tmp/entries" | sort >"$tmp/table.hs"
    cmp -s "$tmp/scan.sorted" "$tmp/table.hs" || bad "table (height size) != chain scan $scan"
    echo "chain scan $scan: $(wc -l <"$tmp/scan.sorted" | tr -d ' ') lines compared"
fi

if [ "$fail" -ne 0 ]; then echo "check-oversize-grandfather: FAILED" >&2; exit 1; fi
echo "check-oversize-grandfather: OK ($n entries)"
