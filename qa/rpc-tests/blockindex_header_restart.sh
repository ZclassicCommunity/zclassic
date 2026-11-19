#!/bin/sh
# Block headers served after a restart are byte-identical to those served before it.
#
# A restarted node keeps the Equihash solutions of loaded block-index entries on disk
# only (CBlockIndex::fSolutionOnDisk) and reads them back when a header is built. This
# script records getblockheader (hex and JSON) and getblock's solution for every block,
# restarts, and compares; then rewrites loaded entries (invalidateblock/reconsiderblock
# change their status) and compares again over a second restart; finally a fresh peer
# syncs the whole chain from the restarted node through getheaders.
#
# usage: blockindex_header_restart.sh --bin <dir> --work <dir> [--base port]
# Exit status 0 when every check passed. Needs jq. Shell only, no Python.
BIN=""; WORK=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
SD=$WORK/s; rm -rf "$SD"; mkdir -p "$SD"
SCN_ID=1; SCN_LOG=$WORK/checks.txt; OBS_LOG=$WORK/obs.txt; : >"$SCN_LOG"; : >"$OBS_LOG"
iso_base BASE "${PORT_BASE:-}" 112
trap stop_all EXIT
A="-disablesafemode -parkdeepreorg=0"
N=30

# dump <file>: every block's header (hex and JSON solution) and getblock solution
dump() {
    : >"$1"
    h=0
    while [ $h -le $N ]; do
        hash=$(cli 0 getblockhash $h)
        printf '%s %s\n' "$h" "$(cli 0 getblockheader "$hash" false)" >>"$1"
        printf '%s %s\n' "$h" "$(cli 0 getblockheader "$hash" | jq -r .solution)" >>"$1"
        printf '%s %s\n' "$h" "$(cli 0 getblock "$hash" 1 | jq -r .solution)" >>"$1"
        h=$((h + 1))
    done
}
same() { if cmp -s "$2" "$3"; then pass "$1"; else bad "$1: $2 and $3 differ"; fi; }
wait_best() { t=0; until [ "$(cli 1 getbestblockhash)" = "$1" ]; do t=$((t+1)); [ $t -lt 60 ] || return 1; sleep 1; done; }

start 0 "$BIN" $A -connect=0 || exit 1
cli 0 generate $N >/dev/null
ck "height" "$(cli 0 getblockcount)" $N
dump "$WORK/before.txt"
ck "no empty solution recorded" "$(grep -c ' $' "$WORK/before.txt")" 0

stop 0; start 0 "$BIN" $A -connect=0 || exit 1
dump "$WORK/after1.txt"
same "headers identical after a restart" "$WORK/before.txt" "$WORK/after1.txt"

# Rewrite loaded entries: their status changes, so the flush writes them again.
B=$(cli 0 getblockhash 20)
cli 0 invalidateblock "$B" >/dev/null
ck "height after invalidate" "$(cli 0 getblockcount)" 19
cli 0 reconsiderblock "$B" >/dev/null
ck "height after reconsider" "$(cli 0 getblockcount)" $N
stop 0; start 0 "$BIN" $A -connect=0 || exit 1
dump "$WORK/after2.txt"
same "headers identical after rewriting loaded entries" "$WORK/before.txt" "$WORK/after2.txt"

start 1 "$BIN" $A -connect=127.0.0.1:$BASE || exit 1
wait_best "$(cli 0 getbestblockhash)" || true
ck "a fresh peer syncs from the restarted node" "$(cli 1 getbestblockhash)" "$(cli 0 getbestblockhash)"
ck "no unavailable solution logged" "$(grep -c 'solution unavailable\|holds no matching solution\|stored solution of block' "$SD/node0/regtest/debug.log")" 0

np=$(grep -c "^PASS" "$SCN_LOG"); nf=$(grep -c "^FAIL" "$SCN_LOG")
say "blockindex_header_restart: $np pass, $nf fail"
[ "$nf" = 0 ] && [ "$np" -gt 0 ]
