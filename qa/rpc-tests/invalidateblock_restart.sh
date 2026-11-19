#!/bin/sh
# invalidateblock survives a clean restart while a connected peer re-offers the block.
#
# A node invalidates five blocks its peer also has, restarts with the peer connected, and must
# stay on the lowered tip, reject a new block the peer mines on the invalidated branch, and
# return to that branch only on reconsiderblock (and stay there over the next restart).
# Before the fix LoadBlockIndexDB gave a failed block no branch ID, RewindBlockIndex erased it
# as insufficiently validated, and the peer's copy was accepted and connected again.
#
# usage: invalidateblock_restart.sh --bin <dir> --work <dir> [--base port]
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
PEER="-connect=127.0.0.1:$BASE"

# wait_height <node> <height>: until the node reaches it (bounded)
wait_height() { local t=0; until [ "$(cli "$1" getblockcount)" = "$2" ]; do t=$((t+1)); [ $t -lt 60 ] || return 1; sleep 1; done; }
tips() { cli 0 getchaintips | jq -c '[.[]|"\(.height):\(.status)"]|sort'; }

start 0 "$BIN" $A -connect=0 || exit 1
start 1 "$BIN" $A $PEER || exit 1
cli 0 generate 105 >/dev/null
wait_height 1 105; ck "peer synced" "$(cli 1 getblockcount)" 105
BH=$(cli 0 getblockhash 101)
cli 0 invalidateblock "$BH" >/dev/null
ck "height after invalidate" "$(cli 0 getblockcount)" 100

stop 1; start 1 "$BIN" $A $PEER || exit 1; sleep 8
ck "kept after the peer reconnects" "$(cli 0 getblockcount)" 100

stop 0; start 0 "$BIN" $A -connect=0 || exit 1; sleep 10
ck "kept after a clean restart, peer connected" "$(cli 0 getblockcount)" 100
ck "chain tips after the restart" "$(tips)" '["100:active","105:invalid"]'
ck "no block index entry erased at the start" "$(grep -o "[0-9]* block index entries to erase" "$SD/node0/regtest/debug.log" | tail -1)" "0 block index entries to erase"

cli 1 generate 1 >/dev/null; sleep 6
ck "a new block on the invalidated branch is rejected" "$(cli 0 getblockcount)" 100

cli 0 reconsiderblock "$BH" >/dev/null
wait_height 0 105 || true
ck "reconsiderblock returns to the branch" "$(cli 0 getbestblockhash)" "$(cli 1 getblockhash 105)"
# the rejected child was not stored: the peer offers it again on the next connection
stop 0; start 0 "$BIN" $A -connect=0 || exit 1; sleep 4
wait_height 0 106 || true
ck "the reconsidered branch survives a restart and takes the child" "$(cli 0 getbestblockhash)" "$(cli 1 getbestblockhash)"
ck "no rewind at start" "$(grep -c 'First insufficiently validated' "$SD/node0/regtest/debug.log")" 0

# The failure flags survive a restart (and invalidateblock writes them at once), so the request that
# clears them must be as durable: a reconsiderblock or unparkblock lost by a kill -9 left the node
# on the lowered tip, refusing the peer's chain.
wait_best() { local t=0; until [ "$(cli 0 getbestblockhash)" = "$1" ]; do t=$((t+1)); [ $t -lt 30 ] || return 1; sleep 1; done; }
BEST=$(cli 0 getbestblockhash); B3=$(cli 0 getblockhash 103)
cli 0 invalidateblock "$B3" >/dev/null; cli 0 reconsiderblock "$B3" >/dev/null
kill9 0; start 0 "$BIN" $A -connect=0 || exit 1; wait_best "$BEST" || true
ck "reconsiderblock survives a kill -9" "$(cli 0 getbestblockhash)" "$BEST"
cli 0 parkblock "$B3" >/dev/null; cli 0 unparkblock "$B3" >/dev/null
kill9 0; start 0 "$BIN" $A -connect=0 || exit 1; wait_best "$BEST" || true
ck "unparkblock survives a kill -9" "$(cli 0 getbestblockhash)" "$BEST"

np=$(grep -c "^PASS" "$SCN_LOG"); nf=$(grep -c "^FAIL" "$SCN_LOG")
say "invalidateblock_restart: $np pass, $nf fail"
[ "$nf" = 0 ] && [ "$np" -gt 0 ]
