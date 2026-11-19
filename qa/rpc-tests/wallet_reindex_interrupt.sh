#!/bin/sh
# A node that is rebuilding its block index (-reindex) must refuse to mine or accept blocks,
# and stopping or killing it halfway must not damage the block database: the next start
# finishes the reindex and the chain verifies.
#
# usage: wallet_reindex_interrupt.sh --bin <dir> --work <dir> [--base port] [--blocks N]
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
BIN=""; WORK=""; PORT_BASE=""; BLOCKS=2500
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;;
        --blocks) BLOCKS=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--base port] [--blocks N]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
iso_base BASE "${PORT_BASE:-}" 112
SD=$WORK/reindex; rm -rf "$SD"; mkdir -p "$SD"; : >"$SD/pids"
SCN_LOG=$WORK/checks.log; : >"$SCN_LOG"; SCN_ID=reindex; OBS_LOG=$WORK/obs.log; : >"$OBS_LOG"
trap 'stop_all' EXIT

# wait_height <n> <height> <seconds>: node n reports at least this many blocks
wait_height() {
    w=0
    while [ $w -lt $(( $3 * 2 )) ]; do
        h=$(cli "$1" getblockcount 2>/dev/null); case $h in ''|*[!0-9]*) ;; *) [ "$h" -ge "$2" ] && return 0 ;; esac
        w=$((w + 1)); sleep 0.5
    done
    return 1
}
# reindex_running <n>: the node answers RPC but has fewer blocks than the chain
mid_reindex() {
    for t in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
        h=$(cli "$1" getblockcount 2>/dev/null)
        case $h in ''|*[!0-9]*) sleep 0.1 ;; *) [ "$h" -lt $(( BLOCKS - 100 )) ] && return 0; return 1 ;; esac
    done
    return 1
}
start_reindex() { # start without waiting for the chain; returns when RPC answers
    dir=$SD/node0; mkdir -p "$dir"
    [ -f "$dir/zclassic.conf" ] || { echo "regtest=1"; echo "rpcuser=ri"; echo "rpcpassword=ri0"; } >"$dir/zclassic.conf"
    echo "$BIN" >"$dir/bindir"; rm -f "$dir/regtest/.lock"
    $ZCL_RUN "$BIN/zclassicd" -datadir="$dir" -regtest -server=1 -daemon=0 -showmetrics=0 -listen=0 \
        -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=$((BASE + 100)) -dnsseed=0 -discover=0 -listenonion=0 -upnp=0 \
        -debuglogfile=1 -exportdir="$SD/export" -experimentalfeatures $NU_ARGS "$@" >>"$dir/stdout.log" 2>&1 &
    echo "$!" >"$dir/pid"; echo "$!" >>"$SD/pids"
    t=0; until cli 0 getblockcount >/dev/null 2>&1; do
        kill -0 "$(cat "$dir/pid")" 2>/dev/null || return 1
        t=$((t + 1)); [ $t -lt 600 ] || return 1; sleep 0.2
    done
}
mkdir -p "$SD/export"
start 0 "$BIN" -listen=0 || exit 1
cli 0 generate "$BLOCKS" >/dev/null; ck "chain built" "$(cli 0 getblockcount)" "$BLOCKS"
stop 0

# 1. mining and block submission are refused while the block files are replayed
if start_reindex -reindex && mid_reindex 0; then
    ckerr "generate during -reindex is refused" "rebuilt|reindex" 0 generate 1
    ckerr "submitblock during -reindex is refused" "rebuilt|reindex" 0 submitblock 00
    wait_height 0 "$BLOCKS" 180; ck "reindex completes after the refused calls" "$(cli 0 getblockcount)" "$BLOCKS"
else
    say "  skip reindex finished before it could be probed"; pass "generate during -reindex (reindex too fast to probe)"
fi
stop 0

# 2. stop (clean) in the middle of a reindex, restart: the reindex resumes and finishes
for how in stop kill9; do
    if start_reindex -reindex && mid_reindex 0; then
        if [ $how = stop ]; then stop 0; else kill9 0; fi
        start_reindex || { bad "$how mid-reindex: node did not start again"; continue; }
        if wait_height 0 "$BLOCKS" 240; then pass "$how mid-reindex: the next start finishes the reindex"; else bad "$how mid-reindex: height $(cli 0 getblockcount) of $BLOCKS"; fi
        ck "$how mid-reindex: chain verifies" "$(cli 0 verifychain 4 0)" true
        ck "$how mid-reindex: no block database corruption reported" "$(grep -ci 'corrupt' "$SD/node0/regtest/debug.log" 2>/dev/null)" 0
        stop 0
    else
        pass "$how mid-reindex (reindex too fast to interrupt)"
    fi
done

# 3. a node whose reindex was interrupted still takes new blocks afterwards
start 0 "$BIN" -listen=0 || exit 1
wait_height 0 "$BLOCKS" 60
cli 0 generate 3 >/dev/null; ck "mining after the interrupted reindexes" "$(cli 0 getblockcount)" "$((BLOCKS + 3))"
ck "chain verifies at the end" "$(cli 0 verifychain 4 0)" true
stop 0
np=$(grep -c '^PASS' "$SCN_LOG"); nf=$(grep -c '^FAIL' "$SCN_LOG")
say "reindex interrupt: $np pass, $nf fail"
[ "$nf" = 0 ] && [ "$np" -gt 0 ]
