#!/bin/sh
# getnodestatus on regtest: node A (miner) generates 20 blocks, node B starts alone at height 0 and
# then connects to A. B must not report synced=true before it holds all 20 blocks, then reports
# synced=true and state ok; with -zslpindex=1 the index shows up in `indexes`.
#
# usage: nodestatus.sh --bin <dir with zclassicd and zclassic-cli> --work <dir> [--base port]
#   env NODESTATUS_BENCH=1  also time 1000 alternating getnodestatus and getblockchaininfo calls
#                           while gettxoutsetinfo runs in a loop (p50/p99 in milliseconds).
# Output: PASS/FAIL lines on stdout and <work>/results.txt; exit 0 only if nothing failed.
# POSIX sh, temp datadirs under --work, stops every daemon it starts. Node 0 is B, node 1 is A
# (the wallet_matrix_lib.sh convention).
BIN=""; WORK=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;;
        *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
iso_base BASE "${PORT_BASE:-}" 112
SD=$WORK/nodestatus; rm -rf "$SD"; mkdir -p "$SD"
SCN_ID=nodestatus; SCN_LOG=$WORK/nodestatus.log; OBS_LOG=$WORK/obs.txt; : >"$SCN_LOG"; : >"$OBS_LOG"
trap 'stop_all' EXIT

# 1. node A mines 20 blocks and answers getnodestatus without peers
start 1 "$BIN" || { echo "FAIL cannot start A"; exit 1; }
cli 1 generate 20 >/dev/null
ck "A has 20 blocks" "$(cli 1 getblockcount)" 20
st=$(cli 1 getnodestatus)
ck "A without peers is no_peers" "$(printf %s "$st" | jget state)" no_peers
ck "A without peers is not synced" "$(printf %s "$st" | jget synced)" false
ck "A reports its blocks" "$(printf %s "$st" | jget blocks)" 20
case $(printf %s "$st" | jget indexes.txindex) in true|false) pass "A txindex flag is a boolean" ;; *) bad "A txindex flag is not a boolean" ;; esac
ck "A zslpindex is disabled" "$(printf %s "$st" | jget indexes.zslpindex.enabled)" false
[ "$(printf %s "$st" | jget datadir_free_bytes)" -gt 0 ] && pass "datadir_free_bytes is positive" || bad "datadir_free_bytes not positive"
ckerr "getnodestatus refuses arguments" "getnodestatus" 1 getnodestatus 1

# 2. node B starts alone at height 0 with the ZSLP index on, then connects to A
start 0 "$BIN" -connect=0 -zslpindex=1 || { echo "FAIL cannot start B"; exit 1; }
first=$(cli 0 getnodestatus)
ck "B alone waits for peers" "$(printf %s "$first" | jget syncphase)" waiting_for_peers
cli 0 addnode "127.0.0.1:$((BASE + 1))" onetry
n=0; early_true=0; saw_false=0; last=""
if [ "$(printf %s "$first" | jget synced)" = false ]; then saw_false=1; fi
while [ $n -lt 120 ]; do
    last=$(cli 0 getnodestatus)
    s=$(printf %s "$last" | jget synced); b=$(printf %s "$last" | jget blocks)
    [ "$s" = true ] && [ "$b" -ne 20 ] && early_true=$((early_true + 1))
    [ "$s" = true ] && [ "$b" -eq 20 ] && break
    n=$((n + 1)); sleep 1
done
ck "B first answer is not synced" "$saw_false" 1
ck "B never claims synced below 20 blocks" "$early_true" 0
ck "B reaches 20 blocks" "$(cli 0 getblockcount)" 20
ck "B reports synced" "$(printf %s "$last" | jget synced)" true
ck "B state is ok" "$(printf %s "$last" | jget state)" ok
ck "B syncphase is synced" "$(printf %s "$last" | jget syncphase)" synced
ck "B reasons are empty" "$(printf %s "$last" | jget reasons | tr -d ' \n')" "[]"
ck "B best peer height" "$(printf %s "$last" | jget best_peer_height)" 20
ck "B blocks_behind" "$(printf %s "$last" | jget blocks_behind)" 0
ck "B has one outbound peer" "$(printf %s "$last" | jget peers.out)" 1
ck "B zslpindex enabled" "$(printf %s "$last" | jget indexes.zslpindex.enabled)" true
t=0; until [ "$(cli 0 getnodestatus | jget indexes.zslpindex.synced)" = true ] || [ $t -ge 60 ]; do t=$((t + 1)); sleep 1; done
st=$(cli 0 getnodestatus)
ck "B zslpindex synced" "$(printf %s "$st" | jget indexes.zslpindex.synced)" true
ck "B zslpindex indexed_height" "$(printf %s "$st" | jget indexes.zslpindex.indexed_height)" 20
ck "B znamindex disabled" "$(printf %s "$st" | jget indexes.znamindex.enabled)" false
[ "$(printf %s "$st" | jget uptime_seconds)" -ge 0 ] && pass "uptime_seconds present" || bad "uptime_seconds missing"
ck "A sees B inbound" "$(cli 1 getnodestatus | jget peers.in)" 1

# 3. optional latency comparison (one cheap call versus getblockchaininfo, under a parallel scan);
# the two calls alternate so that noise from the scan and the host hits both the same way
if [ "${NODESTATUS_BENCH:-0}" = 1 ]; then
    ( while [ ! -f "$SD/bench.stop" ]; do cli 0 gettxoutsetinfo >/dev/null 2>&1; done ) &
    SCAN=$!
    : >"$SD/lat.getnodestatus"; : >"$SD/lat.getblockchaininfo"; i=0
    while [ $i -lt 1000 ]; do
        for m in getnodestatus getblockchaininfo; do
            t0=$(now); cli 0 "$m" >/dev/null; t1=$(now)
            awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.2f\n", (b - a) * 1000 }' >>"$SD/lat.$m"
        done
        i=$((i + 1))
    done
    for m in getnodestatus getblockchaininfo; do
        sort -n "$SD/lat.$m" | awk -v m="$m" '{ v[NR] = $1 } END { printf "%s p50=%.1fms p99=%.1fms\n", m, v[int(NR*0.50)], v[int(NR*0.99)] }' | tee -a "$OBS_LOG"
    done
    touch "$SD/bench.stop"; wait "$SCAN" 2>/dev/null
fi

stop 0; stop 1
cp "$SCN_LOG" "$WORK/results.txt"
if grep -q '^FAIL' "$SCN_LOG"; then say "nodestatus: FAILED"; exit 1; fi
say "nodestatus: PASS"
exit 0
