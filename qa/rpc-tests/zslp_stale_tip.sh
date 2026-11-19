#!/bin/sh
# ZSLP and ZNAM index whose tip block is missing from the block index, on regtest.
#
# kill -9 shortly after the index applied a block: the index stores commit every
# block, but the block index (and the chain state) are only written now and then,
# so after the restart the index tip is no block this node knows. If the chain then
# moves on without that block (here: a peer has a different, longer chain), the
# index used to report "the index tip ... is not in the block index ... waiting"
# for ever. It must discard its (derived) data and index the active chain.
#
# Node 0 runs -zslpindex and -znamindex, node 1 is a plain node that supplies the
# competing chain.
#
# usage: zslp_stale_tip.sh [dir-with-zclassicd-zclassic-cli]
#   env KEEP=1   keep the temp directory
#
# Needs: jq. Every node runs on 127.0.0.1 with its own temp datadir and ports.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
SRC=${1:-$TOP/src}
ZD=$SRC/zclassicd
ZCLI=$SRC/zclassic-cli
for b in "$ZD" "$ZCLI"; do [ -x "$b" ] || { echo "missing $b" >&2; exit 2; }; done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
. "$(dirname "$0")/jsonq_lib.sh"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/zcl-stale-tip.XXXXXX")
BASE=${E2E_PORT_BASE:-$((20000 + ($$ % 20000)))}
port_busy() {
    if command -v ss >/dev/null 2>&1; then
        [ -n "$(ss -Htln "sport = :$1" 2>/dev/null)" ]
    else
        lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
    fi
}
_try=0
while port_busy "$BASE" || port_busy $((BASE + 1)) || port_busy $((BASE + 100)) || port_busy $((BASE + 101)); do
    BASE=$((BASE + 7)); _try=$((_try + 1)); [ $_try -lt 200 ] || { echo "no free port block" >&2; exit 2; }
done
PIDS=""
CHECKS=0
PASSED=0

say() { printf '%s\n' "$*"; }
ok() { CHECKS=$((CHECKS + 1)); say "  ok   $*"; }
fail() { say "  FAIL $*"; exit 1; }

cleanup() {
    if [ "$PASSED" != 1 ]; then
        for d in "$TMP"/node*; do
            [ -f "$d/regtest/debug.log" ] && { say "---- $d debug.log (tail)"; tail -15 "$d/regtest/debug.log" | cut -c1-300; }
        done
    fi
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    for p in $PIDS; do
        n=0
        while kill -0 "$p" 2>/dev/null && [ $n -lt 60 ]; do sleep 1; n=$((n + 1)); done
        kill -9 "$p" 2>/dev/null || true
    done
    if [ "${KEEP:-0}" = 1 ]; then say "kept $TMP"; else rm -rf "$TMP"; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

cli() { n=$1; shift; "$ZCLI" -datadir="$TMP/node$n" -regtest -rpcport=$((BASE + 100 + n)) "$@"; }

start() { # <n> [extra args]
    n=$1; shift
    dir=$TMP/node$n
    mkdir -p "$dir"
    if [ ! -f "$dir/zclassic.conf" ]; then
        { echo "regtest=1"; echo "rpcuser=stale"; echo "rpcpassword=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"; } >"$dir/zclassic.conf"
    fi
    "$ZD" -datadir="$dir" -regtest -server=1 -daemon=0 -showmetrics=0 \
        -listen=1 -bind=127.0.0.1 -port=$((BASE + n)) \
        -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=$((BASE + 100 + n)) \
        -dnsseed=0 -discover=0 -listenonion=0 -upnp=0 -keypool=5 -debuglogfile=1 -parkdeepreorg=0 \
        "$@" >"$dir/stdout.log" 2>&1 &
    pid=$!
    PIDS="$PIDS $pid"
    echo "$pid" >"$dir/pid"
    t=0
    until cli "$n" getblockcount >/dev/null 2>&1; do
        kill -0 "$pid" 2>/dev/null || { cat "$dir/stdout.log"; fail "node $n exited during startup"; }
        t=$((t + 1)); [ $t -lt 300 ] || fail "node $n did not start"
        sleep 1
    done
}

stop() {
    pid=$(cat "$TMP/node$1/pid")
    cli "$1" stop >/dev/null
    t=0
    while kill -0 "$pid" 2>/dev/null; do t=$((t + 1)); [ $t -lt 120 ] || fail "node $1 did not stop"; sleep 1; done
}

kill9() {
    pid=$(cat "$TMP/node$1/pid")
    kill -9 "$pid"
    t=0
    while kill -0 "$pid" 2>/dev/null; do t=$((t + 1)); [ $t -lt 30 ] || fail "node $1 survived kill -9"; sleep 1; done
}

# wait_indexes <n>: the zslp and znam indexes of node n are at node n's tip, synced, without an error
wait_indexes() {
    for rpc in zslp_getindexinfo znam_getindexinfo; do
        t=0
        while :; do
            info=$(cli "$1" "$rpc" 2>/dev/null || true)
            tip=$(cli "$1" getbestblockhash)
            if [ -n "$info" ] && [ "$(printf '%s' "$info" | jget indexedblock)" = "$tip" ] &&
               [ "$(printf '%s' "$info" | jget synced)" = true ] &&
               [ -z "$(printf '%s' "$info" | jgetd error "")" ]; then break; fi
            t=$((t + 1)); [ $t -lt 120 ] || fail "$rpc of node $1 did not reach the tip: $info"
            sleep 1
        done
    done
}

say "== node 0 (zslp + znam index) and node 1 share a chain; both stop cleanly, so it is on disk"
start 0 -zslpindex=1 -znamindex=1
start 1
cli 0 addnode "127.0.0.1:$((BASE + 1))" onetry >/dev/null
t=0; until [ "$(cli 0 getconnectioncount)" -ge 1 ] && [ "$(cli 1 getconnectioncount)" -ge 1 ]; do
    t=$((t + 1)); [ $t -lt 60 ] || fail "nodes did not connect"; sleep 1; done
cli 0 generate 20 >/dev/null
t=0; until [ "$(cli 1 getblockcount)" = 20 ]; do t=$((t + 1)); [ $t -lt 120 ] || fail "node 1 did not sync"; sleep 1; done
wait_indexes 0
stop 0
stop 1

say "== node 0 alone mines 3 blocks, its indexes follow, then kill -9 before the block index is written"
start 0 -zslpindex=1 -znamindex=1
cli 0 generate 3 >/dev/null
wait_indexes 0
LOST=$(cli 0 getbestblockhash)
kill9 0
ok "node 0 died with its indexes at $LOST"

say "== node 1 mines 6 blocks of a different chain on the same base"
start 1
cli 1 generate 6 >/dev/null
[ "$(cli 1 getblockcount)" = 26 ] || fail "node 1 has height $(cli 1 getblockcount)"

say "== node 0 restarts: $LOST is not in its block index, the chain moves on without it"
start 0 -zslpindex=1 -znamindex=1
[ "$(cli 0 getblockcount)" -lt 23 ] || fail "node 0 kept its last blocks (the block index was written): this run cannot show the problem"
cli 0 addnode "127.0.0.1:$((BASE + 1))" onetry >/dev/null
t=0; until [ "$(cli 0 getbestblockhash)" = "$(cli 1 getbestblockhash)" ]; do
    t=$((t + 1)); [ $t -lt 120 ] || fail "node 0 did not reach the tip of node 1"; sleep 1; done
[ "$(cli 0 getblockheader "$LOST" 2>&1 | grep -c 'Block not found')" = 1 ] || fail "$LOST is known to node 0"
wait_indexes 0
ok "both indexes of node 0 reached node 1's tip $(cli 0 getbestblockhash) (height 26) without an error"
for rpc in zslp_getindexinfo znam_getindexinfo; do
    cli 0 "$rpc" | jq -e '.indexedheight == 26' >/dev/null || fail "$rpc: $(cli 0 "$rpc")"
done
grep -q "rebuilding the index" "$TMP/node0/regtest/debug.log" || fail "no rebuild is logged"
ok "the debug log says the indexes were rebuilt"

PASSED=1
say "zslp_stale_tip.sh: PASS ($CHECKS checks)"
