#!/bin/sh
# The wallet writes its checkpoint (best-block locator, witness cache size, dirty note
# transactions: one wallet.dat transaction) once the node has caught up, not only at the
# hourly interval or at a clean stop.
#
# The state of a wallet whose node was stopped, or whose datadir came from a snapshot sync, at a low
# height: the chain on disk sits at the wallet's locator when the wallet loads (nothing to rescan at
# start-up), then many blocks are connected after start-up and the wallet follows them in memory.
#
# 1  clean stop, the miner mines 1150 blocks, restart: after the catch-up checkpoint_height is the tip
#    and checkpoint_failed is false
# 2  kill -9 right after that checkpoint: the restart asks for no rescan, checkpoint_height is the tip,
#    and the balances and unspent outputs equal those of a node that rescans a copy from genesis
# 3  a clean restart: no rescan either
#
# usage: wallet_checkpoint_after_catchup.sh --bin <dir> --work <dir> [--peer-bin <dir>] [--base port]
# Output: <work>/results.txt. Exit status 0 when every check passed.
# Needs the Zcash parameters in ~/.zcash-params. Shell only, no Python.
BIN=""; WORK=""; PEER_BIN=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;;
        --base) PORT_BASE=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--peer-bin DIR] [--base port]" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$BIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; OBS_LOG=$WORK/obs.txt; : >"$RESULTS"; : >"$OBS_LOG"
iso_base BASE "${PORT_BASE:-}" 112
trap 'stop_all' EXIT
R1="-connect=127.0.0.1:$((BASE + 1))"
LOG() { printf "%s" "$SD/node$1/regtest/debug.log"; }
hv() { cli 0 getwalletinfo | jget "health.$1"; }
# await_cp <tip-expected>: wait up to 60 s for checkpoint_height to reach it; prints the value seen
await_cp() {
    t=0
    while :; do
        v=$(hv checkpoint_height)
        [ "$v" = "$1" ] && break
        t=$((t + 1)); [ $t -lt 60 ] || break
        sleep 1
    done
    printf "%s\n" "$v"
}
rescans() { grep -c "Rescanning last" "$(LOG 0)"; }
snap() { # snap <n> <label>: the balances of node n in one line
    printf "%s|%s|%s" "$(cli "$1" z_gettotalbalance 1 | jq -cS .)" "$(cli "$1" listunspent 1 | jq -cS "[.[] | {txid, vout, amount}] | sort_by(.txid, .vout)")" \
        "$(cli "$1" z_listunspent 1 | jq -cS "[.[] | {txid, amount, address}] | sort_by(.txid, .address)")"
}

scn_catchup() {
    setup2 -disablesafemode || return
    ZS=$(cli 0 z_getnewaddress sapling); give_z 0 "$ZS" 4
    SPR=$(cli 0 z_getnewaddress sprout); give_z 0 "$SPR" 2
    give_t 0 3 >/dev/null
    mine 2
    stop 0
    h0=$(cli 1 getblockcount)
    cli 1 generate 1150 >/dev/null
    top=$(cli 1 getblockcount)
    start 0 "$BIN" $R1 -disablesafemode || return
    sync_to 0
    ck "catch-up: the wallet followed the chain to the tip" "$(hv tip_height)" "$top"
    ck "catch-up: no start-up rescan (the chain on disk sat at the locator)" "$(rescans)" 0
    ck "catch-up: checkpoint_height is the tip (was $h0 at the start)" "$(await_cp "$top")" "$top"
    ck "catch-up: no failed checkpoint" "$(hv checkpoint_failed) $(hv checkpoint_failures)" "false 0"
    ck "catch-up: notes ready" "$(hv sapling.witness_ready) $(hv sapling.witness_missing)" "1 0"
    kill9 0
    cp -R "$SD/node0" "$SD/node2"; rm -f "$SD/node2/pid" "$SD/node2/regtest/.lock"
    M=$(wc -l <"$(LOG 0)")
    start 0 "$BIN" $R1 -disablesafemode || return
    sync_to 0
    ck "kill -9: the restart asks for no rescan" "$(tail -n +$((M + 1)) "$(LOG 0)" | grep -c "Rescanning last")" 0
    ck "kill -9: checkpoint_height is the tip" "$(hv checkpoint_height) $(hv tip_height)" "$top $top"
    start 2 "$BIN" -connect=127.0.0.1:$((BASE + 1)) -disablesafemode -rescan || return
    sync_to 2
    ck "kill -9: balances equal a -rescan of the same datadir" "$(snap 0)" "$(snap 2)"
    ck "kill -9: the shielded balance is there" "$(zbal 0 "$ZS")" 4.00000000
    stop 0
    M=$(wc -l <"$(LOG 0)")
    start 0 "$BIN" $R1 -disablesafemode || return
    ck "clean restart: no rescan" "$(tail -n +$((M + 1)) "$(LOG 0)" | grep -c "Rescanning last")" 0
    ck "clean restart: checkpoint_height is the tip" "$(hv checkpoint_height)" "$top"
}

SCN_ID=1; SCN_LOG=$WORK/scn1.log; SD=$WORK/s1; : >"$SCN_LOG"
rm -rf "$SD"; mkdir -p "$SD"
say "== 1. checkpoint after a catch-up"
( scn_catchup ) 2>&1 | tee "$WORK/scn1.out" >/dev/null
stop_all
np=$(grep -c "^PASS" "$SCN_LOG"); nf=$(grep -c "^FAIL" "$SCN_LOG")
st=PASS; [ "$nf" = 0 ] && [ "$np" -gt 0 ] || st=FAIL
echo "1|checkpoint after a catch-up|$st|$np pass $nf fail" >>"$RESULTS"
cat "$SCN_LOG"; say "   -> $st ($np pass, $nf fail)"
[ "$st" = PASS ]
