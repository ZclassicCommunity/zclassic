#!/bin/sh
# getwalletinfo "health" object and the "status" field of wallet transactions.
#
# 1  funded wallet: sapling and sprout notes counted, witnesses ready, nothing pending, the
#    pre-existing getwalletinfo fields still there
# 2  a send in the mempool: the spent note, the unconfirmed change note, pending_sends.in_mempool,
#    status "pending"
# 3  the send mined: status "mined", counts settle
# 4  a send that expires unmined (-txexpirydelta=5, the miner never sees it): "pending", then
#    "expiringsoon", then "expired"; its inputs are spendable again
# 5  a reorg deeper than the witness cache: the rebuild has run (witness_rebuild_pending false),
#    every unspent confirmed note has a witness at the lowered tip
# 6  restart: the same counts, checkpoint_height at the tip after a clean stop
#
# witness_rebuild_pending = true cannot be sampled over RPC (the rebuild runs inside the
# invalidateblock call that causes it, which holds cs_main); the gtest wallet_health covers it.
#
# usage: wallet_health.sh --bin <dir> --work <dir> [--peer-bin <dir>] [--only 1,2,...] [--base port]
# Output: <work>/results.txt. Exit status 0 when every check passed.
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
BIN=""; WORK=""; PEER_BIN=""; ONLY=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;;
        --only) ONLY=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--peer-bin DIR] [--only N,N] [--base port]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$BIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; OBS_LOG=$WORK/obs.txt; : >"$RESULTS"; : >"$OBS_LOG"
BASE=${PORT_BASE:-$((20000 + ($$ % 20000)))}
trap 'stop_all' EXIT
R1="-connect=127.0.0.1:$((BASE + 1))"

# hv <jq path under .health>: one value of the report on node 0
hv() { case $1 in "["*) cli 0 getwalletinfo | jq -r ".health|$1" ;; *) cli 0 getwalletinfo | jq -r ".health.$1" ;; esac; }
# txst <txid>: the status of a wallet transaction
txst() { local t=0 s; while :; do s=$(cli 0 gettransaction "$1" 2>/dev/null | jq -r .status 2>/dev/null); [ -n "$s" ] && { echo "$s"; return; }; t=$((t + 1)); [ $t -lt 30 ] || { echo none; return; }; sleep 1; done; }
# wait_for <jq path> <want> [secs]: poll a health value
wait_h() { local t=0; until [ "$(hv "$1")" = "$2" ]; do t=$((t + 1)); [ $t -lt "${3:-30}" ] || return 1; sleep 1; done; }
isolate() { stop 1; start 1 "$PEER_BIN" -connect=0 -listen=0 || return 1; local t=0; while [ "$(cli 0 getconnectioncount)" -gt 0 ] && [ $t -lt 30 ]; do t=$((t + 1)); sleep 1; done; ck "isolated from the miner" "$(cli 0 getconnectioncount)" 0; }
rejoin() { stop 1; start 1 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 0)) || return 1; local t=0; until [ "$(cli 0 getconnectioncount)" -ge 1 ]; do t=$((t + 1)); [ $t -lt 60 ] || break; sleep 1; done; }

oldfields() {
    ck "$1: pre-existing getwalletinfo fields unchanged" \
        "$(cli 0 getwalletinfo | jq -r '[has("walletversion"),has("balance"),has("unconfirmed_balance"),has("immature_balance"),has("txcount"),has("keypoololdest"),has("keypoolsize"),has("paytxfee"),has("health")]|all')" true
}

fund() {
    setup2 -txexpirydelta=5 -disablesafemode || return 1
    ZS=$(cli 0 z_getnewaddress sapling); give_z 0 "$ZS" 4
    SPR=$(cli 0 z_getnewaddress sprout); give_z 0 "$SPR" 2
}

scn_fund() {
    fund || return
    oldfields funded
    ck "funded: tip_height" "$(hv tip_height)" "$(cli 0 getblockcount)"
    ck "funded: sapling unspent/spent" "$(hv 'sapling|[.notes_unspent,.notes_spent]|@csv')" "1,0"
    ck "funded: sapling witness ready/missing/stale" "$(hv 'sapling|[.witness_ready,.witness_missing,.witness_stale]|@csv')" "1,0,0"
    ck "funded: sprout unspent/spent" "$(hv 'sprout|[.notes_unspent,.notes_spent]|@csv')" "1,0"
    ck "funded: sprout witness ready/missing/stale" "$(hv 'sprout|[.witness_ready,.witness_missing,.witness_stale]|@csv')" "1,0,0"
    ck "funded: no pending sends" "$(hv 'pending_sends|[.in_mempool,.not_in_mempool,.expiring_soon,.expired,.conflicted]|@csv')" "0,0,0,0,0"
    ck "funded: no rebuild pending" "$(hv witness_rebuild_pending)" false
    c=$(hv witness_cache_size)
    ck "funded: witness cache size in 1..100" "$([ "$c" -ge 1 ] && [ "$c" -le 100 ] && echo yes)" yes
    ck "funded: checkpoint_height is -1 or at most the tip" "$([ "$(hv checkpoint_height)" -le "$(hv tip_height)" ] && echo yes)" yes
    ck "funded: a received note's transaction is mined" "$(txst "$(cli 0 z_listunspent 1 | jq -r '.[0].txid')")" mined
}

scn_pending() {
    fund || return
    ZB=$(cli 1 z_getnewaddress sapling)
    r=$(zsend 0 "$ZS" "[{\"address\":\"$ZB\",\"amount\":1}]" 1 "$FEE")
    case $r in success*) tx=${r#success } ;; *) bad "send: $r"; return ;; esac
    wait_mempool 1 "$tx"; txst "$tx" >/dev/null
    ck "pending: status" "$(txst "$tx")" pending
    ck "pending: in_mempool" "$(hv 'pending_sends|[.in_mempool,.not_in_mempool,.expired,.conflicted]|@csv')" "1,0,0,0"
    ck "pending: sapling spent 1, unspent 1 (unconfirmed change)" "$(hv 'sapling|[.notes_spent,.notes_unspent,.unconfirmed]|@csv')" "1,1,1"
    mine 1
    ck "mined: status" "$(txst "$tx")" mined
    ck "mined: nothing pending" "$(hv 'pending_sends|[.in_mempool,.not_in_mempool,.expiring_soon,.expired,.conflicted]|@csv')" "0,0,0,0,0"
    ck "mined: sapling spent 1, unspent 1 ready" "$(hv 'sapling|[.notes_spent,.notes_unspent,.witness_ready,.unconfirmed]|@csv')" "1,1,1,0"
    ck "mined: balance" "$(zbal 0 "$ZS")" "$(add 4 -1 -$FEE)"
}

scn_expire() {
    fund || return
    b0=$(zbal 0 "$ZS")
    ZB=$(cli 1 z_getnewaddress sapling)
    isolate; sleep 2
    r=$(zsend 0 "$ZS" "[{\"address\":\"$ZB\",\"amount\":1}]" 1 "$FEE")
    case $r in success*) tx=${r#success } ;; *) bad "send: $r"; return ;; esac
    ck "expire: status pending, in node 0 mempool" "$(txst "$tx") $(cli 0 getrawmempool | grep -c "$tx")" "pending 1"
    cli 1 generate 3 >/dev/null; rejoin; sync_to 0
    ck "expire: three blocks on, still in the mempool, status expiringsoon" "$(txst "$tx") $(cli 0 getrawmempool | grep -c "$tx")" "expiringsoon 1"
    ck "expire: expiring_soon counted" "$(hv 'pending_sends|[.in_mempool,.expiring_soon,.expired]|@csv')" "1,1,0"
    isolate; sleep 2
    cli 1 generate 5 >/dev/null; rejoin; sync_to 0
    ck "expire: the miner never saw it" "$(cli 1 getrawmempool | grep -c "$tx")" 0
    ck "expire: status expired" "$(txst "$tx")" expired
    ck "expire: counted as expired, not in the mempool" "$(hv 'pending_sends|[.in_mempool,.not_in_mempool,.expired,.conflicted]|@csv')" "0,0,1,0"
    ck "expire: inputs spendable again (balance as before the send)" "$(zbal 0 "$ZS")" "$b0"
    ck "expire: the original note is unspent again, the expired send's change note is dead" "$(hv 'sapling|[.notes_unspent,.unmined_dead,.notes_spent]|@csv')" "1,1,0"
}

scn_deep() {
    setup2 -disablesafemode || return
    ZS=$(cli 0 z_getnewaddress sapling); give_z 0 "$ZS" 4
    cli 1 generate 110 >/dev/null; sync_to 0
    ck "deep: cache is full before the unwind" "$(hv witness_cache_size)" 100
    ck "deep: note ready" "$(hv 'sapling|[.witness_ready,.witness_stale,.witness_missing]|@csv')" "1,0,0"
    first=$(cli 0 getblockhash $(($(cli 0 getblockcount) - 104)))
    cli 0 invalidateblock "$first" >/dev/null 2>&1
    low=$(cli 0 getblockcount)
    ck "deep: tip_height is the lowered tip" "$(hv tip_height)" "$low"
    ck "deep: rebuild no longer pending" "$(hv witness_rebuild_pending)" false
    ck "deep: note has a witness at the lowered tip" "$(hv 'sapling|[.witness_ready,.witness_stale,.witness_missing]|@csv')" "1,0,0"
    ck "deep: balance intact" "$(zbal 0 "$ZS")" 4.00000000
    cli 0 reconsiderblock "$first" >/dev/null 2>&1; sync_to 0
    ck "deep: after reconsiderblock the note is ready at the tip" "$(hv 'sapling|[.witness_ready,.witness_stale,.witness_missing]|@csv') $(hv tip_height)" "1,0,0 $(cli 1 getblockcount)"
}

scn_restart() {
    fund || return
    mine 2
    stop 0; start 0 "$BIN" $R1 -disablesafemode || return; sync_to 0
    ck "restart: checkpoint_height equals the tip after a clean stop" "$(hv checkpoint_height)" "$(cli 0 getblockcount)"
    ck "restart: counts" "$(hv '[.sapling.witness_ready,.sapling.notes_unspent,.sprout.witness_ready,.sprout.notes_unspent]|@csv')" "1,1,1,1"
    ck "restart: no rebuild pending, nothing pending" "$(hv witness_rebuild_pending) $(hv 'pending_sends|[.in_mempool,.not_in_mempool,.expired]|@csv')" "false 0,0,0"
    oldfields restart
    mine 1
    ck "restart: new block, witness ready at the new tip" "$(hv 'sapling|.witness_ready') $(hv tip_height)" "1 $(cli 1 getblockcount)"
}

run_scn() {
    id=$1; name=$2; fn=$3
    if [ -n "$ONLY" ]; then case ",$ONLY," in *",$id,"*) ;; *) return 0 ;; esac; fi
    SCN_ID=$id; SCN_LOG=$WORK/scn$id.log; SD=$WORK/s$id; : >"$SCN_LOG"
    rm -rf "$SD"; mkdir -p "$SD"
    say "== $id. $name"
    ( $fn ) 2>&1 | tee "$WORK/scn$id.out" >/dev/null
    stop_all
    np=$(grep -c '^PASS' "$SCN_LOG"); nf=$(grep -c '^FAIL' "$SCN_LOG")
    st=PASS; [ "$nf" = 0 ] && [ "$np" -gt 0 ] || st=FAIL
    echo "$id|$name|$st|$np pass $nf fail" >>"$RESULTS"
    say "   -> $st ($np pass, $nf fail)"
}

run_scn 1 "funded wallet" scn_fund
run_scn 2 "pending then mined send" scn_pending
run_scn 3 "send that expires unmined" scn_expire
run_scn 4 "reorg deeper than the witness cache" scn_deep
run_scn 5 "restart" scn_restart

say; say "id|scenario|result|checks"; cat "$RESULTS"
! grep -q "|FAIL|" "$RESULTS"
