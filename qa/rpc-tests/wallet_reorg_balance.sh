#!/bin/sh
# Live wallet versus restarted wallet after a reorg that drops shielded sends.
#
# A node sends shielded funds in consecutive blocks, invalidates the last six, mines a longer
# branch of its own and reconsiders the old one. The sends of the dropped blocks cannot be put
# back in the mempool (their anchors are gone with the blocks), so they are neither in the chain
# nor in the mempool and must not contribute confirmed funds. The balances (z_gettotalbalance,
# z_getbalance per address, z_listunspent, listunspent) of the running wallet must equal those
# of the same wallet after a restart and after a restart with -rescan.
#
# usage: wallet_reorg_balance.sh --bin <dir> --work <dir> [--base port]
# Output: <work>/results.txt. Exit status 0 when every check passed.
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
BIN=""; WORK=""; PORT_BASE=""; ONLY=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
PEER_BIN=$BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; OBS_LOG=$WORK/obs.txt; : >"$RESULTS"; : >"$OBS_LOG"
BASE=${PORT_BASE:-$((20000 + ($$ % 20000)))}
trap stop_all EXIT
NODE_ARGS="-disablesafemode -parkdeepreorg=0 -connect=0"

# snap <n> <minconf>: totals, per-address balances, notes and unspent outputs, exact
snap() {
    printf "tot=%s z1=%s z2=%s notes=%s utxo=%s" "$(cli "$1" z_gettotalbalance "$2" | jq -c "[.transparent,.private,.total]")" \
        "$(zbal "$1" "$Z1" "$2")" "$(zbal "$1" "$Z2" "$2")" \
        "$(cli "$1" z_listunspent "$2" | jq -c "[.[]|(.amount*100000000|round)]|sort")" \
        "$(cli "$1" listunspent "$2" | jq -c "[.[]|.txid[0:8]+\":\"+(.vout|tostring)]|sort")"
}
# reorg_setup: node 0 holds a 3 coin Sapling note and sends 0.2 seven times, one block each, then
# invalidates the last six of those blocks (the first of them holds the second send)
reorg_setup() {
    start 0 "$BIN" $NODE_ARGS || return 1
    cli 0 generate 110 >/dev/null
    Z1=$(cli 0 z_getnewaddress sapling); Z2=$(cli 0 z_getnewaddress sapling)
    r=$(wait_op 0 "$(cli 0 z_shieldcoinbase "*" "$Z1" 0.0001 0 | jq -r .opid)"); case $r in success*) ;; *) bad "shieldcoinbase: $r" ;; esac
    cli 0 generate 1 >/dev/null
    r=$(zsend 0 "$Z1" "[{\"address\":\"$Z2\",\"amount\":3}]"); case $r in success*) ;; *) bad "first send: $r" ;; esac
    cli 0 generate 1 >/dev/null
    for k in 1 2 3 4 5 6 7; do
        r=$(zsend 0 "$Z2" "[{\"address\":\"$Z1\",\"amount\":0.2}]"); case $r in success*) ;; *) bad "send $k: $r" ;; esac
        cli 0 generate 1 >/dev/null
    done
    ht=$(cli 0 getblockcount); first=$(cli 0 getblockhash $((ht - 5)))
    cli 0 invalidateblock "$first" >/dev/null
}
# restart_checks: the wallet restarted, then a -rescan copy of it, must show what the live one did
restart_checks() {
    for mc in 0 1; do eval "LIVE$mc=\$(snap 0 $mc)"; done
    stop 0; start 0 "$BIN" $NODE_ARGS || return
    for mc in 0 1; do eval "w=\$LIVE$mc"; ck "live == restart, minconf $mc" "$(snap 0 $mc)" "$w"; done
    stop 0; rm -rf "$SD/node3"; cp -a "$SD/node0" "$SD/node3"; rm -f "$SD/node3/regtest/.lock"
    start 3 "$BIN" $NODE_ARGS -rescan || return
    for mc in 0 1; do eval "w=\$LIVE$mc"; ck "live == rescan, minconf $mc" "$(snap 3 $mc)" "$w"; done
    stop 3
}
# 1: at the lowered tip
scn_invalidate_only() { reorg_setup || return; restart_checks; }
# 2: a longer branch on top, then the old one reconsidered (it stays parked behind the new one)
scn_reorg_balance() {
    reorg_setup || return
    cli 0 generate 8 >/dev/null
    cli 0 reconsiderblock "$first" >/dev/null; sleep 2
    restart_checks
}

run_scn() {
    id=$1; name=$2; fn=$3
    SCN_ID=$id; SCN_LOG=$WORK/scn$id.log; SD=$WORK/s$id; : >"$SCN_LOG"
    rm -rf "$SD"; mkdir -p "$SD"
    say "== $id. $name"
    ( $fn ) 2>&1 | tee "$WORK/scn$id.out" >/dev/null
    stop_all
    np=$(grep -c "^PASS" "$SCN_LOG"); nf=$(grep -c "^FAIL" "$SCN_LOG")
    st=PASS; [ "$nf" = 0 ] && [ "$np" -gt 0 ] || st=FAIL
    echo "$id|$name|$st|$np pass $nf fail" >>"$RESULTS"
    say "   -> $st ($np pass, $nf fail)"
    BASE=$((BASE + 7)); [ $BASE -lt 60000 ] || BASE=20000
}


run_scn 1 "invalidated blocks with shielded sends: live == restart == rescan" scn_invalidate_only
run_scn 2 "shielded sends dropped by a reorg: live == restart == rescan" scn_reorg_balance

say; say "id|scenario|result|checks"; cat "$RESULTS"
! grep -q "|FAIL|" "$RESULTS"
