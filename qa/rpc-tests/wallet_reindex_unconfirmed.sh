#!/bin/sh
# An unconfirmed wallet send must survive -reindex.
#
# ReacceptWalletTransactions runs at the end of init, while the block import thread of -reindex
# is still working (the chain can be empty or short): the wallet's pending send is refused or
# cannot be judged then, and nothing offered it again, so after the reindex it was in neither the
# chain nor the mempool and the inputs it spends counted as unspent (minconf 1 transparent
# balance too high by the amount sent, minconf 0 total too high by the fee). The wallet now
# offers its transactions to the mempool again when the reindex has finished (mempool admission
# only; nothing is relayed).
# The balances, the unspent outputs and the mempool after the reindex must equal those of the
# same wallet before it.
#
# usage: wallet_reindex_unconfirmed.sh --bin <dir> --work <dir> [--base port]
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
NODE_ARGS="-disablesafemode -connect=0"

# snap <n>: transparent balances at minconf 0 and 1, unspent outputs, mempool size, exact
snap() {
    printf "t0=%s t1=%s tot0=%s utxo=%s pool=%s" "$(bal "$1" '*' 0)" "$(bal "$1" '*' 1)" "$(cli "$1" z_gettotalbalance 0 | jraw total)" \
        "$(cli "$1" listunspent 0 | jq -c "[.[]|.txid[0:8]+\":\"+(.vout|tostring)+\":\"+(.confirmations|tostring)]|sort")" \
        "$(cli "$1" getrawmempool | jlen)"
}

# 1: node 0 holds mature non-coinbase funds and one unconfirmed transparent send
scn_reindex_unconfirmed() {
    start 0 "$BIN" $NODE_ARGS || return
    cli 0 generate 110 >/dev/null
    Z1=$(cli 0 z_getnewaddress sapling); T=$(cli 0 getnewaddress)
    r=$(wait_op 0 "$(cli 0 z_shieldcoinbase "*" "$Z1" 0.0001 0 | jget opid)"); case $r in success*) ;; *) bad "shieldcoinbase: $r" ;; esac
    cli 0 generate 1 >/dev/null
    r=$(zsend 0 "$Z1" "[{\"address\":\"$T\",\"amount\":5}]"); case $r in success*) ;; *) bad "fund t address: $r" ;; esac
    cli 0 generate 2 >/dev/null
    cli 0 sendtoaddress "$(cli 0 getnewaddress)" 0.51 >/dev/null || bad "sendtoaddress"
    BEFORE=$(snap 0)
    ck "one transaction pending" "$(cli 0 getrawmempool | jlen)" 1
    stop 0; start 0 "$BIN" $NODE_ARGS || return
    ck "restart keeps the pending send" "$(snap 0)" "$BEFORE"
    stop 0; start 0 "$BIN" $NODE_ARGS -reindex || return
    t=0; until [ "$(cli 0 getblockcount)" = 113 ] && [ "$(cli 0 getrawmempool | jlen)" = 1 ]; do
        t=$((t + 1)); [ $t -lt 60 ] || break; sleep 1
    done
    ck "height after -reindex" "$(cli 0 getblockcount)" 113
    ck "-reindex keeps the pending send" "$(snap 0)" "$BEFORE"
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

run_scn 1 "unconfirmed send survives -reindex" scn_reindex_unconfirmed

say; say "id|scenario|result|checks"; cat "$RESULTS"
! grep -q "|FAIL|" "$RESULTS"
