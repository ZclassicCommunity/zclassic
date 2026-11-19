#!/bin/sh
# The wallet's retry of its pending transactions must not cost proof verification at every tip
# of a catch-up.
#
# After a hard kill before the first chainstate flush a node restarts at height 0 and re-syncs
# from its peer; its wallet holds confirmed shielded transactions of a chain it no longer has
# and a shielded send that was never mined. CWallet::UpdatedBlockTip offers them to the mempool
# at each of the next REACCEPT_TIPS_AFTER_UNWIND tips. AcceptToMemoryPool verifies the
# JoinSplit and Sapling proofs of a transaction (about 2 ms each, 12 ms for the send) before it
# looks for its inputs and anchors, so each of those passes cost 9 to 20 ms for work whose
# outcome (a refusal, the anchors are not in the chain yet) was known without the proofs: 0.2 to
# 0.4 s on a 147 block re-sync. The wallet now checks the prerequisites first and hands a
# transaction to the mempool only when they are met.
#
# Checks: the -debug=bench line of each pass says how many transactions were handed to the
# mempool; over the whole re-sync that must be at most a few (the passes at the last tips, once
# the anchors are back), where it was one per refused transaction at every tip before; and the
# send is still mined and counted exactly. Since the start-up retries are held until the node
# has caught up with the best known header, the retry normally runs once, at the caught-up tip,
# and hands the send over there (0 refused): node 0 re-accepts its own send without having
# verified its proofs at any earlier tip. Without that hold the retry ran at up to 20 tips
# during the re-sync; the bound on handed transactions covers both shapes.
#
# usage: wallet_reaccept_bound.sh --bin <dir> --work <dir> [--peer-bin <dir>] [--base port]
# Output: <work>/results.txt. Exit status 0 when every check passed.
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
BIN=""; WORK=""; PEER_BIN=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;;
        *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--peer-bin DIR] [--base port]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$BIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; OBS_LOG=$WORK/obs.txt; : >"$RESULTS"; : >"$OBS_LOG"
iso_base BASE "${PORT_BASE:-}" 112
trap stop_all EXIT

# fund_notes <n> <zaddr> <count> <amount>: <count> separate notes of <amount> on <zaddr>
fund_notes() {
    local n=$1 zs=$2 cnt=$3 amt=$4 addrs json ops ta op r
    cli 1 generate 3 >/dev/null
    addrs=$(for i in $(seq 1 "$cnt"); do cli 1 getnewaddress; done)
    json=$(printf '%s\n' "$addrs" | jq -Rsc --argjson a "$(add "$amt" 0.001)" 'split("\n")[:-1]|map({key:.,value:$a})|from_entries')
    cli 1 sendmany "" "$json" >/dev/null; cli 1 generate 1 >/dev/null
    ops=""; for ta in $addrs; do op=$(cli 1 z_sendmany "$ta" "[{\"address\":\"$zs\",\"amount\":$amt}]" 1 0.001); ops="$ops $op"; done
    for op in $ops; do r=$(wait_op 1 "$op"); case $r in success*) ;; *) bad "fund_notes: $r" ;; esac; done
    cli 1 generate 1 >/dev/null; sync_to "$n"
}

scn_bound() {
    start 1 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 0)) || return
    start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) -debug=bench || return
    cli 1 generate 112 >/dev/null; sync_to 0
    zs=$(cli 0 z_getnewaddress); cli 1 generate 30 >/dev/null; sync_to 0
    fund_notes 0 "$zs" 5 1
    b0=$(zbal 0 "$zs"); rec=$(cli 1 z_getnewaddress | jq -Rsc --argjson amt 4.5 'split("\n")[:-1]|map({address:.,amount:$amt})')
    r=$(zsend 0 "$zs" "$rec" 1 "$FEE")
    case $r in success*) ;; *) bad "z_sendmany: $r"; return ;; esac
    tx=${r#success }
    LOG=$SD/node0/regtest/debug.log; L0=$(wc -l <"$LOG")
    # the wallet database is flushed after 2 s without writes: a kill -9 sooner may lose the send itself, which is not what is tested
    sleep 4
    kill9 0; start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) -debug=bench || return
    sync_to 0
    ck "re-synced to the peer tip" "$(cli 0 getblockcount)" "$(cli 1 getblockcount)"
    # one bench line per pass of the per-tip retry: "... (<refused> refused, <handed> handed to the mempool)"
    tail -n +"$((L0 + 1))" "$LOG" | grep 'Wallet mempool re-offer at tip' >"$SD/passes.txt"
    passes=$(wc -l <"$SD/passes.txt" | tr -d ' ')
    handed=$(sed 's/.*, \([0-9]*\) handed to the mempool.*/\1/' "$SD/passes.txt" | awk '{ s += $1 } END { print s + 0 }')
    obs "retry_passes" "$passes"; obs "transactions_handed_to_mempool_over_all_passes" "$handed"
    ck "the retry ran, and at most 20 times" "$([ "$passes" -ge 1 ] && [ "$passes" -le 20 ] && echo yes)" yes
    ck "at most 3 transactions handed to the mempool over the whole re-sync" "$([ "$handed" -le 3 ] && echo yes)" yes
    refused_last=$(tail -n 1 "$SD/passes.txt" | sed 's/.*(//; s/ refused.*//')
    obs "refused_at_last_pass" "$refused_last"
    # the send is in the miner mempool (relayed before the kill) and counted exactly once mined
    w=0; until cli 1 getrawmempool | grep -q "$tx" || [ $w -ge 120 ]; do sleep 1; w=$((w + 1)); done
    cli 1 getrawmempool | grep -q "$tx" && pass "the pending send is in the miner mempool" || bad "the pending send is not in the miner mempool"
    mine 1
    w=0; until [ "$(zbal 0 "$zs")" = "$(add "$b0" -4.5 -$FEE)" ] || [ $w -ge 60 ]; do sleep 1; w=$((w + 1)); done
    ck "exact balance after the send is mined" "$(zbal 0 "$zs")" "$(add "$b0" -4.5 -$FEE)"
    alive reaccept_bound
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
}

run_scn 1 "no proof verification per tip while re-syncing after a hard kill" scn_bound

say; say "id|scenario|result|checks"; cat "$RESULTS"
! grep -q "|FAIL|" "$RESULTS"
