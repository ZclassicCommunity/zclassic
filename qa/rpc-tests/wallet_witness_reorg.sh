#!/bin/sh
# Wallet witness-cache reorg matrix on regtest (CWallet::DecrementNoteWitnesses).
#
# A block disconnect used to assert(nWitnessCacheSize > 0) after the decrement,
# killing the daemon whenever more blocks were disconnected than the wallet had
# seen connect (fresh wallet, wallet created over an existing chain, a reorg to
# genesis) or deeper than the cache. Every sequence here must leave the daemon
# alive with exact balances, valid witnesses (a shielded spend is accepted and
# mined by a second node, normally an older binary) and the same notes and
# totals as a reference node holding a copy of the wallet restarted with -rescan.
#
# usage: wallet_witness_reorg.sh --bin <dir> --work <dir> [--peer-bin <dir>] [--only 1,2,...] [--base port]
#   --bin       directory with zclassicd and zclassic-cli: the wallet under test
#   --peer-bin  binary for the miner/peer nodes (default: --bin); use an old release
#   --only      comma list of scenario numbers (default: all)
# Output: <work>/results.txt. Exit status 0 when every scenario passed.
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
BIN=""; WORK=""; PEER_BIN=""; ONLY=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;;
        --only) ONLY=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--peer-bin DIR] [--only N,N]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$BIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
for f in "$HERE"/wallet_matrix_scn?.sh; do . "$f"; done
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; OBS_LOG=$WORK/obs.txt; : >"$RESULTS"; : >"$OBS_LOG"
BASE=${PORT_BASE:-$((20000 + ($$ % 20000)))}
trap 'stop_all' EXIT

R1="-connect=127.0.0.1:$((BASE + 1))"
# watch <what>: the node must still answer after the sequence
# refcheck <label>: a copy of node 0's wallet, restarted with -rescan on node 3,
# must hold the same notes and totals as node 0 (exact amounts)
refcheck() {
    local l=$1 want got
    rm -f "$SD/export/ref-$l.dat"
    # the fallback below restarts node 0, so it must never hide a node that died
    case $(cli 0 getblockcount 2>/dev/null) in ''|*[!0-9]*) bad "$l: daemon not responding before the reference copy"; return ;; esac
    if ! cli 0 backupwallet "ref-$l.dat" >/dev/null 2>&1; then
        # a binary without a working backupwallet: copy the file with the node stopped
        stop 0; cp "$SD/node0/regtest/wallet.dat" "$SD/export/ref-$l.dat"; start 0 "$BIN" $R1 -disablesafemode || return; sync_to 0
    fi
    rm -rf "$SD/node3"; mkdir -p "$SD/node3/regtest"; cp "$SD/export/ref-$l.dat" "$SD/node3/regtest/wallet.dat"
    start 3 "$BIN" -connect=127.0.0.1:$((BASE + 1)) -rescan || return
    sync_to 3
    want=$(printf 'z=%s notes=%s t=%s' "$(cli 0 z_gettotalbalance 0 | jq -r .private | f8)" "$(cli 0 z_listunspent 0 | jq -c '[.[]|(.amount*100000000|round)]|sort')" "$(bal 0 '*' 0)")
    got=$(printf 'z=%s notes=%s t=%s' "$(cli 3 z_gettotalbalance 0 | jq -r .private | f8)" "$(cli 3 z_listunspent 0 | jq -c '[.[]|(.amount*100000000|round)]|sort')" "$(bal 3 '*' 0)")
    ck "$l: wallet equals the -rescan reference" "$got" "$want"
    stop 3
}
# spend_check <label> <zaddr> <balance-before> <amount>: shielded spend, mined by node 1, exact
spend_check() {
    local l=$1 zs=$2 b=$3 amt=$4 ta
    ta=$(cli 1 getnewaddress)
    zconfirm 0 "$zs" "[{\"address\":\"$ta\",\"amount\":$amt}]" >/dev/null
    ck "$l: shielded spend accepted and mined, exact balance" "$(zbal 0 "$zs")" "$(add "$b" -$amt -$FEE)"
}
# base_note: miner (1) funds, node 0 gets a 4 ZCL Sapling note; sets ZS
base_note() {
    setup2 -disablesafemode || return 1
    ZS=$(cli 0 z_getnewaddress); give_z 0 "$ZS" 4
    cli 1 generate 3 >/dev/null; sync_to 0
    ck "note received" "$(zbal 0 "$ZS")" 4.00000000
}

# 1: fresh zero-note wallet follows a short chain, then a longer competing chain from genesis
scn_fork_genesis() {
    start 1 "$PEER_BIN" -connect=0 || return; start 2 "$PEER_BIN" -connect=0 || return; start 0 "$BIN" -connect=0 -disablesafemode || return
    cli 1 generate 3 >/dev/null; cli 2 generate 6 >/dev/null
    cli 0 addnode "127.0.0.1:$((BASE + 1))" onetry; sync_to 0 1
    ck "followed the short chain" "$(cli 0 getblockcount)" 3
    cli 0 addnode "127.0.0.1:$((BASE + 2))" onetry; sync_to 0 2
    alive fork_genesis 0
    ck "reorged to the longer chain" "$(cli 0 getblockcount)" 6
    ck "wallet usable" "$(bal 0 '*' 0)" 0.00000000
}
# 2: wallet with zero notes at height N, restart, first chain event is a disconnect
scn_zero_note_restart() {
    setup2 -disablesafemode || return
    ta=$(give_t 0 5); stop 0; start 0 "$BIN" $R1 -disablesafemode || return; sync_to 0
    H=$(cli 0 getbestblockhash); cli 0 invalidateblock "$H" >/dev/null
    alive zero_note_restart 0
    cli 0 reconsiderblock "$H" >/dev/null; sync_to 0
    ck "t balance exact" "$(bal 0 '*' 0)" 5.00000000
}
# 3-6: wallet with a Sapling note, restart variants, first chain event is a disconnect
restart_variant() { # <label> <restart args...>
    local l=$1; shift
    base_note || return
    case $l in kill9) kill9 0; start 0 "$BIN" $R1 -disablesafemode ;; *) stop 0; start 0 "$BIN" $R1 -disablesafemode "$@" ;; esac || return
    sync_to 0
    H=$(cli 0 getbestblockhash); cli 0 invalidateblock "$H" >/dev/null
    alive "$l" 0
    ck "$l: note intact after the disconnect" "$(zbal 0 "$ZS")" 4.00000000
    cli 0 invalidateblock "$(cli 0 getbestblockhash)" >/dev/null; cli 0 reconsiderblock "$H" >/dev/null; sync_to 0
    alive "$l after reconsider" 0
    refcheck "$l"
    spend_check "$l" "$ZS" 4.00000000 1.5
}
scn_note_restart() { restart_variant restart; }
scn_note_rescan() { restart_variant rescan -rescan; }
scn_note_zap() { restart_variant zap -zapwallettxes=1; }
scn_note_kill9() { restart_variant kill9; }
# 7: wallet created over an existing chain (wallet.dat removed): no connect was ever seen
scn_wallet_over_chain() {
    setup2 -disablesafemode || return
    cli 1 generate 5 >/dev/null; sync_to 0
    stop 0; rm -f "$SD/node0/regtest/wallet.dat"; start 0 "$BIN" $R1 -disablesafemode || return; sync_to 0
    H=$(cli 0 getbestblockhash); cli 0 invalidateblock "$H" >/dev/null
    alive wallet_over_chain 0
    cli 0 reconsiderblock "$H" >/dev/null; sync_to 0
    # a replaced branch: both nodes drop the last two blocks
    for k in 1 2; do T=$(cli 0 getbestblockhash); cli 0 invalidateblock "$T" >/dev/null; cli 1 invalidateblock "$T" >/dev/null; done
    alive "wallet_over_chain, two blocks" 0
    cli 1 generate 2 >/dev/null; sync_to 0
    ZS=$(cli 0 z_getnewaddress); give_z 0 "$ZS" 3
    cli 1 generate 1 >/dev/null; sync_to 0
    ck "note received after the reorg" "$(zbal 0 "$ZS")" 3.00000000
    T=$(cli 0 getbestblockhash); cli 0 invalidateblock "$T" >/dev/null; cli 0 reconsiderblock "$T" >/dev/null; sync_to 0
    refcheck wallet_over_chain
    spend_check wallet_over_chain "$ZS" 3.00000000 1
}
# 8: invalidate more blocks than the witness cache holds, with a note older than the cache
scn_deep_invalidate() {
    base_note || return
    cli 1 generate 110 >/dev/null; sync_to 0
    first=$(cli 0 getblockhash $(($(cli 0 getblockcount) - 104)))
    cli 0 invalidateblock "$first" >/dev/null
    alive deep_invalidate 0
    ck "deep: chain went back" "$(cli 0 getblockcount)" $(($(cli 1 getblockcount) - 105))
    cli 0 reconsiderblock "$first" >/dev/null; sync_to 0
    alive "deep_invalidate reconsider" 0
    ck "deep: note back" "$(zbal 0 "$ZS")" 4.00000000
    refcheck deep_invalidate
    spend_check deep_invalidate "$ZS" 4.00000000 1.25
}
# 9: reorg driven by the peer: the receiving block and its successors replaced
scn_p2p_reorg() {
    base_note || return
    ta=$(cli 1 getnewaddress); b=$(zbal 0 "$ZS")
    cli 1 generate 2 >/dev/null; sync_to 0
    stop 0; stop 1
    start 1 "$PEER_BIN" -connect=0 || return
    first=$(cli 1 getblockhash $(($(cli 1 getblockcount) - 5)))
    cli 1 invalidateblock "$first" >/dev/null; cli 1 generate 14 >/dev/null  # a fork deeper than 3 blocks is parked until it has twice the work
    start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) -disablesafemode || return; sync_to 0
    alive p2p_reorg 0
    ck "chain is the peer's" "$(cli 0 getbestblockhash)" "$(cli 1 getbestblockhash)"
    # the funding block was replaced; whatever the new chain holds, the wallet must equal a rescan
    refcheck p2p_reorg
    zb=$(zbal 0 "$ZS")
    if [ "$zb" != 0.00000000 ]; then spend_check p2p_reorg "$ZS" "$zb" 0.5; fi
}
# rebuilds: how many witness rebuilds (full rescans) node 0 has logged
rebuilds() { grep -c 'rebuilding witnesses' "$SD/node0/regtest/debug.log"; }
# local_spend <label> <zaddr> <balance-before> <amount>: shielded spend mined by node 0 itself
# (node 1 still holds the chain node 0 invalidated); the anchor must be in node 0's chain
local_spend() {
    local l=$1 zs=$2 b=$3 amt=$4 r
    r=$(zsend 0 "$zs" "[{\"address\":\"$(cli 0 getnewaddress)\",\"amount\":$amt}]")
    case $r in success*) cli 0 generate 1 >/dev/null ;; *) bad "$l: z_sendmany: $r" ;; esac
    ck "$l: shielded spend at the lowered tip mined, exact balance" "$(zbal 0 "$zs")" "$(add "$b" -$amt -$FEE)"
}
# 10: invalidate twice deeper than the cache, with commitments both below and inside the
# removed range (a stale witness would carry an anchor the shortened chain does not hold):
# one rebuild per unwind, a spend at the lowered tip, then a deep unwind whose connect
# phase moves to another branch (the rebuild runs once, at the first connected block)
scn_deeper_invalidate() {
    base_note || return
    mz=$(cli 1 z_getnewaddress)
    give_z 1 "$mz" 1; cli 1 generate 150 >/dev/null; give_z 1 "$mz" 1; cli 1 generate 80 >/dev/null; sync_to 0
    first=$(cli 0 getblockhash $(($(cli 0 getblockcount) - 224)))
    cli 0 invalidateblock "$first" >/dev/null
    alive deeper_invalidate 0
    ck "deeper: one rebuild for a 225-block unwind" "$(rebuilds)" 1
    ck "deeper: note intact" "$(zbal 0 "$ZS")" 4.00000000
    local_spend deeper "$ZS" 4.00000000 1
    cli 0 generate 1 >/dev/null   # branch B: two blocks above the fork
    tipb=$(cli 0 getbestblockhash)
    cli 0 reconsiderblock "$first" >/dev/null; sync_to 0
    alive "deeper reconsider" 0
    cli 0 invalidateblock "$first" >/dev/null
    alive "deeper: unwind onto branch B" 0
    ck "deeper: back on branch B" "$(cli 0 getbestblockhash)" "$tipb"
    ck "deeper: one more rebuild for the unwind and the connect phase" "$(rebuilds)" 2
    ck "deeper: balance on branch B" "$(zbal 0 "$ZS")" "$(add 4 -1 -$FEE)"
    local_spend "deeper, branch B" "$ZS" "$(add 4 -1 -$FEE)" 0.5
}
# 11: Sprout note (the same template, Sprout tree), invalidate deeper than the cache
scn_sprout_deep() {
    NU_ARGS="-nuparams=5ba81b19:230 -nuparams=76b809bb:240"
    setup2 -disablesafemode || return
    SP=$(cli 0 z_getnewaddress sprout); give_z 0 "$SP" 3
    cli 1 generate 130 >/dev/null; sync_to 0
    ck "sprout note received" "$(zbal 0 "$SP")" 3.00000000
    first=$(cli 0 getblockhash $(($(cli 0 getblockcount) - 104)))
    cli 0 invalidateblock "$first" >/dev/null
    alive sprout_deep 0
    ck "sprout: one rebuild" "$(rebuilds)" 1
    ck "sprout: note intact" "$(zbal 0 "$SP")" 3.00000000
    cli 0 reconsiderblock "$first" >/dev/null; sync_to 0
    alive "sprout_deep reconsider" 0
    refcheck sprout_deep
    spend_check sprout_deep "$SP" 3.00000000 1
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
    BASE=$((BASE + 7)); [ $BASE -lt 60000 ] || BASE=20000
    R1="-connect=127.0.0.1:$((BASE + 1))"
}

run_scn 1 "fresh wallet, reorg down to genesis" scn_fork_genesis
run_scn 2 "zero-note wallet, restart, invalidate tip" scn_zero_note_restart
run_scn 3 "note wallet, restart, invalidate tip" scn_note_restart
run_scn 4 "note wallet, -rescan, invalidate tip" scn_note_rescan
run_scn 5 "note wallet, -zapwallettxes=1, invalidate tip" scn_note_zap
run_scn 6 "note wallet, kill -9, invalidate tip" scn_note_kill9
run_scn 7 "wallet created over an existing chain" scn_wallet_over_chain
run_scn 8 "invalidate deeper than the witness cache" scn_deep_invalidate
run_scn 9 "peer-driven reorg replacing the funding block" scn_p2p_reorg
run_scn 10 "invalidate twice the cache deep: one rebuild, spend at the lowered tip, unwind onto another branch" scn_deeper_invalidate
run_scn 11 "Sprout note, invalidate deeper than the cache" scn_sprout_deep

say; say "id|scenario|result|checks"; cat "$RESULTS"
! grep -q '|FAIL|' "$RESULTS"
