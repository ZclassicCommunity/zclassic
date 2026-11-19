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
# 7  (run id 6) every note count against a brute-force recount from z_listunspent,
#    z_listreceivedbyaddress and the mempool, in three wallet states
#
# witness_rebuild_pending = true cannot be sampled over RPC (the rebuild runs inside the
# invalidateblock call that causes it, which holds cs_main); the gtest wallet_health covers it.
#
# usage: wallet_health.sh --bin <dir> --work <dir> [--peer-bin <dir>] [--only 1,2,...] [--base port]
# Output: <work>/results.txt. Exit status 0 when every check passed.
# Needs the Zcash parameters in ~/.zcash-params. Shell only, no Python.
BIN=""; WORK=""; PEER_BIN=""; ONLY=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;;
        --only) ONLY=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--peer-bin DIR] [--only N,N] [--base port]" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$BIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; OBS_LOG=$WORK/obs.txt; : >"$RESULTS"; : >"$OBS_LOG"
iso_base BASE "${PORT_BASE:-}" 112
trap 'stop_all' EXIT
R1="-connect=127.0.0.1:$((BASE + 1))"

# hv <path under .health>: one value of the report on node 0
hv() { cli 0 getwalletinfo | jget "health.$1"; }
# hcsv <pool or ""> <field>...: the fields of health.<pool> (or of health, with ""), comma-joined, from one getwalletinfo
hcsv() {
    local d p=$1 f o="" s=""; shift
    d=$(cli 0 getwalletinfo)
    for f in "$@"; do o="$o$s$(printf '%s' "$d" | jget "health.${p:+$p.}$f")"; s=,; done
    printf '%s\n' "$o"
}
# hadd <pool> <field> <field>: the sum of two integer fields; hge <pool> <a> <b>: true when a >= b.
# Both print "nonnumeric" when a field is missing or not an integer, so a check cannot pass on an absent field.
hadd() {
    local d a b; d=$(cli 0 getwalletinfo)
    a=$(printf '%s' "$d" | jget "health.$1.$2"); b=$(printf '%s' "$d" | jget "health.$1.$3")
    case $a$b in *[!0-9]*|'') echo nonnumeric; return ;; esac
    echo $((a + b))
}
hge() {
    local d a b; d=$(cli 0 getwalletinfo)
    a=$(printf '%s' "$d" | jget "health.$1.$2"); b=$(printf '%s' "$d" | jget "health.$1.$3")
    case $a$b in *[!0-9]*|'') echo nonnumeric; return ;; esac
    [ "$a" -ge "$b" ] && echo true || echo false
}
# ucount <z_listunspent json> <field> <any|zero|pos>: the notes that have <field> (sapling "outindex", sprout "jsindex"),
# all of them, those with 0 confirmations, or those with more; "nonnumeric" when a confirmation count is not an integer
ucount() {
    local n i c=0 conf; n=$(printf '%s' "$1" | jlen) || return 1; i=0
    while [ "$i" -lt "$n" ]; do
        if [ "$(printf '%s' "$1" | jhas "[$i].$2")" = true ]; then
            case $3 in
            any) c=$((c + 1)) ;;
            *) conf=$(printf '%s' "$1" | jget "[$i].confirmations")
               case $conf in ''|*[!0-9]*) echo nonnumeric; return 1 ;; esac
               if [ "$3" = zero ] && [ "$conf" -eq 0 ]; then c=$((c + 1)); fi
               if [ "$3" = pos ] && [ "$conf" -gt 0 ]; then c=$((c + 1)); fi ;;
            esac
        fi
        i=$((i + 1))
    done
    echo "$c"
}
# txst <txid>: the status of a wallet transaction
txst() { local t=0 s; while :; do s=$(cli 0 gettransaction "$1" 2>/dev/null | jget status 2>/dev/null); [ -n "$s" ] && { echo "$s"; return; }; t=$((t + 1)); [ $t -lt 30 ] || { echo none; return; }; sleep 1; done; }
# wait_h <path under .health> <want> [secs]: poll a health value
wait_h() { local t=0; until [ "$(hv "$1")" = "$2" ]; do t=$((t + 1)); [ $t -lt "${3:-30}" ] || return 1; sleep 1; done; }
isolate() { stop 1; start 1 "$PEER_BIN" -connect=0 -listen=0 || return 1; local t=0; while [ "$(cli 0 getconnectioncount)" -gt 0 ] && [ $t -lt 30 ]; do t=$((t + 1)); sleep 1; done; ck "isolated from the miner" "$(cli 0 getconnectioncount)" 0; }
rejoin() { stop 1; start 1 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 0)) || return 1; local t=0; until [ "$(cli 0 getconnectioncount)" -ge 1 ]; do t=$((t + 1)); [ $t -lt 60 ] || break; sleep 1; done; }

oldfields() {
    local d k all=true; d=$(cli 0 getwalletinfo)
    for k in walletversion balance unconfirmed_balance immature_balance txcount keypoololdest keypoolsize paytxfee health; do
        [ "$(printf '%s' "$d" | jhas "$k")" = true ] || all=false
    done
    ck "$1: pre-existing getwalletinfo fields unchanged" "$all" true
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
    ck "funded: sapling unspent/spent" "$(hcsv sapling notes_unspent notes_spent)" "1,0"
    ck "funded: sapling witness ready/missing/stale" "$(hcsv sapling witness_ready witness_missing witness_stale)" "1,0,0"
    ck "funded: sprout unspent/spent" "$(hcsv sprout notes_unspent notes_spent)" "1,0"
    ck "funded: sprout witness ready/missing/stale" "$(hcsv sprout witness_ready witness_missing witness_stale)" "1,0,0"
    ck "funded: no pending sends" "$(hcsv pending_sends in_mempool not_in_mempool expiring_soon expired conflicted)" "0,0,0,0,0"
    ck "funded: no rebuild pending" "$(hv witness_rebuild_pending)" false
    c=$(hv witness_cache_size)
    ck "funded: witness cache size in 1..100" "$([ "$c" -ge 1 ] && [ "$c" -le 100 ] && echo yes)" yes
    ck "funded: checkpoint_height is -1 or at most the tip" "$([ "$(hv checkpoint_height)" -le "$(hv tip_height)" ] && echo yes)" yes
    ck "funded: a received note's transaction is mined" "$(txst "$(cli 0 z_listunspent 1 | jget '[0].txid')")" mined
}

scn_pending() {
    fund || return
    ZB=$(cli 1 z_getnewaddress sapling)
    r=$(zsend 0 "$ZS" "[{\"address\":\"$ZB\",\"amount\":1}]" 1 "$FEE")
    case $r in success*) tx=${r#success } ;; *) bad "send: $r"; return ;; esac
    wait_mempool 1 "$tx"; txst "$tx" >/dev/null
    ck "pending: status" "$(txst "$tx")" pending
    ck "pending: in_mempool" "$(hcsv pending_sends in_mempool not_in_mempool expired conflicted)" "1,0,0,0"
    ck "pending: sapling spent 1, unspent 1 (unconfirmed change)" "$(hcsv sapling notes_spent notes_unspent unconfirmed)" "1,1,1"
    mine 1
    ck "mined: status" "$(txst "$tx")" mined
    ck "mined: nothing pending" "$(hcsv pending_sends in_mempool not_in_mempool expiring_soon expired conflicted)" "0,0,0,0,0"
    ck "mined: sapling spent 1, unspent 1 ready" "$(hcsv sapling notes_spent notes_unspent witness_ready unconfirmed)" "1,1,1,0"
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
    ck "expire: expiring_soon counted" "$(hcsv pending_sends in_mempool expiring_soon expired)" "1,1,0"
    isolate; sleep 2
    cli 1 generate 5 >/dev/null; rejoin; sync_to 0
    ck "expire: the miner never saw it" "$(cli 1 getrawmempool | grep -c "$tx")" 0
    ck "expire: status expired" "$(txst "$tx")" expired
    ck "expire: counted as expired, not in the mempool" "$(hcsv pending_sends in_mempool not_in_mempool expired conflicted)" "0,0,1,0"
    ck "expire: inputs spendable again (balance as before the send)" "$(zbal 0 "$ZS")" "$b0"
    ck "expire: the original note is unspent again, the expired send's change note is dead" "$(hcsv sapling notes_unspent unmined_dead notes_spent)" "1,1,0"
}

scn_deep() {
    setup2 -disablesafemode || return
    ZS=$(cli 0 z_getnewaddress sapling); give_z 0 "$ZS" 4
    cli 1 generate 110 >/dev/null; sync_to 0
    ck "deep: cache is full before the unwind" "$(hv witness_cache_size)" 100
    ck "deep: note ready" "$(hcsv sapling witness_ready witness_stale witness_missing)" "1,0,0"
    first=$(cli 0 getblockhash $(($(cli 0 getblockcount) - 104)))
    cli 0 invalidateblock "$first" >/dev/null 2>&1
    low=$(cli 0 getblockcount)
    ck "deep: tip_height is the lowered tip" "$(hv tip_height)" "$low"
    ck "deep: rebuild no longer pending" "$(hv witness_rebuild_pending)" false
    ck "deep: note has a witness at the lowered tip" "$(hcsv sapling witness_ready witness_stale witness_missing)" "1,0,0"
    ck "deep: balance intact" "$(zbal 0 "$ZS")" 4.00000000
    cli 0 reconsiderblock "$first" >/dev/null 2>&1; sync_to 0
    ck "deep: after reconsiderblock the note is ready at the tip" "$(hcsv sapling witness_ready witness_stale witness_missing) $(hv tip_height)" "1,0,0 $(cli 1 getblockcount)"
}

scn_restart() {
    fund || return
    mine 2
    stop 0; start 0 "$BIN" $R1 -disablesafemode || return; sync_to 0
    ck "restart: checkpoint_height equals the tip after a clean stop" "$(hv checkpoint_height)" "$(cli 0 getblockcount)"
    ck "restart: counts" "$(hcsv "" sapling.witness_ready sapling.notes_unspent sprout.witness_ready sprout.notes_unspent)" "1,1,1,1"
    ck "restart: no rebuild pending, nothing pending" "$(hv witness_rebuild_pending) $(hcsv pending_sends in_mempool not_in_mempool expired)" "false 0,0,0"
    oldfields restart
    mine 1
    ck "restart: new block, witness ready at the new tip" "$(hv sapling.witness_ready) $(hv tip_height)" "1 $(cli 1 getblockcount)"
}

# recount <label>: every note count of the report against what z_listunspent, z_listreceivedbyaddress and the
# mempool say independently (sapling notes have "outindex", sprout notes "jsindex")
recount() {
    local l=$1 u rcv_s rcv_p a mp mine_mp t
    u=$(cli 0 z_listunspent 0 9999999)
    rcv_s=0; rcv_p=0
    for a in $(cli 0 z_listaddresses | jpick); do
        case $a in zs*|zregtestsapling*|ztestsapling*) rcv_s=$((rcv_s + $(cli 0 z_listreceivedbyaddress "$a" 0 | jlen))) ;;
                   *) rcv_p=$((rcv_p + $(cli 0 z_listreceivedbyaddress "$a" 0 | jlen))) ;; esac
    done
    for pool in sapling:outindex sprout:jsindex; do
        p=${pool%%:*}; f=${pool#*:}
        ck "$l: $p notes_unspent = z_listunspent 0" "$(hv "$p.notes_unspent")" "$(ucount "$u" "$f" any)"
        ck "$l: $p unconfirmed = z_listunspent at depth 0" "$(hv "$p.unconfirmed")" "$(ucount "$u" "$f" zero)"
        ck "$l: $p witness_ready = confirmed unspent notes (all witnesses at the tip)" "$(hv "$p.witness_ready")" "$(ucount "$u" "$f" pos)"
        ck "$l: $p witness_missing + witness_stale = 0" "$(hadd "$p" witness_missing witness_stale)" 0
        [ "$p" = sapling ] && t=$rcv_s || t=$rcv_p
        ck "$l: $p notes_spent + notes_unspent = every note received (z_listreceivedbyaddress 0 skips dead transactions)" "$(hadd "$p" notes_spent notes_unspent)" "$t"
        ck "$l: $p unmined_dead = 0 (no dead transaction in this scenario)" "$(hv "$p.unmined_dead")" 0
        ck "$l: $p witnesses_held_unspent >= witness_ready" "$(hge "$p" witnesses_held_unspent witness_ready)" true
    done
    mine_mp=0
    for t in $(cli 0 getrawmempool | jpick); do cli 0 gettransaction "$t" >/dev/null 2>&1 && mine_mp=$((mine_mp + 1)); done
    ck "$l: pending_sends.in_mempool = wallet transactions in the mempool" "$(hv pending_sends.in_mempool)" "$mine_mp"
    ck "$l: tip_height = getblockcount" "$(hv tip_height)" "$(cli 0 getblockcount)"
}

scn_recount() {
    fund || return
    give_z 0 "$ZS" 1.5; give_z 0 "$ZS" 0.75
    ZB=$(cli 1 z_getnewaddress sapling)
    recount "three sapling notes, one sprout"
    zconfirm 0 "$ZS" "[{\"address\":\"$ZB\",\"amount\":2}]" 1 "$FEE" >/dev/null
    r=$(zsend 0 "$ZS" "[{\"address\":\"$ZB\",\"amount\":0.5}]" 1 "$FEE")
    case $r in success*) wait_mempool 1 "${r#success }"; txst "${r#success }" >/dev/null ;; *) bad "recount: send: $r"; return ;; esac
    recount "one send mined, one pending"
    ck "one pending send is counted" "$(hv pending_sends.in_mempool)" 1
    mine 1
    recount "both mined"
    t0=$(now); i=0; while [ $i -lt 20 ]; do cli 0 getwalletinfo >/dev/null; i=$((i + 1)); done
    obs "getwalletinfo_20_calls_s" "$(elapsed "$t0")"
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
run_scn 6 "every count against a brute-force recount" scn_recount

say; say "id|scenario|result|checks"; cat "$RESULTS"
! grep -q "|FAIL|" "$RESULTS"
