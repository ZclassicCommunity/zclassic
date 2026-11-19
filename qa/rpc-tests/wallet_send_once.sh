#!/bin/sh
# z_sendmany with an idempotency_key: the send journal ("send once").
#
# scenarios (ids 1-9 in the run list at the end):
# 1  same key, same request, twice: one operation, one transaction, one debit, the same txid; a
#    third call after the block returns it again; the key never reaches wallet.dat or the log
# 2  same key, different request: "idempotency key reused with different parameters", nothing sent;
#    invalid keys are refused
# 3  restart between the calls: the same operation id, and z_getoperationstatus / z_getoperationresult
#    answer for it from the journal
# 4  a crash (-testcrashpoint) after STARTED, after the BUILT record, after BUILT is complete (the
#    transaction is in the wallet), and after the broadcast: restart, retry with the same key and
#    request; exactly one transaction is mined, balances equal the uncrashed reference
# 5  an unmined send that expires: the key is released and the retry sends
# 6  without a key nothing changes: the same RPC output shapes as the parent build (--ref-bin)
# 7  older binaries (--old-bin, --ref-bin) open a wallet.dat that holds journal records, report the same
#    balances, and the current binary still reads the journal afterwards
# 10 the broadcast of a built transaction is refused: never reported as failed, retried once accepted
# 11 a retry after the wallet was locked again returns the stored operation id
#
# usage: wallet_send_once.sh --bin <dir> --work <dir> [--peer-bin <dir>] [--ref-bin <dir>] [--old-bin <dir>]
#                            [--only 1,2,...] [--base port]
# Output: <work>/results.txt. Exit status 0 when every check passed.
# Needs the Zcash parameters in ~/.zcash-params. Shell only, no Python.
BIN=""; WORK=""; PEER_BIN=""; REF_BIN=""; OLD_BIN=""; ONLY=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;;
        --ref-bin) REF_BIN=$2; shift 2 ;; --old-bin) OLD_BIN=$2; shift 2 ;;
        --only) ONLY=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--peer-bin DIR] [--ref-bin DIR] [--old-bin DIR] [--only N,N] [--base port]" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$BIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; OBS_LOG=$WORK/obs.txt; : >"$RESULTS"; : >"$OBS_LOG"
iso_base BASE "${PORT_BASE:-}" 112
trap 'stop_all' EXIT
R1="-connect=127.0.0.1:$((BASE + 1))"
KEY="send-once.test:key-1"
EXTRA="-txexpirydelta=5 -disablesafemode"
# SENDONCE_EXPIRY_MARGIN: blocks past the expiry height before a key is released (more than MAX_REORG_LENGTH)
MARGIN=100

# rec <amount>: one recipient, the miner's sapling address
rec() { printf '[{"address":"%s","amount":%s}]' "$ZB" "$1"; }
# jsend <amount> <key>: z_sendmany from node 0 with a key; prints the operation id or the error
jsend() { cli 0 z_sendmany "$ZS" "$(rec "$1")" 1 "$FEE" "$2" 2>&1; }
jlist() { cli 0 z_listsendjournal; }
jstates() { jlist | jjoin state; }
jcount() { jlist | jlen; }
# jfinal: the shape of a z_getoperationresult answer: [keys of the entry, keys of its result, status]
jfinal() { local d; d=$(cat); printf '[%s,%s,%s]\n' "$(printf '%s' "$d" | jkeys '[0]')" "$(printf '%s' "$d" | jkeys '[0].result')" "$(printf '%s' "$d" | jraw '[0].status')"; }
zb_count() { cli 1 z_listreceivedbyaddress "$ZB" 1 | jlen; }
zb_total() { cli 1 z_listreceivedbyaddress "$ZB" 1 | jsatlist | awk '{ if ($1 !~ /^-?[0-9]+$/) bad = 1; s += $1 } END { if (bad) print "NaN"; else printf "%.8f", s / 100000000 }'; }
wait_dead() {
    local pid t=0; pid=$(cat "$SD/node$1/pid")
    while kill -0 "$pid" 2>/dev/null; do t=$((t + 1)); [ $t -lt 120 ] || return 1; sleep 0.5; done
    rm -f "$SD/node$1/regtest/.lock"
}
isolate() { stop 1; start 1 "$PEER_BIN" -connect=0 -listen=0 || return 1; local t=0; while [ "$(cli 0 getconnectioncount)" -gt 0 ] && [ $t -lt 30 ]; do t=$((t + 1)); sleep 1; done; ck "isolated from the miner" "$(cli 0 getconnectioncount)" 0; }
rejoin() { stop 1; start 1 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 0)) || return 1; local t=0; until [ "$(cli 0 getconnectioncount)" -ge 1 ]; do t=$((t + 1)); [ $t -lt 60 ] || break; sleep 1; done; }

# fund [extra node 0 args]: node 0 holds 4 on a sapling address, node 1 has a sapling address to pay
fund() {
    setup2 $EXTRA "$@" || return 1
    ZS=$(cli 0 z_getnewaddress sapling); give_z 0 "$ZS" 4
    ZB=$(cli 1 z_getnewaddress sapling)
    ck "funded" "$(zbal 0 "$ZS")" 4.00000000
}
final_checks() { # <label>: exactly one transaction paid ZB, one debit on ZS
    ck "$1: ZS debited exactly once" "$(zbal 0 "$ZS")" "$(add 4 -1 -$FEE)"
    ck "$1: ZB received exactly one note" "$(zb_count)" 1
    ck "$1: ZB received exactly 1" "$(zb_total)" 1.00000000
}

scn_basic() {
    fund || return
    op1=$(jsend 1 "$KEY"); r1=$(wait_op 0 "$op1")
    case $r1 in success*) tx1=${r1#success } ;; *) bad "first send: $r1"; return ;; esac
    op2=$(jsend 1 "$KEY")
    ck "same key, same request: same operation id" "$op2" "$op1"
    ck "the operation answers with the same txid" "$(cli 0 z_getoperationstatus "[\"$op2\"]" | jget '[0].result.txid')" "$tx1"
    ck "one operation in the queue" "$(cli 0 z_listoperationids | jlen)" 1
    wait_mempool 1 "$tx1"; mine 1
    op3=$(jsend 1 "$KEY")
    ck "after the block: still the same operation id" "$op3" "$op1"
    mine 1
    final_checks "one send"
    ck "journal: one record, committed" "$(jstates)" committed
    ck "journal entry: txid" "$(jlist | jget '[0].txid')" "$tx1"
    ck "journal entry: opid" "$(jlist | jget '[0].opid')" "$op1"
    ck "journal listing does not contain the key" "$(jlist | grep -c "$KEY")" 0
    ck "journal listing: key hash is 16 hex characters" "$(jlist | jget '[0].keyhash' | grep -Ec '^[0-9a-f]{16}$')" 1

    # 2: a different request under the same key
    ckerr "same key, different amount" "idempotency key reused with different parameters" 0 z_sendmany "$ZS" "$(rec 2)" 1 "$FEE" "$KEY"
    ckerr "same key, different fee" "idempotency key reused with different parameters" 0 z_sendmany "$ZS" "$(rec 1)" 1 0.0002 "$KEY"
    ckerr "same key, different minconf" "idempotency key reused with different parameters" 0 z_sendmany "$ZS" "$(rec 1)" 2 "$FEE" "$KEY"
    ckerr "same key, different recipient" "idempotency key reused with different parameters" 0 z_sendmany "$ZS" "[{\"address\":\"$(cli 1 z_getnewaddress sapling)\",\"amount\":1}]" 1 "$FEE" "$KEY"
    ckerr "key with a space" "idempotency_key must be" 0 z_sendmany "$ZS" "$(rec 1)" 1 "$FEE" "bad key"
    ckerr "key with a slash" "idempotency_key must be" 0 z_sendmany "$ZS" "$(rec 1)" 1 "$FEE" "a/b"
    ckerr "empty key" "idempotency_key must be" 0 z_sendmany "$ZS" "$(rec 1)" 1 "$FEE" ""
    ckerr "129 character key" "idempotency_key must be" 0 z_sendmany "$ZS" "$(rec 1)" 1 "$FEE" "$(printf 'k%.0s' $(seq 129))"
    ckerr "six parameters" "z_sendmany" 0 z_sendmany "$ZS" "$(rec 1)" 1 "$FEE" "$KEY" extra
    mine 1
    final_checks "after the refused calls"
    ck "journal still one record" "$(jcount)" 1

    # 3: restart between the calls
    stop 0; start 0 "$BIN" $R1 $EXTRA || return; sync_to 0
    ck "restart: queue is empty" "$(cli 0 z_listoperationids | jlen)" 0
    ck "restart: the same operation id" "$(jsend 1 "$KEY")" "$op1"
    ck "restart: z_getoperationstatus answers from the journal" "$(cli 0 z_getoperationstatus "[\"$op1\"]" | jarr '[0].status' '[0].result.txid')" "[\"success\",\"$tx1\"]"
    ck "restart: z_getoperationresult answers from the journal" "$(cli 0 z_getoperationresult "[\"$op1\"]" | jarr '[0].status' '[0].result.txid')" "[\"success\",\"$tx1\"]"
    ck "restart: and again (results are not consumed)" "$(cli 0 z_getoperationresult "[\"$op1\"]" | jget '[0].result.txid')" "$tx1"
    ckerr "restart: different request still refused" "idempotency key reused with different parameters" 0 z_sendmany "$ZS" "$(rec 3)" 1 "$FEE" "$KEY"
    ck "restart: an unknown operation id is not invented" "$(cli 0 z_getoperationstatus '["opid-unknown"]' | jlen)" 0
    mine 1
    final_checks "after restart"
    stop 0
    ck "the key is not in wallet.dat" "$(grep -c -a "$KEY" "$SD/node0/regtest/wallet.dat")" 0
    ck "the key is not in debug.log" "$(grep -c -a "$KEY" "$SD/node0/regtest/debug.log")" 0
    ck "the key is not in the shell log of the node" "$(grep -c -a "$KEY" "$SD/node0/stdout.log")" 0
    start 0 "$BIN" $R1 $EXTRA || return; sync_to 0
    ck "second restart: journal intact" "$(jstates)" committed
}

# crash <label> <crashpoint> <mode>
crash_case() {
    local l=$1 cp=$2 mode=$3 pid exp t
    fund -testcrashpoint=$cp || return
    ref=$(add 4 -1 -$FEE)
    op=$(jsend 1 "$KEY")
    case $op in opid-*) ;; *) [ "$mode" = started ] || bad "$l: z_sendmany said [$op]" ;; esac
    wait_dead 0 || { bad "$l: the node did not die at $cp"; return; }
    ck "$l: the node died at the crash point" "$(grep -c "testcrashpoint: exiting at $cp" "$SD/node0/stdout.log")" 1
    start 0 "$BIN" $R1 $EXTRA || return; sync_to 0
    case $mode in
    started)
        ck "$l: STARTED without an operation is released at start" "$(jcount)" 0
        ck "$l: nothing was sent" "$(cli 1 getrawmempool | jlen) $(zbal 0 "$ZS")" "0 4.00000000"
        r=$(jsend 1 "$KEY"); ck "$l: retry returns an operation id" "$(echo "$r" | grep -c '^opid-')" 1
        res=$(wait_op 0 "$r"); ck "$l: retry sends" "$(echo "$res" | cut -d" " -f1)" success
        wait_mempool 1 "${res#success }"
        mine 1 ;;
    builtrecord)
        ck "$l: BUILT record on disk, outcome unknown" "$(jstates)" outcome_unknown
        txid=$(jlist | jget '[0].txid'); expiry=$(jlist | jget '[0].expiryheight')
        ck "$l: the transaction was never sent" "$(cli 0 getrawmempool | grep -c "$txid") $(cli 1 getrawmempool | grep -c "$txid")" "0 0"
        r=$(jsend 1 "$KEY")
        ck "$l: retry while unknown returns the stored operation id" "$r" "$op"
        ck "$l: no second transaction was built" "$(cli 0 getrawmempool | jlen) $(jcount)" "0 1"
        ck "$l: the stored operation is undecided" "$(cli 0 z_getoperationstatus "[\"$op\"]" | jcat '[0].status' '[0].journal')" "executing outcome_unknown"
        mine 3
        ck "$l: still unknown 3 blocks on" "$(jstates)" outcome_unknown
        ck "$l: balance untouched" "$(zbal 0 "$ZS")" 4.00000000
        h=$(cli 0 getblockcount); n=$((expiry + MARGIN - h)); [ $n -lt 1 ] || mine $n
        ck "$l: still unknown at expiry + margin (a reorg could still mine it)" "$(jstates)" outcome_unknown
        r=$(jsend 1 "$KEY")
        ck "$l: retry at expiry + margin returns the stored operation id" "$r" "$op"
        mine 1
        ck "$l: expired past expiry + margin" "$(jstates)" expired
        r=$(jsend 1 "$KEY")
        ck "$l: the key was released: a new operation" "$([ "$r" != "$op" ] && echo "$r" | grep -c '^opid-')" 1
        res=$(wait_op 0 "$r"); ck "$l: the retry sends" "$(echo "$res" | cut -d" " -f1)" success
        wait_mempool 1 "${res#success }"
        mine 1 ;;
    built|broadcast)
        txid=$(jlist | jget '[0].txid')
        ck "$l: the transaction is in the wallet" "$(cli 0 gettransaction "$txid" | jget txid)" "$txid"
        ck "$l: after the start the journal says committed (the transaction is in the mempool)" "$(jstates)" committed
        ck "$l: in the node's mempool" "$(cli 0 getrawmempool | grep -c "$txid")" 1
        cli 0 resendwallettransactions >/dev/null
        wait_mempool 1 "$txid"
        r=$(jsend 1 "$KEY")
        ck "$l: retry returns the stored operation id" "$r" "$op"
        ck "$l: the stored operation is a success with the txid" "$(cli 0 z_getoperationstatus "[\"$op\"]" | jcat '[0].status' '[0].result.txid')" "success $txid"
        mine 1 ;;
    esac
    final_checks "$l"
    ck "$l: one journal record" "$(jcount)" 1
    mine 1
    ck "$l: one more call after the block: stored" "$(jsend 1 "$KEY" | grep -c '^opid-')" 1
    final_checks "$l (final)"
}
scn_crash_started() { crash_case "crash after STARTED" sendonce-after-started started; }
scn_crash_builtrecord() { crash_case "crash after the BUILT record" sendonce-after-built-record builtrecord; }
scn_crash_built() { crash_case "crash after BUILT, before the broadcast" sendonce-after-built built; }
scn_crash_broadcast() { crash_case "crash after the broadcast, before COMMITTED" sendonce-after-broadcast broadcast; }

scn_expire() {
    fund || return
    isolate || return
    op=$(jsend 1 "$KEY"); r=$(wait_op 0 "$op")
    case $r in success*) tx=${r#success } ;; *) bad "send: $r"; return ;; esac
    ck "unmined: committed, in node 0's mempool only" "$(jstates) $(cli 0 getrawmempool | grep -c "$tx") $(cli 1 getrawmempool | grep -c "$tx")" "committed 1 0"
    exp=$(jlist | jget '[0].expiryheight')
    cli 1 generate $((exp + MARGIN + 2 - $(cli 1 getblockcount))) >/dev/null
    rejoin; sync_to 0
    ck "unmined: dropped from the mempool at expiry" "$(cli 0 getrawmempool | grep -c "$tx")" 0
    ck "unmined: the journal released the key (expired)" "$(jstates)" expired
    ck "unmined: the in-memory operation still says success (the queue does not know the tx expired)" "$(cli 0 z_getoperationstatus "[\"$op\"]" | jget '[0].status')" success
    stop 0; start 0 "$BIN" $R1 $EXTRA || return; sync_to 0
    ck "unmined: after a restart the journal answers: failed, key released" "$(cli 0 z_getoperationstatus "[\"$op\"]" | jget '[0].status') $(jstates)" "failed expired"
    ck "unmined: balance is back" "$(zbal 0 "$ZS")" 4.00000000
    ck "unmined: nothing reached ZB" "$(zb_count)" 0
    r=$(jsend 1 "$KEY")
    ck "unmined: the retry is a new operation" "$([ "$r" != "$op" ] && echo "$r" | grep -c '^opid-')" 1
    ck "unmined: and it sends" "$(wait_op 0 "$r" | cut -d' ' -f1)" success
    mine 1
    final_checks "after the retry"
    ck "unmined: one record, committed" "$(jstates)" committed
}

# nokey <label> <bindir>: summary of a keyless send, for comparison between binaries
nokey() {
    setup2 $EXTRA || return 1
    ZS=$(cli 0 z_getnewaddress sapling); give_z 0 "$ZS" 4
    ZB=$(cli 1 z_getnewaddress sapling)
    op=$(cli 0 z_sendmany "$ZS" "$(rec 1)" 1 "$FEE")
    st=$(cli 0 z_getoperationstatus "[\"$op\"]" | jkeys '[0]')
    r=$(wait_op 0 "$op")
    wait_mempool 1 "${r#success }"; mine 1
    fin=$(cli 0 z_getoperationresult "[\"$op\"]" | jfinal)
    ck "keyless: opid shape" "$(echo "$op" | grep -Ec '^opid-[0-9a-f-]{36}$')" 1
    {
        echo "status-keys $st"
        echo "result $fin"
        echo "balance $(zbal 0 "$ZS")"
        echo "zb $(zb_total)"
        echo "listoperationids-after-result $(cli 0 z_listoperationids | jlen)"
        echo "empty-amounts $(errtxt 0 z_sendmany "$ZS" "[]")"
        echo "bad-address $(errtxt 0 z_sendmany "$ZS" "[{\"address\":\"nonsense\",\"amount\":1}]")"
    } >"$WORK/nokey.$1"
}
scn_nokey_new() {
    nokey new || return
    ck "keyless: nothing journaled" "$(jcount)" 0
    ck "keyless: balance exactly as before the journal" "$(zbal 0 "$ZS")" "$(add 4 -1 -$FEE)"
}
scn_nokey_ref() {
    [ -n "$REF_BIN" ] || { say "  (no --ref-bin: skipped)"; pass "skipped without --ref-bin"; return; }
    BIN_SAVE=$BIN; BIN=$REF_BIN
    nokey ref || { BIN=$BIN_SAVE; return; }
    BIN=$BIN_SAVE
    if [ -f "$WORK/nokey.new" ]; then
        # the amounts and ids differ between runs: compare the shapes, the balances and the error texts
        if diff -u "$WORK/nokey.ref" "$WORK/nokey.new" >"$WORK/nokey.diff" 2>&1; then pass "keyless output identical to the parent build"; else bad "keyless output differs: $(tr '\n' ' ' <"$WORK/nokey.diff" | cut -c1-300)"; fi
    else
        bad "no keyless run of the current build to compare with (run scenario 6 first)"
    fi
}

scn_old() {
    # a wallet.dat with a committed record and a BUILT one, as the current binary leaves it
    fund -testcrashpoint=sendonce-after-built-record:2 || return
    op=$(jsend 1 "$KEY"); r=$(wait_op 0 "$op"); case $r in success*) ;; *) bad "send A: $r"; return ;; esac
    mine 1
    ZC=$(cli 1 z_getnewaddress sapling)
    cli 0 z_sendmany "$ZS" "[{\"address\":\"$ZC\",\"amount\":0.5}]" 1 "$FEE" "second-key" >/dev/null 2>&1
    wait_dead 0 || { bad "node 0 did not die at the second crash point"; return; }
    start 0 "$BIN" $R1 $EXTRA || return; sync_to 0
    states=$(jstates); ck "journal holds a committed and an unresolved record" "$states" "committed,outcome_unknown"
    zt=$(cli 0 z_gettotalbalance 1 | jarr transparent private); hold=$(cli 0 getblockcount)
    keys=$(jlist | jpluck keyhash)
    stop 0; stop 1
    for b in ${OLD_BIN:+"old:$OLD_BIN"} ${REF_BIN:+"ref:$REF_BIN"}; do
        tag=${b%%:*}; dir=${b#*:}
        rm -rf "$SD/node0.keep" "$SD/node0.$tag"; cp -a "$SD/node0" "$SD/node0.keep"
        start 0 "$dir" -connect=0 $EXTRA || { bad "$tag: the older binary does not start on a wallet.dat with journal records"; continue; }
        ck "$tag: opens the wallet, same height" "$(cli 0 getblockcount)" "$hold"
        ck "$tag: same balances" "$(cli 0 z_gettotalbalance 1 | jarr transparent private)" "$zt"
        ck "$tag: getwalletinfo works" "$(cli 0 getwalletinfo | jhas balance)" true
        ck "$tag: does not know z_listsendjournal" "$(errtxt 0 z_listsendjournal | grep -ci 'method not found')" 1
        ck "$tag: no complaint about the wallet in its log" "$(grep -ci 'error reading wallet\|wallet.dat corrupt\|noncritical\|Error loading' "$SD/node0/regtest/debug.log")" 0
        stop 0
        # the current binary on the wallet.dat the older one has just written
        start 0 "$BIN" -connect=0 $EXTRA || { bad "$tag: the current binary does not start after the older one"; continue; }
        ck "$tag: current binary still reads the journal" "$(jlist | jpluck keyhash)" "$keys"
        ck "$tag: ... with the same states" "$(jstates)" "$states"
        ck "$tag: ... and the same balances" "$(cli 0 z_gettotalbalance 1 | jarr transparent private)" "$zt"
        stop 0
        rm -rf "$SD/node0"; mv "$SD/node0.keep" "$SD/node0"
    done
}

# the broadcast of a built transaction is refused (an absurd fee against a tiny -minrelaytxfee): the
# operation must not read "failed" (the wallet holds the transaction and offers it again), a retry
# builds nothing, and once the node accepts it the one transaction is mined
scn_refused() {
    local op r t s txid
    fund -minrelaytxfee=0.00000001 || return
    op=$(cli 0 z_sendmany "$ZS" "$(rec 1)" 1 0.001 "$KEY" 2>&1)
    case $op in opid-*) ;; *) bad "refused: z_sendmany said [$op]"; return ;; esac
    t=0; until [ "$(jlist | jgetd '[0].error_code' "")" != "" ]; do t=$((t + 1)); [ $t -lt 600 ] || { bad "refused: no stored broadcast error"; return; }; sleep 1; done
    txid=$(jlist | jget '[0].txid')
    ck "refused: the broadcast error is stored, the record stays built" "$(jlist | jcat '[0].stored_state' '[0].state')" "built outcome_unknown"
    ck "refused: the error is the absurd fee" "$(jlist | jget '[0].error' | grep -ci 'absurd')" 1
    s=$(cli 0 z_getoperationstatus "[\"$op\"]" | jcat '[0].status' '[0].journal' '[0].last_error.message')
    ck "refused: the live operation is not reported as failed" "$(echo "$s" | cut -d' ' -f1,2)" "executing outcome_unknown"
    ck "refused: z_getoperationresult does not hand out a failure" "$(cli 0 z_getoperationresult "[\"$op\"]" | jlen)" 0
    ck "refused: the operation is still in the queue" "$(cli 0 z_listoperationids | jlen)" 1
    ck "refused: the built transaction is in the wallet, in no mempool" "$(cli 0 gettransaction "$txid" | jget txid) $(cli 0 getrawmempool | grep -c "$txid")" "$txid 0"
    ck "refused: retry returns the stored operation id" "$(cli 0 z_sendmany "$ZS" "$(rec 1)" 1 0.001 "$KEY" 2>&1)" "$op"
    ck "refused: nothing new was built" "$(jcount) $(cli 0 getrawmempool | jlen)" "1 0"
    ck "refused: balance untouched" "$(zbal 0 "$ZS")" 4.00000000
    stop 0; start 0 "$BIN" $R1 $EXTRA || return; sync_to 0
    ck "refused: after a restart with the normal relay fee the wallet offers it again: committed" "$(jstates) $(cli 0 getrawmempool | grep -c "$txid")" "committed 1"
    ck "refused: the operation now answers success with the txid" "$(cli 0 z_getoperationstatus "[\"$op\"]" | jcat '[0].status' '[0].result.txid')" "success $txid"
    cli 0 resendwallettransactions >/dev/null; wait_mempool 1 "$txid"; mine 1
    ck "refused: ZS debited exactly once" "$(zbal 0 "$ZS")" "$(add 4 -1 -0.001)"
    ck "refused: ZB received exactly one note of 1" "$(zb_count) $(zb_total)" "1 1.00000000"
    ck "refused: retry after the block: stored" "$(cli 0 z_sendmany "$ZS" "$(rec 1)" 1 0.001 "$KEY" 2>&1)" "$op"
}

# a retry after the wallet was locked again gets its operation id back, not "wallet locked"
scn_locked() {
    local op r tx
    fund || return
    cli 0 encryptwallet "pw1" >/dev/null 2>&1
    wait_dead 0 || { bad "locked: encryptwallet did not stop the node"; return; }
    start 0 "$BIN" $R1 $EXTRA || return; sync_to 0
    ckerr "locked: a keyed send needs the passphrase" "assphrase" 0 z_sendmany "$ZS" "$(rec 1)" 1 "$FEE" "$KEY"
    ck "locked: the refused call left no record" "$(jcount)" 0
    cli 0 walletpassphrase pw1 600 >/dev/null
    op=$(jsend 1 "$KEY"); r=$(wait_op 0 "$op")
    case $r in success*) tx=${r#success } ;; *) bad "locked: send: $r"; return ;; esac
    cli 0 walletlock >/dev/null
    ck "locked: retry with the same key returns the stored operation id" "$(jsend 1 "$KEY")" "$op"
    ckerr "locked: a new key still needs the passphrase" "assphrase" 0 z_sendmany "$ZS" "$(rec 1)" 1 "$FEE" "another-key"
    ck "locked: one record" "$(jcount)" 1
    stop 0; start 0 "$BIN" $R1 $EXTRA || return; sync_to 0
    ck "locked: after a restart, still locked, the same operation id" "$(jsend 1 "$KEY")" "$op"
    wait_mempool 1 "$tx"; mine 1   # the miner may not have the transaction yet: it is relayed with a delay
    final_checks "locked"
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

run_scn 1 "same key twice, different request, restart" scn_basic
run_scn 2 "crash after STARTED" scn_crash_started
run_scn 3 "crash after the BUILT record" scn_crash_builtrecord
run_scn 4 "crash after BUILT, before the broadcast" scn_crash_built
run_scn 5 "crash after the broadcast, before COMMITTED" scn_crash_broadcast
run_scn 6 "unmined send expires, key released" scn_expire
run_scn 7 "no key: current build" scn_nokey_new
run_scn 8 "no key: parent build, compared" scn_nokey_ref
run_scn 9 "older binaries and a wallet.dat with journal records" scn_old
run_scn 10 "broadcast refused after BUILT" scn_refused
run_scn 11 "retry after the wallet was locked" scn_locked

say; say "id|scenario|result|checks"; cat "$RESULTS"
! grep -q "|FAIL|" "$RESULTS"
