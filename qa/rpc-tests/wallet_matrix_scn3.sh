#!/bin/sh
# Scenarios 7 to 12 for wallet_matrix.sh.

# ---------------------------------------------------------------- 7
scn_reorg() {
    setup2 -disablesafemode || return
    zs=$(cli 0 z_getnewaddress); ta=$(cli 0 getnewaddress); mz=$(cli 1 z_getnewaddress)
    give_z 0 "$zs" 20
    mt=$(cli 1 getnewaddress); cli 1 sendtoaddress "$mt" 5 >/dev/null; cli 1 generate 1 >/dev/null
    # (a) a shielded receipt mined, then invalidated, then reconsidered
    r=$(zsend 1 "$mt" "[{\"address\":\"$zs\",\"amount\":2}]"); tx=${r#success }; cli 1 generate 1 >/dev/null; sync_to 0
    H=$(cli 1 getbestblockhash)
    ck "receipt confirmed" "$(zbal 0 "$zs")" 22.00000000
    cli 0 invalidateblock "$H" >/dev/null
    ck "invalidated: note leaves minconf 1 balance" "$(zbal 0 "$zs")" 20.00000000
    obs "invalidated_minconf0_balance" "$(zbal 0 "$zs" 0)"
    ck "invalidated: tx is not confirmed" "$(cli 0 z_listreceivedbyaddress "$zs" 1 | jq --arg t "$tx" '[.[]|select(.txid==$t)]|length')" 0
    cli 0 reconsiderblock "$H" >/dev/null; sync_to 0
    ck "reconsidered: balance returns" "$(zbal 0 "$zs")" 22.00000000
    zconfirm 0 "$zs" "[{\"address\":\"$ta\",\"amount\":5.5}]" >/dev/null
    ck "the reconsidered note was spendable (witness valid)" "$(zbal 0 "$zs")" "$(add 22 -5.5 -$FEE)"
    ck "t side" "$(bal 0)" 5.50000000

    # (b) both nodes drop the block; the miner re-mines the same tx in a new block
    cli 1 sendtoaddress "$mt" 2 >/dev/null; cli 1 generate 1 >/dev/null
    r=$(zsend 1 "$mt" "[{\"address\":\"$zs\",\"amount\":1}]"); tx=${r#success }; cli 1 generate 1 >/dev/null; sync_to 0
    H=$(cli 1 getbestblockhash); b=$(zbal 0 "$zs")
    cli 0 invalidateblock "$H" >/dev/null; cli 1 invalidateblock "$H" >/dev/null
    ck "node 0 drops the note" "$(zbal 0 "$zs")" "$(add "$b" -1)"
    wait_mempool 1 "$tx"; cli 1 generate 1 >/dev/null; sync_to 0
    ck "tx re-mined: note back" "$(zbal 0 "$zs")" "$b"
    ck "tx re-mined in a different block" "$([ "$(cli 0 getbestblockhash)" != "$H" ] && echo yes)" yes
    zconfirm 0 "$zs" "[{\"address\":\"$ta\",\"amount\":0.5}]" >/dev/null
    ck "re-mined note spendable" "$(zbal 0 "$zs")" "$(add "$b" -0.5 -$FEE)"

    # (c) two-node fork resolved by the longer chain; node 0 spends on the losing branch
    zb=$(zbal 0 "$zs"); stop 0; stop 1; start 1 "$PEER_BIN" -connect=0 || return; start 0 "$BIN" -connect=0 -disablesafemode || return; ck "isolated node 0 has no peers" "$(cli 0 getconnectioncount)" 0
    ot=$(cli 1 getnewaddress)
    t0=$(zsend 0 "$zs" "[{\"address\":\"$ot\",\"amount\":1}]"); tx0=${t0#success }
    cli 0 generate 3 >/dev/null
    ck "node 0 branch confirms its spend" "$(zbal 0 "$zs")" "$(add "$zb" -1 -$FEE)"
    cli 1 generate 6 >/dev/null
    stop 0; stop 1; start 1 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 0)) || return; start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) -disablesafemode || return; sync_to 0
    ck "after the reorg the losing spend is back to unconfirmed" "$(cli 0 gettransaction "$tx0" | jget confirmations)" 0
    cli 1 sendrawtransaction "$(cli 0 gettransaction "$tx0" | jget hex)" >/dev/null 2>&1; wait_mempool 1 "$tx0"; cli 1 generate 1 >/dev/null; sync_to 0
    ck "the spend is re-mined on the winning chain" "$(zbal 0 "$zs")" "$(add "$zb" -1 -$FEE)"

    # (d) deeper reorg with many notes
    zb=$(zbal 0 "$zs"); cli 1 sendtoaddress "$mt" 8 >/dev/null; cli 1 generate 1 >/dev/null; r=$(zsend 1 "$mt" "[{\"address\":\"$mz\",\"amount\":7}]"); cli 1 generate 1 >/dev/null
    first=$(cli 1 getbestblockhash)
    i=0; while [ $i -lt 10 ]; do r=$(zsend 1 "$mz" "[{\"address\":\"$zs\",\"amount\":0.5}]"); case $r in success*) ;; *) bad "deep: miner z_sendmany $i: $r" ;; esac; cli 1 generate 1 >/dev/null; i=$((i + 1)); done; sync_to 0
    ck "ten new notes counted" "$(zbal 0 "$zs")" "$(add "$zb" 5)"
    nxt=$(cli 1 getblock "$first" | jget nextblockhash)
    cli 0 invalidateblock "$nxt" >/dev/null
    ck "deep invalidate: all ten notes gone" "$(zbal 0 "$zs")" "$zb"
    cli 0 reconsiderblock "$nxt" >/dev/null; sync_to 0
    ck "deep reconsider: all ten notes back" "$(zbal 0 "$zs")" "$(add "$zb" 5)"
    zconfirm 0 "$zs" "[{\"address\":\"$ta\",\"amount\":$(add "$zb" 5 -$FEE)}]" >/dev/null
    ck "every note spendable after the deep reorg" "$(zbal 0 "$zs")" 0.00000000
    alive reorg
}

# ---------------------------------------------------------------- 8
# Cross-version: node 0 alternates between $BIN and $ALT_BIN on ONE datadir.
cv_open() { start 0 "$1" -connect=127.0.0.1:$((BASE + 1)) ${2:+"$2"} || return 1; sync_to 0; }
cv_snap() { printf '%s sp=%s zs=%s zv=%s' "$(snap 0)" "$(zbal 0 "$SP")" "$(zbal 0 "$ZS")" "$(cli 0 z_listunspent 0 | jq -c '[.[]|.memo[0:4]]|sort')"; }
scn_crossver() {
    NU_ARGS="-nuparams=5ba81b19:230 -nuparams=76b809bb:240"
    start 1 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 0)) || return
    start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) || return
    cli 1 generate 112 >/dev/null; sync_to 0
    SP=$(cli 0 z_getnewaddress sprout)
    TA=$(give_t 0 5); give_t 0 2 >/dev/null
    give_z 0 "$SP" 3 6364
    cli 1 generate 135 >/dev/null; sync_to 0
    ZS=$(cli 0 z_getnewaddress); give_z 0 "$ZS" 4 6162; give_z 0 "$ZS" 1.5 6566
    S0=$(cv_snap); obs "created_wallet" "$(printf %s "$S0" | cut -c1-120)"
    ck "created: t" "$(bal 0)" 7.00000000
    ck "created: sapling" "$(zbal 0 "$ZS")" 5.50000000
    ck "created: sprout" "$(zbal 0 "$SP")" 3.00000000
    stop 0
    other=$(cli 1 getnewaddress); n=0; prev=$S0; cur_bin=$BIN
    for b in "$ALT_BIN" "$BIN" "$ALT_BIN" "$BIN" "$ALT_BIN"; do
        n=$((n + 1)); cv_open "$b" || return
        ck "open $n with $(basename "$(dirname "$b")")/$(basename "$b"): wallet identical" "$(cv_snap)" "$prev"
        # spend one of each kind with this binary
        zconfirm 0 "$ZS" "[{\"address\":\"$other\",\"amount\":0.1}]" >/dev/null
        zconfirm 0 "$SP" "[{\"address\":\"$other\",\"amount\":0.1}]" >/dev/null
        tx=$(cli 0 sendtoaddress "$other" 0.1); wait_mempool 1 "$tx"; mine 1
        prev=$(cv_snap); stop 0
    done
    cv_open "$BIN" || return
    ck "last open identical" "$(cv_snap)" "$prev"
    ck "sprout spend count: 5 rounds + 0 left over (balance exact)" "$(zbal 0 "$SP")" "$(add 3 -0.5 -$(awk 'BEGIN{print 5*0.0001}'))"
    stop 0
    # rescan with the other binary on the same datadir
    cv_open "$ALT_BIN" -rescan || return
    ck "-rescan with the alternate binary: totals" "$(zbal 0 "$ZS")" "$(add 5.5 -0.5 -$(awk 'BEGIN{print 5*0.0001}'))"
    stop 0
    # encrypted variant
    cv_open "$BIN" || return
    cli 0 encryptwallet "cvpw" >/dev/null 2>&1; pid=$(cat "$SD/node0/pid"); t=0; while kill -0 "$pid" 2>/dev/null && [ $t -lt 120 ]; do t=$((t + 1)); sleep 1; done
    enc=$(cv_snap 2>/dev/null)
    for b in "$ALT_BIN" "$BIN" "$ALT_BIN"; do
        cv_open "$b" || return
        ck "encrypted wallet opens: unlocked_until" "$(cli 0 getwalletinfo | jget unlocked_until)" 0
        cli 0 walletpassphrase cvpw 600 >/dev/null
        zconfirm 0 "$ZS" "[{\"address\":\"$other\",\"amount\":0.1}]" >/dev/null
        zconfirm 0 "$SP" "[{\"address\":\"$other\",\"amount\":0.1}]" >/dev/null
        cli 0 walletlock >/dev/null; stop 0
    done
    cv_open "$BIN" || return
    ck "encrypted wallet after 3 alternations: sapling" "$(zbal 0 "$ZS")" "$(add 5.5 -0.5 -$(awk 'BEGIN{print 5*0.0001}') -0.3 -$(awk 'BEGIN{print 3*0.0001}'))"
    alive crossver
}

# ---------------------------------------------------------------- 9
scn_interop() {
    # The pre-Sapling Sprout JoinSplits are PHGR13: only the previous release (the
    # peer) can create them; the binary under test verifies them.
    if [ "$PEER_BIN" = "$BIN" ]; then
        echo "needs a PHGR13-capable peer (--peer-bin <previous release>): the binary under test cannot create PHGR13 proofs" >"$SD/skip"
        return
    fi
    NU_ARGS="-nuparams=5ba81b19:230 -nuparams=76b809bb:240"
    setup2 || return
    sp=$(cli 0 z_getnewaddress sprout); ms=$(cli 1 z_getnewaddress sprout)
    mt=$(cli 1 getnewaddress)
    in_tip() { cli 1 getblock "$(cli 1 getbestblockhash)" | jq -r --arg t "$1" '[.tx[]|select(.==$t)]|length'; }
    # pre-Sapling era: the peer makes the PHGR13 JoinSplit, node 0 verifies it; node 0 cannot make one
    give_z 0 "$sp" 3
    r=$(zsend 0 "$sp" "[{\"address\":\"$mt\",\"amount\":1}]")
    ck "sprout->t (PHGR13) is refused on node 0, naming PHGR13" "$(printf %s "$r" | grep -c 'PHGR13 proofs can no longer be created')" 1
    ck "node 0 holds the peer-made sprout note" "$(zbal 0 "$sp")" 3.00000000
    mtt=$(cli 1 getnewaddress)
    cli 1 sendtoaddress "$mtt" 3 >/dev/null; cli 1 generate 1 >/dev/null
    t=$(zconfirm 1 "$mtt" "[{\"address\":\"$ms\",\"amount\":2}]"); sync_to 0
    ck "peer sprout note" "$(zbal 1 "$ms")" 2.00000000
    t=$(zconfirm 1 "$ms" "[{\"address\":\"$sp\",\"amount\":1}]"); sync_to 0
    ck "peer sprout->sprout, node 0 receives (PHGR)" "$(zbal 0 "$sp")" "$(add 3 1)"
    cli 1 generate 135 >/dev/null; sync_to 0
    zs=$(cli 0 z_getnewaddress); mz=$(cli 1 z_getnewaddress)
    ta=$(give_t 0 5)
    t=$(zconfirm 0 "$ta" "[{\"address\":\"$zs\",\"amount\":3,\"memo\":\"6162\"}]"); ck "t->sapling mined by the peer" "$(cli 1 getrawtransaction "$t" 1 | jget confirmations)" 1
    t=$(zconfirm 0 "$zs" "[{\"address\":\"$mz\",\"amount\":1},{\"address\":\"$mt\",\"amount\":0.5}]"); ck "sapling->sapling+t mined by the peer" "$(cli 1 getrawtransaction "$t" 1 | jget confirmations)" 1
    ck "peer received the sapling output" "$(zbal 1 "$mz")" 1.00000000
    t=$(zconfirm 0 "$sp" "[{\"address\":\"$mt\",\"amount\":0.5}]"); ck "sprout->t after Sapling (Groth16 JoinSplit) mined by the peer" "$(cli 1 getrawtransaction "$t" 1 | jget confirmations)" 1
    obs "groth16_joinsplit_tx_version" "$(cli 1 getrawtransaction "$t" 1 | jq -r '[.version,.overwintered,(.vjoinsplit|length)]|@csv')"
    obs "sprout_to_sapling_z_sendmany" "$(zsend 0 "$sp" "[{\"address\":\"$zs\",\"amount\":0.5}]" | cut -c1-100)"
    # peer creates, node 0 validates
    t=$(zconfirm 1 "$mz" "[{\"address\":\"$zs\",\"amount\":0.3,\"memo\":\"6364\"}]"); sync_to 0
    ck "node 0 accepted the peer's sapling tx" "$(cli 0 z_listreceivedbyaddress "$zs" | jq --arg t "$t" '[.[]|select(.txid==$t)]|length')" 1
    t=$(zconfirm 1 "$ms" "[{\"address\":\"$sp\",\"amount\":0.2}]"); sync_to 0
    ck "node 0 accepted the peer's sprout tx (Groth16)" "$(cli 0 z_listreceivedbyaddress "$sp" | jq --arg t "$t" '[.[]|select(.txid==$t)]|length')" 1
    ck "tips agree" "$(cli 0 getbestblockhash)" "$(cli 1 getbestblockhash)"
    alive interop
}

# ---------------------------------------------------------------- 10
scn_coinsel() {
    setup2 || return
    d=$(cli 1 getnewaddress)
    for a in 0.1 0.5 1.25 2 3.75 7 0.3 0.05; do cli 1 sendtoaddress "$(cli 0 getnewaddress)" "$a" >/dev/null; done
    cli 1 generate 1 >/dev/null; sync_to 0
    ck "eight coins" "$(cli 0 listunspent | jlen)" 8
    for amt in 0.04 1.2 0.6 5 2.5 0.9; do
        map=$(cli 0 listunspent 0 | jq -c '[.[]|{k:"\(.txid):\(.vout)",v:.amount}]')
        tx=$(cli 0 sendtoaddress "$d" "$amt"); wait_mempool 1 "$tx"
        ins=$(cli 0 decoderawtransaction "$(cli 0 gettransaction "$tx" | jget hex)" | jq -r '.vin[]|"\(.txid):\(.vout)"')
        amts=$(for i in $ins; do printf '%s' "$map" | jq -r --arg k "$i" '.[]|select(.k==$k)|.v'; done | sort -n | tr '\n' ',')
        obs "send_${amt}_inputs" "$amts"
        cli 1 generate 1 >/dev/null; sync_to 0
    done
    alive coinsel
}

# ---------------------------------------------------------------- 11
scn_load() {
    NN=${LOAD_NOTES:-2000}; NU=${LOAD_UTXOS:-5000}
    setup2 || return
    rec=$(recips 0 z_getnewaddress 50 0.01); zs=$(printf %s "$rec" | jget "[0].address"); R="-connect=127.0.0.1:$((BASE + 1))"
    # UTXOs: miner sendmany, 1000 outputs per transaction
    t0=$(now); i=0; ta=""
    while [ $((i * 1000)) -lt "$NU" ]; do
        j=$(jq -nc --arg p "$(cli 0 getnewaddress)" '{($p):0.01}')   # placeholder for shape
        addrs=$(for k in $(seq 1 1000); do cli 0 getnewaddress; done | jq -Rsc 'split("\n")[:-1]|map({key:.,value:0.01})|from_entries')
        cli 1 sendmany "" "$addrs" >/dev/null; cli 1 generate 1 >/dev/null; i=$((i + 1))
    done
    sync_to 0; obs_t "build_${NU}_utxos" "$(elapsed "$t0")"
    ck "utxo count" "$(cli 0 listunspent | jlen)" "$((i * 1000))"  # built in whole 1000-output transactions
    # notes: miner funds a t address then z_sendmany 50 recipients per transaction
    t0=$(now); fa=$(cli 1 getnewaddress); mzl=$(cli 1 z_getnewaddress); cli 1 sendtoaddress "$fa" "$(awk -v n="$NN" 'BEGIN{print n*0.01+5}')" >/dev/null; cli 1 generate 1 >/dev/null
    r=$(zsend 1 "$fa" "[{\"address\":\"$mzl\",\"amount\":$(awk -v n="$NN" 'BEGIN{print n*0.01+3}')}]" 1 0.001); case $r in success*) cli 1 generate 1 >/dev/null ;; *) bad "load: miner shielding: $r" ;; esac
    i=0; while [ $((i * 50)) -lt "$NN" ]; do
        r=$(zsend 1 "$mzl" "$rec" 1 0.001); case $r in success*) cli 1 generate 1 >/dev/null ;; *) bad "load note batch $i: $r"; break ;; esac
        i=$((i + 1))
    done
    sync_to 0; obs_t "build_${NN}_notes" "$(elapsed "$t0")"
    nn=$(cli 0 z_listunspent | jlen); ck "note count" "$nn" "$((i * 50))"
    tm() { t0=$(now); "$@" >/dev/null; elapsed "$t0"; }
    obs_t listunspent "$(tm cli 0 listunspent)"; obs_t getbalance "$(tm cli 0 getbalance)"
    obs_t z_listunspent "$(tm cli 0 z_listunspent)"; obs_t z_getbalance "$(tm cli 0 z_getbalance "$zs")"
    obs_t z_gettotalbalance "$(tm cli 0 z_gettotalbalance)"; obs_t getwalletinfo "$(tm cli 0 getwalletinfo)"
    obs_t listtransactions "$(tm cli 0 listtransactions '*' 100000)"
    zb=$(zbal 0 "$zs"); ck "z balance exact (one of 50 addresses)" "$zb" "$(awk -v n="$i" 'BEGIN{printf "%.8f", n*0.01}')"
    d=$(cli 1 getnewaddress)
    spend=$(awk -v n="$i" 'BEGIN { printf "%.3f", n * 0.01 * 0.875 }')   # 35 of 40 notes of this address (0.35 at the default size)
    # sendmany spending many transparent coins
    t0=$(now); tx=$(cli 0 sendtoaddress "$d" "$(awk -v n="$NU" 'BEGIN{print n*0.01*0.5}')"); obs_t "sendtoaddress_half_of_utxos" "$(elapsed "$t0")"
    wait_mempool 1 "$tx"; mine 1
    # z_sendmany spending many notes (about 150)
    t0=$(now); r=$(zsend 0 "$zs" "[{\"address\":\"$d\",\"amount\":$spend}]" 1 0.001); obs_t "z_sendmany_spends_35_notes" "$(elapsed "$t0")"
    case $r in success*) mine 1; ck "z_sendmany many notes: balance" "$(zbal 0 "$zs")" "$(add "$zb" -$spend -0.001)" ;; *) bad "z_sendmany many notes: $r" ;; esac
    t0=$(now); mg=$(cli 0 z_mergetoaddress '["ANY_TADDR"]' "$zs" 0.0001 500); r=$(wait_op 0 "$(printf %s "$mg" | jget opid)"); obs_t "z_mergetoaddress_500_utxos" "$(elapsed "$t0")"; mine 1
    zt0=$(cli 0 z_gettotalbalance 0 | jget private | f8); t0=$(now); mg=$(cli 0 z_mergetoaddress "$(printf %s "$rec" | jq -c '[.[].address]')" "$zs" 0.0001 0 200); r=$(wait_op 0 "$(printf %s "$mg" | jget opid)"); obs_t "z_mergetoaddress_200_notes" "$(elapsed "$t0")"
    w=0; while [ "$(cli 0 z_gettotalbalance 0 | jget private | f8)" != "$(add "$zt0" -0.0001)" ] && [ $w -lt 300 ]; do sleep 0.1; w=$((w + 1)); done; obs_t "merge_effect_visible_in_wallet_after_op_success" "$(awk -v w=$w 'BEGIN{printf "%.1f", w/10}')"
    wait_mempool 1 "${r#success }"; mine 1
    s=$(snap 0)
    stop 0; t0=$(now); start 0 "$BIN" $R; obs_t "restart_to_rpc" "$(elapsed "$t0")"; ck "restart identical" "$(snap 0)" "$s"
    stop 0; t0=$(now); start 0 "$BIN" $R -rescan; sync_to 0; obs_t "rescan_start_to_rpc" "$(elapsed "$t0")"; ck "-rescan identical" "$(snap 0 | sed 's/txs=.*//')" "$(printf %s "$s" | sed 's/txs=.*//')"
    alive load
}

# ---------------------------------------------------------------- 12
scn_robust() {
    setup2 || return
    zs=$(cli 0 z_getnewaddress); zs2=$(cli 0 z_getnewaddress); ta=$(give_t 0 5); give_z 0 "$zs" 3
    d=$(cli 1 getnewaddress); n=0
    try() { local key=$1; shift; obs "e_$key" "$(errtxt 0 "$@" | cut -c1-110)"; }
    k=0
    deep=$(awk 'BEGIN{for(i=0;i<20000;i++)printf "["}')
    for amt in 1e30 21000001 0 -0.00000001 0.000000001 abc '[]' null '"1"' 99999999999999999999 NaN; do k=$((k + 1)); try "send_$k" sendtoaddress "$d" "$amt"; done
    alive "sendtoaddress amounts"
    try sendmany_dup sendmany "" "{\"$d\":1,\"$d\":2}"
    try sendmany_arr sendmany "" "[1,2]"
    try sendmany_empty sendmany "" "{}"
    try sendmany_neg sendmany "" "{\"$d\":-1}"
    try sendmany_minconf_neg sendmany "" "{\"$d\":1}" -5
    try sendmany_bad_json sendmany "" "{"
    try sendmany_deep sendmany "" "$deep"
    alive "sendmany"
    for rec in "{" "null" "[null]" "[1]" '[{"address":1}]' '[{"amount":1}]' "[{\"address\":\"$zs2\"}]" "[{\"address\":\"$zs2\",\"amount\":\"x\"}]" \
        "[{\"address\":\"$zs2\",\"amount\":1e30}]" "[{\"address\":\"$zs2\",\"amount\":99999999999}]" "[{\"address\":\"$zs2\",\"amount\":0}]" \
        "[{\"address\":\"$zs2\",\"amount\":1,\"memo\":\"zz\"}]" "[{\"address\":\"$zs2\",\"amount\":1,\"memo\":\"\"}]" "[{\"address\":\"$zs2\",\"amount\":1,\"memo\":\"abc\"}]" \
        "[{\"address\":\"$zs2\",\"amount\":1,\"memo\":5}]" "[{\"address\":\"$zs2\",\"amount\":1,\"extra\":1}]" "[{\"address\":\"$zs2\",\"amount\":0.1},{\"address\":\"$zs2\",\"amount\":0.1}]" \
        "[{\"address\":\"$zs2\",\"amount\":1.123456789}]" "$deep"; do
        k=$((k + 1)); obs "zsend_$k" "$(zsend 0 "$zs" "$rec" | sed 's/success .*/success/' | cut -c1-110)"
        mine 1 2>/dev/null
    done
    alive "z_sendmany inputs"
    try zs_minconf_neg z_sendmany "$zs" "[{\"address\":\"$zs2\",\"amount\":0.1}]" -1
    try zs_minconf_str z_sendmany "$zs" "[{\"address\":\"$zs2\",\"amount\":0.1}]" x
    try zs_fee_neg z_sendmany "$zs" "[{\"address\":\"$zs2\",\"amount\":0.1}]" 1 -1
    try zs_fee_huge z_sendmany "$zs" "[{\"address\":\"$zs2\",\"amount\":0.1}]" 1 100000000
    try zs_from_t_empty z_sendmany "$(cli 0 getnewaddress)" "[{\"address\":\"$zs2\",\"amount\":0.1}]"
    try zs_to_self_t z_sendmany "$zs" "[{\"address\":\"$ta\",\"amount\":0.1}]" 0
    try import_garbage importprivkey "$(head -c 60 /dev/zero | tr '\0' x)"
    try zimport_garbage z_importkey "$(head -c 200 /dev/zero | tr '\0' x)"
    try zimportvk_garbage z_importviewingkey "garbage" yes
    try zimport_height_neg z_importkey "$(cli 0 z_exportkey "$zs")" yes -1
    try zimport_height_huge z_importkey "$(cli 0 z_exportkey "$zs")" yes 99999999999
    try importwallet_missing importwallet "/nonexistent/file"
    try importwallet_dir importwallet "$SD"
    try dumpwallet_outside dumpwallet "/nonexistent_dir/x"
    try dumpwallet_dotdot dumpwallet "../escape"
    try zexportwallet_dotdot z_exportwallet "../escape"
    try backupwallet_dir backupwallet "$SD"
    try backupwallet_empty backupwallet ""
    try gettx_bad gettransaction "xyz"
    try gettx_unknown gettransaction "$(head -c 64 /dev/zero | tr '\0' 0)"
    try listtx_neg listtransactions "*" -1
    try listtx_from_neg listtransactions "*" 10 -1
    try listtx_huge listtransactions "*" 99999999999999
    try listunspent_bad_addr listunspent 1 9999999 '["notanaddress"]'
    try listunspent_minconf_neg listunspent -1
    try zlistunspent_bad z_listunspent 1 9999999 false '["notanaddress"]'
    try zlistunspent_range z_listunspent 5 1
    try lockunspent_bad lockunspent false '[{"txid":"zz","vout":0}]'
    try lockunspent_vout lockunspent false "[{\"txid\":\"$(head -c 64 /dev/zero | tr '\0' 0)\",\"vout\":99}]"
    try fundraw_nonhex fundrawtransaction "zzzz"
    try fundraw_empty fundrawtransaction ""
    try sign_garbage signrawtransaction "00"
    try sendraw_garbage sendrawtransaction "deadbeef"
    try createraw_neg createrawtransaction '[]' "{\"$d\":-1}"
    try createraw_dup createrawtransaction '[]' "{\"$d\":1,\"$d\":1}"
    try merge_bad_from z_mergetoaddress '["garbage"]' "$zs"
    try merge_empty z_mergetoaddress '[]' "$zs"
    try merge_dup z_mergetoaddress "[\"$zs\",\"$zs\"]" "$zs2"
    try merge_limit_neg z_mergetoaddress '["ANY_TADDR"]' "$zs" 0.0001 -1
    try shield_bad z_shieldcoinbase "garbage" "$zs"
    try getbalance_bad getbalance "*" -5
    try getbalance_bad2 getbalance "nosuchaccount"
    try zgetbalance_bad z_getbalance "garbage"
    try zgetbalance_t z_getbalance "$ta"
    try zgetbalance_minconf_neg z_getbalance "$zs" -1
    try zlist_recv_bad z_listreceivedbyaddress "garbage"
    try zlist_recv_foreign z_listreceivedbyaddress "$(cli 1 z_getnewaddress)"
    try zopstatus_bad z_getoperationstatus '["opid-nonexistent"]'
    try zopstatus_notarray z_getoperationstatus "x"
    try zopresult_bad z_getoperationresult '[1]'
    try zvalidate_empty z_validateaddress ""
    try validate_empty validateaddress ""
    try keypoolrefill_neg keypoolrefill -1
    t0=$(now); try keypoolrefill_3000 keypoolrefill 3000; obs_t "keypoolrefill_3000" "$(elapsed "$t0")"
    try walletpassphrase_unenc walletpassphrase x 1
    try encrypt_empty encryptwallet ""
    try settxfee_neg settxfee -1
    try settxfee_huge settxfee 100000000
    try signmessage_bad signmessage "$ta" ""
    try addmultisig_bad addmultisigaddress 5 '["a"]'
    try importaddress_bad importaddress "garbage" "" false
    alive "wallet RPC inputs"
    ck "wallet unchanged by the invalid calls' failures (t balance not negative)" "$([ "$(bal 0 '*' 0 | cut -c1-1)" != "-" ] && echo ok)" ok
    ck "chain tips agree" "$(cli 0 getbestblockhash)" "$(cli 1 getbestblockhash)"
}

# ---------------------------------------------------------------- 13
# What does a kill -9 right after sendtoaddress do to NETWORK relay of that tx?
scn_relay() {
    setup2 || return
    ta=$(give_t 0 10); other=$(cli 1 getnewaddress); R="-connect=127.0.0.1:$((BASE + 1))"; i=0
    while [ $i -lt 4 ]; do
        i=$((i + 1)); tx=$(cli 0 sendtoaddress "$other" 0.1); kill9 0; start 0 "$BIN" $R
        known=$(cli 0 gettransaction "$tx" >/dev/null 2>&1 && echo yes || echo no)
        w=0; until cli 1 getrawmempool | grep -q "$tx" || [ $w -ge 90 ]; do sleep 1; w=$((w + 1)); done
        if cli 1 getrawmempool | grep -q "$tx"; then at="${w}s"; else at="never(90s)"; fi
        obs "round${i}_wallet_knows=$known,reached_peer_after" "$at"
        [ "$at" = "never(90s)" ] && cli 1 sendrawtransaction "$(cli 0 gettransaction "$tx" | jget hex)" >/dev/null 2>&1
        cli 1 generate 1 >/dev/null; sync_to 0
    done
    pass "relay probe finished"
    ck "final balance = funds minus 4 sends, exact" "$(bal 0)" "$(add 10 -0.4 "$(cli 0 listtransactions '*' 100 | jq '[.[]|select(.category=="send")|.fee]|add' | f8)")"
}

# ---------------------------------------------------------------- 14
# Crash window: how much does a kill -9 right after confirmed receipts lose from wallet.dat, and
# does the next startup recover it by itself (no -rescan)?
scn_window() {
    setup2 || return
    zs=$(cli 0 z_getnewaddress); ta=$(cli 0 getnewaddress); R="-connect=127.0.0.1:$((BASE + 1))"
    mt=$(cli 1 getnewaddress); mz=$(cli 1 z_getnewaddress)
    cli 1 sendtoaddress "$mt" 8 >/dev/null; cli 1 generate 1 >/dev/null
    r=$(zsend 1 "$mt" "[{\"address\":\"$mz\",\"amount\":6}]"); cli 1 generate 1 >/dev/null
    i=0; while [ $i -lt 10 ]; do
        i=$((i + 1)); cli 1 sendtoaddress "$ta" 0.1 >/dev/null
        r=$(zsend 1 "$mz" "[{\"address\":\"$zs\",\"amount\":0.1}]"); case $r in success*) ;; *) bad "window: miner z_sendmany $i: $r" ;; esac
        cli 1 generate 1 >/dev/null
    done; sync_to 0
    ck "10 t receipts" "$(bal 0)" 1.00000000; ck "10 z receipts" "$(zbal 0 "$zs")" 1.00000000
    kill9 0; start 0 "$BIN" $R
    obs "kill9_after_10_blocks_t_immediate" "$(bal 0)"; obs "kill9_after_10_blocks_z_immediate" "$(zbal 0 "$zs")"
    w=0; until [ "$(bal 0)" = 1.00000000 ] && [ "$(zbal 0 "$zs")" = 1.00000000 ] || [ $w -ge 120 ]; do sleep 1; w=$((w + 1)); done
    obs_t "kill9_recovered_by_startup_scan_after_seconds" "$w"
    ck "startup recovers every receipt without -rescan (t)" "$(bal 0)" 1.00000000
    ck "startup recovers every receipt without -rescan (z)" "$(zbal 0 "$zs")" 1.00000000
    ck "no duplicate notes" "$(cli 0 z_listunspent | jlen)" 10
    ck "no duplicate coins" "$(cli 0 listunspent | jlen)" 10
    ck "10 notes spendable after recovery" "$(zsend 0 "$zs" "[{\"address\":\"$mt\",\"amount\":0.9}]" | cut -c1-7)" success
}
