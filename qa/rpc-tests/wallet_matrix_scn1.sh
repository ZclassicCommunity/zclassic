#!/bin/sh
# Scenarios 1 and 2 for wallet_matrix.sh (sourced after wallet_matrix_lib.sh).

# fee_of <node> <txid>: wallet fee of a transaction (negative number as printed)
fee_of() { cli "$1" gettransaction "$2" | jgetd fee 0 | awk '{ printf "%.8f", $1 }'; }
f8() { awk '{ printf "%.8f", $1 }'; }
# recips <node> <rpc> <count> <amount>: JSON recipient list of fresh addresses
recips() { for k in $(seq 1 "$3"); do cli "$1" "$2"; done | jq -Rsc --argjson amt "$4" 'split("
")[:-1]|map({address:.,amount:$amt})'; }

# ---------------------------------------------------------------- 1
scn_transparent() {
    setup2 || return
    a=$(give_t 0 10)
    ck "getbalance after one confirmation" "$(bal 0)" 10.00000000
    ck "getbalance minconf 2 with 1 confirmation" "$(bal 0 '*' 2)" 0.00000000
    cli 1 generate 1 >/dev/null; sync_to 0
    ck "getbalance minconf 2 with 2 confirmations" "$(bal 0 '*' 2)" 10.00000000
    ck "getunconfirmedbalance" "$(cli 0 getunconfirmedbalance | f8)" 0.00000000
    u=$(cli 0 listunspent)
    ck "listunspent count" "$(printf %s "$u" | jlen)" 1
    ck "listunspent address" "$(printf %s "$u" | jget "[0].address")" "$a"
    ck "listunspent amount" "$(printf %s "$u" | jget "[0].amount" | f8)" 10.00000000
    ck "getreceivedbyaddress" "$(cli 0 getreceivedbyaddress "$a" | f8)" 10.00000000
    ck "getwalletinfo balance" "$(cli 0 getwalletinfo | jget balance | f8)" 10.00000000

    dest=$(cli 1 getnewaddress)
    tx=$(cli 0 sendtoaddress "$dest" 3); wait_mempool 1 "$tx"
    fee=$(fee_of 0 "$tx"); obs "default_fee_sendtoaddress" "$fee"
    g=$(cli 0 gettransaction "$tx")
    ck "gettransaction amount" "$(printf %s "$g" | jget amount | f8)" -3.00000000
    ck "gettransaction confirmations (mempool)" "$(printf %s "$g" | jget confirmations)" 0
    exp=$(add 10 -3 "$fee")
    ck "balance minconf 0 after send (change counted)" "$(bal 0 '*' 0)" "$exp"
    cli 1 generate 1 >/dev/null; sync_to 0
    ck "balance minconf 1 after confirm" "$(bal 0)" "$exp"
    ck "recipient getreceivedbyaddress" "$(cli 1 getreceivedbyaddress "$dest" | f8)" 3.00000000
    ck "one change output" "$(cli 0 listunspent | jlen)" 1
    ck "change amount" "$(cli 0 listunspent | jget "[0].amount" | f8)" "$exp"
    lt=$(cli 0 listtransactions "*" 10)
    ck "listtransactions has the send" "$(printf %s "$lt" | jq --arg t "$tx" '[.[]|select(.txid==$t and .category=="send")]|length')" 1
    ck "listtransactions has the receive" "$(printf %s "$lt" | jq --arg a "$a" '[.[]|select(.address==$a and .category=="receive")]|length')" 1
    cur=$exp

    # fee handling: settxfee must raise the fee of the next transaction
    cli 0 settxfee 0.001 >/dev/null
    tx=$(cli 0 sendtoaddress "$dest" 1); wait_mempool 1 "$tx"; f2=$(fee_of 0 "$tx"); obs "fee_after_settxfee_0.001" "$f2"
    cli 0 settxfee 0 >/dev/null
    [ "$(awk -v a="$f2" -v b="$fee" 'BEGIN{print (a < b) ? 1 : 0}')" = 1 ] && pass "settxfee raises the fee" || bad "settxfee did not raise the fee ($f2 vs $fee)"
    cli 1 generate 1 >/dev/null; sync_to 0; cur=$(add "$cur" -1 "$f2")
    ck "balance after settxfee send" "$(bal 0)" "$cur"

    # sendmany, two recipients, and subtractfeefromamount
    d1=$(cli 1 getnewaddress); d2=$(cli 1 getnewaddress)
    tx=$(cli 0 sendmany "" "{\"$d1\":1,\"$d2\":2}"); wait_mempool 1 "$tx"; f=$(fee_of 0 "$tx")
    cli 1 generate 1 >/dev/null; sync_to 0; cur=$(add "$cur" -3 "$f")
    ck "sendmany balance" "$(bal 0)" "$cur"
    ck "sendmany recipient 2" "$(cli 1 getreceivedbyaddress "$d2" | f8)" 2.00000000
    tx=$(cli 0 sendtoaddress "$d1" 1 "" "" true); wait_mempool 1 "$tx"; f=$(fee_of 0 "$tx")
    cli 1 generate 1 >/dev/null; sync_to 0; cur=$(add "$cur" -1)
    ck "subtractfeefromamount: wallet pays exactly the amount" "$(bal 0)" "$cur"
    ck "subtractfeefromamount: recipient gets amount minus fee" "$(cli 1 getreceivedbyaddress "$d1" | f8)" "$(add 1 1 "$f")"

    # lockunspent
    nu=$(cli 0 listunspent | jlen); cli 0 lockunspent false "$(cli 0 listunspent | jq -c 'map({txid,vout})')" >/dev/null
    ck "listlockunspent" "$(cli 0 listlockunspent | jlen)" "$nu"
    ckerr "send with every coin locked" "insufficient funds" 0 sendtoaddress "$dest" 1
    cli 0 lockunspent true "$(cli 0 listlockunspent | jq -c .)" >/dev/null
    ck "listlockunspent empty after unlock" "$(cli 0 listlockunspent | jlen)" 0

    # fundrawtransaction -> signrawtransaction -> sendrawtransaction
    raw=$(cli 0 createrawtransaction '[]' "{\"$dest\":0.5}")
    fr=$(cli 0 fundrawtransaction "$raw"); frfee=$(printf %s "$fr" | jget fee | f8)
    sg=$(cli 0 signrawtransaction "$(printf %s "$fr" | jget hex)")
    ck "signrawtransaction complete" "$(printf %s "$sg" | jget complete)" true
    tx=$(cli 0 sendrawtransaction "$(printf %s "$sg" | jget hex)"); wait_mempool 1 "$tx"
    cli 1 generate 1 >/dev/null; sync_to 0; cur=$(add "$cur" -0.5 "-$frfee")
    ck "fundrawtransaction path balance" "$(bal 0)" "$cur"
    obs "fundraw_fee" "$frfee"

    # explicit coin control: spend one named coin, pay 1, fee 0.001
    c=$(cli 0 listunspent | jraw '[0]'); cv=$(printf %s "$c" | jget amount | f8)
    chg=$(cli 0 getnewaddress)
    raw=$(cli 0 createrawtransaction "[{\"txid\":\"$(printf %s "$c" | jget txid)\",\"vout\":$(printf %s "$c" | jget vout)}]" "{\"$dest\":1,\"$chg\":$(add "$cv" -1 -0.001)}")
    sg=$(cli 0 signrawtransaction "$raw")
    tx=$(cli 0 sendrawtransaction "$(printf %s "$sg" | jget hex)"); wait_mempool 1 "$tx"
    cli 1 generate 1 >/dev/null; sync_to 0; cur=$(add "$cur" -1 -0.001)
    ck "coin control: balance" "$(bal 0)" "$cur"
    ck "coin control: spent coin is gone" "$(cli 0 listunspent | jq --arg t "$(printf %s "$c" | jget txid)" --argjson v "$(printf %s "$c" | jget vout)" '[.[]|select(.txid==$t and .vout==$v)]|length')" 0
    ckerr "sendrawtransaction of a double spend" "missing|spent|conflict|bad-txns|already" 0 sendrawtransaction "$(printf %s "$sg" | jget hex)"
    ckerr "sendtoaddress more than the balance" "insufficient funds" 0 sendtoaddress "$dest" 1000000
    ckerr "sendtoaddress invalid address" "invalid" 0 sendtoaddress "nonsense" 1
    ckerr "sendtoaddress negative amount" "amount" 0 sendtoaddress "$dest" -1
    ck "balance equals the sum of listunspent" "$(cli 0 listunspent | jq '[.[].amount]|add' | f8)" "$cur"
    alive transparent
}

# ---------------------------------------------------------------- 2
scn_sapling() {
    setup2 || return
    zs=$(cli 0 z_getnewaddress); zs2=$(cli 0 z_getnewaddress sapling); zs3=$(cli 0 z_getnewaddress)
    v=$(cli 0 z_validateaddress "$zs")
    ck "z_validateaddress isvalid" "$(printf %s "$v" | jget isvalid)" true
    ck "z_validateaddress type" "$(printf %s "$v" | jget type)" sapling
    ck "z_validateaddress ismine" "$(printf %s "$v" | jget ismine)" true
    ck "z_validateaddress on garbage" "$(cli 0 z_validateaddress notanaddress | jget isvalid)" false
    ck "z_listaddresses has all three" "$(cli 0 z_listaddresses | jq --arg a "$zs" --arg b "$zs2" --arg c "$zs3" '[.[]|select(.==$a or .==$b or .==$c)]|length')" 3

    give_z 0 "$zs" 5 48656c6c6f
    ck "z_getbalance after receive" "$(zbal 0 "$zs")" 5.00000000
    tb=$(cli 0 z_gettotalbalance)
    ck "z_gettotalbalance private" "$(printf %s "$tb" | jget private | f8)" 5.00000000
    ck "z_gettotalbalance transparent" "$(printf %s "$tb" | jget transparent | f8)" 0.00000000
    ck "z_gettotalbalance total" "$(printf %s "$tb" | jget total | f8)" 5.00000000
    zl=$(cli 0 z_listunspent)
    ck "z_listunspent count" "$(printf %s "$zl" | jlen)" 1
    ck "z_listunspent amount" "$(printf %s "$zl" | jget "[0].amount" | f8)" 5.00000000
    ck "z_listunspent memo" "$(printf %s "$zl" | jget "[0].memo" | cut -c1-10)" 48656c6c6f
    ck "z_listunspent spendable" "$(printf %s "$zl" | jget "[0].spendable")" true
    ck "z_listreceivedbyaddress amount" "$(cli 0 z_listreceivedbyaddress "$zs" | jget "[0].amount" | f8)" 5.00000000
    ck "z_listreceivedbyaddress memo" "$(cli 0 z_listreceivedbyaddress "$zs" | jget "[0].memo" | cut -c1-10)" 48656c6c6f

    # t -> z with memo
    ta=$(give_t 0 3)
    zconfirm 0 "$ta" "[{\"address\":\"$zs2\",\"amount\":2,\"memo\":\"48656c6c6f\"}]" >/dev/null
    ck "t->z: z balance" "$(zbal 0 "$zs2")" 2.00000000
    ck "t->z: t balance (change)" "$(bal 0)" "$(add 3 -2 -$FEE)"
    ck "t->z: memo arrived" "$(cli 0 z_listreceivedbyaddress "$zs2" | jget "[0].memo" | cut -c1-10)" 48656c6c6f
    # z -> z
    zconfirm 0 "$zs" "[{\"address\":\"$zs2\",\"amount\":1}]" >/dev/null
    ck "z->z: sender" "$(zbal 0 "$zs")" "$(add 5 -1 -$FEE)"
    ck "z->z: recipient" "$(zbal 0 "$zs2")" 3.00000000
    # z -> t
    ta2=$(cli 0 getnewaddress); r0=$(cli 0 getreceivedbyaddress "$ta2" | f8)
    zconfirm 0 "$zs2" "[{\"address\":\"$ta2\",\"amount\":0.5}]" >/dev/null
    ck "z->t: z balance" "$(zbal 0 "$zs2")" "$(add 3 -0.5 -$FEE)"
    ck "z->t: t received" "$(add "$(cli 0 getreceivedbyaddress "$ta2" | f8)" "-$r0")" 0.50000000
    tcur=$(add 3 -2 -$FEE 0.5)
    ck "z->t: t balance" "$(bal 0)" "$tcur"
    # z -> many (t and z mixed)
    tb2=$(cli 0 getnewaddress)
    zconfirm 0 "$zs" "[{\"address\":\"$tb2\",\"amount\":0.1},{\"address\":\"$zs2\",\"amount\":0.2},{\"address\":\"$zs3\",\"amount\":0.3,\"memo\":\"6162\"}]" >/dev/null
    zcur=$(add 5 -1 -$FEE -0.6 -$FEE)
    ck "z->many: sender" "$(zbal 0 "$zs")" "$zcur"
    ck "z->many: z recipient 2" "$(zbal 0 "$zs2")" "$(add 3 -0.5 -$FEE 0.2)"
    ck "z->many: z recipient 3" "$(zbal 0 "$zs3")" 0.30000000
    ck "z->many: t recipient" "$(cli 0 getreceivedbyaddress "$tb2" | f8)" 0.10000000
    tcur=$(add "$tcur" 0.1)
    tot=$(cli 0 z_gettotalbalance)
    ck "total balance = t + z" "$(printf %s "$tot" | jget total | f8)" "$(add "$tcur" "$(zbal 0 "$zs")" "$(zbal 0 "$zs2")" "$(zbal 0 "$zs3")")"

    # errors and parameter variants
    r=$(zsend 0 "$zs" "[{\"address\":\"$ta2\",\"amount\":1000000}]"); case $r in failed*nsufficient*|rpcerror*nsufficient*) pass "insufficient funds" ;; *) bad "insufficient funds: $r" ;; esac
    ckerr "invalid from address" "invalid" 0 z_sendmany "garbage" "[{\"address\":\"$ta2\",\"amount\":1}]"
    ckerr "invalid recipient address" "invalid" 0 z_sendmany "$zs" "[{\"address\":\"garbage\",\"amount\":1}]"
    ckerr "memo to a transparent address" "memo" 0 z_sendmany "$zs" "[{\"address\":\"$ta2\",\"amount\":1,\"memo\":\"6162\"}]"
    ckerr "memo not hexadecimal" "hex" 0 z_sendmany "$zs" "[{\"address\":\"$zs2\",\"amount\":1,\"memo\":\"hello world\"}]"
    ckerr "memo longer than 512 bytes" "memo|long|512" 0 z_sendmany "$zs" "[{\"address\":\"$zs2\",\"amount\":1,\"memo\":\"$(head -c 1030 /dev/zero | tr '\0' 6)\"}]"
    ckerr "empty recipient list" "empty|amounts|recipient" 0 z_sendmany "$zs" "[]"
    ckerr "negative amount" "amount|positive|negative" 0 z_sendmany "$zs" "[{\"address\":\"$zs2\",\"amount\":-1}]"
    r=$(zsend 0 "$zs" "[{\"address\":\"$zs2\",\"amount\":1}]" 200); case $r in failed*|rpcerror*) pass "minconf 200 spends nothing" ;; *) bad "minconf 200: $r" ;; esac
    # custom fee and fee 0
    b=$(zbal 0 "$zs")
    zconfirm 0 "$zs" "[{\"address\":\"$zs2\",\"amount\":0.1}]" 1 0.001 >/dev/null
    ck "custom fee 0.001" "$(zbal 0 "$zs")" "$(add "$b" -0.1 -0.001)"
    zs4=$(cli 0 z_getnewaddress); give_z 0 "$zs4" 1; r=$(zsend 0 "$zs4" "[{\"address\":\"$zs2\",\"amount\":0.1}]" 1 0); obs "fee_0_z_sendmany" "$(printf %s "$r" | sed "s/success .*/success/" | cut -c1-100)"; sleep 3; obs "fee_0_tx_reached_miner_mempool" "$(cli 1 getrawmempool | jlen)"; mine 1
    mine 1
    # unconfirmed visibility
    b=$(zbal 0 "$zs2" 0)
    t=$(zsend 0 "$zs" "[{\"address\":\"$zs2\",\"amount\":0.25}]" | sed 's/success //'); wait_mempool 1 "$t"
    w=0; while [ "$(zbal 0 "$zs2" 0)" = "$b" ] && [ $w -lt 300 ]; do sleep 0.1; w=$((w + 1)); done; obs_t "z_unconfirmed_incoming_visible_after_seconds" "$(awk -v w=$w 'BEGIN{printf "%.1f", w/10}')"
    ck "minconf 0 shows the unconfirmed incoming note" "$(zbal 0 "$zs2" 0)" "$(add "$b" 0.25)"
    mine 1
    # operation lifecycle
    op=$(cli 0 z_sendmany "$zs" "[{\"address\":\"$zs2\",\"amount\":0.01}]" 1 $FEE); r=$(wait_op 0 "$op"); wait_mempool 1 "${r#success }"; mine 1
    ck "z_getoperationstatus keeps the operation" "$(cli 0 z_getoperationstatus "[\"$op\"]" | jget "[0].id")" "$op"
    ck "z_getoperationresult returns it" "$(cli 0 z_getoperationresult "[\"$op\"]" | jget "[0].id")" "$op"
    ck "z_getoperationresult removes it" "$(cli 0 z_listoperationids | jq --arg o "$op" '[.[]|select(.==$o)]|length')" 0
    ck "status of a removed operation" "$(cli 0 z_getoperationstatus "[\"$op\"]" | jlen)" 0
    # many recipients in one transaction
    rec=$(jq -nc --argjson a "$(recips 0 z_getnewaddress 12 0.001)" --argjson b "$(recips 1 getnewaddress 40 0.001)" '$a+$b')
    b=$(zbal 0 "$zs"); r=$(zsend 0 "$zs" "$rec")
    case $r in success*) pass "52 recipients (12 z, 40 t)"; wait_mempool 1 "${r#success }"; mine 1; ck "52 recipients balance" "$(zbal 0 "$zs")" "$(add "$b" -0.052 -$FEE)" ;; *) bad "52 recipients: $r" ;; esac
    big=$(jq -nc --arg t "$tb2" '[range(0;1000)|{address:$t,amount:0.0001}]')
    obs "1000_recipients" "$(zsend 0 "$zs" "$big" | sed 's/success .*/success/' | cut -c1-90)"
    alive sapling

    # z_shieldcoinbase: node 0 mines coinbase of its own
    zsc=$(cli 0 z_getnewaddress); cli 0 generate 105 >/dev/null; sync_to 1 0
    ckerr "z_shieldcoinbase to a transparent address" "invalid|zaddr" 0 z_shieldcoinbase "*" "$ta2"
    ckerr "z_shieldcoinbase fee negative" "fee|amount" 0 z_shieldcoinbase "*" "$zsc" -1
    ckerr "z_shieldcoinbase limit negative" "limit" 0 z_shieldcoinbase "*" "$zsc" 0.0001 -1
    sh=$(cli 0 z_shieldcoinbase "*" "$zsc" 0.0001 2)
    ck "z_shieldcoinbase limit 2: shielding utxos" "$(printf %s "$sh" | jget shieldingUTXOs)" 2
    obs "z_shieldcoinbase_remaining" "$(printf %s "$sh" | jget remainingUTXOs)"
    sv=$(printf %s "$sh" | jget shieldingValue | f8)
    r=$(wait_op 0 "$(printf %s "$sh" | jget opid)")
    case $r in success*) cli 0 generate 1 >/dev/null; sync_to 1 0; ck "z_shieldcoinbase balance" "$(zbal 0 "$zsc")" "$(add "$sv" -0.0001)" ;; *) bad "z_shieldcoinbase op: $r" ;; esac
    sh=$(cli 0 z_shieldcoinbase "*" "$zsc" 0.0001 0); sv2=$(printf %s "$sh" | jget shieldingValue | f8)
    r=$(wait_op 0 "$(printf %s "$sh" | jget opid)")
    case $r in success*) cli 0 generate 1 >/dev/null; sync_to 1 0
        ck "z_shieldcoinbase unlimited: nothing remains" "$(printf %s "$sh" | jget remainingUTXOs)" 0
        ck "z_shieldcoinbase unlimited: balance" "$(zbal 0 "$zsc")" "$(add "$sv" -0.0001 "$sv2" -0.0001)" ;; *) bad "z_shieldcoinbase all: $r" ;; esac

    # z_mergetoaddress: t inputs (limits), then z inputs
    for i in 1 2 3 4 5; do cli 1 sendtoaddress "$(cli 0 getnewaddress)" 1 >/dev/null; done; cli 1 generate 1 >/dev/null; sync_to 0 1
    nt=$(cli 0 listunspent | jq "[.[]|select(.generated|not)]|length"); cb=$(cli 0 listunspent | jq "[.[]|select(.generated)|.amount]|add // 0" | f8); obs "merge_t_utxos_before" "$nt"
    pv=$(cli 0 z_gettotalbalance | jget private | f8)
    mg=$(cli 0 z_mergetoaddress "[\"ANY_TADDR\",\"$zs\"]" "$zs3" 0.0001 0 0 2>&1)
    case $mg in *opid*) r=$(wait_op 0 "$(printf %s "$mg" | jget opid)"); wait_mempool 1 "${r#success }"; mine 1
        ck "mixed t and z sources are merged (notes)" "$([ "$(printf %s "$mg" | jget mergingNotes)" -ge 1 ] && echo yes)" yes
        ck "mixed merge: shielded total gains the t value minus fee" "$(cli 0 z_gettotalbalance | jget private | f8)" "$(add "$pv" "$(printf %s "$mg" | jget mergingTransparentValue)" -0.0001)" ;;
        *) obs "mixed_t_and_z_sources" "$(printf %s "$mg" | tr '\n' ' ' | cut -c1-100)" ;; esac
    for i in 1 2 3 4 5; do cli 1 sendtoaddress "$(cli 0 getnewaddress)" 1 >/dev/null; done; cli 1 generate 1 >/dev/null; sync_to 0 1
    nt=$(cli 0 listunspent | jq "[.[]|select(.generated|not)]|length"); obs "merge_t_utxos_before_limit_test" "$nt"
    mg=$(cli 0 z_mergetoaddress '["ANY_TADDR"]' "$zs3" 0.0001 2)
    ck "z_mergetoaddress transparent_limit 2" "$(printf %s "$mg" | jget mergingUTXOs)" 2
    ck "z_mergetoaddress remaining" "$(printf %s "$mg" | jget remainingUTXOs)" "$((nt - 2))"
    r=$(wait_op 0 "$(printf %s "$mg" | jget opid)"); case $r in success*) wait_mempool 1 "${r#success }"; mine 1 ;; *) bad "merge limit: $r" ;; esac
    z0=$(zbal 0 "$zs3"); tb=$(bal 0); cb0=$(cli 0 listunspent | jq "[.[]|select(.generated)|.amount]|add // 0" | f8)
    mg=$(cli 0 z_mergetoaddress '["ANY_TADDR"]' "$zs3" 0.0001 0)
    r=$(wait_op 0 "$(printf %s "$mg" | jget opid)")
    case $r in success*) wait_mempool 1 "${r#success }"; mine 1
        cb=$(cli 0 listunspent | jq "[.[]|select(.generated)|.amount]|add // 0" | f8); ck "merge all t: only coinbase coins remain" "$(bal 0)" "$cb"
        ck "merge all t: z gained the t balance minus fee" "$(zbal 0 "$zs3")" "$(add "$z0" "$tb" "-$cb0" -0.0001)" ;; *) bad "merge all t: $r" ;; esac
    tot=$(cli 0 z_gettotalbalance | jget private | f8)
    mg=$(cli 0 z_mergetoaddress "[\"$zs\",\"$zs2\",\"$zs3\"]" "$zs3" 0.0001 0 0)
    r=$(wait_op 0 "$(printf %s "$mg" | jget opid)")
    case $r in success*) wait_mempool 1 "${r#success }"; mine 1
        ck "merge all z notes: private total drops by the fee only" "$(cli 0 z_gettotalbalance | jget private | f8)" "$(add "$tot" -0.0001)"
        ck "merge all z notes: one note at the target" "$(cli 0 z_listunspent 1 9999999 false "[\"$zs3\"]" | jlen)" 1 ;; *) bad "merge z: $r" ;; esac
    alive sapling-end
}
