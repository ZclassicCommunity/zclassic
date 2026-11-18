#!/bin/sh
# Scenarios 3 to 6 for wallet_matrix.sh.

# snap <node> [sprout-addr]: one line describing the whole wallet, for before/after comparisons
snap() { local n=$1
    n=$1
    printf 't=%s u=%s unspent=%s znotes=%s ztot=%s txs=%s' \
        "$(bal "$n" '*' 1)" "$(bal "$n" '*' 0)" \
        "$(cli "$n" listunspent 0 | jq -c '[.[]|.amount*100000000|round]|sort')" \
        "$(cli "$n" z_listunspent 0 | jq -c '[.[]|(.amount*100000000|round)]|sort')" \
        "$(cli "$n" z_gettotalbalance 0 | jq -r .private | f8)" \
        "$(cli "$n" listtransactions '*' 100000 | jq length)"
}
# fresh <n> [args]: an empty wallet node on the same chain
fresh() { local n=$1; shift; start "$n" "$BIN" -connect=127.0.0.1:$((BASE + 1)) "$@" && sync_to "$n"; }

# ---------------------------------------------------------------- 3
scn_sprout() {
    # Sprout notes before Sapling exist only as PHGR13 JoinSplits, which a current
    # binary verifies but can no longer create: the miner must be a binary that can.
    if [ "$PEER_BIN" = "$BIN" ]; then
        echo "needs a PHGR13-capable miner (--peer-bin <previous release>): the binary under test cannot create PHGR13 proofs" >"$SD/skip"
        return
    fi
    NU_ARGS="-nuparams=5ba81b19:230 -nuparams=76b809bb:240"
    setup2 || return
    sp=$(cli 0 z_getnewaddress sprout); sp2=$(cli 0 z_getnewaddress sprout)
    v=$(cli 0 z_validateaddress "$sp")
    ck "sprout address type" "$(printf %s "$v" | jq -r .type)" sprout
    ck "sprout address ismine" "$(printf %s "$v" | jq -r .ismine)" true
    ck "chain is before Sapling" "$([ "$(cli 0 getblockcount)" -lt 230 ] && echo yes)" yes
    give_z 0 "$sp" 4 48656c6c6f
    ck "sprout note received (t->sprout)" "$(zbal 0 "$sp")" 4.00000000
    ck "sprout memo" "$(cli 0 z_listreceivedbyaddress "$sp" | jq -r '.[0].memo' | cut -c1-10)" 48656c6c6f
    ta=$(cli 0 getnewaddress)
    # The binary under test cannot create a PHGR13 proof: both spends before Sapling are
    # refused with an error that says why, and nothing changes.
    r=$(zsend 0 "$sp" "[{\"address\":\"$ta\",\"amount\":1}]")
    ck "sprout -> t before Sapling is refused, naming PHGR13" "$(printf %s "$r" | grep -c 'PHGR13 proofs can no longer be created')" 1
    r=$(zsend 0 "$sp" "[{\"address\":\"$sp2\",\"amount\":1}]")
    ck "sprout -> sprout before Sapling is refused, naming PHGR13" "$(printf %s "$r" | grep -c 'PHGR13 proofs can no longer be created')" 1
    ck "refused spends leave the note untouched" "$(zbal 0 "$sp")" 4.00000000
    obs "sprout_spend_before_sapling" "$(printf %s "$r" | cut -c1-150)"
    s1=$(snap 0); stop 0; start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)); ck "restart keeps sprout notes" "$(snap 0)" "$s1"
    # cross Sapling activation with the wallet holding Sprout notes
    cli 1 generate 135 >/dev/null; sync_to 0
    ck "chain is past Sapling" "$([ "$(cli 0 getblockcount)" -gt 241 ] && echo yes)" yes
    ck "sprout notes survive activation" "$(zbal 0 "$sp")" 4.00000000
    zs=$(cli 0 z_getnewaddress)
    r=$(zsend 0 "$sp" "[{\"address\":\"$zs\",\"amount\":0.5}]"); obs "sprout_to_sapling_after_activation" "$(printf %s "$r" | sed 's/success .*/success/' | cut -c1-100)"
    case $r in success*) mine 1; ck "sprout -> sapling moved value" "$(zbal 0 "$zs")" 0.50000000 ;; esac
    b=$(zbal 0 "$sp"); t=$(zconfirm 0 "$sp" "[{\"address\":\"$ta\",\"amount\":0.25}]")
    ck "sprout -> t after Sapling (groth16 joinsplit tx)" "$(zbal 0 "$sp")" "$(add "$b" -0.25 -$FEE)"
    obs "sprout_tx_version_after_sapling" "$(cli 0 getrawtransaction "$t" 1 2>/dev/null | jq -r '[.version,.overwintered]|@csv' 2>/dev/null)"
    r=$(zsend 0 "$ta" "[{\"address\":\"$sp\",\"amount\":0.1}]"); obs "t_to_sprout_after_sapling" "$(printf %s "$r" | sed 's/success .*/success/' | cut -c1-100)"
    case $r in success*) mine 1; ck "t -> sprout after Sapling" "$(zbal 0 "$sp")" "$(add "$b" -0.25 -$FEE 0.1)" ;; esac
    mg=$(cli 0 z_mergetoaddress "[\"$sp\",\"$sp2\"]" "$sp" 0.0001 0 0 2>&1); obs "merge_sprout_notes" "$(printf %s "$mg" | tr '\n' ' ' | cut -c1-120)"
    obs "z_setmigration" "$(errtxt 0 z_setmigration true)"
    obs "z_getmigrationstatus" "$(errtxt 0 z_getmigrationstatus)"
    alive sprout
}

# ---------------------------------------------------------------- 4
scn_keys() {
    setup2 || return
    ta=$(give_t 0 5); zs=$(cli 0 z_getnewaddress); give_z 0 "$zs" 4 48656c6c6f
    sp=$(cli 0 z_getnewaddress sprout); give_z 0 "$sp" 2
    WIF=$(cli 0 dumpprivkey "$ta"); ZK=$(cli 0 z_exportkey "$zs"); VK=$(cli 0 z_exportviewingkey "$sp")
    obs "sapling_z_exportviewingkey" "$(errtxt 0 z_exportviewingkey "$zs" | cut -c1-70)"
    ck "dumpprivkey looks like a key" "$([ -n "$WIF" ] && echo yes)" yes
    ckerr "dumpprivkey of an address not in the wallet" "private key|not known|no key" 0 dumpprivkey "$(cli 1 getnewaddress)"
    ckerr "z_exportkey of a foreign address" "spending key|not found|not know|does not hold" 0 z_exportkey "$(cli 1 z_getnewaddress)"
    # importprivkey with rescan
    fresh 2 || return
    ck "fresh wallet is empty" "$(bal 2)" 0.00000000
    cli 2 importprivkey "$WIF" "lab" true >/dev/null
    ck "importprivkey rescan: balance" "$(bal 2)" 5.00000000
    ckerr "importprivkey garbage" "invalid|encoding" 2 importprivkey "notakey"
    # importprivkey without rescan, then a restart with -rescan
    fresh 3 || return
    cli 3 importprivkey "$WIF" "" false >/dev/null
    ck "importprivkey no rescan: nothing seen yet" "$(bal 3)" 0.00000000
    stop 3; start 3 "$BIN" -connect=127.0.0.1:$((BASE + 1)) -rescan; sync_to 3
    ck "restart with -rescan finds the coins" "$(bal 3)" 5.00000000
    # z_importkey: rescan, no rescan, startHeight
    fresh 4 || return
    cli 4 z_importkey "$ZK" yes >/dev/null
    ck "z_importkey rescan yes: balance" "$(zbal 4 "$zs")" 4.00000000
    ck "z_importkey memo kept" "$(cli 4 z_listreceivedbyaddress "$zs" | jq -r '.[0].memo' | cut -c1-10)" 48656c6c6f
    ck "z_importkey twice is harmless" "$(cli 4 z_importkey "$ZK" no >/dev/null 2>&1; echo $?)" 0
    fresh 5 || return
    cli 5 z_importkey "$ZK" no >/dev/null
    ck "z_importkey no rescan: nothing seen yet" "$(zbal 5 "$zs")" 0.00000000
    stop 5; start 5 "$BIN" -connect=127.0.0.1:$((BASE + 1)) -rescan; sync_to 5
    ck "-rescan finds the z notes" "$(zbal 5 "$zs")" 4.00000000
    fresh 6 || return
    cli 6 z_importkey "$ZK" yes "$(cli 6 getblockcount)" >/dev/null
    ck "z_importkey startHeight at the tip misses older notes" "$(zbal 6 "$zs")" 0.00000000
    fresh 7 || return
    cli 7 z_importkey "$ZK" yes 0 >/dev/null
    ck "z_importkey startHeight 0 finds them" "$(zbal 7 "$zs")" 4.00000000
    ckerr "z_importkey garbage" "invalid|spending key" 7 z_importkey "garbage"
    # viewing keys: balance visible, cannot spend
    fresh 8 || return
    cli 8 z_importviewingkey "$VK" yes >/dev/null
    obs "viewingkey_z_getbalance" "$(errtxt 8 z_getbalance "$sp" 1)"
    ck "viewing key: z_gettotalbalance includeWatchonly" "$(cli 8 z_gettotalbalance 1 true | jq -r .private | f8)" 2.00000000
    ck "viewing key: z_listunspent includeWatchonly" "$(cli 8 z_listunspent 1 9999999 true | jq length)" 1
    ck "viewing key: note is not spendable" "$(cli 8 z_listunspent 1 9999999 true | jq -r '.[0].spendable')" false
    ck "viewing key: z_listunspent without watchonly" "$(cli 8 z_listunspent 1 9999999 false | jq length)" 0
    r=$(zsend 8 "$sp" "[{\"address\":\"$ta\",\"amount\":1}]"); case $r in failed*|rpcerror*) pass "viewing key cannot spend: $(printf %s "$r" | cut -c1-80)" ;; *) bad "viewing-key wallet spent: $r" ;; esac
    ck "z_exportviewingkey roundtrip" "$(cli 8 z_exportviewingkey "$sp" 2>&1 | head -c 12)" "$(printf %s "$VK" | head -c 12)"
    # dumpwallet / importwallet and z_exportwallet / z_importwallet
    cli 0 dumpwallet "tdump" >/dev/null; cli 0 z_exportwallet "zdump" >/dev/null
    ck "wallet files written to the export dir" "$([ -s "$SD/export/tdump" ] && [ -s "$SD/export/zdump" ] && echo yes)" yes
    ck "dumpwallet holds no z key" "$(grep -c "$ZK" "$SD/export/tdump")" 0
    ck "z_exportwallet holds the z key" "$(grep -c "$ZK" "$SD/export/zdump")" 1
    fresh 9 || return; cli 9 importwallet "$SD/export/tdump" >/dev/null
    ck "importwallet: t balance" "$(bal 9)" 5.00000000
    fresh 10 || return; cli 10 z_importwallet "$SD/export/zdump" >/dev/null
    ck "z_importwallet: t balance" "$(bal 10)" 5.00000000
    ck "z_importwallet: z balance" "$(zbal 10 "$zs")" 4.00000000
    ckerr "importwallet missing file" "open|cannot|exist|not" 10 importwallet "nosuchfile"
    # backupwallet then a restore into a fresh datadir
    s0=$(snap 0); cli 0 backupwallet "walletbackup" >/dev/null
    ck "backup file exists" "$([ -s "$SD/export/walletbackup" ] && echo yes)" yes
    mkdir -p "$SD/node11/regtest"; cp "$SD/export/walletbackup" "$SD/node11/regtest/wallet.dat"
    fresh 11 -rescan || return
    ck "restore: t balance" "$(bal 11)" 5.00000000
    ck "restore: z balance" "$(zbal 11 "$zs")" 4.00000000
    ck "restore: same unspent notes and coins" "$(snap 11 | sed 's/txs=.*//')" "$(printf %s "$s0" | sed 's/txs=.*//')"
    zconfirm 11 "$zs" "[{\"address\":\"$ta\",\"amount\":1}]" >/dev/null
    ck "restored wallet can spend its note" "$(zbal 11 "$zs")" "$(add 4 -1 -$FEE)"
    alive keys 11
}

# ---------------------------------------------------------------- 5
scn_encrypt() {
    setup2 || return
    ta=$(give_t 0 5); zs=$(cli 0 z_getnewaddress); give_z 0 "$zs" 4; sp=$(cli 0 z_getnewaddress sprout)
    other=$(cli 1 getnewaddress)
    cli 0 encryptwallet "pw1" >/dev/null 2>&1
    pid=$(cat "$SD/node0/pid"); t=0; while kill -0 "$pid" 2>/dev/null && [ $t -lt 120 ]; do t=$((t + 1)); sleep 1; done
    ck "encryptwallet stops the daemon" "$(kill -0 "$pid" 2>/dev/null && echo running || echo stopped)" stopped
    start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) || return
    sync_to 0
    ck "balance survives encryption + restart" "$(bal 0)" 5.00000000
    ck "z balance survives" "$(zbal 0 "$zs")" 4.00000000
    ck "wallet reports locked (unlocked_until 0)" "$(cli 0 getwalletinfo | jq -r .unlocked_until)" 0
    ckerr "sendtoaddress while locked" "unlock|locked|passphrase" 0 sendtoaddress "$other" 1
    r=$(zsend 0 "$zs" "[{\"address\":\"$other\",\"amount\":1}]"); case $r in *assphrase*|*nlock*|*ocked*) pass "z_sendmany while locked fails cleanly: $(printf %s "$r" | cut -c1-90)" ;; *) bad "z_sendmany while locked: $r" ;; esac; alive "z_sendmany while locked"; cli 0 getblockcount >/dev/null 2>&1 || { say "  (daemon died; restarting it, still locked)"; start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)); }
    # the same constructor path for a Sprout from-address (no notes needed: the key lookup comes first)
    r=$(zsend 0 "$sp" "[{\"address\":\"$other\",\"amount\":1}]"); case $r in *assphrase*|*nlock*|*ocked*) pass "z_sendmany from Sprout while locked fails cleanly" ;; *) bad "z_sendmany from Sprout while locked: $r" ;; esac; alive "z_sendmany from Sprout while locked"; cli 0 getblockcount >/dev/null 2>&1 || { say "  (daemon died; restarting it, still locked)"; start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)); }
    # every spending RPC refuses up front (a synchronous RPC error, not an opid that fails later)
    ckerr "z_sendmany from a t-address while locked" "assphrase" 0 z_sendmany "$ta" "[{\"address\":\"$other\",\"amount\":1}]"
    ckerr "z_sendmany from Sapling while locked is a direct RPC error" "assphrase" 0 z_sendmany "$zs" "[{\"address\":\"$other\",\"amount\":1}]"
    ckerr "z_sendmany from Sprout while locked is a direct RPC error" "assphrase" 0 z_sendmany "$sp" "[{\"address\":\"$other\",\"amount\":1}]"
    ckerr "z_mergetoaddress from Sprout while locked" "assphrase" 0 z_mergetoaddress "[\"$sp\"]" "$sp"
    ckerr "z_mergetoaddress from Sapling while locked" "assphrase" 0 z_mergetoaddress "[\"$zs\"]" "$zs"
    ckerr "z_mergetoaddress from t-addresses while locked" "assphrase" 0 z_mergetoaddress "[\"$ta\"]" "$zs"
    ckerr "z_shieldcoinbase while locked" "assphrase" 0 z_shieldcoinbase "*" "$zs"
    ckerr "z_exportkey while locked" "assphrase" 0 z_exportkey "$zs"
    alive "spending RPCs while locked"
    obs "z_getnewaddress_while_locked" "$(errtxt 0 z_getnewaddress | sed 's/OK:.*/OK/')"
    ckerr "dumpprivkey while locked" "unlock|locked|passphrase" 0 dumpprivkey "$ta"
    ckerr "walletpassphrase wrong" "incorrect|passphrase" 0 walletpassphrase "nope" 600
    cli 0 walletpassphrase pw1 600 >/dev/null
    ck "unlocked_until set" "$([ "$(cli 0 getwalletinfo | jq -r .unlocked_until)" -gt 0 ] && echo yes)" yes
    tx=$(cli 0 sendtoaddress "$other" 1); wait_mempool 1 "$tx"; f=$(fee_of 0 "$tx"); mine 1
    ck "t send unlocked" "$(bal 0)" "$(add 5 -1 "$f")"
    zconfirm 0 "$zs" "[{\"address\":\"$other\",\"amount\":1}]" >/dev/null
    ck "z send unlocked" "$(zbal 0 "$zs")" "$(add 4 -1 -$FEE)"
    ck "new z address unlocked" "$(cli 0 z_validateaddress "$(cli 0 z_getnewaddress)" | jq -r .ismine)" true
    cli 0 walletlock >/dev/null
    ck "walletlock" "$(cli 0 getwalletinfo | jq -r .unlocked_until)" 0
    ckerr "send after walletlock" "unlock|locked|passphrase" 0 sendtoaddress "$other" 1
    # incoming funds while locked are visible
    give_z 0 "$zs" 2; ck "z note received while locked is counted" "$(zbal 0 "$zs")" "$(add 4 -1 -$FEE 2)"
    give_t 0 1 >/dev/null; ck "t coins received while locked" "$(bal 0)" "$(add 5 -1 "$f" 1)"
    # passphrase change
    cli 0 walletpassphrasechange pw1 pw2 >/dev/null
    ckerr "old passphrase rejected after change" "incorrect|passphrase" 0 walletpassphrase pw1 60
    cli 0 walletpassphrase pw2 600 >/dev/null; ck "new passphrase unlocks" "$([ "$(cli 0 getwalletinfo | jq -r .unlocked_until)" -gt 0 ] && echo yes)" yes
    # keypool
    cli 0 keypoolrefill 25 >/dev/null; ck "keypoolrefill unlocked" "$([ "$(cli 0 getwalletinfo | jq -r .keypoolsize)" -ge 25 ] && echo yes)" yes
    cli 0 walletlock >/dev/null
    n=0; while a=$(cli 0 getnewaddress 2>/dev/null) && [ -n "$a" ] && [ $n -lt 60 ]; do n=$((n + 1)); done
    obs "getnewaddress_while_locked_until_keypool_empty" "$n"
    ck "at least the refilled keypool is usable while locked" "$([ $n -ge 25 ] && echo yes)" yes
    ckerr "keypoolrefill while locked" "unlock|locked|passphrase" 0 keypoolrefill 30
    # restart again, unlock, spend
    stop 0; start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) || return
    cli 0 walletpassphrase pw2 600 >/dev/null
    zconfirm 0 "$zs" "[{\"address\":\"$other\",\"amount\":0.5}]" >/dev/null
    ck "spend after second restart" "$(zbal 0 "$zs")" "$(add 4 -1 -$FEE 2 -0.5 -$FEE)"
    alive encrypt
}

# ---------------------------------------------------------------- 6
scn_crash() {
    setup2 || return
    ta=$(give_t 0 5); zs=$(cli 0 z_getnewaddress); give_z 0 "$zs" 4 6162
    ztx=$(cli 0 z_listunspent | jq -r '.[0].txid')
    s0=$(snap 0); total0=$(cli 0 z_gettotalbalance | jq -r .total | f8)
    R="-connect=127.0.0.1:$((BASE + 1))"
    # clean restart
    stop 0; start 0 "$BIN" $R; ck "clean restart" "$(snap 0)" "$s0"
    # -rescan, -zapwallettxes, -reindex
    stop 0; t0=$(now); start 0 "$BIN" $R -rescan; sync_to 0; ck "-rescan" "$(snap 0)" "$s0"; obs_t "rescan_start" "$(elapsed "$t0")"
    stop 0; t0=$(now); start 0 "$BIN" $R -zapwallettxes=2; sync_to 0; ck "-zapwallettxes=2" "$(snap 0 | sed 's/txs=.*//')" "$(printf %s "$s0" | sed 's/txs=.*//')"; obs_t "zapwallettxes_start" "$(elapsed "$t0")"
    stop 0; start 0 "$BIN" $R -zapwallettxes=1; sync_to 0; ck "-zapwallettxes=1" "$(snap 0 | sed 's/txs=.*//')" "$(printf %s "$s0" | sed 's/txs=.*//')"
    stop 0; t0=$(now); { start 0 "$BIN" $R -reindex || { say "  -reindex start failed; wiping block/chainstate of the TEMP datadir and resyncing"; rm -rf "$SD/node0/regtest/blocks" "$SD/node0/regtest/chainstate"; start 0 "$BIN" $R; }; }; sync_to 0; ck "-reindex with the wallet" "$(snap 0 | sed 's/txs=.*//')" "$(printf %s "$s0" | sed 's/txs=.*//')"; obs_t "reindex_start" "$(elapsed "$t0")"
    s0=$(snap 0)
    # restart with a pending z_sendmany: the operation is volatile
    other=$(cli 1 getnewaddress)
    op=$(cli 0 z_sendmany "$zs" "[{\"address\":\"$other\",\"amount\":1}]" 1 $FEE); stop 0; start 0 "$BIN" $R; sleep 2; sync_to 0
    rcv=$(cli 1 getreceivedbyaddress "$other" 0 | f8)
    ck "restart during z_sendmany: ops are gone" "$(cli 0 z_listoperationids | jq length)" 0
    exp=$total0; [ "$rcv" != 0.00000000 ] && exp=$(add "$total0" -1 -$FEE)
    obs "pending_op_stop_delivered" "$rcv"
    cli 1 generate 1 >/dev/null; sync_to 0
    ck "restart during z_sendmany: no double counting" "$(cli 0 z_gettotalbalance | jq -r .private | f8)" "$([ "$rcv" = 0.00000000 ] && echo 4.00000000 || add 4 -1 -$FEE)"
    zcur=$(cli 0 z_gettotalbalance | jq -r .private | f8)

    # kill -9 right after a transparent send reaches the mempool
    tb=$(bal 0 '*' 0); tx=$(cli 0 sendtoaddress "$other" 1); wait_mempool 1 "$tx"; f=$(fee_of 0 "$tx")
    kill9 0; start 0 "$BIN" $R
    known=$(cli 0 gettransaction "$tx" >/dev/null 2>&1 && echo yes || echo no); obs "t_send_known_to_wallet_after_kill9" "$known"
    obs "t_balance_after_kill9_minconf0_delta" "$(add "$(bal 0 '*' 0)" "-$tb")"
    cli 1 generate 1 >/dev/null; sync_to 0
    ck "after kill -9 + next block the t balance is chain-consistent" "$(bal 0)" "$(add "$tb" -1 "$f")"
    ck "after kill -9 the spent coin is not double counted (listunspent sum)" "$(cli 0 listunspent | jq '[.[].amount]|add // 0' | f8)" "$(bal 0)"
    stop 0; start 0 "$BIN" $R -rescan; sync_to 0; ck "-rescan after the kill -9 agrees" "$(bal 0)" "$(add "$tb" -1 "$f")"

    # kill -9 immediately after sendtoaddress returns (no wait for relay): what can the crash lose?
    tb=$(bal 0 '*' 0)
    tx=$(cli 0 sendtoaddress "$other" 0.5); kill9 0; start 0 "$BIN" $R
    known=$(cli 0 gettransaction "$tx" >/dev/null 2>&1 && echo yes || echo no)
    obs "t_send_immediate_kill9_wallet_knows_tx" "$known"
    obs "t_send_immediate_kill9_balance_delta_before_sync" "$(add "$(bal 0 '*' 0)" "-$tb")"
    obs "t_send_immediate_kill9_tx_in_peer_mempool_after_3s" "$(sleep 3; cli 1 getrawmempool | grep -c "$tx")"
    if [ "$known" = yes ]; then
        cli 1 sendrawtransaction "$(cli 0 gettransaction "$tx" | jq -r .hex)" >/dev/null 2>&1; wait_mempool 1 "$tx"
        f=$(fee_of 0 "$tx"); exp=$(add "$tb" -0.5 "$f")
    else exp=$tb; fi
    cli 1 generate 1 >/dev/null; sync_to 0
    ck "immediate kill -9: balance chain-consistent after the tx is (re)broadcast and mined" "$(bal 0)" "$exp"
    stop 0; start 0 "$BIN" $R -rescan; sync_to 0
    ck "immediate kill -9: -rescan agrees" "$(bal 0)" "$exp"

    # kill -9 during z_sendmany proving
    zb=$(cli 0 z_gettotalbalance | jq -r .private | f8)
    cli 0 z_sendmany "$zs" "[{\"address\":\"$other\",\"amount\":0.5}]" 1 $FEE >/dev/null; sleep 1; kill9 0
    start 0 "$BIN" $R; sleep 3; sync_to 0
    pend=$(cli 1 getrawmempool | jq length); obs "z_sendmany_proving_kill9_mempool_txs" "$pend"; cli 1 generate 1 >/dev/null; sync_to 0
    zz=$(cli 0 z_gettotalbalance | jq -r .private | f8)
    case $zz in "$zb") pass "kill -9 during proving: nothing sent, balance unchanged" ;; "$(add "$zb" -0.5 -$FEE)") pass "kill -9 during proving: tx completed, balance exact" ;; *) bad "kill -9 during proving: balance $zz from $zb" ;; esac
    stop 0; start 0 "$BIN" $R -rescan; sync_to 0; ck "-rescan after the proving kill -9 agrees" "$(cli 0 z_gettotalbalance | jq -r .private | f8)" "$zz"
    zb=$zz

    # kill -9 immediately after a z note is mined and connected
    ta3=$(cli 1 getnewaddress); cli 1 sendtoaddress "$ta3" 3 >/dev/null; cli 1 generate 1 >/dev/null
    r=$(zsend 1 "$ta3" "[{\"address\":\"$zs\",\"amount\":1.5,\"memo\":\"6364\"}]"); cli 1 generate 1 >/dev/null; sync_to 0
    kill9 0; start 0 "$BIN" $R
    obs "z_note_after_connect_kill9_immediate" "$(zbal 0 "$zs" | f8)"
    sleep 3
    obs "z_note_after_connect_kill9_after_3s" "$(cli 0 z_gettotalbalance | jq -r .private | f8)"
    stop 0; start 0 "$BIN" $R -rescan; sync_to 0
    ck "-rescan recovers the note received before the kill -9" "$(cli 0 z_gettotalbalance | jq -r .private | f8)" "$(add "$zb" 1.5)"
    ck "memo recovered" "$(cli 0 z_listreceivedbyaddress "$zs" | jq -r '[.[]|select(.memo|startswith("6364"))]|length')" 1

    # kill -9 while blocks (with payments to us) connect
    tb=$(bal 0)
    ( for i in 1 2 3 4 5 6; do cli 1 sendtoaddress "$ta" 1 >/dev/null; cli 1 generate 15 >/dev/null; done ) & bgp=$!
    sleep 4; kill9 0; wait "$bgp"
    start 0 "$BIN" $R; sync_to 0
    ck "kill -9 while blocks connect: t balance exact after sync" "$(bal 0)" "$(add "$tb" 6)"
    ck "kill -9 while blocks connect: chain agrees with the peer" "$(cli 0 getbestblockhash)" "$(cli 1 getbestblockhash)"
    ck "kill -9 while blocks connect: listunspent sum" "$(cli 0 listunspent | jq '[.[].amount]|add' | f8)" "$(bal 0)"
    stop 0; start 0 "$BIN" $R -rescan; sync_to 0; ck "-rescan agrees at the end" "$(bal 0)" "$(add "$tb" 6)"
    alive crash
}
obs_t() { echo "$SCN_ID.$1 = $2" >>"$WORK/timings.txt"; say "  time $1 = ${2}s"; }
