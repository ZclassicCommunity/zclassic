#!/bin/sh
# Retired witnesses on regtest (CWallet::RetireSpentNotes): a wallet with many notes, most of
# them spent, a chain that buries the spends deeper than the witness cache, and the ways that
# state can be lost or contradicted: restart with and without -rescan, a hard kill at every step of
# the wallet checkpoint, a reorg of 50 blocks, an operator invalidateblock deeper than the cache
# that un-spends retired notes, and a wallet.dat that older binaries open.
#
# Every scenario compares the wallet that ran (or restarted WITHOUT -rescan) with a copy of the same
# datadir restarted WITH -rescan: z_gettotalbalance, z_listunspent and listunspent must be equal,
# and a shielded spend of a note that was unspent must still be accepted and mined by the peer.
#
# The wallet: 60 Sapling addresses, 5 notes of 0.2 on each (five transactions of 60 outputs: 300
# notes); 48 of the addresses are emptied by one spend each (240 notes spent, 48 change notes), all
# mined in one block; 12 addresses keep their 5 notes. The first spend is 96 blocks deep when the
# scenarios start (the witness cache holds 100).
#
#   1 buried      20 more blocks: the spends are 116 deep and retired; restart plain / -rescan / plain
#   2 crash       _exit(77) at each step of the checkpoint while the spends cross the limit
#   3 reorg50     a recent spend 31 deep, 50 blocks unwound by a longer branch from the peer
#   4 deepunwind  operator invalidateblock 117 blocks deep: the retired notes are unspent again
#                 (a running wallet; then a restarted one, on a new branch that spends them again)
#   5 downgrade   the wallet.dat of scenario 1 opened by the previous release and by the parent
#                 commit's build: blocks mined, importprivkey and z_importkey with rescan, a restart, a
#                 spend of an unrelated note, balances and note counts equal the -rescan reference; then
#                 opened again by this build (equal to a -rescan of the same wallet.dat); then 1, 2 and 3
#                 block disconnects as the FIRST events on the older binary, followed by z_importkey with
#                 rescan, must leave balances and notes equal; 4 disconnects are recorded (the stated limit)
#                 and a 97-block unwind by this build, then the older binary mines on it without aborting
#
#   6 stalechain  kill -9 between the wallet checkpoint and the coins flush: the chain restarts below the
#                 checkpoint; retired notes need no rescan
#
# usage: wallet_witness_retire.sh --bin <dir> --work <dir> [--peer-bin <dir>] [--old-bin <dir>]
#            [--parent-bin <dir>] [--only 1,2,..] [--reuse-template] [--base port]
#            [--addrs N] [--per-addr N] [--spent-addrs N]
#   --bin         zclassicd/zclassic-cli under test
#   --peer-bin    the miner node (default: --bin)
#   --old-bin     previous release (scenario 5); --parent-bin the build of the parent commit
#   --reuse-template  use the template datadirs of an earlier run in --work (the proofs of the
#                 300 notes take most of the time)
# Output: <work>/results.txt. Exit status 0 when every scenario passed.
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
BIN=""; WORK=""; PEER_BIN=""; OLD_BIN=""; PARENT_BIN=""; ONLY=""; PORT_BASE=""; NA=60; NPA=5; NSA=48; REUSE=0
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;;
        --old-bin) OLD_BIN=$2; shift 2 ;; --parent-bin) PARENT_BIN=$2; shift 2 ;;
        --only) ONLY=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;; --reuse-template) REUSE=1; shift ;;
        --addrs) NA=$2; shift 2 ;; --per-addr) NPA=$2; shift 2 ;; --spent-addrs) NSA=$2; shift 2 ;;
        *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--peer-bin DIR] [--old-bin DIR] [--parent-bin DIR] [--only N,N]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$BIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; OBS_LOG=$WORK/obs.txt; : >"$RESULTS"; : >"$OBS_LOG"
BASE=${PORT_BASE:-$((20000 + ($$ % 20000)))}
TPL=$WORK/template
trap 'stop_all' EXIT
R1="-connect=127.0.0.1:$((BASE + 1))"
NOTEV=0.2                 # value of every note
BURIED=96                 # depth of the spends in the template (the cache holds 100)

# snap <n>: totals, notes and unspent outputs, exact
snap() {
    printf 'z=%s t=%s notes=%s utxo=%s' "$(cli "$1" z_gettotalbalance 1 | jq -c '[.transparent,.private]')" "$(bal "$1" '*' 1)" \
        "$(cli "$1" z_listunspent 1 | jq -c '[.[]|(.amount*100000000|round)]|sort')" \
        "$(cli "$1" listunspent 1 | jq -c '[.[]|.txid[0:8]+":"+(.vout|tostring)]|sort')"
}
nnotes() { cli "$1" z_listunspent 1 | jq length; }
ztot() { n8 "$(cli "$1" z_gettotalbalance 1 | jq -r .private)"; }
confirmations() { cli 0 gettransaction "$1" | jq -r .confirmations; }
# refsnap <connect arg> [extra args]: node 0 is stopped; a copy of its datadir restarted with -rescan on node 3
refsnap() {
    local c=$1; shift
    rm -rf "$SD/node3"; cp -a "$SD/node0" "$SD/node3"; rm -f "$SD/node3/regtest/.lock"
    start 3 "$BIN" $c -rescan -disablesafemode "$@" || return 1
    if [ "$c" != "-connect=0" ]; then sync_to 3; fi
    REF=$(snap 3); REFTIP=$(cli 3 getbestblockhash); stop 3
}
spend_check() { # <label> <zaddr> <balance-before> <amount>: a shielded spend is accepted and mined by the peer
    local l=$1 zs=$2 b=$3 amt=$4 ta
    ta=$(cli 1 getnewaddress)
    zconfirm 0 "$zs" "[{\"address\":\"$ta\",\"amount\":$amt}]" >/dev/null
    ck "$l: shielded spend accepted and mined by the peer, exact balance" "$(zbal 0 "$zs")" "$(add "$b" -$amt -$FEE)"
}
start_pair() { # [node 0 extra args]: miner first, then the wallet under test
    start 1 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 0)) || return 1
    start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) -disablesafemode "$@" || return 1
}
alive_n() { [ -f "$SD/node$1/pid" ] && kill -0 "$(cat "$SD/node$1/pid")" 2>/dev/null; }

# ---- the template: notes received, notes spent, the spends BURIED blocks deep -----------------
build_template() {
    SD=$TPL; SCN_ID=0; SCN_LOG=$WORK/template.log; : >"$SCN_LOG"
    rm -rf "$SD"; mkdir -p "$SD"
    setup2 -disablesafemode || return 1
    : >"$SD/zaddrs"; i=1
    while [ $i -le $NA ]; do cli 0 z_getnewaddress >>"$SD/zaddrs"; i=$((i + 1)); done
    rec=$(jq -R -s -c --argjson v $NOTEV 'split("\n")|map(select(length>0))|map({address:.,amount:$v})' "$SD/zaddrs")
    i=1; t0=$(now)
    while [ $i -le $NPA ]; do
        ta=$(cli 1 getnewaddress)
        cli 1 sendtoaddress "$ta" "$(add "$(awk -v n=$NA -v v=$NOTEV 'BEGIN{printf "%.8f", n*v}')" 1)" >/dev/null
        cli 1 generate 1 >/dev/null
        r=$(zsend 1 "$ta" "$rec" 1 "$FEE")
        case $r in success*) cli 1 generate 1 >/dev/null; sync_to 0 ;; *) bad "template: funding $i: $r"; return 1 ;; esac
        i=$((i + 1))
    done
    say "  funded $((NA * NPA)) notes in $(elapsed $t0)s"
    TOTAL=$(awk -v n=$NA -v p=$NPA -v v=$NOTEV 'BEGIN{printf "%.8f", n*p*v}')
    ck "template: all notes received" "$(ztot 0)" "$TOTAL"
    ck "template: note count" "$(nnotes 0)" "$((NA * NPA))"
    tm=$(cli 1 getnewaddress); echo "$tm" >"$SD/tm"
    SPENT_AMT=$(awk -v n=$NPA -v v=$NOTEV 'BEGIN{printf "%.8f", n*v-0.1}')   # needs all the notes of the address plus a change note
    : >"$SD/spends"; i=1; t0=$(now)
    while [ $i -le $NSA ]; do
        a=$(sed -n "${i}p" "$SD/zaddrs")
        r=$(zsend 0 "$a" "[{\"address\":\"$tm\",\"amount\":$SPENT_AMT}]" 1 "$FEE")
        case $r in success*) echo "${r#success }" >>"$SD/spends" ;; *) bad "template: spend $i: $r"; return 1 ;; esac
        i=$((i + 1))
    done
    wait_mempool 1 "$(head -1 "$SD/spends")"; wait_mempool 1 "$(tail -1 "$SD/spends")"; mine 1
    say "  $NSA spends of $NPA notes mined in $(elapsed $t0)s"
    EXPECT=$(add "$TOTAL" -$(awk -v n=$NSA -v a=$SPENT_AMT -v f=$FEE 'BEGIN{printf "%.8f", n*(a+f)}'))
    echo "$EXPECT" >"$SD/expect"
    t=0; while [ "$(ztot 0)" != "$EXPECT" ] && [ $t -lt 90 ]; do sleep 1; t=$((t + 1)); done   # the wallet credits the change when it has processed the block
    ck "template: balance after the spends" "$(ztot 0)" "$EXPECT"
    first=$(head -1 "$SD/spends")
    ck "template: spends in one block" "$(confirmations "$first")" "$(confirmations "$(tail -1 "$SD/spends")")"
    while [ "$(confirmations "$first")" -lt $BURIED ]; do cli 1 generate 1 >/dev/null; sync_to 0 || return 1; done
    ck "template: spend depth" "$(confirmations "$first")" "$BURIED"
    ck "template: balance" "$(ztot 0)" "$EXPECT"
    stop 0; stop 1
    return 0
}
# from_template: node directories copied from the template, both nodes started
from_template() { # [node 0 extra args]
    rm -rf "$SD"; mkdir -p "$SD"
    cp -a "$TPL/node0" "$SD/node0"; cp -a "$TPL/node1" "$SD/node1"
    cp "$TPL/zaddrs" "$TPL/tm" "$TPL/spends" "$TPL/expect" "$SD/"
    rm -f "$SD/node0/regtest/.lock" "$SD/node1/regtest/.lock" "$SD/node0/pid" "$SD/node1/pid"
    ZS=$(tail -1 "$SD/zaddrs"); ZSB=$(awk -v p=$NPA -v v=$NOTEV 'BEGIN{printf "%.8f", p*v}')   # an address that was never spent from
    EXPECT=$(cat "$SD/expect"); TOTAL=$(awk -v n=$NA -v p=$NPA -v v=$NOTEV 'BEGIN{printf "%.8f", n*p*v}')
    start_pair "$@"
}

scn_buried() {
    from_template -debug=wallet || return
    first=$(head -1 "$SD/spends")
    mine 20
    ck "buried: first spend depth" "$(confirmations "$first")" "$((BURIED + 20))"
    ck "buried: balance" "$(ztot 0)" "$EXPECT"
    obs "unspent notes (never spent + change)" "$(nnotes 0)"
    ck "buried: fewer notes than were received" "$([ "$(nnotes 0)" -lt $((NA * NPA)) ] && echo yes)" yes
    # evidence that notes were retired while running: the last sweep line says how many
    # transactions still carry live notes (the 5 funding transactions, the change)
    live=$(grep "note records changed" "$SD/node0/regtest/debug.log" | tail -1 | sed 's/.*, \([0-9]*\) transactions with live notes remain.*/\1/')
    nrec=$(grep -c "note records changed" "$SD/node0/regtest/debug.log")
    obs "sweeps that retired notes" "$nrec"; obs "transactions with live notes after the sweeps" "$live"
    ck "buried: notes were retired by the running wallet" "$([ "${nrec:-0}" -ge 1 ] && echo yes)" yes
    ck "buried: live transactions are the funding ones and the change" "$([ "${live:-999}" -le $((NPA + NSA)) ] && echo yes)" yes
    A=$(snap 0)
    stop 0; stop 1
    refsnap "-connect=0" || return
    start 0 "$BIN" -connect=0 -disablesafemode -debug=wallet || return        # plain restart, no -rescan
    ck "buried: restart without -rescan equals the -rescan reference" "$(snap 0)" "$REF"
    ck "buried: restart equals the wallet before the restart" "$(snap 0)" "$A"
    ck "buried: the start-up asked for no rescan" "$(grep -c 'Rescanning last' "$SD/node0/regtest/debug.log")" 0
    stop 0
    start 0 "$BIN" -connect=0 -disablesafemode -rescan || return              # and with -rescan
    ck "buried: restart with -rescan equals the reference" "$(snap 0)" "$REF"
    stop 0
    start 0 "$BIN" -connect=0 -disablesafemode || return                      # plain again, after the rescan
    ck "buried: restart after the rescan equals the reference" "$(snap 0)" "$REF"
    stop 0
    start 1 "$PEER_BIN" -connect=0 || return
    start 0 "$BIN" $R1 -disablesafemode || return; sync_to 0
    spend_check buried "$ZS" "$ZSB" 0.25
    stop 0; stop 1
    rm -rf "$WORK/final0"; cp -a "$SD/node0" "$WORK/final0"; rm -f "$WORK/final0/regtest/.lock"
    echo "$ZS" >"$WORK/final.zs"
}

# one crash scenario: the wallet dies at a step of the checkpoint while the spends cross the limit
crash_variant() { # <point> <hit>
    local p=$1 k=$2 i
    from_template -testsetchaininterval=0 "-testcrashpoint=$p:$k" -debug=wallet || return
    i=0
    while alive_n 0 && [ $i -lt 40 ]; do cli 1 generate 1 >/dev/null 2>&1; i=$((i + 1)); sleep 0.5; done
    # a loaded host applies the blocks slowly: wait for the node to reach the hook (up to 10 minutes)
    w=0; while alive_n 0 && [ $w -lt 600 ]; do w=$((w + 1)); sleep 1; done
    if alive_n 0; then bad "$p: the crash hook did not fire after $i blocks"; kill9 0; return; fi
    pass "$p: node died at the hook after $i blocks"
    rm -f "$SD/node0/regtest/.lock"
    stop 1; start 1 "$PEER_BIN" -connect=0 || return
    refsnap "-connect=0" || return
    start 0 "$BIN" -connect=0 -disablesafemode || return                       # plain restart, no -rescan
    ck "$p: restart without -rescan equals the -rescan reference" "$(snap 0)" "$REF"
    ck "$p: same tip as the reference" "$(cli 0 getbestblockhash)" "$REFTIP"
    stop 0
    start 0 "$BIN" $R1 -disablesafemode || return; sync_to 0
    cli 1 generate 3 >/dev/null; sync_to 0
    stop 0
    refsnap "$R1" || return
    start 0 "$BIN" $R1 -disablesafemode || return; sync_to 0
    ck "$p: at the peer's tip the wallet equals the -rescan reference" "$(snap 0)" "$REF"
    spend_check "$p" "$ZS" "$ZSB" 0.25
}
scn_crash() {
    local pt
    for pt in setbestchain-begin setbestchain-after-txs setbestchain-after-locator setbestchain-after-commit; do
        stop_all; SD=$WORK/s2$pt; rm -rf "$SD"; mkdir -p "$SD"
        BASE=$((BASE + 7)); R1="-connect=127.0.0.1:$((BASE + 1))"
        crash_variant "$pt" 14
    done
    stop_all
}

scn_reorg50() {
    from_template -debug=wallet || return
    mine 10
    tm=$(cat "$SD/tm")
    t=$(zconfirm 0 "$ZS" "[{\"address\":\"$tm\",\"amount\":0.5}]")      # a recent spend
    mine 30
    ck "reorg50: the recent spend is 31 deep" "$(confirmations "$t")" 31
    H=$(cli 1 getblockcount)
    first=$(cli 1 getblockhash $((H - 49)))                              # 50 blocks go
    # a fork deeper than 3 blocks is parked until it has twice the work: the new branch is 102 long
    cli 1 invalidateblock "$first" >/dev/null; cli 1 generate 102 >/dev/null
    sync_to 0 || return
    ck "reorg50: the wallet follows the longer branch" "$(cli 0 getblockcount)" "$((H - 50 + 102))"
    alive "reorg50 after the reorg" 0
    stop 0; stop 1
    refsnap "-connect=0" || return
    start 0 "$BIN" -connect=0 -disablesafemode || return
    ck "reorg50: restart without -rescan equals the -rescan reference" "$(snap 0)" "$REF"
    stop 0
    start 1 "$PEER_BIN" -connect=0 || return
    start 0 "$BIN" $R1 -disablesafemode || return; sync_to 0
    ck "reorg50: at the peer's tip, equal to the reference" "$(snap 0)" "$REF"
    spend_check reorg50 "$ZS" "$(zbal 0 "$ZS")" 0.1
}

scn_deepunwind() {
    from_template -debug=wallet || return
    first=$(head -1 "$SD/spends")
    mine 20
    ck "deepunwind: spend depth" "$(confirmations "$first")" "$((BURIED + 20))"
    A=$(snap 0)
    fb=$(cli 0 gettransaction "$first" | jq -r .blockhash)
    h=$(cli 0 getblockcount); fh=$(cli 0 getblockheader "$fb" | jq -r .height)
    obs "blocks unwound" "$((h - fh + 1))"
    # a: the running wallet is unwound (the spends return to the mempool, so they still count as
    # spending), then everything is reconsidered: no restart in between
    cli 0 invalidateblock "$fb" >/dev/null 2>&1
    ck "deepunwind: unwound to the block before the spends" "$(cli 0 getblockcount)" "$((fh - 1))"
    alive "deepunwind after the unwind" 0
    cli 0 reconsiderblock "$fb" >/dev/null 2>&1; sync_to 0
    ck "deepunwind: running wallet back at the tip equals the first state" "$(snap 0)" "$A"
    spend_check deepunwind-a "$ZS" "$ZSB" 0.25
    stop 0; stop 1

    # b: both nodes unwind, restart with empty mempools and no wallet re-broadcast, so the spends
    # are really gone: the 240 retired notes are unspent, and the wallet restarts without -rescan
    # the peer is this build too: an older binary does not keep an invalidateblock across a restart
    PEER_BIN=$BIN; from_template -debug=wallet || return
    mine 20
    cli 0 invalidateblock "$fb" >/dev/null 2>&1; cli 1 invalidateblock "$fb" >/dev/null 2>&1
    ck "deepunwind: both nodes at the block before the spends" "$(cli 0 getblockcount)" "$((fh - 1))"
    stop 0; stop 1
    refsnap "-connect=0" -walletbroadcast=0 || return
    ck "deepunwind: the -rescan reference counts every note again" "$(n8 "$(printf '%s' "$REF" | sed 's/.*z=\[[^,]*,"\([^"]*\)"\].*/\1/')")" "$TOTAL"
    start 0 "$BIN" -connect=0 -disablesafemode -walletbroadcast=0 -debug=wallet || return
    ck "deepunwind: restart without -rescan equals the -rescan reference" "$(snap 0)" "$REF"
    ck "deepunwind: every note is counted again" "$(ztot 0)" "$TOTAL"
    ck "deepunwind: note count" "$(nnotes 0)" "$((NA * NPA))"
    # a spend of a note that was retired: built from the rebuilt witness, proved, and accepted by the
    # node's own mempool rules (anchor, proof, nullifier)
    old=$(sed -n 1p "$SD/zaddrs"); ta=$(cli 0 getnewaddress)
    r=$(zsend 0 "$old" "[{\"address\":\"$ta\",\"amount\":0.25}]" 1 "$FEE")
    ck "deepunwind: a retired note is spent again at the lowered tip (witness rebuilt)" "${r%% *}" success
    case $r in success*) ck "deepunwind: the spend is in the node's mempool" "$(cli 0 getrawmempool | jq -r --arg t "${r#success }" 'index($t) != null')" true ;; esac
}

zn() { sed 's/ t=[^ ]*//; s/ utxo=.*//'; }
scn_downgrade() {
    [ -d "$WORK/final0" ] || { bad "downgrade: needs the state left by scenario 1"; return; }
    local entry label bd s s2
    for entry in "previous-release:$OLD_BIN" "parent-commit:$PARENT_BIN"; do
        label=${entry%%:*}; bd=${entry#*:}
        if [ -z "$bd" ] || [ ! -x "$bd/zclassicd" ]; then say "  (no $label binary given, skipped)"; continue; fi
        rm -rf "$SD/node3" "$SD/node5"; mkdir -p "$SD"
        cp -a "$WORK/final0" "$SD/node3"; rm -f "$SD/node3/regtest/.lock"
        cp -a "$WORK/final0" "$SD/node5"; rm -f "$SD/node5/regtest/.lock"
        start 3 "$BIN" -connect=0 -rescan -disablesafemode || return; REF=$(snap 3)
        K=$(cli 3 dumpprivkey "$(cli 3 getnewaddress)"); ZK=$(cli 3 z_exportkey "$(cli 3 z_getnewaddress)")
        ZSU=$(tail -1 "$TPL/zaddrs"); ZSB=$(zbal 3 "$ZSU"); stop 3
        M=$(wc -l <"$SD/node5/regtest/debug.log")
        start 5 "$bd" -connect=0 -disablesafemode
        if ! alive_n 5 || ! cli 5 getblockcount >/dev/null 2>&1; then
            bad "downgrade $label: the binary did not start on this wallet.dat: $(tail -3 "$SD/node5/stdout.log" | tr '\n' ' ')"; continue
        fi
        ck "downgrade $label: opens the wallet; balances, notes and outputs as the -rescan reference" "$(snap 5)" "$REF"
        cli 5 generate 4 >/dev/null 2>&1
        # a disconnect (witness decrement) and the flush it forces (the wallet checkpoint) on the older binary
        tb=$(cli 5 getbestblockhash); cli 5 invalidateblock "$tb" >/dev/null 2>&1; cli 5 reconsiderblock "$tb" >/dev/null 2>&1
        ck "downgrade $label: mined 4 blocks on it (witness updates ran), alive" "$(cli 5 getblockcount >/dev/null 2>&1 && echo yes)" yes
        ck "downgrade $label: shielded balance and notes unchanged after the blocks" "$(snap 5 | zn)" "$(printf '%s' "$REF" | zn)"
        ck "downgrade $label: no assertion in the logs" "$(cat "$SD/node5/stdout.log" "$SD/node5/regtest/debug.log" | grep -ci 'assertion\|Aborted')" 0
        obs "$label: its own log lines about a rescan, repair or retire" "$(tail -n +$((M + 1)) "$SD/node5/regtest/debug.log" | grep -ci 'Rescanning last\|note state\|retire')"
        # imports that rescan from below the notes, on the older binary: it must not lose track of the
        # spent notes (it used to erase the nullifier of a note without a witness and count it unspent)
        cli 5 importprivkey "$K" "" true >/dev/null 2>&1
        ck "downgrade $label: importprivkey with rescan: balances and notes as the -rescan reference" "$(snap 5 | zn)" "$(printf '%s' "$REF" | zn)"
        cli 5 z_importkey "$ZK" yes >/dev/null 2>&1
        ck "downgrade $label: z_importkey with rescan: balances and notes as the -rescan reference" "$(snap 5 | zn)" "$(printf '%s' "$REF" | zn)"
        cli 5 generate 1 >/dev/null 2>&1
        ck "downgrade $label: one more block: balances and notes unchanged" "$(snap 5 | zn)" "$(printf '%s' "$REF" | zn)"
        ck "downgrade $label: a spent address keeps only its change note" "$(zbal 5 "$(sed -n 1p "$TPL/zaddrs")")" 0.09990000
        stop 5
        start 5 "$bd" -connect=0 -disablesafemode || return
        ck "downgrade $label: restart: balances and notes as the -rescan reference" "$(snap 5 | zn)" "$(printf '%s' "$REF" | zn)"
        # an unrelated unspent note is still spendable on it
        ck "downgrade $label: the unrelated address holds its 5 notes" "$(zbal 5 "$ZSU")" "$ZSB"
        ta=$(cli 5 getnewaddress); r=$(zsend 5 "$ZSU" "[{\"address\":\"$ta\",\"amount\":0.1}]" 1 "$FEE")
        ck "downgrade $label: a spend of an unrelated unspent note is accepted" "${r%% *}" success
        cli 5 generate 1 >/dev/null 2>&1
        ck "downgrade $label: that spend is mined, exact balance" "$(zbal 5 "$ZSU")" "$(add "$ZSB" -0.1 -$FEE)"
        S5=$(snap 5 | zn)
        stop 5
        # this build reads what the older binary wrote
        M=$(wc -l <"$SD/node5/regtest/debug.log")
        start 5 "$BIN" -connect=0 -disablesafemode -debug=wallet || return
        s2=$(snap 5)
        ck "downgrade $label: this build reads it back, shielded balance and notes unchanged" "$(printf '%s' "$s2" | zn)" "$S5"
        obs "$label: this build's start-up note state lines" "$(tail -n +$((M + 1)) "$SD/node5/regtest/debug.log" | grep 'Wallet note state' | cut -c21-260 | tr '\n' '|')"
        obs "$label: this build's rescan lines" "$(tail -n +$((M + 1)) "$SD/node5/regtest/debug.log" | grep -c 'Rescanning last')"
        stop 5
        rm -rf "$SD/node6"; cp -a "$SD/node5" "$SD/node6"; rm -f "$SD/node6/regtest/.lock" "$SD/node6/pid"
        start 6 "$BIN" -connect=0 -rescan -disablesafemode || return
        ck "downgrade $label: this build, opened again, equals a -rescan of the same wallet.dat" "$(snap 6 | zn)" "$S5"
        stop 6
        # a deep unwind by this build that reaches no retired spend (97 blocks: the witness cache size drops to 3), then
        # the older binary: the frozen witnesses must not outnumber the stored cache size or it aborts at its first block
        rm -rf "$SD/node5"; cp -a "$WORK/final0" "$SD/node5"; rm -f "$SD/node5/regtest/.lock" "$SD/node5/pid"
        start 5 "$BIN" -connect=0 -disablesafemode || return
        j=0; while [ $j -lt 97 ]; do cli 5 invalidateblock "$(cli 5 getbestblockhash)" >/dev/null 2>&1; j=$((j + 1)); done
        stop 5
        start 5 "$bd" -connect=0 -disablesafemode
        if ! alive_n 5 || ! cli 5 getblockcount >/dev/null 2>&1; then
            bad "downgrade $label: after a 97-block unwind by this build the binary did not start: $(tail -3 "$SD/node5/stdout.log" | tr '\n' ' ')"
        else
            cli 5 generate 3 >/dev/null 2>&1
            ck "downgrade $label: after a 97-block unwind: mined 3 blocks, alive" "$(cli 5 getblockcount >/dev/null 2>&1 && echo yes)" yes
            ck "downgrade $label: after a 97-block unwind: balances and notes as the -rescan reference" "$(snap 5 | zn)" "$(printf "%s" "$REF" | zn)"
            ck "downgrade $label: after a 97-block unwind: no assertion in the logs" "$(cat "$SD/node5/stdout.log" "$SD/node5/regtest/debug.log" | grep -ci 'assertion\|Aborted')" 0
            stop 5
            start 5 "$bd" -connect=0 -disablesafemode || return
            ck "downgrade $label: after a 97-block unwind: restart, alive" "$(cli 5 getblockcount >/dev/null 2>&1 && echo yes)" yes
            ck "downgrade $label: after a 97-block unwind: restart, balances and notes as the -rescan reference" "$(snap 5 | zn)" "$(printf "%s" "$REF" | zn)"
            stop 5
        fi
        # the first events on the older binary are block disconnects (an orphaned tip, invalidateblock): it pops one
        # frozen witness per block, so up to RETIRED_WITNESSES_KEPT - 1 = 3 are survived; 4 are the stated limit
        for k in 1 2 3 4; do
            # the reference for this chain height: the same blocks invalidated, then a -rescan, by this build
            rm -rf "$SD/node3"; cp -a "$WORK/final0" "$SD/node3"; rm -f "$SD/node3/regtest/.lock" "$SD/node3/pid"
            start 3 "$BIN" -connect=0 -disablesafemode || return
            j=0; while [ $j -lt $k ]; do cli 3 invalidateblock "$(cli 3 getbestblockhash)" >/dev/null 2>&1; j=$((j + 1)); done
            stop 3
            start 3 "$BIN" -connect=0 -rescan -disablesafemode || return; REFK=$(snap 3); stop 3
            rm -rf "$SD/node5"; cp -a "$WORK/final0" "$SD/node5"; rm -f "$SD/node5/regtest/.lock" "$SD/node5/pid"
            start 5 "$bd" -connect=0 -disablesafemode || return
            j=0; while [ $j -lt $k ]; do cli 5 invalidateblock "$(cli 5 getbestblockhash)" >/dev/null 2>&1; j=$((j + 1)); done
            cli 5 z_importkey "$ZK" yes >/dev/null 2>&1
            if [ $k -le 3 ]; then
                ck "downgrade $label: $k disconnects first, then z_importkey with rescan: balances and notes as the -rescan reference" "$(snap 5 | zn)" "$(printf "%s" "$REFK" | zn)"
                stop 5
            else
                obs "$label: 4 disconnects first, then z_importkey with rescan: unspent notes (the reference has 107)" "$(nnotes 5)"
                stop 5
                start 5 "$BIN" -connect=0 -disablesafemode -debug=wallet || return
                ck "downgrade $label: 4 disconnects first: this build repairs it at its next start (balances and notes as the reference)" "$(snap 5 | zn)" "$(printf "%s" "$REFK" | zn)"
                stop 5
            fi
        done
    done
}

# a hard kill between the wallet checkpoint and the flush of the coins: the chain restarts below the
# checkpoint, so the spends that retired the notes are only 96 deep again. A retired note spent by a
# mined wallet transaction needs no rescan from its own height.
scn_staleckpt() {
    from_template -testsetchaininterval=0 -debug=wallet || return
    first=$(head -1 "$SD/spends")
    mine 20
    ck "stale checkpoint: the spends are 116 deep and retired while running" "$(confirmations "$first")" "$((BURIED + 20))"
    ck "stale checkpoint: notes were retired by the running wallet" "$([ "$(grep -c 'note records changed' "$SD/node0/regtest/debug.log")" -ge 1 ] && echo yes)" yes
    kill9 0; kill9 1
    start 1 "$PEER_BIN" -connect=0 || return
    refsnap "-connect=0" || return
    M=$(wc -l <"$SD/node0/regtest/debug.log")
    start 0 "$BIN" -connect=0 -disablesafemode -debug=wallet || return
    ck "stale checkpoint: the chain restarted below the checkpoint (spends 96 deep)" "$(confirmations "$first")" "$BURIED"
    ck "stale checkpoint: restart without -rescan equals the -rescan reference" "$(snap 0)" "$REF"
    ck "stale checkpoint: same tip as the reference" "$(cli 0 getbestblockhash)" "$REFTIP"
    n=$(tail -n +$((M + 1)) "$SD/node0/regtest/debug.log" | grep 'Rescanning last' | tail -1 | sed 's/.*Rescanning last \([0-9]*\) blocks.*/\1/')
    obs "blocks rescanned at the restart" "${n:-0}"
    ck "stale checkpoint: no rescan from the heights of retired notes (the lag is 20 blocks)" "$([ "${n:-0}" -le 25 ] && echo yes)" yes
    ck "stale checkpoint: no confirmed note without a witness" "$(tail -n +$((M + 1)) "$SD/node0/regtest/debug.log" | grep -c '[1-9][0-9]* confirmed notes without witness')" 0
    stop 0
    stop 1
}

run_scn() {
    id=$1; name=$2; fn=$3
    if [ -n "$ONLY" ]; then case ",$ONLY," in *",$id,"*) ;; *) return 0 ;; esac; fi
    SCN_ID=$id; SCN_LOG=$WORK/scn$id.log; SD=$WORK/s$id; : >"$SCN_LOG"
    say "== $id. $name"
    ( $fn ) 2>&1 | tee "$WORK/scn$id.out" >/dev/null
    stop_all
    np=$(grep -c '^PASS' "$SCN_LOG"); nf=$(grep -c '^FAIL' "$SCN_LOG")
    st=PASS; [ "$nf" = 0 ] && [ "$np" -gt 0 ] || st=FAIL
    echo "$id|$name|$st|$np pass $nf fail" >>"$RESULTS"
    say "   -> $st ($np pass, $nf fail)"
    BASE=$((BASE + 11)); [ $BASE -lt 60000 ] || BASE=20000
    R1="-connect=127.0.0.1:$((BASE + 1))"
}

if [ "$REUSE" = 1 ] && [ -d "$TPL/node0" ] && [ -f "$TPL/expect" ]; then
    say "== template: reusing $TPL"
else
    say "== template ($((NA * NPA)) notes, $NSA spends of $NPA notes)"
    ( build_template ) 2>&1 | tee "$WORK/template.out" >/dev/null
    SD=$TPL; stop_all
    nf=$(grep -c '^FAIL' "$WORK/template.log"); [ "$nf" = 0 ] || { echo "template failed"; cat "$WORK/template.log"; exit 1; }
    BASE=$((BASE + 11)); R1="-connect=127.0.0.1:$((BASE + 1))"
fi
run_scn 1 "buried spends: restart, rescan" scn_buried
run_scn 2 "crash at each step of the checkpoint" scn_crash
run_scn 3 "reorg of 50 blocks over a recent spend" scn_reorg50
run_scn 4 "operator invalidateblock deeper than the witness cache" scn_deepunwind
run_scn 5 "wallet.dat opened by older binaries" scn_downgrade
run_scn 6 "kill between the wallet checkpoint and the coins flush" scn_staleckpt
say; say "id|scenario|result|checks"; cat "$RESULTS"
! grep -q '|FAIL|' "$RESULTS"
