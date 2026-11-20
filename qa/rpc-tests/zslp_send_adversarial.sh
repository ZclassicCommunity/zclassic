#!/bin/sh
# ZSLP wallet token transactions under attack and under races, on regtest.
#
# zslp_send.sh proves that the token transactions this wallet builds are right. This test tries to make
# the wallet burn tokens or a mint baton anyway, and checks that every attempt either fails closed (nothing
# is broadcast) or produces a VALID transaction that burns nothing:
#   1. two zslp_send calls race for the one token output of a wallet;
#   2. a poisoned fee coin: anyone can pay this wallet ordinary ZCL inside an INVALID transaction of the
#      same token. Z23's rules make a SEND or MINT invalid when ANY input, a fee input included, comes from
#      such a transaction (send_ancestry_invalid, mint_baton_lineage_invalid), so the wallet must never use
#      that coin for the fee of a transaction of that token;
#   3. token outputs at a watch-only address are not spendable tokens;
#   4. a -minrelaytxfee high enough that the P2PKH dust threshold passes 546 raises the token output value,
#      and a default node relays and mines the transaction;
#   5. the index catching up after a restart: requests are refused until it is at the tip, never built
#      against a stale index.
# At the end every index must show no invalid, unknown or burning transaction built by these wallets.
#
# usage: zslp_send_adversarial.sh [dir-with-zclassicd-zclassic-cli-zclassic-tx]
#   env CC=<compiler>   compiler for slpscript (default: cc)
#   env KEEP=1          keep the temp directory
# Needs: jq, a C compiler, the Zcash parameters in ~/.zcash-params. Ports 49000-49999.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../lib/isolation.sh"
TOP=$(cd "$HERE/../.." && pwd)
SRC=${1:-$TOP/src}
SVC=$TOP/src/c23/services
ZD=$SRC/zclassicd
ZCLI=$SRC/zclassic-cli
ZTX=$SRC/zclassic-tx
for b in "$ZD" "$ZCLI" "$ZTX"; do [ -x "$b" ] || { echo "missing $b" >&2; exit 2; }; done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
. "$(dirname "$0")/jsonq_lib.sh"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/zcl-zslp-adv.XXXXXX")
iso_base BASE "${ZSLP_PORT_BASE:-}" 128
used_ports=$( (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | awk '{print $4}' | sed 's/.*://' | sort -u)
while :; do
    clash=0
    for off in 0 1 2 100 101 102; do
        printf '%s\n' "$used_ports" | grep -qx "$((BASE + off))" && clash=1
    done
    [ $clash = 0 ] && break
    iso_rebase BASE 128 10
done
PIDS=""
CHECKS=0
DUST=0.00000546

say() { printf '%s\n' "$*"; }
ok() { CHECKS=$((CHECKS + 1)); say "  ok   $*"; }
fail() { say "  FAIL $*"; exit 1; }

PASSED=0
cleanup() {
    if [ "$PASSED" != 1 ]; then
        for d in "$TMP"/node*; do
            [ -f "$d/regtest/debug.log" ] && { say "---- $d debug.log (tail)"; tail -15 "$d/regtest/debug.log" | cut -c1-300; }
        done
    fi
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    for p in $PIDS; do
        n=0
        while kill -0 "$p" 2>/dev/null && [ $n -lt 60 ]; do sleep 1; n=$((n + 1)); done
        kill -9 "$p" 2>/dev/null || true
    done
    if [ "${KEEP:-0}" = 1 ]; then say "kept $TMP"; else rm -rf "$TMP"; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

cli() { n=$1; shift; "$ZCLI" -datadir="$TMP/node$n" -regtest -rpcport=$((BASE + 100 + n)) "$@"; }

start() {
    n=$1; shift
    dir=$TMP/node$n
    mkdir -p "$dir"
    if [ ! -f "$dir/zclassic.conf" ]; then
        { echo "regtest=1"; echo "rpcuser=adv"; echo "rpcpassword=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"; } >"$dir/zclassic.conf"
    fi
    $ZCL_RUN "$ZD" -datadir="$dir" -regtest -server=1 -daemon=0 -showmetrics=0 \
        -listen=1 -bind=127.0.0.1 -port=$((BASE + n)) \
        -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=$((BASE + 100 + n)) \
        -dnsseed=0 -discover=0 -listenonion=0 -upnp=0 -keypool=20 -debuglogfile=1 -parkdeepreorg=0 \
        "$@" >"$dir/stdout.log" 2>&1 &
    pid=$!
    PIDS="$PIDS $pid"
    echo "$pid" >"$dir/pid"
    t=0
    until cli "$n" getbalance >/dev/null 2>&1; do
        kill -0 "$pid" 2>/dev/null || { cat "$dir/stdout.log"; fail "node $n exited during startup"; }
        t=$((t + 1)); [ $t -lt 300 ] || fail "node $n did not start"
        sleep 1
    done
}

stop() {
    n=$1
    pid=$(cat "$TMP/node$n/pid")
    cli "$n" stop >/dev/null
    t=0
    while kill -0 "$pid" 2>/dev/null; do t=$((t + 1)); [ $t -lt 120 ] || fail "node $n did not stop"; sleep 1; done
}

connect() {
    cli "$1" addnode "127.0.0.1:$((BASE + $2))" onetry >/dev/null
    # wait for the handshake: a wallet transaction relayed before it would wait for the next rebroadcast
    t=0
    until [ "$(cli "$1" getpeerinfo | jq "[.[] | select(.version > 0)] | length")" -ge 1 ]; do
        t=$((t + 1)); [ $t -lt 60 ] || fail "node $1 did not connect to node $2"; sleep 1
    done
}

zat() { jq -n --arg a "$1" '$a | tonumber * 100000000 | round'; }
btc() { jq -n --argjson z "$1" '$z / 100000000' | awk '{ printf "%.8f", $1 }'; }

wait_index() {
    t=0
    while :; do
        info=$(cli "$1" zslp_getindexinfo 2>/dev/null || true)
        tip=$(cli "$1" getbestblockhash)
        if [ -n "$info" ] && [ "$(printf '%s' "$info" | jget indexedblock)" = "$tip" ] &&
           [ "$(printf '%s' "$info" | jget synced)" = true ]; then return 0; fi
        t=$((t + 1)); [ $t -lt 240 ] || fail "the index of node $1 did not reach the tip: $info"
        sleep 1
    done
}

NODES="0 1 2"
wait_tip() {
    want=$(cli 2 getbestblockhash)
    for n in $NODES; do
        t=0
        until [ "$(cli "$n" getbestblockhash)" = "$want" ]; do
            t=$((t + 1)); [ $t -lt 180 ] || fail "node $n did not reach the tip of node 2"
            sleep 1
        done
        wait_index "$n"
    done
}

relayed() {
    for n in $NODES; do
        for x in $(cli "$n" getrawmempool | jq -r '.[]'); do
            t=0
            until cli 2 getrawmempool | grep -q "$x"; do
                t=$((t + 1)); [ $t -lt 60 ] || fail "transaction $x did not reach node 2"
                sleep 1
            done
        done
    done
}

settle() { relayed; cli 2 generate 1 >/dev/null; wait_tip; }

expect_err() {
    sub=$1; shift
    if out=$("$@" 2>&1); then fail "expected an error containing \"$sub\" but it succeeded: $out"; fi
    case $out in
        *"$sub"*) ok "refused: $sub" ;;
        *) fail "expected an error containing \"$sub\", got: $out" ;;
    esac
}

tbal() { cli "$1" zslp_listunspent 1 | jq -r --arg t "$2" '([.balances[] | select(.tokenid == $t) | .amount] | first) // "0"'; }
status_of() { cli 2 zslp_gettransaction "$1" | jget validity; }

# every index: nothing invalid, unknown or burning except the transactions named in $EXPECTED_BAD
clean_index() {
    for n in $NODES; do
        info=$(cli "$n" zslp_getindexinfo)
        [ "$(printf '%s' "$info" | jget invalidtransactions)" = "$EXPECTED_INVALID" ] || fail "node $n: invalid transactions: $info"
        [ "$(printf '%s' "$info" | jget unknowntransactions)" = 0 ] || fail "node $n: unknown transactions: $info"
        [ "$(printf '%s' "$info" | jget burntransactions)" = 0 ] || fail "node $n: burning transactions: $info"
    done
    ok "$1: no index shows an unexpected invalid, unknown or burning transaction"
}
EXPECTED_INVALID=0

say "== build slpscript from the vendored Z23 builder"
# shellcheck disable=SC2086
${CC:-cc} -std=gnu11 -O2 -Wall -Wextra -Werror \
    -iquote "$SVC/glue" -iquote "$SVC/vendor/contexts/market/modules/zslp/include" \
    -iquote "$SVC/vendor/engine/modules/overlay/include" -iquote "$SVC/vendor/core/modules/script/include" \
    "$SVC/tools/slpscript.c" "$SVC/glue/zcl_token_guard.c" \
    "$SVC/vendor/contexts/market/modules/zslp/src/slp.c" "$SVC/vendor/engine/modules/overlay/src/overlay_codec.c" \
    -o "$TMP/slpscript"
SLP=$TMP/slpscript

say "== the network: node 2 mines (and attacks), node 0 is wallet A, node 1 is wallet B; every node indexes"
start 2 -zslpindex=1 -txindex=1
start 0 -zslpindex=1
start 1 -zslpindex=1
connect 0 2; connect 1 2
t=0; until [ "$(cli 2 getconnectioncount)" -ge 2 ]; do t=$((t + 1)); [ $t -lt 60 ] || fail "nodes did not connect"; sleep 1; done
cli 2 generate 110 >/dev/null
wait_tip
A=$(cli 0 getnewaddress)
B=$(cli 1 getnewaddress)
M=$(cli 2 getnewaddress)
cli 2 sendtoaddress "$A" 2 >/dev/null
cli 2 sendtoaddress "$B" 2 >/dev/null
for i in 1 2 3 4; do cli 2 sendtoaddress "$M" 5 >/dev/null; done # non-coinbase coins for the attacker's raw transactions
settle

r=$(cli 0 zslp_genesis '{"ticker":"ADV","name":"Adversarial","decimals":0,"initialquantity":"1000"}')
X=$(printf '%s' "$r" | jget tokenid)
settle
[ "$(tbal 0 "$X")" = 1000 ] || fail "genesis balance"
ok "wallet A created token $X (1000, baton kept)"

# ---- 1. two sends race for one token output ----------------------------------------------
say "== 1. two zslp_send calls race for the one token output of wallet A"
cli 0 zslp_send "$X" "[{\"address\":\"$B\",\"amount\":\"10\"}]" >"$TMP/race1" 2>&1 &
p1=$!
cli 0 zslp_send "$X" "[{\"address\":\"$B\",\"amount\":\"20\"}]" >"$TMP/race2" 2>&1 &
p2=$!
rc1=0; wait $p1 || rc1=$?
rc2=0; wait $p2 || rc2=$?
[ $((rc1 == 0)) -ne $((rc2 == 0)) ] || fail "exactly one of two racing sends must succeed: rc $rc1 / $rc2: $(cat "$TMP/race1" "$TMP/race2")"
grep -q "insufficient confirmed token balance" "$TMP/race1" "$TMP/race2" || fail "the losing send gave another error: $(cat "$TMP/race1" "$TMP/race2")"
[ "$(cli 0 getrawmempool | jlen)" = 1 ] || fail "racing sends left $(cli 0 getrawmempool | jlen) transactions"
settle
total=$(( $(tbal 0 "$X") + $(tbal 1 "$X") ))
[ $total = 1000 ] || fail "after the race A + B hold $total, not 1000"
clean_index "race"
ok "racing sends: one sent, the other was refused for lack of a confirmed token output; nothing burned"

# ---- 2. a poisoned fee coin --------------------------------------------------------------
say "== 2. ordinary ZCL paid to wallet A inside an INVALID transaction of the same token"
# A gives away every ordinary coin, so the poisoned coin is the only one it could use for a fee
plain=$(cli 0 listunspent 0 | jq -c '[.[] | select(.tokenbearing == false and .spendable)]')
n=$(printf '%s' "$plain" | jlen)
sum=$(printf '%s' "$plain" | jq '[.[].amount * 100000000 | round] | add')
ins=$(printf '%s' "$plain" | jq -c '[.[] | {txid, vout}]')
raw=$(cli 0 createrawtransaction "$ins" "{\"$M\":$(btc $((sum - 10000)))}")
cli 0 sendrawtransaction "$(cli 0 signrawtransaction "$raw" | jget hex)" >/dev/null
settle
[ "$(cli 0 listunspent 0 | jq '[.[] | select(.tokenbearing == false)] | length')" = 0 ] || fail "wallet A still has ordinary coins"
ok "wallet A gave away its $n ordinary coins; it holds only token outputs and the baton"

# the attacker: a SEND of token X with no token inputs (INVALID: send_ancestry_invalid) that pays A 0.5 ZCL
u=$(cli 2 listunspent 1 | jq -c '[.[] | select(.spendable and .generated != true and .amount >= 1)] | sort_by(.amount) | .[0]')
utxid=$(printf '%s' "$u" | jget txid); uvout=$(printf '%s' "$u" | jget vout)
change=$(btc $(( $(zat "$(printf '%s' "$u" | jget amount)") - 50000000 - 546 - 10000 )))
raw=$(cli 2 createrawtransaction "[{\"txid\":\"$utxid\",\"vout\":$uvout}]" '{}')
raw=$("$ZTX" -regtest "$raw" "outscript=0:0x$("$SLP" send "$X" 1000)" "outaddr=$DUST:$M" "outaddr=0.5:$A" "outaddr=$change:$M")
P=$(cli 2 sendrawtransaction "$(cli 2 signrawtransaction "$raw" | jget hex)")
settle
[ "$(status_of "$P")" = invalid ] || fail "the attacker's transaction is not INVALID: $(cli 2 zslp_gettransaction "$P")"
EXPECTED_INVALID=1
[ "$(cli 0 listunspent 1 | jq --arg p "$P" '[.[] | select(.txid == $p and .tokenbearing == false)] | length')" = 1 ] ||
    fail "wallet A does not see the poisoned coin as an ordinary coin"
ok "the attacker paid A 0.5 ZCL at $P:2, inside an INVALID SEND of token X; A's wallet sees an ordinary coin"

before_tok=$(tbal 0 "$X")
expect_err "not enough ordinary ZCL" cli 0 zslp_send "$X" "[{\"address\":\"$B\",\"amount\":\"5\"}]"
expect_err "not enough ordinary ZCL" cli 0 zslp_mint "$X" "5"
[ "$(cli 0 getrawmempool | jlen)" = 0 ] || fail "a refused token transaction reached the mempool"
[ "$(cli 0 gettxout "$P" 2 | jget value)" = 0.50000000 ] || fail "the poisoned coin was spent"
ok "with only the poisoned coin for the fee, SEND and MINT are refused and nothing is broadcast"
# an ordinary payment still may use it: no token rules apply to an ordinary transaction
# a clean coin makes the token transactions possible again, without the poisoned coin
cli 2 sendtoaddress "$A" 0.3 >/dev/null
settle
s=$(cli 0 zslp_send "$X" "[{\"address\":\"$B\",\"amount\":\"5\"}]" | jget txid)
settle
[ "$(status_of "$s")" = valid ] || fail "the send is not valid: $(cli 2 zslp_gettransaction "$s")"
cli 2 getrawtransaction "$s" 1 | jq -e --arg p "$P" '[.vin[] | select(.txid == $p)] | length == 0' >/dev/null ||
    fail "the send used the poisoned coin"
mt=$(cli 0 zslp_mint "$X" "7" | jget txid)
settle
[ "$(status_of "$mt")" = valid ] || fail "the mint is not valid: $(cli 2 zslp_gettransaction "$mt")"
cli 2 getrawtransaction "$mt" 1 | jq -e --arg p "$P" '[.vin[] | select(.txid == $p)] | length == 0' >/dev/null ||
    fail "the mint used the poisoned coin"
[ "$(cli 0 gettxout "$P" 2 | jget value)" = 0.50000000 ] || fail "the poisoned coin was spent"
[ "$(tbal 0 "$X")" = $((before_tok - 5 + 7)) ] || fail "A's token balance is $(tbal 0 "$X"), expected $((before_tok - 5 + 7))"
clean_index "poisoned fee coin"
ok "SEND and MINT are VALID and leave the poisoned coin alone"
# an ordinary ZCL payment may spend the poisoned coin: it carries nothing
o=$(cli 0 sendtoaddress "$M" 0.6)
settle
[ "$(cli 0 gettxout "$P" 2)" = "" ] || fail "an ordinary payment of 0.6 ZCL did not use the poisoned coin"
clean_index "ordinary payment"
[ "$(tbal 0 "$X")" = $((before_tok + 2)) ] || fail "the ordinary payment changed A's token balance"
ok "an ordinary payment spent the poisoned coin ($o) and touched no token output"

# ---- 3. watch-only ---------------------------------------------------------------------
say "== 3. tokens at a watch-only address are not spendable"
WA=$(cli 0 zslp_listunspent 1 | jq -r --arg t "$X" '[.outputs[] | select(.tokenid == $t and .role == "token")] | max_by(.amount | tonumber) | .address')
bb=$(tbal 1 "$X")
cli 1 importaddress "$WA" "" true >/dev/null
wait_index 1
seen=$(tbal 1 "$X")
expect_err "insufficient confirmed token balance" cli 1 zslp_send "$X" "[{\"address\":\"$M\",\"amount\":\"$((bb + 1))\"}]"
[ "$(cli 1 getrawmempool | jlen)" = 0 ] || fail "a watch-only send reached the mempool"
ok "wallet B watching $WA (zslp_listunspent now shows $seen) can still send only its own $bb"

# ---- 4. a higher -minrelaytxfee -----------------------------------------------------------
say "== 4. wallet B with -minrelaytxfee=0.0001 (100 times the default of 100 zatoshi per kB)"
stop 1
start 1 -zslpindex=1 -minrelaytxfee=0.0001
connect 1 2
wait_tip
r=$(cli 1 zslp_send "$X" "[{\"address\":\"$A\",\"amount\":\"3\"}]")
h=$(printf '%s' "$r" | jget txid)
settle
v1=$(zat "$(cli 2 getrawtransaction "$h" 1 | jget "vout[1].value")")
[ "$v1" = 5460 ] || fail "token output value $v1, expected 5460 (the P2PKH dust threshold at 0.0001/kB)"
[ "$(status_of "$h")" = valid ] || fail "the send is not valid"
ok "the token outputs carry 5460 zatoshi, a default node relayed and mined the send, and it is VALID"
stop 1
start 1 -zslpindex=1
connect 1 2
wait_tip

# ---- 4b. outputs that carry 0 zatoshi -------------------------------------------------------
say "== 4b. a token output and a mint baton that pay wallet A 0 zatoshi"
# consensus allows a zero-value output (only relay policy calls it dust, and regtest does not require standard
# transactions); the index and zslp_listunspent count it, so zslp_send and zslp_mint must be able to spend it
cli 2 sendtoaddress "$A" 1 >/dev/null
settle
u=$(cli 2 listunspent 1 | jq -c '[.[] | select(.spendable and .generated != true and .amount >= 1)] | sort_by(.amount) | .[0]')
utxid=$(printf '%s' "$u" | jget txid); uvout=$(printf '%s' "$u" | jget vout)
change=$(btc $(( $(zat "$(printf '%s' "$u" | jget amount)") - 20000 )))
raw=$(cli 2 createrawtransaction "[{\"txid\":\"$utxid\",\"vout\":$uvout}]" '{}')
raw=$("$ZTX" -regtest "$raw" "outscript=0:0x$("$SLP" genesis ZV "Zero Value" 2 100)" "outaddr=0:$A" "outaddr=0:$A" "outaddr=$change:$M")
Z=$(cli 2 sendrawtransaction "$(cli 2 signrawtransaction "$raw" | jget hex)")
settle
[ "$(status_of "$Z")" = valid ] || fail "the zero-value GENESIS is not valid: $(cli 2 zslp_gettransaction "$Z")"
[ "$(tbal 0 "$Z")" = 100 ] || fail "zslp_listunspent shows $(tbal 0 "$Z") of the zero-value token, expected 100"
cli 0 gettxout "$Z" 1 | jq -e '.value == 0' >/dev/null || fail "the token output does not carry 0 zatoshi"
ok "wallet A holds 100 units of $Z in a 0 zatoshi output and the baton in another"
s=$(cli 0 zslp_send "$Z" "[{\"address\":\"$B\",\"amount\":\"40\"}]" | jget txid)
settle
[ "$(status_of "$s")" = valid ] || fail "the send of the zero-value token is not valid: $(cli 2 zslp_gettransaction "$s")"
[ "$(tbal 0 "$Z")" = 60 ] && [ "$(tbal 1 "$Z")" = 40 ] || fail "balances after the send: A $(tbal 0 "$Z"), B $(tbal 1 "$Z")"
ok "zslp_send spent the 0 zatoshi token output (A 60, B 40)"
mt=$(cli 0 zslp_mint "$Z" 5 | jget txid)
settle
[ "$(status_of "$mt")" = valid ] || fail "the mint with the zero-value baton is not valid: $(cli 2 zslp_gettransaction "$mt")"
[ "$(tbal 0 "$Z")" = 65 ] || fail "A holds $(tbal 0 "$Z") after the mint, expected 65"
clean_index "zero-value outputs"
ok "zslp_mint spent the 0 zatoshi mint baton"

# ---- 5. the index catching up -------------------------------------------------------------
say "== 5. a restart with the index behind: refused until it is at the tip"
stop 0
cli 2 generate 150 >/dev/null
start 0 -zslpindex=1
connect 0 2
refused=0; tries=0
while :; do
    if out=$(cli 0 zslp_send "$X" "[{\"address\":\"$B\",\"amount\":\"1\"}]" 1 null true 2>&1); then
        info=$(cli 0 zslp_getindexinfo)
        [ "$(printf '%s' "$info" | jget synced)" = true ] || fail "a dry run was built while the index says it is not synced: $info"
        break
    fi
    case $out in
        *"not synced"*|*"Loading"*|*"Rescanning"*|*"Verifying"*|*"Activating"*) refused=$((refused + 1)) ;;
        *) fail "unexpected error while the index catches up: $out" ;;
    esac
    tries=$((tries + 1)); [ $tries -lt 600 ] || fail "the index never caught up"
    sleep 0.2
done
wait_tip
ok "while catching up, $refused request(s) were refused as not synced; once at the tip the dry run was built"

settle
clean_index "the whole run"
PASSED=1
say "PASS: $CHECKS checks"
