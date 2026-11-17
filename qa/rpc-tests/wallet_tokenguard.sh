#!/bin/sh
# Wallet token guard, end to end on regtest.
#
# Real GENESIS, MINT and SEND transactions (their OP_RETURN scripts come from
# the vendored Z23 builder, through src/c23/services/tools/slpscript.c) pay
# token dust, a mint baton and ordinary coins to ONE address of a wallet. Every
# RPC that picks coins is then driven until the wallet has spent every ordinary
# coin it owns, and none of them may ever spend a token-bearing output.
#
# usage: wallet_tokenguard.sh [dir-with-zclassicd-zclassic-cli-zclassic-tx]
#   env BASELINE_SRC=<dir>  also run the CONTROL: the same wallet contents under
#                           an unguarded zclassicd from <dir> must burn token
#                           outputs. It proves this test can see the bug.
#   env CC=<compiler>       compiler for slpscript (default: cc)
#   env KEEP=1              keep the temp directory
#   env E2E_NODE_ARGS=...   extra arguments for every node, for example
#                           "-nuparams=5ba81b19:1 -nuparams=76b809bb:1" to run with
#                           Overwinter and Sapling active (TransactionBuilder paths)
#
# Needs: jq, a C compiler, the Zcash parameters in ~/.zcash-params.
# Every node runs on 127.0.0.1 with its own temp datadir and its own ports.
# This is a shell script because this host has no Python 2, which the
# qa/rpc-tests framework needs.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
SRC=${1:-$TOP/src}
SVC=$TOP/src/c23/services
ZD=$SRC/zclassicd
ZCLI=$SRC/zclassic-cli
ZTX=$SRC/zclassic-tx
for b in "$ZD" "$ZCLI" "$ZTX"; do [ -x "$b" ] || { echo "missing $b" >&2; exit 2; }; done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/zcl-tokenguard-e2e.XXXXXX")
BASE=$((20000 + ($$ % 20000)))
PIDS=""
MN=0
CHECKS=0
DUST=0.00000546

say() { printf '%s\n' "$*"; }
ok() { CHECKS=$((CHECKS + 1)); say "  ok   $*"; }
fail() {
    say "  FAIL $*"
    for d in "$TMP"/node*; do
        [ -f "$d/regtest/debug.log" ] && { say "---- $d debug.log (tail)"; tail -15 "$d/regtest/debug.log"; }
    done
    exit 1
}

PASSED=0
cleanup() {
    if [ "$PASSED" != 1 ]; then
        for d in "$TMP"/node*; do
            [ -f "$d/regtest/debug.log" ] && { say "---- $d debug.log (tail)"; tail -12 "$d/regtest/debug.log" | cut -c1-400; }
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

# ---- nodes ----------------------------------------------------------------

# start <n> <zclassicd> [extra args]: node n, datadir $TMP/node<n>
start() {
    n=$1; bin=$2; shift 2
    dir=$TMP/node$n
    mkdir -p "$dir" "$TMP/export"
    if [ ! -f "$dir/zclassic.conf" ]; then
        {
            echo "regtest=1"
            echo "rpcuser=tokenguard"
            echo "rpcpassword=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
        } >"$dir/zclassic.conf"
    fi
    "$bin" -datadir="$dir" -regtest -server=1 -daemon=0 -showmetrics=0 \
        -listen=1 -bind=127.0.0.1 -port=$((BASE + n)) \
        -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=$((BASE + 100 + n)) \
        -dnsseed=0 -discover=0 -listenonion=0 -upnp=0 -keypool=5 -debuglogfile=1 -exportdir="$TMP/export" \
        -experimentalfeatures -zmergetoaddress ${E2E_NODE_ARGS:-} "$@" >"$dir/stdout.log" 2>&1 &
    pid=$!
    PIDS="$PIDS $pid"
    echo "$pid" >"$dir/pid"
    t=0
    until cli "$n" getblockcount >/dev/null 2>&1; do
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
    while kill -0 "$pid" 2>/dev/null; do
        t=$((t + 1)); [ $t -lt 120 ] || fail "node $n did not stop"
        sleep 1
    done
}

cli() { n=$1; shift; "$ZCLI" -datadir="$TMP/node$n" -regtest -rpcport=$((BASE + 100 + n)) "$@"; }

# sync <n>: node n has node 0's tip
sync() {
    want=$(cli "$MN" getbestblockhash)
    t=0
    until [ "$(cli "$1" getbestblockhash)" = "$want" ]; do
        t=$((t + 1)); [ $t -lt 180 ] || fail "node $1 did not sync"
        sleep 1
    done
}

# confirm <n> <txid>: wait for node 0 to see the tx, mine it, sync node n
confirm() {
    t=0
    until cli "$MN" getrawmempool | grep -q "$2"; do
        t=$((t + 1)); [ $t -lt 120 ] || fail "tx $2 did not reach the miner"
        sleep 1
    done
    cli "$MN" generate 1 >/dev/null
    sync "$1"
}

# ---- transactions ---------------------------------------------------------

zat() { jq -n --arg a "$1" '$a | tonumber * 100000000 | round'; }
btc() { awk -v z="$1" 'BEGIN { printf "%.8f", z / 100000000 }'; }

# slp_tx <outputs...>: node 0 funds, signs and sends a transaction whose
# outputs are exactly the given zclassic-tx output commands followed by its
# change. Prints the txid.
slp_tx() {
    # The wallet learns about a sendrawtransaction spend asynchronously, so
    # listunspent can still offer a coin this function used a moment ago:
    # keep our own list of the coins already taken.
    touch "$TMP/used"
    u=$(cli "$MN" listunspent 1 | jq -c --rawfile used "$TMP/used" '
        ($used | split("\n")) as $u
        | [.[] | select(.spendable and .amount >= 1) | select(("\(.txid):\(.vout)") as $o | $u | index($o) | not)]
        | sort_by(.amount) | .[0]')
    [ "$u" != null ] || fail "miner has no coin to fund a token transaction"
    utxid=$(printf '%s' "$u" | jq -r .txid)
    uvout=$(printf '%s' "$u" | jq -r .vout)
    echo "$utxid:$uvout" >>"$TMP/used"
    nd=0
    for a in "$@"; do case $a in outaddr=*) nd=$((nd + 1)) ;; esac; done
    change=$(btc $(( $(zat "$(printf '%s' "$u" | jq -r .amount)") - 10000 - 546 * nd )))
    raw=$(cli "$MN" createrawtransaction "[{\"txid\":\"$utxid\",\"vout\":$uvout}]" '{}')
    raw=$("$ZTX" -regtest "$raw" "$@" "outaddr=$change:$MINER")
    signed=$(cli "$MN" signrawtransaction "$raw")
    [ "$(printf '%s' "$signed" | jq -r .complete)" = true ] || fail "could not sign a token transaction"
    cli "$MN" sendrawtransaction "$(printf '%s' "$signed" | jq -r .hex)"
}

# inputs <n> <txid>: the outpoints a wallet transaction spends, one per line
inputs() {
    # A transaction an async operation just broadcast reaches the wallet a
    # moment later (the wallet is notified from another thread): wait for it.
    tries=0
    until hex=$(cli "$1" gettransaction "$2" 2>/dev/null | jq -r .hex) && [ -n "$hex" ]; do
        tries=$((tries + 1)); [ $tries -lt 60 ] || return 1
        sleep 1
    done
    cli "$1" decoderawtransaction "$hex" | jq -r '.vin[] | "\(.txid):\(.vout)"'
}

# inputs_of_hex <n> <hex>
inputs_of_hex() { cli "$1" decoderawtransaction "$2" | jq -r '.vin[] | "\(.txid):\(.vout)"'; }

# no_token_inputs <label> <list-of-outpoints>
no_token_inputs() {
    [ -n "$2" ] || fail "$1: no inputs at all"
    hit=$(printf '%s\n' "$2" | grep -Fx -f "$TMP/protected" || true)
    [ -z "$hit" ] || fail "$1 spent token-bearing output(s): $hit"
    ok "$1: $(printf '%s\n' "$2" | wc -l | tr -d ' ') input(s), none token-bearing"
}

# wait_op <n> <opid>: prints "success <txid>" or "failed <message>"
wait_op() {
    t=0
    while :; do
        s=$(cli "$1" z_getoperationstatus "[\"$2\"]" | jq -c '.[0]')
        case $(printf '%s' "$s" | jq -r .status) in
            success) printf 'success %s\n' "$(printf '%s' "$s" | jq -r .result.txid)"; return 0 ;;
            failed) printf 'failed %s\n' "$(printf '%s' "$s" | jq -r .error.message)"; return 0 ;;
        esac
        t=$((t + 1)); [ $t -lt 300 ] || fail "operation $2 did not finish"
        sleep 1
    done
}

# flagged <n>: outpoints listunspent marks tokenbearing, sorted
flagged() { cli "$1" listunspent 0 | jq -r '.[] | select(.tokenbearing == true) | "\(.txid):\(.vout)"' | sort; }

# expect_error <label> <needle> <command...>: the command must fail and say <needle>
expect_error() {
    label=$1; needle=$2; shift 2
    if out=$("$@" 2>&1); then fail "$label: succeeded, expected an error containing '$needle' (got: $out)"; fi
    printf '%s' "$out" | grep -qF "$needle" || fail "$label: error does not contain '$needle': $out"
    ok "$label: refused: $(printf '%s' "$out" | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-230)"
}

# ---- build the script tool ------------------------------------------------

say "== build slpscript from the vendored Z23 builder"
# shellcheck disable=SC2086
${CC:-cc} -std=gnu11 -O2 -Wall -Wextra -Werror \
    -iquote "$SVC/glue" -iquote "$SVC/vendor/contexts/market/modules/zslp/include" \
    -iquote "$SVC/vendor/engine/modules/overlay/include" -iquote "$SVC/vendor/core/modules/script/include" \
    "$SVC/tools/slpscript.c" "$SVC/glue/zcl_token_guard.c" \
    "$SVC/vendor/contexts/market/modules/zslp/src/slp.c" "$SVC/vendor/engine/modules/overlay/src/overlay_codec.c" \
    -o "$TMP/slpscript"
SLP=$TMP/slpscript

# ---- set the stage --------------------------------------------------------

decode() { cli "$1" decoderawtransaction "$(cat)"; }

# stage <n>: the miner (node $MN) pays ordinary coins and token transactions
# to $A; fills $TMP/protected with the token-bearing outpoints at A, known by
# construction (not read back from the wallet under test).
stage() {
    : >"$TMP/protected"; : >"$TMP/ordinary"
    for amt in 1.0 2.0 0.5; do
        t=$(cli "$MN" sendtoaddress "$A" $amt)
        v=$(cli "$MN" gettransaction "$t" | jq -r .hex | decode "$MN" |
            jq -r --arg a "$A" '.vout[] | select(.scriptPubKey.addresses[0] == $a) | .n')
        echo "$t:$v" >>"$TMP/ordinary"
    done
    # GENESIS: vout[1] 1000 tokens, vout[2] mint baton
    G=$(slp_tx "outscript=0:0x$("$SLP" genesis TG "Token Guard" 2 1000)" "outaddr=$DUST:$A" "outaddr=$DUST:$A")
    # MINT: vout[1] 500 tokens, vout[2] mint baton
    M=$(slp_tx "outscript=0:0x$("$SLP" mint "$G" 2 500)" "outaddr=$DUST:$A" "outaddr=$DUST:$A")
    # SEND: vout[1] 400 tokens, vout[2] 0 tokens (carries nothing), vout[3] 600 tokens
    S=$(slp_tx "outscript=0:0x$("$SLP" send "$G" 400 0 600)" "outaddr=$DUST:$A" "outaddr=$DUST:$A" "outaddr=$DUST:$A")
    # the message is the first OP_RETURN but sits at vout[1]: quantity 2 rides on vout[2]
    L=$(slp_tx "outaddr=$DUST:$A" "outscript=0:0x$("$SLP" send "$G" 7 8)" "outaddr=$DUST:$A")
    # an OP_RETURN that is not SLP
    X=$(slp_tx "outscript=0:0x6a0b68656c6c6f20776f726c64" "outaddr=$DUST:$A")
    for o in "$G:1" "$G:2" "$M:1" "$M:2" "$S:1" "$S:3" "$L:2"; do echo "$o" >>"$TMP/protected"; done
    for o in "$S:2" "$L:0" "$X:1"; do echo "$o" >>"$TMP/ordinary"; done
    sort -o "$TMP/protected" "$TMP/protected"
    cli "$MN" generate 1 >/dev/null
    sync "$1"
}

# ---- CONTROL: an unguarded wallet burns them ------------------------------
# A separate miner (node 6) and a wallet run by the baseline binary (node 5),
# on their own chain. Nothing here touches the nodes of the real test.

if [ -n "${BASELINE_SRC:-}" ]; then
    say "== CONTROL: the same stage in a wallet run by the unguarded baseline ($BASELINE_SRC/zclassicd)"
    [ -x "$BASELINE_SRC/zclassicd" ] || fail "no zclassicd in $BASELINE_SRC"
    MN=6
    start 6 "$ZD"
    start 5 "$BASELINE_SRC/zclassicd" -connect=127.0.0.1:$((BASE + MN))
    cli "$MN" generate 120 >/dev/null
    sync 5
    MINER=$(cli "$MN" getnewaddress)
    A=$(cli 5 getnewaddress)
    stage 5
    [ "$(cli 5 listunspent 0 | jq length)" = 13 ] || fail "control: stage is not the same"
    [ "$(cli 5 listunspent 0 | jq 'map(has("tokenbearing")) | any')" = false ] || fail "control: the baseline already has a tokenbearing field"
    op=$(cli 5 z_sendmany "$A" "[{\"address\":\"$MINER\",\"amount\":0.4}]" 1 0.0001)
    r=$(wait_op 5 "$op")
    case $r in success*) ;; *) fail "control: z_sendmany did not complete: $r" ;; esac
    burned=$(inputs 5 "${r#success }" | grep -Fx -f "$TMP/protected" | wc -l | tr -d ' ')
    [ "$burned" -gt 0 ] || fail "control: the unguarded baseline did NOT spend a token output; this test cannot see the bug"
    say "  CONTROL unguarded baseline: z_sendmany of 0.4 spent $burned of the 7 token-bearing outputs as ordinary coin"
    confirm 5 "${r#success }"
    m=$(cli 5 z_mergetoaddress '["ANY_TADDR"]' "$MINER")
    r=$(wait_op 5 "$(printf '%s' "$m" | jq -r .opid)")
    case $r in success*) ;; *) fail "control: z_mergetoaddress did not complete: $r" ;; esac
    burned2=$(inputs 5 "${r#success }" | grep -Fx -f "$TMP/protected" | wc -l | tr -d ' ')
    say "  CONTROL unguarded baseline: z_mergetoaddress then spent $burned2 more; $(cli 5 listunspent 0 | jq length) outputs left of 13"
    [ $((burned + burned2)) = 7 ] || fail "control: expected the baseline to burn all 7 token outputs, it burned $((burned + burned2))"
    stop 5
    stop 6
fi

say "== start miner (node 0) and wallet under test (node 1), ports $BASE+"
MN=0
start 0 "$ZD"
start 1 "$ZD" -connect=127.0.0.1:$((BASE + MN))
cli "$MN" generate 120 >/dev/null
sync 1
MINER=$(cli "$MN" getnewaddress)
A=$(cli 1 getnewaddress)
say "   wallet address A = $A"

say "== stage: 3 ordinary coins, GENESIS, MINT, SEND, a late-message SEND and a non-SLP OP_RETURN, all paying A"
stage 1
say "   genesis $G"
say "   mint    $M"
say "   send    $S"

# The classifier in the tool agrees with what the stage believes it built.
gs=$(cli "$MN" gettransaction "$G" | jq -r .hex | decode "$MN" | jq -r '.vout[0].scriptPubKey.hex')
[ "$("$SLP" roles 4 "$gs" | tr '\n' ' ')" = "1 token 2 baton " ] || fail "slpscript roles disagrees on the genesis transaction"
ok "the mined GENESIS OP_RETURN classifies as: vout 1 token, vout 2 baton"

# ---- 1. listunspent and balances are unchanged apart from the new field ----

say "== 1. listunspent, getbalance"
LU=$(cli 1 listunspent 0)
[ "$(printf '%s' "$LU" | jq length)" = 13 ] || fail "listunspent has $(printf '%s' "$LU" | jq length) entries, expected 13"
ok "listunspent lists all 13 outputs (7 token-bearing, 6 ordinary)"
[ "$(printf '%s' "$LU" | jq 'all(.[]; (.tokenbearing | type) == "boolean")')" = true ] || fail "an entry lacks a boolean tokenbearing"
[ "$(printf '%s' "$LU" | jq -c '[.[] | keys_unsorted | map(select(. != "account"))] | unique')" = '[["txid","vout","generated","address","scriptPubKey","amount","confirmations","spendable","tokenbearing"]]' ] ||
    fail "listunspent fields changed: $(printf '%s' "$LU" | jq -c '[.[] | keys_unsorted] | unique')"
ok "every entry has the old fields in the old order, plus a boolean tokenbearing at the end"
[ "$(flagged 1)" = "$(cat "$TMP/protected")" ] || fail "tokenbearing flags are wrong: $(flagged 1 | tr '\n' ' ')"
ok "tokenbearing is true for exactly the 7 outputs built to carry tokens or a baton"
BAL=$(zat "$(cli 1 getbalance)")
SUM=$(printf '%s' "$LU" | jq '[.[].amount * 100000000 | round] | add')
[ "$BAL" = "$SUM" ] && [ "$BAL" = $((350000000 + 10 * 546)) ] || fail "getbalance $BAL, listunspent sum $SUM, expected $((350000000 + 10 * 546))"
ok "getbalance = sum of listunspent = 3.50005460 (token dust still counted)"
[ "$(zat "$(cli 1 z_gettotalbalance 0 | jq -r .transparent)")" = "$BAL" ] || fail "z_gettotalbalance transparent differs"
[ "$(zat "$(cli 1 z_getbalance "$A" 0)")" = "$BAL" ] || fail "z_getbalance A differs"
ok "z_gettotalbalance and z_getbalance agree with it"

# ---- 2. every automatic spend path ----------------------------------------

say "== 2. spend paths, token outputs sitting in the same wallet at the same address"

# z_sendmany takes the SMALLEST utxos first: the token dust is first in line.
op=$(cli 1 z_sendmany "$A" "[{\"address\":\"$MINER\",\"amount\":0.4}]" 1 0.0001)
r=$(wait_op 1 "$op"); case $r in success*) ;; *) fail "z_sendmany: $r" ;; esac
t=${r#success }
no_token_inputs "z_sendmany from the t-addr" "$(inputs 1 "$t")"
# Which builder made it: v1 before Overwinter, v4 (TransactionBuilder) with Sapling active.
say "       (transaction format: $(cli 1 gettransaction "$t" | jq -r .hex | decode 1 | jq -c '{version, overwintered}'))"
confirm 1 "$t"

t=$(cli 1 sendtoaddress "$MINER" 1.2)
no_token_inputs "sendtoaddress" "$(inputs 1 "$t")"
confirm 1 "$t"

t=$(cli 1 sendmany "" "{\"$MINER\":0.3,\"$(cli "$MN" getnewaddress)\":0.2}")
no_token_inputs "sendmany" "$(inputs 1 "$t")"
confirm 1 "$t"

raw=$(cli 1 createrawtransaction '[]' "{\"$MINER\":0.25}")
f=$(cli 1 fundrawtransaction "$raw")
no_token_inputs "fundrawtransaction (no inputs given)" "$(inputs_of_hex 1 "$(printf '%s' "$f" | jq -r .hex)")"

# A token input the caller put in the transaction: refused, then allowed on request.
raw=$(cli 1 createrawtransaction "[{\"txid\":\"$G\",\"vout\":1}]" "{\"$MINER\":0.25}")
expect_error "fundrawtransaction with a token input, no override" "$G:1 carries ZSLP tokens or a mint baton and is protected" cli 1 fundrawtransaction "$raw"
expect_error "fundrawtransaction with a token input, allowtokeninputs=false" "carries ZSLP tokens" cli 1 fundrawtransaction "$raw" false
f=$(cli 1 fundrawtransaction "$raw" true)
fin=$(inputs_of_hex 1 "$(printf '%s' "$f" | jq -r .hex)")
printf '%s\n' "$fin" | grep -qFx "$G:1" || fail "fundrawtransaction override dropped the input it was given"
[ "$(printf '%s\n' "$fin" | grep -Fx -f "$TMP/protected" | wc -l | tr -d ' ')" = 1 ] || fail "fundrawtransaction override added a token input of its own: $fin"
ok "fundrawtransaction allowtokeninputs=true: keeps the one token input it was given, adds only ordinary inputs ($(printf '%s\n' "$fin" | wc -l | tr -d ' ') inputs)"

# Fee selection: a payment that needs every remaining ordinary zatoshi.
# z_mergetoaddress sweeps all transparent funds of the wallet.
m=$(cli 1 z_mergetoaddress '["ANY_TADDR"]' "$MINER")
r=$(wait_op 1 "$(printf '%s' "$m" | jq -r .opid)"); case $r in success*) ;; *) fail "z_mergetoaddress: $r" ;; esac
t=${r#success }
no_token_inputs "z_mergetoaddress ANY_TADDR ($(printf '%s' "$m" | jq -r .mergingUTXOs) utxos merged)" "$(inputs 1 "$t")"
confirm 1 "$t"

# ---- 3. only token dust is left --------------------------------------------

say "== 3. the wallet has spent every ordinary coin; only token outputs remain"
[ "$(flagged 1)" = "$(cat "$TMP/protected")" ] || fail "token outputs changed: $(flagged 1 | tr '\n' ' ')"
[ "$(cli 1 listunspent 0 | jq length)" = 7 ] || fail "expected exactly the 7 token outputs to remain, have $(cli 1 listunspent 0 | jq -c '[.[] | {txid, vout, amount, tokenbearing}]')"
ok "all 7 token-bearing outputs are still unspent, and nothing else is left"
[ "$(zat "$(cli 1 getbalance)")" = $((7 * 546)) ] || fail "balance is $(cli 1 getbalance), expected 0.00003822"
ok "getbalance = 0.00003822 (7 x 546 zatoshi of token dust)"

NOTE="7 token-bearing outputs holding 0.00003822 are protected and were not used"
expect_error "sendtoaddress" "Insufficient funds ($NOTE" cli 1 sendtoaddress "$MINER" 0.00001
raw=$(cli 1 createrawtransaction '[]' "{\"$MINER\":0.00001}")
expect_error "fundrawtransaction" "Insufficient funds ($NOTE" cli 1 fundrawtransaction "$raw"
expect_error "z_mergetoaddress" "Could not find any funds to merge. ($NOTE" cli 1 z_mergetoaddress '["ANY_TADDR"]' "$MINER"
expect_error "z_mergetoaddress from A" "Could not find any funds to merge. ($NOTE" cli 1 z_mergetoaddress "[\"$A\"]" "$MINER"
op=$(cli 1 z_sendmany "$A" "[{\"address\":\"$MINER\",\"amount\":0.00001}]" 1 0)
r=$(wait_op 1 "$op")
case $r in
    "failed Could not find any non-coinbase UTXOs to spend. ($NOTE"*) ok "z_sendmany: refused: ${r#failed }" ;;
    *) fail "z_sendmany with only token dust: $r" ;;
esac

# ---- 4. restart: nothing was persisted, nothing needs to be ----------------

say "== 4. restart the wallet node"
stop 1
start 1 "$ZD" -connect=127.0.0.1:$((BASE + MN))
sync 1
[ "$(flagged 1)" = "$(cat "$TMP/protected")" ] || fail "after restart: $(flagged 1 | tr '\n' ' ')"
[ "$(cli 1 listlockunspent | jq length)" = 0 ] || fail "protection must not use the lock list"
ok "after a restart the same 7 outputs are flagged, and listlockunspent is empty"
expect_error "sendtoaddress after restart" "Insufficient funds ($NOTE" cli 1 sendtoaddress "$MINER" 0.00001

# ---- 5. restore from a backup of wallet.dat --------------------------------

say "== 5. restore a backup of wallet.dat into a new node"
cli 1 backupwallet tokenguardbackup >/dev/null
WIF=$(cli 1 dumpprivkey "$A")
stop 1
mkdir -p "$TMP/node2/regtest"
cp "$TMP/export/tokenguardbackup" "$TMP/node2/regtest/wallet.dat"
start 2 "$ZD" -connect=127.0.0.1:$((BASE + MN)) -rescan
sync 2
[ "$(flagged 2)" = "$(cat "$TMP/protected")" ] || fail "restored wallet: $(flagged 2 | tr '\n' ' ')"
ok "the restored wallet flags the same 7 outputs"
# give it one ordinary coin and make it pay: only that coin may move
t=$(cli "$MN" sendtoaddress "$A" 0.7); cli "$MN" generate 1 >/dev/null; sync 2
t=$(cli 2 sendtoaddress "$MINER" 0.5)
no_token_inputs "restored wallet, sendtoaddress" "$(inputs 2 "$t")"
confirm 2 "$t"
# more than the ordinary change that is left, less than the balance
want=$(btc $(( $(zat "$(cli 2 getbalance)") - 2000 )))
expect_error "restored wallet, sendtoaddress beyond its ordinary coins" "Insufficient funds ($NOTE" cli 2 sendtoaddress "$MINER" "$want"
[ "$(flagged 2)" = "$(cat "$TMP/protected")" ] || fail "restored wallet lost token outputs"
ok "the restored wallet still holds all 7 token outputs"
stop 2

# ---- 6. a wallet rebuilt from the key by rescanning the chain --------------

say "== 6. new empty wallet, import the key, rescan from genesis"
start 3 "$ZD" -connect=127.0.0.1:$((BASE + MN))
sync 3
[ "$(cli 3 listunspent 0 | jq length)" = 0 ] || fail "new wallet is not empty"
cli 3 importprivkey "$WIF" "" true >/dev/null
[ "$(flagged 3)" = "$(cat "$TMP/protected")" ] || fail "rescanned wallet: $(flagged 3 | tr '\n' ' ')"
ok "the rescanned wallet flags the same 7 outputs"
expect_error "rescanned wallet, sendtoaddress" "Insufficient funds ($NOTE" cli 3 sendtoaddress "$MINER" 0.00001
op=$(cli 3 z_sendmany "$A" "[{\"address\":\"$MINER\",\"amount\":0.00001}]" 1 0)
r=$(wait_op 3 "$op"); case $r in failed*token-bearing*) ok "rescanned wallet, z_sendmany: refused" ;; *) fail "rescanned wallet z_sendmany: $r" ;; esac

# ---- 7. the expert path: a deliberate token transfer -----------------------

say "== 7. explicit inputs: a token SEND built by hand moves the tokens"
t=$(cli "$MN" sendtoaddress "$A" 0.1); cli "$MN" generate 1 >/dev/null; sync 3
coin=$(cli 3 listunspent 1 | jq -r '[.[] | select(.tokenbearing == false)][0] | "\(.txid) \(.vout)"')
set -- $coin
# spend the 400-token output and one ordinary coin; send all 400 tokens on
raw=$(cli 3 createrawtransaction "[{\"txid\":\"$S\",\"vout\":1},{\"txid\":\"$1\",\"vout\":$2}]" '{}')
raw=$("$ZTX" -regtest "$raw" "outscript=0:0x$("$SLP" send "$G" 400)" "outaddr=$DUST:$MINER" "outaddr=0.0998:$A")
signed=$(cli 3 signrawtransaction "$raw")
[ "$(printf '%s' "$signed" | jq -r .complete)" = true ] || fail "signrawtransaction refused an explicit token input"
# (not $t: the wait loops in confirm and sync use that name as a counter)
stx=$(cli 3 sendrawtransaction "$(printf '%s' "$signed" | jq -r .hex)")
confirm 3 "$stx"
ok "createrawtransaction + signrawtransaction + sendrawtransaction spent $S:1 in a token SEND (tx $stx)"
grep -vFx "$S:1" "$TMP/protected" >"$TMP/protected.new"; mv "$TMP/protected.new" "$TMP/protected"
[ "$(flagged 3)" = "$(cat "$TMP/protected")" ] || fail "after the token SEND: $(flagged 3 | tr '\n' ' ')"
[ "$(cli 3 listunspent 0 | jq --arg t "$stx" '[.[] | select(.txid == $t)] | length')" = 1 ] || fail "the change of the token SEND is missing"
[ "$(cli 3 listunspent 0 | jq --arg t "$stx" '[.[] | select(.txid == $t and .tokenbearing)] | length')" = 0 ] || fail "ordinary change of a token SEND is flagged"
ok "6 token outputs remain flagged; the ordinary change of the SEND (vout 2) is not flagged"
t=$(cli 3 sendtoaddress "$MINER" 0.05)
no_token_inputs "sendtoaddress after the token SEND" "$(inputs 3 "$t")"

PASSED=1
say "wallet_tokenguard.sh: PASS ($CHECKS checks)"
