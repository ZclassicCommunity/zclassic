#!/bin/sh
# ZSLP token creation, minting, sending and burning, end to end on regtest.
#
# Three nodes, each with its own datadir, wallet and token index. Node 2 only mines and
# is the neutral watcher; node 0 (wallet A) and node 1 (wallet B) build the token
# transactions with zslp_genesis, zslp_mint, zslp_send and zslp_burn. After every block
# all three indexes must give the same answer for every token and every transaction, the
# token and ZCL balances must be exact, and at the end the indexes must show NO invalid,
# unknown or burning transaction: nothing the wallets built destroyed a token by accident.
#
# Covered: genesis with and without a mint baton (and with a document), mint (baton kept,
# baton moved, baton closed), send to one and to many recipients, token change, exact
# amounts, wallets sending to each other, a wallet with tokens but no ordinary ZCL,
# refusals (over-precision, overflow, zero, z-address, unconfirmed or missing balance,
# no baton, locked wallet, index off), a dry run that changes nothing, the unconfirmed-
# parent rule, two sends in one block, burn, a reorg of a send, a restart, and the
# OP_RETURN bytes against Z23's own builder (the vendored slpscript tool).
#
# usage: zslp_send.sh [dir-with-zclassicd-zclassic-cli-zclassic-tx]
#   env CC=<compiler>   compiler for slpscript (default: cc)
#   env KEEP=1          keep the temp directory
#   env DUMP=<file>     write every block of the run as raw hex, one per line, in height order
#                       (to replay the run elsewhere; no such harness is in this tree yet)
#
# Needs: jq, a C compiler, the Zcash parameters in ~/.zcash-params.
# Every node runs on 127.0.0.1 with its own temp datadir; ports 49000-49999.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
SRC=${1:-$TOP/src}
SVC=$TOP/src/c23/services
ZD=$SRC/zclassicd
ZCLI=$SRC/zclassic-cli
for b in "$ZD" "$ZCLI"; do [ -x "$b" ] || { echo "missing $b" >&2; exit 2; }; done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/zcl-zslp-send.XXXXXX")
# a base whose P2P ports (BASE..BASE+9) and RPC ports (BASE+100..BASE+109) are all free, in 49000-49799
BASE=${ZSLP_PORT_BASE:-$((49000 + ($$ % 600)))}
used_ports=$( (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | awk '{print $4}' | sed 's/.*://' | sort -u)
while :; do
    clash=0
    for off in 0 1 2 3 4 5 6 7 8 9 100 101 102 103 104 105 106 107 108 109; do
        printf '%s\n' "$used_ports" | grep -qx "$((BASE + off))" && clash=1
    done
    [ $clash = 0 ] && break
    BASE=$((BASE + 10)); [ $BASE -lt 49880 ] || { echo "no free port range in 49000-49999" >&2; exit 2; }
done
PIDS=""
CHECKS=0

say() { printf '%s\n' "$*"; }
ok() { CHECKS=$((CHECKS + 1)); say "  ok   $*"; }
fail() {
    say "  FAIL $*"
    exit 1
}

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

# ---- nodes ----------------------------------------------------------------

cli() { n=$1; shift; "$ZCLI" -datadir="$TMP/node$n" -regtest -rpcport=$((BASE + 100 + n)) "$@"; }

# With PEER_BIN=<dir>, node 2 (the miner and relay) is a build that knows nothing about tokens, and the
# watcher whose index everything is compared with is a new node 5: tokens are then ordinary transactions
# to the miner, which must relay and mine them.
PEER_BIN=${PEER_BIN:-}
WN=2; OTHERN="0 1"; ALLN="0 1 2"; IDXN="0 1 2"; MNBIN=$ZD; MNARGS="-zslpindex=1 -txindex=1"
if [ -n "$PEER_BIN" ]; then
    [ -x "$PEER_BIN/zclassicd" ] || { echo "missing $PEER_BIN/zclassicd" >&2; exit 2; }
    WN=5; OTHERN="0 1 5"; ALLN="0 1 2 5"; IDXN="0 1 5"; MNBIN=$PEER_BIN/zclassicd; MNARGS=""
fi

# start <n> <zclassicd> [extra args]
start() {
    n=$1; bin=$2; shift 2
    dir=$TMP/node$n
    mkdir -p "$dir"
    if [ ! -f "$dir/zclassic.conf" ]; then
        {
            echo "regtest=1"
            echo "rpcuser=zslp"
            echo "rpcpassword=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
        } >"$dir/zclassic.conf"
    fi
    "$bin" -datadir="$dir" -regtest -server=1 -daemon=0 -showmetrics=0 \
        -listen=1 -bind=127.0.0.1 -port=$((BASE + n)) \
        -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=$((BASE + 100 + n)) \
        -dnsseed=0 -discover=0 -listenonion=0 -upnp=0 -keypool=20 -debuglogfile=1 -parkdeepreorg=0 \
        "$@" >"$dir/stdout.log" 2>&1 &
    pid=$!
    PIDS="$PIDS $pid"
    echo "$pid" >"$dir/pid"
    t=0
    until cli "$n" getblockcount >/dev/null 2>&1; do
        kill -0 "$pid" 2>/dev/null || { cat "$dir/stdout.log"; fail "node $n exited during startup"; }
        t=$((t + 1)); [ $t -lt 300 ] || fail "node $n did not start"
        sleep 1
    done
    t=0
    until cli "$n" getbalance >/dev/null 2>&1; do
        kill -0 "$pid" 2>/dev/null || { cat "$dir/stdout.log"; fail "node $n exited while loading its wallet"; }
        t=$((t + 1)); [ $t -lt 300 ] || fail "node $n did not load its wallet"
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

connect() { cli "$1" addnode "127.0.0.1:$((BASE + $2))" onetry >/dev/null; }

# ---- exact arithmetic helpers ---------------------------------------------

zat() { jq -n --arg a "$1" '$a | tonumber * 100000000 | round'; }
# a decimal token amount string with its point removed, as an integer
units() { printf '%s' "$1" | tr -d '.' | sed 's/^0*\([0-9]\)/\1/'; }

# expect_err <substring> <command...>: the command must fail and its output must contain the substring
expect_err() {
    sub=$1; shift
    if out=$("$@" 2>&1); then fail "expected an error containing \"$sub\" but it succeeded: $out"; fi
    case $out in
        *"$sub"*) ok "refused: $sub" ;;
        *) fail "expected an error containing \"$sub\", got: $out" ;;
    esac
}

# ---- waiting and agreeing -------------------------------------------------

wait_index() {
    t=0
    while :; do
        info=$(cli "$1" zslp_getindexinfo 2>/dev/null || true)
        tip=$(cli "$1" getbestblockhash)
        if [ -n "$info" ] && [ "$(printf '%s' "$info" | jq -r '.indexedblock')" = "$tip" ] &&
           [ "$(printf '%s' "$info" | jq -r '.synced')" = true ]; then return 0; fi
        t=$((t + 1)); [ $t -lt 240 ] || fail "the index of node $1 did not reach the tip: $info"
        sleep 1
    done
}

wait_tip() {
    want=$(cli 2 getbestblockhash)
    for n in $OTHERN; do
        t=0
        until [ "$(cli "$n" getbestblockhash)" = "$want" ]; do
            t=$((t + 1)); [ $t -lt 180 ] || fail "node $n did not reach the tip of node 2"
            sleep 1
        done
    done
}

# every node's index tells the same story about every token and every transaction made so far
TOKENS=""
TXS=""
agree() {
    for n in $IDXN; do wait_index $n; done
    for t in $TOKENS; do
        ref=$(cli $WN zslp_gettoken "$t" 1000 | jq -S -c .)
        reft=$(cli $WN zslp_listtransactions "$t" 0 1000 | jq -S -c .)
        for n in $OTHERN; do
            [ "$(cli $n zslp_gettoken "$t" 1000 | jq -S -c .)" = "$ref" ] || fail "node $n disagrees with node 2 about token $t"
            [ "$(cli $n zslp_listtransactions "$t" 0 1000 | jq -S -c .)" = "$reft" ] || fail "node $n disagrees with node 2 about the transactions of token $t"
        done
    done
    for x in $TXS; do
        ref=$(cli $WN zslp_gettransaction "$x" | jq -S -c .)
        for n in $OTHERN; do
            [ "$(cli $n zslp_gettransaction "$x" | jq -S -c .)" = "$ref" ] || fail "node $n disagrees with node 2 about transaction $x"
        done
    done
    ref=$(cli $WN zslp_getindexinfo | jq -S -c '{tokens, validtransactions, invalidtransactions, unknowntransactions, burntransactions, unspentoutputs}')
    for n in $OTHERN; do
        [ "$(cli $n zslp_getindexinfo | jq -S -c '{tokens, validtransactions, invalidtransactions, unknowntransactions, burntransactions, unspentoutputs}')" = "$ref" ] ||
            fail "node $n disagrees with node 2 about the index counters"
    done
}

# mine one block on node 2, wait for everyone, compare the three indexes
# the transactions of nodes 0 and 1 have reached the miner's mempool
relayed() {
    for n in $OTHERN; do
        for x in $(cli $n getrawmempool | jq -r '.[]'); do
            t=0
            until cli 2 getrawmempool | grep -q "$x"; do
                t=$((t + 1)); [ $t -lt 60 ] || fail "transaction $x did not reach node 2"
                sleep 1
            done
        done
    done
}

settle() {
    relayed
    cli 2 generate 1 >/dev/null
    wait_tip
    agree
}

# token invariant: the holders add up to minted - burned
conserved() {
    tk=$(cli $WN zslp_gettoken "$1" 1000)
    sum=0
    for a in $(printf '%s' "$tk" | jq -r '.holders[].amount'); do sum=$((sum + $(units "$a"))); done
    minted=$(units "$(printf '%s' "$tk" | jq -r .totalminted)")
    burned=$(units "$(printf '%s' "$tk" | jq -r .totalburned)")
    [ "$sum" = $((minted - burned)) ] || fail "token $1: holders add up to $sum, minted - burned is $((minted - burned))"
    ok "token $(printf %s "$1" | cut -c1-12)...: holders $sum = minted $minted - burned $burned"
}

# the wallet's confirmed token balance, from the wallet's own listunspent
tbal() { cli "$1" zslp_listunspent 1 | jq -r --arg t "$2" '([.balances[] | select(.tokenid == $t) | .amount] | first) // "0"'; }
# number of token outputs the wallet holds of a token
tcount() { cli "$1" zslp_listunspent 1 | jq -r --arg t "$2" '[.outputs[] | select(.tokenid == $t and .role == "token")] | length'; }
# a number of ZCL as zatoshi
zbal() { zat "$(cli "$1" getbalance)"; }

# the ZCL effect of a transaction on a wallet, from the chain data only: outputs paid to it minus inputs it spent
delta() {
    n=$1; x=$2
    raw=$(cli "$n" getrawtransaction "$x" 1)
    d=0
    for row in $(printf '%s' "$raw" | jq -r '.vout[] | select(.scriptPubKey.addresses != null) | "\(.scriptPubKey.addresses[0]):\(.value)"'); do
        a=${row%%:*}; v=${row#*:}
        [ "$(cli "$n" validateaddress "$a" | jq -r .ismine)" = true ] && d=$((d + $(zat "$v")))
    done
    for row in $(printf '%s' "$raw" | jq -r '.vin[] | select(.txid != null) | "\(.txid):\(.vout)"'); do
        ptx=${row%%:*}; pn=${row#*:}
        prow=$(cli "$n" getrawtransaction "$ptx" 1 | jq -r --argjson i "$pn" '.vout[$i] | "\(.scriptPubKey.addresses[0]):\(.value)"')
        a=${prow%%:*}; v=${prow#*:}
        [ "$(cli "$n" validateaddress "$a" | jq -r .ismine)" = true ] && d=$((d - $(zat "$v")))
    done
    echo "$d"
}

# fee_of <node> <txid>: inputs minus outputs, in zatoshi
fee_of() {
    n=$1; x=$2
    raw=$(cli "$n" getrawtransaction "$x" 1)
    out=0
    for v in $(printf '%s' "$raw" | jq -r '.vout[].value'); do out=$((out + $(zat "$v"))); done
    in=0
    for row in $(printf '%s' "$raw" | jq -r '.vin[] | select(.txid != null) | "\(.txid):\(.vout)"'); do
        ptx=${row%%:*}; pn=${row#*:}
        in=$((in + $(zat "$(cli "$n" getrawtransaction "$ptx" 1 | jq -r --argjson i "$pn" '.vout[$i].value')")))
    done
    echo $((in - out))
}

# the OP_RETURN of vout 0 as hex
opret() { cli "${2:-2}" getrawtransaction "$1" 1 | jq -r '.vout[0].scriptPubKey.hex'; }
vcount() { cli "${2:-2}" getrawtransaction "$1" 1 | jq -r '.vout | length'; }
vaddr() { cli $WN getrawtransaction "$1" 1 | jq -r --argjson i "$2" '.vout[$i].scriptPubKey.addresses[0]'; }
vval() { zat "$(cli $WN getrawtransaction "$1" 1 | jq -r --argjson i "$2" '.vout[$i].value')"; }

# ---- the script tool, built from the vendored Z23 builder ------------------

say "== build slpscript from the vendored Z23 builder"
# shellcheck disable=SC2086
${CC:-cc} -std=gnu11 -O2 -Wall -Wextra -Werror \
    -iquote "$SVC/glue" -iquote "$SVC/vendor/contexts/market/modules/zslp/include" \
    -iquote "$SVC/vendor/engine/modules/overlay/include" -iquote "$SVC/vendor/core/modules/script/include" \
    "$SVC/tools/slpscript.c" "$SVC/glue/zcl_token_guard.c" \
    "$SVC/vendor/contexts/market/modules/zslp/src/slp.c" "$SVC/vendor/engine/modules/overlay/src/overlay_codec.c" \
    -o "$TMP/slpscript"
SLP=$TMP/slpscript

# ---- the network ----------------------------------------------------------

start_all() {
    start 2 "$MNBIN" $MNARGS
    start 0 "$ZD" -zslpindex=1
    start 1 "$ZD" -zslpindex=1
    if [ "$WN" = 5 ]; then start 5 "$ZD" -zslpindex=1 -txindex=1; fi
}
connect_all() {
    connect 0 2; connect 1 2
    if [ "$WN" = 5 ]; then connect 5 2; fi
    want=$(echo $OTHERN | wc -w)
    t=0; until [ "$(cli 2 getconnectioncount)" -ge "$want" ]; do t=$((t + 1)); [ $t -lt 60 ] || fail "nodes did not connect"; sleep 1; done
}

say "== the network: node 2 mines and relays, nodes 0 and 1 are the wallets, $WN is the watcher${PEER_BIN:+ (node 2 is the peer build $PEER_BIN)}"
start_all
connect_all

cli 2 generate 110 >/dev/null
wait_tip
agree
A=$(cli 0 getnewaddress)
B=$(cli 1 getnewaddress)
M=$(cli 2 getnewaddress)
Z=$(cli 0 z_getnewaddress)

ftx=$(cli 2 sendtoaddress "$A" 30); settle
ok "wallet A is funded: $(cli 0 getbalance) ZCL"
[ "$(cli 1 getbalance)" = "0.00000000" ] || fail "wallet B is not empty"

# ---- genesis: with a baton ------------------------------------------------

say "== GENESIS with a mint baton"
before=$(zbal 0)
r=$(cli 0 zslp_genesis '{"ticker":"AAA","name":"Alpha","decimals":2,"initialquantity":"1000.00"}')
AAA=$(printf '%s' "$r" | jq -r .tokenid)
g1=$(printf '%s' "$r" | jq -r .txid)
[ "$AAA" = "$g1" ] || fail "the token id is not the genesis txid"
[ "$(printf '%s' "$r" | jq -r .broadcast)" = true ] || fail "genesis was not broadcast"
fee=$(zat "$(printf '%s' "$r" | jq -r .fee)")
TOKENS="$AAA"; TXS="$g1"
settle
[ "$(opret "$AAA")" = "$($SLP genesisdec AAA Alpha 2 2 100000)" ] || fail "the GENESIS message differs from Z23's builder"
ok "GENESIS message is byte for byte Z23's builder"
[ "$(vcount "$AAA")" = 4 ] || fail "genesis outputs: $(vcount "$AAA")"
[ "$(vval "$AAA" 1)" = 546 ] && [ "$(vval "$AAA" 2)" = 546 ] || fail "token dust is not 546"
[ "$(fee_of 0 "$AAA")" = "$fee" ] || fail "reported fee $fee, chain says $(fee_of 0 "$AAA")"
[ $(( $(zbal 0) - before )) = "$(delta 0 "$AAA")" ] || fail "ZCL balance moved by $(( $(zbal 0) - before )), chain says $(delta 0 "$AAA")"
ok "ZCL balance moved exactly by the fee and the two dust outputs that stay in the wallet: fee $fee"
tk=$(cli $WN zslp_gettoken "$AAA")
[ "$(printf '%s' "$tk" | jq -r .ticker)/$(printf '%s' "$tk" | jq -r .decimals)/$(printf '%s' "$tk" | jq -r .totalminted)" = "AAA/2/1000.00" ] || fail "token record: $tk"
[ "$(printf '%s' "$tk" | jq -r '.mintbaton.vout')" = 2 ] || fail "the baton is not at vout 2"
[ "$(tbal 0 "$AAA")" = "1000.00" ] || fail "wallet A holds $(tbal 0 "$AAA")"
conserved "$AAA"

# ---- genesis: no baton, fixed supply --------------------------------------

say "== GENESIS without a baton"
r=$(cli 0 zslp_genesis '{"ticker":"BBB","name":"Beta","decimals":0,"initialquantity":"5000","batonaddress":null}')
BBB=$(printf '%s' "$r" | jq -r .tokenid)
TOKENS="$TOKENS $BBB"; TXS="$TXS $BBB"
settle
[ "$(opret "$BBB")" = "$($SLP genesisdec BBB Beta 0 0 5000)" ] || fail "no-baton GENESIS message differs from Z23's builder"
[ "$(vcount "$BBB")" = 3 ] || fail "no-baton genesis has $(vcount "$BBB") outputs"
[ "$(cli $WN zslp_gettoken "$BBB" | jq -r .mintbaton)" = null ] || fail "BBB has a baton"
[ "$(tbal 0 "$BBB")" = "5000" ] || fail "A holds $(tbal 0 "$BBB") BBB"
ok "BBB: fixed supply of 5000, no baton, 3 outputs (message, tokens, ZCL change)"
conserved "$BBB"

# ---- genesis: a document, 8 decimals, the baton to wallet B -----------------

say "== GENESIS with a document and the baton at wallet B"
DH=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
r=$(cli 0 zslp_genesis "{\"ticker\":\"CCC\",\"name\":\"Gamma-3 coin\",\"decimals\":8,\"initialquantity\":\"21.00000000\",\"documenturl\":\"https://example.org/c.json\",\"documenthash\":\"$DH\",\"batonaddress\":\"$B\"}")
CCC=$(printf '%s' "$r" | jq -r .tokenid)
TOKENS="$TOKENS $CCC"; TXS="$TXS $CCC"
settle
tk=$(cli $WN zslp_gettoken "$CCC")
[ "$(printf '%s' "$tk" | jq -r .documenturi)" = "https://example.org/c.json" ] || fail "document url: $tk"
[ "$(printf '%s' "$tk" | jq -r .documenthash)" = "$DH" ] || fail "document hash: $tk"
[ "$(printf '%s' "$tk" | jq -r .totalminted)" = "21.00000000" ] || fail "supply: $tk"
[ "$(vaddr "$CCC" 2)" = "$B" ] || fail "the baton is not at wallet B's address"
[ "$(cli 1 zslp_listunspent 1 | jq -r '[.outputs[] | select(.role == "mintbaton")] | length')" = 1 ] || fail "wallet B does not list the baton"
ok "CCC: document url and hash in the index, baton at B, 8 decimals"
conserved "$CCC"

# ---- refusals before anything is spent --------------------------------------

say "== refusals"
expect_err "ticker must be" cli 0 zslp_genesis '{"ticker":"bad ticker","name":"x","decimals":0,"initialquantity":"1"}'
expect_err "ticker must be" cli 0 zslp_genesis '{"ticker":"ABCDEFGHIJK","name":"x","decimals":0,"initialquantity":"1"}'
expect_err "decimals must be between 0 and 8" cli 0 zslp_genesis '{"ticker":"X","name":"x","decimals":9,"initialquantity":"1"}'
expect_err "greater than zero" cli 0 zslp_genesis '{"ticker":"X","name":"x","decimals":2,"initialquantity":"0.00"}'
expect_err "decimal places" cli 0 zslp_genesis '{"ticker":"X","name":"x","decimals":2,"initialquantity":"1.001"}'
expect_err "exceeds the maximum" cli 0 zslp_genesis '{"ticker":"X","name":"x","decimals":2,"initialquantity":"21000000000000.01"}'
expect_err "must be a string" cli 0 zslp_genesis '{"ticker":"X","name":"x","decimals":2,"initialquantity":5}'
expect_err "unknown field" cli 0 zslp_genesis '{"ticker":"X","name":"x","decimals":2,"initialquantity":"5","bogus":1}'
expect_err "shielded address" cli 0 zslp_genesis "{\"ticker\":\"X\",\"name\":\"x\",\"decimals\":2,\"initialquantity\":\"5\",\"address\":\"$Z\"}"
expect_err "64 hex" cli 0 zslp_genesis '{"ticker":"X","name":"x","decimals":2,"initialquantity":"5","documenthash":"abcd"}'
expect_err "documenturl" cli 0 zslp_genesis '{"ticker":"X","name":"x","decimals":2,"initialquantity":"5","documenturl":"has space"}'

expect_err "decimal places" cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"1.234\"}]"
expect_err "plain decimal" cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"1e2\"}]"
expect_err "plain decimal" cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"-1\"}]"
expect_err "digits before the decimal point" cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\".5\"}]"
expect_err "must be a string" cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":1.5}]"
expect_err "greater than zero" cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"0.00\"}]"
expect_err "treat as unknown" cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"92233720368547758.08\"}]"
expect_err "too large" cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"184467440737095516.16\"}]"
expect_err "shielded address" cli 0 zslp_send "$AAA" "[{\"address\":\"$Z\",\"amount\":\"1.00\"}]"
expect_err "not a valid" cli 0 zslp_send "$AAA" '[{"address":"notanaddress","amount":"1.00"}]'
expect_err "insufficient confirmed token balance" cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"1000.01\"}]"
expect_err "insufficient confirmed token balance" cli 1 zslp_send "$AAA" "[{\"address\":\"$A\",\"amount\":\"1.00\"}]"
expect_err "no such token" cli 0 zslp_send 0000000000000000000000000000000000000000000000000000000000000001 "[{\"address\":\"$B\",\"amount\":\"1\"}]"
expect_err "minconf must be at least 1" cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"1.00\"}]" 0
expect_err "recipients must be" cli 0 zslp_send "$AAA" "[]"
expect_err "unknown recipient field" cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"1.00\",\"memo\":\"x\"}]"
expect_err "pass confirm=true" cli 0 zslp_burn "$AAA" "1.00" false
expect_err "does not hold the confirmed mint baton" cli 0 zslp_mint "$CCC" "1.00000000"
expect_err "does not hold the confirmed mint baton" cli 0 zslp_mint "$BBB" "1"
LONGNAME=$(awk 'BEGIN { for (i = 0; i < 64; i++) printf "n" }')
LONGURL=https://$(awk 'BEGIN { for (i = 0; i < 247; i++) printf "a" }')
expect_err "would not be relayed" cli 0 zslp_genesis "{\"ticker\":\"LONGTOK\",\"name\":\"$LONGNAME\",\"decimals\":8,\"initialquantity\":\"1\",\"documenturl\":\"$LONGURL\",\"documenthash\":\"$(printf '%064d' 7)\"}"
[ "$(cli 0 getrawmempool | jq length)" = 0 ] || fail "a refused request left something in the mempool"
ok "every refusal left the mempool empty"

say "== the index off, and a locked wallet"
start 3 "$ZD"
for c in 'zslp_send 0000000000000000000000000000000000000000000000000000000000000001 [{"address":"x","amount":"1"}]' \
         'zslp_genesis {"ticker":"X","name":"x","decimals":0,"initialquantity":"1"}' \
         'zslp_mint 0000000000000000000000000000000000000000000000000000000000000001 1' \
         'zslp_burn 0000000000000000000000000000000000000000000000000000000000000001 1 true'; do
    # shellcheck disable=SC2086
    expect_err "token index is disabled" cli 3 $c
done
[ -d "$TMP/node3/regtest/zslpindex" ] && fail "a node without -zslpindex created an index"
ok "with the index off the four commands answer that it is disabled; no index directory exists"
start 4 "$ZD" -zslpindex=1 -experimentalfeatures -developerencryptwallet
cli 4 encryptwallet "pw-1-2-3" | grep -q "wallet encrypted" || fail "encryptwallet did not encrypt"
t=0; while kill -0 "$(cat "$TMP/node4/pid")" 2>/dev/null; do t=$((t + 1)); [ $t -lt 60 ] || fail "node 4 did not stop after encryptwallet"; sleep 1; done
start 4 "$ZD" -zslpindex=1 -experimentalfeatures -developerencryptwallet
expect_err "walletpassphrase" cli 4 zslp_genesis '{"ticker":"X","name":"x","decimals":0,"initialquantity":"1"}'
expect_err "walletpassphrase" cli 4 zslp_send 0000000000000000000000000000000000000000000000000000000000000001 '[{"address":"x","amount":"1"}]'
expect_err "walletpassphrase" cli 4 zslp_burn 0000000000000000000000000000000000000000000000000000000000000001 1 true
ok "a locked wallet gets the usual unlock-needed error"
stop 3; stop 4

# ---- a dry run changes nothing ----------------------------------------------

say "== dry run"
before=$(zbal 0)
r=$(cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"5.00\"}]" 1 null true)
[ "$(printf '%s' "$r" | jq -r .broadcast)" = false ] || fail "a dry run says it broadcast"
[ "$(printf '%s' "$r" | jq -r '.hex | length > 100')" = true ] || fail "no hex from the dry run"
[ "$(cli 0 getrawmempool | jq length)" = 0 ] || fail "a dry run put a transaction in the mempool"
[ "$(zbal 0)" = "$before" ] || fail "a dry run changed the ZCL balance"
[ "$(tbal 0 "$AAA")" = "1000.00" ] || fail "a dry run changed the token balance"
dec=$(cli 0 decoderawtransaction "$(printf '%s' "$r" | jq -r .hex)")
[ "$(printf '%s' "$dec" | jq -r '.vout | length')" = 4 ] || fail "dry-run layout"
ok "dry run: signed hex returned, nothing broadcast, nothing spent"

# ---- send to one recipient ---------------------------------------------------

say "== SEND to one recipient, with token change"
beforeA=$(zbal 0); beforeB=$(zbal 1)
r=$(cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"100.50\"}]")
s1=$(printf '%s' "$r" | jq -r .txid)
[ "$(printf '%s' "$r" | jq -r .tokenchange)" = "899.50" ] || fail "token change: $r"
fee=$(zat "$(printf '%s' "$r" | jq -r .fee)")
TXS="$TXS $s1"
settle
[ "$(opret "$s1")" = "$($SLP send "$AAA" 10050 89950)" ] || fail "the SEND message differs from Z23's builder"
ok "SEND message is byte for byte Z23's builder"
[ "$(vaddr "$s1" 1)" = "$B" ] || fail "vout 1 is not the recipient"
[ "$(vval "$s1" 1)" = 546 ] && [ "$(vval "$s1" 2)" = 546 ] || fail "token outputs are not dust"
src=$(cli $WN zslp_gettransaction "$s1" | jq -r '.inputs[0].txid')
[ "$(vcount "$s1")" = 4 ] || fail "outputs: $(vcount "$s1")"
changeaddr=$(printf '%s' "$r" | jq -r .changeaddress)
[ "$(vaddr "$s1" 2)" = "$changeaddr" ] || fail "token change did not go to the reported address"
srcaddr=$(cli $WN getrawtransaction "$src" 1 | jq -r --argjson i "$(cli $WN zslp_gettransaction "$s1" | jq -r '.inputs[0].vout')" '.vout[$i].scriptPubKey.addresses[0]')
[ "$changeaddr" = "$srcaddr" ] || fail "token change went to $changeaddr, not the source address $srcaddr"
ok "token change returned to the address of the token input"
[ "$(tbal 0 "$AAA")" = "899.50" ] || fail "A holds $(tbal 0 "$AAA")"
[ "$(tbal 1 "$AAA")" = "100.50" ] || fail "B holds $(tbal 1 "$AAA")"
[ "$(fee_of 0 "$s1")" = "$fee" ] || fail "fee mismatch"
[ $(( $(zbal 0) - beforeA )) = "$(delta 0 "$s1")" ] || fail "wallet A ZCL moved by $(( $(zbal 0) - beforeA )), chain says $(delta 0 "$s1")"
[ $(( $(zbal 1) - beforeB )) = 546 ] || fail "wallet B ZCL moved by $(( $(zbal 1) - beforeB )), expected the 546 dust"
ok "A: tokens 899.50, B: 100.50; ZCL moved exactly (fee $fee, 546 dust to B)"
[ "$(cli $WN zslp_gettransaction "$s1" | jq -r '.validity + "/" + .inputamount + "/" + .outputamount + "/" + .burnedamount')" = "valid/1000.00/1000.00/0.00" ] || fail "index view of the send"
conserved "$AAA"

# ---- send to many ------------------------------------------------------------

say "== SEND to many recipients"
A2=$(cli 0 getnewaddress)
r=$(cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"1.01\"},{\"address\":\"$A2\",\"amount\":\"2.02\"},{\"address\":\"$B\",\"amount\":\"3.03\"}]")
s2=$(printf '%s' "$r" | jq -r .txid)
TXS="$TXS $s2"
settle
[ "$(opret "$s2")" = "$($SLP send "$AAA" 101 202 303 89344)" ] || fail "multi-recipient SEND message differs from Z23's builder"
[ "$(vcount "$s2")" = 6 ] || fail "outputs: $(vcount "$s2")"
[ "$(vaddr "$s2" 1)/$(vaddr "$s2" 2)/$(vaddr "$s2" 3)" = "$B/$A2/$B" ] || fail "recipient order"
[ "$(tbal 1 "$AAA")" = "104.54" ] || fail "B holds $(tbal 1 "$AAA")"
[ "$(tbal 0 "$AAA")" = "895.46" ] || fail "A holds $(tbal 0 "$AAA")"
ok "three recipients in order, then the token change, then the ZCL change"
conserved "$AAA"

# ---- B has tokens but no ordinary ZCL ------------------------------------------

say "== a wallet with tokens and no ordinary ZCL"
expect_err "not enough ordinary ZCL" cli 1 zslp_send "$AAA" "[{\"address\":\"$A\",\"amount\":\"1.00\"}]"
[ "$(cli 1 getrawmempool | jq length)" = 0 ] || fail "left something in the mempool"
ok "B's token dust is never used as the fee"
cli 2 sendtoaddress "$B" 2 >/dev/null; settle
beforeA=$(zbal 0); beforeB=$(zbal 1)
r=$(cli 1 zslp_send "$AAA" "[{\"address\":\"$A\",\"amount\":\"4.04\"}]")
s3=$(printf '%s' "$r" | jq -r .txid); TXS="$TXS $s3"
settle
[ "$(tbal 0 "$AAA")" = "899.50" ] || fail "A holds $(tbal 0 "$AAA")"
[ "$(tbal 1 "$AAA")" = "100.50" ] || fail "B holds $(tbal 1 "$AAA")"
[ $(( $(zbal 1) - beforeB )) = "$(delta 1 "$s3")" ] || fail "B ZCL moved by $(( $(zbal 1) - beforeB )), chain says $(delta 1 "$s3")"
[ $(( $(zbal 0) - beforeA )) = 546 ] || fail "A ZCL moved by $(( $(zbal 0) - beforeA )), expected 546"
ok "B sent tokens to A once it had ZCL: A 899.50, B 100.50"
conserved "$AAA"

# ---- mint ----------------------------------------------------------------------

say "== MINT, baton kept"
oldbaton=$(cli $WN zslp_gettoken "$AAA" | jq -r '.mintbaton.txid + ":" + (.mintbaton.vout|tostring)')
r=$(cli 0 zslp_mint "$AAA" "250.50")
m1=$(printf '%s' "$r" | jq -r .txid); TXS="$TXS $m1"
settle
[ "$(opret "$m1")" = "$($SLP mint "$AAA" 2 25050)" ] || fail "the MINT message differs from Z23's builder"
tk=$(cli $WN zslp_gettoken "$AAA")
[ "$(printf '%s' "$tk" | jq -r .totalminted)" = "1250.50" ] || fail "minted: $tk"
[ "$(printf '%s' "$tk" | jq -r '.mintbaton.txid')" = "$m1" ] && [ "$(printf '%s' "$tk" | jq -r '.mintbaton.vout')" = 2 ] || fail "baton did not move to the mint transaction"
[ "$(cli $WN zslp_gettransaction "$m1" | jq -r '.inputs[0].txid + ":" + (.inputs[0].vout|tostring)')" = "$oldbaton" ] || fail "the mint did not spend the baton"
[ "$(tbal 0 "$AAA")" = "1150.00" ] || fail "A holds $(tbal 0 "$AAA")"
[ "$(vaddr "$m1" 2)" = "$(cli $WN getrawtransaction "${oldbaton%:*}" 1 | jq -r --argjson i "${oldbaton#*:}" '.vout[$i].scriptPubKey.addresses[0]')" ] || fail "the new baton is not at the old baton's address"
ok "MINT: 250.50 created, the baton returned to its address"
conserved "$AAA"

say "== MINT by wallet B, the baton at B, closing the supply"
cli 2 sendtoaddress "$B" 1 >/dev/null; settle
r=$(cli 1 zslp_mint "$CCC" "1.50000000" null)
m2=$(printf '%s' "$r" | jq -r .txid); TXS="$TXS $m2"
settle
[ "$(opret "$m2")" = "$($SLP mint "$CCC" 0 150000000)" ] || fail "the closing MINT message differs from Z23's builder"
[ "$(cli $WN zslp_gettoken "$CCC" | jq -r .mintbaton)" = null ] || fail "the baton still exists"
[ "$(cli $WN zslp_gettoken "$CCC" | jq -r .totalminted)" = "22.50000000" ] || fail "minted"
[ "$(tbal 1 "$CCC")" = "1.50000000" ] || fail "B holds $(tbal 1 "$CCC")"
expect_err "does not hold the confirmed mint baton" cli 1 zslp_mint "$CCC" "1.00000000"
ok "baton closed: the supply of CCC is fixed at 22.50000000 for good"
conserved "$CCC"

# ---- unconfirmed parents and two sends in one block ------------------------------

say "== the unconfirmed-parent rule"
r=$(cli 0 zslp_send "$BBB" "[{\"address\":\"$B\",\"amount\":\"40\"}]")
u1=$(printf '%s' "$r" | jq -r .txid); TXS="$TXS $u1"
expect_err "insufficient confirmed token balance" cli 0 zslp_send "$BBB" "[{\"address\":\"$B\",\"amount\":\"10\"}]"
expect_err "insufficient confirmed token balance" cli 1 zslp_send "$BBB" "[{\"address\":\"$A\",\"amount\":\"10\"}]"
ok "a token output that is not confirmed is not spent: not the change, not the received dust"
[ "$(cli 0 getrawmempool | jq length)" = 1 ] || fail "the refused sends left something in the mempool"
settle
[ "$(tbal 0 "$BBB")" = "4960" ] && [ "$(tbal 1 "$BBB")" = "40" ] || fail "BBB: A $(tbal 0 "$BBB") B $(tbal 1 "$BBB")"
r=$(cli 0 zslp_send "$BBB" "[{\"address\":\"$B\",\"amount\":\"10\"}]")
u2=$(printf '%s' "$r" | jq -r .txid); TXS="$TXS $u2"
settle
[ "$(tbal 0 "$BBB")" = "4950" ] && [ "$(tbal 1 "$BBB")" = "50" ] || fail "BBB after the second send"
ok "after one confirmation the change is spendable"

say "== minconf and an explicit fee"
expect_err "insufficient confirmed token balance" cli 0 zslp_send "$BBB" "[{\"address\":\"$B\",\"amount\":\"1\"}]" 50
expect_err "below the minimum relay fee" cli 0 zslp_send "$BBB" "[{\"address\":\"$B\",\"amount\":\"1\"}]" 1 0.00000001
expect_err "fee must be between" cli 0 zslp_send "$BBB" "[{\"address\":\"$B\",\"amount\":\"1\"}]" 1 5
r=$(cli 0 zslp_send "$BBB" "[{\"address\":\"$B\",\"amount\":\"1\"}]" 1 0.0001)
f1=$(printf '%s' "$r" | jq -r .txid); TXS="$TXS $f1"
[ "$(printf '%s' "$r" | jq -r .fee)" = "0.00010000" ] || fail "the reported fee is $(printf '%s' "$r" | jq -r .fee), asked for 0.0001"
settle
[ "$(fee_of 0 "$f1")" = 10000 ] || fail "the chain says the fee is $(fee_of 0 "$f1") zatoshi, asked for 10000"
ok "an explicit fee is paid exactly; a fee below the relay minimum or above the maximum is refused; minconf is honoured"

say "== two sends in one block, each from its own confirmed output"
c1=$(cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"250.50\"}]" | jq -r .txid)
c2=$(cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"2.02\"}]" | jq -r .txid)
[ "$(cli 0 getrawmempool | jq length)" = 2 ] || fail "expected two transactions in the mempool"
TXS="$TXS $c1 $c2"
relayed; cli 2 generate 1 >/dev/null; wait_tip; agree
h=$(cli 2 getblockcount)
[ "$(cli $WN getblock "$h" | jq -r '.tx | length')" = 3 ] || fail "the two sends are not in one block"
for x in $c1 $c2; do [ "$(cli $WN zslp_gettransaction "$x" | jq -r .validity)" = valid ] || fail "$x is not valid"; done
[ "$(cli $WN zslp_gettransaction "$c1" | jq -r "[.inputs[] | .txid + \":\" + (.vout|tostring)] | sort | join(\",\")")" != "$(cli $WN zslp_gettransaction "$c2" | jq -r "[.inputs[] | .txid + \":\" + (.vout|tostring)] | sort | join(\",\")")" ] || fail "the two sends spent the same token output"
ok "both sends are valid in the same block"
conserved "$AAA"

# ---- burn ------------------------------------------------------------------------

say "== BURN"
expect_err "pass confirm=true" cli 0 zslp_burn "$AAA" "10.00" false
expect_err "pass confirm=true" cli 0 zslp_burn "$AAA" "10.00"
r=$(cli 0 zslp_burn "$AAA" "10.00" false '{"dryrun":true}')
[ "$(printf '%s' "$r" | jq -r .broadcast)" = false ] || fail "burn dry run"
[ "$(cli 0 getrawmempool | jq length)" = 0 ] || fail "burn dry run broadcast"
before=$(cli $WN zslp_gettoken "$AAA" | jq -r .totalburned)
bal0=$(units "$(tbal 0 "$AAA")")
r=$(cli 0 zslp_burn "$AAA" "10.00" true)
b1=$(printf '%s' "$r" | jq -r .txid); TXS="$TXS $b1"
[ "$(printf '%s' "$r" | jq -r .burned)" = "10.00" ] || fail "burn result: $r"
settle
tk=$(cli $WN zslp_gettoken "$AAA")
[ "$(printf '%s' "$tk" | jq -r .burnedinsends)" = "10.00" ] && [ "$(printf '%s' "$tk" | jq -r .burnedbyspending)" = "0.00" ] || fail "burn accounting: $tk"
[ "$(units "$(tbal 0 "$AAA")")" = $((bal0 - 1000)) ] || fail "A's balance after the burn: $(tbal 0 "$AAA")"
[ "$(cli $WN zslp_gettransaction "$b1" | jq -r '.validity + "/" + .burnedamount')" = "valid/10.00" ] || fail "burn view"
ok "BURN: exactly 10.00 destroyed, accounted as burned in a send, the rest is back with A"
conserved "$AAA"

say "== BURN of a whole balance keeps the ZCL change out of a token slot"
bal=$(tbal 0 "$BBB"); n=$(tcount 0 "$BBB")
r=$(cli 0 zslp_burn "$BBB" "$bal" true)
b2=$(printf '%s' "$r" | jq -r .txid); TXS="$TXS $b2"
[ "$n" = 1 ] || fail "expected A to hold BBB in one output, it holds $n"
settle
[ "$(tbal 0 "$BBB")" = "0" ] || fail "A still holds BBB"
[ "$(cli $WN zslp_gettoken "$BBB" | jq -r .burnedinsends)" = "$bal" ] || fail "burned $(cli $WN zslp_gettoken "$BBB" | jq -r .burnedinsends), asked for $bal"
lu=$(cli 0 listunspent 1 | jq -c --arg t "$b2" '[.[] | select(.txid == $t) | {vout, tokenbearing}] | sort_by(.vout)')
[ "$lu" = '[{"vout":1,"tokenbearing":true},{"vout":2,"tokenbearing":false}]' ] || fail "outputs of the full burn: vout 1 is the token slot, the ZCL change at vout 2 is a plain coin: $lu"
[ "$(cli $WN getrawtransaction "$b2" 1 | jq -r '.vout | length')" -ge 3 ] || fail "full burn layout"
ok "after a full burn vout[1] is a token slot (dust) and the ZCL change is a plain, spendable coin"
conserved "$BBB"

# ---- reorg of a send -----------------------------------------------------------------

say "== reorg of a send"
pre=$(cli $WN zslp_gettoken "$AAA" 1000 | jq -S -c .)
preB=$(cli 1 zslp_listunspent 1 | jq -S -c .)
r=$(cli 0 zslp_send "$AAA" "[{\"address\":\"$B\",\"amount\":\"7.07\"}]")
rx=$(printf '%s' "$r" | jq -r .txid); TXS="$TXS $rx"
settle
post=$(cli $WN zslp_gettoken "$AAA" 1000 | jq -S -c .)
[ "$pre" != "$post" ] || fail "the send did not change the token"
tip=$(cli 2 getbestblockhash)
for n in $ALLN; do cli $n invalidateblock "$tip"; done
for n in $IDXN; do wait_index $n; done
[ "$(cli $WN zslp_gettoken "$AAA" 1000 | jq -S -c .)" = "$pre" ] || fail "node 2's index did not return to its exact prior state"
for n in $OTHERN; do [ "$(cli $n zslp_gettoken "$AAA" 1000 | jq -S -c .)" = "$pre" ] || fail "node $n's index did not return to its exact prior state"; done
[ "$(cli 1 zslp_listunspent 1 | jq -S -c .)" = "$preB" ] || fail "B's token outputs did not return exactly"
ok "after invalidateblock all three indexes are exactly what they were before the send"
for n in $ALLN; do cli $n reconsiderblock "$tip"; done
wait_tip; agree
[ "$(cli $WN zslp_gettoken "$AAA" 1000 | jq -S -c .)" = "$post" ] || fail "reconsiderblock did not restore the exact state"
ok "after reconsiderblock the exact state is back"
conserved "$AAA"

# ---- restart ----------------------------------------------------------------------------

say "== restart"
tA=$(tbal 0 "$AAA"); tB=$(tbal 1 "$AAA"); zA=$(zbal 0)
for n in $ALLN; do stop "$n"; done
start_all
connect_all
wait_tip; agree
[ "$(tbal 0 "$AAA")" = "$tA" ] && [ "$(tbal 1 "$AAA")" = "$tB" ] && [ "$(zbal 0)" = "$zA" ] || fail "balances changed over a restart"
r=$(cli 1 zslp_send "$AAA" "[{\"address\":\"$A\",\"amount\":\"0.07\"}]")
x=$(printf '%s' "$r" | jq -r .txid); TXS="$TXS $x"
settle
[ "$(tbal 0 "$AAA")" = "$(printf '%s' "$tA + 0.07" | awk '{printf "%.2f", $1 + $3}')" ] || fail "A after the post-restart send: $(tbal 0 "$AAA")"
ok "balances survive a restart, and sending still works"

# ---- the token guard still protects every token output ---------------------------------

say "== the guard still protects token outputs from ordinary sends"
before=$(cli $WN zslp_gettoken "$AAA" 1000 | jq -S -c .)
x=$(cli 0 sendtoaddress "$M" 1)
settle
[ "$(cli $WN zslp_getindexinfo | jq -r .burntransactions)" = 0 ] || fail "an ordinary send burned a token"
ok "an ordinary sendtoaddress did not touch a token output"
expect_err "protected" cli 0 sendtoaddress "$M" "$(cli 0 getbalance)"
[ "$(cli $WN zslp_gettoken "$AAA" 1000 | jq -S -c .)" = "$before" ] || fail "the token changed under ordinary sends"
ok "an ordinary send of the whole balance is refused because token outputs are protected"

# ---- varied transactions -------------------------------------------------------------------

say "== varied transactions: nine tokens with 0 to 8 decimals, every kind of send, mint and burn"
# n base units of a token with d decimals, as a decimal string
amt() { awk -v n="$1" -v d="$2" 'BEGIN { s = sprintf("%d", n); if (d == 0) { print s; exit } while (length(s) <= d) s = "0" s; print substr(s, 1, length(s) - d) "." substr(s, length(s) - d + 1) }'; }
VT=""
for d in 0 1 2 3 4 5 6 7 8; do
    q=$(awk -v d=$d 'BEGIN { f = substr("56789012", 1, d); print (d == 0 ? "1234" : "1234." f) }')
    r=$(cli 0 zslp_genesis "{\"ticker\":\"V$d\",\"name\":\"Varied $d\",\"decimals\":$d,\"initialquantity\":\"$q\"}")
    VT="$VT $(printf '%s' "$r" | jq -r .tokenid)"
done
TOKENS="$TOKENS $VT"; TXS="$TXS $VT"
settle
ok "nine tokens created, decimals 0 to 8"
A3=$(cli 0 getnewaddress)

d=0
for t in $VT; do
    x=$(cli 0 zslp_send "$t" "[{\"address\":\"$B\",\"amount\":\"$(amt 1 $d)\"}]" | jq -r .txid); TXS="$TXS $x"
    d=$((d + 1))
done
settle
d=0
for t in $VT; do
    x=$(cli 0 zslp_send "$t" "[{\"address\":\"$B\",\"amount\":\"$(amt 1 $d)\"},{\"address\":\"$A3\",\"amount\":\"$(amt 2 $d)\"},{\"address\":\"$B\",\"amount\":\"$(amt 3 $d)\"}]" | jq -r .txid); TXS="$TXS $x"
    d=$((d + 1))
done
settle
d=0
for t in $VT; do
    x=$(cli 0 zslp_mint "$t" "$(amt 7 $d)" | jq -r .txid); TXS="$TXS $x"
    d=$((d + 1))
done
settle
ok "single sends, three-recipient sends and mints of the smallest units, for every decimals setting"
for t in $VT; do conserved "$t"; done

# a send that spends every output the wallet holds of the token: many inputs, one recipient
for t in $VT; do
    n=$(tcount 0 "$t")
    [ "$n" -ge 3 ] || fail "expected A to hold at least three outputs of $t, it holds $n"
    r=$(cli 0 zslp_send "$t" "[{\"address\":\"$B\",\"amount\":\"$(tbal 0 "$t")\"}]")
    [ "$(printf '%s' "$r" | jq -r .tokeninputs)" = "$n" ] || fail "the consolidation spent $(printf '%s' "$r" | jq -r .tokeninputs) of $n outputs"
    [ "$(printf '%s' "$r" | jq -r .tokenchange)" = "$(amt 0 $(cli $WN zslp_gettoken "$t" | jq -r .decimals))" ] || fail "a send of everything left token change"
    TXS="$TXS $(printf '%s' "$r" | jq -r .txid)"
done
settle
for t in $VT; do [ "$(tbal 0 "$t")" = "0" ] || [ "$(units "$(tbal 0 "$t")")" = 0 ] || fail "A still holds $t"; done
ok "A sent everything it held of each token, in one transaction each, with no token change"
for t in $VT; do conserved "$t"; done

# burns by B, three tokens
for d in 0 4 8; do
    t=$(echo $VT | cut -d' ' -f$((d + 1)))
    x=$(cli 1 zslp_burn "$t" "$(amt 1 $d)" true | jq -r .txid); TXS="$TXS $x"
done
settle
ok "B burned one base unit each of V0, V4 and V8"

# the biggest send: 18 recipients and the token change make 19 outputs; one more recipient is refused
V2=$(echo $VT | cut -d' ' -f3)
RC=""
i=0; while [ $i -lt 18 ]; do RC="$RC{\"address\":\"$A3\",\"amount\":\"0.01\"},"; i=$((i + 1)); done
RC19="$RC{\"address\":\"$A3\",\"amount\":\"0.01\"}"
expect_err "at most 19" cli 1 zslp_send "$V2" "[$RC19]"
x=$(cli 1 zslp_send "$V2" "[${RC%,}]" | jq -r .txid); TXS="$TXS $x"
settle
[ "$(cli $WN getrawtransaction "$x" 1 | jq -r '.vout | length')" = 21 ] || fail "the 18-recipient send has $(cli $WN getrawtransaction "$x" 1 | jq -r '.vout | length') outputs, expected 21 (message, 18, token change, ZCL change)"
ok "an 18-recipient send is valid; a 19th recipient (20 token outputs with the change) is refused"
for t in $VT; do conserved "$t"; done

# ---- the whole run ----------------------------------------------------------------------

say "== the whole run"
info=$(cli $WN zslp_getindexinfo)
for k in invalidtransactions unknowntransactions burntransactions; do
    [ "$(printf '%s' "$info" | jq -r ".$k")" = 0 ] || fail "the index counts $k = $(printf '%s' "$info" | jq -r ".$k"): $info"
done
ok "no invalid, unknown or burning transaction: nothing the wallets built destroyed a token by accident"
for t in $TOKENS; do conserved "$t"; done
agree
ok "all three indexes agree on every token and on all $(echo $TXS | wc -w) transactions"

# ---- a second opinion --------------------------------------------------------------------------

say "== slpverify: raw blocks replayed by an independent ledger with the vendored Z23 rules"
${CC:-cc} -std=gnu11 -O2 -Wall -Wextra -Werror \
    -iquote "$SVC/glue" -iquote "$SVC/vendor/contexts/market/modules/zslp/include" \
    -iquote "$SVC/vendor/engine/modules/overlay/include" -iquote "$SVC/vendor/core/modules/script/include" \
    "$SVC/tools/slpverify.c" "$SVC/glue/zcl_slp_index.c" \
    "$SVC/vendor/contexts/market/modules/zslp/src/slp.c" "$SVC/vendor/engine/modules/overlay/src/overlay_codec.c" \
    -o "$TMP/slpverify"
h=$(cli 2 getblockcount)
: >"$TMP/blocks.hex"
i=1
while [ $i -le "$h" ]; do
    cli $WN getblock "$(cli 2 getblockhash $i)" 0 >>"$TMP/blocks.hex"
    i=$((i + 1))
done
"$TMP/slpverify" "$TMP/blocks.hex" 30 >"$TMP/verify.out" || fail "slpverify: $(tail -3 "$TMP/verify.out")"
nslp=$(sed -n 's/^summary slp \([0-9]*\) .*/\1/p' "$TMP/verify.out")
ok "slpverify judged $nslp SLP transactions in $h blocks: every one is valid"
# its token totals and its unspent token outputs are exactly the wallets' view
{
    for n in 0 1; do
        cli $n zslp_listunspent 1 | jq -r '.outputs[] | [.txid, .vout, .tokenid, .role, .amount] | @tsv'
    done
} | awk -F'\t' '{ a = $5; gsub(/\./, "", a); sub(/^0+/, "", a); if (a == "") a = "0"; print "unspent", $1, $2, $3, $4, a }' | sort >"$TMP/unspent.node"
grep '^unspent ' "$TMP/verify.out" | sort >"$TMP/unspent.verify"
cmp -s "$TMP/unspent.node" "$TMP/unspent.verify" || { diff "$TMP/unspent.node" "$TMP/unspent.verify" | head -8; fail "slpverify and the wallets disagree about the unspent token outputs"; }
ok "the $(wc -l <"$TMP/unspent.verify" | tr -d ' ') unspent token outputs are the same in slpverify's ledger and in the wallets"
: >"$TMP/tokens.node"
for t in $TOKENS; do
    tk=$(cli $WN zslp_gettoken "$t")
    echo "token $t minted $(units "$(printf '%s' "$tk" | jq -r .totalminted)") burnedsends $(units "$(printf '%s' "$tk" | jq -r .burnedinsends)") burnedspent $(units "$(printf '%s' "$tk" | jq -r .burnedbyspending)")" >>"$TMP/tokens.node"
done
sort "$TMP/tokens.node" >"$TMP/tokens.node.s"
grep '^token ' "$TMP/verify.out" | sort >"$TMP/tokens.verify"
cmp -s "$TMP/tokens.node.s" "$TMP/tokens.verify" || { diff "$TMP/tokens.node.s" "$TMP/tokens.verify" | head -8; fail "slpverify and the index disagree about the token totals"; }
ok "minted, burned-in-sends and burned-by-spending agree for all $(echo $TOKENS | wc -w) tokens"

if [ -n "${DUMP:-}" ]; then
    : >"$DUMP"
    h=$(cli 2 getblockcount)
    i=1
    while [ $i -le "$h" ]; do
        cli $WN getblock "$(cli 2 getblockhash $i)" 0 >>"$DUMP"
        i=$((i + 1))
    done
    say "wrote $h blocks to $DUMP"
fi

PASSED=1
say "zslp_send: $CHECKS checks passed"
