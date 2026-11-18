#!/bin/sh
# ZSLP token index, end to end on regtest.
#
# Real GENESIS, MINT and SEND transactions (their OP_RETURN scripts come from the
# vendored Z23 builder, through src/c23/services/tools/slpscript.c) are mined,
# some of them deliberately invalid (over-spend, wrong token id, burned by an
# ordinary spend, quantities at and above 2^63). After every block the index is
# snapshotted; then the chain is reorganised out one block at a time and the exact
# snapshot of each height must come back, a reorg that removes a GENESIS for good
# is followed by the miner and by a peer's index, and a fresh index is built three
# times: interrupted by kill -9 and by a clean stop in the middle of the token
# blocks, and from block 0 in one go. Each must equal the reference exactly.
#
# usage: zslp_index.sh [dir-with-zclassicd-zclassic-cli-zclassic-tx]
#   env BASELINE_SRC=<dir>  also prove the flag-off behaviour against the unmodified
#                           zclassicd in <dir>: the RPC `help` list may differ only by
#                           the eleven zslp_* commands (and their category heading); set
#                           BASELINE_NEW_ZSLP=n when the baseline already has some of them.
#                           The help text of every baseline command must be unchanged; when
#                           the baseline is an older release, name the commands that later
#                           work changed on purpose in BASELINE_HELP_CHANGED="cmd cmd ..."
#                           (the list must match exactly; a failing run prints the real one)
#   env CC=<compiler>       compiler for slpscript (default: cc)
#   env KEEP=1              keep the temp directory
#
# Needs: jq, a C compiler, the Zcash parameters in ~/.zcash-params.
# Every node runs on 127.0.0.1 with its own temp datadir and its own ports.
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

TMP=$(mktemp -d "${TMPDIR:-/tmp}/zcl-zslp-e2e.XXXXXX")
BASE=${E2E_PORT_BASE:-$((20000 + ($$ % 20000)))}
# Another job on the host may already listen in the block: move on until the block is free.
port_busy() { # tcp-port -> true when something already listens on it
    if command -v ss >/dev/null 2>&1; then
        [ -n "$(ss -Htln "sport = :$1" 2>/dev/null)" ]
    else
        lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
    fi
}
_try=0
while [ "$_try" -lt 100 ]; do
    _i=0; _ok=1
    while [ "$_i" -lt 120 ]; do
        if port_busy $((BASE + _i)); then _ok=0; break; fi
        _i=$((_i + 1))
    done
    [ "$_ok" -eq 1 ] && break
    BASE=$((BASE + 121)); _try=$((_try + 1))
done
PIDS=""
CHECKS=0
DUST=0.00000546

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

# start <n> <zclassicd> [extra args]: node n, datadir $TMP/node<n>
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
        -dnsseed=0 -discover=0 -listenonion=0 -upnp=0 -keypool=5 -debuglogfile=1 -parkdeepreorg=0 \
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

kill9() {
    n=$1
    pid=$(cat "$TMP/node$n/pid")
    kill -9 "$pid"
    t=0
    while kill -0 "$pid" 2>/dev/null; do
        t=$((t + 1)); [ $t -lt 30 ] || fail "node $n survived kill -9"
        sleep 1
    done
}

cli() { n=$1; shift; "$ZCLI" -datadir="$TMP/node$n" -regtest -rpcport=$((BASE + 100 + n)) "$@"; }

# sync <n>: node n has node 0's tip
sync() {
    want=$(cli 0 getbestblockhash)
    t=0
    until [ "$(cli "$1" getbestblockhash)" = "$want" ]; do
        t=$((t + 1)); [ $t -lt 180 ] || fail "node $1 did not sync"
        sleep 1
    done
}

# wait_index <n>: the index of node n has reached node n's own tip
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

# ---- transactions ---------------------------------------------------------

zat() { jq -n --arg a "$1" '$a | tonumber * 100000000 | round'; }
btc() { awk -v z="$1" 'BEGIN { printf "%.8f", z / 100000000 }'; }

# tx <"txid:vout ..." outputs to spend, may be empty> <zclassic-tx output commands...>
# Node 0 adds one ordinary funding coin, signs and broadcasts; the last output is its change.
# Prints the txid.
tx() {
    tin=$1; shift
    touch "$TMP/used"
    u=$(cli 0 listunspent 1 | jq -c --rawfile used "$TMP/used" '
        ($used | split("\n")) as $u
        | [.[] | select(.spendable and .amount >= 1 and (.tokenbearing | not)) | select(("\(.txid):\(.vout)") as $o | $u | index($o) | not)]
        | sort_by(.amount) | .[0]')
    [ "$u" != null ] || fail "the miner has no coin to fund a transaction"
    utxid=$(printf '%s' "$u" | jq -r .txid)
    uvout=$(printf '%s' "$u" | jq -r .vout)
    echo "$utxid:$uvout" >>"$TMP/used"
    ins="[{\"txid\":\"$utxid\",\"vout\":$uvout}"
    ntok=0
    for o in $tin; do ins="$ins,{\"txid\":\"${o%:*}\",\"vout\":${o#*:}}"; ntok=$((ntok + 1)); done
    ins="$ins]"
    nd=0
    for a in "$@"; do case $a in outaddr=*) nd=$((nd + 1)) ;; esac; done
    change=$(btc $(( $(zat "$(printf '%s' "$u" | jq -r .amount)") + 546 * ntok - 10000 - 546 * nd )))
    raw=$(cli 0 createrawtransaction "$ins" '{}')
    raw=$("$ZTX" -regtest "$raw" "$@" "outaddr=$change:$M0")
    signed=$(cli 0 signrawtransaction "$raw")
    [ "$(printf '%s' "$signed" | jq -r .complete)" = true ] || fail "could not sign a transaction: $signed"
    cli 0 sendrawtransaction "$(printf '%s' "$signed" | jq -r .hex)"
}

# mine <txid>: wait for node 0's mempool to hold it, mine one block, wait for node 0's index,
# and record the snapshot and the token list of the new height
mine() {
    t=0
    until cli 0 getrawmempool | grep -q "$1"; do
        t=$((t + 1)); [ $t -lt 60 ] || fail "tx $1 is not in the miner's mempool"
        sleep 1
    done
    cli 0 generate 1 >/dev/null
    wait_index 0
    h=$(cli 0 getblockcount)
    snapshot 0 >"$TMP/snap.$h"
    echo "$TOKENS" >"$TMP/tokens.$h"
}

# ---- queries --------------------------------------------------------------

TOKENS=""
ADDRS=""

# snapshot <n>: everything the index says, canonical
snapshot() {
    n=$1
    cli "$n" zslp_listtokens 0 1000 | jq -S -c .
    for a in $ADDRS; do cli "$n" zslp_getbalances "$a" | jq -S -c 'del(.synced)'; done
    cli "$n" zslp_getindexinfo | jq -S -c '{tokens, validtransactions, invalidtransactions, unknowntransactions, burntransactions, unspentoutputs}'
    for t in $TOKENS; do
        if out=$(cli "$n" zslp_gettoken "$t" 1000 2>/dev/null); then
            printf '%s\n' "$out" | jq -S -c .
        else
            echo "none $t"
        fi
        cli "$n" zslp_listtransactions "$t" 0 1000 | jq -S -c .
    done
}

# bal <n> <addr> <tokenid>: the amount string, "0" when absent
bal() { cli "$1" zslp_getbalances "$2" | jq -r --arg t "$3" '([.balances[] | select(.tokenid == $t) | .amount] | first) // "0"'; }

# tok <n> <tokenid> <field>
tok() { cli "$1" zslp_gettoken "$2" | jq -r ".$3"; }

# txf <n> <txid> <field>
txf() { cli "$1" zslp_gettransaction "$2" | jq -r ".$3"; }

expect() { # <label> <got> <want>
    [ "$2" = "$3" ] || fail "$1: got '$2', expected '$3'"
    ok "$1 = $3"
}

expect_error() {
    label=$1; needle=$2; shift 2
    if out=$("$@" 2>&1); then fail "$label: succeeded, expected an error containing '$needle' (got: $out)"; fi
    printf '%s' "$out" | grep -qF "$needle" || fail "$label: error does not contain '$needle': $out"
    ok "$label: refused: $(printf '%s' "$out" | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-120)"
}

# ---- build the script tool ------------------------------------------------

say "== build slpscript from the vendored Z23 builder"
${CC:-cc} -std=gnu11 -O2 -Wall -Wextra -Werror \
    -iquote "$SVC/glue" -iquote "$SVC/vendor/contexts/market/modules/zslp/include" \
    -iquote "$SVC/vendor/engine/modules/overlay/include" -iquote "$SVC/vendor/core/modules/script/include" \
    "$SVC/tools/slpscript.c" "$SVC/glue/zcl_token_guard.c" \
    "$SVC/vendor/contexts/market/modules/zslp/src/slp.c" "$SVC/vendor/engine/modules/overlay/src/overlay_codec.c" \
    -o "$TMP/slpscript"
SLP=$TMP/slpscript

# ---- nodes ----------------------------------------------------------------

say "== start node 0 (miner, index on), node 1 (wallet, index on) and node 2 (index OFF), ports $BASE+"
start 0 "$ZD" -zslpindex=1
start 1 "$ZD" -zslpindex=1 -connect=127.0.0.1:$((BASE + 0))
start 2 "$ZD" -connect=127.0.0.1:$((BASE + 0))
cli 0 generate 120 >/dev/null
sync 1; sync 2
M0=$(cli 0 getnewaddress); M1=$(cli 0 getnewaddress); M2=$(cli 0 getnewaddress)
M3=$(cli 0 getnewaddress); M4=$(cli 0 getnewaddress)
A=$(cli 1 getnewaddress)
ADDRS="$M0 $M1 $M2 $M3 $M4 $A"
wait_index 0; wait_index 1

# ---- 0. the index is off by default ---------------------------------------

say "== 0. node 2 runs without -zslpindex"
for c in zslp_getindexinfo zslp_listtokens "zslp_gettoken 00" "zslp_getbalances $A" "zslp_gettransaction 00" "zslp_listtransactions 00" zslp_listunspent; do
    # shellcheck disable=SC2086
    expect_error "node 2 $c" "disabled" cli 2 $c
done
[ ! -e "$TMP/node2/regtest/zslpindex" ] || fail "a node without -zslpindex created a zslpindex directory"
ok "no zslpindex directory is created while the flag is off"

info=$(cli 0 zslp_getindexinfo)
expect "node 0 index running" "$(printf '%s' "$info" | jq -r .running)" true
expect "node 0 index synced at the tip" "$(printf '%s' "$info" | jq -r .synced)" true
expect "node 0 no tokens yet" "$(printf '%s' "$info" | jq -r .tokens)" 0
snapshot 0 >"$TMP/snap.$(cli 0 getblockcount)"
echo "" >"$TMP/tokens.$(cli 0 getblockcount)"

# ---- 1. GENESIS, SEND, MINT -----------------------------------------------

say "== 1. GENESIS 1000.00 (2 decimals) with a baton, SEND to another wallet, MINT"
G=$(tx "" "outscript=0:0x$("$SLP" genesisdec TOK "Index Test" 2 2 100000)" "outaddr=$DUST:$M1" "outaddr=$DUST:$M2")
TOKENS=$G
mine "$G"
expect "GENESIS validity" "$(txf 0 "$G" validity)" valid
expect "GENESIS type" "$(txf 0 "$G" type)" GENESIS
expect "ticker" "$(tok 0 "$G" ticker)" TOK
expect "decimals" "$(tok 0 "$G" decimals)" 2
expect "totalminted" "$(tok 0 "$G" totalminted)" "1000.00"
expect "holder M1" "$(bal 0 "$M1" "$G")" "1000.00"
expect "baton is G:2" "$(cli 0 zslp_gettoken "$G" | jq -r '.mintbaton | "\(.txid):\(.vout)"')" "$G:2"
expect "token count" "$(cli 0 zslp_getindexinfo | jq -r .tokens)" 1

# 400.00 to A (node 1's wallet), 500.00 to M3, 100.00 burned
S1=$(tx "$G:1" "outscript=0:0x$("$SLP" send "$G" 40000 50000)" "outaddr=$DUST:$A" "outaddr=$DUST:$M3")
mine "$S1"
expect "SEND validity" "$(txf 0 "$S1" validity)" valid
expect "SEND burned" "$(txf 0 "$S1" burnedamount)" "100.00"
expect "holder A" "$(bal 0 "$A" "$G")" "400.00"
expect "holder M3" "$(bal 0 "$M3" "$G")" "500.00"
expect "holder M1 spent" "$(bal 0 "$M1" "$G")" "0"
expect "burnedinsends" "$(tok 0 "$G" burnedinsends)" "100.00"
expect "circulating" "$(tok 0 "$G" circulating)" "900.00"
sync 1; wait_index 1
expect "node 1 sees A's balance" "$(bal 1 "$A" "$G")" "400.00"
lu=$(cli 1 zslp_listunspent)
expect "node 1 wallet lists one token output" "$(printf '%s' "$lu" | jq -r '.outputs | length')" 1
expect "its amount" "$(printf '%s' "$lu" | jq -r '.outputs[0].amount')" "400.00"
expect "its token" "$(printf '%s' "$lu" | jq -r '.outputs[0].ticker')" TOK
expect "it is protected" "$(printf '%s' "$lu" | jq -r '.outputs[0].protected')" true
expect "wallet balance row" "$(printf '%s' "$lu" | jq -r '.balances[0].amount')" "400.00"

# MINT 250.00 more, the baton moves to M2 again
MT=$(tx "$G:2" "outscript=0:0x$("$SLP" mint "$G" 2 25000)" "outaddr=$DUST:$M4" "outaddr=$DUST:$M2")
mine "$MT"
expect "MINT validity" "$(txf 0 "$MT" validity)" valid
expect "totalminted after MINT" "$(tok 0 "$G" totalminted)" "1250.00"
expect "baton moved" "$(cli 0 zslp_gettoken "$G" | jq -r '.mintbaton.txid')" "$MT"
expect "holder M4" "$(bal 0 "$M4" "$G")" "250.00"

# ---- 2. invalid and burning transactions ----------------------------------

say "== 2. zero quantity, over-spend, wrong token id, burn by an ordinary spend"
# a SEND with a zero slot: the zero slot creates no output, the rest moves on
SZ=$(tx "$MT:1" "outscript=0:0x$("$SLP" send "$G" 0 25000)" "outaddr=$DUST:$M3" "outaddr=$DUST:$M4")
mine "$SZ"
expect "zero-slot SEND validity" "$(txf 0 "$SZ" validity)" valid
expect "zero slot creates nothing" "$(cli 0 zslp_gettransaction "$SZ" | jq -r '.outputs | length')" 1
expect "zero slot holder" "$(bal 0 "$M3" "$G")" "500.00"
expect "the 250.00 moved to M4's new output" "$(bal 0 "$M4" "$G")" "250.00"
# a MINT of zero keeps the baton moving and mints nothing
MZ=$(tx "$MT:2" "outscript=0:0x$("$SLP" mint "$G" 2 0)" "outaddr=$DUST:$M1" "outaddr=$DUST:$M2")
mine "$MZ"
expect "zero MINT validity" "$(txf 0 "$MZ" validity)" valid
expect "zero MINT minted" "$(txf 0 "$MZ" mintedamount)" "0.00"
expect "zero MINT: totalminted unchanged" "$(tok 0 "$G" totalminted)" "1250.00"
expect "zero MINT: baton moved" "$(cli 0 zslp_gettoken "$G" | jq -r '.mintbaton.txid')" "$MZ"

# SEND 600.00 out of the 500.00 held at M3: invalid, the input is burned
OV=$(tx "$S1:2" "outscript=0:0x$("$SLP" send "$G" 60000)" "outaddr=$DUST:$M3")
mine "$OV"
expect "over-spend validity" "$(txf 0 "$OV" validity)" invalid
expect "over-spend reason" "$(txf 0 "$OV" reason)" send_output_exceeds_input
expect "over-spend creates nothing" "$(bal 0 "$M3" "$G")" "0"
expect "over-spend burned 500.00 by spending" "$(tok 0 "$G" burnedbyspending)" "500.00"

# a second token H (no decimals, no baton); a SEND naming H but spending G tokens
H=$(tx "" "outscript=0:0x$("$SLP" genesis HHH "Other" 0 7777)" "outaddr=$DUST:$M1")
TOKENS="$G $H"
mine "$H"
expect "token count 2" "$(cli 0 zslp_getindexinfo | jq -r .tokens)" 2
WR=$(tx "$SZ:2" "outscript=0:0x$("$SLP" send "$H" 250)" "outaddr=$DUST:$M3")
mine "$WR"
expect "wrong-token validity" "$(txf 0 "$WR" validity)" invalid
expect "wrong-token reason" "$(txf 0 "$WR" reason)" send_ancestry_invalid
expect "G burned by that" "$(tok 0 "$G" burnedbyspending)" "750.00"
expect "H untouched" "$(bal 0 "$M1" "$H")" "7777"

# an ordinary transaction spends H's output: the tokens are gone
BU=$(tx "$H:1" "outaddr=$DUST:$M3")
mine "$BU"
expect "ordinary spend type" "$(txf 0 "$BU" type)" NONE
expect "ordinary spend is a burn" "$(txf 0 "$BU" validity)" burn
expect "H burned by spending" "$(tok 0 "$H" burnedbyspending)" "7777"
expect "H holder gone" "$(bal 0 "$M1" "$H")" "0"
expect "H circulating" "$(tok 0 "$H" circulating)" "0"

# ---- 3. 2^63 and above ----------------------------------------------------

say "== 3. quantities at and above 2^63"
BIG=$(tx "" "outscript=0:0x$("$SLP" genesis BIG "Too big" 0 9223372036854775808)" "outaddr=$DUST:$M1")
mine "$BIG"
expect "2^63 GENESIS is UNKNOWN" "$(txf 0 "$BIG" validity)" unknown
expect "2^63 GENESIS reason" "$(txf 0 "$BIG" reason)" quantity_unrepresentable
expect_error "2^63 GENESIS makes no token" "No ZSLP token" cli 0 zslp_gettoken "$BIG"
MAXG=$(tx "" "outscript=0:0x$("$SLP" genesis MAX "Max" 0 9223372036854775807)" "outaddr=$DUST:$M1")
TOKENS="$G $H $MAXG"
mine "$MAXG"
expect "INT64_MAX minted exactly" "$(tok 0 "$MAXG" totalminted)" 9223372036854775807
SPL=$(tx "$MAXG:1" "outscript=0:0x$("$SLP" send "$MAXG" 9223372036854775800 7)" "outaddr=$DUST:$M2" "outaddr=$DUST:$M3")
mine "$SPL"
expect "exact split valid" "$(txf 0 "$SPL" validity)" valid
expect "exact split big half" "$(bal 0 "$M2" "$MAXG")" 9223372036854775800
expect "exact split small half" "$(bal 0 "$M3" "$MAXG")" 7
OVF=$(tx "$SPL:2" "outscript=0:0x$("$SLP" send "$MAXG" 18446744073709551615 1)" "outaddr=$DUST:$M4" "outaddr=$DUST:$M4")
mine "$OVF"
expect "uint64 overflow of the output sum is INVALID" "$(txf 0 "$OVF" reason)" output_quantity_overflow
TOP=$(tx "$SPL:1" "outscript=0:0x$("$SLP" send "$MAXG" 9223372036854775808 1)" "outaddr=$DUST:$M4" "outaddr=$DUST:$M4")
mine "$TOP"
expect "output sum above INT64_MAX is UNKNOWN" "$(txf 0 "$TOP" validity)" unknown
expect "supply of MAX is fully burned, exactly" "$(tok 0 "$MAXG" circulating)" 0
info=$(cli 0 zslp_getindexinfo)
expect "unknown transactions counted" "$(printf '%s' "$info" | jq -r .unknowntransactions)" 2

# invariant: for every token the holders add up to the circulating supply
for t in $TOKENS; do
    j=$(cli 0 zslp_gettoken "$t" 1000)
    sum=$(printf '%s' "$j" | jq -r '[.holders[].amount | gsub("\\."; "") | tonumber] | add // 0')
    circ=$(printf '%s' "$j" | jq -r '.circulating | gsub("\\."; "") | tonumber')
    [ "$sum" = "$circ" ] || fail "token $t: holders sum $sum != circulating $circ"
done
ok "for every token the holder balances sum to the circulating supply"
sync 1; wait_index 1
snapshot 1 >"$TMP/n1.snap"
snapshot 0 >"$TMP/n0.snap"
cmp -s "$TMP/n0.snap" "$TMP/n1.snap" || { diff "$TMP/n0.snap" "$TMP/n1.snap" | head -6; fail "node 1's index differs from node 0's"; }
ok "node 1 (synced over the network) indexes exactly what node 0 does"

# ---- 4. reorgs ------------------------------------------------------------

say "== 4. reorg the chain out one block at a time"
TIPH=$(cli 0 getblockcount)
HBLK=$(cli 0 gettransaction "$H" | jq -r .blockhash)
HH=$(cli 0 getblock "$HBLK" | jq -r .height)
h=$TIPH
while [ "$h" -ge "$HH" ]; do
    cli 0 invalidateblock "$(cli 0 getblockhash "$h")"
    h=$((h - 1))
    wait_index 0
    [ "$(cli 0 getblockcount)" = "$h" ] || fail "the chain did not move to $h"
    TOKENS=$(cat "$TMP/tokens.$h")
    snapshot 0 >"$TMP/now"
    cmp -s "$TMP/now" "$TMP/snap.$h" || { diff "$TMP/now" "$TMP/snap.$h" | head -6; fail "the index after a reorg to height $h is not the snapshot of height $h"; }
    ok "reorg to height $h: the index is exactly the snapshot taken when the chain was there"
done
expect_error "the GENESIS of H is gone" "No ZSLP token" cli 0 zslp_gettoken "$H"

say "== 5. a peer mines a longer chain that never contains H's GENESIS; node 0 and node 1 follow it"
# node 7 syncs the short chain node 0 is on now, then mines a longer one of its own
start 7 "$ZD" -connect=127.0.0.1:$((BASE + 0))
sync 7
cli 7 generate $((TIPH - h + 2)) >/dev/null
t=0
until [ "$(cli 0 getbestblockhash)" = "$(cli 7 getbestblockhash)" ] && [ "$(cli 1 getbestblockhash)" = "$(cli 7 getbestblockhash)" ]; do
    t=$((t + 1)); [ $t -lt 180 ] || fail "node 0 and node 1 did not follow node 7's chain"; sleep 1
done
wait_index 0; wait_index 1
expect_error "H's GENESIS is not on the new chain (node 0)" "No ZSLP token" cli 0 zslp_gettoken "$H"
expect "node 1 followed the reorg with its index: token count" "$(cli 1 zslp_getindexinfo | jq -r .tokens)" 1
expect "node 1: balance of A unchanged" "$(bal 1 "$A" "$G")" "400.00"
expect "node 0 and node 1 agree on the token list" \
    "$(cli 0 zslp_listtokens | jq -S -c .)" "$(cli 1 zslp_listtokens | jq -S -c .)"
t=0
until [ "$(cli 2 getbestblockhash)" = "$(cli 0 getbestblockhash)" ]; do
    t=$((t + 1)); [ $t -lt 120 ] || fail "node 2 did not follow the reorg"; sleep 1
done
ok "node 2 (no index) followed the same reorg"
stop 7
# a restart empties the mempools, so the transactions of the abandoned blocks cannot come back
stop 1; stop 0
start 0 "$ZD" -zslpindex=1
start 1 "$ZD" -zslpindex=1 -connect=127.0.0.1:$((BASE + 0))
wait_index 0; wait_index 1
expect_error "H's GENESIS is gone after the restart (node 0)" "No ZSLP token" cli 0 zslp_gettoken "$H"
expect "node 0 index synced after the restart" "$(cli 0 zslp_getindexinfo | jq -r .synced)" true
ok "both indexes survived a restart on the new chain"

say "== 6. a fresh index built from the chain, interrupted by kill -9 and by a clean stop"
TOKENS=$G
G2=$(tx "" "outscript=0:0x$("$SLP" genesisdec TWO "Second" 3 2 5000000)" "outaddr=$DUST:$M1" "outaddr=$DUST:$M2")
TOKENS="$G $G2"
mine "$G2"
SA=$(tx "$G2:1" "outscript=0:0x$("$SLP" send "$G2" 1000000 2000000 1500000)" "outaddr=$DUST:$M3" "outaddr=$DUST:$M4" "outaddr=$DUST:$M1")
mine "$SA"
MB=$(tx "$G2:2" "outscript=0:0x$("$SLP" mint "$G2" 2 123456)" "outaddr=$DUST:$M3" "outaddr=$DUST:$M2")
mine "$MB"
for i in 1 2 3 4 5 6; do cli 0 generate 1 >/dev/null; wait_index 0; done
snapshot 0 >"$TMP/ref.snap"
GBLK=$(cli 0 gettransaction "$G" | jq -r .blockhash)
GHT=$(cli 0 getblock "$GBLK" | jq -r .height)
G2BLK=$(cli 0 gettransaction "$G2" | jq -r .blockhash)
FH=$(cli 0 getblock "$G2BLK" | jq -r .height)
CH=$(cli 0 getblockcount)
say "   chain height $CH, GENESIS of G at $GHT, GENESIS of G2 at $FH"

build_interrupted() { # <node> <how: kill|stop>
    n=$1; how=$2
    start "$n" "$ZD" -zslpindex=1 -zslpindexstart=$((GHT - 1)) -zslpindexdelayms=700 -connect=127.0.0.1:$((BASE + 0))
    sync "$n"
    t=0
    until [ "$(cli "$n" zslp_getindexinfo | jq -r '.indexedheight // 0')" -ge $((FH + 2)) ]; do
        t=$((t + 1)); [ $t -lt 180 ] || fail "node $n did not start indexing"
        sleep 1
    done
    mid=$(cli "$n" zslp_getindexinfo)
    [ "$(printf '%s' "$mid" | jq -r .synced)" = false ] || fail "the index finished before it could be interrupted"
    say "   interrupting node $n ($how) at indexed height $(printf '%s' "$mid" | jq -r .indexedheight) of $CH"
    if [ "$how" = kill ]; then kill9 "$n"; else stop "$n"; fi
    start "$n" "$ZD" -zslpindex=1 -zslpindexstart=$((GHT - 1)) -connect=127.0.0.1:$((BASE + 0))
    wait_index "$n"
    snapshot "$n" >"$TMP/n$n.snap"
    cmp -s "$TMP/ref.snap" "$TMP/n$n.snap" || { diff "$TMP/ref.snap" "$TMP/n$n.snap" | head -6; fail "node $n: the index resumed after $how differs from the reference"; }
    ok "node $n: the index resumed after $how equals the reference exactly"
}
build_interrupted 3 kill
build_interrupted 4 stop

say "== 7. a fresh node builds the whole index from block 0 in one go"
start 5 "$ZD" -zslpindex=1 -connect=127.0.0.1:$((BASE + 0))
sync 5
wait_index 5
snapshot 5 >"$TMP/n5.snap"
cmp -s "$TMP/ref.snap" "$TMP/n5.snap" || { diff "$TMP/ref.snap" "$TMP/n5.snap" | head -6; fail "the from-block-0 index differs from the reference"; }
ok "node 5: built from block 0, equals the reference"

say "== 7b. -reindex on a node with an index: the index is kept and is still exact"
stop 5
start 5 "$ZD" -zslpindex=1 -reindex -connect=127.0.0.1:$((BASE + 0))
wait_index 5
snapshot 5 >"$TMP/n5r.snap"
cmp -s "$TMP/ref.snap" "$TMP/n5r.snap" || { diff "$TMP/ref.snap" "$TMP/n5r.snap" | head -6; fail "the index after -reindex differs from the reference"; }
ok "node 5: the index after -reindex equals the reference"

# ---- 8. the flag-off RPC list ---------------------------------------------

if [ -n "${BASELINE_SRC:-}" ]; then
    say "== 8. flag off: the RPC list is the baseline's plus the zslp_* commands, nothing else"
    start 6 "$BASELINE_SRC/zclassicd"
    cli 6 help | grep -v '^$' | grep -v '^==' | sed 's/ .*//' | sort >"$TMP/help.base"
    cli 2 help | grep -v '^$' | grep -v '^==' | sed 's/ .*//' | sort >"$TMP/help.new"
    diff "$TMP/help.base" "$TMP/help.new" | grep '^[<>]' | sort >"$TMP/help.diff" || true
    [ "$(grep -c '^<' "$TMP/help.diff" || true)" = 0 ] || fail "commands vanished: $(grep '^<' "$TMP/help.diff")"
    svc_other=$(grep '^> ' "$TMP/help.diff" | grep -v '^> zslp_' | grep -v '^> znam_' || true)
    [ -z "$svc_other" ] || fail "unexpected new commands: $svc_other"
    svc_new=$(grep -c "^> zslp_" "$TMP/help.diff" || true)
    if [ -n "${BASELINE_NEW_ZSLP:-}" ]; then expect "new commands" "$svc_new" "$BASELINE_NEW_ZSLP"
    else [ "$svc_new" -le 11 ] || fail "new commands: got '$svc_new', expected at most 11"; fi
    # Collect every baseline command whose help text differs, so one run names them
    # all. Against the commit just before the index nothing may differ. Against an
    # older release the commands that later work changed on purpose are declared in
    # BASELINE_HELP_CHANGED; an undeclared difference fails, and so does a declared
    # one that did not happen.
    norm() { printf '%s\n' "$@" | sort | tr '\n' ' ' | sed 's/ *$//'; }
    changed=""
    for c in $(cat "$TMP/help.base"); do
        [ "$(cli 6 help "$c")" = "$(cli 2 help "$c")" ] || changed="$changed $c"
    done
    changed=$(norm $changed)
    declared=$(norm ${BASELINE_HELP_CHANGED:-})
    [ "$changed" = "$declared" ] || fail "help text differs from the baseline for [$changed]; declared in BASELINE_HELP_CHANGED: [$declared]"
    ok "the help text of all $(wc -l <"$TMP/help.base" | tr -d ' ') baseline commands is unchanged${declared:+, except the declared: $declared}"
    stop 6
fi

PASSED=1
say "zslp_index.sh: PASS ($CHECKS checks)"
