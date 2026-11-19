#!/bin/sh
# token-name-rules, end to end on regtest: the two index rules shared with Z23.
#
#   ZSLP-VOUT0    an SLP message counts only as the script of vout[0]
#   ZNAM-OWNER-2  the owner of a name transaction is the address of the output its first input spends,
#                 rendered by script type: P2PKH -> the P2PKH address, P2SH -> the P2SH address
#
# Real transactions are mined: SLP GENESIS messages at vout[0] (read) and at vout[1] (not a message), a name
# registered from a P2SH multisig coin (owned by the P2SH address, updatable by that P2SH owner and by nobody else),
# a name registered from a key (owned by the P2PKH address, not updatable from the P2SH owner's coin).
# The pure rule cases, including the P2SH/P2PKH same-hash cases that cannot be built on a chain, are the shared
# vectors src/test/data/token_name_rules.txt (src/test/znam_tests.cpp, src/test/zslp_tests.cpp).
#
# usage: token_name_rules.sh [dir-with-zclassicd-zclassic-cli-zclassic-tx]
#   env E2E_PORT_BASE=<n>   first of 120 free local ports (default: a block in 20000-30200)
#   env KEEP=1              keep the temp directory
# Needs: jq, a C compiler, the Zcash parameters in ~/.zcash-params.
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

TMP=$(mktemp -d "${TMPDIR:-/tmp}/zcl-tnr-e2e.XXXXXX")
BASE=${E2E_PORT_BASE:-$((20000 + ($$ % 10000)))}
port_busy() {
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
say() { printf '%s\n' "$*"; }
ok() { CHECKS=$((CHECKS + 1)); say "  ok   $*"; }
fail() { say "  FAIL $*"; exit 1; }

PASSED=0
cleanup() {
    if [ "$PASSED" != 1 ] && [ -f "$TMP/node0/regtest/debug.log" ]; then
        say "---- debug.log (tail)"; tail -15 "$TMP/node0/regtest/debug.log" | cut -c1-300
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

cli() { "$ZCLI" -datadir="$TMP/node0" -regtest -rpcport=$((BASE + 100)) "$@"; }

expect() { [ "$2" = "$3" ] || fail "$1: got '$2', expected '$3'"; ok "$1 = $3"; }
expect_error() {
    label=$1; needle=$2; shift 2
    if out=$("$@" 2>&1); then fail "$label: succeeded, expected an error containing '$needle' (got: $out)"; fi
    printf '%s' "$out" | grep -qF "$needle" || fail "$label: error does not contain '$needle': $out"
    ok "$label: refused"
}

# ---- tools ----------------------------------------------------------------

say "== build znamscript and slpscript from the vendored Z23 builders"
${CC:-cc} -std=gnu11 -O2 -Wall -Wextra -Werror \
    -iquote "$SVC/glue" -iquote "$SVC/vendor/contexts/naming/modules/znam/include" \
    -iquote "$SVC/vendor/engine/modules/overlay/include" -iquote "$SVC/vendor/core/modules/script/include" \
    "$SVC/tools/znamscript.c" "$SVC/glue/zcl_znam_index.c" \
    "$SVC/vendor/contexts/naming/modules/znam/src/znam.c" "$SVC/vendor/engine/modules/overlay/src/overlay_codec.c" \
    -o "$TMP/znamscript"
${CC:-cc} -std=gnu11 -O2 -Wall -Wextra -Werror \
    -iquote "$SVC/glue" -iquote "$SVC/vendor/contexts/market/modules/zslp/include" \
    -iquote "$SVC/vendor/engine/modules/overlay/include" -iquote "$SVC/vendor/core/modules/script/include" \
    "$SVC/tools/slpscript.c" "$SVC/glue/zcl_token_guard.c" \
    "$SVC/vendor/contexts/market/modules/zslp/src/slp.c" "$SVC/vendor/engine/modules/overlay/src/overlay_codec.c" \
    -o "$TMP/slpscript"
ZS=$TMP/znamscript
SLP=$TMP/slpscript

# ---- node -----------------------------------------------------------------

say "== start one node with -znamindex=1 -zslpindex=1, ports $BASE+"
mkdir -p "$TMP/node0"
{
    echo "regtest=1"
    echo "rpcuser=tnr"
    echo "rpcpassword=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
} >"$TMP/node0/zclassic.conf"
"$ZD" -datadir="$TMP/node0" -regtest -server=1 -daemon=0 -showmetrics=0 \
    -listen=1 -bind=127.0.0.1 -port=$((BASE + 0)) \
    -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=$((BASE + 100)) \
    -dnsseed=0 -discover=0 -listenonion=0 -upnp=0 -keypool=5 -debuglogfile=1 -parkdeepreorg=0 \
    -znamindex=1 -zslpindex=1 >"$TMP/node0/stdout.log" 2>&1 &
PIDS="$PIDS $!"
t=0
until cli getblockcount >/dev/null 2>&1; do
    kill -0 "$!" 2>/dev/null || { cat "$TMP/node0/stdout.log"; fail "the node exited during startup"; }
    t=$((t + 1)); [ $t -lt 300 ] || fail "the node did not start"
    sleep 1
done
cli generate 120 >/dev/null

wait_index() {
    t=0
    while :; do
        tip=$(cli getbestblockhash)
        zn=$(cli znam_getindexinfo 2>/dev/null || true)
        zs=$(cli zslp_getindexinfo 2>/dev/null || true)
        if [ -n "$zn" ] && [ -n "$zs" ] &&
           [ "$(printf '%s' "$zn" | jq -r '.indexedblock')" = "$tip" ] && [ "$(printf '%s' "$zn" | jq -r '.synced')" = true ] &&
           [ "$(printf '%s' "$zs" | jq -r '.indexedblock')" = "$tip" ] && [ "$(printf '%s' "$zs" | jq -r '.synced')" = true ]; then return 0; fi
        t=$((t + 1)); [ $t -lt 240 ] || fail "the indexes did not reach the tip"
        sleep 1
    done
}
wait_index

DUST=0.00000546
FEE=10000
btc() { awk -v z="$1" 'BEGIN { printf "%.8f", z / 100000000 }'; }
zat() { jq -n --arg a "$1" '$a | tonumber * 100000000 | round'; }
touch "$TMP/used"

# coin <address> -> "txid vout amount" of an unspent, unused coin of <address> worth at least 1 ZCL
coin() {
    u=$(cli listunspent 1 9999999 "[\"$1\"]" | jq -c --rawfile used "$TMP/used" '
        ($used | split("\n")) as $u
        | [.[] | select(.spendable and .amount >= 1) | select(("\(.txid):\(.vout)") as $o | $u | index($o) | not)]
        | sort_by(.amount) | .[0]')
    [ "$u" != null ] || fail "no coin left at $1"
    printf '%s %s %s' "$(printf '%s' "$u" | jq -r .txid)" "$(printf '%s' "$u" | jq -r .vout)" "$(printf '%s' "$u" | jq -r .amount)"
}

# rawtx <address> <outputs...>: a transaction whose FIRST input is a coin of <address>; the outputs are zclassic-tx
# commands in the given order; the change goes back to <address> as the LAST output. Signed by the wallet, sent,
# prints the txid.
rawtx() {
    addr=$1; shift
    c=$(coin "$addr"); ctxid=${c%% *}; rest=${c#* }; cvout=${rest%% *}; camt=${rest#* }
    echo "$ctxid:$cvout" >>"$TMP/used"
    change=$(btc $(( $(zat "$camt") - FEE )))
    raw=$(cli createrawtransaction "[{\"txid\":\"$ctxid\",\"vout\":$cvout}]" '{}')
    raw=$("$ZTX" -regtest "$raw" "$@" "outaddr=$change:$addr")
    signed=$(cli signrawtransaction "$raw")
    [ "$(printf '%s' "$signed" | jq -r .complete)" = true ] || fail "could not sign: $signed"
    cli sendrawtransaction "$(printf '%s' "$signed" | jq -r .hex)"
}

mine() { cli generate 1 >/dev/null; wait_index; }

nf() { cli znam_getname "$1" | jq -r ".$2"; }

K1=$(cli getnewaddress)
K2=$(cli getnewaddress)
T1=$(cli getnewaddress)
for a in $K1 $K2; do
    cli sendtoaddress "$a" 3 >/dev/null; cli sendtoaddress "$a" 3 >/dev/null
done

# a 1-of-1 multisig P2SH address of this wallet: the wallet signs for it
PK=$(cli validateaddress "$(cli getnewaddress)" | jq -r .pubkey)
MS=$(cli addmultisigaddress 1 "[\"$PK\"]")
case "$MS" in t*) ;; *) fail "addmultisigaddress returned '$MS'" ;; esac
[ "$(cli validateaddress "$MS" | jq -r .isscript)" = true ] || fail "$MS is not a P2SH address"
cli sendtoaddress "$MS" 3 >/dev/null; cli sendtoaddress "$MS" 3 >/dev/null; cli sendtoaddress "$MS" 3 >/dev/null
mine

# ---- ZSLP-VOUT0 -----------------------------------------------------------

say "== ZSLP-VOUT0: a GENESIS at vout[0] is a token, the same GENESIS at vout[1] is not a message"
expect "no tokens yet" "$(cli zslp_getindexinfo | jq -r .tokens)" 0
G0=$(rawtx "$K1" "outscript=0:0x$("$SLP" genesis TKA "Token A" 0 1000)" "outaddr=$DUST:$K1")
mine
expect "the GENESIS at vout[0] makes a token" "$(cli zslp_getindexinfo | jq -r .tokens)" 1
expect "and is a GENESIS message" "$(cli zslp_getindexinfo | jq -r .genesismessages)" 1
G1=$(rawtx "$K1" "outaddr=$DUST:$K1" "outscript=0:0x$("$SLP" genesis TKB "Token B" 0 1000)")
mine
expect "the GENESIS at vout[1] makes no token" "$(cli zslp_getindexinfo | jq -r .tokens)" 1
expect "and is no message" "$(cli zslp_getindexinfo | jq -r .genesismessages)" 1
expect_error "its transaction is unknown to the index" "" cli zslp_gettransaction "$G1"
G2=$(rawtx "$K1" "outaddr=$DUST:$K1" "outaddr=$DUST:$K1" "outscript=0:0x$("$SLP" genesis TKC "Token C" 0 1000)")
mine
expect "the GENESIS at vout[2] makes no token either" "$(cli zslp_getindexinfo | jq -r .tokens)" 1
expect "token A is the token of the first GENESIS" "$(cli zslp_listtokens | jq -r '.[0].tokenid')" "$G0"

# ---- ZNAM-OWNER-2 ---------------------------------------------------------

say "== ZNAM-OWNER-2: a name registered from a P2SH coin belongs to the P2SH address"
R=$(rawtx "$MS" "outscript=0:0x$("$ZS" register shname taddr "$T1")")
mine
expect "the P2SH-registered name is owned by the P2SH address" "$(nf shname owner)" "$MS"
expect "and resolves to its target" "$(nf shname value)" "$T1"
TX2=$(cli getnewaddress)
U1=$(rawtx "$MS" "outscript=0:0x$("$ZS" update shname taddr "$TX2")")
mine
expect "the P2SH owner updates the name from another P2SH coin" "$(nf shname value)" "$TX2"
TX3=$(cli getnewaddress)
U2=$(rawtx "$K2" "outscript=0:0x$("$ZS" update shname taddr "$TX3")")
mine
expect "a key owner cannot update it" "$(nf shname value)" "$TX2"

say "== ZNAM-OWNER-2: a name registered from a key belongs to the P2PKH address; the P2SH owner cannot touch it"
R2=$(rawtx "$K1" "outscript=0:0x$("$ZS" register keyname taddr "$T1")")
mine
expect "the key-registered name is owned by the P2PKH address" "$(nf keyname owner)" "$K1"
U3=$(rawtx "$MS" "outscript=0:0x$("$ZS" update keyname taddr "$TX3")")
mine
expect "the P2SH owner cannot update a key-owned name" "$(nf keyname value)" "$T1"
TR=$(rawtx "$K1" "outscript=0:0x$("$ZS" transfer keyname "$MS")")
mine
expect "TRANSFER to the P2SH address hands the name over" "$(nf keyname owner)" "$MS"
U4=$(rawtx "$MS" "outscript=0:0x$("$ZS" update keyname taddr "$TX3")")
mine
expect "and the P2SH owner can now update it" "$(nf keyname value)" "$TX3"
U5=$(rawtx "$K1" "outscript=0:0x$("$ZS" update keyname taddr "$T1")")
mine
expect "while the old key owner cannot" "$(nf keyname value)" "$TX3"

PASSED=1
say "== token-name-rules: $CHECKS checks passed"
