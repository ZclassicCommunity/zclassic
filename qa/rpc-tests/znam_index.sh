#!/bin/sh
# ZNAM name index, end to end on regtest.
#
# Real REGISTER, UPDATE and TRANSFER transactions are mined: some through the wallet commands
# (znam_register / znam_update / znam_transfer), some as hand-built raw transactions whose OP_RETURN comes from
# the vendored Z23 builder (src/c23/services/tools/znamscript.c), so a stranger's update, two registrations of
# one name in one block (in both orders), malformed records and a record whose OP_RETURN is not the first one can
# be tried. After every block the index is snapshotted; then the chain is reorganised out one block at a time and
# the exact snapshot of each height must come back, a reorg that removes a registration for good is followed by
# the miner and by a peer's index, and a fresh index is built from the chain: interrupted by kill -9, and in one
# go. Each must equal the reference exactly. Last, a name is resolved and paid, through RPC: resolve first, then
# send to the ADDRESS.
#
# usage: znam_index.sh [dir-with-zclassicd-zclassic-cli-zclassic-tx]
#   env BASELINE_SRC=<dir>  also prove the flag-off behaviour against an unmodified zclassicd in <dir>: the RPC
#                           `help` list may differ only by the znam_* commands (and their category heading).
#                           The help text of every baseline command must be unchanged; when the baseline is
#                           an older release, name the commands that later work changed on purpose in
#                           BASELINE_HELP_CHANGED="cmd cmd ..." (exact list; a failing run prints the real one)
#   env CC=<compiler>       compiler for znamscript (default: cc)
#   env KEEP=1              keep the temp directory
#
# Needs: jq, a C compiler, the Zcash parameters in ~/.zcash-params.
# Every node runs on 127.0.0.1 with its own temp datadir and its own ports
# (a free block in 20000-30200, or from env E2E_PORT_BASE=<n> as in zslp_index.sh).
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

TMP=$(mktemp -d "${TMPDIR:-/tmp}/zcl-znam-e2e.XXXXXX")
BASE=${E2E_PORT_BASE:-$((20000 + ($$ % 10000)))}
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
            echo "rpcuser=znam"
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
        info=$(cli "$1" znam_getindexinfo 2>/dev/null || true)
        tip=$(cli "$1" getbestblockhash)
        if [ -n "$info" ] && [ "$(printf '%s' "$info" | jq -r '.indexedblock')" = "$tip" ] &&
           [ "$(printf '%s' "$info" | jq -r '.synced')" = true ]; then return 0; fi
        t=$((t + 1)); [ $t -lt 240 ] || fail "the index of node $1 did not reach the tip: $info"
        sleep 1
    done
}

expect() { # <label> <got> <want>
    [ "$2" = "$3" ] || fail "$1: got '$2', expected '$3'"
    ok "$1 = $3"
}

expect_error() {
    label=$1; needle=$2; shift 2
    if out=$("$@" 2>&1); then fail "$label: succeeded, expected an error containing '$needle' (got: $out)"; fi
    printf '%s' "$out" | grep -qF "$needle" || fail "$label: error does not contain '$needle': $out"
    ok "$label: refused: $(printf '%s' "$out" | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-110)"
}

# ---- queries --------------------------------------------------------------

NAMES="alice bob carol dave eve shop zshop trailing late frank"

# snapshot <n>: everything the index says, canonical
snapshot() {
    n=$1
    cli "$n" znam_getindexinfo | jq -S -c '{names, messages, applied, ignored, appliedbycommand}'
    cli "$n" znam_listnames "" 0 1000 | jq -S -c 'map(del(.expired))'
    for nm in $NAMES; do
        if out=$(cli "$n" znam_getname "$nm" 2>/dev/null); then
            printf '%s\n' "$out" | jq -S -c 'del(.synced, .expired)'
        else
            echo "none $nm"
        fi
    done
}

# nf <n> <name> <field>
nf() { cli "$1" znam_getname "$2" | jq -r ".$3"; }
# rf <n> <name> <field> [recentblocks]: field of the pay-resolution
rf() { cli "$1" znam_resolve "$2" pay ${4:-100} | jq -r ".$3"; }

# ---- transactions ---------------------------------------------------------

DUSTVAL=0.0001
btc() { awk -v z="$1" 'BEGIN { printf "%.8f", z / 100000000 }'; }
zat() { jq -n --arg a "$1" '$a | tonumber * 100000000 | round'; }

# otx <owner-address> <script-hex> [extra zclassic-tx output commands...]
# A raw transaction whose FIRST input is a coin of <owner-address> (so Z23 reads that address as the signer), with
# the OP_RETURN as vout[0] and the change back to the owner. Node 0 signs and broadcasts. Prints the txid.
otx() {
    owner=$1; hex=$2; shift 2
    touch "$TMP/used"
    u=$(cli 0 listunspent 1 9999999 "[\"$owner\"]" | jq -c --rawfile used "$TMP/used" '
        ($used | split("\n")) as $u
        | [.[] | select(.spendable and .amount >= 1) | select(("\(.txid):\(.vout)") as $o | $u | index($o) | not)]
        | sort_by(.amount) | .[0]')
    [ "$u" != null ] || fail "no coin left at $owner"
    utxid=$(printf '%s' "$u" | jq -r .txid)
    uvout=$(printf '%s' "$u" | jq -r .vout)
    echo "$utxid:$uvout" >>"$TMP/used"
    change=$(btc $(( $(zat "$(printf '%s' "$u" | jq -r .amount)") - 10000 )))
    raw=$(cli 0 createrawtransaction "[{\"txid\":\"$utxid\",\"vout\":$uvout}]" '{}')
    if [ "${LATE:-0}" = 1 ]; then
        raw=$("$ZTX" -regtest "$raw" "outaddr=$change:$owner" "outscript=0:0x$hex" "$@")
    else
        raw=$("$ZTX" -regtest "$raw" "outscript=0:0x$hex" "$@" "outaddr=$change:$owner")
    fi
    signed=$(cli 0 signrawtransaction "$raw")
    [ "$(printf '%s' "$signed" | jq -r .complete)" = true ] || fail "could not sign a transaction: $signed"
    cli 0 sendrawtransaction "$(printf '%s' "$signed" | jq -r .hex)"
}

# mine <txid...>: wait for node 0's mempool to hold them, mine one block, wait for node 0's index, record the snapshot
mine() {
    for id in "$@"; do
        t=0
        until cli 0 getrawmempool | grep -q "$id"; do
            t=$((t + 1)); [ $t -lt 60 ] || fail "tx $id is not in the miner's mempool"
            sleep 1
        done
    done
    cli 0 generate 1 >/dev/null
    wait_index 0
    h=$(cli 0 getblockcount)
    snapshot 0 >"$TMP/snap.$h"
}

# mine_blocks <n>: mine n blocks without ZNAM transactions; every one of those heights has the same snapshot
mine_blocks() {
    cli 0 generate "$1" >/dev/null
    wait_index 0
    h=$(cli 0 getblockcount)
    snapshot 0 >"$TMP/snap.$h"
    i=1
    while [ $i -lt "$1" ]; do cp "$TMP/snap.$h" "$TMP/snap.$((h - i))"; i=$((i + 1)); done
}

# ---- build the script tool ------------------------------------------------

say "== build znamscript from the vendored Z23 builder"
${CC:-cc} -std=gnu11 -O2 -Wall -Wextra -Werror \
    -iquote "$SVC/glue" -iquote "$SVC/vendor/contexts/naming/modules/znam/include" \
    -iquote "$SVC/vendor/engine/modules/overlay/include" -iquote "$SVC/vendor/core/modules/script/include" \
    "$SVC/tools/znamscript.c" "$SVC/glue/zcl_znam_index.c" \
    "$SVC/vendor/contexts/naming/modules/znam/src/znam.c" "$SVC/vendor/engine/modules/overlay/src/overlay_codec.c" \
    -o "$TMP/znamscript"
ZS=$TMP/znamscript
[ "$("$ZS" parse "$("$ZS" register alice taddr t1abc)")" = "1 alice 3 t1abc" ] || fail "znamscript does not round-trip"
ok "the vendored builder and parser round-trip"

# ---- nodes ----------------------------------------------------------------

say "== start node 0 (miner, index on), node 1 (wallet, index on) and node 2 (index OFF), ports $BASE+"
start 0 "$ZD" -znamindex=1
start 1 "$ZD" -znamindex=1 -connect=127.0.0.1:$((BASE + 0))
start 2 "$ZD" -connect=127.0.0.1:$((BASE + 0))
cli 0 generate 120 >/dev/null
sync 1; sync 2

# ---- 0. the index is off by default ---------------------------------------

say "== 0. node 2 runs without -znamindex"
expect "node 2 znam_getindexinfo" "$(cli 2 znam_getindexinfo | jq -r .enabled)" false
for c in "znam_resolve alice" "znam_getname alice" "znam_listnames" znam_listmine "znam_register alice t1x" "znam_update alice t1x" "znam_transfer alice t1x"; do
    # shellcheck disable=SC2086
    expect_error "node 2 $c" "disabled" cli 2 $c
done
[ ! -e "$TMP/node2/regtest/znamindex" ] || fail "a node without -znamindex created a znamindex directory"
ok "no znamindex directory is created while the flag is off"

# owners: five addresses of node 0's wallet, each funded with several coins; targets: addresses of node 1's wallet
O1=$(cli 0 getnewaddress); O2=$(cli 0 getnewaddress); O3=$(cli 0 getnewaddress); O4=$(cli 0 getnewaddress); O5=$(cli 0 getnewaddress)
T1=$(cli 1 getnewaddress); T2=$(cli 1 getnewaddress); T3=$(cli 1 getnewaddress); T4=$(cli 1 getnewaddress)
ZA=$(cli 1 z_getnewaddress sapling)
# Fund each owner address with six coins of 2 ZCL, in ONE raw transaction per owner (spending one mature coinbase
# coin). sendtoaddress would not do: the wallet may spend a coin it just paid to an owner as the input of the next one.
MCH=$(cli 0 getnewaddress)
k=0
for o in $O1 $O2 $O3 $O4 $O5; do
    c=$(cli 0 listunspent 100 9999999 | jq -c --argjson k "$k" '[.[] | select(.spendable and .amount >= 12)] | sort_by(.txid, .vout) | .[$k]')
    [ "$c" != null ] || fail "no mature coin to fund owner $k"
    k=$((k + 1))
    ctxid=$(printf '%s' "$c" | jq -r .txid); cvout=$(printf '%s' "$c" | jq -r .vout)
    echo "$ctxid:$cvout" >>"$TMP/used"
    back=$(btc $(( $(zat "$(printf '%s' "$c" | jq -r .amount)") - 1200000000 - 10000 )))
    raw=$(cli 0 createrawtransaction "[{\"txid\":\"$ctxid\",\"vout\":$cvout}]" '{}')
    raw=$("$ZTX" -regtest "$raw" "outaddr=2:$o" "outaddr=2:$o" "outaddr=2:$o" "outaddr=2:$o" "outaddr=2:$o" "outaddr=2:$o" "outaddr=$back:$MCH")
    signed=$(cli 0 signrawtransaction "$raw")
    [ "$(printf '%s' "$signed" | jq -r .complete)" = true ] || fail "could not sign a funding transaction: $signed"
    cli 0 sendrawtransaction "$(printf '%s' "$signed" | jq -r .hex)" >/dev/null
done
cli 0 generate 1 >/dev/null
wait_index 0; wait_index 1
snapshot 0 >"$TMP/snap.$(cli 0 getblockcount)"
expect "node 0 index synced" "$(cli 0 znam_getindexinfo | jq -r .synced)" true
expect "no names yet" "$(cli 0 znam_getindexinfo | jq -r .names)" 0

# ---- 1. register, resolve, update, transfer through the wallet commands -----

say "== 1. register and resolve through the wallet commands"
expect_error "an upper-case name is refused" "Not a valid ZNAM name" cli 0 znam_register Alice "$T1"
expect_error "a name with a look-alike Cyrillic letter is refused" "Not a valid ZNAM name" cli 0 znam_register "$(printf 'al\321\226ce')" "$T1"
expect_error "a target that is not an address is refused" "not a t-address" cli 0 znam_register alice "not-an-address"
expect_error "a mistyped address is refused" "valid" cli 0 znam_register alice "$(printf '%s' "$T1" | sed -e 's/x$/~/' -e 's/[^~]$/x/' -e 's/~$/y/')" taddr
R1=$(cli 0 znam_register alice "$T1" "" "$O1" | jq -r .txid)
expect_error "a registration of the same name waiting in the mempool blocks a second one" "already waiting in the mempool" cli 0 znam_register alice "$T2" "" "$O2"
mine "$R1"
expect "alice registered" "$(nf 0 alice owner)" "$O1"
expect "alice resolves to T1" "$(rf 0 alice address)" "$T1"
expect "resolution says which tx set it" "$(rf 0 alice set_txid)" "$R1"
expect "and at which height" "$(rf 0 alice set_height)" "$(cli 0 getblockcount)"
expect "a fresh registration is flagged as recent" "$(rf 0 alice changed_recently)" true
expect "with a warning" "$(cli 0 znam_resolve alice | jq -r '.warnings | length')" 1
expect "the registration is history entry 1" "$(nf 0 alice 'history | length')" 1
expect "the signer is the owner" "$(nf 0 alice 'history[0].signer')" "$O1"
expect_error "a taken name cannot be registered" "already registered" cli 0 znam_register alice "$T2" "" "$O2"
sync 1; wait_index 1
expect "node 1 resolves alice the same" "$(rf 1 alice address)" "$T1"
expect_error "node 1 does not hold alice's owner key, so it cannot update it" "does not hold the key" cli 1 znam_update alice "$T2"

say "== 1b. update, transfer, the recent-change window"
# (a reorg deeper than 100 blocks would trip the wallet's witness cache, so the window is shortened instead of waiting 100 blocks)
mine_blocks 3
expect "3 blocks later, with a 3 block window, the change is no longer recent" "$(rf 0 alice changed_recently 3)" false
expect "with a 4 block window it still is" "$(rf 0 alice changed_recently 4)" true
expect "no warning outside the window" "$(cli 0 znam_resolve alice pay 3 | jq -r '.warnings | length')" 0
expect "a window of 0 turns the flag off" "$(rf 0 alice changed_recently 0)" false
U1=$(cli 0 znam_update alice "$T2" | jq -r .txid)
mine "$U1"
expect "alice resolves to T2 after the owner's update" "$(rf 0 alice address)" "$T2"
expect "the answer names the update tx" "$(rf 0 alice set_txid)" "$U1"
expect "the update is recent" "$(rf 0 alice changed_recently)" true
expect "the primary owner did not change" "$(nf 0 alice owner)" "$O1"
# a stranger's UPDATE (first input is O3's) is mined and ignored
S1=$(otx "$O3" "$("$ZS" update alice taddr "$T3")")
mine "$S1"
expect "a stranger's update is ignored" "$(nf 0 alice value)" "$T2"
info=$(cli 0 znam_getindexinfo)
expect "the ignored message is counted" "$(printf '%s' "$info" | jq -r .ignored)" 1
# TRANSFER to O2
expect_error "a transfer to a P2SH address is refused" "must be a t-address" cli 0 znam_transfer alice "$(cli 0 createmultisig 1 "[\"$(cli 0 validateaddress "$O1" | jq -r .pubkey)\"]" | jq -r .address)"
expect_error "a transfer to a z-address is refused" "must be a t-address" cli 0 znam_transfer alice "$ZA"
TR=$(cli 0 znam_transfer alice "$O2" | jq -r .txid)
mine "$TR"
expect "alice is owned by O2" "$(nf 0 alice owner)" "$O2"
expect "the transfer is a recent change" "$(rf 0 alice changed_recently)" true
expect "O1 owns nothing" "$(cli 0 znam_listnames "$O1" | jq -r length)" 0
expect "O2 owns alice" "$(cli 0 znam_listnames "$O2" | jq -r '.[0].name')" alice
# the old owner's update is ignored, the new owner's applies (the wallet holds both keys and picks the current owner's coin)
S2=$(otx "$O1" "$("$ZS" update alice taddr "$T3")")
mine "$S2"
expect "the previous owner's update is ignored" "$(nf 0 alice value)" "$T2"
U2=$(cli 0 znam_update alice "$T4" | jq -r .txid)
mine "$U2"
expect "the new owner's update applies" "$(nf 0 alice value)" "$T4"
expect "history has four applied entries" "$(nf 0 alice 'history | length')" 4
expect "in order" "$(cli 0 znam_getname alice | jq -r '[.history[].command] | join(",")')" "REGISTER,UPDATE,TRANSFER,UPDATE"
# RENEW is permissionless and not a change a payer must hear about
RN=$(otx "$O5" "$("$ZS" renew alice)")
mine "$RN"
expect "RENEW extends the expiry" "$(nf 0 alice expiryheight)" "$(( $(nf 0 alice registeredheight) + 2 * 210240 ))"
expect "RENEW does not move the change height" "$(rf 0 alice set_txid)" "$U2"

# ---- 2. the same name twice in one block, in both orders ------------------

say "== 2. first come, first served: two registrations of one name in one block"
BA=$(otx "$O3" "$("$ZS" register bob taddr "$T1")")
BB=$(otx "$O4" "$("$ZS" register bob taddr "$T2")")
t=0; until [ "$(cli 0 getrawmempool | jq -r 'length')" -ge 2 ]; do t=$((t + 1)); [ $t -lt 30 ] || fail "mempool"; sleep 1; done
mine "$BA" "$BB"
BLK=$(cli 0 getblockhash "$(cli 0 getblockcount)")
FIRST=$(cli 0 getblock "$BLK" | jq -r --arg a "$BA" --arg b "$BB" '[.tx[] | select(. == $a or . == $b)] | first')
if [ "$FIRST" = "$BA" ]; then WANT=$O3; WANTV=$T1; else WANT=$O4; WANTV=$T2; fi
expect "bob belongs to whoever is FIRST in the block" "$(nf 0 bob owner)" "$WANT"
expect "and has that registration's target" "$(nf 0 bob value)" "$WANTV"
expect "the registration tx is the first one" "$(nf 0 bob registeredtxid)" "$FIRST"
# again, with the order forced the other way by prioritisetransaction
CA=$(otx "$O3" "$("$ZS" register carol taddr "$T1")")
CB=$(otx "$O4" "$("$ZS" register carol taddr "$T2")")
cli 0 prioritisetransaction "$CB" 1000000000 100000000 >/dev/null
mine "$CA" "$CB"
BLK=$(cli 0 getblockhash "$(cli 0 getblockcount)")
FIRST=$(cli 0 getblock "$BLK" | jq -r --arg a "$CA" --arg b "$CB" '[.tx[] | select(. == $a or . == $b)] | first')
if [ "$FIRST" = "$CA" ]; then WANT=$O3; else WANT=$O4; fi
expect "carol belongs to whoever is first in the block" "$(nf 0 carol owner)" "$WANT"
expect "the loser's registration changed nothing" "$(cli 0 znam_getindexinfo | jq -r '.appliedbycommand.REGISTER')" 3
# the other order, forced: CB (higher priority) should lead; if the miner still put CA first the rule is the same
say "   carol: first in block was $( [ "$FIRST" = "$CB" ] && echo the prioritised tx || echo the other tx )"

# ---- 3. malformed records and the one-message rule ------------------------

say "== 3. records Z23 ignores, and the first-OP_RETURN rule"
MSGS0=$(cli 0 znam_getindexinfo | jq -r .messages)
DAVE=$("$ZS" register dave taddr "$T1")
# version 2 (the version push is the 2nd field), an upper-case name (push 04 "dave" -> "Dave"), a record cut short
BADV=$(otx "$O3" "$(printf '%s' "$DAVE" | sed 's/^6a045a4e414d0101/6a045a4e414d0102/')")
BADN=$(otx "$O3" "$(printf '%s' "$DAVE" | sed 's/0464617665/0444617665/')")
TRUNC=$(otx "$O3" "$(printf '%s' "$DAVE" | sed 's/..$//')")
mine "$BADV" "$BADN" "$TRUNC"
expect_error "dave is not registered (version 2, an upper-case name, a truncated record)" "No such name" cli 0 znam_getname dave
expect "none of the three parsed" "$(cli 0 znam_getindexinfo | jq -r .messages)" "$MSGS0"
# a record whose first OP_RETURN is not ZNAM: the second output is never read
TWO=$(otx "$O3" "6a03787878" "outscript=0:0x$DAVE")
mine "$TWO"
expect_error "only the first OP_RETURN of a transaction is its message" "No such name" cli 0 znam_getname dave
# bytes after the last field still parse: Z23 never calls overlay_reader_finish (here one more push, so the script stays standard)
TRL=$(otx "$O3" "$("$ZS" register trailing taddr "$T1")02aabb")
mine "$TRL"
expect "a record with trailing bytes registers (as in Z23)" "$(nf 0 trailing value)" "$T1"
# the OP_RETURN not at vout[0] is still read
LATE=1
LATEID=$(otx "$O4" "$("$ZS" register late taddr "$T3")")
LATE=0
mine "$LATEID"
expect "an OP_RETURN at vout[1] is read" "$(nf 0 late owner)" "$O4"

# ---- 4. pay a name, end to end through RPC ---------------------------------

say "== 4. pay a name: resolve, then send to the resolved ADDRESS"
SH=$(cli 0 znam_register shop "$T3" "" "$O5" | jq -r .txid)
mine "$SH"
expect "shop resolves to T3" "$(rf 0 shop address)" "$T3"
expect "kind transparent" "$(rf 0 shop kind)" transparent
expect "a z-address name" "$(cli 0 znam_register zshop "$ZA" | jq -r .name)" zshop
mine_blocks 1
expect "zshop resolves to a sapling address" "$(rf 0 zshop kind)" sapling
expect "which z_validateaddress accepts" "$(cli 1 z_validateaddress "$(rf 0 zshop address)" | jq -r .isvalid)" true
expect_error "sendtoaddress does not take a name" "Invalid ZClassic address" cli 0 sendtoaddress shop 1
R=$(cli 0 znam_resolve shop)
ADDR=$(printf '%s' "$R" | jq -r .address)
before=$(cli 1 getreceivedbyaddress "$T3" 0)
PAY=$(cli 0 sendtoaddress "$ADDR" 1)
mine "$PAY"
sync 1
expect "the payment reached the resolved address" "$(cli 1 getreceivedbyaddress "$T3" 1)" "$(awk -v b="$before" 'BEGIN { printf "%.8f", b + 1 }')"
expect "the transaction carries no name (no OP_RETURN)" "$(cli 0 getrawtransaction "$PAY" 1 | jq -r '[.vout[].scriptPubKey.type] | index("nulldata")')" null
# the owner changes the address: the next resolution says so, with the new set_txid
U3=$(cli 0 znam_update shop "$T4" | jq -r .txid)
mine "$U3"
R2=$(cli 0 znam_resolve shop)
expect "shop now resolves to T4" "$(printf '%s' "$R2" | jq -r .address)" "$T4"
expect "flagged as changed recently" "$(printf '%s' "$R2" | jq -r .changed_recently)" true
expect "naming the update tx" "$(printf '%s' "$R2" | jq -r .set_txid)" "$U3"
expect "and saying how long ago" "$(printf '%s' "$R2" | jq -r .blocks_since_change)" 0
[ "$(printf '%s' "$R2" | jq -r .address)" != "$ADDR" ] || fail "the address did not change"
ok "an address resolved earlier is not the one resolved now: a payer who confirms the address sees the difference"

# ---- 5. node 1's index agrees ---------------------------------------------

say "== 5. a second node's index agrees"
sync 1; wait_index 1
snapshot 1 >"$TMP/n1.snap"
snapshot 0 >"$TMP/n0.snap"
cmp -s "$TMP/n0.snap" "$TMP/n1.snap" || { diff "$TMP/n0.snap" "$TMP/n1.snap" | head -6; fail "node 1's index differs from node 0's"; }
ok "node 1 (synced over the network) indexes exactly what node 0 does"
expect "node 1 sees the same owner of shop" "$(nf 1 shop owner)" "$O5"

# ---- 6. reorgs ------------------------------------------------------------

say "== 6. reorg the chain out one block at a time"
TIPH=$(cli 0 getblockcount)
ABLK=$(cli 0 gettransaction "$R1" | jq -r .blockhash)
AH=$(cli 0 getblock "$ABLK" | jq -r .height)
h=$TIPH
while [ "$h" -ge "$AH" ]; do
    cli 0 invalidateblock "$(cli 0 getblockhash "$h")"
    h=$((h - 1))
    wait_index 0
    [ "$(cli 0 getblockcount)" = "$h" ] || fail "the chain did not move to $h"
    snapshot 0 >"$TMP/now"
    cmp -s "$TMP/now" "$TMP/snap.$h" || { diff "$TMP/now" "$TMP/snap.$h" | head -6; fail "the index after a reorg to height $h is not the snapshot of height $h"; }
done
ok "all $((TIPH - AH + 1)) reorg steps: the index is exactly the snapshot taken when the chain was at that height"
expect_error "alice is gone with her registration block" "No such name" cli 0 znam_getname alice
expect "no names left" "$(cli 0 znam_getindexinfo | jq -r .names)" 0
expect "resolving it says absent" "$(cli 0 znam_resolve alice | jq -r .error_code)" NAME_ABSENT
# the same blocks come back: the index follows forward to the same state
cli 0 reconsiderblock "$ABLK" >/dev/null
t=0; until [ "$(cli 0 getblockcount)" = "$TIPH" ]; do t=$((t + 1)); [ $t -lt 120 ] || fail "the chain did not come back"; sleep 1; done
wait_index 0
snapshot 0 >"$TMP/now"
cmp -s "$TMP/now" "$TMP/snap.$TIPH" || { diff "$TMP/now" "$TMP/snap.$TIPH" | head -6; fail "after reconsider the index is not the snapshot of the tip"; }
ok "the blocks came back (reconsiderblock): the index is exactly the old tip snapshot again"
cp "$TMP/now" "$TMP/ref.snap"
expect "alice is back" "$(nf 0 alice owner)" "$O2"

# ---- 7. fresh indexes -----------------------------------------------------

say "== 7. fresh indexes built from this chain: interrupted by kill -9 and by a clean stop, and in one go"
CH=$(cli 0 getblockcount)
build_interrupted() { # <node> <how: kill|stop>
    n=$1; how=$2
    start "$n" "$ZD" -znamindex=1 -znamindexdelayms=300 -connect=127.0.0.1:$((BASE + 0))
    sync "$n"
    t=0
    until [ "$(cli "$n" znam_getindexinfo | jq -r '.indexedheight // 0')" -ge 20 ]; do
        t=$((t + 1)); [ $t -lt 240 ] || fail "node $n did not start indexing"
        sleep 1
    done
    mid=$(cli "$n" znam_getindexinfo)
    [ "$(printf '%s' "$mid" | jq -r .synced)" = false ] || fail "the index finished before it could be interrupted"
    say "   interrupting node $n ($how) at indexed height $(printf '%s' "$mid" | jq -r .indexedheight) of $CH"
    if [ "$how" = kill ]; then kill9 "$n"; else stop "$n"; fi
    start "$n" "$ZD" -znamindex=1 -connect=127.0.0.1:$((BASE + 0))
    # kill -9 loses the unflushed chainstate, so the node restarts behind node 0 and catches up again, and the
    # index follows the node's own tip: wait for node 0's tip first, or the index is compared while it has no work
    sync "$n"
    wait_index "$n"
    snapshot "$n" >"$TMP/n$n.snap"
    cmp -s "$TMP/ref.snap" "$TMP/n$n.snap" || { diff "$TMP/ref.snap" "$TMP/n$n.snap" | head -6; fail "node $n: the index resumed after $how differs from the reference"; }
    ok "node $n: the index resumed after $how equals the reference exactly"
}
build_interrupted 3 kill
build_interrupted 4 stop
start 5 "$ZD" -znamindex=1 -connect=127.0.0.1:$((BASE + 0))
sync 5
wait_index 5
snapshot 5 >"$TMP/n5.snap"
cmp -s "$TMP/ref.snap" "$TMP/n5.snap" || { diff "$TMP/ref.snap" "$TMP/n5.snap" | head -6; fail "the from-block-0 index differs from the reference"; }
ok "node 5: built from block 0, equals the reference"
stop 5
start 5 "$ZD" -znamindex=1 -reindex -connect=127.0.0.1:$((BASE + 0))
wait_index 5
snapshot 5 >"$TMP/n5r.snap"
cmp -s "$TMP/ref.snap" "$TMP/n5r.snap" || { diff "$TMP/ref.snap" "$TMP/n5r.snap" | head -6; fail "the index after -reindex differs from the reference"; }
ok "node 5: the index after -reindex equals the reference"
stop 5; stop 4; stop 3
# the same chain, restarted: the index resumes at the tip and is unchanged
stop 1; stop 0
start 0 "$ZD" -znamindex=1
wait_index 0
snapshot 0 >"$TMP/n0r.snap"
cmp -s "$TMP/ref.snap" "$TMP/n0r.snap" || { diff "$TMP/ref.snap" "$TMP/n0r.snap" | head -6; fail "the index after a restart differs from the reference"; }
ok "node 0: the index after a restart equals the reference"

# ---- 8. a longer chain without the registrations --------------------------

say "== 8. a peer mines a longer chain that never contains the registrations; node 0 and node 1 follow it"
start 1 "$ZD" -znamindex=1 -connect=127.0.0.1:$((BASE + 0))
sync 1; wait_index 1
cli 0 invalidateblock "$ABLK" >/dev/null
wait_index 0
start 7 "$ZD" -connect=127.0.0.1:$((BASE + 0))
sync 7
cli 7 generate $((TIPH - AH + 6)) >/dev/null
t=0
until [ "$(cli 0 getbestblockhash)" = "$(cli 7 getbestblockhash)" ] && [ "$(cli 1 getbestblockhash)" = "$(cli 7 getbestblockhash)" ]; do
    t=$((t + 1)); [ $t -lt 180 ] || fail "node 0 and node 1 did not follow node 7's chain"; sleep 1
done
wait_index 0; wait_index 1
expect_error "alice is not on the new chain (node 0)" "No such name" cli 0 znam_getname alice
expect_error "alice is not on the new chain (node 1)" "No such name" cli 1 znam_getname alice
expect "node 1 followed with its index: no names" "$(cli 1 znam_getindexinfo | jq -r .names)" 0
t=0
until [ "$(cli 2 getbestblockhash)" = "$(cli 0 getbestblockhash)" ]; do
    t=$((t + 1)); [ $t -lt 120 ] || fail "node 2 did not follow the reorg"; sleep 1
done
ok "node 2 (no index) followed the same reorg"
# The old chain's transactions go back to the mempool and are mined again by the next block (they are still valid),
# so alice may well be registered again by the same first-in-block rule. A new name shows the new chain accepts
# registrations and the index follows them.
R9=$(cli 0 znam_register frank "$T4" "" "$O3" | jq -r .txid)
mine "$R9"
expect "frank, registered on the new chain, belongs to its registrant" "$(nf 0 frank owner)" "$O3"
stop 7
stop 1; stop 0
start 0 "$ZD" -znamindex=1
start 1 "$ZD" -znamindex=1 -connect=127.0.0.1:$((BASE + 0))
wait_index 0; wait_index 1
expect "the index survived a restart on the new chain" "$(nf 0 frank owner)" "$O3"
snapshot 0 >"$TMP/n0z.snap"
snapshot 1 >"$TMP/n1z.snap"
cmp -s "$TMP/n0z.snap" "$TMP/n1z.snap" || { diff "$TMP/n0z.snap" "$TMP/n1z.snap" | head -6; fail "node 1's index differs from node 0's on the new chain"; }
ok "node 1 agrees with node 0 on the new chain"

# ---- 8b. owner text in errors, canonical addresses, a node that is still catching up ----

say "== 8b. a hostile owner text never reaches the terminal; whitespace-padded addresses are refused; no names while catching up"
ESCOWN=$(printf 'x\033[2J\033]0;pwn\007\177\302\233\377')
ER=$(otx "$O4" "$("$ZS" register esc taddr "$T1")")
mine "$ER"
ET=$(otx "$O4" "$("$ZS" transfer esc "$ESCOWN")")
mine "$ET"
expect "the hostile owner text is stored as given" "$(cli 0 znam_getname esc | jq -r '.owner | length > 0')" true
clean_error() { # <label> <command...>: fails with an error that holds no control byte and no invalid UTF-8
    label=$1; shift
    if out=$("$@" 2>&1); then fail "$label: succeeded"; fi
    printf '%s' "$out" | LC_ALL=C grep -q "$(printf '[\001-\010\013-\037\177\200-\377]')" && fail "$label: the error carries a control or non-ASCII byte: $(printf '%s' "$out" | od -c | head -3)"
    printf '%s' "$out" | grep -qF '?' || fail "$label: the error has no replacement mark: $out"
    ok "$label: the owner text is clean"
}
clean_error "znam_register on a name with a hostile owner" cli 0 znam_register esc "$T1"
clean_error "znam_update on a name with a hostile owner" cli 0 znam_update esc "$T1"
clean_error "znam_transfer on a name with a hostile owner" cli 0 znam_transfer esc "$T1"
NLPAD=$(printf '\n_'); NLPAD=${NLPAD%_}
for pad in ' ' '  ' "$(printf '\t')" "$(printf '\r')" "$NLPAD"; do
    expect_error "znam_transfer refuses a trailing-padded address" "no surrounding whitespace" cli 0 znam_transfer frank "$O4$pad"
    expect_error "znam_transfer refuses a leading-padded address" "no surrounding whitespace" cli 0 znam_transfer frank "$pad$O4"
    expect_error "znam_register refuses a padded owner address" "no surrounding whitespace" cli 0 znam_register zpadded "$T1" "" "$O4$pad"
done
expect "frank was not touched by the refused transfers" "$(nf 0 frank owner)" "$O3"
# the node is level with its own index but its tip is days old: it is still catching up, so no name is answered
stop 1; stop 0
start 0 "$ZD" -znamindex=1 -mocktime=$(( $(date +%s) + 7 * 86400 ))
wait_index 0
expect "the index says synced with the old local tip" "$(cli 0 znam_getindexinfo | jq -r .synced)" true
expect_error "znam_resolve refuses while the node is catching up" "still catching up" cli 0 znam_resolve frank pay
expect_error "znam_register refuses while the node is catching up" "still catching up" cli 0 znam_register zlate "$T1"
expect_error "znam_update refuses while the node is catching up" "still catching up" cli 0 znam_update frank "$T1"
expect_error "znam_transfer refuses while the node is catching up" "still catching up" cli 0 znam_transfer frank "$O4"
expect "znam_getname still answers best-effort" "$(nf 0 frank owner)" "$O3"
stop 0
start 0 "$ZD" -znamindex=1
start 1 "$ZD" -znamindex=1 -connect=127.0.0.1:$((BASE + 0))
wait_index 0; wait_index 1
expect "znam_resolve answers again on a current node" "$(rf 0 frank address)" "$T4"

# ---- 9. the flag-off RPC list ---------------------------------------------

if [ -n "${BASELINE_SRC:-}" ]; then
    say "== 9. flag off: the RPC list is the baseline's plus the znam_* commands (and z_listsendjournal), nothing else"
    start 6 "$BASELINE_SRC/zclassicd"
    cli 6 help | grep -v '^$' | grep -v '^==' | sed 's/ .*//' | sort >"$TMP/help.base"
    cli 2 help | grep -v '^$' | grep -v '^==' | sed 's/ .*//' | sort >"$TMP/help.new"
    diff "$TMP/help.base" "$TMP/help.new" | grep '^[<>]' | sort >"$TMP/help.diff" || true
    [ "$(grep -c '^<' "$TMP/help.diff" || true)" = 0 ] || fail "commands vanished: $(grep '^<' "$TMP/help.diff")"
    svc_other=$(grep '^> ' "$TMP/help.diff" | grep -v '^> zslp_' | grep -v '^> znam_' | grep -v '^> z_listsendjournal$' || true)
    [ -z "$svc_other" ] || fail "unexpected new commands: $svc_other"
    svc_new=$(grep -c "^> znam_" "$TMP/help.diff" || true)
    [ "$svc_new" -le 8 ] || fail "new commands: got '$svc_new', expected at most 8"
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
say "znam_index.sh: PASS ($CHECKS checks)"
