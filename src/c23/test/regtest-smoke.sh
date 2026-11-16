#!/bin/sh
# TEST-ONLY. Regtest smoke for a zclassicd built on the C23 crypto core.
#
# usage: sh src/c23/test/regtest-smoke.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--peer-bin <dir>] [--port-base <n>]
#
# Node A (--bin) runs in a fresh datadir under --work, with no outside network
# (-connect/-listen on 127.0.0.1 only, -dnsseed=0, -bootstrap=0). It
#   1. mines into the Sprout era and shields coinbase to a Sprout address
#      (PHGR13 JoinSplit, libsnark),
#   2. mines past Overwinter and Sapling activation,
#   3. shields coinbase to a Sapling address (output proof),
#   4. sends z->z (spend + output proofs) and z->t (spend proof),
#   5. spends the Sprout note to a t-address (Groth16 JoinSplit),
#   6. restarts and runs verifychain.
# With --peer-bin, node B (for example a Rust-backed zclassicd) runs in its own
# fresh datadir, connected only to node A, and must follow A's chain block by
# block and end on the same tip: every proof and signature A made is then
# verified by B's consensus code, and A's mempool/block acceptance verified its
# own. Never point this at a real datadir; it creates and deletes its own.
set -u
bin=""; peer=""; work=""; base=38232
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --peer-bin) peer=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        *) echo "regtest-smoke: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: regtest-smoke.sh --bin <dir> --work <dir> [--peer-bin <dir>] [--port-base <n>]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "regtest-smoke: $work is not empty" >&2; exit 2; }

OW=120; SAP=140
pa=$base; ra=$((base + 1)); pb=$((base + 2)); rb=$((base + 3))
da=$work/a; db=$work/b
common="-regtest -dnsseed=0 -bootstrap=0 -upnp=0 -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -nuparams=5ba81b19:$OW -nuparams=76b809bb:$SAP -debug=zc23 -debuglogfile=1 -printtoconsole=0 -showmetrics=0"

mkconf() { # <datadir> <rpcport>
    mkdir -p "$1" && printf 'rpcuser=smoke\nrpcpassword=smoke%s\nrpcport=%s\n' "$$" "$2" >"$1/zclassic.conf"
}
cli_a() { "$bin/zclassic-cli" -regtest -datadir="$da" "$@"; }
cli_b() { "$peer/zclassic-cli" -regtest -datadir="$db" "$@"; }

fail() { echo "regtest-smoke: FAIL $*"; cleanup; exit 1; }
cleanup() {
    cli_a stop >/dev/null 2>&1
    [ -z "$peer" ] || cli_b stop >/dev/null 2>&1
    i=0
    while [ $i -lt 60 ] && { [ -f "$da/regtest/zclassicd.pid" ] || [ -f "$db/regtest/zclassicd.pid" ]; }; do
        sleep 1; i=$((i + 1))
    done
}
wait_rpc() { # <cli fn>
    i=0
    while [ $i -lt 600 ]; do
        "$1" getblockcount >/dev/null 2>&1 && return 0
        sleep 1; i=$((i + 1))
    done
    return 1
}
start_a() {
    # shellcheck disable=SC2086
    "$bin/zclassicd" $common -datadir="$da" -port=$pa -listen=1 -connect=0 -daemon >/dev/null 2>&1 || return 1
    wait_rpc cli_a
}
start_b() {
    # shellcheck disable=SC2086
    "$peer/zclassicd" $common -datadir="$db" -port=$pb -listen=0 -connect=127.0.0.1:$pa -daemon >/dev/null 2>&1 || return 1
    wait_rpc cli_b
}
height() { cli_a getblockcount; }
mine() { cli_a generate "$1" >/dev/null || fail "generate $1 at height $(height)"; }
# Wait for an async operation; print its txid.
wait_op() { # <opid> <label>
    i=0
    while [ $i -lt 1800 ]; do
        st=$(cli_a z_getoperationstatus "[\"$1\"]")
        case "$st" in
            *'"status": "success"'*)
                cli_a z_getoperationresult "[\"$1\"]" | sed -n 's/.*"txid": "\([0-9a-f]*\)".*/\1/p' | head -1
                return 0 ;;
            *'"status": "failed"'*)
                echo "$st" >&2; return 1 ;;
        esac
        sleep 1; i=$((i + 1))
    done
    echo "timeout waiting for $2" >&2; return 1
}
opid_of() { sed -n 's/.*\(opid-[0-9a-f-]*\).*/\1/p' | head -1; }
in_block() { # <txid>: the tx is confirmed
    c=$(cli_a getrawtransaction "$1" 1 2>/dev/null | sed -n 's/.*"confirmations": \([0-9]*\).*/\1/p' | head -1)
    [ "${c:-0}" -ge 1 ]
}
sync_b() {
    [ -n "$peer" ] || return 0
    want=$(cli_a getbestblockhash); i=0
    while [ $i -lt 120 ]; do
        [ "$(cli_b getbestblockhash 2>/dev/null)" = "$want" ] && return 0
        sleep 1; i=$((i + 1))
    done
    fail "peer did not reach tip $want at height $(height) (peer at $(cli_b getblockcount 2>&1))"
}
step() { echo "regtest-smoke: $*"; }
t0=$(date +%s)

mkconf "$da" $ra
start_a || fail "node A did not start (see $da/regtest/debug.log)"
if [ -n "$peer" ]; then
    mkconf "$db" $rb
    start_b || fail "peer node did not start (see $db/regtest/debug.log)"
fi

taddr=$(cli_a getnewaddress)
mine 105; sync_b
step "height $(height): Sprout era, shielding coinbase to a Sprout address (PHGR13)"
sprout=$(cli_a z_getnewaddress sprout) || fail "z_getnewaddress sprout"
op=$(cli_a z_shieldcoinbase "*" "$sprout" 0.0001 2 | opid_of)
[ -n "$op" ] || fail "z_shieldcoinbase to Sprout returned no opid"
tx_sprout=$(wait_op "$op" "Sprout shield") || fail "Sprout shield operation"
mine 1; sync_b
in_block "$tx_sprout" || fail "Sprout shield tx $tx_sprout not mined"
sprout_bal=$(cli_a z_getbalance "$sprout")
step "Sprout shield tx $tx_sprout mined, Sprout balance $sprout_bal"

mine $((SAP + 2 - $(height))); sync_b
step "height $(height): Overwinter ($OW) and Sapling ($SAP) active"
zs1=$(cli_a z_getnewaddress sapling) || fail "z_getnewaddress sapling"
zs2=$(cli_a z_getnewaddress sapling)

op=$(cli_a z_shieldcoinbase "*" "$zs1" 0.0001 5 | opid_of)
[ -n "$op" ] || fail "z_shieldcoinbase to Sapling returned no opid"
tx_shield=$(wait_op "$op" "Sapling shield") || fail "Sapling shield operation"
mine 1; sync_b
in_block "$tx_shield" || fail "Sapling shield tx $tx_shield not mined"
b1=$(cli_a z_getbalance "$zs1")
step "t->z shield tx $tx_shield mined, zs1 balance $b1"
case "$b1" in 0|0.0|0.00000000) fail "zs1 balance is zero after shielding" ;; esac

op=$(cli_a z_sendmany "$zs1" "[{\"address\":\"$zs2\",\"amount\":7.5}]" 1 0.0001 | opid_of)
[ -n "$op" ] || fail "z_sendmany z->z returned no opid"
tx_zz=$(wait_op "$op" "z->z") || fail "z->z operation"
mine 1; sync_b
in_block "$tx_zz" || fail "z->z tx $tx_zz not mined"
b2=$(cli_a z_getbalance "$zs2")
[ "$b2" = "7.50000000" ] || fail "zs2 balance $b2 after z->z, want 7.50000000"
step "z->z tx $tx_zz mined, zs2 balance $b2"

op=$(cli_a z_sendmany "$zs2" "[{\"address\":\"$taddr\",\"amount\":3.25}]" 1 0.0001 | opid_of)
[ -n "$op" ] || fail "z_sendmany z->t returned no opid"
tx_zt=$(wait_op "$op" "z->t") || fail "z->t operation"
mine 1; sync_b
in_block "$tx_zt" || fail "z->t tx $tx_zt not mined"
b2=$(cli_a z_getbalance "$zs2")
[ "$b2" = "4.24990000" ] || fail "zs2 balance $b2 after z->t, want 4.24990000"
step "z->t tx $tx_zt mined, zs2 balance $b2"

step "height $(height): spending the Sprout note to a t-address (Groth16 JoinSplit)"
op=$(cli_a z_sendmany "$sprout" "[{\"address\":\"$taddr\",\"amount\":1.0}]" 1 0.0001 | opid_of)
[ -n "$op" ] || fail "z_sendmany Sprout->t returned no opid"
tx_js=$(wait_op "$op" "Sprout->t") || fail "Sprout->t operation (Groth16 JoinSplit)"
mine 1; sync_b
in_block "$tx_js" || fail "Sprout->t tx $tx_js not mined"
step "Sprout->t Groth16 tx $tx_js mined"

mine 2; sync_b
tip=$(cli_a getbestblockhash); h=$(height)
cli_a stop >/dev/null; i=0
while [ -f "$da/regtest/zclassicd.pid" ] && [ $i -lt 120 ]; do sleep 1; i=$((i + 1)); done
start_a || fail "node A did not restart"
[ "$(cli_a getbestblockhash)" = "$tip" ] || fail "tip changed across restart"
vc=$(cli_a verifychain 4 0) || fail "verifychain RPC"
[ "$vc" = "true" ] || fail "verifychain 4 0 returned $vc"
step "restart ok, verifychain 4 0 = true, tip $tip at height $h"
if [ -n "$peer" ]; then
    [ "$(cli_b getbestblockhash)" = "$tip" ] || fail "peer tip differs after restart"
    step "peer ($peer) followed every block and is on the same tip"
    grep -c "Leaving InitialBlockDownload" "$db/regtest/debug.log" | sed 's/^/regtest-smoke: peer left IBD (log lines): /'
fi
cleanup
echo "regtest-smoke: PASS in $(( $(date +%s) - t0 ))s (Sprout PHGR shield, Sapling shield, z->z, z->t, Sprout Groth16 spend; height $h)"
exit 0
