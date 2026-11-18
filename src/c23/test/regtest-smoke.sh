#!/bin/sh
# TEST-ONLY. Regtest smoke for a zclassicd built on the C23 crypto core.
#
# usage: sh src/c23/test/regtest-smoke.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--peer-bin <dir>] [--port-base <n>]
#
# Node A (--bin) runs in a fresh datadir under --work, with no outside network
# (-connect/-listen on 127.0.0.1 only, -dnsseed=0, -bootstrap=0). It
#   1. mines into the Sprout era (with --peer-bin: node B, a libsnark build, creates
#      and MINES a Sprout PHGR13 JoinSplit, which A must accept; A cannot create
#      PHGR13 proofs, they are verify-only since libsnark was removed),
#   2. mines past Overwinter and Sapling activation,
#   3. shields coinbase to a Sapling address (output proof),
#   4. sends z->z (spend + output proofs) and z->t (spend proof),
#   5. spends the Sprout note to a t-address (Groth16 JoinSplit; without --peer-bin
#      the note is first created by a post-Sapling t->Sprout Groth16 JoinSplit),
#   6. restarts and runs verifychain.
# With --peer-bin, node B (for example the previous release) runs in its own
# fresh datadir, connected only to node A, and follows A's chain block by
# block and ends on the same tip: every proof and signature A made is then
# verified by B's consensus code, and A's mempool/block acceptance verified its
# own. B also supplies the one block A cannot make itself (step 1), so A's
# acceptance of a PHGR13 JoinSplit created by an older binary is exercised.
# Never point this at a real datadir; it creates and deletes its own.
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
# Node A must reach the peer's tip (the peer mined a block A has not seen).
sync_a_to_b() {
    want=$(cli_b getbestblockhash); i=0
    while [ $i -lt 120 ]; do
        [ "$(cli_a getbestblockhash 2>/dev/null)" = "$want" ] && return 0
        sleep 1; i=$((i + 1))
    done
    fail "node A did not accept the peer's tip $want (A at $(cli_a getblockcount 2>&1); see $da/regtest/debug.log)"
}
wait_op_b() { # <opid> <label>: wait on the peer's async operation; print its txid
    i=0
    while [ $i -lt 1800 ]; do
        st=$(cli_b z_getoperationstatus "[\"$1\"]")
        case "$st" in
            *'"status": "success"'*)
                cli_b z_getoperationresult "[\"$1\"]" | sed -n 's/.*"txid": "\([0-9a-f]*\)".*/\1/p' | head -1
                return 0 ;;
            *'"status": "failed"'*)
                echo "$st" >&2; return 1 ;;
        esac
        sleep 1; i=$((i + 1))
    done
    echo "timeout waiting for $2" >&2; return 1
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
sprout=""
if [ -n "$peer" ]; then
    # Node B (a libsnark build) creates a PHGR13 JoinSplit and mines it; A, which
    # can no longer create one, must accept the block.
    baddr=$(cli_b getnewaddress) || fail "peer getnewaddress"
    cli_a sendtoaddress "$baddr" 10 >/dev/null || fail "fund the peer"
    mine 1; sync_b
    bsprout=$(cli_b z_getnewaddress sprout) || fail "peer z_getnewaddress sprout"
    step "height $(height): peer creates a PHGR13 JoinSplit (t->Sprout) and mines it"
    op=$(cli_b z_sendmany "$baddr" "[{\"address\":\"$bsprout\",\"amount\":5.0}]" 1 0.0001 | opid_of)
    [ -n "$op" ] || fail "peer z_sendmany t->Sprout returned no opid"
    wait_op_b "$op" "peer PHGR13 shield" >/dev/null || fail "peer PHGR13 shield operation"
    cli_b generate 1 >/dev/null || fail "peer generate"
    sync_a_to_b
    # The JoinSplit is in a block A accepted (its tip equals the peer's).
    tx_sprout=$(cli_b getblock "$(cli_b getbestblockhash)" | sed -n 's/^ *"\([0-9a-f]\{64\}\)",\{0,1\}$/\1/p' | tail -1)
    [ -n "$tx_sprout" ] || fail "could not read the peer block's transactions"
    cli_a getblock "$(cli_a getbestblockhash)" | grep -q "$tx_sprout" || fail "A's tip block does not contain the PHGR13 tx $tx_sprout"
    cli_a getrawtransaction "$tx_sprout" 1 2>/dev/null | grep -q '"vjoinsplit"' || step "(A has no txindex; block membership checked instead)"
    step "A accepted the PHGR13 JoinSplit tx $tx_sprout created and mined by the peer"
    spk=$(cli_b z_exportkey "$bsprout") || fail "peer z_exportkey"
    cli_a z_importkey "$spk" yes >/dev/null || fail "A z_importkey of the Sprout key"
    sprout=$bsprout
    sprout_bal=$(cli_a z_getbalance "$sprout")
    [ "$sprout_bal" = "5.00000000" ] || fail "A sees Sprout balance $sprout_bal, want 5.00000000"
    step "A holds the PHGR13-created Sprout note, balance $sprout_bal"
else
    step "no --peer-bin: PHGR13 proofs cannot be created here; the Sprout note is made after Sapling (Groth16)"
fi

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

if [ -z "$sprout" ]; then
    # No PHGR13 note exists (A cannot make one): make a Sprout note with a Groth16
    # JoinSplit, as any wallet does after Sapling.
    sprout=$(cli_a z_getnewaddress sprout) || fail "z_getnewaddress sprout"
    op=$(cli_a z_shieldcoinbase "*" "$sprout" 0.0001 5 | opid_of)
    [ -n "$op" ] || fail "z_shieldcoinbase to Sprout returned no opid"
    tx_sprout=$(wait_op "$op" "Sprout shield (Groth16)") || fail "Sprout shield (Groth16 JoinSplit) operation"
    mine 1; sync_b
    in_block "$tx_sprout" || fail "Sprout shield tx $tx_sprout not mined"
    step "t->Sprout Groth16 tx $tx_sprout mined, Sprout balance $(cli_a z_getbalance "$sprout")"
fi
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
echo "regtest-smoke: PASS in $(( $(date +%s) - t0 ))s (${peer:+peer-made PHGR13 block accepted, }Sapling shield, z->z, z->t, Sprout Groth16 spend; height $h)"
exit 0
