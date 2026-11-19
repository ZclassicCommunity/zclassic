#!/bin/sh
# Headless Sapling regtest smoke for a zclassicd + zclassic-cli pair (Linux, macOS, or
# Windows under MSYS2/Git Bash).  It never touches a real datadir: it creates its own
# under --work, uses --port-base..+1 on 127.0.0.1 only, and stops what it started.
#
#   1. start a regtest node with Overwinter and Sapling active from block 1,
#   2. mine 102 blocks, z_shieldcoinbase to a Sapling address,
#   3. z -> z (with a memo) and z -> t, each mined,
#   4. assert every balance exactly, stop the node, check the process is gone.
#
# usage: sh zcutil/local-ci-smoke.sh --bin <dir with zclassicd[.exe], zclassic-cli[.exe]>
#            --work <empty dir> [--port-base 43900]
# Needs the Zcash Sapling parameters in the default parameter directory.
set -u
bin=""; work=""; base=43900
while [ $# -gt 0 ]; do
    case $1 in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        *) echo "local-ci-smoke: unknown argument $1" >&2; exit 2 ;;
    esac
done
exe=""; [ -f "$bin/zclassicd.exe" ] && exe=.exe
[ -f "$bin/zclassicd$exe" ] && [ -f "$bin/zclassic-cli$exe" ] && [ -n "$work" ] || { echo "usage: local-ci-smoke.sh --bin DIR --work DIR [--port-base N]" >&2; exit 2; }
mkdir -p "$work" && work=$(cd "$work" && pwd) || exit 2
[ -z "$(ls -A "$work")" ] || { echo "local-ci-smoke: $work is not empty" >&2; exit 2; }
bin=$(cd "$bin" && pwd)
dd=$work/data; mkdir -p "$dd"
rpcport=$((base + 1)); p2p=$base
pw=smoke$$
printf 'rpcuser=smoke\nrpcpassword=%s\nrpcport=%s\n' "$pw" "$rpcport" >"$dd/zclassic.conf"

# On Windows, hand the native paths to the .exe files.
nat() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
cli() { "$bin/zclassic-cli$exe" -regtest -datadir="$(nat "$dd")" "$@"; }
sat() { awk -v v="$1" 'BEGIN { printf "%d", v * 100000000 + 0.5 }'; }
sub8() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.8f", a - b }'; }
fail() { echo "local-ci-smoke: FAIL $*"; cleanup; exit 1; }
cleanup() {
    cli stop >/dev/null 2>&1
    # The node is gone when its RPC no longer answers (a pid file path differs per platform).
    i=0; while [ $i -lt 90 ] && cli getblockcount >/dev/null 2>&1; do sleep 1; i=$((i + 1)); done
    i=0; while [ $i -lt 30 ] && kill -0 "$pid" 2>/dev/null; do sleep 1; i=$((i + 1)); done
}

"$bin/zclassicd$exe" -regtest -datadir="$(nat "$dd")" -port=$p2p -dnsseed=0 -bootstrap=0 -upnp=0 -listen=0 \
    -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 \
    -nuparams=5ba81b19:1 -nuparams=76b809bb:1 -debuglogfile=1 -printtoconsole=0 -showmetrics=0 \
    >"$work/stdout.log" 2>&1 &
pid=$!
i=0
while [ $i -lt 300 ]; do
    cli getblockcount >/dev/null 2>&1 && break
    kill -0 "$pid" 2>/dev/null || fail "node exited at startup (see $work/stdout.log)"
    sleep 1; i=$((i + 1))
done
[ $i -lt 300 ] || fail "RPC did not come up"
echo "node up on rpc $rpcport after ${i}s: $(cli getinfo | sed -n 's/.*"version": *\([0-9]*\).*/version \1/p')"

cli generate 102 >/dev/null || fail "generate 102"
[ "$(cli getblockcount)" = 102 ] || fail "height is not 102"
za=$(cli z_getnewaddress sapling) && zb=$(cli z_getnewaddress sapling) && tb=$(cli getnewaddress) || fail "address creation"
case $za in zs*|zregtestsapling*) ;; *) fail "not a Sapling address: $za" ;; esac

wait_op() { # <opid> -> success or fail
    n=0
    while [ $n -lt 240 ]; do
        st=$(cli z_getoperationstatus "[\"$1\"]" | sed -n 's/.*"status": *"\([a-z]*\)".*/\1/p' | head -1)
        case $st in success) return 0 ;; failed|cancelled) cli z_getoperationresult "[\"$1\"]"; return 1 ;; esac
        sleep 1; n=$((n + 1))
    done
    return 1
}

# 2. shield coinbase
out=$(cli z_shieldcoinbase "*" "$za") || fail "z_shieldcoinbase: $out"
op=$(printf '%s\n' "$out" | sed -n 's/.*"opid": *"\([^"]*\)".*/\1/p')
sv=$(printf '%s\n' "$out" | sed -n 's/.*"shieldingValue": *\([0-9.]*\).*/\1/p')
[ -n "$op" ] && [ -n "$sv" ] || fail "no opid/shieldingValue in: $out"
wait_op "$op" || fail "shield operation did not succeed"
cli generate 1 >/dev/null
bal=$(cli z_getbalance "$za")
exp=$(sub8 "$sv" 0.0001)
[ "$(sat "$bal")" = "$(sat "$exp")" ] || fail "shielded balance $bal, expected $exp (shieldingValue $sv - fee 0.0001)"
echo "ok  shield coinbase: $bal in $za"

# 3a. z -> z with memo (hex of "ci")
amt1=1.5
op=$(cli z_sendmany "$za" "[{\"address\":\"$zb\",\"amount\":$amt1,\"memo\":\"6369\"}]") || fail "z_sendmany z->z"
wait_op "$op" || fail "z->z did not succeed"
cli generate 1 >/dev/null
a1=$(cli z_getbalance "$za"); b1=$(cli z_getbalance "$zb")
exp_a=$(sub8 "$bal" "$(awk -v x=$amt1 'BEGIN { printf "%.8f", x + 0.0001 }')")
[ "$(sat "$b1")" = "$(sat $amt1)" ] || fail "z->z receiver balance $b1, expected $amt1"
[ "$(sat "$a1")" = "$(sat "$exp_a")" ] || fail "z->z sender balance $a1, expected $exp_a"
echo "ok  z->z: sender $a1, receiver $b1"

# 3b. z -> t
amt2=0.5
op=$(cli z_sendmany "$zb" "[{\"address\":\"$tb\",\"amount\":$amt2}]") || fail "z_sendmany z->t"
wait_op "$op" || fail "z->t did not succeed"
cli generate 1 >/dev/null
b2=$(cli z_getbalance "$zb"); t2=$(cli z_getbalance "$tb")
exp_b=$(sub8 "$amt1" "$(awk -v x=$amt2 'BEGIN { printf "%.8f", x + 0.0001 }')")
[ "$(sat "$b2")" = "$(sat "$exp_b")" ] || fail "z->t shielded remainder $b2, expected $exp_b"
[ "$(sat "$t2")" = "$(sat $amt2)" ] || fail "z->t transparent balance $t2, expected $amt2"
echo "ok  z->t: remainder $b2, transparent $t2"

[ "$(cli getblockcount)" = 105 ] || fail "unexpected final height $(cli getblockcount)"
cleanup

if kill -0 "$pid" 2>/dev/null || cli getblockcount >/dev/null 2>&1; then echo "local-ci-smoke: FAIL node still running"; kill -9 "$pid" 2>/dev/null; exit 1; fi
echo "local-ci-smoke: PASS"
