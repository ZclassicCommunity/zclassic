#!/bin/sh
# -zapwallettxes erases every wallet transaction and finds them again by the rescan it implies.
# A node that dies during that rescan must not come back with a best-block locator that says the
# erased transactions were already seen: the next plain start has to rescan and report every
# output again. Also: the test-only crash hooks are refused outside regtest.
#
# usage: wallet_zap_interrupt.sh --bin <dir> --work <dir> [--base port]
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
BIN=""; WORK=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;;
        *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
iso_base BASE "${PORT_BASE:-}" 112
SD=$WORK/zap; rm -rf "$SD"; mkdir -p "$SD"; : >"$SD/pids"
SCN_LOG=$WORK/checks.log; : >"$SCN_LOG"; SCN_ID=zap; OBS_LOG=$WORK/obs.log; : >"$OBS_LOG"
trap 'stop_all' EXIT

# start_crash <args>: start node 0 with a crash hook armed; true if it exited with status 77
start_crash() {
    dir=$SD/node0; rm -f "$dir/regtest/.lock"
    $ZCL_RUN "$BIN/zclassicd" -datadir="$dir" -regtest -server=1 -daemon=0 -showmetrics=0 -listen=0 \
        -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=$((BASE + 100)) -dnsseed=0 -discover=0 -listenonion=0 -upnp=0 \
        -debuglogfile=1 -exportdir="$SD/export" $NU_ARGS "$@" >>"$dir/stdout.log" 2>&1
    rc=$?; rm -f "$dir/regtest/.lock"; [ $rc = 77 ]
}
totals() { cli 0 z_gettotalbalance 1 | jq -c '[.transparent,.private]'; }

start 0 "$BIN" -listen=0 || exit 1
cli 0 generate 105 >/dev/null
ZA=$(cli 0 z_getnewaddress sapling); TA=$(cli 0 getnewaddress)
for k in 1 2 3 4 5; do cli 0 sendtoaddress "$TA" 1 >/dev/null; cli 0 generate 1 >/dev/null; done
o=$(cli 0 z_shieldcoinbase "*" "$ZA" 0.0001 2 | jget opid); wait_op 0 "$o" >/dev/null; cli 0 generate 1 >/dev/null
WANT=$(totals); NTX=$(cli 0 getwalletinfo | jget txcount)
stop 0

# 1. die during the rescan that -zapwallettxes implies (after the third transaction found again)
start_crash -zapwallettxes=2 -testcrashpoint=addtowallet-after-write:3
ck "the node died during the -zapwallettxes rescan" "$?" 0
start 0 "$BIN" -listen=0 || exit 1
ck "plain start after the crash reports every balance again" "$(totals)" "$WANT"
ck "plain start after the crash holds every transaction again" "$(cli 0 getwalletinfo | jget txcount)" "$NTX"
stop 0
start 0 "$BIN" -listen=0 || exit 1
ck "and keeps them after one more restart" "$(totals)" "$WANT"
stop 0

# 2. the crash hooks and the checkpoint interval are regtest-only
for a in -testcrashpoint=any -testsetchaininterval=0; do
    mkdir -p "$SD/testnet"
    # no network: a binary without the check must not reach testnet peers while it is being judged
    $ZCL_RUN "$BIN/zclassicd" -datadir="$SD/testnet" -testnet -listen=0 -connect=0 -dnsseed=0 -server=0 -daemon=0 \
        -showmetrics=0 "$a" >"$SD/testnet/out.log" 2>&1 &
    gp=$!; gw=0; while kill -0 $gp 2>/dev/null && [ $gw -lt 100 ]; do gw=$((gw + 1)); sleep 0.2; done
    if kill -0 $gp 2>/dev/null; then kill $gp; wait $gp; grc=running; else wait $gp; grc=$?; fi
    ck "$a refused outside regtest" "$grc:$(grep -c 'may only be used on regtest' "$SD/testnet/out.log")" "1:1"
done

np=$(grep -c '^PASS' "$SCN_LOG"); nf=$(grep -c '^FAIL' "$SCN_LOG")
say "wallet_zap_interrupt: $np passed, $nf failed"
[ "$nf" = 0 ]
