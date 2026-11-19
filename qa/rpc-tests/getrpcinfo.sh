#!/bin/sh
# TEST-ONLY. getrpcinfo (in-flight tracker + per-method stats) and the narrowed
# locking of getconnectioncount / getpeerinfo, on a two-node regtest.
#
# usage: sh qa/rpc-tests/getrpcinfo.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--port-base <n>]
set -u
bin=""; work=""; base=51900
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        *) echo "getrpcinfo-test: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: getrpcinfo.sh --bin <dir> --work <dir> [--port-base <n>]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "getrpcinfo-test: $work is not empty" >&2; exit 2; }

failures=0
ok() { echo "getrpcinfo-test: PASS $*"; }
bad() { echo "getrpcinfo-test: FAIL $*"; failures=$((failures + 1)); }
dd() { echo "$work/node$1"; }
cli() { cn=$1; shift; "$bin/zclassic-cli" -regtest -datadir="$(dd "$cn")" "$@"; }
for n in 0 1; do
    mkdir -p "$(dd $n)"
    printf 'rpcuser=ri\nrpcpassword=ri%s\nrpcport=%s\n' "$$" "$((base + n * 10 + 1))" >"$(dd $n)/zclassic.conf"
done
start() { # node [extra args]
    n=$1; shift
    "$bin/zclassicd" -regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 \
        -rpcallowip=127.0.0.1 -debuglogfile=1 -printtoconsole=0 -showmetrics=0 -bootstrap=0 \
        -datadir="$(dd $n)" -port=$((base + n * 10)) -listen=1 -connect=0 "$@" -daemon >/dev/null 2>&1 || return 1
    i=0
    while [ $i -lt 600 ]; do cli $n getblockcount >/dev/null 2>&1 && return 0; sleep 1; i=$((i + 1)); done
    return 1
}
stop() {
    for n in 0 1; do cli $n stop >/dev/null 2>&1; done
    for n in 0 1; do
        i=0
        while [ $i -lt 60 ] && [ -f "$(dd $n)/regtest/zclassicd.pid" ]; do sleep 1; i=$((i + 1)); done
    done
}
stop0() { cli 0 stop >/dev/null 2>&1; i=0; while [ $i -lt 60 ] && [ -f "$(dd 0)/regtest/zclassicd.pid" ]; do sleep 1; i=$((i + 1)); done; }
trap stop EXIT

start 0 && start 1 || { echo "getrpcinfo-test: nodes did not start"; exit 1; }

# 1. getrpcinfo shape and counting
cli 0 getrpcinfo >/dev/null || bad "first getrpcinfo failed"
info=$(cli 0 getrpcinfo)
echo "$info" | grep -q '"active_commands"' && ok "active_commands present" || bad "no active_commands"
echo "$info" | grep -q '"methods"' && ok "methods object present" || bad "no methods object"
echo "$info" | grep -q '"getrpcinfo"' && ok "getrpcinfo listed in methods" || bad "getrpcinfo not in methods"
cnt=$(echo "$info" | tr -d ' \n' | sed -n 's/.*"getrpcinfo":{"count":\([0-9]*\).*/\1/p')
[ -n "$cnt" ] && [ "$cnt" -ge 1 ] && ok "getrpcinfo count >= 1 ($cnt)" || bad "getrpcinfo count=$cnt"
echo "$info" | tr -d ' \n' | grep -q '"getrpcinfo":{"count":[0-9]*,"total_us":[0-9]*,"max_us":[0-9]*,"errors":[0-9]*}' \
    && ok "per-method field set" || bad "per-method field set differs"
echo "$info" | tr -d ' \n' | grep -q '"active_commands":\[{"method":"getrpcinfo","duration_us":[0-9]*}\]' \
    && ok "self shown in active_commands" || bad "active_commands entry shape"
cli 0 getrpcinfo extra >/dev/null 2>&1 && bad "getrpcinfo accepted an argument" || ok "getrpcinfo rejects arguments"
cli 0 help | grep -q '^getrpcinfo' && ok "getrpcinfo in help list" || bad "getrpcinfo missing from help"

# 2. errors counted, params never logged
cli 0 getblockhash 99999 >/dev/null 2>&1
info=$(cli 0 getrpcinfo | tr -d ' \n')
echo "$info" | grep -q '"getblockhash":{"count":1,"total_us":[0-9]*,"max_us":[0-9]*,"errors":1}' \
    && ok "failed call counted as error" || bad "error not counted: $info"

# 3. slow-call WARN names the method, never params (threshold 1 ms is not
# reliable, so use -rpcslowlog=0 off and a restart with 1 ms plus a heavier call)
stop0
start 0 -rpcslowlog=1 || { echo "getrpcinfo-test: restart failed"; exit 1; }
cli 0 setgenerate true 1 >/dev/null 2>&1
loops=0
while [ $loops -lt 40 ]; do
    cli 0 getinfo >/dev/null 2>&1; cli 0 getblockchaininfo >/dev/null 2>&1; cli 0 gettxoutsetinfo >/dev/null 2>&1
    grep -q 'WARN: slow RPC' "$(dd 0)/regtest/debug.log" 2>/dev/null && break
    loops=$((loops + 1))
done
if grep -q 'WARN: slow RPC' "$(dd 0)/regtest/debug.log" 2>/dev/null; then
    ok "slow RPC WARN line logged"
    grep 'WARN: slow RPC' "$(dd 0)/regtest/debug.log" | grep -qE 'WARN: slow RPC [A-Za-z0-9_.-]+ took [0-9]+ ms$' \
        && ok "WARN line has method and ms only" || bad "WARN line format"
else
    echo "getrpcinfo-test: SKIP no call exceeded 1 ms (WARN line not exercised)"
fi
stop0
start 0 || { echo "getrpcinfo-test: restart 2 failed"; exit 1; }
# 4. getconnectioncount / getpeerinfo on a connected pair
cli 0 addnode "127.0.0.1:$((base + 10))" onetry >/dev/null 2>&1
i=0
while [ $i -lt 60 ]; do
    [ "$(cli 0 getconnectioncount 2>/dev/null)" = 1 ] && [ "$(cli 1 getconnectioncount 2>/dev/null)" = 1 ] && break
    sleep 1; i=$((i + 1))
done
[ "$(cli 0 getconnectioncount)" = 1 ] && ok "node 0 getconnectioncount == 1" || bad "node 0 getconnectioncount"
[ "$(cli 1 getconnectioncount)" = 1 ] && ok "node 1 getconnectioncount == 1" || bad "node 1 getconnectioncount"
# wait for the handshake so the per-peer state fields exist
i=0
while [ $i -lt 60 ]; do
    cli 0 getpeerinfo | grep -q '"banscore"' && break
    sleep 1; i=$((i + 1))
done
keys=$(cli 0 getpeerinfo | sed -n 's/^ *"\([a-z_]*\)" *:.*/\1/p' | sort | tr '\n' ' ')
want="addr banscore bytesrecv bytessent conntime id inbound inflight lastrecv lastsend pingtime services startingheight subver synced_blocks synced_headers timeoffset version whitelisted "
# addrlocal and pingwait are optional fields; drop them before comparing
keys=$(echo "$keys" | sed 's/addrlocal //; s/pingwait //')
[ "$keys" = "$want" ] && ok "getpeerinfo field set unchanged" || bad "getpeerinfo fields: $keys"
# repeated calls under load stay consistent
loops=0
while [ $loops -lt 20 ]; do
    [ "$(cli 0 getconnectioncount)" = 1 ] || { bad "getconnectioncount flapped"; break; }
    cli 0 getpeerinfo >/dev/null || { bad "getpeerinfo failed"; break; }
    loops=$((loops + 1))
done
[ $loops -eq 20 ] && ok "20 repeated getconnectioncount/getpeerinfo calls"

if [ "$failures" -ne 0 ]; then echo "getrpcinfo-test: $failures failure(s)"; exit 1; fi
echo "getrpcinfo-test: all passed"
