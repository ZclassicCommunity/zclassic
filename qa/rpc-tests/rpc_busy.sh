#!/bin/sh
# TEST-ONLY. A full RPC work queue must answer HTTP 503 with a JSON-RPC body that names -rpcthreads and
# -rpcworkqueue, and log one rate-limited line. Out-of-range -rpcthreads must stop start-up with a message
# that names the option and its range (values used to be clamped silently).
#
# usage: sh qa/rpc-tests/rpc_busy.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--port-base <n>]
set -u
bin=""; work=""; base=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        *) echo "rpc-busy-test: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: rpc_busy.sh --bin <dir> --work <dir> [--port-base <n>]" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "rpc-busy-test: SKIP (no curl)"; exit 0; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "rpc-busy-test: $work is not empty" >&2; exit 2; }

port_free() { ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -q "[:.]$1\$"; }
if [ -z "$base" ]; then
    base=$((20000 + $$ % 20000))
    n=0
    while [ $n -lt 200 ]; do
        ok=1; p=$base
        while [ $p -lt $((base + 2)) ]; do port_free $p || ok=0; p=$((p + 1)); done
        [ $ok = 1 ] && break
        base=$((base + 7)); n=$((n + 1))
    done
fi
pp=$base; rp=$((base + 1))

da=$work/a; mkdir -p "$da"
user=busy; pass=busy$$
printf 'rpcuser=%s\nrpcpassword=%s\nrpcport=%s\n' "$user" "$pass" "$rp" >"$da/zclassic.conf"
flags="-regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -showmetrics=0 -bootstrap=0 -listen=0 -connect=0 -debuglogfile=1 -disablewallet=1"
clia() { "$bin/zclassic-cli" -regtest -datadir="$da" "$@"; }
failures=0
ok() { echo "rpc-busy-test: PASS $*"; }
bad() { echo "rpc-busy-test: FAIL $*"; failures=$((failures + 1)); }
cleanup() { clia stop >/dev/null 2>&1; }
trap cleanup EXIT INT TERM

# Scenario 1: one worker and a queue of one, so a burst of concurrent calls overflows the queue
"$bin/zclassicd" $flags -datadir="$da" -port=$pp -rpcthreads=1 -rpcworkqueue=1 -daemon >/dev/null 2>&1 \
    || { echo "rpc-busy-test: daemon did not launch"; exit 1; }
i=0; up=0
while [ $i -lt 300 ]; do clia getblockcount >/dev/null 2>&1 && { up=1; break; }; sleep 1; i=$((i + 1)); done
[ $up = 1 ] || { echo "rpc-busy-test: daemon did not start"; exit 1; }
ok "daemon serves RPC on port $rp with -rpcthreads=1 -rpcworkqueue=1"

body='{"jsonrpc":"1.0","id":"busy","method":"gettxoutsetinfo","params":[]}'
got503=0; attempt=0
while [ $attempt -lt 5 ] && [ $got503 = 0 ]; do
    attempt=$((attempt + 1))
    k=1
    while [ $k -le 20 ]; do
        curl -s -m 60 -u "$user:$pass" -H 'content-type: text/plain;' --data-binary "$body" \
            -o "$work/r$attempt.$k.body" -w '%{http_code}' "http://127.0.0.1:$rp/" >"$work/r$attempt.$k.code" 2>/dev/null &
        k=$((k + 1))
    done
    wait
    for f in "$work"/r$attempt.*.code; do
        [ "$(cat "$f")" = "503" ] && got503=1
    done
done

if [ $got503 = 1 ]; then
    ok "burst of 20 calls produced HTTP 503 (attempt $attempt)"
else
    bad "no HTTP 503 in $attempt burst(s) of 20 calls; codes: $(cat "$work"/r*.code | sort | uniq -c | tr '\n' ' ')"
fi

busy_body=""
for f in "$work"/r*.code; do
    b=${f%.code}.body
    if [ "$(cat "$f")" = "503" ]; then busy_body=$b; break; fi
done
if [ -n "$busy_body" ] && grep -q 'RPC server busy' "$busy_body" \
    && grep -q -- '-rpcworkqueue' "$busy_body" && grep -q -- '-rpcthreads' "$busy_body"; then
    ok "503 body is a JSON-RPC error naming -rpcworkqueue and -rpcthreads"
else
    bad "503 body missing the busy message: $(cat "$busy_body" 2>/dev/null)"
fi

if grep -q "HTTP: work queue full, rejected" "$da/regtest/debug.log" 2>/dev/null; then
    ok "debug.log has the rate-limited work queue line"
else
    bad "no 'HTTP: work queue full' line in debug.log"
fi

clia stop >/dev/null 2>&1
i=0
while [ $i -lt 60 ] && [ -f "$da/regtest/zclassicd.pid" ]; do sleep 1; i=$((i + 1)); done
[ ! -f "$da/regtest/zclassicd.pid" ] && ok "daemon stopped" || bad "daemon did not stop"

# Scenario 2: -rpcthreads=0 is refused at start-up, with the option named
db=$work/b; mkdir -p "$db"
cp "$da/zclassic.conf" "$db/zclassic.conf"
"$bin/zclassicd" $flags -datadir="$db" -port=$((pp + 100)) -rpcthreads=0 -printtoconsole=1 >"$work/b.out" 2>&1 &
bpid=$!
i=0
while [ $i -lt 60 ] && kill -0 "$bpid" 2>/dev/null; do sleep 1; i=$((i + 1)); done
if kill -0 "$bpid" 2>/dev/null; then
    bad "daemon with -rpcthreads=0 still running after 60 s"
    kill "$bpid" 2>/dev/null
    wait "$bpid" 2>/dev/null
else
    wait "$bpid"; rc=$?
    [ "$rc" -ne 0 ] && ok "-rpcthreads=0 refused at start-up (status $rc)" || bad "-rpcthreads=0 exited 0"
fi
if grep -q -- "-rpcthreads=0 is invalid: must be between 1 and 256" "$work/b.out" "$db/regtest/debug.log" 2>/dev/null; then
    ok "start-up error names -rpcthreads=0 and its range"
else
    bad "no range message for -rpcthreads=0: $(cat "$work/b.out")"
fi

[ $failures -eq 0 ] && { echo "rpc-busy-test: all passed"; exit 0; }
echo "rpc-busy-test: $failures failure(s)"; exit 1
