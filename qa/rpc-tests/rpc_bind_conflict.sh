#!/bin/sh
# TEST-ONLY. A second zclassicd whose RPC port is already taken must refuse to start (exit non-zero,
# clear error), and the first daemon must keep serving. Regression: with the default bind set (no
# -rpcallowip, so ::1 and 127.0.0.1) the daemon used to log "Binding RPC on address ... failed" and
# keep running without a usable RPC server when only one of the two endpoints could be bound.
#
# usage: sh qa/rpc-tests/rpc_bind_conflict.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--port-base <n>]
set -u
bin=""; work=""; base=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        *) echo "rpc-bind-test: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: rpc_bind_conflict.sh --bin <dir> --work <dir> [--port-base <n>]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "rpc-bind-test: $work is not empty" >&2; exit 2; }

# four consecutive free ports: a p2p and an rpc port per daemon
port_free() { ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -q "[:.]$1\$"; }
if [ -z "$base" ]; then
    base=$((20000 + $$ % 20000))
    n=0
    while [ $n -lt 200 ]; do
        ok=1; p=$base
        while [ $p -lt $((base + 4)) ]; do port_free $p || ok=0; p=$((p + 1)); done
        [ $ok = 1 ] && break
        base=$((base + 7)); n=$((n + 1))
    done
fi
pa=$base; ra=$((base + 1)); pb=$((base + 2))

da=$work/a; db=$work/b
mkdir -p "$da" "$db"
printf 'rpcuser=bind\nrpcpassword=bind%s\nrpcport=%s\n' "$$" "$ra" >"$da/zclassic.conf"
cp "$da/zclassic.conf" "$db/zclassic.conf"   # same rpcport: the conflict
flags="-regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -showmetrics=0 -bootstrap=0 -listen=0 -connect=0 -debuglogfile=1"
clia() { "$bin/zclassic-cli" -regtest -datadir="$da" "$@"; }
failures=0
ok() { echo "rpc-bind-test: PASS $*"; }
bad() { echo "rpc-bind-test: FAIL $*"; failures=$((failures + 1)); }
cleanup() { clia stop >/dev/null 2>&1; [ -n "${bpid:-}" ] && kill "$bpid" 2>/dev/null; }
trap cleanup EXIT INT TERM

# no -rpcallowip / -rpcbind: the default bind set
"$bin/zclassicd" $flags -datadir="$da" -port=$pa -daemon >/dev/null 2>&1 || { echo "rpc-bind-test: first daemon did not launch"; exit 1; }
i=0; up=0
while [ $i -lt 120 ]; do clia getblockcount >/dev/null 2>&1 && { up=1; break; }; sleep 1; i=$((i + 1)); done
[ $up = 1 ] || { echo "rpc-bind-test: first daemon did not start"; exit 1; }
ok "first daemon serves RPC on port $ra"

"$bin/zclassicd" $flags -datadir="$db" -port=$pb -printtoconsole=0 >"$work/b.out" 2>&1 &
bpid=$!
i=0
while [ $i -lt 60 ] && kill -0 "$bpid" 2>/dev/null; do sleep 1; i=$((i + 1)); done
if kill -0 "$bpid" 2>/dev/null; then
    bad "second daemon still running after 60 s with the RPC port taken"
    kill "$bpid" 2>/dev/null
    wait "$bpid" 2>/dev/null
else
    wait "$bpid"; rc=$?
    [ "$rc" -ne 0 ] && ok "second daemon exited with status $rc after $i s" || bad "second daemon exited 0"
fi
bpid=""
if grep -q "Unable to bind to RPC port $ra" "$work/b.out" "$db/regtest/debug.log" 2>/dev/null; then
    ok "output or debug.log names the RPC port that could not be bound"
else
    bad "no 'Unable to bind to RPC port $ra' message"; cat "$work/b.out"
fi
grep -q "Unable to start HTTP server" "$work/b.out" "$db/regtest/debug.log" 2>/dev/null \
    && ok "start-up error names the HTTP server" || bad "no 'Unable to start HTTP server' message"

n=$(clia getblockcount 2>&1)
[ "$n" = "0" ] && ok "first daemon unaffected (getblockcount $n)" || bad "first daemon not answering: $n"

clia stop >/dev/null 2>&1
i=0
while [ $i -lt 60 ] && [ -f "$da/regtest/zclassicd.pid" ]; do sleep 1; i=$((i + 1)); done
[ ! -f "$da/regtest/zclassicd.pid" ] && ok "first daemon stopped" || bad "first daemon did not stop"

# Second scenario: a foreign program holds only 127.0.0.1:<port>, so ::1 binds but the address clients
# use does not. The daemon used to keep running with an RPC server nobody could reach.
if command -v nc >/dev/null 2>&1; then
    rc_port=$((ra + 100))
    nc -l 127.0.0.1 "$rc_port" >/dev/null 2>&1 &
    ncpid=$!
    sleep 1
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q "^127.0.0.1:$rc_port\$"; then
        dc=$work/c; mkdir -p "$dc"
        printf 'rpcuser=bind\nrpcpassword=bind%s\nrpcport=%s\n' "$$" "$rc_port" >"$dc/zclassic.conf"
        "$bin/zclassicd" $flags -datadir="$dc" -port=$((pb + 1)) -printtoconsole=0 >"$work/c.out" 2>&1 &
        bpid=$!
        i=0
        while [ $i -lt 60 ] && kill -0 "$bpid" 2>/dev/null; do sleep 1; i=$((i + 1)); done
        if kill -0 "$bpid" 2>/dev/null; then
            bad "daemon still running with 127.0.0.1:$rc_port taken (partial bind)"
            kill "$bpid" 2>/dev/null
            wait "$bpid" 2>/dev/null
        else
            wait "$bpid"; rc=$?
            [ "$rc" -ne 0 ] && grep -q "Unable to bind to RPC port $rc_port" "$work/c.out" \
                && ok "partial bind refused (status $rc)" || bad "partial bind: status $rc, output: $(cat "$work/c.out")"
        fi
        bpid=""
    else
        echo "rpc-bind-test: SKIP partial-bind scenario (nc did not listen on 127.0.0.1)"
    fi
    kill "$ncpid" 2>/dev/null
else
    echo "rpc-bind-test: SKIP partial-bind scenario (no nc)"
fi
[ $failures -eq 0 ] && { echo "rpc-bind-test: all passed"; exit 0; }
echo "rpc-bind-test: $failures failure(s)"; exit 1
