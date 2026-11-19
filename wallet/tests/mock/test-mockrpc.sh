#!/bin/sh
# Test for wallet/tests/mock/mockrpc.c (POSIX sh, a C23 compiler and curl).
# Builds the mock, starts it on a loopback port, and checks fixture replies, defaults,
# method-not-found, parse errors, the getwalletsummary derivation, request logging,
# path-traversal safety and /__shutdown. Only the processes it starts are ever signalled.
# usage: test-mockrpc.sh [port]   (default 18990)
set -u
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
port=${1:-18990}
cc=${CC:-cc}
work=$(mktemp -d)
pids=""
cleanup() { for p in $pids; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; fails=$((fails + 1)); }

$cc -std=c2x -O2 -Wall -Wextra -Werror -o "$work/mockrpc" "$here/mockrpc.c" || { echo "FAIL compile" >&2; exit 1; }

start() {   # <port> <scenario> [fixtures dir]; sets $last_pid
    MOCK_PORT=$1 MOCK_SCENARIO=$2 MOCK_FIXTURES=${3:-$here/fixtures} MOCK_LOG=$work/req-$1.log \
        "$work/mockrpc" 2>"$work/stderr-$1" &
    last_pid=$!
    pids="$pids $last_pid"
    i=0
    while [ $i -lt 50 ]; do
        curl -s --max-time 2 "http://127.0.0.1:$1/" 2>/dev/null | grep -q '"ok": true' && return 0
        kill -0 "$last_pid" 2>/dev/null || break
        sleep 0.1
        i=$((i + 1))
    done
    echo "FAIL mock did not come up on $1" >&2; cat "$work/stderr-$1" >&2
    exit 1
}
rpc() {   # <port> <json body>
    curl -s --max-time 5 -u user:pass -H 'content-type: text/plain;' -d "$2" "http://127.0.0.1:$1/"
}
check() {   # <name> <got> <want>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1: got '$2' want '$3'"; fi
}
contains() {   # <name> <got> <substring>
    case $2 in *"$3"*) pass "$1" ;; *) fail "$1: '$2' lacks '$3'" ;; esac
}

start "$port" funded-synced
health=$(curl -s --max-time 2 "http://127.0.0.1:$port/")
contains "health read names the scenario" "$health" '"scenario": "funded-synced"'

want="{\"result\": $(cat "$here/fixtures/funded-synced/getinfo.json"), \"error\": null, \"id\": 7}"
check "fixture reply is wrapped in the JSON-RPC envelope" "$(rpc "$port" '{"jsonrpc":"1.0","id":7,"method":"getinfo","params":[]}')" "$want"

contains "built-in default z_getnewaddress is a Sapling address" \
    "$(rpc "$port" '{"id":"a1","method":"z_getnewaddress","params":[]}')" '"result": "zs1newmockaddr'
check "default null result (importprivkey) keeps a string id" \
    "$(rpc "$port" '{"id":"a1","method":"importprivkey","params":["x"]}')" '{"result": null, "error": null, "id": "a1"}'
check "default empty array (z_getoperationstatus)" \
    "$(rpc "$port" '{"id":3,"method":"z_getoperationstatus","params":[]}')" '{"result": [], "error": null, "id": 3}'
check "unknown method is -32601" \
    "$(rpc "$port" '{"id":4,"method":"nosuchmethod","params":[]}')" \
    '{"result": null, "error": {"code": -32601, "message": "Method not found: nosuchmethod"}, "id": 4}'
contains "method name cannot escape the fixture directory" \
    "$(rpc "$port" '{"id":5,"method":"../../README","params":[]}')" '"code": -32601'
check "malformed JSON is -32700" \
    "$(rpc "$port" '{"id":6,"method":')" '{"result": null, "error": {"code": -32700, "message": "Parse error"}, "id": null}'
check "non-object JSON is -32700" \
    "$(rpc "$port" '[1,2]')" '{"result": null, "error": {"code": -32700, "message": "Parse error"}, "id": null}'

summary=$(rpc "$port" '{"id":8,"method":"getwalletsummary","params":[]}')
contains "getwalletsummary transparent" "$summary" '"transparent": "12.34500000"'
contains "getwalletsummary private" "$summary" '"private": "100.00000000"'
contains "getwalletsummary total" "$summary" '"total": "112.34500000"'
contains "getwalletsummary carries the request id" "$summary" '"id": 8}'

# Request log: one compact line per POST (nine POSTs above, malformed ones included).
lines=$(wc -l < "$work/req-$port.log" | tr -d ' ')
check "request log has one line per POST" "$lines" 9
contains "request log is compact JSON" "$(sed -n 1p "$work/req-$port.log")" '{"jsonrpc":"1.0","id":7,"method":"getinfo","params":[]}'

# A scenario without z_gettotalbalance: the old-daemon fallback stays reachable.
mkdir -p "$work/fx/empty"
start $((port + 1)) empty "$work/fx"
contains "getwalletsummary without a balance fixture is -32601" \
    "$(rpc $((port + 1)) '{"id":9,"method":"getwalletsummary","params":[]}')" '"code": -32601'

# Shutdown over HTTP and by signal.
curl -s --max-time 2 "http://127.0.0.1:$port/__shutdown" | grep -q '"stopping": true' && pass "GET /__shutdown acknowledges" || fail "GET /__shutdown"
first=$(echo $pids | cut -d' ' -f1)
i=0; while kill -0 "$first" 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$first" 2>/dev/null; then fail "mock still running after /__shutdown"; else pass "mock exits after /__shutdown"; fi
kill -TERM "$last_pid"
i=0; while kill -0 "$last_pid" 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$last_pid" 2>/dev/null; then fail "mock ignores SIGTERM"; else pass "mock exits on SIGTERM"; fi

[ "$fails" -eq 0 ] && { echo "mockrpc: all tests passed"; exit 0; }
echo "mockrpc: $fails test(s) failed" >&2
exit 1
