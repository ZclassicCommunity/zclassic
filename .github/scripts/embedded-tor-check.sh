#!/bin/sh
# Bounded embedded-Tor check for a release candidate.
#
# usage: embedded-tor-check.sh <dir with zclassicd, zclassic-cli> <empty work dir> [wait-seconds]
#
# Starts zclassicd -regtest -embeddedtor=1 in a fresh temp datadir (loopback
# only, ports chosen at random), waits up to wait-seconds (default 240) for
# getnetworkinfo to list an .onion local address, then stops the node and
# fails if any process of it is left. Exit 0 only when the onion address
# appeared and the node exited cleanly.
set -u
bin=${1:-}; work=${2:-}; limit=${3:-240}
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: embedded-tor-check.sh <bin dir> <work dir> [seconds]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "embedded-tor-check: $work is not empty" >&2; exit 2; }

p2p=$((20000 + $$ % 20000)); rpc=$((p2p + 1))
cat > "$work/zclassic.conf" <<CONF
regtest=1
server=1
rpcuser=torcheck
rpcpassword=torcheck$$
rpcport=$rpc
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
port=$p2p
bind=127.0.0.1
listen=1
dnsseed=0
bootstrap=0
upnp=0
embeddedtor=1
debug=tor
debuglogfile=1
CONF
cli() { "$bin/zclassic-cli" -datadir="$work" "$@" 2>&1; }

"$bin/zclassicd" -datadir="$work" -printtoconsole=0 >"$work/stdout.log" 2>&1 &
pid=$!
dump_logs() {
    for f in "$work"/regtest/debug.log "$work"/regtest/tor/tor.log "$work"/regtest/tor/tor-child.log "$work/stdout.log"; do
        [ -f "$f" ] && { echo "---- $f (tail)"; tail -n 60 "$f"; }
    done
}
finish() { # <rc>
    cli stop >/dev/null
    i=0
    while [ $i -lt 90 ] && kill -0 "$pid" 2>/dev/null; do sleep 1; i=$((i + 1)); done
    if kill -0 "$pid" 2>/dev/null; then
        echo "embedded-tor-check: node did not stop in 90s, killing"; kill "$pid"; sleep 3
        kill -9 "$pid" 2>/dev/null
        [ "$1" -eq 0 ] && set -- 1
    fi
    wait "$pid" 2>/dev/null
    left=$(ps -axo pid=,command= | grep -F "$work" | grep -v grep | grep -vF "embedded-tor-check.sh" || true)
    if [ -n "$left" ]; then echo "embedded-tor-check: processes left over:"; echo "$left"; set -- 1; fi
    exit "$1"
}

onion=""; elapsed=0
while [ $elapsed -lt "$limit" ]; do
    kill -0 "$pid" 2>/dev/null || { echo "embedded-tor-check: zclassicd exited early"; dump_logs; exit 1; }
    onion=$(cli getnetworkinfo | tr -d ' ",' | awk -F: '/^address:.*\.onion$/ { print $2; exit }')
    [ -n "$onion" ] && break
    sleep 5; elapsed=$((elapsed + 5))
done
if [ -z "$onion" ]; then
    echo "embedded-tor-check: FAIL no onion local address within ${limit}s"
    dump_logs; finish 1
fi
echo "embedded-tor-check: PASS onion local address after ${elapsed}s: $onion"
finish 0
