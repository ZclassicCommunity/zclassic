#!/bin/sh
# Fail-soft embedded Tor: killing the Tor child must cost only the onion side.
#
# A regtest node runs with -embeddedtor=1 -embeddedtormode=child and gets its onion service. The
# Tor child is killed with SIGKILL. The node must keep answering RPC (getblockcount every 2 s for
# 60 s), getnetworkinfo torstatus must go to "restarting" and back to "running" within 120 s, and
# the same onion address must be advertised again (the service is re-created from the cached key
# on the restarted Tor's new control port). Before fail-soft the node shut itself down here.
# Prints the time from the kill to the onion address being advertised again.
#
# Tor needs outbound network to bootstrap, but the onion address is advertised once ADD_ONION
# succeeds, which does not wait for that. Skips (exit 0) when the binary has no embedded Tor.
#
# usage: sh qa/rpc-tests/tor_restart.sh --bin <dir with zclassicd, zclassic-cli> --work <empty dir>
#            [--base <port>]
set -u
bin=""; work=""; base=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --base) base=$2; shift 2 ;;
        *) echo "tor-restart: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: tor_restart.sh --bin <dir> --work <dir> [--base <port>]" >&2; exit 2; }
if ! "$bin/zclassicd" -help 2>/dev/null | grep -q -- '-embeddedtormode'; then
    echo "tor-restart: SKIP $bin/zclassicd was built without embedded Tor"; exit 0
fi
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "tor-restart: $work is not empty" >&2; exit 2; }

. "$(dirname "$0")/../lib/isolation.sh"
iso_base base "$base" 4
p2p=$base; rpc=$((base + 2))   # p2p + 1 is the onion-service listener

dd=$work/node; mkdir -p "$dd"
printf 'rpcuser=tor\nrpcpassword=tor%s\nrpcport=%s\n' "$$" "$rpc" >"$dd/zclassic.conf"
flags="-regtest -embeddedtor=1 -embeddedtormode=child -listen=1 -bind=127.0.0.1 -port=$p2p -connect=0
 -dnsseed=0 -upnp=0 -discover=0 -showmetrics=0 -bootstrap=0 -debug=tor -debuglogfile=1"
cli() { "$bin/zclassic-cli" -regtest -datadir="$dd" -rpcclienttimeout=10 "$@"; }
failures=0
ok() { echo "tor-restart: PASS $*"; }
bad() { echo "tor-restart: FAIL $*"; failures=$((failures + 1)); }
node_pid() { cat "$dd/regtest/zclassicd.pid" 2>/dev/null; }
onion() { cli getnetworkinfo 2>/dev/null | grep -o '[a-z2-7]\{56\}\.onion' | head -1; }
torstatus() { cli getnetworkinfo 2>/dev/null | sed -n 's/.*"torstatus": *"\([^"]*\)".*/\1/p'; }
tor_child() { ps -eo pid=,ppid=,args= | awk -v p="$1" '$2 == p && /--zcl-embedded-tor/ { print $1 }' | head -1; }
cleanup() { cli stop >/dev/null 2>&1; sleep 2; [ -n "${ISO_PID:-}" ] && kill_node "$ISO_PID"; }
trap cleanup EXIT INT TERM

start_node "$work/node.out" "$bin/zclassicd" $flags -datadir="$dd"
i=0
while [ $i -lt 120 ]; do cli getblockcount >/dev/null 2>&1 && break; sleep 1; i=$((i + 1)); done
cli getblockcount >/dev/null 2>&1 || { echo "tor-restart: node did not start: $(tail -3 "$work/node.out")"; exit 1; }
npid=$(node_pid)
i=0; addr1=""
while [ $i -lt 120 ] && [ -z "$addr1" ]; do addr1=$(onion); [ -n "$addr1" ] || sleep 1; i=$((i + 1)); done
[ -n "$addr1" ] && ok "onion service advertised" || { bad "no onion address in getnetworkinfo after 120 s"; exit 1; }
[ "$(torstatus)" = running ] && ok "torstatus running" || bad "torstatus is '$(torstatus)', wanted running"
tpid=$(tor_child "$npid")
[ -n "$tpid" ] || { bad "no Tor child under zclassicd pid $npid"; exit 1; }

# Kill the Tor child. The node must keep serving through it.
kill -9 "$tpid"
t0=$(date +%s)
seen_restarting=0; back=""; misses=0; n=0
while [ $n -lt 30 ]; do
    cli getblockcount >/dev/null 2>&1 || misses=$((misses + 1))
    s=$(torstatus)
    [ "$s" = restarting ] && seen_restarting=1
    if [ -z "$back" ] && [ "$seen_restarting" = 1 ] && [ "$s" = running ] && [ -n "$(onion)" ]; then
        back=$(( $(date +%s) - t0 ))
    fi
    sleep 2; n=$((n + 1))
done
kill -0 "$npid" 2>/dev/null && [ "$misses" = 0 ] && ok "node answered getblockcount every 2 s for 60 s after the kill" \
    || bad "node missed $misses of 30 getblockcount calls (alive: $(kill -0 "$npid" 2>/dev/null && echo yes || echo no))"
[ "$seen_restarting" = 1 ] && ok "torstatus went to restarting" || bad "torstatus never showed restarting"
while [ -z "$back" ] && [ $(( $(date +%s) - t0 )) -lt 120 ]; do # real-clock: the 120 s limit is the spec
    [ "$(torstatus)" = running ] && [ -n "$(onion)" ] && back=$(( $(date +%s) - t0 )) || sleep 1
done
[ -n "$back" ] && ok "Tor running and onion advertised again ${back}s after the kill" \
    || bad "Tor not back within 120 s (torstatus '$(torstatus)')"
addr2=$(onion)
[ -n "$addr2" ] && [ "$addr2" = "$addr1" ] && ok "same onion address after the restart" \
    || bad "onion address changed or missing after the restart"
tpid2=$(tor_child "$npid")
[ -n "$tpid2" ] && [ "$tpid2" != "$tpid" ] && ok "a new Tor child runs" || bad "no new Tor child (old $tpid, now '$tpid2')"
log=$dd/regtest/debug.log
grep -q 'embedded Tor stopped (fault=exited); restarting in' "$log" && ok "one restart line with a fault token" \
    || bad "no 'embedded Tor stopped (fault=...)' line in debug.log"
grep -q 'shutting down' "$log" && bad "debug.log says shutting down" || ok "no shutdown requested"
[ -n "$back" ] && echo "tor-restart: time to onion restored ${back}s"

cli stop >/dev/null 2>&1
i=0; while kill -0 "$npid" 2>/dev/null && [ $i -lt 60 ]; do sleep 1; i=$((i + 1)); done
kill -0 "$npid" 2>/dev/null && bad "node did not stop within 60 s" || ok "node stopped"
ps -eo args= | grep -v grep | grep -q -- "--zcl-embedded-tor.*$dd/regtest/tor" && bad "Tor child left behind" || ok "no Tor child left behind"
echo "tor-restart: $failures failure(s)"
[ "$failures" = 0 ]
