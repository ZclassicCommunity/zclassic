#!/bin/sh
# TEST-ONLY. banlist.dat: bans set with setban survive a restart, removals are persisted,
# and a damaged banlist.dat is set aside instead of stopping the node. One regtest node.
#
# usage: sh qa/rpc-tests/banlist_persist.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--port-base <n>]
set -u
bin=""; work=""; base=52300
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        *) echo "banlist-persist: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: banlist_persist.sh --bin <dir> --work <dir> [--port-base <n>]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "banlist-persist: $work is not empty" >&2; exit 2; }

failures=0
ok() { echo "banlist-persist: PASS $*"; }
bad() { echo "banlist-persist: FAIL $*"; failures=$((failures + 1)); }
dir="$work/node"
mkdir -p "$dir"
printf 'rpcuser=bp\nrpcpassword=bp%s\nrpcport=%s\n' "$$" "$((base + 1))" >"$dir/zclassic.conf"
cli() { "$bin/zclassic-cli" -regtest -datadir="$dir" "$@"; }
start() {
    "$bin/zclassicd" -regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 \
        -rpcallowip=127.0.0.1 -debuglogfile=1 -printtoconsole=0 -showmetrics=0 -bootstrap=0 \
        -datadir="$dir" -port=$base -listen=1 -connect=0 "$@" -daemon >/dev/null 2>&1 || return 1
    i=0
    while [ $i -lt 600 ]; do cli getblockcount >/dev/null 2>&1 && return 0; sleep 1; i=$((i + 1)); done
    return 1
}
stop() {
    cli stop >/dev/null 2>&1
    i=0
    while [ $i -lt 60 ] && [ -f "$dir/regtest/zclassicd.pid" ]; do sleep 1; i=$((i + 1)); done
}
trap stop EXIT
banned() { cli listbanned | tr -d ' \n'; }

start || { echo "banlist-persist: node did not start"; exit 1; }
[ "$(banned)" = "[]" ] && ok "fresh node has no bans" || bad "fresh node bans: $(banned)"

cli setban 192.0.2.1 add 86400 >/dev/null || bad "setban host"
cli setban 198.51.100.0/24 add >/dev/null || bad "setban subnet"
list=$(banned)
echo "$list" | grep -q '"address":"192.0.2.1/' && echo "$list" | grep -q '"address":"198.51.100.0/' \
    && ok "both bans listed" || bad "bans not listed: $list"

# the scheduler writes within seconds, no shutdown needed
i=0; while [ $i -lt 20 ] && [ ! -f "$dir/regtest/banlist.dat" ]; do sleep 1; i=$((i + 1)); done
[ -f "$dir/regtest/banlist.dat" ] && ok "banlist.dat written while running" || bad "no banlist.dat after 20 s"

stop
start || { echo "banlist-persist: restart 1 failed"; exit 1; }
list=$(banned)
echo "$list" | grep -q '"address":"192.0.2.1/' && echo "$list" | grep -q '"address":"198.51.100.0/' \
    && ok "both bans survive a restart" || bad "bans lost on restart: $list"
echo "$list" | tr ',' '\n' | grep -A1 '192.0.2.1/' | grep -q '"banned_until":' && ok "ban time kept" || bad "ban time missing"

cli setban 192.0.2.1 remove >/dev/null || bad "setban remove"
stop
start || { echo "banlist-persist: restart 2 failed"; exit 1; }
list=$(banned)
echo "$list" | grep -q '192.0.2.1' && bad "removed ban came back: $list" || ok "removed ban stays removed"
echo "$list" | grep -q '"address":"198.51.100.0/' && ok "other ban kept" || bad "other ban lost: $list"

# a damaged file is set aside and the node still starts, with an empty list
stop
printf 'not a ban list' >"$dir/regtest/banlist.dat"
start || { echo "banlist-persist: node refused to start with a damaged banlist.dat"; exit 1; }
[ "$(banned)" = "[]" ] && ok "damaged banlist.dat gives an empty list" || bad "damaged file bans: $(banned)"
[ -f "$dir/regtest/banlist.dat.bad" ] && ok "damaged file kept as banlist.dat.bad" || bad "no banlist.dat.bad"

if [ "$failures" -ne 0 ]; then echo "banlist-persist: $failures failure(s)"; exit 1; fi
echo "banlist-persist: all passed"
