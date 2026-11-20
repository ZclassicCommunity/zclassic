#!/bin/sh
# TEST-ONLY. Startup against a real regtest daemon:
#  1. bind=<addr>=onion in zclassic.conf (the file is read once, so the address is
#     bound once and the node comes up; it used to fail with "Unable to bind"
#     because every repeatable option from the file was added twice);
#  2. a partial snapshot kept for resume (bootstrap-peer-staging-*) is removed at
#     startup when -bootstrap=0 turns bootstrap off, and kept when it is on.
#
# usage: sh qa/rpc-tests/startup_conf_staging.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--port-base <n>]
set -u
bin=""; work=""; base=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        *) echo "startup-test: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: startup_conf_staging.sh --bin <dir> --work <dir> [--port-base <n>]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
. "$(dirname "$0")/../lib/isolation.sh"
iso_base base "$base" 16
[ -z "$(ls -A "$work")" ] || { echo "startup-test: $work is not empty" >&2; exit 2; }

dd=$work/node
mkdir -p "$dd/regtest"
onionport=$((base + 2))
printf 'rpcuser=st\nrpcpassword=st%s\nrpcport=%s\nbind=127.0.0.1:%s=onion\n' "$$" "$((base + 1))" "$onionport" >"$dd/zclassic.conf"
cli() { "$bin/zclassic-cli" -regtest -datadir="$dd" "$@"; }
failures=0
ok() { echo "startup-test: PASS $*"; }
bad() { echo "startup-test: FAIL $*"; failures=$((failures + 1)); }
start() { # [extra args]
    "$bin/zclassicd" -regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -rpcbind=127.0.0.1 \
        -rpcallowip=127.0.0.1 -debuglogfile=1 -printtoconsole=0 -showmetrics=0 \
        -datadir="$dd" -port=$base -listen=1 -connect=0 "$@" -daemon >/dev/null 2>&1 || return 1
    i=0
    while [ $i -lt 120 ]; do cli getblockcount >/dev/null 2>&1 && return 0; sleep 1; i=$((i + 1)); done
    return 1
}
stop() {
    cli stop >/dev/null 2>&1
    i=0
    while [ $i -lt 60 ] && [ -f "$dd/regtest/zclassicd.pid" ]; do sleep 1; i=$((i + 1)); done
}
log=$dd/regtest/debug.log

# 1. the onion listener from the conf file
start -bootstrap=0 || { echo "startup-test: node did not start with bind=...=onion in the conf file"; tail -5 "$log" 2>/dev/null; exit 1; }
ok "node started with bind=127.0.0.1:$onionport=onion in zclassic.conf"
n=$(grep -c "Onion service target: 127.0.0.1:$onionport" "$log")
[ "$n" -eq 1 ] && ok "the onion listener was set up once" || bad "onion service target logged $n times"
grep -q "Unable to bind" "$log" && bad "a bind error was logged" || ok "no bind error in the log"
stop

# 2. a kept partial snapshot and -bootstrap=0
stage=$dd/regtest/bootstrap-peer-staging-deadbeef
mkdir -p "$stage/blocks" && echo partial >"$stage/blocks/x"
start -bootstrap=0 || { echo "startup-test: node did not start (2)"; exit 1; }
[ ! -e "$stage" ] && ok "-bootstrap=0 removed the kept partial snapshot" || bad "kept partial snapshot still there with -bootstrap=0"
stop

# the same directory is left alone while bootstrap is on and has nothing to do for it:
# a regtest node has no snapshot anchor, so the datadir is not touched
mkdir -p "$stage/blocks" && echo partial >"$stage/blocks/x"
start || { echo "startup-test: node did not start (3)"; exit 1; }
[ -e "$stage/blocks/x" ] && ok "bootstrap enabled: the kept partial snapshot is not removed" || bad "kept partial snapshot removed while bootstrap is enabled"
stop

[ "$failures" -eq 0 ] && { echo "startup-test: ALL PASSED"; exit 0; }
echo "startup-test: $failures FAILED"
exit 1
