#!/bin/sh
# TEST-ONLY. -blocknotify must fire once per block that the init-time replay connects.
#
# kill -9 right after mining: the block files and the block index reach the disk
# but the chain state does not, so after the restart ActivateBestChain (run in RPC
# warmup) replays the missing blocks. The replay connects blocks in batches; once the
# node is out of initial block download every block must still produce its own tip
# notification (-blocknotify, ZMQ hashblock), as on a node that is not replaying.
#
# usage: sh qa/rpc-tests/replay_blocknotify.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--port-base <n>]
set -u
bin=""; work=""; base=51400
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        *) echo "replay-test: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: replay_blocknotify.sh --bin <dir> --work <dir> [--port-base <n>]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "replay-test: $work is not empty" >&2; exit 2; }

dd=$work/node
notify=$work/notify.log
mkdir -p "$dd/regtest"
printf 'rpcuser=rp\nrpcpassword=rp%s\nrpcport=%s\n' "$$" "$((base + 1))" >"$dd/zclassic.conf"
cli() { "$bin/zclassic-cli" -regtest -datadir="$dd" "$@"; }
failures=0
ok() { echo "replay-test: PASS $*"; }
bad() { echo "replay-test: FAIL $*"; failures=$((failures + 1)); }
start() {
    "$bin/zclassicd" -regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -rpcbind=127.0.0.1 \
        -rpcallowip=127.0.0.1 -debuglogfile=1 -printtoconsole=0 -showmetrics=0 -bootstrap=0 \
        -datadir="$dd" -port=$base -listen=1 -connect=0 -dbcache=450 \
        "-blocknotify=echo %s >> $notify" -daemon >/dev/null 2>&1 || return 1
    i=0
    while [ $i -lt 120 ]; do cli getblockcount >/dev/null 2>&1 && return 0; sleep 1; i=$((i + 1)); done
    return 1
}
log=$dd/regtest/debug.log
pidf=$dd/regtest/zclassicd.pid

stop() {
    cli stop >/dev/null 2>&1
    i=0; while [ $i -lt 60 ] && [ -f "$pidf" ]; do sleep 1; i=$((i + 1)); done
}

start || { echo "replay-test: node did not start"; tail -5 "$log" 2>/dev/null; exit 1; }
cli generate 10 >/dev/null || { echo "replay-test: generate failed"; stop; exit 1; }
stop
# The chain state as it was at height 10 ...
cp -R "$dd/regtest/chainstate" "$work/chainstate.h10" || exit 1
start || { echo "replay-test: node did not restart"; exit 1; }
N=40
cli generate $((N - 10)) >/dev/null || { echo "replay-test: generate failed"; stop; exit 1; }
tip=$(cli getbestblockhash)
[ "$(cli getblockcount)" -eq "$N" ] || bad "expected height $N"
stop
# ... under the block files and block index of height 40: what a crash leaves behind.
rm -rf "$dd/regtest/chainstate" && cp -R "$work/chainstate.h10" "$dd/regtest/chainstate" || exit 1
: >"$notify"
mark=$(wc -l <"$log")

start || { echo "replay-test: node did not restart"; tail -5 "$log"; exit 1; }
[ "$(cli getbestblockhash)" = "$tip" ] && ok "tip restored after the crash" || bad "tip differs after the restart"

replayed=$(tail -n +$((mark + 1)) "$log" | grep -c "UpdateTip: new best=")
got=$(wc -l <"$notify")
echo "replay-test: blocks connected after the restart: $replayed, notifications: $got"
if [ "$replayed" -lt 2 ]; then
    echo "replay-test: SKIP the chain state was flushed, nothing was replayed"
elif [ "$got" -eq "$replayed" ]; then
    ok "one -blocknotify per replayed block ($got)"
else
    bad "$replayed blocks were replayed but $got notifications were sent"
fi
[ "$replayed" -lt 2 ] || grep -q "^${tip}$" "$notify" || bad "the tip hash was never notified"

cli stop >/dev/null 2>&1
i=0; while [ $i -lt 60 ] && [ -f "$pidf" ]; do sleep 1; i=$((i + 1)); done
[ "$failures" -eq 0 ] && { echo "replay-test: ALL PASS"; exit 0; }
echo "replay-test: $failures FAILED"; exit 1
