#!/bin/sh
# A node that has been at the tip longer than -dbflushinterval and is hard-killed must restart
# within one interval's worth of blocks of its pre-kill height.
#
# Without a periodic flush at the tip, the block index entries and the coins of every block since
# the node started live only in memory (the block index was written once an hour, the coins once a
# day or when the cache filled): a kill -9 after 40 or 80 minutes brought the node back at its
# start-up height and it had to fetch all those blocks from its peers again.
#
# Cases (regtest, -testblockindexinterval is set huge so only the flush interval can write):
#   interval 5 s : mine, wait past the interval, mine one block (the flush runs after it), mine
#                  three more inside the interval, kill -9. The restart must be at the block mined
#                  after the wait or later, and verifychain must pass and a new block be accepted.
#   interval 0   : the legacy once-a-day cadence, same steps. The restart is back at the start-up
#                  height (the control that shows the steps would lose blocks without the interval).
#   interval 5 s again with -dbflushinterval given a bad value (-3, 999999999) : clamps to the
#                  legacy interval, still starts and runs.
#
# usage: chain_flush_interval_kill.sh --bin <dir> --work <dir> [--base port]
# Needs the Zcash parameters in ~/.zcash-params. Shell only, no Python.
B=""; W=""; P=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) B=$2; shift 2 ;; --work) W=$2; shift 2 ;; --base) P=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$B/zclassicd" ] && [ -n "$W" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
. "$(dirname "$0")/../lib/isolation.sh"
iso_base P "$P" 16; R=0; F=0
rm -rf "$W"; mkdir -p "$W"; W=$(cd "$W" && pwd)
trap '[ -f "$D/pid" ] && kill -9 "$(cat "$D/pid")" 2>/dev/null' EXIT
A0="-regtest -server=1 -listen=0 -showmetrics=0 -debuglogfile=1 -keypool=5 -nuparams=5ba81b19:1 -nuparams=76b809bb:1 -experimentalfeatures -rpcport=$P -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -dnsseed=0 -discover=0 -listenonion=0 -testblockindexinterval=100000 -testsetchaininterval=100000"
cli() { "$B/zclassic-cli" -regtest -datadir="$D" -rpcport=$P -rpcuser=u -rpcpassword=p "$@"; }
st() { rm -f "$D/regtest/.lock"; $ZCL_RUN "$B/zclassicd" $A0 -datadir="$D" "$@" >> "$D/out.log" 2>&1 & echo $! > "$D/pid"
    for k in $(seq 600); do cli getblockcount >/dev/null 2>&1 && return 0; kill -0 "$(cat "$D/pid")" 2>/dev/null || return 1; sleep 0.1; done; return 1; }
sp() { cli stop >/dev/null 2>&1; while kill -0 "$(cat "$D/pid")" 2>/dev/null; do sleep 0.2; done; }
hardkill() { kill -9 "$(cat "$D/pid")" 2>/dev/null; while kill -0 "$(cat "$D/pid")" 2>/dev/null; do sleep 0.1; done; }

# run <label> <flush option> <expect>  where expect is "kept" (restart at the flushed height or later) or "lost"
run() {
    i=$((i + 1)); D=$W/it$i; mkdir -p "$D"; : > "$D/out.log"
    printf "rpcuser=u\nrpcpassword=p\n" > "$D/zclassic.conf"
    st $2 || { echo "FAIL $1: start failed: $(grep -m1 -i 'assert\|error' "$D/out.log" | cut -c1-150)"; F=$((F + 1)); return; }
    cli generate 30 >/dev/null
    sleep 7
    cli generate 1 >/dev/null; HF=$(cli getblockcount)      # the flush after this block is the durable height
    cli generate 3 >/dev/null; HK=$(cli getblockcount)      # inside the interval: may be lost
    hardkill
    : > "$D/out.log"
    if ! st $2; then echo "FAIL $1: restart failed: $(grep -m1 -i 'assert\|error' "$D/out.log" | cut -c1-150)"; F=$((F + 1)); return; fi
    HR=$(cli getblockcount); v=$(cli verifychain 4 0)
    cli generate 1 >/dev/null 2>&1; h2=$(cli getblockcount)
    if [ "$3" = kept ]; then
        if [ "$HR" -ge "$HF" ] && [ "$HR" -le "$HK" ] && [ $((HK - HR)) -le 3 ] && [ "$v" = true ] && [ "$h2" = $((HR + 1)) ]; then
            echo "ok   $1: killed at $HK, restarted at $HR (flushed height $HF), chain verifies, new block accepted"; R=$((R + 1))
        else echo "FAIL $1: killed at $HK, flushed $HF, restarted at $HR, verifychain $v, after mining $h2"; F=$((F + 1)); fi
    else
        if [ "$HR" -lt "$HF" ] && [ "$v" = true ] && [ "$h2" = $((HR + 1)) ]; then
            echo "ok   $1: killed at $HK, restarted at $HR (before $HF): without the interval the blocks are lost, as before"; R=$((R + 1))
        else echo "FAIL $1: control did not lose the blocks: killed at $HK, flushed $HF, restarted at $HR, verifychain $v"; F=$((F + 1)); fi
    fi
    sp
}
i=0
run "interval 5 s" "-dbflushinterval=5" kept
run "interval 0 (legacy 24 h)" "-dbflushinterval=0" lost
run "interval 1 s" "-dbflushinterval=1" kept
# values outside the range clamp to the legacy interval: same as the control
run "interval -3 (clamped)" "-dbflushinterval=-3" lost
run "interval 999999999 (clamped)" "-dbflushinterval=999999999" lost
echo "flush-interval-kill: $R ok, $F fail"
[ "$F" = 0 ] && [ "$R" -gt 0 ]
