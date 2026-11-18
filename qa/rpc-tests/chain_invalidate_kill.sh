#!/bin/sh
# A hard kill after invalidateblock must not leave a node that needs -reindex.
#
# invalidateblock disconnects the blocks, then flags them failed. The block index was written
# (periodic write, here forced with -testblockindexinterval=1) before the coins, so a kill after
# the next new block left a block index whose failed blocks included the best block of the on-disk
# coins: at start-up every block index candidate was pruned as worse than that tip and
# PruneBlockIndexCandidates asserted. The unwind now flushes the coins to the disconnected tip
# before the flags are set and flags durably afterwards.
#
# Per case (5, 20 and 50 blocks): start, invalidate, wait, mine a block on the shorter chain (this
# writes the block index), kill -9 after a delay, restart WITHOUT -reindex. The node must start,
# keep the invalidation (the invalid chain is not the best chain) and verify its chain.
#
# usage: chain_invalidate_kill.sh --bin <dir> --work <dir> [--base port]
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
B=""; W=""; P=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) B=$2; shift 2 ;; --work) W=$2; shift 2 ;; --base) P=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$B/zclassicd" ] && [ -n "$W" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
P=${P:-$((20000 + ($$ % 20000)))}; R=0; F=0
rm -rf "$W"; mkdir -p "$W/tpl"; W=$(cd "$W" && pwd)
trap '[ -f "$D/pid" ] && kill -9 "$(cat "$D/pid")" 2>/dev/null' EXIT
printf "rpcuser=u\nrpcpassword=p\n" > "$W/tpl/zclassic.conf"
A0="-regtest -server=1 -listen=0 -showmetrics=0 -debuglogfile=1 -keypool=5 -nuparams=5ba81b19:1 -nuparams=76b809bb:1 -experimentalfeatures -rpcport=$P -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -dnsseed=0 -discover=0 -listenonion=0"
cli() { "$B/zclassic-cli" -regtest -datadir="$D" -rpcport=$P -rpcuser=u -rpcpassword=p "$@"; }
st() { rm -f "$D/regtest/.lock"; "$B/zclassicd" $A0 -datadir="$D" "$@" >> "$D/out.log" 2>&1 & echo $! > "$D/pid"
    for k in $(seq 600); do cli getblockcount >/dev/null 2>&1 && return 0; kill -0 "$(cat "$D/pid")" 2>/dev/null || return 1; sleep 0.1; done; return 1; }
sp() { cli stop >/dev/null 2>&1; while kill -0 "$(cat "$D/pid")" 2>/dev/null; do sleep 0.2; done; }
D=$W/tpl; st || { echo "template start failed"; exit 1; }
cli generate 120 >/dev/null
for i in 1 2 3 4 5 6; do cli sendtoaddress "$(cli getnewaddress)" 1 >/dev/null; cli generate 8 >/dev/null; done
sp
i=0
for n in 5 20 50; do
  for delay in 0 0.3; do
    i=$((i + 1)); D=$W/it$i; rm -rf "$D"; cp -a "$W/tpl" "$D"; : > "$D/out.log"
    st -testblockindexinterval=1 || { echo "FAIL case $i: first start"; F=$((F + 1)); continue; }
    cli generate 1 >/dev/null; sleep 2
    h=$(cli getblockcount)
    cli invalidateblock "$(cli getblockhash $((h - n + 1)))" >/dev/null 2>&1
    sleep 2; cli generate 1 >/dev/null
    [ "$delay" = 0 ] || sleep "$delay"
    kill -9 "$(cat "$D/pid")"; while kill -0 "$(cat "$D/pid")" 2>/dev/null; do sleep 0.1; done
    : > "$D/out.log"
    if st; then
      hh=$(cli getblockcount); v=$(cli verifychain 4 0)
      if [ "$v" = true ] && [ "$hh" -lt "$h" ]; then echo "ok   case $i: unwind $n blocks, kill after $delay s: restarted, height $hh, chain verifies"; R=$((R + 1))
      else echo "FAIL case $i: height $hh (was $h) verifychain $v"; F=$((F + 1)); fi
      sp
    else
      echo "FAIL case $i: unwind $n blocks, kill after $delay s: restart without -reindex failed: $(grep -m1 -i 'assert\|error' "$D/out.log" | cut -c1-150)"; F=$((F + 1))
    fi
  done
done
# the node dies at the 2nd, 3rd and 4th full flush (the 1st is the start-up one) while the unwind runs (kill -9 at that exact point)
for hit in 2 3 4; do
    i=$((i + 1)); D=$W/it$i; rm -rf "$D"; cp -a "$W/tpl" "$D"; : > "$D/out.log"
    st || { echo "FAIL case $i: first start"; F=$((F + 1)); continue; }
    cli stop >/dev/null 2>&1; while kill -0 "$(cat "$D/pid")" 2>/dev/null; do sleep 0.2; done
    st -testcrashpoint=flush-after-coins:$hit || { echo "FAIL case $i: start"; F=$((F + 1)); continue; }
    h=$(cli getblockcount)
    cli invalidateblock "$(cli getblockhash $((h - 19)))" >/dev/null 2>&1; sleep 1
    kill -9 "$(cat "$D/pid")" 2>/dev/null; while kill -0 "$(cat "$D/pid")" 2>/dev/null; do sleep 0.1; done
    fired=$(grep -c "exiting at flush-after-coins" "$D/out.log"); : > "$D/out.log"
    if st; then
      v=$(cli verifychain 4 0)
      if [ "$v" = true ]; then echo "ok   case $i: crash at full flush $hit (fired=$fired): restarted, height $(cli getblockcount), chain verifies"; R=$((R + 1))
      else echo "FAIL case $i: verifychain $v"; F=$((F + 1)); fi
      sp
    else echo "FAIL case $i: crash at full flush $hit: restart without -reindex failed"; F=$((F + 1)); fi
done
echo "invalidate-kill: $R ok, $F fail"
[ "$F" = 0 ] && [ "$R" -gt 0 ]
