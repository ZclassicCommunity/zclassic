#!/bin/sh
# Usage: profile_loadblock.sh <zclassicd> <fresh-datadir> <blk-file> <seconds> <outdir> [extra zclassicd args]
# Profiles block import (-loadblock) of a COPIED blk file into a throwaway
# datadir. Full block validation (CheckBlock, Equihash, merkle, ConnectBlock)
# runs exactly as in a sync from genesis. No network (-connect=0, -listen=0),
# and no production datadir, wallet or service is touched.
# -reindex is NOT used: on this baseline it dereferences a null pindexPrev for
# the genesis block (AcceptBlockHeader, main.cpp:4489) and segfaults.
set -u
BIN=$1; DD=$2; BLK=$3; SECS=$4; OUT=$5; shift 5
mkdir -p "$OUT" "$DD"
cat > "$DD/zclassic.conf" <<EOF
server=0
listen=0
bootstrap=0
connect=0
dnsseed=0
discover=0
debug=bench
debuglogfile=1
EOF
# step 1: let the node create its own genesis (no import), then stop it
"$BIN" -datadir="$DD" -conf="$DD/zclassic.conf" -printtoconsole=0 "$@" > "$OUT/init_stdout.txt" 2>&1 &
IP=$!
i=0
while [ $i -lt 90 ]; do
  grep -q "init message: Done loading\|Done loading" "$DD/debug.log" 2>/dev/null && break
  i=$((i+1)); sleep 1
done
kill -INT "$IP"; wait "$IP"
rm -f "$DD/debug.log"
# step 2: profiled import
perf record ${HB_PERF_OPTS:--e cpu-clock:u -F 499} -o "$OUT/perf.data" -- \
  "$BIN" -datadir="$DD" -conf="$DD/zclassic.conf" -loadblock="$BLK" -printtoconsole=0 "$@" > "$OUT/stdout.txt" 2>&1 &
PP=$!
sleep "$SECS"
ZP=$(pgrep -f -- "^$BIN -datadir=$DD" | head -1)
[ -n "$ZP" ] && kill -INT "$ZP"
wait "$PP"
cp "$DD/debug.log" "$OUT/debug.log" 2>/dev/null
grep -c "UpdateTip" "$OUT/debug.log" > "$OUT/updatetip_count.txt" 2>/dev/null
grep "UpdateTip" "$OUT/debug.log" | tail -1 > "$OUT/last_tip.txt"
perf report -i "$OUT/perf.data" --no-children --sort symbol --stdio 2>/dev/null | head -200 > "$OUT/report.txt"
