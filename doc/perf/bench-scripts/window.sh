#!/bin/sh
# Usage: window.sh <nowallet|wallet> <seconds>
# Runs the Rust-backed baseline zclassicd from genesis (-bootstrap=0, no snapshot),
# on a fresh datadir with debug.log enabled, samples load and disk, stops with
# zclassic-cli stop, falls back to SIGTERM on the exact PID it spawned, keeps debug.log.
set -eu
MODE=$1
DUR=$2
B=$HOME/work/zclassic-c23-rust-removal/src
ROOT=$HOME/work/zc23-p0-data
D=$ROOT/$MODE
OUT=$HOME/work/zc23-p0-bench/$MODE
CAP_KB=26214400
RPC=28232
rm -rf "$D" "$OUT"
mkdir -p "$D" "$OUT"
umask 077
PW=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d " \n")
{
  echo "rpcuser=p0bench"
  echo "rpcpassword=$PW"
  echo "rpcport=$RPC"
  echo "rpcbind=127.0.0.1"
  echo "rpcallowip=127.0.0.1"
  echo "server=1"
  echo "port=28033"
  echo "listen=0"
  echo "bootstrap=0"
  echo "debug=bench"
  echo "debuglogfile=1"
} > "$D/zclassic.conf"
WALLET_FLAG=""
[ "$MODE" = nowallet ] && WALLET_FLAG="-disablewallet"
{ echo "start_utc=$(date -u +%FT%TZ)"; uptime; cat /proc/loadavg; } > "$OUT/host-start.txt"
"$B/zclassicd" -datadir="$D" -conf="$D/zclassic.conf" $WALLET_FLAG > "$OUT/stdout.txt" 2>&1 &
PID=$!
START=$(date +%s)
CAP_HIT=0
EARLY=0
while :; do
  NOW=$(date +%s)
  [ $((NOW - START)) -ge "$DUR" ] && break
  if ! kill -0 "$PID" 2>/dev/null; then EARLY=1; echo "daemon exited early" >> "$OUT/stdout.txt"; break; fi
  USED=$(du -sk "$D" | cut -f1)
  echo "$((NOW - START)) $(cat /proc/loadavg) disk_kb=$USED" >> "$OUT/sampler.txt"
  if [ "$USED" -ge "$CAP_KB" ]; then CAP_HIT=1; break; fi
  sleep 60
done
"$B/zclassic-cli" -datadir="$D" -conf="$D/zclassic.conf" -rpcport=$RPC getblockcount > "$OUT/tip-before-stop.txt" 2>&1 || true
"$B/zclassic-cli" -datadir="$D" -conf="$D/zclassic.conf" -rpcport=$RPC stop > "$OUT/stop.txt" 2>&1 || true
i=0
while kill -0 "$PID" 2>/dev/null && [ "$i" -lt 240 ]; do sleep 1; i=$((i+1)); done
if kill -0 "$PID" 2>/dev/null; then
  echo "cli stop did not exit within 240s; SIGTERM to pid $PID" >> "$OUT/stop.txt"
  kill -TERM "$PID"
  i=0
  while kill -0 "$PID" 2>/dev/null && [ "$i" -lt 600 ]; do sleep 1; i=$((i+1)); done
fi
wait "$PID" 2>/dev/null || true
echo "stop_wait_s=$i early_exit=$EARLY cap_hit=$CAP_HIT" >> "$OUT/stop.txt"
{ echo "end_utc=$(date -u +%FT%TZ) cap_hit=$CAP_HIT early_exit=$EARLY"; uptime; cat /proc/loadavg; } > "$OUT/host-end.txt"
cp "$D/debug.log" "$OUT/debug.log" 2>/dev/null || echo "no debug.log" > "$OUT/debug.log.missing"
du -sk "$D" > "$OUT/disk-final.txt"
rm -f "$D/zclassic.conf"
echo done
