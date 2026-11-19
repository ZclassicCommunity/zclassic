#!/bin/sh
# Build the ZSLP index over a COPY of a mainnet datadir and dump what it found.
#
#   zslp_mainnet_crosscheck.sh <datadir-copy> <dir-with-zclassicd-and-zclassic-cli> <out-dir> [extra zclassicd args]
#
# NEVER point this at a live node's datadir: it opens the datadir (blocks/, chainstate/) read-write
# like any node. Copy blocks/ and chainstate/ to a scratch directory first. The node it starts has
# no peers, no wallet, no listening socket, and its own leased RPC port, and is stopped at the end.
#
# Output files in <out-dir>:
#   progress.log     one line every 30 s while indexing, then "SYNCED after N seconds"
#   indexinfo.json   zslp_getindexinfo when done (counters, by message type and validity)
#   tokens.json      every token (zslp_listtokens, all pages)
#   txs.jsonl        one line per (token, transaction): zslp_gettransaction, merged with the token id
#   size_kb          size of <datadir>/zslpindex
#
# Needs: jq.
set -u
[ $# -ge 3 ] || { sed -n 2,5p "$0" >&2; exit 2; }
D=$1; Z=$2; OUT=$3; shift 3
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
[ -x "$Z/zclassicd" ] && [ -x "$Z/zclassic-cli" ] || { echo "no zclassicd/zclassic-cli in $Z" >&2; exit 2; }
mkdir -p "$OUT"
. "$(dirname "$0")/../lib/isolation.sh"
iso_base PB "${ZSLP_PORT_BASE:-}" 4   # PB = p2p port, PB+1 = rpc port
CLI="$Z/zclassic-cli -datadir=$D -rpcport=$((PB + 1)) -rpcuser=scan -rpcpassword=scan"
$ZCL_RUN "$Z/zclassicd" -datadir="$D" -zslpindex=1 "$@" -connect=0 -listen=0 -dnsseed=0 -discover=0 -listenonion=0 \
    -bootstrap=0 -disablewallet -upnp=0 -showmetrics=0 -server=1 -port=$PB -rpcport=$((PB + 1)) \
    -rpcuser=scan -rpcpassword=scan -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -daemon=0 >"$OUT/node.out" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null' INT TERM
t=0
until $CLI getblockcount >/dev/null 2>&1; do
    kill -0 $PID 2>/dev/null || { echo "node exited"; tail -20 "$OUT/node.out"; exit 1; }
    t=$((t + 1)); [ $t -lt 1800 ] || { echo "no rpc"; kill $PID; exit 1; }
    sleep 2
done
S=$(date +%s)
echo "rpc up, chain $($CLI getblockcount) $($CLI getbestblockhash)" >"$OUT/progress.log"
while :; do
    I=$($CLI zslp_getindexinfo 2>&1)
    echo "$(date +%s) $(( $(date +%s) - S ))s $(echo "$I" | jq -c '{indexedheight,chainheight,progress,synced,error,tokens,validtransactions,invalidtransactions,unknowntransactions,burntransactions,unspentoutputs}' 2>/dev/null)" >>"$OUT/progress.log"
    [ "$(echo "$I" | jq -r .synced 2>/dev/null)" = true ] && break
    kill -0 $PID 2>/dev/null || { echo "node died" >>"$OUT/progress.log"; exit 1; }
    sleep 30
done
E=$(date +%s)
echo "SYNCED after $((E - S)) seconds" >>"$OUT/progress.log"
$CLI zslp_getindexinfo >"$OUT/indexinfo.json"

# every token, every transaction
: >"$OUT/tokens.json.tmp"
skip=0
while :; do
    page=$($CLI zslp_listtokens $skip 1000)
    n=$(echo "$page" | jq length)
    echo "$page" | jq -c '.[]' >>"$OUT/tokens.json.tmp"
    [ "$n" -eq 1000 ] || break
    skip=$((skip + 1000))
done
jq -s . "$OUT/tokens.json.tmp" >"$OUT/tokens.json"; rm -f "$OUT/tokens.json.tmp"
: >"$OUT/txs.jsonl"
for tok in $(jq -r '.[].tokenid' "$OUT/tokens.json"); do
    skip=0
    while :; do
        page=$($CLI zslp_listtransactions "$tok" $skip 1000)
        n=$(echo "$page" | jq length)
        for tx in $(echo "$page" | jq -r '.[].txid'); do
            $CLI zslp_gettransaction "$tx" | jq -c --arg t "$tok" '. + {token: $t}' >>"$OUT/txs.jsonl"
        done
        [ "$n" -eq 1000 ] || break
        skip=$((skip + 1000))
    done
done
du -sk "$D/zslpindex" | awk '{print $1}' >"$OUT/size_kb"
echo "dumped $(wc -l <"$OUT/txs.jsonl") transactions of $(jq length "$OUT/tokens.json") tokens" >>"$OUT/progress.log"
echo done >"$OUT/state"
# with KEEP_NODE set the node stays up (so raw transactions can be fetched with getrawtransaction)
# until the file <out-dir>/stop exists
if [ -n "${KEEP_NODE:-}" ]; then
    until [ -e "$OUT/stop" ]; do sleep 5; done
fi
$CLI stop >/dev/null 2>&1
wait $PID 2>/dev/null
