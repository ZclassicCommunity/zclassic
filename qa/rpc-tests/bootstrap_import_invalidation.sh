#!/bin/sh
# A node that imports a chain snapshot (blocks/ + chainstate/, as a bootstrap install does) must not
# inherit the failure marks the snapshot's source set with invalidateblock: the block index is not
# verified, only the UTXO set is. Before 95499ca26 such marks were dropped at the first start
# (RewindBlockIndex); with it they are kept, and the importing node refuses the chain its peers
# follow.
#
# The source invalidates block 146 of a 150-block chain (tip 145) and its blocks/ + chainstate/ are
# imported with -bootstrapdatadir into a fresh node, which connects to a peer at height 155 on the
# chain through 146. The importing node must reach 155. The source itself, restarted, must still
# refuse 146 (invalidateblock survives a restart on the node that ran it).
#
# usage: bootstrap_import_invalidation.sh --bin <dir> --work <dir> [--base port]
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
rm -rf "$W"; mkdir -p "$W/src" "$W/peer" "$W/imp" "$W/snap"; W=$(cd "$W" && pwd)
trap 'for d in src peer imp; do [ -f "$W/$d/pid" ] && kill -9 "$(cat "$W/$d/pid")" 2>/dev/null; done' EXIT
for d in src peer imp; do printf "rpcuser=u\nrpcpassword=p\n" > "$W/$d/zclassic.conf"; done
A0="-regtest -server=1 -showmetrics=0 -debuglogfile=1 -keypool=5 -nuparams=5ba81b19:1 -nuparams=76b809bb:1 -experimentalfeatures -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -dnsseed=0 -discover=0 -listenonion=0 -bootstrap=0"
port() { case $1 in src) echo $P ;; peer) echo $((P + 1)) ;; imp) echo $((P + 2)) ;; esac; }
cli() { n=$1; shift; "$B/zclassic-cli" -regtest -datadir="$W/$n" -rpcport=$(port $n) -rpcuser=u -rpcpassword=p "$@"; }
st() { n=$1; shift; rm -f "$W/$n/regtest/.lock"; "$B/zclassicd" $A0 -datadir="$W/$n" -rpcport=$(port $n) "$@" >> "$W/$n/out.log" 2>&1 & echo $! > "$W/$n/pid"
    for k in $(seq 900); do cli $n getblockcount >/dev/null 2>&1 && return 0; kill -0 "$(cat "$W/$n/pid")" 2>/dev/null || return 1; sleep 0.1; done; return 1; }
sp() { cli $1 stop >/dev/null 2>&1; while kill -0 "$(cat "$W/$1/pid")" 2>/dev/null; do sleep 0.2; done; }
ok() { R=$((R + 1)); echo "ok   $1"; }
bad() { F=$((F + 1)); echo "FAIL $1"; }

st src -listen=0 || { echo "source start failed"; exit 1; }
cli src generate 130 >/dev/null
for i in 1 2 3 4; do cli src sendtoaddress "$(cli src getnewaddress)" 1 >/dev/null; cli src generate 5 >/dev/null; done
sp src
cp -a "$W/src/regtest" "$W/peer/"; rm -f "$W/peer/regtest/wallet.dat" "$W/peer/regtest/peers.dat"
st src -listen=0; X=$(cli src getblockhash 146); cli src invalidateblock "$X"; h=$(cli src getblockcount); sp src
[ "$h" = 145 ] || bad "source tip after invalidateblock: $h"
cp -a "$W/src/regtest/blocks" "$W/src/regtest/chainstate" "$W/snap/"

st peer -listen=1 -port=$((P + 11)) || { echo "peer start failed"; exit 1; }
cli peer generate 5 >/dev/null; PT=$(cli peer getbestblockhash)

st imp -listen=0 -bootstrapdatadir="$W/snap" -connect=127.0.0.1:$((P + 11)) || { echo "import start failed: $(tail -3 "$W/imp/out.log")"; exit 1; }
for k in $(seq 150); do [ "$(cli imp getbestblockhash)" = "$PT" ] && break; sleep 0.2; done
h=$(cli imp getblockcount); s=$(cli imp getchaintips | jq -r '[.[] | select(.height == 150)][0].status // "absent"')
[ "$(cli imp getbestblockhash)" = "$PT" ] && ok "importing node follows its peer to height $h (old tip 150: $s)" || bad "importing node stuck at height $h; tip 150 of the snapshot source is $s"
sp imp
st imp -listen=0 -connect=127.0.0.1:$((P + 11)); for k in $(seq 100); do [ "$(cli imp getbestblockhash)" = "$PT" ] && break; sleep 0.2; done
[ "$(cli imp getbestblockhash)" = "$PT" ] && ok "importing node, restarted: still at the peer's tip" || bad "importing node, restarted: height $(cli imp getblockcount)"
sp imp; sp peer

st src -listen=0; s=$(cli src getchaintips | jq -r '[.[] | select(.height == 150)][0].status // "absent"'); h=$(cli src getblockcount); sp src
[ "$s" = invalid ] && [ "$h" = 145 ] && ok "the source, restarted, still refuses block 146 (tip 150 $s, height $h)" || bad "the source, restarted: tip 150 $s, height $h"
echo "bootstrap-import-invalidation: $R ok, $F fail"
[ "$F" = 0 ] && [ "$R" -gt 0 ]
