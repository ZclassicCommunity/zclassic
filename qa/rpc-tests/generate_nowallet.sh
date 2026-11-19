#!/bin/sh
# generate, getblocktemplate and setgenerate on a node that has no coinbase script (-disablewallet,
# or an encrypted wallet whose key pool ran out) must answer with an RPC error and leave the node
# running. They used to dereference the missing script: a hardened build aborted the daemon with an
# assertion (boost::shared_ptr operator->), a plain one crashed.
#
# usage: generate_nowallet.sh --bin <dir> --work <dir> [--base port]
# Needs the Zcash parameters in ~/.zcash-params. Shell only, no Python.
B=""; W=""; P=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) B=$2; shift 2 ;; --work) W=$2; shift 2 ;; --base) P=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$B/zclassicd" ] && [ -n "$W" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
. "$(dirname "$0")/jsonq_lib.sh"
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
. "$(dirname "$0")/../lib/isolation.sh"
iso_base P "$P" 16; R=0; F=0
rm -rf "$W"; mkdir -p "$W"; W=$(cd "$W" && pwd)
trap '[ -f "$D/pid" ] && kill -9 "$(cat "$D/pid")" 2>/dev/null' EXIT
A0="-regtest -server=1 -listen=0 -showmetrics=0 -debuglogfile=1 -keypool=5 -nuparams=5ba81b19:1 -nuparams=76b809bb:1 -experimentalfeatures -rpcport=$P -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -dnsseed=0 -discover=0 -listenonion=0"
cli() { "$B/zclassic-cli" -regtest -datadir="$D" -rpcport=$P -rpcuser=u -rpcpassword=p "$@"; }
st() { rm -f "$D/regtest/.lock"; $ZCL_RUN "$B/zclassicd" $A0 -datadir="$D" "$@" >> "$D/out.log" 2>&1 & echo $! > "$D/pid"
    for k in $(seq 600); do cli getblockcount >/dev/null 2>&1 && return 0; kill -0 "$(cat "$D/pid")" 2>/dev/null || return 1; sleep 0.1; done; return 1; }
sp() { cli stop >/dev/null 2>&1; while kill -0 "$(cat "$D/pid")" 2>/dev/null; do sleep 0.2; done; }
newdir() { D=$W/$1; mkdir -p "$D"; : > "$D/out.log"; printf "rpcuser=u\nrpcpassword=p\n" > "$D/zclassic.conf"; }
ok() { echo "ok   $1"; R=$((R + 1)); }
bad() { echo "FAIL $1"; F=$((F + 1)); }

# expect_error <label> <rpc> [args]: the call must fail with the coinbase-script message and the node must stay up
expect_error() {
    l=$1; shift
    out=$(cli "$@" 2>&1); rc=$?
    if [ $rc -ne 0 ] && printf '%s' "$out" | grep -Eq "No coinbase script available|Wallet disabled and -mineraddress not set" && kill -0 "$(cat "$D/pid")" 2>/dev/null && cli getblockcount >/dev/null 2>&1; then ok "$l: RPC error, node still running"
    else bad "$l: rc=$rc out='$(printf '%s' "$out" | head -c 150)' alive=$(kill -0 "$(cat "$D/pid")" 2>/dev/null && echo yes || echo no)"; fi
}

# A wallet node provides an address to use as -mineraddress later
newdir wal; st || { echo "wallet node start failed"; exit 1; }
ADDR=$(cli getnewaddress); sp

# 1. -disablewallet, no -mineraddress
newdir nw; st -disablewallet || { echo "FAIL start -disablewallet"; exit 1; }
expect_error "generate with -disablewallet" generate 1
expect_error "getblocktemplate with -disablewallet" getblocktemplate
expect_error "generate again (no state left behind)" generate 2
r=$(cli setgenerate true 2>&1); echo "$r" | grep -q "generate method\|No coinbase script" && kill -0 "$(cat "$D/pid")" 2>/dev/null && ok "setgenerate true with -disablewallet: refused ('$(printf '%s' "$r" | head -c 60)')" || bad "setgenerate: $r"
sp
# 2. the same node with -mineraddress can mine
newdir ma; st -disablewallet -mineraddress=$ADDR -minetolocalwallet=0 || { bad "start -disablewallet -mineraddress"; }
n=$(cli generate 2 2>&1 | jlen 2>/dev/null); [ "$n" = 2 ] && [ "$(cli getblockcount)" = 2 ] && ok "generate with -disablewallet -mineraddress mines 2 blocks" || bad "generate with -mineraddress: '$n'"
cli getblocktemplate >/dev/null 2>&1; rcg=$?; kill -0 "$(cat "$D/pid")" 2>/dev/null && ok "getblocktemplate with -mineraddress answers without killing the node (rc=$rcg)" || bad "getblocktemplate with -mineraddress killed the node"
sp
# 3. -prune : no wallet there either
newdir pr; st -prune=550 || { bad "start -prune=550"; }
expect_error "generate under -prune=550 (which turns the wallet off)" generate 1
sp
echo "generate-nowallet: $R ok, $F fail"
[ "$F" = 0 ] && [ "$R" -gt 0 ]
