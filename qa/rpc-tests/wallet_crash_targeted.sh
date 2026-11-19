#!/bin/sh
# Two crash points that the random run of wallet_crash_consistency.sh rarely reaches:
#  A: a wallet restored from an older backup rescans at start-up; the node dies after that rescan
#     and before its checkpoint (-testcrashpoint=init-after-rescan);
#  B: the node dies inside DisconnectTip, between the wallet transaction sync and the witness
#     update (-testcrashpoint=disconnect-between-sync-and-chaintip, during invalidateblock).
# After each crash: a plain restart must report exactly what a -rescan of a copy reports
# (z_gettotalbalance, z_listunspent, listunspent), and so must a second plain restart.
#
# usage: wallet_crash_targeted.sh --bin <dir> --work <dir> [--base port]
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
B=""; W=""; P=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) B=$2; shift 2 ;; --work) W=$2; shift 2 ;; --base) P=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$B/zclassicd" ] && [ -n "$W" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
. "$(dirname "$0")/jsonq_lib.sh"
. "$(dirname "$0")/../lib/isolation.sh"
iso_base P "$P" 16; R=0; F=0
rm -rf "$W"; mkdir -p "$W"; W=$(cd "$W" && pwd)
trap 'for f in "$W"/*/pid "$W"/*.ref/pid; do [ -f "$f" ] && kill -9 "$(cat "$f")" 2>/dev/null; done' EXIT
A0="-regtest -server=1 -listen=0 -showmetrics=0 -debuglogfile=1 -keypool=5 -nuparams=5ba81b19:1 -nuparams=76b809bb:1 -experimentalfeatures -zmergetoaddress -rpcport=$P -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -walletbroadcast=0"
cli() { $B/zclassic-cli -regtest -datadir=$D -rpcport=$P -rpcuser=u -rpcpassword=p "$@"; }
st() { rm -f $D/regtest/.lock; mkdir -p $D/export; $ZCL_RUN $B/zclassicd $A0 -exportdir=$D/export -datadir=$D "$@" >> $D/out.log 2>&1 & echo $! > $D/pid; for i in $(seq 240); do cli getblockcount >/dev/null 2>&1 && return 0; kill -0 $(cat $D/pid) 2>/dev/null || { wait $(cat $D/pid); return $?; }; sleep 0.25; done; return 1; }
sp() { cli stop >/dev/null 2>&1; while kill -0 $(cat $D/pid) 2>/dev/null; do sleep 0.2; done; }
wop() { for i in $(seq 600); do s=$(cli z_getoperationstatus "[\"$1\"]" | jget "[0].status"); case $s in success|failed) return;; esac; sleep 0.5; done; }
snap() { echo "$(cli z_gettotalbalance 1 | jq -c "[.transparent,.private]") $(cli z_listunspent 1 | jq -c "[.[]|.txid[0:8]+\":\"+(.outindex // .jsoutindex|tostring)+\":\"+(.amount|tostring)]|sort") $(cli listunspent 1 | jq -c "[.[]|.txid[0:8]+\":\"+(.vout|tostring)]|sort")"; }
cmp3() { # cmp3 <label>: plain restart, -rescan copy, second plain restart
  local base=$D; rm -rf $base.ref; cp -a $base $base.ref
  st || { echo "FAIL $1: restart rc=$?"; F=$((F+1)); return; }; s1=$(snap); sp
  D=$base.ref; st -rescan; s2=$(snap); sp; D=$base
  st; s3=$(snap); sp
  if [ "$s1" = "$s2" ] && [ "$s3" = "$s2" ]; then echo "ok   $1"; R=$((R+1)); else echo "FAIL $1"; echo " restart  $s1"; echo " rescan   $s2"; echo " restart2 $s3"; F=$((F+1)); fi
}
setup() { D=$W/$1; mkdir -p $D; printf "rpcuser=u\nrpcpassword=p\n" > $D/zclassic.conf; st || exit 1
  cli generate 110 >/dev/null; ZA=$(cli z_getnewaddress sapling); ZB=$(cli z_getnewaddress sapling); SP=$(cli z_getnewaddress sprout); TA=$(cli getnewaddress)
  cli sendtoaddress $TA 10 >/dev/null; cli generate 1 >/dev/null
  wop $(cli z_shieldcoinbase "*" $ZA 0.0001 4 | jget opid); cli generate 1 >/dev/null
  wop $(cli z_sendmany $TA "[{\"address\":\"$SP\",\"amount\":2}]" 1 0.0001); cli generate 1 >/dev/null; }
more() { wop $(cli z_sendmany $ZA "[{\"address\":\"$ZB\",\"amount\":1},{\"address\":\"$TA\",\"amount\":0.5}]" 1 0.0001); cli generate 1 >/dev/null
  wop $(cli z_sendmany $SP "[{\"address\":\"$TA\",\"amount\":0.3}]" 1 0.0001); cli generate 1 >/dev/null
  wop $(cli z_sendmany $ZB "[{\"address\":\"$ZA\",\"amount\":0.2}]" 1 0.0001); cli generate 3 >/dev/null; }
for n in 1 2 3; do
  setup A$n; cli backupwallet bk; more; sp; cp $D/export/bk $D/regtest/wallet.dat
  st -testcrashpoint=init-after-rescan; rc=$?; echo "A$n: start with the old backup and the hook: rc=$rc (77 = fired)"; grep -c "exiting at init-after-rescan" $D/out.log
  cmp3 "A$n restored backup, crash after the start-up rescan"
done
for n in 1 2 3; do
  setup B$n; more; sp; st -testcrashpoint=disconnect-between-sync-and-chaintip:$n || true
  h=$(cli getblockcount); cli invalidateblock $(cli getblockhash $((h-4))) >/dev/null 2>&1; sleep 1
  kill -0 $(cat $D/pid) 2>/dev/null && { echo "B$n: hook did not fire"; sp; } || echo "B$n: fired $(grep -c "exiting at disconnect" $D/out.log)"
  cmp3 "B$n crash inside DisconnectTip (hit $n)"
done
echo "targeted: $R ok, $F fail"
[ "$F" = 0 ]
