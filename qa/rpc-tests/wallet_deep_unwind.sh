#!/bin/sh
# Deep unwind meets crash: a wallet with a Sapling note older than the witness cache, a
# chain unwound by invalidateblock deeper than the cache (the witnesses cannot be rolled back
# and are rebuilt, see doc/wallet-crash-consistency.md), then the node stops in one of four
# ways before any block connects:
#   1 hook-before  _exit(77) when the rebuild is about to start (-testcrashpoint=rebuild-before-scan):
#                  the unwind exists in memory only, wallet.dat holds the state from before it
#   2 hook-after   _exit(77) after the rebuild, before it is written (rebuild-after-scan)
#   3 kill9        kill -9 after invalidateblock returned
#   4 clean        a clean stop (the shutdown checkpoint)
#   5 hook-mid-unwind  _exit(77) inside the 104th DisconnectTip, before the unwind has finished
# The wallet restarts WITHOUT -rescan. Its balances, z_listunspent and listunspent must equal
# those of a copy of the same datadir restarted with -rescan, at the lowered tip and again after
# reconsiderblock, and a shielded spend of the old note must be accepted and mined by the peer.
#
# usage: wallet_deep_unwind.sh --bin <dir> --work <dir> [--peer-bin <dir>] [--only 1,2,3,4,5] [--base port]
# Output: <work>/results.txt. Exit status 0 when every variant passed.
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
BIN=""; WORK=""; PEER_BIN=""; ONLY=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;;
        --only) ONLY=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--peer-bin DIR] [--only N,N]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$BIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; OBS_LOG=$WORK/obs.txt; : >"$RESULTS"; : >"$OBS_LOG"
BASE=${PORT_BASE:-$((20000 + ($$ % 20000)))}
trap 'stop_all' EXIT
R1="-connect=127.0.0.1:$((BASE + 1))"

# snap <n>: totals, notes and unspent outputs, exact
snap() {
    printf 'z=%s t=%s notes=%s utxo=%s' "$(cli "$1" z_gettotalbalance 1 | jq -c '[.transparent,.private]')" "$(bal "$1" '*' 1)" \
        "$(cli "$1" z_listunspent 1 | jq -c '[.[]|(.amount*100000000|round)]|sort')" \
        "$(cli "$1" listunspent 1 | jq -c '[.[]|.txid[0:8]+":"+(.vout|tostring)]|sort')"
}
# refsnap <label>: node 0 is stopped; a copy of its datadir, restarted with -rescan on node 3
refsnap() { # <label> <connect arg>
    rm -rf "$SD/node3"; cp -a "$SD/node0" "$SD/node3"; rm -f "$SD/node3/regtest/.lock"
    start 3 "$BIN" $2 -rescan -disablesafemode || return 1
    if [ "$2" != "-connect=0" ]; then sync_to 3; fi
    REF=$(snap 3); REFTIP=$(cli 3 getbestblockhash); stop 3
}

variant() { # <label> <crash arg or ''> <how: hook|kill9|clean>
    local l=$1 hook=$2 how=$3 pid s1 s2 s3 s4
    setup2 -disablesafemode || return
    ZS=$(cli 0 z_getnewaddress); give_z 0 "$ZS" 4
    cli 1 generate 3 >/dev/null; sync_to 0
    ck "$l: note received" "$(zbal 0 "$ZS")" 4.00000000
    cli 1 generate 110 >/dev/null; sync_to 0            # the note is now older than the 100-block cache
    stop 0
    start 0 "$BIN" $R1 -disablesafemode $hook || return; sync_to 0   # a checkpoint exists, then the unwind
    first=$(cli 0 getblockhash $(($(cli 0 getblockcount) - 104)))
    pid=$(cat "$SD/node0/pid")
    cli 0 invalidateblock "$first" >/dev/null 2>&1
    case $how in
        hook) sleep 2; if kill -0 "$pid" 2>/dev/null; then bad "$l: the crash hook did not fire"; kill9 0
              else pass "$l: node died at the hook"; rm -f "$SD/node0/regtest/.lock"; fi ;;
        kill9) kill9 0 ;;
        clean) stop 0 ;;
    esac
    # the peer is stopped: no block can connect before the restarted wallet has been compared
    stop 1
    refsnap "$l" "-connect=0" || return
    start 0 "$BIN" -connect=0 -disablesafemode || return        # plain restart, no -rescan
    s1=$(snap 0)
    ck "$l: restart without -rescan equals the -rescan reference (no block connected)" "$s1" "$REF"
    ck "$l: same chain tip as the reference" "$(cli 0 getbestblockhash)" "$REFTIP"
    ck "$l: the note is still counted" "$(zbal 0 "$ZS")" 4.00000000
    cli 0 reconsiderblock "$first" >/dev/null 2>&1
    stop 0; start 1 "$PEER_BIN" -connect=0 || return; refsnap "$l tip" "$R1" || return
    start 0 "$BIN" $R1 -disablesafemode || return; sync_to 0
    alive "$l after reconsider" 0
    ck "$l: at the tip, wallet equals the -rescan reference" "$(snap 0)" "$REF"
    spend_check "$l" "$ZS" 4.00000000 1.25
}
spend_check() {
    local l=$1 zs=$2 b=$3 amt=$4 ta
    ta=$(cli 1 getnewaddress)
    zconfirm 0 "$zs" "[{\"address\":\"$ta\",\"amount\":$amt}]" >/dev/null
    ck "$l: shielded spend accepted and mined by the peer, exact balance" "$(zbal 0 "$zs")" "$(add "$b" -$amt -$FEE)"
}
scn_hook_before() { variant hook-before "-testcrashpoint=rebuild-before-scan" hook; }
scn_hook_after() { variant hook-after "-testcrashpoint=rebuild-after-scan" hook; }
scn_kill9() { variant kill9 "" kill9; }
scn_hook_midunwind() { variant hook-mid-unwind "-testcrashpoint=disconnect-between-sync-and-chaintip:104" hook; }
scn_clean() { variant clean "" clean; }

run_scn() {
    id=$1; name=$2; fn=$3
    if [ -n "$ONLY" ]; then case ",$ONLY," in *",$id,"*) ;; *) return 0 ;; esac; fi
    SCN_ID=$id; SCN_LOG=$WORK/scn$id.log; SD=$WORK/s$id; : >"$SCN_LOG"
    rm -rf "$SD"; mkdir -p "$SD"
    say "== $id. $name"
    ( $fn ) 2>&1 | tee "$WORK/scn$id.out" >/dev/null
    stop_all
    np=$(grep -c '^PASS' "$SCN_LOG"); nf=$(grep -c '^FAIL' "$SCN_LOG")
    st=PASS; [ "$nf" = 0 ] && [ "$np" -gt 0 ] || st=FAIL
    echo "$id|$name|$st|$np pass $nf fail" >>"$RESULTS"
    say "   -> $st ($np pass, $nf fail)"
    BASE=$((BASE + 7)); [ $BASE -lt 60000 ] || BASE=20000
    R1="-connect=127.0.0.1:$((BASE + 1))"
}
run_scn 1 "deep unwind, crash before the rebuild" scn_hook_before
run_scn 2 "deep unwind, crash after the rebuild, before it is written" scn_hook_after
run_scn 3 "deep unwind, kill -9 after invalidateblock" scn_kill9
run_scn 4 "deep unwind, clean stop (shutdown checkpoint)" scn_clean
run_scn 5 "deep unwind, crash inside the 104th disconnect (witness caches already rolled back in memory)" scn_hook_midunwind
say; say "id|scenario|result|checks"; cat "$RESULTS"
! grep -q '|FAIL|' "$RESULTS"
