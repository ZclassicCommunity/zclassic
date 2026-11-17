#!/bin/sh
# Wallet RPC functional matrix on regtest, with exact balance assertions.
#
# usage: wallet_matrix.sh --bin <dir> --work <dir> [--peer-bin <dir>] [--alt-bin <dir>]
#                         [--only 1,2,...] [--base port]
#   --base      first port (P2P base..base+n, RPC base+100+n; each scenario adds 7).
#               Default derives from the PID; give distinct values to concurrent runs,
#               which can otherwise collide (seen: bind failure at node startup)
#   --bin       directory with zclassicd and zclassic-cli: the wallet under test
#   --peer-bin  binary for the miner/peer node (default: --bin); a different
#               build here exercises transaction/block interop (scenario 9)
#   --alt-bin   second binary for cross-version scenario 8 (default: --bin)
#   --only      comma list of scenario numbers (default: all but 11)
#   env LOAD_NOTES / LOAD_UTXOS  sizes for scenario 11 (run only when selected)
# Output: <work>/results.txt (one line per scenario) and <work>/obs.txt
# (recorded observations; diff them between two binaries).
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
BIN=""; WORK=""; PEER_BIN=""; ALT_BIN=""; ONLY=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;;
        --alt-bin) ALT_BIN=$2; shift 2 ;; --only) ONLY=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--peer-bin DIR] [--alt-bin DIR] [--only N,N]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$BIN}; ALT_BIN=${ALT_BIN:-$BIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
for f in "$HERE"/wallet_matrix_scn?.sh; do . "$f"; done
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; OBS_LOG=$WORK/obs.txt; : >"$RESULTS"; : >"$OBS_LOG"
BASE=${PORT_BASE:-$((20000 + ($$ % 20000)))}
trap 'stop_all' EXIT

run_scn() {
    id=$1; name=$2; fn=$3
    if [ -n "$ONLY" ]; then case ",$ONLY," in *",$id,"*) ;; *) return 0 ;; esac
    elif [ "$id" = 11 ]; then return 0; fi
    SCN_ID=$id; SCN_LOG=$WORK/scn$id.log; SD=$WORK/s$id; : >"$SCN_LOG"
    rm -rf "$SD"; mkdir -p "$SD"
    say "== $id. $name"
    t0=$(now)
    ( $fn ) 2>&1 | tee "$WORK/scn$id.out" >/dev/null
    stop_all
    np=$(grep -c '^PASS' "$SCN_LOG"); nf=$(grep -c '^FAIL' "$SCN_LOG")
    st=PASS; [ "$nf" = 0 ] && [ "$np" -gt 0 ] || st=FAIL
    echo "$id|$name|$st|$np pass $nf fail|$(elapsed "$t0")s" >>"$RESULTS"
    say "   -> $st ($np pass, $nf fail)"
    BASE=$((BASE + 7)); [ $BASE -lt 60000 ] || BASE=20000
}

run_scn 1 "transparent wallet RPCs" scn_transparent
run_scn 2 "shielded Sapling RPCs" scn_sapling
run_scn 3 "Sprout legacy notes" scn_sprout
run_scn 4 "keys, export, import, backup" scn_keys
run_scn 5 "encryption" scn_encrypt
run_scn 6 "persistence, rescan, crash" scn_crash
run_scn 7 "reorgs" scn_reorg
run_scn 8 "cross-version wallet.dat" scn_crossver
run_scn 9 "two-node interop" scn_interop
run_scn 10 "coin selection stability" scn_coinsel
run_scn 11 "load" scn_load
run_scn 12 "input robustness" scn_robust
run_scn 13 "relay after kill -9" scn_relay
run_scn 14 "crash window after confirmed receipts" scn_window

say; say "id|scenario|result|checks|time"; cat "$RESULTS"
! grep -q '|FAIL|' "$RESULTS"
