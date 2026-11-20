#!/bin/sh
# Cost of a wallet with many spent notes, before and after retiring their witnesses: the same
# datadir (a template built by wallet_witness_retire.sh, spends 96 blocks deep) is run by two
# binaries. For each: blocks are mined one at a time past the point where the spends are buried
# deeper than the witness cache, with -debug=bench and a wallet checkpoint at every block
# (-testsetchaininterval=0); then a clean stop and a start.
#
# usage: wallet_witness_retire_perf.sh --template <dir> --work <dir> --before <bindir> --after <bindir>
#            [--peer-bin <dir>] [--blocks N] [--base port]
#   --template  <work>/template of an earlier wallet_witness_retire.sh run (node0, node1)
# Output: <work>/perf.txt, one line per measurement and binary, and the table on stdout.
# Needs the Zcash parameters in ~/.zcash-params. Shell only, no Python.
TPL=""; WORK=""; BEFORE=""; AFTER=""; PEER_BIN=""; BLOCKS=40; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --template) TPL=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --before) BEFORE=$2; shift 2 ;; --after) AFTER=$2; shift 2 ;;
        --peer-bin) PEER_BIN=$2; shift 2 ;; --blocks) BLOCKS=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -d "$TPL/node0" ] && [ -x "$BEFORE/zclassicd" ] && [ -x "$AFTER/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --template DIR --work DIR --before BIN --after BIN" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$AFTER}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd); TPL=$(cd "$TPL" && pwd)
PERF=$WORK/perf.txt; : >"$PERF"
iso_base BASE "${PORT_BASE:-}" 112
SCN_LOG=$WORK/perf.log; SCN_ID=perf; OBS_LOG=$WORK/perf.obs; : >"$SCN_LOG"; : >"$OBS_LOG"
trap 'stop_all' EXIT

fsz() { ls -l "$1" | awk '{print $5}'; }
mib() { awk -v b="$1" 'BEGIN{printf "%.1f", b/1048576}'; }
# stat <file> <regex>: mean, max of the first number matched after the regex's capture, over the last N lines
mstat() { # <log> <pattern with one (...) capture of the ms value> <lines to use>
    grep -E "$2" "$1" | tail -n "$3" | sed -E "s/$2/\\1/" | awk '{ s += $1; if ($1 > m) m = $1; n++ } END { if (n) printf "%.2f %.2f %d", s / n, m, n; else printf "n/a n/a 0" }'
}
rss() { awk '/VmRSS/ {r=$2} /VmHWM/ {h=$2} END {printf "%.0f %.0f", r/1024, h/1024}' "/proc/$(cat "$SD/node0/pid")/status"; }

run_one() { # <label> <bindir>
    local label=$1 bd=$2 t0 t1 i lg
    SD=$WORK/$label; rm -rf "$SD"; mkdir -p "$SD"
    cp -a "$TPL/node0" "$SD/node0"; cp -a "$TPL/node1" "$SD/node1"
    rm -f "$SD/node0/regtest/.lock" "$SD/node1/regtest/.lock" "$SD/node0/pid" "$SD/node1/pid"
    lg=$SD/node0/regtest/debug.log
    sz0=$(fsz "$SD/node0/regtest/wallet.dat")
    start 1 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 0)) || return 1
    t0=$(now); start 0 "$bd" -connect=127.0.0.1:$((BASE + 1)) -disablesafemode -debug=bench -testsetchaininterval=0 || return 1
    t1=$(elapsed "$t0")
    nl=$(wc -l <"$lg")
    i=0; while [ $i -lt $BLOCKS ]; do cli 1 generate 1 >/dev/null; sync_to 0 || return 1; i=$((i + 1)); done
    tail -n +$((nl + 1)) "$lg" >"$SD/blocks.log"
    cb=$(mstat "$SD/blocks.log" '.*- Callbacks: ([0-9.]+)ms.*' 20)
    wu=$(mstat "$SD/blocks.log" '.*- Wallet witness update: ([0-9.]+)ms.*' 20)
    fl=$(mstat "$SD/blocks.log" '.*- Flush: ([0-9.]+)ms.*' 20)
    cp_=$(mstat "$SD/blocks.log" '.*- Wallet checkpoint: ([0-9.]+)ms.*' 20)
    cpn=$(grep -E "Wallet checkpoint" "$SD/blocks.log" | tail -n 20 | sed -E 's/.*\(([0-9]+) note transactions marked.*/\1/' | awk '{s += $1; n++} END { if (n) printf "%.0f", s / n; else printf "n/a" }')
    wutx=$(grep -E "Wallet witness update" "$SD/blocks.log" | tail -1 | sed -E 's/.*\(([0-9]+) transactions with live notes, ([0-9]+) retired.*/\1 live, \2 retired/')
    r=$(rss)
    sz1=$(fsz "$SD/node0/regtest/wallet.dat")
    stop 0
    sz2=$(fsz "$SD/node0/regtest/wallet.dat")
    # the compact size of what the wallet holds: a copy rewritten by -salvagewallet on an empty chain
    mkdir -p "$SD/node6/regtest"; cp "$SD/node0/regtest/wallet.dat" "$SD/node6/regtest/wallet.dat"; cp "$SD/node0/zclassic.conf" "$SD/node6/"
    start 6 "$bd" -connect=0 -salvagewallet; stop 6
    sz3=$(fsz "$SD/node6/regtest/wallet.dat")
    # restart: time to RPC, wallet load, resident memory
    t0=$(now); start 0 "$bd" -connect=0 -disablesafemode -debug=bench || return 1
    t1b=$(elapsed "$t0")
    ld=$(grep '\[startup\] load wallet ' "$lg" | tail -1 | sed -E 's/.*load wallet +([0-9.]+) ms.*/\1/')
    r2=$(rss)
    stop 0
    {
        echo "$label|wallet.dat at the start (MiB)|$(mib "$sz0")"
        echo "$label|wallet.dat after $BLOCKS blocks, running (MiB)|$(mib "$sz1")"
        echo "$label|wallet.dat after the clean stop (MiB)|$(mib "$sz2")"
        echo "$label|wallet.dat rewritten by -salvagewallet (MiB)|$(mib "$sz3")"
        echo "$label|first start: time to RPC (s)|$t1"
        echo "$label|Callbacks per block, last 20 blocks (mean ms / max ms)|$(echo $cb | awk '{print $1" / "$2}')"
        echo "$label|wallet witness update per block (mean ms / max ms)|$(echo $wu | awk '{print $1" / "$2}') ($wutx)"
        echo "$label|Flush per block incl. the wallet checkpoint (mean ms / max ms)|$(echo $fl | awk '{print $1" / "$2}')"
        echo "$label|wallet checkpoint (mean ms / max ms), note transactions written|$(echo $cp_ | awk '{print $1" / "$2}'), $cpn"
        echo "$label|RSS / peak RSS while running (MiB)|$(echo $r | awk '{print $1" / "$2}')"
        echo "$label|restart: time to RPC (s)|$t1b"
        echo "$label|restart: wallet load (ms)|$ld"
        echo "$label|restart: RSS / peak RSS (MiB)|$(echo $r2 | awk '{print $1" / "$2}')"
    } >>"$PERF"
    stop 1
}


run_one before "$BEFORE" || say "before failed"
stop_all; iso_rebase BASE 112 11
run_one after "$AFTER" || say "after failed"
stop_all
say; say "| measurement | before | after |"; say "|---|---|---|"
cut -d'|' -f2 "$PERF" | awk '!s[$0]++' | while IFS= read -r m; do
    b=$(grep -F "before|$m|" "$PERF" | head -1 | cut -d'|' -f3-); a=$(grep -F "after|$m|" "$PERF" | head -1 | cut -d'|' -f3-)
    say "| $m | $b | $a |"
done
