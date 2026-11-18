#!/bin/bash
# Peak RSS and wall time of a z_sendmany at various prover thread settings.
# Linux reads VmHWM from /proc; elsewhere (macOS) the peak is the maximum of a 50 ms `ps -o rss=` sampler.
# A pt of 0 is the default (automatic) setting; any other value is an explicit -proverthreads.
# usage: prover_memory_bench.sh --bin DIR --work DIR [--peer-bin DIR] [--base PORT]
#   env PT_LIST="1 4 0"  N_LIST="1 5 20 40"  R=1  EXTRA="-opt ..."
#   env DAEMON_ENV  "VAR=val" exported to the node 0 daemon only (e.g. MALLOC_ARENA_MAX=2)
#   env OUT=<file>  where the result lines go (default <work>/bench.txt)
# Regtest only, temporary datadirs under --work; pick --base inside a free port range.
BIN=""; WORK=""; PEER_BIN=""; PORT_BASE=51000
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;;
        --base) PORT_BASE=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
PEER_BIN=${PEER_BIN:-$BIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
SCN_ID=bench; SCN_LOG=$WORK/bench.log; OBS_LOG=$WORK/obs.txt; : >"$SCN_LOG"
SD=$WORK/sbench; rm -rf "$SD"; mkdir -p "$SD"
BASE=$PORT_BASE
trap 'peak_stop; stop_all' EXIT
OUT=${OUT:-$WORK/bench.txt}; : >"$OUT"

# 0.1 s polling (the library's wait_op polls once a second)
wait_op() {
    [ -n "$2" ] || { echo "failed (no operation id)"; return 0; }
    local t s; t=0
    while :; do
        s=$(cli "$1" z_getoperationstatus "[\"$2\"]" | jq -c '.[0]')
        case $(printf '%s' "$s" | jq -r .status) in
            success) printf 'success %s\n' "$(printf '%s' "$s" | jq -r .result.txid)"; return 0 ;;
            failed) printf 'failed %s\n' "$(printf '%s' "$s" | jq -r .error.message)"; return 0 ;;
        esac
        t=$((t + 1)); [ $t -lt 18000 ] || { echo "timeout"; return 1; }
        sleep 0.1
    done
}

fund_notes() {
    local n=$1 zs=$2 cnt=$3 amt=$4 addrs json ops ta op r
    cli 1 generate 3 >/dev/null
    addrs=$(for i in $(seq 1 "$cnt"); do cli 1 getnewaddress; done)
    json=$(printf '%s\n' "$addrs" | jq -Rsc --argjson a "$(add "$amt" 0.001)" 'split("\n")[:-1]|map({key:.,value:$a})|from_entries')
    cli 1 sendmany "" "$json" >/dev/null; cli 1 generate 1 >/dev/null
    ops=""; for ta in $addrs; do op=$(cli 1 z_sendmany "$ta" "[{\"address\":\"$zs\",\"amount\":$amt}]" 1 0.001); ops="$ops $op"; done
    for op in $ops; do r=$(wait_op 1 "$op"); case $r in success*) ;; *) echo "fund fail $r" >&2 ;; esac; done
    cli 1 generate 1 >/dev/null; sync_to "$n"
}
zrecips() { for k in $(seq 1 "$1"); do cli 1 z_getnewaddress; done | jq -Rsc --argjson amt "$2" 'split("\n")[:-1]|map({address:.,amount:$amt})'; }
status_kb() { # pid key; VmHWM falls back to the sampled peak when /proc is absent
    if [ -r "/proc/$1/status" ]; then awk -v k="$2" '$1==k":" {print $2}' "/proc/$1/status"; return; fi
    case $2 in
        VmHWM) cat "$PEAK_FILE" 2>/dev/null ;;
        *) ps -o rss= -p "$1" | tr -d " " ;;
    esac
}
PEAK_FILE=$WORK/peak_rss_kb; SAMPLER=""
peak_start() { # pid: sample RSS every 50 ms into $PEAK_FILE (no /proc here)
    [ -r "/proc/$1/status" ] && { echo 5 >"/proc/$1/clear_refs"; return; }
    : >"$PEAK_FILE"
    ( m=0; while kill -0 "$1" 2>/dev/null; do r=$(ps -o rss= -p "$1" | tr -d " "); [ -n "$r" ] && [ "$r" -gt "$m" ] && { m=$r; echo "$m" >"$PEAK_FILE"; }; sleep 0.05; done ) &
    SAMPLER=$!
}
peak_stop() { [ -n "$SAMPLER" ] && { kill "$SAMPLER" 2>/dev/null; wait "$SAMPLER" 2>/dev/null; SAMPLER=""; }; }

start 1 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 0)) || exit 1
cli 1 generate 112 >/dev/null
for pt in ${PT_LIST:-1 4 0}; do
    if [ -f "$SD/node0/pid" ]; then stop 0; fi
    ( export ${DAEMON_ENV:-DUMMY=1}; start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) -proverthreads=$pt $EXTRA ) || exit 1
    sync_to 0
    pid=$(cat "$SD/node0/pid")
    for N in ${N_LIST:-1 5 20 40}; do
        R=${R:-1}
        zs=$(cli 0 z_getnewaddress); cli 1 generate 30 >/dev/null; sync_to 0
        fund_notes 0 "$zs" "$N" 1
        total=$(add "$N" -0.5); per=$(awk -v t="$total" -v r="$R" 'BEGIN { printf "%.8f", t / r }')
        rec=$(zrecips "$R" "$per")
        sleep 3
        rss0=$(status_kb "$pid" VmRSS)
        peak_start "$pid"
        t0=$(now)
        r=$(zsend 0 "$zs" "$rec" 1 "$FEE"); t=$(elapsed "$t0")
        hwm=$(status_kb "$pid" VmHWM); rss1=$(status_kb "$pid" VmRSS)
        peak_stop
        sleep 5; rss2=$(status_kb "$pid" VmRSS)
        case $r in success*) wait_mempool 1 "${r#success }"; mine 1; st=ok ;; *) st="FAIL:$r" ;; esac
        line="pt=$pt N=$N R=$R time=${t}s hwm_kb=$hwm rss_before_kb=$rss0 rss_after_kb=$rss1 rss_after5s_kb=$rss2 $st"
        echo "$line" | tee -a "$OUT"
    done
done
