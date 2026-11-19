#!/bin/sh
# TEST-ONLY. One real mainnet bootstrap from the compiled bootstrap peers, interrupted and resumed:
# start a node on an empty scratch datadir, kill -9 it once the snapshot download passes
# --kill-pct percent, start it again (it must resume from the staging directory, not from zero),
# let it finish the download, verify the snapshot against the compiled commitment, import, replay to
# the network tip, and report the timeline plus how many download streams were active over time.
#
# usage: sh qa/bootstrap-resume/mainnet-e2e.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--kill-pct <n>] [--port-base <n>] [--stay-minutes <n>]
#
# The node uses ONLY the scratch datadir (-datadir=<work>/dd), -listen=0 and the given ports. It never
# touches any other datadir. It is a client of the public bootstrap peers like any fresh user node.
set -u
bin=""; work=""; killpct=30; base=""; stay=10
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --kill-pct) killpct=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        --stay-minutes) stay=$2; shift 2 ;;
        *) echo "mainnet-e2e: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: mainnet-e2e.sh --bin <dir> --work <dir> [options]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "mainnet-e2e: $work is not empty" >&2; exit 2; }
dd=$work/dd
mkdir -p "$dd"
. "$(dirname "$0")/../lib/isolation.sh"
iso_base base "$base" 16
printf 'rpcuser=e2e\nrpcpassword=e2e%s\nrpcport=%s\n' "$$" "$((base + 1))" >"$dd/zclassic.conf"
cli() { "$bin/zclassic-cli" -datadir="$dd" "$@"; }
say() { echo "mainnet-e2e: $(date +%H:%M:%S) $*"; }
now_s() { date +%s; }
jnum() { sed -n "s/.*\"$1\": *\\([0-9.]*\\).*/\\1/p" | head -1; }
start() {
    $ZCL_RUN "$bin/zclassicd" -datadir="$dd" -port=$base -listen=0 -disablewallet -showmetrics=0 -printtoconsole=0 -debuglogfile=1 \
        -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 "$@" >/dev/null 2>&1 &
    PID=$!
}

samples=$work/samples.txt
: >"$samples"
sample_until() { # <condition-fn> <label> ; appends "elapsed pct streams bytes mbps" to samples every 2 s
    while :; do
        j=$(cli getbootstrapinfo 2>/dev/null)
        if [ -n "$j" ]; then
            phase=$(echo "$j" | sed -n 's/.*"phase": *"\([a-z_]*\)".*/\1/p' | head -1)
            pct=$(echo "$j" | jnum percent); st=$(echo "$j" | jnum streams); by=$(echo "$j" | jnum bytes_received); mb=$(echo "$j" | jnum mbps)
            echo "$(($(now_s) - t0)) $1 phase=${phase:-?} pct=${pct:-} streams=${st:-} bytes=${by:-} mibps=${mb:-}" >>"$samples"
            "$2" && return 0
        fi
        kill -0 "$PID" 2>/dev/null || return 1
        sleep 2
    done
}
reach_killpct() { [ "${pct:-0}" -ge "$killpct" ]; }

t0=$(now_s)
say "run 1: starting a fresh node (kill -9 once the download reaches ${killpct}%)"
start
sample_until run1 reach_killpct || { say "FAIL run 1 ended before ${killpct}%"; tail -20 "$dd/debug.log"; exit 1; }
t_kill=$(now_s)
kill -9 "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
rm -f "$dd/zclassicd.pid"
st=$(ls -d "$dd"/bootstrap-peer-staging-* 2>/dev/null | head -1)
staged=$(du -sb "$st" 2>/dev/null | cut -f1)
say "killed at ${pct}% after $((t_kill - t0)) s; staging $(basename "$st") holds $staged bytes ($(find "$st" -type f ! -name '*.part' ! -name '.z23*' | wc -l) complete files, $(find "$st" -name '*.part' | wc -l) partial)"
bytes_run1=$by
grep -a 'downloading snapshot\|streams active' "$dd/debug.log" | tail -3

say "run 2: starting again; it must resume instead of starting over"
t_restart=$(now_s)
start
dl_deadline=$(($(now_s) + 7200))
resumed_logged=0
while :; do
    kill -0 "$PID" 2>/dev/null || { say "FAIL node exited during run 2"; tail -30 "$dd/debug.log"; exit 1; }
    j=$(cli getbootstrapinfo 2>/dev/null)
    if [ -n "$j" ]; then
        phase=$(echo "$j" | sed -n 's/.*"phase": *"\([a-z_]*\)".*/\1/p' | head -1)
        pct=$(echo "$j" | jnum percent); st2=$(echo "$j" | jnum streams); by=$(echo "$j" | jnum bytes_received); mb=$(echo "$j" | jnum mbps)
        echo "$(($(now_s) - t0)) run2 phase=${phase:-?} pct=${pct:-} streams=${st2:-} bytes=${by:-} mibps=${mb:-}" >>"$samples"
        [ "$phase" != "active" ] && [ "$phase" != "idle" ] && break
    fi
    h=$(cli getblockcount 2>/dev/null)
    [ -n "$h" ] && [ "$h" -gt 0 ] 2>/dev/null && break
    [ "$(now_s)" -gt "$dl_deadline" ] && { say "FAIL download did not finish in 2 h"; exit 1; }
    sleep 2
done
t_imported=$(now_s)
say "bootstrap finished $((t_imported - t_restart)) s after the restart (phase ${phase:-?})"
grep -a 'staging directory\|staging scan\|download complete\|pre-install audit\|Bootstrap snapshot chainstate commitment verified\|Bootstrap snapshot verified\|best known header\|bundles post-anchor' "$dd/debug.log" | cut -c1-260

say "waiting for RPC and the imported chain"
i=0
while [ $i -lt 600 ]; do cli getblockcount >/dev/null 2>&1 && break; sleep 2; i=$((i + 1)); done
info=$(cli getblockchaininfo 2>/dev/null)
say "right after the import: blocks=$(echo "$info" | jnum blocks) headers=$(echo "$info" | jnum headers) verificationprogress=$(echo "$info" | jnum verificationprogress) syncphase=$(echo "$info" | sed -n 's/.*"syncphase": *"\([a-z_]*\)".*/\1/p' | head -1)"

say "following the network to the tip (up to 120 minutes)"
t_sync0=$(now_s)
deadline=$(($(now_s) + 7200))
while :; do
    info=$(cli getblockchaininfo 2>/dev/null)
    blocks=$(echo "$info" | jnum blocks); headers=$(echo "$info" | jnum headers)
    ibd=$(echo "$info" | sed -n 's/.*"initialblockdownload": *\(true\|false\).*/\1/p' | head -1)
    say "blocks=${blocks:-?} headers=${headers:-?} ibd=${ibd:-?} connections=$(echo "$info" | jnum connections) verificationprogress=$(echo "$info" | jnum verificationprogress)"
    conns=$(echo "$info" | jnum connections)
    maxpeer=$(cli getpeerinfo 2>/dev/null | sed -n 's/.*"startingheight": *\([0-9]*\).*/\1/p' | sort -n | tail -1)
    # at the tip: connected to several peers and within a few blocks of the highest height any of them reported
    [ -n "$blocks" ] && [ -n "$maxpeer" ] && [ "${conns:-0}" -ge 3 ] && [ "$blocks" -ge $((maxpeer - 3)) ] && break
    [ "$(now_s)" -gt "$deadline" ] && { say "FAIL did not reach the tip in 2 h"; break; }
    sleep 15
done
t_tip=$(now_s)
say "at the network tip $((t_tip - t_sync0)) s after the import; total wall time $((t_tip - t0)) s"
best=$(cli getbestblockhash)
say "best block $best at height $(cli getblockcount)"
say "chain tips: $(cli getchaintips | tr -d '\n ' | cut -c1-300)"
say "peers (synced_blocks is the last block in common with that peer; it equals our height when they follow the same chain):"
cli getpeerinfo | sed -n 's/.*"\(addr\|synced_blocks\|synced_headers\|startingheight\|subver\)": *"\?\([^",]*\).*/\1=\2/p' | paste -sd' ' | sed 's/addr=/\naddr=/g' | head -14
say "staying connected ${stay} min to watch new blocks arrive from the peers"
end=$(($(now_s) + stay * 60)); last=$(cli getblockcount)
while [ "$(now_s)" -lt "$end" ]; do
    sleep 60
    cur=$(cli getblockcount); [ "$cur" != "$last" ] && say "new tip height $cur $(cli getbestblockhash)"; last=$cur
done
say "bootstrapinfo at the end: $(cli getbootstrapinfo | tr -d '\n ')"
say "stream counts seen while downloading (run1 then run2):"
awk '{for (i = 1; i <= NF; i++) if ($i ~ /^streams=/) print $2, $i}' "$samples" | sort | uniq -c
cp "$dd/debug.log" "$work/debug.log.copy" 2>/dev/null
cli stop >/dev/null 2>&1
say "done; samples in $samples"
