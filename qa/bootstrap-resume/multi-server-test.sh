#!/bin/sh
# TEST-ONLY. Multi-server snapshot download against two local bootstrap servers on regtest.
#
# usage: sh qa/bootstrap-resume/multi-server-test.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--mode <list>] [--port-base <n>]
#            [--files <n>] [--file-mib <n>] [--kbps <n>] [--window-ms <n>] [--base-bin <dir>]
#
# Same fixture as resume-test.sh (a regtest chain frozen into a serve directory and padded with
# block files), copied once per server. Each server is rate limited with
# -bootstrapservemaxtotalkbps; the client is given both with two -bootstrappeer options.
#
# Modes (comma separated, default all):
#   speed     one capped server vs two capped servers (each capped alike): the time each takes, and the
#             bytes each server served. Expect close to 2x.
#   both      both servers get streams (getbootstrapinfo "servers"), no byte is fetched twice.
#   skew      one server capped at 1/8 of the other: the fast one serves most bytes and the total rate
#             approaches the sum of the two caps.
#   kill      one server is killed mid-download: the client finishes from the other.
#   diff      a server on another chain tip sharing no file: used for nothing; the result is the primary's snapshot.
#   share     a server on another chain tip sharing the block files: those come from both servers.
#   resume    the client is killed mid-download (files partly from both servers), restarted, finishes.
#   single    an explicit single -bootstrappeer puts all streams on it (as before).
# Every finished download must end on the server's best block with the same UTXO-set commitment.
# --base-bin runs the speed mode's single-server case with another binary for comparison.
# Never point this at a real datadir; it creates and deletes its own under --work.
set -u

bin=""; work=""; base=36100; modes="all"; files=16; filemib=16; kbps=65536; window=2000; basebin=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --mode) modes=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        --files) files=$2; shift 2 ;;
        --file-mib) filemib=$2; shift 2 ;;
        --kbps) kbps=$2; shift 2 ;;
        --window-ms) window=$2; shift 2 ;;
        --base-bin) basebin=$2; shift 2 ;;
        *) echo "multi-server-test: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: multi-server-test.sh --bin <dir> --work <dir> [options]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "multi-server-test: $work is not empty" >&2; exit 2; }

sp1=$base; sr1=$((base + 1)); sp2=$((base + 2)); sr2=$((base + 3)); cp=$((base + 4)); cr=$((base + 5)); gp=$((base + 6)); gr=$((base + 7))
common="-regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -debuglogfile=1 -printtoconsole=0 -showmetrics=0 -disablewallet"
failures=0
want() { case ",$modes," in *,"$1",*|*,all,*) return 0 ;; esac; return 1; }
say() { echo "multi-server-test: $*"; }
pass() { echo "multi-server-test: PASS $*"; }
fail() { echo "multi-server-test: FAIL $*"; failures=$((failures + 1)); }

mkconf() { mkdir -p "$1/regtest" && printf 'rpcuser=bs\nrpcpassword=bs%s\nrpcport=%s\n' "$$" "$2" >"$1/zclassic.conf"; }
cli() { b=$1; d=$2; shift 2; "$b/zclassic-cli" -regtest -datadir="$d" "$@"; }
wait_rpc() { i=0; lim=${3:-120}; while [ $i -lt $lim ]; do cli "$1" "$2" getblockcount >/dev/null 2>&1 && return 0; sleep 1; i=$((i + 1)); done; return 1; }
stop_node() { cli "$1" "$2" stop >/dev/null 2>&1; i=0; while [ $i -lt 90 ] && [ -f "$2/regtest/zclassicd.pid" ]; do sleep 1; i=$((i + 1)); done; }
now_ms() { date +%s%3N; }
json_num() { sed -n "s/.*\"$1\": *\\([0-9.]*\\).*/\\1/p" | head -1; }

srcdir=$work/src; serve1=$work/serve1; serve2=$work/serve2; serve_diff=$work/serve_diff; serve_share=$work/serve_share; sdir1=$work/server1; sdir2=$work/server2; cdir=$work/client
make_fixture() {
    say "building the regtest fixture ($files padding files of ~$filemib MiB, two copies)"
    mkconf "$srcdir" "$gr"
    "$bin/zclassicd" -regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 \
        -rpcallowip=127.0.0.1 -debuglogfile=1 -printtoconsole=0 -showmetrics=0 -bootstrap=0 \
        -datadir="$srcdir" -port=$gp -listen=0 -connect=0 -daemon >/dev/null 2>&1 || return 1
    wait_rpc "$bin" "$srcdir" || return 1
    cli "$bin" "$srcdir" generate 220 >/dev/null || return 1
    info=$(cli "$bin" "$srcdir" gettxoutsetinfo) || return 1
    fx_height=$(echo "$info" | sed -n 's/.*"height": *\([0-9]*\).*/\1/p' | head -1)
    fx_best=$(echo "$info" | sed -n 's/.*"bestblock": *"\([0-9a-f]*\)".*/\1/p' | head -1)
    fx_commit=$(echo "$info" | sed -n 's/.*"hash_chainstate_full": *"\([0-9a-f]*\)".*/\1/p' | head -1)
    [ -n "$fx_height" ] && [ -n "$fx_best" ] && [ -n "$fx_commit" ] || { echo "no txoutsetinfo: $info"; return 1; }
    stop_node "$bin" "$srcdir"
    mkdir -p "$serve1"
    cp -a "$srcdir/regtest/blocks" "$serve1/blocks" && cp -a "$srcdir/regtest/chainstate" "$serve1/chainstate" || return 1
    rm -f "$serve1/blocks/index/LOCK" "$serve1/chainstate/LOCK"
    head -c $((filemib * 1048576)) /dev/urandom >"$work/pad.bin"
    i=1
    while [ $i -le "$files" ]; do
        { printf 'padding-file-%s-' "$i"; head -c $((filemib * 1048576 - i * 4097)) "$work/pad.bin"; } >"$serve1/blocks/blk$(printf '%05d' "$i").dat"
        i=$((i + 1))
    done
    rm -f "$work/pad.bin"
    cp -a "$serve1" "$serve2" || return 1
    # another chain tip (three more blocks) for the "diff" mode: a different height and commitment
    "$bin/zclassicd" -regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 \
        -rpcallowip=127.0.0.1 -debuglogfile=1 -printtoconsole=0 -showmetrics=0 -bootstrap=0 \
        -datadir="$srcdir" -port=$gp -listen=0 -connect=0 -daemon >/dev/null 2>&1 || return 1
    wait_rpc "$bin" "$srcdir" || return 1
    cli "$bin" "$srcdir" generate 3 >/dev/null || return 1
    info=$(cli "$bin" "$srcdir" gettxoutsetinfo) || return 1
    d_height=$(echo "$info" | sed -n 's/.*"height": *\([0-9]*\).*/\1/p' | head -1)
    d_best=$(echo "$info" | sed -n 's/.*"bestblock": *"\([0-9a-f]*\)".*/\1/p' | head -1)
    d_commit=$(echo "$info" | sed -n 's/.*"hash_chainstate_full": *"\([0-9a-f]*\)".*/\1/p' | head -1)
    [ -n "$d_height" ] && [ -n "$d_best" ] && [ -n "$d_commit" ] || { echo "no txoutsetinfo for the other tip: $info"; return 1; }
    echo "$d_height $d_best $d_commit" >"$work/serve_diff.meta"; echo "$d_height $d_best $d_commit" >"$work/serve_share.meta"
    stop_node "$bin" "$srcdir"
    mkdir -p "$serve_diff" && cp -a "$srcdir/regtest/blocks" "$serve_diff/blocks" && cp -a "$srcdir/regtest/chainstate" "$serve_diff/chainstate" || return 1
    rm -f "$serve_diff/blocks/index/LOCK" "$serve_diff/chainstate/LOCK"
    cp -a "$serve_diff" "$serve_share" && i=1 && while [ $i -le "$files" ]; do cp -a "$serve1/blocks/blk$(printf '%05d' "$i").dat" "$serve_share/blocks/" || return 1; i=$((i + 1)); done
    echo "$fx_height $fx_best $fx_commit" >"$work/serve1.meta"; echo "$fx_height $fx_best $fx_commit" >"$work/serve2.meta"
    snapshot_bytes=$(find "$serve1" -type f -printf '%s\n' | awk '{s += $1} END {print s}')
    say "fixture: height $fx_height best $fx_best commitment $fx_commit; $snapshot_bytes bytes"
}

start_server() { # <n 1|2> <kbps> [extra]
    n=$1; k=$2; shift 2
    eval "sd=\$sdir$n; sv=\$serve$n; spn=\$sp$n; srn=\$sr$n"
    mkconf "$sd" "$srn"
    "$bin/zclassicd" $common -bootstrap=0 -datadir="$sd" -port=$spn -listen=1 -connect=0 \
        -bootstrapserve=1 -bootstrapsourcedir="$sv" -bootstrapservemaxtotalkbps=$k \
        -debug=net -bootstrapservemaxbytesperday=0 "$@" >/dev/null 2>&1 &
    eval "SPID$n=$!"
    wait_rpc "$bin" "$sd" 60 || { fail "server $n did not start (see $sd/regtest/debug.log)"; tail -5 "$sd/regtest/debug.log"; return 1; }
}
stop_server() { # <n>
    eval "sd=\$sdir$1; p=\$SPID$1"
    stop_node "$bin" "$sd"; wait "$p" 2>/dev/null
}
kill_server() { # <n> : SIGKILL
    eval "p=\$SPID$1"; kill -9 "$p" 2>/dev/null; wait "$p" 2>/dev/null
}
client_bin=$bin
start_client() { # <peer list: "1" "2" or "1 2"> [extra args]
    peers=$1; shift
    mkconf "$cdir" "$cr"
    pargs=""
    for p in $peers; do eval "pp=\$sp$p"; pargs="$pargs -bootstrappeer=127.0.0.1:$pp"; done
    "$client_bin/zclassicd" $common -datadir="$cdir" -port=$cp -listen=0 -connect=0 -bootstrap=1 \
        -bootstrapmode=trustless -bootstrapschedwindowms=$window $pargs "$@" >/dev/null 2>&1 &
    CPID=$!
}
kill_client() { kill -9 "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null; rm -f "$cdir/regtest/zclassicd.pid" "$cdir/regtest/.lock"; }
end_client() { { echo "== client log at the end of a run"; grep -a "Bootstrap:" "$client_log"; } >>"$work/client-bootstrap-all.log" 2>/dev/null; stop_node "$client_bin" "$cdir"; wait "$CPID" 2>/dev/null; }
fresh_client() { rm -rf "$cdir"; }
client_log=$cdir/regtest/debug.log
served_bytes() { # <n> [from-line]
    tail -n +"${2:-1}" "$work/server$1/regtest/debug.log" | grep -a 'sending bootstrap snapshot chunk' |
        sed 's/.*bytes=\([0-9]*\).*/\1/' | awk '{s += $1} END {print s + 0}'
}
log_lines() { wc -l <"$work/server$1/regtest/debug.log" 2>/dev/null || echo 0; }
wait_imported() { # waits for the fixture height; prints nothing
    i=0
    while [ $i -lt "${WAIT_ITER:-400}" ]; do
        h=$(cli "$client_bin" "$cdir" getblockcount 2>/dev/null)
        [ "$h" = "$fx_height" ] && return 0
        kill -0 "$CPID" 2>/dev/null || return 1
        sleep 0.5; i=$((i + 1))
    done
    return 1
}
check_imported() { # <label>
    h=$(cli "$client_bin" "$cdir" getblockcount 2>/dev/null)
    b=$(cli "$client_bin" "$cdir" getbestblockhash 2>/dev/null)
    c=$(cli "$client_bin" "$cdir" gettxoutsetinfo 2>/dev/null | sed -n 's/.*"hash_chainstate_full": *"\([0-9a-f]*\)".*/\1/p' | head -1)
    if [ "$h" = "$fx_height" ] && [ "$b" = "$fx_best" ] && [ "$c" = "$fx_commit" ]; then
        pass "$1: imported height $h, best block and UTXO-set commitment equal the servers'"
        return 0
    fi
    fail "$1: client height '$h' best '$b' commitment '$c', expected $fx_height $fx_best $fx_commit"
    return 1
}
# runs a whole download, returns after import; sets DL_MS
download() { # <peers> [extra client args]
    t0=$(now_ms); start_client "$@"
    wait_imported || { fail "client did not finish (see $client_log)"; tail -15 "$client_log"; return 1; }
    DL_MS=$(( $(now_ms) - t0 ))
    DL_CPU=$(awk '{printf "%.1f", ($14 + $15) / 100}' /proc/$CPID/stat 2>/dev/null)
    DL_RB=$(sed -n "s/^rchar: //p" /proc/$CPID/io 2>/dev/null)
    DL_WB=$(sed -n "s/^wchar: //p" /proc/$CPID/io 2>/dev/null)
    { echo "== download $*"; grep -a "Bootstrap:" "$client_log"; } >>"$work/client-bootstrap.log" 2>/dev/null
    return 0
}

test_speed() {
    say "== speed: one capped server vs two capped servers ($kbps kbit/s each) =="
    fresh_client; start_server 1 $kbps || return 1
    l1=$(log_lines 1)
    if [ -n "$basebin" ]; then client_bin=$basebin; fi
    download "1" || { stop_server 1; client_bin=$bin; return 1; }
    client_bin=$bin
    SINGLE_MS=$DL_MS
    one_ms=$DL_MS; one_b=$(served_bytes 1 $l1); one_cpu=$DL_CPU
    check_imported "speed (one server)"; end_client; stop_server 1
    fresh_client; start_server 1 $kbps && start_server 2 $kbps || return 1
    l1=$(log_lines 1); l2=$(log_lines 2)
    download "1 2" || { stop_server 1; stop_server 2; return 1; }
    two_ms=$DL_MS; b1=$(served_bytes 1 $l1); b2=$(served_bytes 2 $l2)
    check_imported "speed (two servers)"
    say "RESULT speed: one server $((one_ms / 1000)).$((one_ms % 1000 / 100)) s ($one_b bytes, client CPU ${one_cpu:-?} s); two servers $((two_ms / 1000)).$((two_ms % 1000 / 100)) s (server 1 $b1 bytes, server 2 $b2 bytes); speedup $(awk -v a=$one_ms -v b=$two_ms 'BEGIN {printf "%.2f", a / b}')x"
    [ "$b1" -gt 0 ] && [ "$b2" -gt 0 ] && pass "speed: both servers served bytes" || fail "speed: a server served nothing"
    total=$((b1 + b2))
    # Bytes served beyond the snapshot are the in-flight windows (16 chunks of 1 MiB) of streams moved off a
    # server; every such move is logged, so the waste must be explained by the moves (plus 2% slack).
    moves=$(grep -ac 'moves off' "$client_log"); moves=${moves:-0}
    allowed=$((snapshot_bytes + snapshot_bytes / 50 + moves * 16 * 1048576))
    [ "$total" -le "$allowed" ] && pass "speed: $total bytes served in total for a $snapshot_bytes byte snapshot ($moves stream moves, bound $allowed)" || fail "speed: $total bytes served for a $snapshot_bytes byte snapshot ($moves stream moves, bound $allowed)"
    grep -a 'bytes by server\|from 2 servers' "$client_log" | tail -2
    end_client; stop_server 1; stop_server 2
}

# One uncapped (or --kbps capped) server, one client run with --base-bin (default --bin): the download time and
# the client's CPU, for comparing two binaries on the same fixture. Not part of "all".
test_one() {
    say "== one server, one client ($client_bin) =="
    fresh_client; start_server 1 $kbps || return 1
    l1=$(log_lines 1)
    if [ -n "$basebin" ]; then client_bin=$basebin; fi
    download "1" || { stop_server 1; client_bin=$bin; return 1; }
    check_imported "one"
    dl=$(grep -a 'download complete' "$client_log" | tail -1 | sed 's/.*complete: //')
    say "RESULT one: $((DL_MS / 1000)).$((DL_MS % 1000 / 100)) s to height, client CPU ${DL_CPU:-?} s, file bytes read ${DL_RB:-?} written ${DL_WB:-?}, $(served_bytes 1 $l1) bytes served; $dl"
    end_client; stop_server 1; client_bin=$bin
}

# The same two servers, one of them throttled, for an old and a new client (--base-bin: the old one), each
# with the throttled server listed first and last. Not part of "all". An old client uses one server only.
test_cmp() {
    low=$((kbps / 8))
    WAIT_ITER=2400 # an old client stays on the throttled server
    say "== comparison: server 1 capped at $low kbit/s, server 2 at $kbps; old = ${basebin:-none}, new = $bin =="
    for order in "1 2" "2 1"; do
        for who in old new; do
            if [ $who = old ]; then [ -n "$basebin" ] || continue; client_bin=$basebin; else client_bin=$bin; fi
            fresh_client; start_server 1 $low && start_server 2 $kbps || { client_bin=$bin; return 1; }
            download "$order" || { stop_server 1; stop_server 2; client_bin=$bin; return 1; }
            check_imported "cmp $who ($order)"
            say "RESULT cmp: $who client, peers listed \"$order\": $((DL_MS / 1000)).$((DL_MS % 1000 / 100)) s, $(awk -v b=$snapshot_bytes -v ms=$DL_MS 'BEGIN {printf "%.1f", b / 1048576 / (ms / 1000)}') MiB/s (server 1 is the throttled one)"
            end_client; stop_server 1; stop_server 2
            client_bin=$bin
        done
    done
}

test_both() {
    say "== both servers get streams, getbootstrapinfo shows them =="
    fresh_client; start_server 1 $kbps && start_server 2 $kbps || return 1
    start_client "1 2"
    seen=0; sn=0
    i=0
    while [ $i -lt "${WAIT_ITER:-400}" ]; do
        j=$(cli "$client_bin" "$cdir" getbootstrapinfo 2>/dev/null)
        n=$(echo "$j" | json_num servers_in_use)
        if [ "${n:-0}" = 2 ]; then seen=1; sn=$(echo "$j" | grep -c '"state": *"ok"'); echo "$j" | tr -d '\n ' | sed 's/.*"servers"/"servers"/' | cut -c1-300; break; fi
        kill -0 "$CPID" 2>/dev/null || break
        sleep 0.25; i=$((i + 1))
    done
    [ $seen = 1 ] && pass "both: getbootstrapinfo reported servers_in_use 2 ($sn servers listed ok)" || fail "both: never saw servers_in_use 2"
    wait_imported || fail "both: client did not finish"
    check_imported "both"
    pr=$(grep -a 'Bootstrap snapshot:' "$client_log" | tail -1); say "last status line: ${pr:-n/a}"
    end_client; stop_server 1; stop_server 2
}

test_skew() {
    low=$((kbps / 8))
    say "== skew: server 1 capped at $low kbit/s, server 2 at $kbps =="
    fresh_client; start_server 1 $low && start_server 2 $kbps || return 1
    # the best single server on the same fixture: what two servers must not fall behind
    download "2" || { stop_server 1; stop_server 2; return 1; }
    alone_ms=$DL_MS
    check_imported "skew (fast server alone)"
    end_client
    fresh_client
    l1=$(log_lines 1); l2=$(log_lines 2)
    download "1 2" || { stop_server 1; stop_server 2; return 1; }
    b1=$(served_bytes 1 $l1); b2=$(served_bytes 2 $l2)
    rate=$(awk -v b=$snapshot_bytes -v ms=$DL_MS 'BEGIN {printf "%.1f", b / 1048576 / (ms / 1000)}')
    alone=$(awk -v b=$snapshot_bytes -v ms=$alone_ms 'BEGIN {printf "%.1f", b / 1048576 / (ms / 1000)}')
    sum=$(awk -v a=$low -v b=$kbps 'BEGIN {printf "%.1f", (a + b) * 1000 / 8 / 1048576}')
    say "RESULT skew: $((DL_MS / 1000)) s, $rate MiB/s with both (caps sum $sum MiB/s); the fast server alone $((alone_ms / 1000)) s, $alone MiB/s; slow server served $b1 bytes, fast $b2 bytes"
    check_imported "skew"
    [ "$b2" -gt $((b1 * 2)) ] && pass "skew: the fast server served most bytes" || fail "skew: fast server $b2 vs slow $b1"
    # two servers must never be slower than the best one alone by more than noise (30%: sequential runs vary that much on a loaded host)
    [ $((DL_MS * 100)) -le $((alone_ms * 130)) ] && pass "skew: both servers ($DL_MS ms) are not slower than the fast one alone ($alone_ms ms)" || fail "skew: both servers took $DL_MS ms, the fast one alone $alone_ms ms"
    grep -a 'moves off' "$client_log" | head -5
    end_client; stop_server 1; stop_server 2
}

# The single-server time on this fixture (measured once, or taken from the speed mode): what a download that loses or
# only partly uses a second server is compared with.
SINGLE_MS=""
need_single() {
    [ -n "$SINGLE_MS" ] && return 0
    say "(measuring the single-server time first)"
    fresh_client; start_server 1 $kbps || return 1
    download "1" || { stop_server 1; return 1; }
    SINGLE_MS=$DL_MS
    end_client; stop_server 1
    say "single server: $((SINGLE_MS / 1000)).$((SINGLE_MS % 1000 / 100)) s"
}

test_kill() {
    say "== kill server 2 at ~35% =="
    need_single || return 1
    fresh_client; start_server 1 $kbps && start_server 2 $kbps || return 1
    kt0=$(now_ms)
    start_client "1 2"
    pct=0
    while [ "$pct" -lt 35 ]; do
        j=$(cli "$client_bin" "$cdir" getbootstrapinfo 2>/dev/null)
        pct=$(echo "$j" | json_num percent); pct=${pct:-0}
        kill -0 "$CPID" 2>/dev/null || { fail "kill: client exited early"; stop_server 1; stop_server 2; return 1; }
        sleep 0.2
    done
    kill_server 2
    say "killed server 2 at ${pct}%"
    if wait_imported; then
        check_imported "kill"
        kms=$(($(now_ms) - kt0))
        say "RESULT kill: $((kms / 1000)).$((kms % 1000 / 100)) s with server 2 killed at ${pct}% (single server $((SINGLE_MS / 1000)).$((SINGLE_MS % 1000 / 100)) s)"
        # two servers for the first third, one for the rest: well under the single-server time; a client that keeps
        # sending streams to the dead server takes far longer
        [ $kms -le $((SINGLE_MS * 130 / 100 + 5000)) ] && pass "kill: finished in $kms ms, within 1.3x the single-server time ($SINGLE_MS ms) plus 5 s" || fail "kill: took $kms ms, the single-server time is $SINGLE_MS ms"
    else fail "kill: client did not finish from the other server"; tail -15 "$client_log"; fi
    grep -a 'failed on\|stream .* moves' "$client_log" | tail -4
    end_client; stop_server 1
}

# Server 2 holds another chain tip (three blocks further): another height, best block and commitment.
# The download is always server 1's snapshot; server 2 may supply only files whose path, size and
# SHA-256 equal server 1's manifest entries, and the result must equal server 1's chain.
other_tip() { # <label> <serve dir of server 2> <log message expected>
    lbl=$1; saved2=$serve2; serve2=$2; want_msg=$3
    need_single || return 1
    fresh_client; start_server 1 $kbps && start_server 2 $kbps || { serve2=$saved2; return 1; }
    l1=$(log_lines 1); l2=$(log_lines 2)
    download "1 2" || { serve2=$saved2; stop_server 1; stop_server 2; return 1; }
    check_imported "$lbl"
    b1=$(served_bytes 1 $l1); b2=$(served_bytes 2 $l2)
    grep -aq "$want_msg" "$client_log" && pass "$lbl: the client logged '$want_msg'" || fail "$lbl: no '$want_msg' message"
    say "RESULT $lbl: $((DL_MS / 1000)).$((DL_MS % 1000 / 100)) s (single server $((SINGLE_MS / 1000)).$((SINGLE_MS % 1000 / 100)) s); server 1 served $b1 bytes, server 2 (other tip) served $b2 bytes, snapshot $snapshot_bytes"
    [ $DL_MS -le $((SINGLE_MS * 115 / 100 + 2000)) ] && pass "$lbl: finished in $DL_MS ms, within 1.15x the single-server time ($SINGLE_MS ms) plus 2 s" || fail "$lbl: took $DL_MS ms, the single-server time is $SINGLE_MS ms"
    OT_B1=$b1; OT_B2=$b2
    end_client; stop_server 1; stop_server 2
    serve2=$saved2
}
test_diff() {
    say "== server 2 on another chain tip sharing (almost) no file =="
    other_tip diff "$serve_diff" "serves a different snapshot" || return 1
    [ "$OT_B2" -le $((snapshot_bytes / 20)) ] && pass "diff: server 2 supplied almost nothing ($OT_B2 bytes)" || fail "diff: server 2 served $OT_B2 bytes"
}
test_share() {
    say "== server 2 on another chain tip sharing the padding (block) files =="
    other_tip share "$serve_share" "has a different manifest but" || return 1
    [ "$OT_B1" -gt 0 ] && [ "$OT_B2" -gt 0 ] && pass "share: the shared files came from both servers" || fail "share: server 1 served $OT_B1, server 2 served $OT_B2"
    [ "$OT_B1" -le $((snapshot_bytes + snapshot_bytes / 20)) ] || fail "share: server 1 served more than the snapshot"
}

test_resume() {
    say "== kill the client at ~40%, restart with both servers =="
    fresh_client; start_server 1 $kbps && start_server 2 $kbps || return 1
    l1=$(log_lines 1); l2=$(log_lines 2)
    start_client "1 2"
    pct=0
    while [ "$pct" -lt 40 ]; do
        j=$(cli "$client_bin" "$cdir" getbootstrapinfo 2>/dev/null)
        pct=$(echo "$j" | json_num percent); pct=${pct:-0}
        kill -0 "$CPID" 2>/dev/null || { fail "resume: client exited early"; stop_server 1; stop_server 2; return 1; }
        sleep 0.2
    done
    kill_client
    s1=$(served_bytes 1 $l1); s2=$(served_bytes 2 $l2)
    st=$(ls -d "$cdir"/regtest/bootstrap-peer-staging-* 2>/dev/null | head -1)
    say "killed at ${pct}%: server 1 served $s1, server 2 served $s2; staged $(find "$st" -type f ! -name '*.part' ! -name '.z23-staging*' | wc -l) files, $(find "$st" -type f -name '*.part' | wc -l) partial"
    [ "$s1" -gt 0 ] && [ "$s2" -gt 0 ] && pass "resume: files were fetched from both servers before the kill" || fail "resume: one server served nothing before the kill"
    start_client "2 1"
    if wait_imported; then check_imported "resume"; else fail "resume: restarted client did not finish"; tail -15 "$client_log"; fi
    t1=$(served_bytes 1 $l1); t2=$(served_bytes 2 $l2)
    total=$((t1 + t2))
    say "RESULT resume: $total bytes served in total for a $snapshot_bytes byte snapshot (ratio $(awk -v a=$total -v b=$snapshot_bytes 'BEGIN {printf "%.3f", a / b}'))"
    grep -a 'staging scan' "$client_log" | tail -1
    end_client; stop_server 1; stop_server 2
}

test_single() {
    say "== explicit single -bootstrappeer: all streams on it =="
    fresh_client; start_server 1 $kbps && start_server 2 $kbps || return 1
    l2=$(log_lines 2)
    download "1" || { stop_server 1; stop_server 2; return 1; }
    check_imported "single"
    b2=$(served_bytes 2 $l2)
    [ "$b2" -eq 0 ] && pass "single: the other server was not used" || fail "single: server 2 served $b2 bytes"
    end_client; stop_server 1; stop_server 2
}

make_fixture || { echo "multi-server-test: could not build the fixture"; exit 1; }
case ",$modes," in *,one,*) test_one ;; esac
case ",$modes," in *,cmp,*) test_cmp ;; esac
want speed && test_speed
want both && test_both
want skew && test_skew
want kill && test_kill
want diff && test_diff
want share && test_share
want resume && test_resume
want single && test_single

if [ $failures -eq 0 ]; then echo "multi-server-test: ALL PASSED"; exit 0; fi
echo "multi-server-test: $failures FAILURE(S)"
exit 1
