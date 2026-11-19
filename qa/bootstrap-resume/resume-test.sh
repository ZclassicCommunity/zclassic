#!/bin/sh
# TEST-ONLY. Kill-and-resume, corruption, manifest-change and stream-recovery tests for
# the bootstrap snapshot download, against a local bootstrap server on regtest.
#
# usage: sh qa/bootstrap-resume/resume-test.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--mode <list>] [--port-base <n>]
#            [--kills <n>] [--files <n>] [--file-mib <n>] [--kbps <n>]
#            [--old-server-bin <dir>] [--old-client-bin <dir>]
#
# How it works. A regtest chain is mined, frozen into a "serve" directory exactly like a
# self-snapshot (blocks/, chainstate/ plus a ".meta" with the UTXO-set commitment), and padded
# with --files extra block files of ~--file-mib MiB so the download takes a while. A server node
# (-bootstrapserve, rate limited with -bootstrapservemaxtotalkbps) serves it. A client with a
# fresh datadir fetches it with -bootstrapmode=trustless -bootstrappeer=127.0.0.1:<port>: the same
# BootstrapFromPeer / parallel downloader / staging code as mainnet; only the final trust anchor
# differs (regtest has no compiled anchor, so the v2 trustless commitment path is used).
#
# Modes (comma separated, default all):
#   kills     kill -9 the client at random instants --kills times, restart each time, finish; the
#             imported chain must end on the server's best block, and the bytes the server served in
#             total must stay close to one copy of the snapshot.
#   single    one interrupted sync (kill at ~30%), restart, finish: time and bytes.
#   corrupt   flip a byte in a staged complete file and truncate another; restart: both are detected
#             and fetched again, never imported.
#   manifest  grow the served snapshot between runs (same anchor: staged files are reused), then serve
#             a different snapshot (staging is discarded).
#   stream    cut one client stream at the server mid-download: parallelism must come back.
#   slots     the server serves at most --slots peers at once (-bootstrapservemaxpeers); how does a
#             4-stream client fare? (not part of "all": it takes a minute of timeouts on old servers)
#   interop   new client against an OLD server binary and an OLD client against the new server.
# Never point this at a real datadir; it creates and deletes its own under --work.
set -u

bin=""; work=""; base=""; modes="all"; kills=32; files=24; filemib=24; kbps=262144
oldserver=""; oldclient=""; serverargs=""; slots=3
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --mode) modes=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        --kills) kills=$2; shift 2 ;;
        --files) files=$2; shift 2 ;;
        --file-mib) filemib=$2; shift 2 ;;
        --kbps) kbps=$2; shift 2 ;;
        --old-server-bin) oldserver=$2; shift 2 ;;
        --old-client-bin) oldclient=$2; shift 2 ;;
        --server-args) serverargs=$2; shift 2 ;;
        --slots) slots=$2; shift 2 ;;
        *) echo "resume-test: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: resume-test.sh --bin <dir> --work <dir> [options]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "resume-test: $work is not empty" >&2; exit 2; }

. "$(dirname "$0")/../lib/isolation.sh"
. "$(dirname "$0")/../rpc-tests/jsonq_lib.sh"
iso_base base "$base" 16
sp=$base; sr=$((base + 1)); cp=$((base + 2)); cr=$((base + 3)); op=$((base + 4)); orp=$((base + 5)); gp=$((base + 6)); gr=$((base + 7))
common="-regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -debuglogfile=1 -printtoconsole=0 -showmetrics=0 -disablewallet"
failures=0
want() {
    case ",$modes," in *,"$1",*) return 0 ;; esac
    [ "$1" != slots ] && case ",$modes," in *,all,*) return 0 ;; esac
    return 1
}
say() { echo "resume-test: $*"; }
pass() { echo "resume-test: PASS $*"; }
fail() { echo "resume-test: FAIL $*"; failures=$((failures + 1)); }

mkconf() { # <datadir> <rpcport>
    mkdir -p "$1/regtest" && printf 'rpcuser=bs\nrpcpassword=bs%s\nrpcport=%s\n' "$$" "$2" >"$1/zclassic.conf"
}
cli() { # <bindir> <datadir> args...
    b=$1; d=$2; shift 2
    "$b/zclassic-cli" -regtest -datadir="$d" "$@"
}
wait_rpc() { # <bindir> <datadir> [seconds]
    i=0; lim=${3:-120}
    while [ $i -lt $lim ]; do
        cli "$1" "$2" getblockcount >/dev/null 2>&1 && return 0
        sleep 1; i=$((i + 1))
    done
    return 1
}
stop_node() { # <bindir> <datadir>
    cli "$1" "$2" stop >/dev/null 2>&1
    i=0
    while [ $i -lt 90 ] && [ -f "$2/regtest/zclassicd.pid" ]; do sleep 1; i=$((i + 1)); done
}
now_ms() { date +%s%3N; }
rand_range() { # <lo> <hi> : integer in [lo, hi]
    r=$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
    echo $(($1 + r % ($2 - $1 + 1)))
}
# epoch_utc "YYYY-MM-DD HH:MM:SS": seconds since the epoch of a UTC log timestamp (portable; date -d is GNU only).
# The node writes its debug.log timestamps in UTC. Prints nothing when the text is not a timestamp.
epoch_utc() {
    awk -v s="$1" 'BEGIN {
        if (split(s, a, /[- :]/) != 6) exit
        y = a[1] + 0; m = a[2] + 0; d = a[3] + 0
        if (m <= 2) y--
        era = int(y / 400); yoe = y - era * 400
        mp = (m + 9) % 12; doy = int((153 * mp + 2) / 5) + d - 1
        doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
        printf "%d\n", (era * 146097 + doe - 719468) * 86400 + a[4] * 3600 + a[5] * 60 + a[6]
    }'
}
sleep_ms() { # <ms>
    s=$(($1 / 1000)); m=$(($1 % 1000))
    sleep "$s.$(printf '%03d' "$m")"
}

# ---------------------------------------------------------------------------------------------
# fixture
# ---------------------------------------------------------------------------------------------
srcdir=$work/src; serve=$work/serve; sdir=$work/server; cdir=$work/client
make_fixture() {
    say "building the regtest fixture (chain, serve dir, $files padding files of ~$filemib MiB)"
    mkconf "$srcdir" "$gr"
    # shellcheck disable=SC2086
    $ZCL_RUN "$bin/zclassicd" -regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 \
        -rpcallowip=127.0.0.1 -debuglogfile=1 -printtoconsole=0 -showmetrics=0 -bootstrap=0 \
        -datadir="$srcdir" -port=$gp -listen=0 -connect=0 -daemon >/dev/null 2>&1 || return 1
    wait_rpc "$bin" "$srcdir" || return 1
    cli "$bin" "$srcdir" generate 220 >/dev/null || return 1
    info=$(cli "$bin" "$srcdir" gettxoutsetinfo) || return 1
    fx_height=$(echo "$info" | jgetd height "")
    fx_best=$(echo "$info" | jgetd bestblock "")
    fx_commit=$(echo "$info" | jgetd hash_chainstate_full "")
    [ -n "$fx_height" ] && [ -n "$fx_best" ] && [ -n "$fx_commit" ] || { echo "no txoutsetinfo: $info"; return 1; }
    stop_node "$bin" "$srcdir"
    mkdir -p "$serve"
    cp -a "$srcdir/regtest/blocks" "$serve/blocks" && cp -a "$srcdir/regtest/chainstate" "$serve/chainstate" || return 1
    rm -f "$serve/blocks/index/LOCK" "$serve/chainstate/LOCK"
    # one random block reused with a distinct header and length per file keeps every file unique
    head -c $((filemib * 1048576)) /dev/urandom >"$work/pad.bin"
    i=1
    while [ $i -le "$files" ]; do
        {
            printf 'padding-file-%s-' "$i"
            head -c $((filemib * 1048576 - i * 4097)) "$work/pad.bin"
        } >"$serve/blocks/blk$(printf '%05d' "$i").dat"
        i=$((i + 1))
    done
    rm -f "$work/pad.bin"
    echo "$fx_height $fx_best $fx_commit" >"$work/serve.meta"
    snapshot_bytes=$(find "$serve" -type f -printf '%s\n' | awk '{s += $1} END {print s}')
    snapshot_files=$(find "$serve" -type f | wc -l)
    say "fixture: height $fx_height best $fx_best; $snapshot_files files, $snapshot_bytes bytes"
}

# ---------------------------------------------------------------------------------------------
# server and client control
# ---------------------------------------------------------------------------------------------
server_bin=$bin
start_server() { # [extra args]
    mkconf "$sdir" "$sr"
    # shellcheck disable=SC2086
    $ZCL_RUN "$server_bin/zclassicd" $common -bootstrap=0 -datadir="$sdir" -port=$sp -listen=1 -connect=0 \
        -bootstrapserve=1 -bootstrapsourcedir="$serve" -bootstrapservemaxtotalkbps=$kbps \
        -debug=net -bootstrapservemaxbytesperday=0 $serverargs "$@" >/dev/null 2>&1 &
    SPID=$!
    wait_rpc "$server_bin" "$sdir" 60 || { fail "server did not start (see $sdir/regtest/debug.log)"; return 1; }
}
stop_server() {
    stop_node "$server_bin" "$sdir"
    wait "$SPID" 2>/dev/null
}
client_bin=$bin
start_client() { # [extra args]; leaves the pid in CPID
    mkconf "$cdir" "$cr"
    # shellcheck disable=SC2086
    $ZCL_RUN "$client_bin/zclassicd" $common -datadir="$cdir" -port=$cp -listen=0 -connect=0 -bootstrap=1 \
        -bootstrapmode=trustless -bootstrappeer=127.0.0.1:$sp "$@" >/dev/null 2>&1 &
    CPID=$!
}
kill_client() {
    kill -9 "$CPID" 2>/dev/null
    wait "$CPID" 2>/dev/null
    rm -f "$cdir/regtest/zclassicd.pid" "$cdir/regtest/.lock"
}
client_log=$cdir/regtest/debug.log
server_log=$sdir/regtest/debug.log
staging_state() { # prints: files=<n> parts=<n> bytes=<n>
    st=$(ls -d "$cdir"/regtest/bootstrap-peer-staging-* 2>/dev/null | head -1)
    if [ -z "$st" ]; then echo "files=0 parts=0 bytes=0"; return; fi
    f=$(find "$st" -type f ! -name '*.part' ! -name '.z23-staging*' | wc -l)
    p=$(find "$st" -type f -name '*.part' | wc -l)
    b=$(find "$st" -type f ! -name '.z23-staging*' -printf '%s\n' | awk '{s += $1} END {print s + 0}')
    echo "files=$f parts=$p bytes=$b"
}
served_bytes() { # sums the chunk payload bytes the server logged from line $1 on
    tail -n +"${1:-1}" "$server_log" | grep -a 'sending bootstrap snapshot chunk' |
        sed 's/.*bytes=\([0-9]*\).*/\1/' | awk '{s += $1} END {print s + 0}'
}
log_lines() { wc -l <"$server_log" 2>/dev/null || echo 0; }
wait_imported() { # <bindir> ; waits until the client answers RPC and has the fixture height
    i=0
    while [ $i -lt 300 ]; do
        h=$(cli "$1" "$cdir" getblockcount 2>/dev/null)
        [ "$h" = "$fx_height" ] && return 0
        kill -0 "$CPID" 2>/dev/null || return 1
        sleep 1; i=$((i + 1))
    done
    return 1
}
check_imported() { # <label>
    h=$(cli "$client_bin" "$cdir" getblockcount 2>/dev/null)
    b=$(cli "$client_bin" "$cdir" getbestblockhash 2>/dev/null)
    if [ "$h" = "$fx_height" ] && [ "$b" = "$fx_best" ]; then
        pass "$1: imported height $h, best block $b equals the server's"
        return 0
    fi
    fail "$1: client at height '$h' best '$b', expected $fx_height $fx_best"
    return 1
}
fresh_client() {
    rm -rf "$cdir"
}
end_client() {
    stop_node "$client_bin" "$cdir"
    wait "$CPID" 2>/dev/null
}
sample_streams() { # <seconds> ; prints "t=<s> percent=<p> streams=<n>" every 0.5 s while the client downloads
    end=$(($(now_ms) + $1 * 1000)); t0=$(now_ms)
    while [ "$(now_ms)" -lt "$end" ]; do
        j=$(cli "$client_bin" "$cdir" getbootstrapinfo 2>/dev/null) || { sleep 0.2; continue; }
        act=0; [ "$(echo "$j" | jgetd phase "")" = active ] && act=1
        echo "t=$((($(now_ms) - t0) / 1000)).$((($(now_ms) - t0) % 1000 / 100)) percent=$(echo "$j" | jgetd percent "") streams=$(echo "$j" | jgetd streams "") active=$act"
        [ "$act" = 1 ] || break
        sleep 0.5
    done
}

# ---------------------------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------------------------
restart_args() { # a node killed after its install was verified (blocks/ and chainstate/, no pending marker) has finished
    # its bootstrap: restart it as a user would, without asking to bootstrap into that chain again (an explicit
    # -bootstrappeer on a datadir that holds a chain is refused by design). A kill during the install itself (marker
    # present, or one of the directories missing) is restarted with the same arguments and must recover by itself.
    if [ -e "$cdir/regtest/blocks" ] && [ -e "$cdir/regtest/chainstate" ] &&
       [ ! -e "$cdir/regtest/bootstrap-trustless-pending" ] && [ ! -e "$cdir/regtest/bootstrap-anchor-pending" ]; then
        echo "-bootstrap=0"
    fi
}
test_kills() {
    say "== kill -9 at $kills random instants, restart each time =="
    fresh_client; start_server || return 1
    from=$(log_lines); cyc=$from; prevb=0
    chunk=1048576 # the snapshot chunk size
    allow_total=0
    n=0; finished=0
    while [ $n -lt "$kills" ]; do
        ra=$(restart_args); [ -z "$ra" ] || say "the previous run had finished its bootstrap; restarting it without -bootstrap"
        cl=$(wc -l <"$client_log" 2>/dev/null || echo 0)
        start_client $ra
        t=$(rand_ms_for_kill)
        sleep_ms "$t"
        if ! kill -0 "$CPID" 2>/dev/null; then say "client exited by itself after $n kills"; finished=1; break; fi
        h=$(cli "$client_bin" "$cdir" getblockcount 2>/dev/null)
        if [ "$h" = "$fx_height" ]; then say "client finished the import after $n kills (kill window too long); stopping the kill loop"; finished=1; break; fi
        killed_at=$(date +%s)
        kill_client
        n=$((n + 1))
        sq=$(served_bytes "$cyc"); cyc=$(log_lines)
        ss=$(staging_state); nb=${ss##*bytes=}
        # What a killed run loses is what was in flight at the kill (requests the server had queued that the client
        # never stored; the LAST status line before the kill says how many were in flight; lines repeat when that moves by 4)
        # plus the last chunk of every partial file it resumed (always requested again).
        infl=$(tail -n +$((cl + 1)) "$client_log" | sed -n 's/.*, \([0-9][0-9]*\) requests in flight.*/\1/p' | tail -1)
        resumed=$(tail -n +$((cl + 1)) "$client_log" | sed -n 's/.*staging scan: .*, \([0-9][0-9]*\) partial files continue.*/\1/p' | tail -1)
        # The line can be older than the kill (the manager that prints it is a thread of a loaded host), and the window
        # opens by a request per chunk received (about 32 a second here): add the growth the line can have missed from
        # its age in whole seconds, capped by the full window of 4 streams x 16 requests.
        lts=$(tail -n +$((cl + 1)) "$client_log" | grep -a "requests in flight" | tail -1 | cut -c1-19)
        age=0
        if [ -n "$lts" ]; then lsec=$(epoch_utc "$lts"); [ -n "$lsec" ] || lsec=$killed_at; age=$((killed_at - lsec)); [ $age -lt 0 ] && age=0; fi
        infl_max=$(( ${infl:-0} + (age + 1) * 32 )); [ $infl_max -gt 64 ] && infl_max=64
        allow=$(( (infl_max + 4 + ${resumed:-0}) * chunk ))
        lost=$((sq - (nb - prevb)))
        say "kill $n at +${t} ms: staging $ss (this run: server queued $sq bytes, staged $((nb - prevb)), lost $lost; ${infl:-0} requests in flight in a ${age} s old status line, at most $infl_max at the kill, ${resumed:-0} partial files resumed, allowed $allow)"
        if [ "$nb" -gt 0 ]; then
            allow_total=$((allow_total + allow))
            if [ "$lost" -gt "$allow" ]; then fail "kills: run $n lost $lost bytes, more than its ${infl:-0}+4 requests in flight and ${resumed:-0} resumed partial files allow ($allow)"; fi
            prevb=$nb
        else
            prevb=0
        fi
    done
    cl=$(wc -l <"$client_log" 2>/dev/null || echo 0)
    if [ $finished -eq 0 ]; then
        start_client $(restart_args)
        if ! wait_imported "$client_bin"; then
            fail "kills: client never reached height $fx_height (datadir: $(ls -A "$cdir/regtest" | tr -s "[:space:]" " "))"; tail -20 "$client_log"; end_client; stop_server; return 1
        fi
    fi
    check_imported "kills (${n} kills)"
    served=$(served_bytes "$from")
    ratio=$(awk -v a="$served" -v b="$snapshot_bytes" 'BEGIN {printf "%.3f", a / b}')
    say "server served $served bytes in total for $n kills; snapshot is $snapshot_bytes bytes (ratio $ratio)"
    # one copy plus what the killed runs could lose (the per-run allowances above) plus the last chunk of each
    # partial file the final run resumed; no multiplier
    resumed=$(tail -n +$((cl + 1)) "$client_log" | sed -n 's/.*staging scan: .*, \([0-9][0-9]*\) partial files continue.*/\1/p' | tail -1)
    limit=$((snapshot_bytes + allow_total + ${resumed:-0} * chunk))
    if [ "$served" -le "$limit" ]; then pass "kills: total bytes served stayed within bound ($served <= $limit)"; else fail "kills: served $served > bound $limit"; fi
    # No torn write is injected here (kill -9 leaves the page cache intact and a resume starts at a whole chunk),
    # so a staged file that fails its hash is a bug.
    if grep -aq 'hash mismatch' "$client_log"; then fail "kills: a staged file failed verification although no torn write was injected"; grep -a 'hash mismatch' "$client_log" | head -3; else pass "kills: no staged file failed verification"; fi
    if ls -d "$cdir"/regtest/bootstrap-peer-staging-* >/dev/null 2>&1; then fail "kills: staging directory still present after a successful import"; else pass "kills: staging directory removed after the import"; fi
    grep -a 'staging scan\|staging directory\|pre-install audit\|download complete' "$client_log" | tail -6
    end_client; stop_server
}
rand_ms_for_kill() { rand_range 2200 $((kill_max_ms)); }

test_single() {
    say "== one interrupted sync: kill at ~30%, restart, finish =="
    fresh_client; start_server || return 1
    from=$(log_lines)
    t0=$(now_ms)
    start_client
    pct=0
    while [ "$pct" -lt 30 ]; do
        j=$(cli "$client_bin" "$cdir" getbootstrapinfo 2>/dev/null)
        pct=$(echo "$j" | jgetd percent ""); pct=${pct:-0}
        kill -0 "$CPID" 2>/dev/null || { fail "single: client exited early"; stop_server; return 1; }
        sleep 0.2
    done
    kill_client
    t1=$(now_ms)
    st=$(staging_state)
    served1=$(served_bytes "$from")
    say "killed at ${pct}% after $(((t1 - t0) / 1000)) s; staging $st; served so far $served1 bytes"
    t2=$(now_ms)
    start_client
    if ! wait_imported "$client_bin"; then fail "single: restarted client never finished"; tail -20 "$client_log"; end_client; stop_server; return 1; fi
    t3=$(now_ms)
    served=$(served_bytes "$from")
    say "RESULT interrupted sync: first run $(((t1 - t0) / 1000)) s, second run $(((t3 - t2) / 1000)) s, total $(((t3 - t0) / 1000)) s; server served $served bytes for a $snapshot_bytes byte snapshot (ratio $(awk -v a="$served" -v b="$snapshot_bytes" 'BEGIN {printf "%.3f", a / b}'))"
    check_imported "single"
    grep -a 'staging scan\|staging directory' "$client_log" | tail -3
    end_client; stop_server
}

test_corrupt() {
    say "== corrupted and truncated staged files =="
    fresh_client; start_server || return 1
    from=$(log_lines)
    start_client
    # let it finish a good number of files, then kill
    pct=0
    while [ "$pct" -lt 40 ]; do
        j=$(cli "$client_bin" "$cdir" getbootstrapinfo 2>/dev/null)
        pct=$(echo "$j" | jgetd percent ""); pct=${pct:-0}
        kill -0 "$CPID" 2>/dev/null || { fail "corrupt: client exited early"; stop_server; return 1; }
        sleep 0.2
    done
    kill_client
    st=$(ls -d "$cdir"/regtest/bootstrap-peer-staging-* | head -1)
    victims=$(find "$st/blocks" -type f -name 'blk000*.dat' ! -name '*.part' | sort | head -2)
    v1=$(echo "$victims" | sed -n 1p); v2=$(echo "$victims" | sed -n 2p)
    [ -n "$v1" ] && [ -n "$v2" ] || { fail "corrupt: not enough complete staged files to damage"; stop_server; return 1; }
    # flip one byte in the middle of v1 (same size), truncate v2, add a stray file and a bogus .part
    sz=$(stat -c %s "$v1")
    printf 'X' | dd of="$v1" bs=1 seek=$((sz / 2)) conv=notrunc 2>/dev/null
    sz2=$(stat -c %s "$v2")
    truncate -s $((sz2 - 777)) "$v2"
    echo stray >"$st/blocks/stray-file.dat"
    say "damaged $(basename "$v1") (flipped byte), $(basename "$v2") (truncated), added a stray file"
    start_client
    if ! wait_imported "$client_bin"; then fail "corrupt: client never finished"; tail -20 "$client_log"; end_client; stop_server; return 1; fi
    check_imported "corrupt"
    if grep -aq "$(basename "$v1") is corrupt or the wrong size" "$client_log"; then pass "corrupt: flipped-byte file detected and discarded"; else fail "corrupt: flipped file not reported"; fi
    if grep -aq "$(basename "$v2") is corrupt or the wrong size" "$client_log"; then pass "corrupt: truncated file detected and discarded"; else fail "corrupt: truncated file not reported"; fi
    if grep -aq 'stray entries removed' "$client_log" && grep -a 'staging scan' "$client_log" | tail -1 | grep -q '1 stray'; then pass "corrupt: stray file removed"; else fail "corrupt: stray file not removed"; fi
    end_client; stop_server
}

test_manifest() {
    say "== changed manifest: same anchor keeps files, different snapshot discards =="
    fresh_client; start_server || return 1
    start_client
    pct=0
    while [ "$pct" -lt 35 ]; do
        j=$(cli "$client_bin" "$cdir" getbootstrapinfo 2>/dev/null)
        pct=$(echo "$j" | jgetd percent ""); pct=${pct:-0}
        kill -0 "$CPID" 2>/dev/null || { fail "manifest: client exited early"; stop_server; return 1; }
        sleep 0.2
    done
    kill_client
    before=$(staging_state); say "staging before the server grows: $before"
    stop_server
    # the server grows the snapshot: one more block file (same chain anchor)
    { printf 'grown-'; head -c $((3 * 1048576)) /dev/urandom; } >"$serve/blocks/blk99999.dat"
    start_server || return 1
    from=$(log_lines)
    start_client
    if ! wait_imported "$client_bin"; then fail "manifest: client never finished after the server grew"; tail -20 "$client_log"; end_client; stop_server; return 1; fi
    check_imported "manifest (grown)"
    if grep -a 'bootstrap-peer-staging' "$client_log" | grep -aq 'same anchor, manifest changed'; then pass "manifest: grown snapshot reused the staging directory"; else fail "manifest: grown snapshot did not report reuse"; fi
    kept=$(grep -a 'staging scan' "$client_log" | tail -1 | sed -n 's/.*kept \([0-9]*\) verified files.*/\1/p')
    if [ "${kept:-0}" -gt 0 ]; then pass "manifest: $kept verified files kept across the manifest change"; else fail "manifest: no files kept across the manifest change"; fi
    end_client
    stop_server
    rm -f "$serve/blocks/blk99999.dat"

    # a different snapshot: stage some of the original, then serve a snapshot at another tip
    fresh_client; start_server || return 1
    start_client
    pct=0
    while [ "$pct" -lt 25 ]; do
        j=$(cli "$client_bin" "$cdir" getbootstrapinfo 2>/dev/null)
        pct=$(echo "$j" | jgetd percent ""); pct=${pct:-0}
        kill -0 "$CPID" 2>/dev/null || { fail "manifest: client exited early (2)"; stop_server; return 1; }
        sleep 0.2
    done
    kill_client
    old=$(ls -d "$cdir"/regtest/bootstrap-peer-staging-* | head -1)
    stop_server
    cp "$work/serve.meta" "$work/serve.meta.orig"
    printf '%s %s %s\n' "$((fx_height + 1))" "0000000000000000000000000000000000000000000000000000000000000abc" "$fx_commit" >"$work/serve.meta"
    start_server || return 1
    start_client
    sleep 12
    if [ -d "$old" ]; then fail "manifest: the staging directory of the other snapshot was kept"; else pass "manifest: staging of a different snapshot was discarded"; fi
    new=$(ls -d "$cdir"/regtest/bootstrap-peer-staging-* 2>/dev/null | head -1)
    if [ -n "$new" ] && [ "$new" != "$old" ]; then pass "manifest: fresh staging directory $(basename "$new") for the new snapshot"; else fail "manifest: no new staging directory"; fi
    kill_client
    mv "$work/serve.meta.orig" "$work/serve.meta"
    stop_server
}

test_stream() {
    say "== stream recovery: cut one stream at the server =="
    fresh_client; start_server || return 1
    start_client
    # wait until 4 streams are up
    i=0
    while [ $i -lt 200 ]; do
        s=$(cli "$client_bin" "$cdir" getbootstrapinfo 2>/dev/null | jgetd streams "")
        [ "${s:-0}" -ge 4 ] && break
        sleep 0.2; i=$((i + 1))
    done
    say "streams before the cut: ${s:-0}"
    victim=$(cli "$server_bin" "$sdir" getpeerinfo | jpick addr | grep -E '^127\.0\.0\.1:[0-9]+$' | head -1)
    [ -n "$victim" ] || { fail "stream: no client connection found at the server"; kill_client; stop_server; return 1; }
    cli "$server_bin" "$sdir" disconnectnode "$victim" >/dev/null 2>&1
    say "disconnected $victim at the server; sampling streams for 25 s (t=seconds percent streams)"
    sample_streams 25 | tee "$work/stream-samples.txt" | awk 'NR % 4 == 1' | head -12
    # Judge recovery only on samples taken while the download was still running: on a fast
    # host it can finish inside the sampling window, and the stream count then drops to
    # zero for a reason that has nothing to do with the cut.
    act_streams() { sed -n 's/.*streams=\([0-9][0-9]*\) active=1$/\1/p' "$work/stream-samples.txt"; }
    min=$(act_streams | sort -n | head -1)
    last=$(act_streams | tail -1)
    rec=$(act_streams | tail -n +3 | sort -n | tail -1)
    done_early=$(tail -1 "$work/stream-samples.txt" | grep -c 'active=0$' || true)
    # A stream the cut just sent back to reconnect is counted by the client a moment before the server sees its
    # connection: look again for a few seconds before judging the server-side count.
    peers=0; k=0
    while [ $k -lt 12 ]; do
        peers=$(cli "$server_bin" "$sdir" getpeerinfo | jpick addr | grep -c '^127\.0\.0\.1')
        [ "${peers:-0}" -ge 4 ] && break
        sleep 0.5; k=$((k + 1))
    done
    # The server-side count is only comparable while the client still runs all four
    # streams: near the end of a download fewer files than streams are left and the
    # streams close one by one, so the download can end (or taper) between the last
    # sample and the getpeerinfo above. Ask the client again after reading the server.
    j=$(cli "$client_bin" "$cdir" getbootstrapinfo 2>/dev/null) || j=""
    still4=0; [ "$(echo "$j" | jgetd phase "")" = active ] && [ "$(echo "$j" | jgetd streams "")" -ge 4 ] 2>/dev/null && [ "${last:-0}" -ge 4 ] && still4=1
    say "streams: min after cut ${min:-?}, recovered to ${rec:-?}, last while downloading ${last:-?}; client connections now at the server: $peers"
    if grep -aq 'reconnecting\|stream .* failed' "$client_log"; then say "client log:"; grep -a 'stream [0-9]* failed\|stream [0-9]* reconnected\|reconnecting with verified files' "$client_log" | head -4; fi
    echo "$last" >"$work/stream-last.txt"
    echo "$peers" >"$work/stream-peers.txt"
    if [ "${rec:-0}" -ge 4 ] && { [ "${peers:-0}" -ge 4 ] || [ "${done_early:-0}" = 1 ] || [ "$still4" = 0 ]; }; then
        pass "stream: all 4 streams are connected again ($peers connections at the server)"
    else
        fail "stream: recovered to only ${rec:-?} streams / $peers connections at the server after a stream was cut"
    fi
    kill_client
    stop_server
}

test_slots() {
    say "== a server limited to -bootstrapservemaxpeers=$slots serves a 4-stream client =="
    fresh_client
    serverargs="-bootstrapservemaxpeers=$slots"
    start_server || { serverargs=""; return 1; }
    t0=$(now_ms)
    start_client
    if ! wait_imported "$client_bin"; then fail "slots: client never finished"; tail -20 "$client_log"; end_client; stop_server; serverargs=""; return 1; fi
    t1=$(now_ms)
    say "RESULT slots=$slots: download+import took $(((t1 - t0) / 1000)) s; stream failures: $(grep -ac 'stream [0-9]* failed' "$client_log"); read timeouts: $(grep -ac 'read timeout' "$client_log")"
    grep -a 'stream [0-9]* failed\|stream [0-9]* reconnected' "$client_log" | head -6
    check_imported "slots"
    end_client; stop_server
    serverargs=""
}

test_interop() {
    say "== interop with old binaries =="
    if [ -n "$oldserver" ]; then
        say "-- new client, OLD server ($oldserver)"
        fresh_client
        server_bin=$oldserver; start_server -debug=net || { server_bin=$bin; return 1; }
        from=$(log_lines)
        start_client
        pct=0
        while [ "$pct" -lt 30 ]; do
            j=$(cli "$client_bin" "$cdir" getbootstrapinfo 2>/dev/null)
            pct=$(echo "$j" | jgetd percent ""); pct=${pct:-0}
            kill -0 "$CPID" 2>/dev/null || break
            sleep 0.2
        done
        kill_client
        say "killed at ${pct}%: staging $(staging_state)"
        start_client
        if wait_imported "$client_bin"; then
            check_imported "old server"
            grep -a 'staging scan' "$client_log" | tail -1
            kept=$(grep -a 'staging scan' "$client_log" | tail -1 | sed -n 's/.*kept \([0-9]*\) verified files.*/\1/p')
            [ "${kept:-0}" -gt 0 ] && pass "interop: resume against an old server reused $kept verified files" || fail "interop: nothing reused against the old server"
        else
            fail "interop: client did not finish against the old server"; tail -20 "$client_log"
        fi
        end_client
        server_bin=$oldserver; stop_server; server_bin=$bin
    else
        say "(no --old-server-bin: skipped)"
    fi
    if [ -n "$oldclient" ]; then
        say "-- OLD client ($oldclient), new server"
        fresh_client
        start_server || return 1
        client_bin=$oldclient; start_client
        if wait_imported "$oldclient"; then
            check_imported "old client"
        else
            fail "interop: old client did not finish against the new server"; tail -20 "$client_log"
        fi
        end_client
        client_bin=$bin
        stop_server
    else
        say "(no --old-client-bin: skipped)"
    fi
}

# the longest a kill is delayed: startup (~2 s) plus a slice of the download. The download takes about
# snapshot_bytes / rate; spread the kills so that roughly --kills of them are needed to get through.
make_fixture || { echo "resume-test: could not build the fixture"; exit 1; }
rate_bps=$((kbps * 1000 / 8))
dl_ms=$((snapshot_bytes * 1000 / rate_bps))
kill_max_ms=$((2500 + dl_ms * 2 / (kills + 1)))
say "expected download time at $kbps kbit/s: $((dl_ms / 1000)) s; kill window 2200..$kill_max_ms ms"

want kills && test_kills
want single && test_single
want corrupt && test_corrupt
want manifest && test_manifest
want stream && test_stream
want slots && test_slots
want interop && test_interop

# manual, never run by a gate: one real mainnet bootstrap from the public snapshot servers (downloads about 10 GiB)
echo "resume-test: real-network check, run by hand: sh $(dirname "$0")/mainnet-e2e.sh --bin <dir> --work <empty dir>"
if [ $failures -eq 0 ]; then
    echo "resume-test: ALL PASSED"
    exit 0
fi
echo "resume-test: $failures FAILURE(S)"
exit 1
