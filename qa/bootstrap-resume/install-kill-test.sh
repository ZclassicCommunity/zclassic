#!/bin/sh
# TEST-ONLY. A node killed while it installs a downloaded bootstrap snapshot must start again
# by itself and finish the bootstrap, without any manual cleanup of its datadir.
#
# usage: sh qa/bootstrap-resume/install-kill-test.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--port-base <n>] [--random <n>] [--cases <list>]
#            [--files <n>] [--file-mib <n>]
#
# The fixture is the one of resume-test.sh (a regtest chain frozen into a serve directory, served by a
# local -bootstrapserve node; the client fetches it with -bootstrapmode=trustless -bootstrappeer, the
# same BootstrapFromPeer / staging / install code as mainnet), with few small padding files so a
# download takes seconds.
#
# The install is: write the pending marker (fsync'd); rename staging/blocks to blocks/; rename
# staging/chainstate to chainstate/; remove the staging directory; open the databases; verify; clear
# the marker. Regtest-only -testcrashpoint=<name> makes the client _exit(77) at one of those steps:
#   bootstrap-install-before-marker          nothing written yet
#   bootstrap-install-after-marker           marker present, nothing renamed
#   bootstrap-install-after-blocks-rename    blocks/ installed, chainstate/ still staged
#   bootstrap-install-after-chainstate-rename  both installed, staging directory not yet removed
#   bootstrap-install-before-marker-clear    installed and verified, marker not yet cleared
#   bootstrap-recover-after-rollback         (second crash) inside the recovery of the third point
# Cases (comma separated, default all):
#   points    one deterministic case per crash point (and the double crash): restart WITHOUT any
#             cleanup, the client must finish the bootstrap and reach the same tip and
#             gettxoutsetinfo hash as an uninterrupted bootstrap.
#   random    --random N runs: kill -9 at a random instant after the pending marker appears (0..1500 ms,
#             which spans the install, the database open and the verification), restart, same check.
#   refuse    a datadir that already holds blocks/ and no pending marker is still refused with a
#             clear message and left untouched; so is a half-installed blocks/ whose staging
#             directory is gone.
# Never point this at a real datadir; it creates and deletes its own under --work.
set -u

bin=""; work=""; base=""; cases="all"; nrandom=20; files=4; filemib=4
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        --cases) cases=$2; shift 2 ;;
        --random) nrandom=$2; shift 2 ;;
        --files) files=$2; shift 2 ;;
        --file-mib) filemib=$2; shift 2 ;;
        *) echo "install-kill-test: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: install-kill-test.sh --bin <dir> --work <dir> [options]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "install-kill-test: $work is not empty" >&2; exit 2; }

# Leased, bind-tested port block (qa/lib/isolation.sh; --port-base overrides) and the JSON helpers of the other shell tests.
. "$(dirname "$0")/../lib/isolation.sh"
. "$(dirname "$0")/../rpc-tests/jsonq_lib.sh"
iso_base base "$base" 6

sp=$base; sr=$((base + 1)); cp=$((base + 2)); cr=$((base + 3)); gp=$((base + 4)); gr=$((base + 5))
common="-regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -debuglogfile=1 -printtoconsole=0 -showmetrics=0 -disablewallet"
failures=0; SPID=""; CPID=""; completed=0
want() { case ",$cases," in *,"$1",*|*,all,*) return 0 ;; esac; return 1; }
say() { echo "install-kill-test: $*"; }
pass() { echo "install-kill-test: PASS $*"; }
fail() { echo "install-kill-test: FAIL $*"; failures=$((failures + 1)); }
# only the processes this script started are killed
trap '[ -n "$CPID" ] && kill -9 "$CPID" 2>/dev/null; [ -n "$SPID" ] && kill -9 "$SPID" 2>/dev/null' EXIT

srcdir=$work/src; serve=$work/serve; sdir=$work/server; cdir=$work/client; cd_=$cdir/regtest
mkconf() { mkdir -p "$1/regtest" && printf 'rpcuser=bs\nrpcpassword=bs%s\nrpcport=%s\n' "$$" "$2" >"$1/zclassic.conf"; }
cli() { b=$1; d=$2; shift 2; "$b/zclassic-cli" -regtest -datadir="$d" "$@"; }
wait_rpc() { i=0; lim=${3:-120}
    while [ $i -lt $lim ]; do cli "$1" "$2" getblockcount >/dev/null 2>&1 && return 0; sleep 1; i=$((i + 1)); done; return 1; }
stop_node() { cli "$1" "$2" stop >/dev/null 2>&1; i=0
    while [ $i -lt 90 ] && [ -f "$2/regtest/zclassicd.pid" ]; do sleep 1; i=$((i + 1)); done; }
rand_range() { r=$(od -An -N4 -tu4 /dev/urandom | tr -d ' '); echo $(($1 + r % ($2 - $1 + 1))); }
sleep_ms() { sleep "$(($1 / 1000)).$(printf '%03d' "$(($1 % 1000))")"; }

make_fixture() {
    say "building the regtest fixture ($files padding files of $filemib MiB)"
    mkconf "$srcdir" "$gr"
    "$bin/zclassicd" -regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 \
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
    head -c $((filemib * 1048576)) /dev/urandom >"$work/pad.bin"
    i=1
    while [ $i -le "$files" ]; do
        { printf 'padding-file-%s-' "$i"; head -c $((filemib * 1048576 - i * 4097)) "$work/pad.bin"; } >"$serve/blocks/blk$(printf '%05d' "$i").dat"
        i=$((i + 1))
    done
    rm -f "$work/pad.bin"
    echo "$fx_height $fx_best $fx_commit" >"$work/serve.meta"
    say "fixture: height $fx_height best $fx_best commitment $fx_commit"
}
start_server() {
    mkconf "$sdir" "$sr"
    "$bin/zclassicd" $common -bootstrap=0 -datadir="$sdir" -port=$sp -listen=1 -connect=0 \
        -bootstrapserve=1 -bootstrapsourcedir="$serve" -bootstrapservemaxbytesperday=0 >/dev/null 2>&1 &
    SPID=$!
    wait_rpc "$bin" "$sdir" 60 || { fail "server did not start"; return 1; }
}
start_client() { # [extra args]; pid in CPID; stdout/stderr appended to $cdir/out.log
    mkconf "$cdir" "$cr"
    "$bin/zclassicd" $common -datadir="$cdir" -port=$cp -listen=0 -connect=0 -bootstrap=1 \
        -bootstrapmode=trustless -bootstrappeer=127.0.0.1:$sp "$@" >>"$cdir/out.log" 2>&1 &
    CPID=$!
}
fresh_client() { rm -rf "$cdir"; mkdir -p "$cdir"; }
kill_client() { kill -9 "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null; rm -f "$cd_/zclassicd.pid" "$cd_/.lock"; }
# wait for the client process to leave by itself; its exit status (or "timeout") is left in WRC
wait_exit() { i=0
    while kill -0 "$CPID" 2>/dev/null; do
        [ $i -ge ${1:-1500} ] && { WRC=timeout; return; }
        sleep 0.2; i=$((i + 1))
    done
    wait "$CPID" 2>/dev/null; WRC=$?; rm -f "$cd_/zclassicd.pid" "$cd_/.lock"
}
wait_imported() { i=0
    while [ $i -lt 240 ]; do
        h=$(cli "$bin" "$cdir" getblockcount 2>/dev/null)
        [ "$h" = "$fx_height" ] && return 0
        kill -0 "$CPID" 2>/dev/null || return 1
        sleep 0.5; i=$((i + 1))
    done
    return 1
}
state() { # one line: which of blocks/ chainstate/ marker exist, and the staging directories
    s=""
    [ -e "$cd_/blocks" ] && s="$s blocks/"
    [ -e "$cd_/chainstate" ] && s="$s chainstate/"
    [ -e "$cd_/bootstrap-trustless-pending" ] && s="$s marker"
    for st in "$cd_"/bootstrap-peer-staging-*; do
        [ -d "$st" ] || continue
        s="$s staging[$(ls -A "$st" | grep -v '^\.z23' | tr '\n' ',' | sed 's/,$//')]"
    done
    echo "${s:- (empty)}"
}
# the same tip and UTXO-set hash as an uninterrupted bootstrap (fx_*, confirmed by the reference run)
check_same() { # <label>
    j=$(cli "$bin" "$cdir" gettxoutsetinfo 2>/dev/null)
    h=$(echo "$j" | jgetd height "")
    b=$(echo "$j" | jgetd bestblock "")
    c=$(echo "$j" | jgetd hash_chainstate_full "")
    left=""
    [ -e "$cd_/bootstrap-trustless-pending" ] && left="$left marker"
    ls -d "$cd_"/bootstrap-peer-staging-* >/dev/null 2>&1 && left="$left staging"
    if [ "$h" = "$ref_height" ] && [ "$b" = "$ref_best" ] && [ "$c" = "$ref_commit" ] && [ -z "$left" ]; then
        pass "$1: height $h, tip $b, utxo hash $c; no marker or staging left"
        return 0
    fi
    fail "$1: height '$h' tip '$b' hash '$c' (want $ref_height $ref_best $ref_commit); left over:$left"
    tail -15 "$cd_/debug.log" 2>/dev/null | sed 's/^/    log: /'
    tail -5 "$cdir/out.log" | sed 's/^/    out: /'
    return 1
}
finish_plain() { # <label> : start without a crash point, no cleanup, must complete
    extra=""
    if [ -e "$cd_/blocks" ] && [ -e "$cd_/chainstate" ] && [ ! -e "$cd_/bootstrap-trustless-pending" ]; then
        # killed after the install was verified and its marker cleared: the bootstrap is complete and
        # the datadir is a verified chain. A restart with an explicit -bootstrappeer asks to bootstrap into
        # it again and is refused (see the refuse case); a user restarts such a node without it.
        extra="-bootstrap=0"; completed=$((completed + 1))
        say "$1: the install was already complete and verified at the kill; restarting without a bootstrap"
    fi
    start_client $extra
    if wait_imported; then check_same "$1"; else
        fail "$1: the restarted client did not complete the bootstrap (state:$(state))"
        tail -8 "$cd_/debug.log" 2>/dev/null | sed 's/^/    log: /'; tail -5 "$cdir/out.log" | sed 's/^/    out: /'
        kill_client; return 1
    fi
    stop_node "$bin" "$cdir"; wait "$CPID" 2>/dev/null
}

test_reference() {
    say "== reference: uninterrupted bootstrap =="
    fresh_client; start_client
    wait_imported || { fail "reference: bootstrap did not complete"; tail -10 "$cd_/debug.log"; kill_client; return 1; }
    j=$(cli "$bin" "$cdir" gettxoutsetinfo)
    ref_height=$(echo "$j" | jgetd height "")
    ref_best=$(echo "$j" | jgetd bestblock "")
    ref_commit=$(echo "$j" | jgetd hash_chainstate_full "")
    if [ "$ref_height" = "$fx_height" ] && [ "$ref_best" = "$fx_best" ] && [ "$ref_commit" = "$fx_commit" ]; then
        pass "reference: height $ref_height tip $ref_best utxo hash $ref_commit equal the server's"
    else
        fail "reference: $ref_height $ref_best $ref_commit differ from the server's $fx_height $fx_best $fx_commit"
    fi
    stop_node "$bin" "$cdir"; wait "$CPID" 2>/dev/null
}

crash_case() { # <label> <crash point> [second crash point]
    label=$1; pt=$2; pt2=${3:-}
    fresh_client
    start_client "-testcrashpoint=$pt"
    wait_exit; r=$WRC
    st=$(state)
    if [ "$r" != 77 ]; then
        fail "$label: expected the client to leave at $pt (exit 77), got '$r' (state:$st)"; kill_client 2>/dev/null; return 1
    fi
    say "$label: crashed at $pt; state:$st"
    if [ -n "$pt2" ]; then
        start_client "-testcrashpoint=$pt2"
        wait_exit; r=$WRC
        if [ "$r" != 77 ]; then
            fail "$label: expected the second start to leave at $pt2 (exit 77), got '$r' (state:$(state))"; return 1
        fi
        say "$label: crashed again at $pt2; state:$(state)"
    fi
    finish_plain "$label" || return 1
    case "$label" in
        after-blocks-rename|recovery-crash)
            if grep -aq "moved it back into" "$cd_/debug.log"; then pass "$label: blocks/ was moved back into its staging directory (nothing deleted, nothing downloaded again)"; else fail "$label: no roll back logged"; fi ;;
    esac
}

test_points() {
    say "== deterministic crash points =="
    crash_case "before-marker" bootstrap-install-before-marker
    crash_case "after-marker" bootstrap-install-after-marker
    crash_case "after-blocks-rename" bootstrap-install-after-blocks-rename
    crash_case "after-chainstate-rename" bootstrap-install-after-chainstate-rename
    crash_case "before-marker-clear" bootstrap-install-before-marker-clear
    crash_case "recovery-crash" bootstrap-install-after-blocks-rename bootstrap-recover-after-rollback
}

test_random() {
    say "== $nrandom random kill -9 after the pending marker appears =="
    n=0
    while [ $n -lt "$nrandom" ]; do
        n=$((n + 1))
        fresh_client; start_client
        i=0
        while [ $i -lt 6000 ] && [ ! -e "$cd_/bootstrap-trustless-pending" ] && kill -0 "$CPID" 2>/dev/null; do sleep 0.005; i=$((i + 1)); done
        d=$(rand_range 0 1500)
        sleep_ms "$d"
        if kill -0 "$CPID" 2>/dev/null; then kill_client; else wait "$CPID" 2>/dev/null; fi
        st=$(state)
        say "random $n: kill at marker +${d} ms; state:$st"
        finish_plain "random $n (+${d} ms,$st)"
    done
    say "random: $nrandom runs, $completed of them killed after the install was already complete"
}

test_refuse() {
    say "== existing chain data is refused and left alone =="
    # 1. a real chain (the fixture node's blocks/ and chainstate/) of a user, no marker
    fresh_client; cp -a "$srcdir/regtest/blocks" "$srcdir/regtest/chainstate" "$cd_/" || return 1
    rm -f "$cd_/blocks/index/LOCK" "$cd_/chainstate/LOCK"; echo mine >"$cd_/blocks/sentinel"; before=$(find "$cd_/blocks" "$cd_/chainstate" -type f | wc -l)
    start_client; wait_exit 150; r=$WRC
    if [ "$r" != timeout ] && [ "$r" != 0 ] && grep -aq 'already exists' "$cdir/out.log" "$cd_/debug.log" 2>/dev/null && [ -f "$cd_/blocks/sentinel" ] && [ "$(find "$cd_/blocks" "$cd_/chainstate" -type f | wc -l)" = "$before" ]; then
        pass "refuse: an existing chain ($before files) without a marker is refused (exit $r) and untouched"
    else
        fail "refuse: exit '$r', sentinel $([ -f "$cd_/blocks/sentinel" ] && echo kept || echo GONE)"; tail -3 "$cdir/out.log"
    fi
    if grep -aq 'no interrupted bootstrap install was found' "$cdir/out.log" "$cd_/debug.log" 2>/dev/null; then pass "refuse: the message says no interrupted install was found"; else fail "refuse: message does not say why"; fi
    kill_client 2>/dev/null
    # 2. a marker and a half-installed blocks/ with no staging directory to return it to
    fresh_client; mkdir -p "$cd_/blocks"; echo mine >"$cd_/blocks/sentinel"; echo "bootstrap-trustless-pending" >"$cd_/bootstrap-trustless-pending"
    start_client; wait_exit 150; r=$WRC
    if [ "$r" != timeout ] && [ "$r" != 0 ] && grep -aq 'left untouched' "$cdir/out.log" "$cd_/debug.log" 2>/dev/null && [ -f "$cd_/blocks/sentinel" ]; then
        pass "refuse: half-installed blocks/ with no staging directory is refused (exit $r) and untouched"
    else
        fail "refuse (marker, no staging): exit '$r', sentinel $([ -f "$cd_/blocks/sentinel" ] && echo kept || echo GONE)"; tail -3 "$cdir/out.log"
    fi
    kill_client 2>/dev/null
}

make_fixture || { echo "install-kill-test: could not build the fixture"; exit 1; }
start_server || exit 1
test_reference
want points && test_points
want random && test_random
want refuse && test_refuse
stop_node "$bin" "$sdir"; wait "$SPID" 2>/dev/null
if [ $failures -eq 0 ]; then echo "install-kill-test: ALL PASSED"; exit 0; fi
echo "install-kill-test: $failures FAILURE(S)"
exit 1
