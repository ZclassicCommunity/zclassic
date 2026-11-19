#!/bin/sh
# Wallet crash-consistency regression: kill the wallet node at controlled and random
# points, restart it WITHOUT -rescan, and require exactly the balances and unspent
# outputs that a node which rescans the same crashed datadir from genesis reports.
#
# usage: wallet_crash_consistency.sh --bin <dir> --work <dir> [--peer-bin <dir>]
#            [--seeds "11 23 ..."] [--iters <per seed>] [--base <port>] [--no-hooks]
#   --bin       directory with zclassicd and zclassic-cli: the wallet under test
#   --peer-bin  binary of the miner/peer node (default: --bin)
#   --seeds     fixed seed list; every seed is one independent chain and one
#               reproducible sequence of actions and kill points
#               (default: 12 seeds, with --iters 25: 300 crash/verify cycles)
#   --only      run only one kind of crash: kill, stale, reindex, hook or clean (default: a mix)
#   --no-hooks  the binary has no -testcrashpoint hook (an older release): only kill -9
#               at random moments is used, the hook points are skipped
# One crash/verify cycle (an "iteration"):
#   1. random wallet actions on node 0 (t send, z->z, z_mergetoaddress, shielding,
#      Sprout notes, blocks mined by node 1 or by node 0, reorgs, clean restarts)
#   2. a crash: kill -9 at a random moment (after an action, during a proving
#      operation, during generate), or _exit(77) at a named write point
#      (-testcrashpoint: the wallet checkpoint steps, the chain tip callbacks, the
#      chain-state flush, the startup rescan, shutdown), with or without frequent
#      wallet checkpoints (-testsetchaininterval=0)
#   3. the crashed datadir is copied; node 0 restarts on it normally (no -rescan), node 2
#      starts on the copy with -rescan; both follow node 1 to the same tip
#   4. exact equality of z_gettotalbalance, z_listunspent and listunspent (minconf 1)
# Output: <work>/results.txt (one line per seed), <work>/hits.txt (how often every crash
# point fired). Failures keep the crashed datadir under <work>/fail-<seed>-<iter>/.
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
#   --ref-bin   binary of the -rescan reference node (default: --bin); an older release here
#               makes the reference independent of the wallet code under test
BIN=""; WORK=""; PEER_BIN=""; REF_BIN=""; PORT_BASE=""; NOHOOKS=0; ONLY=""
SEEDS="11 23 37 41 53 67 79 83 97 101 113 127"; ITERS=25
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;; --ref-bin) REF_BIN=$2; shift 2 ;;
        --seeds) SEEDS=$2; shift 2 ;; --iters) ITERS=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;;
        --no-hooks) NOHOOKS=1; shift ;; --only) ONLY=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--peer-bin DIR] [--seeds \"..\"] [--iters N] [--no-hooks]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$BIN}; REF_BIN=${REF_BIN:-$BIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; HITS=$WORK/hits.txt; : >"$RESULTS"; : >"$HITS"
iso_base BASE "${PORT_BASE:-}" 112
trap 'stop_all' EXIT

# ---- reproducible randomness (LCG; the shell's $RANDOM is not portable) ------
RS=1
rnd() { RS=$(( (RS * 1103515245 + 12345) % 2147483648 )); R=$(( (RS / 65536) % $1 )); }

# ---- quiet helpers: nothing here may record a failure by itself ---------------
alive_n() { [ -f "$SD/node$1/pid" ] && kill -0 "$(cat "$SD/node$1/pid")" 2>/dev/null; }
# await_exit <n> <seconds>: wait for the process of node n to be gone
await_exit() { w=0; while alive_n "$1" && [ $w -lt $(( $2 * 5 )) ]; do w=$((w + 1)); sleep 0.2; done; ! alive_n "$1"; }
# qwait_op <n> <opid>: wait for an async operation; silent; returns when it ended or the node is gone
qwait_op() {
    [ -n "$2" ] || return 0
    qt=0
    while alive_n "$1" && [ $qt -lt 600 ]; do
        qs=$(cli "$1" z_getoperationstatus "[\"$2\"]" 2>/dev/null | jq -r '.[0].status' 2>/dev/null)
        case $qs in success|failed|cancelled) cli "$1" z_getoperationresult "[\"$2\"]" >/dev/null 2>&1; return 0 ;; esac
        qt=$((qt + 1)); sleep 0.5
    done
    return 0
}
zq() { # zq <from> <recipients-json>: z_sendmany and wait, quietly
    o=$(cli 0 z_sendmany "$1" "$2" 1 0.0001 2>/dev/null) || return 0
    qwait_op 0 "$o"
}
# start_try <n> <bindir> [args]: start a node, return 0 if RPC came up, 1 if it exited first. A port that
# another process happens to hold (ephemeral ports of other jobs on a shared host) is retried a few times.
start_try() {
    ta=0
    while :; do
        start_once "$@" && return 0
        ta=$((ta + 1))
        grep -qE "Unable to bind|Unable to start HTTP server|Failed to listen" "$SD/node$1/stdout.log" 2>/dev/null && [ $ta -lt 4 ] || return 1
        sleep 4
    done
}
start_once() {
    n=$1; bd=$2; shift 2; dir=$SD/node$n
    mkdir -p "$dir" "$SD/export"; echo "$bd" >"$dir/bindir"
    [ -f "$dir/zclassic.conf" ] || { echo "regtest=1"; echo "rpcuser=cc"; echo "rpcpassword=cc$n"; } >"$dir/zclassic.conf"
    rm -f "$dir/regtest/.lock"
    $ZCL_RUN "$bd/zclassicd" -datadir="$dir" -regtest -server=1 -daemon=0 -showmetrics=0 \
        -listen=1 -bind=127.0.0.1 -port=$((BASE + n)) \
        -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=$((BASE + 100 + n)) \
        -dnsseed=0 -discover=0 -listenonion=0 -upnp=0 -keypool=10 -debuglogfile=1 -exportdir="$SD/export" \
        -experimentalfeatures -zmergetoaddress $NU_ARGS "$@" >>"$dir/stdout.log" 2>&1 &
    echo "$!" >"$dir/pid"; echo "$!" >>"$SD/pids"
    st=0
    until cli "$n" getblockcount >/dev/null 2>&1; do
        kill -0 "$(cat "$dir/pid")" 2>/dev/null || { wait "$(cat "$dir/pid")" 2>/dev/null; echo "zclassicd exited with status $?" >>"$dir/stdout.log"; return 1; }
        st=$((st + 1)); [ $st -lt 900 ] || return 1
        sleep 0.5
    done
    return 0
}
# stop_try <n>: ask for a clean stop; true if the process is gone afterwards
stop_try() { cli "$1" stop >/dev/null 2>&1; await_exit "$1" 90 || { kill -9 "$(cat "$SD/node$1/pid")" 2>/dev/null; await_exit "$1" 10; return 1; }; }
tip() { cli "$1" getbestblockhash 2>/dev/null; }
# converge: both nodes on the same best block (the longest chain wins; blocks lost by the crash come back from the peer)
converge() {
    c=0
    while [ $c -lt 240 ]; do
        a=$(tip "$1"); b=$(tip "$2")
        [ -n "$a" ] && [ "$a" = "$b" ] && return 0
        c=$((c + 1)); sleep 0.5
        # equal-work forks stay parked (a reorg of more than one block needs more work): one more block settles it
        case $c in 20) cli 1 generate 1 >/dev/null 2>&1 ;; 50) cli 1 generate 2 >/dev/null 2>&1 ;; 90) cli 1 generate 4 >/dev/null 2>&1 ;; 140) cli 1 generate 8 >/dev/null 2>&1 ;; esac
    done
    return 1
}
# settle_mempools: pending transactions change what the wallet reports at one confirmation (a note spent by
# a pending transaction is not listed), and two nodes that restarted separately need not hold the same
# pending transactions. Mine them away on the peer so that both nodes are compared on the chain alone.
settle_mempools() {
    sm=0
    while [ $sm -lt 4 ]; do
        # A pending wallet transaction that a restart put back into a node's mempool reaches the peer
        # only when the wallet resends it (minutes later, at random), and the other node may never
        # have taken it back (it restarted on a shorter chain): hand every one to the peer to mine.
        for mn in 0 2; do
            for mx in $(cli "$mn" getrawmempool 2>/dev/null | jq -r '.[]' 2>/dev/null); do
                mh=$(cli "$mn" getrawtransaction "$mx" 2>/dev/null) && cli 1 sendrawtransaction "$mh" >/dev/null 2>&1
            done
        done
        n0=$(cli 0 getrawmempool 2>/dev/null | jq length 2>/dev/null); n2=$(cli 2 getrawmempool 2>/dev/null | jq length 2>/dev/null)
        n1=$(cli 1 getrawmempool 2>/dev/null | jq length 2>/dev/null)
        [ "${n0:-0}" = 0 ] && [ "${n1:-0}" = 0 ] && [ "${n2:-0}" = 0 ] && return 0
        cli 1 generate 1 >/dev/null 2>&1; converge 0 1; converge 2 1
        sm=$((sm + 1))
    done
    return 0
}
# snapshot <n>: everything a user sees of the confirmed wallet, one deterministic text
snapshot() {
    t=$(cli "$1" z_gettotalbalance 1 2>/dev/null | jq -c '[.transparent,.private]' 2>/dev/null)
    zl=$(cli "$1" z_listunspent 1 9999999 true 2>/dev/null | jq -r '.[]|"\(.txid):\(.jsindex // "s"):\(.jsoutindex // .outindex):\(.amount):\(.address)"' 2>/dev/null | sort)
    tl=$(cli "$1" listunspent 1 9999999 2>/dev/null | jq -r '.[]|"\(.txid):\(.vout):\(.amount)"' 2>/dev/null | sort)
    printf 'total %s\nz\n%s\nt\n%s\n' "$t" "$zl" "$tl"
}
# selfcheck <n>: a node's own view must not count a note or an output twice: no outpoint listed twice,
# and the private total equals the sum of the listed unspent notes (both at one confirmation).
# Prints nothing when consistent, a reason otherwise.
selfcheck() {
    zj=$(cli "$1" z_listunspent 1 9999999 true 2>/dev/null); tj=$(cli "$1" listunspent 1 9999999 2>/dev/null)
    [ -n "$zj" ] && [ -n "$tj" ] || { echo "node $1 did not answer"; return; }
    zd=$(printf '%s' "$zj" | jq -r '.[]|"\(.txid):\(.jsindex // "s"):\(.jsoutindex // .outindex)"' | sort | uniq -d | wc -l)
    td=$(printf '%s' "$tj" | jq -r '.[]|"\(.txid):\(.vout)"' | sort | uniq -d | wc -l)
    zs=$(printf '%s' "$zj" | jq '[.[].amount * 100000000 | round] | add // 0')
    pv=$(cli "$1" z_gettotalbalance 1 2>/dev/null | jq '.private | tonumber * 100000000 | round')
    [ "$zd" = 0 ] || echo "node $1 lists $zd shielded notes twice"
    [ "$td" = 0 ] || echo "node $1 lists $td transparent outputs twice"
    [ "$zs" = "$pv" ] || echo "node $1 private total $pv zat != sum of its unspent notes $zs zat"
}

# ---- scenario ---------------------------------------------------------------
HOOKS="addtowallet-after-write chaintip-before chaintip-after connect-after-updatetip connect-between-sync-and-chaintip disconnect-between-sync-and-chaintip flush-after-coins flush-before-setbestchain setbestchain-begin setbestchain-after-txs setbestchain-after-locator setbestchain-after-commit init-after-rescan any"
NHOOKS=$(echo $HOOKS | wc -w)
RUNARGS=""    # extra arguments node 0 is started with in this iteration

setup_seed() {
    start 1 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 0)) || return 1
    start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) || return 1
    cli 0 generate 120 >/dev/null; sync_to 1 0 || return 1
    ZA=$(cli 0 z_getnewaddress); ZB=$(cli 0 z_getnewaddress); ZC=$(cli 0 z_getnewaddress)
    SP1=$(cli 0 z_getnewaddress sprout); SP2=$(cli 0 z_getnewaddress sprout)
    TA=$(cli 0 getnewaddress); TB=$(cli 0 getnewaddress); MT=$(cli 1 getnewaddress)
    cli 0 sendtoaddress "$TA" 20 >/dev/null; cli 0 sendtoaddress "$TB" 20 >/dev/null
    # the peer gets transparent funds of its own, so it can pay the wallet (incoming t, Sapling, Sprout)
    for k in 1 2 3 4; do cli 0 sendtoaddress "$MT" 5 >/dev/null; done
    cli 1 generate 1 >/dev/null; sync_to 0 || return 1
    o=$(cli 0 z_shieldcoinbase "*" "$ZA" 0.0001 5 2>/dev/null | jq -r .opid); qwait_op 0 "$o"; cli 1 generate 1 >/dev/null; sync_to 0 || return 1
    # a Sprout note and a Sapling note from t funds
    zq "$TA" "[{\"address\":\"$SP1\",\"amount\":5}]"; cli 1 generate 1 >/dev/null
    sync_to 0
}

# reorg_tip: the peer replaces its newest block (a reorg of one block) and mines on
reorg_tip() {
    tb=$(tip 1); [ -n "$tb" ] && cli 1 invalidateblock "$tb" >/dev/null 2>&1
    cli 1 generate 2 >/dev/null 2>&1
}

# act: one random wallet action on node 0 (or the chain)
act() {
    rnd 19
    case $R in
        # incoming funds from the peer: a transparent payment, a Sapling note, a Sprout note
        16) cli 1 sendtoaddress "$TA" 0.07 >/dev/null 2>&1 ;;
        17) o=$(cli 1 z_sendmany "$MT" "[{\"address\":\"$ZB\",\"amount\":0.09}]" 1 0.0001 2>/dev/null) && qwait_op 1 "$o" ;;
        18) o=$(cli 1 z_sendmany "$MT" "[{\"address\":\"$SP2\",\"amount\":0.06}]" 1 0.0001 2>/dev/null) && qwait_op 1 "$o" ;;
        0|1) zq "$ZA" "[{\"address\":\"$ZB\",\"amount\":0.01},{\"address\":\"$ZC\",\"amount\":0.02},{\"address\":\"$ZA\",\"amount\":0.03}]" ;;
        2) zq "$ZB" "[{\"address\":\"$ZC\",\"amount\":0.005}]" ;;
        3) o=$(cli 0 z_mergetoaddress "[\"$ZA\",\"$ZB\",\"$ZC\"]" "$ZA" 0.0001 0 0 2>/dev/null | jq -r .opid); qwait_op 0 "$o" ;;
        4) o=$(cli 0 z_shieldcoinbase "*" "$ZB" 0.0001 2>/dev/null | jq -r .opid); qwait_op 0 "$o" ;;
        5) cli 0 sendtoaddress "$(cli 0 getnewaddress)" 0.5 >/dev/null 2>&1 ;;
        6) zq "$TB" "[{\"address\":\"$ZA\",\"amount\":1}]" ;;
        7) zq "$SP1" "[{\"address\":\"$SP2\",\"amount\":0.05}]" ;;
        8) zq "$TA" "[{\"address\":\"$SP1\",\"amount\":0.5}]" ;;
        9) cli 0 generate 2 >/dev/null 2>&1 ;;
        10|11) cli 1 generate 1 >/dev/null 2>&1 ;;
        12) cli 1 generate 3 >/dev/null 2>&1 ;;
        13) reorg_tip ;;
        14) cli 0 z_getnewaddress >/dev/null 2>&1; cli 0 backupwallet "$SD/export/bk$$" >/dev/null 2>&1; rm -f "$SD/export/bk$$" ;;
        15) zq "$ZC" "[{\"address\":\"$TA\",\"amount\":0.004}]" ;;
    esac
}
acts() { # acts <n>
    k=$1; while [ $k -gt 0 ]; do act; k=$((k - 1)); done
}

# crash_external: kill -9 at a random moment (the process is left dead, lock removed)
crash_external() {
    rnd 4
    case $R in
        0) ;;                                                         # between operations
        1) ( act ) & bg=$!; rnd 8; sleep 0.$((R + 1)); kill9 0; kill $bg 2>/dev/null; return ;;  # during an operation
        2) ( cli 0 generate 3 >/dev/null 2>&1 ) & bg=$!; rnd 6; sleep 0.$R; kill9 0; kill $bg 2>/dev/null; return ;;
        3) cli 1 generate 2 >/dev/null 2>&1; rnd 3; sleep 0.$R ;;   # right after blocks arrived
    esac
    kill9 0
}

# sc_stale: a wallet transaction is mined, a restart moves the wallet's checkpoint (the
# best-block locator) onto its block, then the peer replaces that block: the wallet sees the
# transaction disconnected and connected again after its checkpoint was written.
sc_stale() {
    # T creates notes, S spends them in the next block (S merges every note of the address)
    rnd 4
    case $R in
        0|1|2) zq "$ZA" "[{\"address\":\"$ZA\",\"amount\":0.02},{\"address\":\"$ZC\",\"amount\":0.01}]"
               cli 1 generate 1 >/dev/null 2>&1; converge 0 1 || return 0
               o=$(cli 0 z_mergetoaddress "[\"$ZA\"]" "$ZB" 0.0001 0 0 2>/dev/null | jq -r .opid); qwait_op 0 "$o" ;;
        3) zq "$SP1" "[{\"address\":\"$SP1\",\"amount\":0.05}]"
           cli 1 generate 1 >/dev/null 2>&1; converge 0 1 || return 0
           zq "$SP1" "[{\"address\":\"$SP2\",\"amount\":0.04}]" ;;
    esac
    cli 1 generate 1 >/dev/null 2>&1; converge 0 1 || return 0
    rnd 2
    if [ $R = 0 ]; then kill9 0; else stop_try 0 || true; fi
    start_try 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) || return 0
    converge 0 1 || return 0
    rnd 3
    if [ $R = 0 ]; then
        reorg_tip           # the peer's chain replaces the newest block
    else
        # the node disconnects the block that holds the transaction and connects the same block
        # again (what a restart after a rolled-back chain state, a reindex or reconsiderblock does)
        bh=$(cli 0 getblockhash $(( $(cli 0 getblockcount) - 1 )) 2>/dev/null)
        [ -n "$bh" ] && { cli 0 invalidateblock "$bh" >/dev/null 2>&1; cli 0 reconsiderblock "$bh" >/dev/null 2>&1; }
    fi
    converge 0 1 || return 0
}
# sc_reindex: the node rebuilds its block index from the block files and replays every block
# through the wallet, which already knows all of them
sc_reindex() {
    stop_try 0 || true
    start_try 0 "$BIN" -reindex -connect=127.0.0.1:$((BASE + 1)) || return 0
    converge 0 1 || return 0
    acts 1
}

# crash_hook <name> <n> <fast-checkpoints>: restart node 0 with the hook armed, drive it until it dies
crash_hook() {
    # A clean stop writes a checkpoint at the tip, so the start-up rescan (the first point) is rare
    # and only follows a crash: that point is armed behind a kill -9, the others behind either, and
    # the start-up point can only be hit once.
    if [ "$1" = init-after-rescan ]; then kill9 0 2>/dev/null || true; set -- "$1" 1 "$3"
    elif [ $(($2 % 2)) = 0 ]; then kill9 0 2>/dev/null || true; else stop_try 0 || true; fi
    ARGS="-connect=127.0.0.1:$((BASE + 1)) -testcrashpoint=$1:$2"
    [ "$3" = 1 ] && ARGS="$ARGS -testsetchaininterval=0"
    if start_try 0 "$BIN" $ARGS; then
        acts 2
        alive_n 0 && { cli 1 generate 1 >/dev/null 2>&1; rnd 2; [ $R = 0 ] && reorg_tip; acts 1; }
        alive_n 0 && { cli 0 stop >/dev/null 2>&1; await_exit 0 60 || kill9 0; }
        alive_n 0 && kill9 0
    fi
    rm -f "$SD/node0/regtest/.lock"
}

# verify <iteration> <label>: restart on the crashed datadir, compare with a -rescan node on a copy
verify() {
    it=$1; label=$2
    rm -rf "$SD/crashimg" "$SD/node2"; cp -a "$SD/node0" "$SD/crashimg"; cp -a "$SD/node0" "$SD/node2"
    rm -f "$SD/node2/regtest/.lock" "$SD/node2/pid"
    RI=""
    if ! start_try 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)); then
        # kill -9 right after invalidateblock/reconsiderblock can leave the chain database in a state the node
        # itself asks to -reindex (RewindBlockIndex); every release does, it is not about the wallet. Recover
        # the way the node asks, count it, and verify the wallet after that.
        if grep -q "restart with -reindex" "$SD/node0/stdout.log" 2>/dev/null; then
            RI="-reindex"; hit_note "chain-db-reindex-recovery" "$it"; : >"$SD/node0/stdout.log"
            start_try 0 "$BIN" -reindex -connect=127.0.0.1:$((BASE + 1)) || { bad "$it $label: node 0 did not restart even with -reindex"; keep_fail "$it"; return 1; }
        else bad "$it $label: node 0 did not restart after the crash ($(tail -n 1 "$SD/node0/stdout.log" 2>/dev/null | cut -c1-200))"; keep_fail "$it"; return 1; fi
    fi
    rs=0; until start_try 2 "$REF_BIN" -rescan $RI -connect=127.0.0.1:$((BASE + 1)); do
        rs=$((rs + 1))
        [ $rs -lt 3 ] || { bad "$it $label: reference node did not start ($(tail -n 1 "$SD/node2/stdout.log" 2>/dev/null | cut -c1-200))"; keep_fail "$it"; return 1; }
        sleep 5; rm -f "$SD/node2/regtest/.lock"
    done
    converge 0 1 || { bad "$it $label: node 0 did not reach the peer's tip"; keep_fail "$it"; return 1; }
    converge 2 1 || { bad "$it $label: reference did not reach the peer's tip"; keep_fail "$it"; return 1; }
    settle_mempools
    sleep 1
    s0=$(snapshot 0); s2=$(snapshot 2)
    # the wallet notifications of the newest block arrive a moment after the tip moves: settle once
    if [ "$s0" != "$s2" ]; then sleep 3; s0=$(snapshot 0); s2=$(snapshot 2); fi
    if [ "$s0" != "$s2" ]; then
        stop_try 2 || true
        bad "$it $label: restarted wallet differs from the rescanned reference"
        printf 'restarted:\n%s\nrescanned:\n%s\n' "$s0" "$s2" >"$SD/diff-$it.txt"
        keep_fail "$it"; return 1
    fi
    sc=$(selfcheck 0)
    if [ -n "$sc" ]; then
        stop_try 2 || true
        bad "$it $label: $(printf '%s' "$sc" | tr '\n' ';')"; printf 'selfcheck:\n%s\n%s\n' "$sc" "$s0" >"$SD/diff-$it.txt"
        keep_fail "$it"; return 1
    fi
    # Whatever the first restart repaired in memory has to be on disk: restart once more, by a clean
    # stop or by another kill -9, and ask again. The reference is unchanged (same chain, no crash).
    rnd 2
    if [ $R = 0 ]; then stop_try 0 || true; else kill9 0; fi
    if ! start_try 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)); then
        bad "$it $label: node 0 did not start the second time ($(tail -n 1 "$SD/node0/stdout.log" 2>/dev/null | cut -c1-200))"; keep_fail "$it"; return 1
    fi
    converge 0 1 && converge 2 1 || { stop_try 2 || true; bad "$it $label: the nodes did not reach the peer's tip the second time"; keep_fail "$it"; return 1; }
    settle_mempools
    sleep 1
    s0b=$(snapshot 0); s2b=$(snapshot 2)
    # a node that was killed re-connects the blocks it lost; give the wallet up to 40 s to show them
    w=0; while [ "$s0b" != "$s2b" ] && [ $w -lt 20 ]; do sleep 2; w=$((w + 1)); s0b=$(snapshot 0); s2b=$(snapshot 2); done
    [ $w -gt 0 ] && [ "$s0b" = "$s2b" ] && obs "settle_after_second_restart_$it" "$((w * 2))s"
    sc=$(selfcheck 0; selfcheck 2)
    stop_try 2 || true
    if [ -n "$sc" ]; then
        bad "$it $label: $(printf '%s' "$sc" | tr '\n' ';')"
        printf 'selfcheck:\n%s\nnode 0:\n%s\nreference:\n%s\n' "$sc" "$s0b" "$s2b" >"$SD/diff-$it.txt"
        keep_fail "$it"; return 1
    fi
    if [ "$s0b" = "$s2b" ]; then pass "$it $label"; return 0; fi
    bad "$it $label: after a second restart the wallet differs from the rescanned reference"
    printf 'second restart:\n%s\nrescanned:\n%s\n' "$s0b" "$s2b" >"$SD/diff-$it.txt"
    { echo "--- node 0 now:"; cli 0 getblockchaininfo 2>&1 | jq -c '[.blocks,.headers,.bestblockhash]' 2>&1
      echo "--- transactions the reference lists as unspent notes, as node 0 sees them:"
      printf '%s\n' "$s2b" | sed -n '/^z$/,/^t$/p' | grep -v '^[zt]$' | cut -d: -f1 | sort -u | while read -r xid; do
          printf '%s ' "$xid"; cli 0 gettransaction "$xid" 2>&1 | jq -c '[.confirmations,.blockhash]' 2>&1 | head -1; done
      echo "--- node 0 z_listunspent 0:"; cli 0 z_listunspent 0 9999999 true 2>&1 | jq -r '.[]|"\(.txid):\(.amount):conf=\(.confirmations)"' 2>&1
      echo "--- node 0 debug.log tail:"; tail -n 40 "$SD/node0/regtest/debug.log" | cut -c1-200; } >>"$SD/diff-$it.txt" 2>&1
    keep_fail "$it"; return 1
}
keep_fail() { f=$WORK/fail-$SEED-$1; rm -rf "$f"; mkdir -p "$f"; cp -a "$SD/crashimg" "$f/crashed-datadir" 2>/dev/null; cp "$SD"/diff-$1.txt "$f/" 2>/dev/null
    cp "$SD/node0/stdout.log" "$f/node0-stdout.log" 2>/dev/null; cp "$SD/node2/stdout.log" "$f/ref-stdout.log" 2>/dev/null; echo "seed=$SEED iter=$1" >"$f/WHY"; }

hit_note() { echo "$1 $2" >>"$HITS"; }

run_seed() {
    SEED=$1; SD=$WORK/seed$SEED; rm -rf "$SD"; mkdir -p "$SD"; : >"$SD/pids"
    SCN_LOG=$SD/checks.log; : >"$SCN_LOG"; SCN_ID=$SEED; OBS_LOG=$SD/obs.log; : >"$OBS_LOG"
    RS=$SEED; t0=$(now)
    say "== seed $SEED ($ITERS iterations)"
    if ! setup_seed; then bad "seed $SEED: setup failed"; stop_all; echo "$SEED|FAIL|setup|$(elapsed "$t0")s" >>"$RESULTS"; return; fi
    i=0
    while [ $i -lt "$ITERS" ]; do
        i=$((i + 1)); : >"$SD/node0/stdout.log"
        acts 2; rnd 3; [ $R = 0 ] && cli 1 generate 1 >/dev/null 2>&1
        # a control restart now and then moves the chain-state flush point without a crash
        rnd 10; if [ $R = 0 ]; then stop_try 0 || true; start_try 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) || { bad "$i: restart failed"; break; }; acts 1; fi
        rnd 100; kind=$R
        case "$ONLY" in kill) kind=5 ;; stale) kind=30 ;; reindex) kind=50 ;; hook) kind=70 ;; clean) kind=97 ;; esac
        if [ $kind -ge 95 ]; then
            # a clean shutdown, no crash: the control of every other kind
            stop_try 0 || true; label="control-clean-stop"; hit_note "clean-stop" "$i"
        elif [ $kind -lt 25 ] || { [ "$NOHOOKS" = 1 ] && [ $kind -ge 55 ]; }; then
            crash_external; hit_note "kill-9" "$i"; label="kill-9"
        elif [ $kind -lt 45 ]; then
            sc_stale; crash_external; hit_note "stale-checkpoint-reorg" "$i"; label="stale-checkpoint-reorg+kill-9"
        elif [ $kind -lt 55 ]; then
            if [ "$NOHOOKS" = 1 ]; then sc_stale; else sc_reindex; fi
            crash_external; hit_note "reindex" "$i"; label="reindex+kill-9"
        else
            h=$(( (i + SEED) % NHOOKS + 1 )); name=$(echo $HOOKS | cut -d' ' -f$h)
            rnd 3; cnt=$((R + 1)); rnd 2; fast=$R
            crash_hook "$name" "$cnt" "$fast"
            if grep -q "testcrashpoint: exiting at" "$SD/node0/stdout.log" 2>/dev/null; then
                at=$(grep "testcrashpoint: exiting at" "$SD/node0/stdout.log" | tail -1 | awk '{print $4}')
                label="hook:$name:$cnt:fast=$fast fired-at=$at"; hit_note "$at" "$i"
            else label="hook:$name:$cnt:fast=$fast not-reached"; hit_note "not-reached:$name" "$i"; fi
        fi
        # exit status 77 or a kill: the node must be gone; anything else (abort, assertion) is itself a failure
        if alive_n 0; then kill9 0; fi
        if grep -qiE 'Assertion .* failed|terminate called' "$SD/node0/stdout.log" 2>/dev/null; then bad "$i $label: the node aborted ($(grep -iE 'Assertion|terminate' "$SD/node0/stdout.log" | tail -1 | cut -c1-120))"; keep_fail "$i"; : >"$SD/node0/stdout.log"; fi
        verify "$i" "$label" || true
        stop_try 2 || true
    done
    stop_all
    np=$(grep -c '^PASS' "$SCN_LOG"); nf=$(grep -c '^FAIL' "$SCN_LOG")
    st=PASS; [ "$nf" = 0 ] && [ "$np" -gt 0 ] || st=FAIL
    echo "$SEED|$st|$np pass $nf fail|$(elapsed "$t0")s" >>"$RESULTS"
    say "   -> seed $SEED $st ($np pass, $nf fail)"
    iso_rebase BASE 112 7
}

for s in $SEEDS; do run_seed "$s"; done
say; say "seed|result|checks|time"; cat "$RESULTS"
say "crash points that fired:"; cut -d' ' -f1 "$HITS" | sort | uniq -c | sort -rn
! grep -q '|FAIL|' "$RESULTS"
