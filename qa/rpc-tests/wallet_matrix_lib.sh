#!/bin/sh
# Helpers for wallet_matrix.sh (sourced). POSIX sh, jq, no Python.
# Topology per scenario: node 0 = wallet under test ($BIN), node 1 = miner/peer
# ($PEER_BIN, defaults to $BIN). The subject node does not mine (except where a
# scenario says so), so its balances are exactly controllable.

NU_ARGS="-nuparams=5ba81b19:1 -nuparams=76b809bb:1"
FEE=0.0001

say() { printf '%s\n' "$*"; }

# ---- assertions: append PASS/FAIL lines to $SCN_LOG, never abort ----------
pass() { echo "PASS $*" >>"$SCN_LOG"; say "  ok   $*"; }
bad() { echo "FAIL $*" >>"$SCN_LOG"; say "  FAIL $*"; }
ck() { if [ "$2" = "$3" ]; then pass "$1"; else bad "$1: got [$2] want [$3]"; fi; }
# obs <key> <value>: a recorded observation, diffed across binaries
obs() { echo "$SCN_ID.$1 = $2" >>"$OBS_LOG"; say "  obs  $1 = $2"; }
# ckerr <desc> <regex> <node> <cli args...>: the call must fail and match
ckerr() {
    local d=$1 re=$2 n=$3 out; shift 3
    if out=$(cli "$n" "$@" 2>&1); then bad "$d: expected an error, got [$(printf %s "$out" | cut -c1-100)]"
    elif printf '%s' "$out" | grep -Eqi "$re"; then pass "$d"
    else bad "$d: error [$(printf %s "$out" | cut -c1-160)] does not match /$re/"; fi
}
# errtxt <node> <cli args...>: the error text (or OK:<out>) of a call, one line
errtxt() { local n=$1 o; shift; if o=$(cli "$n" "$@" 2>&1); then printf 'OK:%s' "$(printf %s "$o" | tr '\n' ' ' | cut -c1-80)"; else printf '%s' "$o" | tr '\n' ' ' | cut -c1-140; fi; }
alive() { r=$(cli "${2:-0}" getblockcount 2>/dev/null); case $r in ''|*[!0-9]*) bad "$1: daemon not responding";; *) pass "$1: daemon alive";; esac; }

zat() { jq -n --arg a "$1" '$a | tonumber * 100000000 | round'; }
btc() { awk -v z="$1" 'BEGIN { printf "%.8f", z / 100000000 }'; }
# add <a> <b> ...: signed sum of amounts, 8 decimals
add() { awk 'BEGIN { s = 0; for (i = 1; i < ARGC; i++) s += ARGV[i] * 100000000; printf "%.8f", s / 100000000 }' "$@"; }
n8() { awk -v z="$1" 'BEGIN { printf "%.8f", z }'; }
now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$(now)" 'BEGIN { printf "%.1f", b - a }'; }

# ---- nodes ----------------------------------------------------------------
cli() { local n=$1; shift; "$(cat "$SD/node$n/bindir")/zclassic-cli" -datadir="$SD/node$n" -regtest -rpcport=$((BASE + 100 + n)) -rpcclienttimeout=900 "$@"; }

# start <n> <bindir> [extra args]
start() {
    local n=$1 bd=$2 dir pid t; shift 2
    dir=$SD/node$n
    mkdir -p "$dir" "$SD/export"
    echo "$bd" >"$dir/bindir"
    if [ ! -f "$dir/zclassic.conf" ]; then
        { echo "regtest=1"; echo "rpcuser=wm"; echo "rpcpassword=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"; } >"$dir/zclassic.conf"
    fi
    "$bd/zclassicd" -datadir="$dir" -regtest -server=1 -daemon=0 -showmetrics=0 \
        -listen=1 -bind=127.0.0.1 -port=$((BASE + n)) \
        -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=$((BASE + 100 + n)) \
        -dnsseed=0 -discover=0 -listenonion=0 -upnp=0 -keypool=10 -debuglogfile=1 -exportdir="$SD/export" \
        -experimentalfeatures -developerencryptwallet -zmergetoaddress $NU_ARGS "$@" >>"$dir/stdout.log" 2>&1 &
    pid=$!
    echo "$pid" >"$dir/pid"
    echo "$pid" >>"$SD/pids"
    local t s; t=0
    until cli "$n" getblockcount >/dev/null 2>&1; do
        kill -0 "$pid" 2>/dev/null || { tail -5 "$dir/stdout.log"; bad "node $n exited during startup ($*)"; return 1; }
        t=$((t + 1)); [ $t -lt 900 ] || { bad "node $n did not start"; return 1; }
        sleep 1
    done
}
# start_fail <n> <bindir> [args]: returns 0 when the node starts
stop() {
    local n=$1 pid t; pid=$(cat "$SD/node$n/pid")
    cli "$n" stop >/dev/null 2>&1
    local t s; t=0
    while kill -0 "$pid" 2>/dev/null; do
        t=$((t + 1)); [ $t -lt 180 ] || { bad "node $n did not stop"; kill -9 "$pid"; break; }
        sleep 1
    done
}
kill9() { local pid; pid=$(cat "$SD/node$1/pid"); kill -9 "$pid" 2>/dev/null; while kill -0 "$pid" 2>/dev/null; do sleep 0.2; done; rm -f "$SD/node$1/regtest/.lock"; }
stop_all() {
    [ -f "$SD/pids" ] || return 0
    for p in $(cat "$SD/pids"); do kill "$p" 2>/dev/null; done
    for p in $(cat "$SD/pids"); do
        t=0; while kill -0 "$p" 2>/dev/null && [ $t -lt 60 ]; do t=$((t + 1)); sleep 1; done
        kill -9 "$p" 2>/dev/null
    done
}

# sync_to <n> [m]: node n reaches node m's (default 1) tip
sync_to() {
    local want t; want=$(cli "${2:-1}" getbestblockhash); t=0
    until [ "$(cli "$1" getbestblockhash)" = "$want" ]; do
        t=$((t + 1)); [ $t -lt 240 ] || { bad "node $1 did not sync"; return 1; }
        sleep 1
    done
}
# mine <count>: miner (node 1) mines, node 0 follows
mine() { cli 1 generate "$1" >/dev/null; sync_to 0; }
# wait_mempool <node> <txid>
wait_mempool() {
    local t; t=0; until cli "$1" getrawmempool | grep -q "$2"; do t=$((t + 1)); [ $t -lt 120 ] || { bad "tx $2 not in node $1 mempool"; return 1; }; sleep 1; done
}
# wait_op <n> <opid>: prints "success <txid>" or "failed <message>"
wait_op() {
    [ -n "$2" ] || { echo "failed (no operation id)"; return 0; }
    local t s; t=0
    while :; do
        s=$(cli "$1" z_getoperationstatus "[\"$2\"]" | jq -c '.[0]')
        case $(printf '%s' "$s" | jq -r .status) in
            success) printf 'success %s\n' "$(printf '%s' "$s" | jq -r .result.txid)"; return 0 ;;
            failed) printf 'failed %s\n' "$(printf '%s' "$s" | jq -r .error.message)"; return 0 ;;
        esac
        t=$((t + 1)); [ $t -lt 1800 ] || { echo "timeout"; return 1; }
        sleep 1
    done
}
# zsend <n> <from> <recipients-json> [minconf] [fee]: runs z_sendmany to
# completion; prints "success <txid>" / "failed <msg>" / "rpcerror <msg>"
zsend() {
    local op; if ! op=$(cli "$1" z_sendmany "$2" "$3" "${4:-1}" "${5:-$FEE}" 2>&1); then echo "rpcerror $op" | tr '\n' ' '; echo; return 0; fi
    wait_op "$1" "$op"
}
# zconfirm <n> <from> <recipients> [minconf] [fee]: zsend, expects success, mines it; prints txid
zconfirm() {
    local r t; r=$(zsend "$@")
    case $r in success*) t=${r#success }; wait_mempool 1 "$t"; mine 1; echo "$t" ;; *) bad "z_sendmany $2: $r"; echo none ;; esac
}

# funds ---------------------------------------------------------------------
# give_t <n> <amount>: miner pays a fresh t address of node n and confirms; prints the address
give_t() { local a; a=$(cli "$1" getnewaddress); cli 1 sendtoaddress "$a" "$2" >/dev/null; cli 1 generate 1 >/dev/null; sync_to 0; echo "$a"; }
# give_z <n> <zaddr> <amount> [memohex]: miner pays a z address through a non-coinbase t address
give_z() {
    local ta rec r; ta=$(cli 1 getnewaddress)
    cli 1 sendtoaddress "$ta" "$(add "$3" 1)" >/dev/null
    cli 1 generate 1 >/dev/null
    if [ -n "${4:-}" ]; then rec="[{\"address\":\"$2\",\"amount\":$3,\"memo\":\"$4\"}]"; else rec="[{\"address\":\"$2\",\"amount\":$3}]"; fi
    r=$(zsend 1 "$ta" "$rec" 1 "$FEE")
    case $r in success*) cli 1 generate 1 >/dev/null; sync_to "$1" ;; *) bad "give_z: $r" ;; esac
}
# setup2 [subject extra args]: node 1 miner, node 0 subject, miner has mature coins
setup2() {
    start 1 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 0)) || return 1
    start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) "$@" || return 1
    cli 1 generate 112 >/dev/null; sync_to 0
}
bal() { cli "$1" getbalance "${2:-*}" "${3:-1}"; }
zbal() { cli "$1" z_getbalance "$2" "${3:-1}"; }
