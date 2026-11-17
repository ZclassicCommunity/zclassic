#!/bin/sh
# Two regtest nodes on this host, each with the embedded Tor. Node B reaches
# node A only through A's v3 onion service and syncs blocks mined on A.
# Needs real Tor network access. All state is in a fresh temporary directory.
#
#   sh twonode.sh <bindir> <inprocess|child|default> [strace]
#
# "default" writes no embeddedtormode line, so the daemon's compiled-in default runs
# (child on Linux, inprocess elsewhere); the checks for that mode then apply.
#
# <bindir> holds zclassicd and zclassic-cli. With "strace", node B runs under
# strace -f -e trace=network and privacy_check.sh inspects every network
# system call it made.
set -u
BINDIR=${1:?bindir}
MODE=${2:?inprocess, child or default}
MODE_LINE="embeddedtormode=$MODE"
if [ "$MODE" = default ]; then
    MODE_LINE=""
    case "$(uname -s)" in Linux) MODE=child ;; *) MODE=inprocess ;; esac
fi
TRACE=${3:-}
ZD=$BINDIR/zclassicd
CLI=$BINDIR/zclassic-cli
here=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/zcl-twonode.XXXXXX")
A=$TMP/a
B=$TMP/b
mkdir -p "$A" "$B"
fail=0
pass=0
t0=$(date +%s)

say() { printf '%s\n' "$*"; }
ok() { pass=$((pass + 1)); say "PASS $*"; }
bad() { fail=$((fail + 1)); say "FAIL $*"; }
check() { if [ "$1" = 0 ]; then ok "$2"; else bad "$2"; fi; }
now() { echo $(( $(date +%s) - t0 )); }
fmode() { # path -> octal mode (GNU stat -c, else BSD stat -f)
    stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null
}
listen_of() { # tcp-port -> sorted local listen addresses (ss on Linux, lsof elsewhere)
    if command -v ss >/dev/null 2>&1; then
        ss -Htln "sport = :$1" 2>/dev/null | awk '{ print $4 }' | sort -u | tr '\n' ' '
    else
        lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | awk 'NR > 1 { print $9 }' | sort -u | tr '\n' ' '
    fi
}

# Free loopback ports: P2P and RPC for each node.
port() {
    awk -v seed="$$$(date +%s)" 'BEGIN { srand(seed); print 20000 + int(rand() * 20000) }'
}
PA=$(port); RA=$((PA + 1)); PB=$((PA + 2)); RB=$((PA + 3))

conf() { # dir p2p rpc
    cat > "$1/zclassic.conf" <<EOF
regtest=1
server=1
rpcuser=zcltest
rpcpassword=zcltest$$
rpcport=$3
rpcallowip=127.0.0.1
port=$2
listen=1
onlynet=onion
embeddedtor=1
$MODE_LINE
debug=tor
debug=net
debuglogfile=1
EOF
}
conf "$A" "$PA" "$RA"
conf "$B" "$PB" "$RB"
cli_a() { "$CLI" -datadir="$A" "$@" 2>&1; }
cli_b() { "$CLI" -datadir="$B" "$@" 2>&1; }

PID_A=
PID_B=
cleanup() {
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null
}
trap cleanup EXIT INT TERM

wait_rpc() { # cli-function seconds
    i=0
    while [ $i -lt "$2" ]; do
        if $1 getblockcount >/dev/null 2>&1; then return 0; fi
        sleep 1; i=$((i + 1))
    done
    return 1
}
wait_gone() { # pid seconds
    i=0
    while [ $i -lt "$2" ]; do
        kill -0 "$1" 2>/dev/null || return 0
        sleep 1; i=$((i + 1))
    done
    return 1
}
onion_of() { # cli-function
    $1 getnetworkinfo | tr -d ' ",' | awk -F: '/^address:.*\.onion$/ { print $2; exit }'
}
tor_progress() { # datadir -> highest bootstrap percentage logged by Tor
    f=$1/regtest/tor/tor.log
    [ -f "$f" ] || f=$1/regtest/tor/tor-child.log
    grep -o 'Bootstrapped [0-9]*%' "$f" 2>/dev/null | tr -dc '0-9\n' | sort -n | tail -1
}

say "tmp $TMP mode $MODE ports A=$PA/$RA B=$PB/$RB"

# ------------------------------------------------------------------ node A
"$ZD" -datadir="$A" -bind=127.0.0.1 -rpcbind=127.0.0.1 > "$TMP/a.out" 2>&1 &
PID_A=$!
wait_rpc cli_a 120; check $? "A: RPC up after $(now)s"
ONION=
i=0
while [ $i -lt 120 ]; do
    ONION=$(onion_of cli_a)
    [ -n "$ONION" ] && break
    sleep 1; i=$((i + 1))
done
[ ${#ONION} = 62 ]; check $? "A: announces a v3 onion local address ($ONION) after $(now)s"
grep -q 'embedded Tor started' "$A/regtest/debug.log"; check $? "A: $(grep -o 'embedded Tor started.*' "$A/regtest/debug.log" | head -1)"
KEY=$A/regtest/onion_v3_private_key
[ "$(fmode "$KEY")" = 600 ]; check $? "A: onion key file mode is $(fmode "$KEY") (umask $(umask))"
[ "$(fmode "$A/regtest/tor")" = 700 ]; check $? "A: tor state dir mode is $(fmode "$A/regtest/tor")"
cli_a generate 5 >/dev/null; [ "$(cli_a getblockcount)" = 5 ]; check $? "A: mined 5 blocks (height $(cli_a getblockcount))"

i=0
while [ $i -lt 240 ]; do
    [ "$(tor_progress "$A")" = 100 ] && break
    sleep 2; i=$((i + 2))
done
[ "$(tor_progress "$A")" = 100 ]; check $? "A: Tor bootstrapped to $(tor_progress "$A")% after $(now)s"

# ------------------------------------------------------------------ node B
# B knows A only by its onion address.
echo "connect=$ONION:$PA" >> "$B/zclassic.conf"
# A host name B must never resolve itself: with -onlynet=onion it has to go to
# Tor as a name (and fail there; .invalid does not exist).
echo "addnode=zcl-embedded-tor-test.invalid:8033" >> "$B/zclassic.conf"
# A literal IPv4 address (TEST-NET-1, never routed). The name proxy does not
# cover it; it must still go to Tor, never be dialled directly. The compiled
# mainnet bootstrap peers that init adds as -addnode take the same path.
echo "addnode=192.0.2.1:8033" >> "$B/zclassic.conf"
# B runs without -bind: an onion-only node must then listen on loopback only.
if [ "$TRACE" = strace ]; then
    strace -f -qq -e trace=network,clone,clone3,fork,vfork,execve -o "$TMP/b.strace" "$ZD" -datadir="$B" -rpcbind=127.0.0.1 > "$TMP/b.out" 2>&1 &
else
    "$ZD" -datadir="$B" -rpcbind=127.0.0.1 > "$TMP/b.out" 2>&1 &
fi
PID_B=$!
wait_rpc cli_b 120; check $? "B: RPC up after $(now)s"
LISTEN_B=$(listen_of "$PB")
[ "$LISTEN_B" = "127.0.0.1:$PB " ]; check $? "B: P2P port listens on loopback only without -bind ($LISTEN_B)"
i=0
while [ $i -lt 600 ]; do
    [ "$(cli_b getblockcount 2>/dev/null)" = 5 ] && break
    sleep 3; i=$((i + 3))
done
[ "$(cli_b getblockcount)" = 5 ]; check $? "B: synced to height $(cli_b getblockcount) through A's onion service after $(now)s"
[ "$(cli_b getbestblockhash)" = "$(cli_a getbestblockhash)" ] && [ -n "$(cli_a getbestblockhash)" ]
check $? "B: best block equals A's ($(cli_a getbestblockhash))"
cli_b getpeerinfo | grep -q "\"addr\" *: *\"$ONION:$PA\""; check $? "B: its peer is $ONION:$PA"
PEERS_A=$(cli_a getpeerinfo | grep -c '"addr"')
cli_a getpeerinfo | grep '"addr"' | grep -q '127\.0\.0\.1'
check $? "A: sees $PEERS_A inbound peer(s), arriving from the local Tor (127.0.0.1)"
[ ${#ONION} = 62 ] && [ "$(onion_of cli_b)" != "$ONION" ] && [ -n "$(onion_of cli_b)" ]
check $? "B: has its own onion service ($(onion_of cli_b))"

# Blocks mined while connected propagate over the onion link.
cli_a generate 3 >/dev/null
i=0
while [ $i -lt 180 ]; do
    [ "$(cli_b getblockcount 2>/dev/null)" = 8 ] && break
    sleep 2; i=$((i + 2))
done
[ "$(cli_b getblockcount)" = 8 ] && [ "$(cli_b getbestblockhash)" = "$(cli_a getbestblockhash)" ]
check $? "B: followed A to height $(cli_b getblockcount) after $(now)s"

# ------------------------------------- init failure after Tor has been started
# Node C wants A's P2P port. Its Tor is up before the bind fails, so it must
# be stopped on the way out.
C=$TMP/c
mkdir -p "$C"
conf "$C" "$PA" "$((PA + 4))"
"$ZD" -datadir="$C" -bind=127.0.0.1 -rpcbind=127.0.0.1 > "$TMP/c.out" 2>&1
RC_C=$?
[ "$RC_C" != 0 ] && grep -q 'Unable to bind' "$TMP/c.out"
check $? "C: startup fails on the busy P2P port (exit $RC_C: $(grep -o 'Unable to bind[^.]*' "$TMP/c.out" | head -1))"
grep -q 'embedded Tor started' "$C/regtest/debug.log" && grep -q 'embedded Tor stopped' "$C/regtest/debug.log"
check $? "C: its Tor was started and then $(grep -o 'embedded Tor stopped.*' "$C/regtest/debug.log" | tail -1)"
TORPID_C=$(grep -o 'embedded Tor started (child process, pid [0-9]*' "$C/regtest/debug.log" | grep -o '[0-9]*$' | head -1)
! pgrep -f -- "$C" >/dev/null && { [ -z "$TORPID_C" ] || ! kill -0 "$TORPID_C" 2>/dev/null; }
check $? "C: no process left behind (Tor child pid: ${TORPID_C:-none, in-process})"

# ------------------------------------------------------------ clean shutdown
TORPID_A=$(grep -o 'embedded Tor started (child process, pid [0-9]*' "$A/regtest/debug.log" | grep -o '[0-9]*$' | head -1)
TORPID_B=$(grep -o 'embedded Tor started (child process, pid [0-9]*' "$B/regtest/debug.log" | grep -o '[0-9]*$' | head -1)
ZB=$(pgrep -f -- "zclassicd -datadir=$B" | head -1)
cli_b stop >/dev/null
wait_gone "$PID_B" 90; check $? "B: exited after stop"
[ -n "$ZB" ] && wait_gone "$ZB" 30
PID_B=
grep -q 'embedded Tor stopped' "$B/regtest/debug.log"; check $? "B: $(grep -o 'embedded Tor stopped.*' "$B/regtest/debug.log" | tail -1)"
cli_a stop >/dev/null
wait_gone "$PID_A" 90; check $? "A: exited after stop"
PID_A=
grep -q 'embedded Tor stopped' "$A/regtest/debug.log"; check $? "A: $(grep -o 'embedded Tor stopped.*' "$A/regtest/debug.log" | tail -1)"
if [ "$MODE" = child ]; then
    [ -n "$TORPID_A" ] && [ -n "$TORPID_B" ] && ! kill -0 "$TORPID_A" 2>/dev/null && ! kill -0 "$TORPID_B" 2>/dev/null
    check $? "child mode: Tor processes $TORPID_A and $TORPID_B are gone"
fi
sleep 1
! pgrep -f -- "$TMP" >/dev/null; check $? "no process of this test is left running"

# ------------------------------------------------- restart reuses the service
"$ZD" -datadir="$A" -bind=127.0.0.1 -rpcbind=127.0.0.1 > "$TMP/a2.out" 2>&1 &
PID_A=$!
wait_rpc cli_a 120
ONION2=
i=0
while [ $i -lt 120 ]; do
    ONION2=$(onion_of cli_a)
    [ -n "$ONION2" ] && break
    sleep 1; i=$((i + 1))
done
[ "$ONION2" = "$ONION" ]; check $? "A restarted: same onion address from the cached key ($ONION2)"
[ "$(cli_a getblockcount)" = 8 ]; check $? "A restarted: height $(cli_a getblockcount)"
cli_a stop >/dev/null
wait_gone "$PID_A" 90; check $? "A: exited after the second stop"
PID_A=

if [ "$TRACE" = strace ]; then
    sh "$here/privacy_check.sh" "$TMP/b.strace" "$B/regtest/debug.log"
    check $? "privacy: node B's network system calls (see lines above)"
fi

grep -q 'zcl-embedded-tor-test.invalid' "$B/regtest/debug.log"
check $? "B: tried the .invalid addnode $(grep -c 'zcl-embedded-tor-test.invalid' "$B/regtest/debug.log") time(s); it went to the proxy as a name"
grep -q 'trying connection 192.0.2.1:8033' "$B/regtest/debug.log"
check $? "B: tried the literal IPv4 addnode $(grep -c 'trying connection 192.0.2.1:8033' "$B/regtest/debug.log") time(s) (through Tor; the strace check covers direct dials)"

# ------------------------------------------------ Tor exits: node shuts down
if [ "$MODE" = child ]; then
    E=$TMP/e
    mkdir -p "$E"
    conf "$E" "$((PA + 5))" "$((PA + 6))"
    "$ZD" -datadir="$E" -rpcbind=127.0.0.1 > "$TMP/e.out" 2>&1 &
    PID_E=$!
    i=0
    while [ $i -lt 120 ]; do
        "$CLI" -datadir="$E" getblockcount >/dev/null 2>&1 && break
        sleep 1; i=$((i + 1))
    done
    TORPID_E=$(grep -o 'embedded Tor started (child process, pid [0-9]*' "$E/regtest/debug.log" | grep -o '[0-9]*$' | head -1)
    [ -n "$TORPID_E" ] && kill -9 "$TORPID_E"
    wait_gone "$PID_E" 60; RC_E=$?
    grep -q 'embedded Tor has exited; shutting down' "$E/regtest/debug.log" && [ "$RC_E" = 0 ]
    check $? "E: killing its Tor child (pid ${TORPID_E:-none}) shuts the node down"
    kill "$PID_E" 2>/dev/null
fi

# Sanitizer reports (only an instrumented build prints any).
! grep -q 'ERROR: AddressSanitizer\|runtime error:' "$TMP"/*.out
check $? "no AddressSanitizer error and no UBSan runtime error in the nodes' output"
grep -h 'ERROR: AddressSanitizer\|runtime error:\|SUMMARY: ' "$TMP"/*.out | sort | uniq -c | head -20

say "RESULT mode=$MODE pass=$pass fail=$fail seconds=$(now)"
if [ "$fail" = 0 ]; then
    rm -rf "$TMP"
else
    say "kept $TMP"
fi
[ "$fail" = 0 ]
