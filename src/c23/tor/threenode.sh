#!/bin/sh
# Three regtest nodes on this host, each with the embedded Tor and its own v3
# onion service (so every node has its own onion in mapLocalHost). Checks that a
# node that has an onion service of its own can still dial any OTHER onion:
#   * A and B dial each other by onion (addnode ... onetry) after both are up;
#   * C connects to A and B by onion at the same time (-connect twice) and
#     follows the blocks mined on A and, later, on B.
# This is a regression guard, not a reproducer: explicit -addnode/-connect/RPC
# dials go to the proxy by name (pszDest set), which skips the IsLocal() test
# that treated every v3 address as local once the node had its own, so builds
# from before the v3 identity fix pass it too. The identity itself is covered by
# src/test/onion_v3_tests.cpp.
# Needs real Tor network access. All state is in a fresh temporary directory.
#
#   sh threenode.sh <bindir> <inprocess|child|default>
set -u
BINDIR=${1:?bindir}
MODE=${2:?inprocess, child or default}
MODE_LINE="embeddedtormode=$MODE"
if [ "$MODE" = default ]; then
    MODE_LINE=""
    case "$(uname -s)" in Linux) MODE=child ;; *) MODE=inprocess ;; esac
fi
ZD=$BINDIR/zclassicd
CLI=$BINDIR/zclassic-cli
TMP=$(mktemp -d "${TMPDIR:-/tmp}/zcl-threenode.XXXXXX")
A=$TMP/a
B=$TMP/b
C=$TMP/c
mkdir -p "$A" "$B" "$C"
fail=0
pass=0
t0=$(date +%s)

say() { printf '%s\n' "$*"; }
ok() { pass=$((pass + 1)); say "PASS $*"; }
bad() { fail=$((fail + 1)); say "FAIL $*"; }
check() { if [ "$1" = 0 ]; then ok "$2"; else bad "$2"; fi; }
now() { echo $(( $(date +%s) - t0 )); }

# Pick the base of a block of free loopback ports. Random bases collided with other
# jobs on a busy shared host, and half the old range (32768+) is the kernel's
# ephemeral range, so stay below it and probe every port of the block first.
# ZCL_TEST_PORT_BASE pins the base for a caller that manages ports itself.
port_busy() { # tcp-port -> true when something already listens on it
    if command -v ss >/dev/null 2>&1; then
        [ -n "$(ss -Htln "sport = :$1" 2>/dev/null)" ]
    else
        lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
    fi
}
port() {
    if [ -n "${ZCL_TEST_PORT_BASE:-}" ]; then echo "$ZCL_TEST_PORT_BASE"; return; fi
    _try=0
    while :; do
        _base=$(awk -v seed="$$$(date +%s)" -v t="$_try" 'BEGIN { srand(seed + t); print 20000 + int(rand() * 12000) }')
        _i=0; _ok=1
        while [ "$_i" -lt 24 ]; do
            if port_busy $((_base + _i)); then _ok=0; break; fi
            _i=$((_i + 1))
        done
        _try=$((_try + 1))
        if [ "$_ok" -eq 1 ] || [ "$_try" -ge 200 ]; then echo "$_base"; return; fi
    done
}
PA=$(port); RA=$((PA + 1)); PB=$((PA + 2)); RB=$((PA + 3)); PC=$((PA + 4)); RC=$((PA + 5))

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
conf "$C" "$PC" "$RC"
cli_a() { "$CLI" -datadir="$A" "$@" 2>&1; }
cli_b() { "$CLI" -datadir="$B" "$@" 2>&1; }
cli_c() { "$CLI" -datadir="$C" "$@" 2>&1; }

PID_A=
PID_B=
PID_C=
cleanup() {
    for p in "$PID_A" "$PID_B" "$PID_C"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
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
wait_onion() { # cli-function -> prints the onion address
    i=0
    while [ $i -lt 180 ]; do
        o=$(onion_of "$1")
        if [ -n "$o" ]; then echo "$o"; return 0; fi
        sleep 1; i=$((i + 1))
    done
    return 1
}
height_is() { # cli-function height seconds
    i=0
    while [ $i -lt "$3" ]; do
        [ "$($1 getblockcount 2>/dev/null)" = "$2" ] && return 0
        sleep 3; i=$((i + 3))
    done
    return 1
}
# the first "addr" of getpeerinfo entries that are outbound (inbound false) to $2
outbound_to() { # cli-function onion:port
    $1 getpeerinfo | tr -d ' ",' | awk -v want="$2" '
        /^addr:/ { a = substr($0, 6) }
        /^inbound:false/ { if (a == want) { found = 1 } }
        END { exit found ? 0 : 1 }'
}
peer_count() { $1 getpeerinfo | grep -c '"addr"'; }
tor_progress() { # datadir
    f=$1/regtest/tor/tor.log
    [ -f "$f" ] || f=$1/regtest/tor/tor-child.log
    grep -o 'Bootstrapped [0-9]*%' "$f" 2>/dev/null | tr -dc '0-9\n' | sort -n | tail -1
}

say "tmp $TMP mode $MODE ports A=$PA B=$PB C=$PC"

# ------------------------------------------------------------ nodes A and B
"$ZD" -datadir="$A" -bind=127.0.0.1 -rpcbind=127.0.0.1 > "$TMP/a.out" 2>&1 &
PID_A=$!
"$ZD" -datadir="$B" -bind=127.0.0.1 -rpcbind=127.0.0.1 > "$TMP/b.out" 2>&1 &
PID_B=$!
wait_rpc cli_a 120; check $? "A: RPC up after $(now)s"
wait_rpc cli_b 120; check $? "B: RPC up after $(now)s"
OA=$(wait_onion cli_a); [ ${#OA} = 62 ]; check $? "A: own v3 onion $OA after $(now)s"
OB=$(wait_onion cli_b); [ ${#OB} = 62 ]; check $? "B: own v3 onion $OB after $(now)s"
[ "$OA" != "$OB" ]; check $? "A and B have different onions"
cli_a generate 5 >/dev/null; [ "$(cli_a getblockcount)" = 5 ]; check $? "A: mined 5 blocks"
for n in A B; do
    d=$A; [ $n = B ] && d=$B
    i=0
    while [ $i -lt 300 ]; do [ "$(tor_progress "$d")" = 100 ] && break; sleep 2; i=$((i + 2)); done
    [ "$(tor_progress "$d")" = 100 ]; check $? "$n: Tor bootstrapped to $(tor_progress "$d")% after $(now)s"
done

# A and B dial each other, each with its own onion already in mapLocalHost.
i=0
while [ $i -lt 600 ]; do
    cli_a addnode "$OB:$PB" onetry >/dev/null
    cli_b addnode "$OA:$PA" onetry >/dev/null
    outbound_to cli_a "$OB:$PB" && outbound_to cli_b "$OA:$PA" && break
    sleep 10; i=$((i + 10))
done
outbound_to cli_a "$OB:$PB"; check $? "A: dialled B's onion ($OB:$PB) with its own onion service up (after $(now)s)"
outbound_to cli_b "$OA:$PA"; check $? "B: dialled A's onion ($OA:$PA) with its own onion service up (after $(now)s)"
height_is cli_b 5 300; check $? "B: synced to height $(cli_b getblockcount) from A over the onion link"
grep -q "AddLocal($OA" "$A/regtest/debug.log"; check $? "A: its own onion is in mapLocalHost ($(grep -c 'AddLocal(' "$A/regtest/debug.log") AddLocal lines)"

# ------------------------------------------------------------------ node C
# C is told about both onions at start (two -connect), and has its own.
{
    echo "connect=$OA:$PA"
    echo "connect=$OB:$PB"
} >> "$C/zclassic.conf"
"$ZD" -datadir="$C" -rpcbind=127.0.0.1 > "$TMP/c.out" 2>&1 &
PID_C=$!
wait_rpc cli_c 120; check $? "C: RPC up after $(now)s"
OC=$(wait_onion cli_c); [ ${#OC} = 62 ]; check $? "C: own v3 onion $OC"
i=0
while [ $i -lt 900 ]; do
    outbound_to cli_c "$OA:$PA" && outbound_to cli_c "$OB:$PB" && break
    sleep 5; i=$((i + 5))
done
outbound_to cli_c "$OA:$PA"; check $? "C: connected to A's onion"
outbound_to cli_c "$OB:$PB"; check $? "C: connected to B's onion at the same time ($(peer_count cli_c) peers)"
[ "$(peer_count cli_c)" -ge 2 ]; check $? "C: holds two onion peers at once ($(peer_count cli_c))"
height_is cli_c 5 600; check $? "C: synced to height $(cli_c getblockcount) through the two onion peers"
[ "$(cli_c getbestblockhash)" = "$(cli_a getbestblockhash)" ] && [ -n "$(cli_a getbestblockhash)" ]
check $? "C: best block equals A's"

# Blocks mined on B reach C (and A) over the onion links.
cli_b generate 3 >/dev/null
height_is cli_a 8 300; check $? "A: followed B to height $(cli_a getblockcount)"
height_is cli_c 8 300; check $? "C: followed to height $(cli_c getblockcount)"
[ "$(cli_c getbestblockhash)" = "$(cli_b getbestblockhash)" ]; check $? "C: best block equals B's"

# Nobody was banned and nobody was refused as "local".
for n in A B C; do
    d=$A; [ $n = B ] && d=$B; [ $n = C ] && d=$C
    ! grep -qi 'banned\|Warning: not banning' "$d/regtest/debug.log"
    check $? "$n: no ban line in debug.log"
done
[ "$(cli_c listbanned | grep -c '"address"')" = 0 ]; check $? "C: ban list empty"

for n in C B A; do
    case $n in A) c=cli_a; p=$PID_A ;; B) c=cli_b; p=$PID_B ;; C) c=cli_c; p=$PID_C ;; esac
    $c stop >/dev/null
    wait_gone "$p" 90; check $? "$n: exited after stop"
done
PID_A=; PID_B=; PID_C=
sleep 1
! pgrep -f -- "$TMP" >/dev/null; check $? "no process of this test is left running"
! grep -q 'ERROR: AddressSanitizer\|runtime error:' "$TMP"/*.out
check $? "no sanitizer report in the nodes' output"

say "RESULT mode=$MODE pass=$pass fail=$fail seconds=$(now)"
if [ "$fail" = 0 ]; then
    rm -rf "$TMP"
else
    say "kept $TMP"
fi
[ "$fail" = 0 ]
