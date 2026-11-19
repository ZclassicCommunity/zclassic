#!/bin/sh
# An old zclassicd (beta 12 and older, no BIP155) must be unaffected by a node
# that speaks addrv2. Regtest, clearnet only, no Tor, all state in a fresh
# temporary directory, ports random.
#
#   sh oldpeer.sh <new-bindir> <old-bindir> <base-bindir>
#
#   new-bindir   the zclassicd/zclassic-cli with addrv2 (this branch)
#   old-bindir   the beta 12 zclassicd/zclassic-cli (the "old peer")
#   base-bindir  the zclassicd/zclassic-cli this branch was cut from
#
# The same scenario runs twice with the old peer: once against the base binary,
# once against the new one. The old peer must stay connected and must not log
# a disconnect or a ban; the "addr", "getaddr" and "verack" messages the new
# node sends must be the same (command and size, in the same order) as the base
# node's. The only difference on the wire is the extra "sendaddrv2" command,
# which an old peer ignores as an unknown command. Byte-for-byte equality of the
# addr payload is covered by the unit test addrv2_tests/addr_bytes_unchanged_for_old_peer.
# The new node's peers.dat, written after it has seen an onion address, must be
# readable by the old binary.
set -u
NEW=${1:?new bindir}
OLD=${2:?old (beta 12) bindir}
BASE=${3:?base bindir}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/zcl-oldpeer.XXXXXX")
fail=0
pass=0
say() { printf '%s\n' "$*"; }
ok() { pass=$((pass + 1)); say "PASS $*"; }
bad() { fail=$((fail + 1)); say "FAIL $*"; }
check() { if [ "$1" = 0 ]; then ok "$2"; else bad "$2"; fi; }

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
PO=$(port); RO=$((PO + 1)); PN=$((PO + 2)); RN=$((PO + 3))

PIDS=
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT INT TERM

conf() { # dir p2p rpc extra...
    d=$1; p=$2; r=$3; shift 3
    mkdir -p "$d"
    {
        echo regtest=1
        echo server=1
        echo rpcuser=zcltest
        echo "rpcpassword=zcltest$$"
        echo "rpcport=$r"
        echo rpcallowip=127.0.0.1
        echo "port=$p"
        echo listen=1
        echo bind=127.0.0.1
        echo rpcbind=127.0.0.1
        echo dnsseed=0
        echo debug=net
        echo debug=addrman
        echo debuglogfile=1
        for l in "$@"; do echo "$l"; done
    } > "$d/zclassic.conf"
}
wait_rpc() { # cli datadir seconds
    i=0
    while [ $i -lt "$3" ]; do
        "$1" -datadir="$2" getblockcount >/dev/null 2>&1 && return 0
        sleep 1; i=$((i + 1))
    done
    return 1
}
wait_gone() { i=0; while [ $i -lt "$2" ]; do kill -0 "$1" 2>/dev/null || return 0; sleep 1; i=$((i + 1)); done; return 1; }
peers() { "$1" -datadir="$2" getpeerinfo 2>/dev/null | grep -c '"addr"'; }

# one run: $1 label, $2 bindir of the node under test
run() {
    label=$1; bin=$2
    O=$TMP/$label-old; N=$TMP/$label-node
    conf "$O" "$PO" "$RO"
    conf "$N" "$PN" "$RN" "externalip=93.184.216.34"
    "$OLD/zclassicd" -datadir="$O" > "$TMP/$label-old.out" 2>&1 &
    PO_PID=$!
    "$bin/zclassicd" -datadir="$N" > "$TMP/$label-node.out" 2>&1 &
    PN_PID=$!
    PIDS="$PIDS $PO_PID $PN_PID"
    wait_rpc "$OLD/zclassic-cli" "$O" 120; check $? "$label: old peer RPC up"
    wait_rpc "$bin/zclassic-cli" "$N" 120; check $? "$label: node RPC up"
    # a fresh tip, so the node is not in initial block download and advertises itself
    "$bin/zclassic-cli" -datadir="$N" generate 1 >/dev/null 2>&1
    "$bin/zclassic-cli" -datadir="$N" addnode "127.0.0.1:$PO" onetry >/dev/null 2>&1
    i=0
    while [ $i -lt 60 ]; do
        [ "$(peers "$OLD/zclassic-cli" "$O")" -ge 1 ] && break
        sleep 1; i=$((i + 1))
    done
    [ "$(peers "$OLD/zclassic-cli" "$O")" -ge 1 ]; check $? "$label: old peer is connected to the node"
    # old peer syncs the block: proof the link works for real traffic
    i=0
    while [ $i -lt 60 ]; do
        [ "$("$OLD/zclassic-cli" -datadir="$O" getblockcount 2>/dev/null)" = 1 ] && break
        sleep 1; i=$((i + 1))
    done
    [ "$("$OLD/zclassic-cli" -datadir="$O" getblockcount 2>/dev/null)" = 1 ]; check $? "$label: old peer followed the node to height 1"
    sleep 20
    [ "$(peers "$OLD/zclassic-cli" "$O")" -ge 1 ] && [ "$(peers "$bin/zclassic-cli" "$N")" -ge 1 ]
    check $? "$label: still connected after 20s on both sides"
    ! grep -qi 'banned\|disconnecting peer\|Warning: not banning' "$O/regtest/debug.log"
    check $? "$label: old peer logged no ban or disconnect"
    # what the node sent to the old peer, in order, without the sizes of ping/pong/version
    grep -o 'sending: [a-z0-9]* ([0-9]* bytes)' "$N/regtest/debug.log" | grep -E 'sending: (addr|getaddr|verack|addrv2|sendaddrv2) ' > "$TMP/$label.sent"
    grep -o 'received: [a-z0-9]* ([0-9]* bytes)' "$O/regtest/debug.log" | grep -E 'received: (addr|getaddr|verack|addrv2|sendaddrv2) ' > "$TMP/$label.recv"
    say "--- $label: sent by node"; cat "$TMP/$label.sent"
    "$OLD/zclassic-cli" -datadir="$O" stop >/dev/null 2>&1
    "$bin/zclassic-cli" -datadir="$N" stop >/dev/null 2>&1
    wait_gone "$PO_PID" 60; check $? "$label: old peer exited"
    wait_gone "$PN_PID" 60; check $? "$label: node exited"
    PIDS=
}

say "tmp $TMP"
run base "$BASE"
run new "$NEW"

# the legacy stream is the same; the only extra command is sendaddrv2
grep -v sendaddrv2 "$TMP/new.sent" > "$TMP/new.sent.legacy"
cmp -s "$TMP/base.sent" "$TMP/new.sent.legacy"; check $? "node to old peer: addr/getaddr/verack identical (command, size, order) to the base binary"
grep -q 'sending: addr ' "$TMP/new.sent"; check $? "the node did send an addr message (the comparison is not empty)"
! grep -q 'sending: addrv2 ' "$TMP/new.sent"; check $? "no addrv2 was sent to the old peer"
grep -q 'sending: sendaddrv2 ' "$TMP/new.sent"; check $? "sendaddrv2 was announced (ignored by the old peer)"
grep -q 'Unknown command "sendaddrv2"' "$TMP/new-old/regtest/debug.log"; check $? "old peer ignored sendaddrv2 as an unknown command"

# peers.dat of the new node, after it has stored addresses, loads in the old binary
cp "$TMP/new-node/regtest/peers.dat" "$TMP/peers.dat.new" 2>/dev/null
[ -s "$TMP/peers.dat.new" ]; check $? "the new node wrote peers.dat"
if [ -s "$TMP/peers.dat.new" ]; then
    # load it in the old binary (fresh datadir, no network)
    L=$TMP/old-load
    conf "$L" "$PO" "$RO" connect=0 listen=0
    mkdir -p "$L/regtest"
    cp "$TMP/peers.dat.new" "$L/regtest/peers.dat"
    "$OLD/zclassicd" -datadir="$L" > "$TMP/old-load.out" 2>&1 &
    PL=$!
    PIDS="$PL"
    wait_rpc "$OLD/zclassic-cli" "$L" 120
    nl=$(grep -o 'Loaded [0-9]* addresses from peers.dat' "$L/regtest/debug.log" | awk '{print $2}')
    nn=$(grep -o 'Flushed [0-9]* addresses to peers.dat' "$TMP/new-node/regtest/debug.log" | tail -1 | awk '{print $2}')
    [ -n "$nl" ] && [ "$nl" = "$nn" ]
    check $? "the old binary loaded the new node's peers.dat with every entry ($nn written, ${nl:-none} loaded)"
    "$OLD/zclassic-cli" -datadir="$L" stop >/dev/null 2>&1
    wait_gone "$PL" 60
    PIDS=
fi
[ ! -e "$TMP/new-node/regtest/onion_peers.dat" ] || say "note: onion_peers.dat present ($(wc -c < "$TMP/new-node/regtest/onion_peers.dat") bytes)"

say "RESULT pass=$pass fail=$fail"
if [ "$fail" = 0 ]; then rm -rf "$TMP"; else say "kept $TMP"; fi
[ "$fail" = 0 ]
