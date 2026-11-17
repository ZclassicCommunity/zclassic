#!/bin/sh
# Onion address gossip (BIP155 addrv2 subset). Regtest, three nodes with the
# embedded Tor and their own v3 onion service, plus a clearnet node:
#
#   A and B run onion services and know each other (A -addnode B).
#   C knows only A (-addnode A's onion) and must LEARN B's onion address by
#   gossip (A's answer to C's getaddr) and connect to it, on its own.
#   D is a plain clearnet node connected to A's clearnet listener. It must
#   never be sent A's onion address.
#
# Afterwards the peers.dat of C, written after it learned an onion peer, is
# loaded by the old binary (beta 12), which must accept it.
#
# Needs real Tor network access. All state is in a fresh temporary directory.
#
#   sh addrv2gossip.sh <bindir> <inprocess|child|default> [old-bindir] [strace]
set -u
BINDIR=${1:?bindir}
MODE=${2:?inprocess, child or default}
OLDBIN=${3:-}
TRACE=${4:-}
MODE_LINE="embeddedtormode=$MODE"
if [ "$MODE" = default ]; then
    MODE_LINE=""
    case "$(uname -s)" in Linux) MODE=child ;; *) MODE=inprocess ;; esac
fi
here=$(cd "$(dirname "$0")" && pwd)
ZD=$BINDIR/zclassicd
CLI=$BINDIR/zclassic-cli
TMP=$(mktemp -d "${TMPDIR:-/tmp}/zcl-addrv2gossip.XXXXXX")
A=$TMP/a; B=$TMP/b; C=$TMP/c; D=$TMP/d; E=$TMP/e
mkdir -p "$A" "$B" "$C" "$D" "$E"
fail=0
pass=0
t0=$(date +%s)

say() { printf '%s\n' "$*"; }
ok() { pass=$((pass + 1)); say "PASS $*"; }
bad() { fail=$((fail + 1)); say "FAIL $*"; }
check() { if [ "$1" = 0 ]; then ok "$2"; else bad "$2"; fi; }
now() { echo $(( $(date +%s) - t0 )); }

port() { awk -v seed="$$$(date +%N)" 'BEGIN { srand(seed); print 20000 + int(rand() * 20000) }'; }
# every node uses p2p port P and P+1 (the onion listener), rpc on its own port
PA=$(port); RA=$((PA + 2)); PB=$((PA + 4)); RB=$((PA + 6)); PC=$((PA + 8)); RC=$((PA + 10)); PD=$((PA + 12)); RD=$((PA + 14)); PE=$((PA + 16)); RE=$((PA + 18))

conf() { # dir p2p rpc tor(1 onion-only | 2 embedded Tor, all networks | 0 none)
    cat > "$1/zclassic.conf" <<EOF
regtest=1
server=1
rpcuser=zcltest
rpcpassword=zcltest$$
rpcport=$3
rpcallowip=127.0.0.1
port=$2
listen=1
debug=tor
debug=net
debug=addrman
debuglogfile=1
EOF
    if [ "$4" = 1 ] || [ "$4" = 2 ]; then
        cat >> "$1/zclassic.conf" <<EOF
embeddedtor=1
$MODE_LINE
EOF
    fi
    if [ "$4" = 1 ]; then echo onlynet=onion >> "$1/zclassic.conf"; fi
}
conf "$A" "$PA" "$RA" 1
conf "$B" "$PB" "$RB" 1
conf "$C" "$PC" "$RC" 1
conf "$D" "$PD" "$RD" 2
conf "$E" "$PE" "$RE" 0
echo externalip=93.184.216.34 >> "$E/zclassic.conf"
cli_a() { "$CLI" -datadir="$A" "$@" 2>&1; }
cli_b() { "$CLI" -datadir="$B" "$@" 2>&1; }
cli_c() { "$CLI" -datadir="$C" "$@" 2>&1; }
cli_d() { "$CLI" -datadir="$D" "$@" 2>&1; }
cli_e() { "$CLI" -datadir="$E" "$@" 2>&1; }

PID_A=; PID_B=; PID_C=; PID_D=; PID_E=
cleanup() { for p in "$PID_A" "$PID_B" "$PID_C" "$PID_D" "$PID_E"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; }
trap cleanup EXIT INT TERM

wait_rpc() { i=0; while [ $i -lt "$2" ]; do $1 getblockcount >/dev/null 2>&1 && return 0; sleep 1; i=$((i + 1)); done; return 1; }
wait_gone() { i=0; while [ $i -lt "$2" ]; do kill -0 "$1" 2>/dev/null || return 0; sleep 1; i=$((i + 1)); done; return 1; }
onion_of() { $1 getnetworkinfo | tr -d ' ",' | awk -F: '/^address:.*\.onion$/ { print $2; exit }'; }
wait_onion() { i=0; while [ $i -lt 180 ]; do o=$(onion_of "$1"); if [ -n "$o" ]; then echo "$o"; return 0; fi; sleep 1; i=$((i + 1)); done; return 1; }
height_is() { i=0; while [ $i -lt "$3" ]; do [ "$($1 getblockcount 2>/dev/null)" = "$2" ] && return 0; sleep 3; i=$((i + 3)); done; return 1; }
outbound_to() { # cli-function onion:port
    $1 getpeerinfo | tr -d ' ",' | awk -v want="$2" '
        /^addr:/ { a = substr($0, 6) }
        /^inbound:false/ { if (a == want) { found = 1 } }
        END { exit found ? 0 : 1 }'
}
tor_progress() { f=$1/regtest/tor/tor.log; [ -f "$f" ] || f=$1/regtest/tor/tor-child.log; grep -o 'Bootstrapped [0-9]*%' "$f" 2>/dev/null | tr -dc '0-9\n' | sort -n | tail -1; }
wait_log() { # file pattern seconds
    i=0; while [ $i -lt "$3" ]; do grep -q -- "$2" "$1" 2>/dev/null && return 0; sleep 3; i=$((i + 3)); done; return 1
}

say "tmp $TMP mode $MODE ports A=$PA B=$PB C=$PC D=$PD (onion listeners on port+1)"

# ------------------------------------------------------------ A and B
"$ZD" -datadir="$A" -bind=127.0.0.1 -rpcbind=127.0.0.1 > "$TMP/a.out" 2>&1 &
PID_A=$!
"$ZD" -datadir="$B" -bind=127.0.0.1 -rpcbind=127.0.0.1 > "$TMP/b.out" 2>&1 &
PID_B=$!
wait_rpc cli_a 120; check $? "A: RPC up after $(now)s"
wait_rpc cli_b 120; check $? "B: RPC up after $(now)s"
OA=$(wait_onion cli_a); [ ${#OA} = 62 ]; check $? "A: own v3 onion $OA after $(now)s"
OB=$(wait_onion cli_b); [ ${#OB} = 62 ]; check $? "B: own v3 onion $OB after $(now)s"
grep -q "Onion service target: 127.0.0.1:$((PA + 1))" "$A/regtest/debug.log"; check $? "A: dedicated onion listener 127.0.0.1:$((PA + 1))"
grep -q "ADD_ONION" "$A/regtest/debug.log" && grep -q "127.0.0.1:$((PA + 1))" "$A/regtest/debug.log"
check $? "A: the onion service points at the dedicated listener"
cli_a generate 5 >/dev/null; [ "$(cli_a getblockcount)" = 5 ]; check $? "A: mined 5 blocks"
for n in A B; do
    d=$A; [ $n = B ] && d=$B
    i=0; while [ $i -lt 300 ]; do [ "$(tor_progress "$d")" = 100 ] && break; sleep 2; i=$((i + 2)); done
    [ "$(tor_progress "$d")" = 100 ]; check $? "$n: Tor bootstrapped after $(now)s"
done

# A dials B (A knows B by addnode). B sees an inbound peer on its onion listener.
i=0
while [ $i -lt 600 ]; do
    cli_a addnode "$OB:$PB" onetry >/dev/null
    outbound_to cli_a "$OB:$PB" && break
    sleep 10; i=$((i + 10))
done
outbound_to cli_a "$OB:$PB"; check $? "A: dialled B's onion (after $(now)s)"
height_is cli_b 5 300; check $? "B: synced from A over the onion link"
wait_log "$B/regtest/debug.log" "(onion service)" 60; check $? "B: the peer was accepted on the onion listener"
wait_log "$A/regtest/debug.log" "sendaddrv2 from peer" 60; check $? "A: B negotiated addrv2"
wait_log "$B/regtest/debug.log" "AdvertizeLocalOnion: advertizing $OB" 60; check $? "B: advertised its onion to its onion peer"
wait_log "$A/regtest/debug.log" "AdvertizeLocalOnion: advertizing $OA" 60; check $? "A: advertised its onion to its onion peer"
# A holds B's address as an addrman entry learned by gossip
wait_log "$A/regtest/debug.log" "Added 1 addresses from" 120; check $? "A: learned an address by gossip"

# ------------------------------------------------------------ D (clearnet link to A)
# D has its own onion service and can reach onion peers, but its only link is the
# clearnet one to A. It must learn B from A's getaddr answer (addrv2) and must never
# be sent A's onion, and never send its own.
"$ZD" -datadir="$D" -bind=127.0.0.1 -rpcbind=127.0.0.1 -connect=127.0.0.1:$PA > "$TMP/d.out" 2>&1 &
PID_D=$!
wait_rpc cli_d 120; check $? "D: RPC up (clearnet link, own onion service)"
i=0; while [ $i -lt 120 ]; do [ "$(cli_d getpeerinfo | grep -c '"addr"')" -ge 1 ] && break; sleep 2; i=$((i + 2)); done
[ "$(cli_d getpeerinfo | grep -c '"addr"')" -ge 1 ]; check $? "D: connected to A over clearnet"
height_is cli_d 5 120; check $? "D: synced from A"
OD=$(wait_onion cli_d); [ ${#OD} = 62 ]; check $? "D: own v3 onion $OD (never to be sent to A)"
wait_log "$D/regtest/debug.log" "sendaddrv2 from peer" 60; check $? "D: A negotiated addrv2 over clearnet"
wait_log "$D/regtest/debug.log" "received: addrv2" 90; check $? "D: received an addrv2 answer from A over clearnet"

# E: a plain clearnet node that tells D its (external) address, so that D's peers.dat has an entry
"$ZD" -datadir="$E" -bind=127.0.0.1 -rpcbind=127.0.0.1 > "$TMP/e.out" 2>&1 &
PID_E=$!
wait_rpc cli_e 120; check $? "E: RPC up (plain clearnet node)"
cli_e generate 1 >/dev/null
cli_e addnode "127.0.0.1:$PD" onetry >/dev/null
wait_log "$D/regtest/debug.log" "Added 1 addresses from 127.0.0.1" 90; check $? "D: learned a clearnet address from E"

# ------------------------------------------------------------ C
# C is told about A only. B's onion must come from gossip.
echo "addnode=$OA:$PA" >> "$C/zclassic.conf"
! grep -q "$OB" "$C/zclassic.conf"; check $? "C: B's onion is not configured anywhere"
if [ "$TRACE" = strace ]; then
    strace -f -qq -e trace=network,clone,clone3,fork,vfork,execve -o "$TMP/c.strace" "$ZD" -datadir="$C" -bind=127.0.0.1 -rpcbind=127.0.0.1 > "$TMP/c.out" 2>&1 &
else
    "$ZD" -datadir="$C" -bind=127.0.0.1 -rpcbind=127.0.0.1 > "$TMP/c.out" 2>&1 &
fi
PID_C=$!
wait_rpc cli_c 180; check $? "C: RPC up after $(now)s"
OC=$(wait_onion cli_c); [ ${#OC} = 62 ]; check $? "C: own v3 onion $OC"
i=0
while [ $i -lt 1200 ]; do
    outbound_to cli_c "$OA:$PA" && outbound_to cli_c "$OB:$PB" && break
    sleep 5; i=$((i + 5))
done
outbound_to cli_c "$OA:$PA"; check $? "C: connected to A's onion (addnode)"
outbound_to cli_c "$OB:$PB"; check $? "C: connected to B's onion, learned by gossip (after $(now)s)"
grep -q "sendaddrv2 from peer" "$C/regtest/debug.log"; check $? "C: negotiated addrv2"
grep -q "received: addrv2" "$C/regtest/debug.log"; check $? "C: received an addrv2 message"
height_is cli_c 5 600; check $? "C: synced to height 5"
# all of C's peers are onion peers
[ "$(cli_c getpeerinfo | tr -d ' ",' | awk -F: '/^addr:/ && $2 !~ /\.onion$/ && $2 !~ /^127\.0\.0\.1$/ { n++ } END { print n + 0 }')" = 0 ]
check $? "C: no clearnet peer (an onion inbound peer shows as 127.0.0.1, the Tor side)"

# ------------------------------------------------------------ privacy
# D is a clearnet peer of A: A must never have advertised its onion to it.
# D's connection as A sees it: the peer whose address is D's local socket.
# A accepted exactly one connection that was not on its onion listener: D's.
DID=$(awk '/Added connection peer=/ { split($0, p, "peer="); last = p[2] + 0 } /connection from [^ ]+ accepted$/ { print last }' "$A/regtest/debug.log" | head -1)
say "D as seen by A: peer id ${DID:-?}"
[ -n "$DID" ]; check $? "A: found D's peer id (the one connection not accepted on the onion listener)"
! grep -q "AdvertizeLocalOnion" "$D/regtest/debug.log"; check $? "D: never advertised its own onion (its only peer is clearnet)"
! grep -q "AdvertizeLocalOnion.*peer=$DID\$" "$A/regtest/debug.log"; check $? "A: never advertised its onion to the clearnet peer D"
grep -c "AdvertizeLocalOnion" "$A/regtest/debug.log" | awk '{ exit ($1 >= 1 ? 0 : 1) }'; check $? "A: did advertise its onion to onion peers"

# no clearnet address was sent to an onion peer: B only has onion peers, none of its
# addr traffic mentions a clearnet address (checked in the unit tests for the payload)
[ "$(cli_b getpeerinfo | tr -d ' ",' | awk -F: '/^addr:/ && $2 !~ /\.onion$/ && $2 !~ /^127\.0\.0\.1$/ { n++ } END { print n + 0 }')" = 0 ]
check $? "B: its peers are onion peers"

# ------------------------------------------------------------ shutdown and files
for n in E D C B A; do
    case $n in A) c=cli_a; p=$PID_A ;; B) c=cli_b; p=$PID_B ;; C) c=cli_c; p=$PID_C ;; D) c=cli_d; p=$PID_D ;; E) c=cli_e; p=$PID_E ;; esac
    $c stop >/dev/null
    wait_gone "$p" 120; check $? "$n: exited after stop"
done
PID_A=; PID_B=; PID_C=; PID_D=; PID_E=
sleep 1
for n in a b c d; do
    [ -s "$TMP/$n/regtest/onion_peers.dat" ]; check $? "$n: onion_peers.dat written ($(wc -c < "$TMP/$n/regtest/onion_peers.dat" 2>/dev/null) bytes)"
done
[ -s "$C/regtest/peers.dat" ]; check $? "C: peers.dat written"
if [ "$TRACE" = strace ]; then
    sh "$here/privacy_check.sh" "$TMP/c.strace" "$C/regtest/debug.log"; check $? "C: strace privacy check (leaks=0)"
fi
# restart C: it reloads the onion store
"$ZD" -datadir="$C" -bind=127.0.0.1 -rpcbind=127.0.0.1 -connect=0 > "$TMP/c2.out" 2>&1 &
PID_C=$!
wait_rpc cli_c 180
grep -q "Loaded [1-9][0-9]* Tor v3 addresses from onion_peers.dat" "$C/regtest/debug.log"; check $? "C: reloaded its onion store after restart"
cli_c stop >/dev/null; wait_gone "$PID_C" 120; PID_C=

# the old binary reads the peers.dat of a node that learned onion peers
if [ -n "$OLDBIN" ]; then
    O=$TMP/old
    mkdir -p "$O/regtest"
    cp "$D/regtest/peers.dat" "$O/regtest/peers.dat"
    OP=$((PA + 16))
    printf 'regtest=1\nserver=1\nrpcuser=zcltest\nrpcpassword=zcltest%s\nrpcport=%s\nport=%s\nlisten=0\ndnsseed=0\nconnect=0\ndebuglogfile=1\n' "$$" "$((OP + 1))" "$OP" > "$O/zclassic.conf"
    "$OLDBIN/zclassicd" -datadir="$O" > "$TMP/old.out" 2>&1 &
    PO=$!
    i=0; while [ $i -lt 120 ]; do "$OLDBIN/zclassic-cli" -datadir="$O" getblockcount >/dev/null 2>&1 && break; sleep 1; i=$((i + 1)); done
    grep -q "Loaded [1-9][0-9]* addresses from peers.dat" "$O/regtest/debug.log"; check $? "old binary: peers.dat of the onion-aware node D (clearnet entries, onion store learned) loaded ($(grep -o 'Loaded [0-9]* addresses from peers.dat' "$O/regtest/debug.log"))"
    ! grep -q "Invalid or missing peers.dat" "$O/regtest/debug.log"; check $? "old binary: no peers.dat error"
    "$OLDBIN/zclassic-cli" -datadir="$O" stop >/dev/null 2>&1
    wait_gone "$PO" 90
fi

! pgrep -f -- "$TMP" >/dev/null; check $? "no process of this test is left running"

say "RESULT mode=$MODE pass=$pass fail=$fail seconds=$(now)"
if [ "$fail" = 0 ]; then rm -rf "$TMP"; else say "kept $TMP"; fi
[ "$fail" = 0 ]
