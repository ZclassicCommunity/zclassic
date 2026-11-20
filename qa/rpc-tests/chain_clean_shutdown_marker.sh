#!/bin/sh
# The clean-shutdown marker shortens the startup VerifyDB only after a verified clean stop.
#
# A clean stop writes <datadir>/shutdown.clean last, bound to the tip, the coins best block and a
# digest of the block and database file names, sizes and mtimes. The next start removes it before
# opening any database and checks only the last 6 blocks (level 3) when everything still matches.
# After kill -9 (no marker), a touched chainstate/CURRENT or a changed blk00000.dat the full
# default check must run, and the marker must always be gone once the node is up.
#
# usage: chain_clean_shutdown_marker.sh --bin <dir> --work <dir> [--base port]
# Needs the Zcash parameters in ~/.zcash-params. Shell only, no Python.
B=""; W=""; P=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) B=$2; shift 2 ;; --work) W=$2; shift 2 ;; --base) P=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$B/zclassicd" ] && [ -n "$W" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
P=${P:-$((20000 + ($$ % 20000)))}; R=0; F=0
rm -rf "$W"; mkdir -p "$W/d"; W=$(cd "$W" && pwd); D=$W/d; N=$D/regtest
trap '[ -f "$W/pid" ] && kill -9 "$(cat "$W/pid")" 2>/dev/null' EXIT
printf "rpcuser=u\nrpcpassword=p\n" > "$D/zclassic.conf"
A0="-regtest -server=1 -listen=0 -showmetrics=0 -debuglogfile=1 -keypool=5 -nuparams=5ba81b19:1 -nuparams=76b809bb:1 -experimentalfeatures -rpcport=$P -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -dnsseed=0 -discover=0 -listenonion=0"
cli() { "$B/zclassic-cli" -regtest -datadir="$D" -rpcport=$P -rpcuser=u -rpcpassword=p "$@"; }
st() { [ -d "$N" ] && : > "$N/debug.log";"$B/zclassicd" $A0 -datadir="$D" "$@" >> "$W/out.log" 2>&1 & echo $! > "$W/pid"
    for k in $(seq 600); do cli getblockcount >/dev/null 2>&1 && return 0; kill -0 "$(cat "$W/pid")" 2>/dev/null || return 1; sleep 0.1; done; return 1; }
sp() { cli stop >/dev/null 2>&1; while kill -0 "$(cat "$W/pid")" 2>/dev/null; do sleep 0.2; done; }
ok() { echo "ok   $1"; R=$((R + 1)); }
no() { echo "FAIL $1"; F=$((F + 1)); }

st || { echo "first start failed: $(tail -3 "$W/out.log")"; exit 1; }
cli generate 20 >/dev/null
H=$(cli getblockcount)
sp
[ -f "$N/shutdown.clean" ] && grep -q "^magic=ZCLSHUT$" "$N/shutdown.clean" && grep -q "^height=$H$" "$N/shutdown.clean" \
    && ok "clean stop wrote shutdown.clean at height $H" || no "no shutdown.clean after a clean stop"

# check <label> <short|full> [reason]: start, expect the VerifyDB path, the marker gone, the height kept
check() {
    lbl=$1; mode=$2; why=${3:-}; shift; shift; [ $# -gt 0 ] && shift
    if ! st "$@"; then no "$lbl: restart failed: $(tail -2 "$W/out.log")"; return; fi
    h=$(cli getblockcount)
    if [ "$mode" = short ]; then
        grep -q "VerifyDB: clean shutdown marker matched; checking last 6 blocks" "$N/debug.log"; r=$?
    else
        grep -q "VerifyDB: full startup check ($why)" "$N/debug.log" && ! grep -q "clean shutdown marker matched" "$N/debug.log"; r=$?
    fi
    if [ $r = 0 ] && [ ! -e "$N/shutdown.clean" ] && [ "$h" = "$H" ]; then ok "$lbl: $mode VerifyDB, marker consumed, height $h"
    else no "$lbl: wanted $mode VerifyDB ($(grep -m1 'VerifyDB:' "$N/debug.log")), marker present=$([ -e "$N/shutdown.clean" ] && echo yes || echo no), height $h of $H"; fi
}

check "restart after clean stop" short
# kill -9: no marker is written, and the one read at the last start is gone
kill -9 "$(cat "$W/pid")"; while kill -0 "$(cat "$W/pid")" 2>/dev/null; do sleep 0.1; done
[ ! -e "$N/shutdown.clean" ] && ok "no marker after kill -9" || no "marker present after kill -9"
check "restart after kill -9" full "no marker"
sp

# A clean stop followed by an mtime change of chainstate/CURRENT
touch "$N/chainstate/CURRENT"
check "restart after touching chainstate/CURRENT" full "files changed"
sp

# A clean stop followed by one byte appended to blk00000.dat: the full path, or the corruption error
printf 'x' >> "$N/blocks/blk00000.dat"
if st; then
    h=$(cli getblockcount)
    if grep -q "VerifyDB: full startup check (files changed)" "$N/debug.log" && [ ! -e "$N/shutdown.clean" ] && [ "$h" = "$H" ]; then
        ok "restart after appending to blk00000.dat: full VerifyDB, height $h"
    else no "restart after appending to blk00000.dat: $(grep -m1 'VerifyDB:' "$N/debug.log"), height $h"; fi
    sp
else
    grep -qi "corrupt" "$W/out.log" && ok "restart after appending to blk00000.dat: corruption reported" \
        || no "restart after appending to blk00000.dat failed without a corruption error"
fi

# -cleanshutdownmarker=0 and an explicit -checkblocks both keep the full check
check "restart with -cleanshutdownmarker=0" full "disabled" -cleanshutdownmarker=0
sp
check "restart with -checkblocks=10" full "explicit check, reindex or bootstrap" -checkblocks=10
sp
check "restart after clean stop, again" short
sp

echo "clean-shutdown-marker: $R ok, $F fail"
[ "$F" = 0 ] && [ "$R" -gt 0 ]
