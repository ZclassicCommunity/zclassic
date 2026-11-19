#!/bin/sh
# A node killed during -reindex must finish the reindex by itself when it is started again
# WITHOUT -reindex.
#
# The reindex wipes the block index, then the chainstate, and only then wrote its "reindexing"
# flag. A node that died between the wipe and the flag started with an empty block index next to
# full block files (height 0, genesis written over the first block file), and one that died later
# resumed on a half-built chainstate. The flag is now written first, and a start that finds it
# runs the reindex again from the start with a wiped chainstate. The flag is cleared only after the
# block index and the chainstate are flushed (a kill just after the last block left both empty).
#
# Cases: the node leaves at the crash point after the wipe (-testcrashpoint=reindex-after-wipe),
# kill -9 at several delays after the start of -reindex, and an empty block index without the flag
# (plain start and -reindex-chainstate). Each is restarted without -reindex
# and must reach the full height with a chain that verifies and accept a new block.
#
# usage: chain_reindex_resume.sh --bin <dir> --work <dir> [--base port]
# Needs jq and the Zcash parameters in ~/.zcash-params. Shell only, no Python.
B=""; W=""; P=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) B=$2; shift 2 ;; --work) W=$2; shift 2 ;; --base) P=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$B/zclassicd" ] && [ -n "$W" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
P=${P:-$((20000 + ($$ % 20000)))}; R=0; F=0
rm -rf "$W"; mkdir -p "$W/tpl"; W=$(cd "$W" && pwd)
trap '[ -f "$D/pid" ] && kill -9 "$(cat "$D/pid")" 2>/dev/null' EXIT
printf "rpcuser=u\nrpcpassword=p\n" > "$W/tpl/zclassic.conf"
A0="-regtest -server=1 -listen=0 -showmetrics=0 -debuglogfile=1 -keypool=5 -nuparams=5ba81b19:1 -nuparams=76b809bb:1 -experimentalfeatures -rpcport=$P -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -dnsseed=0 -discover=0 -listenonion=0"
cli() { "$B/zclassic-cli" -regtest -datadir="$D" -rpcport=$P -rpcuser=u -rpcpassword=p "$@"; }
st() { rm -f "$D/regtest/.lock"; "$B/zclassicd" $A0 -datadir="$D" "$@" >> "$D/out.log" 2>&1 & echo $! > "$D/pid"
    for k in $(seq 600); do cli getblockcount >/dev/null 2>&1 && return 0; kill -0 "$(cat "$D/pid")" 2>/dev/null || return 1; sleep 0.1; done; return 1; }
sp() { cli stop >/dev/null 2>&1; while kill -0 "$(cat "$D/pid")" 2>/dev/null; do sleep 0.2; done; }
D=$W/tpl; st || { echo "template start failed"; exit 1; }
cli generate 120 >/dev/null
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do cli sendtoaddress "$(cli getnewaddress)" 1 >/dev/null; cli generate 20 >/dev/null; done
H=$(cli getblockcount); sp

# check <label>: restart without -reindex, wait for the full height, verify, mine
#
# The reindex starts by itself here, so the operator must be told (debug.log is off by default):
# EXPECT_MSG=1 requires the "Reindexing the block database: <why>" warning on stderr (out.log) and,
# once the RPC server answers, getblockchaininfo carrying "reindexing" (boolean) and "reindexreason"
# (non-empty while it is true); after the reindex it must report false and an empty reason.
EXPECT_MSG=0; MIDRUN=0
check() {
    : > "$D/out.log"
    rm -f "$D/regtest/.lock"; "$B/zclassicd" $A0 -datadir="$D" $2 >> "$D/out.log" 2>&1 & echo $! > "$D/pid"
    first=""
    for k in $(seq 600); do first=$(cli getblockchaininfo 2>/dev/null) && [ -n "$first" ] && break; first=""
        kill -0 "$(cat "$D/pid")" 2>/dev/null || break; sleep 0.05; done
    if [ -z "$first" ]; then echo "FAIL $1: restart without -reindex failed: $(grep -m1 -i 'assert\|error' "$D/out.log" | cut -c1-150)"; F=$((F + 1)); return; fi
    msgok=1
    if [ "$EXPECT_MSG" = 1 ]; then
        grep -q "Reindexing the block database: .*safe to stop and restart" "$D/out.log" || msgok=0
        [ "$msgok" = 1 ] || echo "FAIL $1: no 'Reindexing the block database' message on stderr"
    fi
    r0=$(printf '%s' "$first" | jq -r '.reindexing | type'); why0=$(printf '%s' "$first" | jq -r '.reindexreason | type')
    if [ "$r0" != boolean ] || [ "$why0" != string ]; then msgok=0; echo "FAIL $1: getblockchaininfo lacks reindexing/reindexreason ($r0/$why0)"; fi
    if [ "$(printf '%s' "$first" | jq -r .reindexing)" = true ]; then
        MIDRUN=$((MIDRUN + 1))
        [ -n "$(printf '%s' "$first" | jq -r .reindexreason)" ] || { msgok=0; echo "FAIL $1: reindexing true with no reason"; }
    fi
    for k in $(seq 300); do [ "$(cli getblockcount 2>/dev/null)" = "$H" ] && break; sleep 0.2; done
    for k in $(seq 300); do [ "$(cli getblockchaininfo 2>/dev/null | jq -r .reindexing)" = false ] && break; sleep 0.2; done
    last=$(cli getblockchaininfo | jq -r '[.reindexing, (.reindexreason|length)] | @csv')
    [ "$last" = "false,0" ] || { msgok=0; echo "FAIL $1: after the reindex getblockchaininfo says reindexing,reasonlength = $last"; }
    hh=$(cli getblockcount); v=$(cli verifychain 4 0)
    for k in $(seq 100); do cli generate 1 >/dev/null 2>&1 && break; sleep 0.2; done; h2=$(cli getblockcount)
    if [ "$hh" = "$H" ] && [ "$v" = true ] && [ "$h2" = $((H + 1)) ] && [ "$msgok" = 1 ]; then echo "ok   $1: reindex finished, height $hh, chain verifies, new block accepted"; R=$((R + 1))
    else echo "FAIL $1: height $hh of $H, verifychain $v, after mining $h2, announcement ok=$msgok"; F=$((F + 1)); fi
    sp
}
i=0
i=$((i + 1)); D=$W/it$i; rm -rf "$D"; cp -a "$W/tpl" "$D"; : > "$D/out.log"
st -reindex -testcrashpoint=reindex-after-wipe >/dev/null 2>&1
while kill -0 "$(cat "$D/pid")" 2>/dev/null; do sleep 0.1; done
EXPECT_MSG=1 check "crash point after the wipe"
for d in 0.3 0.6 0.9 1.2 1.5 1.8; do
    i=$((i + 1)); D=$W/it$i; rm -rf "$D"; cp -a "$W/tpl" "$D"; : > "$D/out.log"
    "$B/zclassicd" $A0 -datadir="$D" -reindex >> "$D/out.log" 2>&1 & echo $! > "$D/pid"
    sleep $d; kill -9 "$(cat "$D/pid")" 2>/dev/null; while kill -0 "$(cat "$D/pid")" 2>/dev/null; do sleep 0.1; done
    check "kill -9 $d s into -reindex"
done
# The flag can only be written once the wiped block index is open again, and a new LevelDB syncs
# its files on open: a kill in that window (seen under load) leaves an empty index with no flag
# next to full block files and the old chainstate. A start must reindex, also with
# -reindex-chainstate, which wipes the chainstate (it used to start from genesis and write over
# blk00000.dat).
for x in "" -reindex-chainstate; do
    i=$((i + 1)); D=$W/it$i; rm -rf "$D"; cp -a "$W/tpl" "$D"; : > "$D/out.log"; rm -rf "$D/regtest/blocks/index"
    EXPECT_MSG=1 check "empty block index without the flag, restart ${x:-plain}" $x
done
echo "reindex-resume: $R ok, $F fail (getblockchaininfo answered mid-reindex in $MIDRUN restarts)"
[ "$F" = 0 ] && [ "$R" -gt 0 ]
