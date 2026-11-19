#!/bin/sh
# invalidateblock on a PRUNED node, then reconsiderblock after the invalid fork's block files are gone.
#
# The operator asked for the block to be invalid, so its failure mark persists (also across a
# restart) even after pruning deletes the file that held the block. The question this answers is
# whether reconsiderblock still fully works once the block data is pruned: it must clear the marks,
# leave the node consistent (no assertion, verifychain passes, a restart is clean) and keep following its chain.
#
# Scenario (regtest, tiny block files and a tiny prune target through the regtest-only options
# -testmaxblockfilesize and -testprunetarget):
#   W (wallet node, full history) mines 1100 blocks (chain A), P (-prune) follows it.
#   P, disconnected from W, invalidates block 1090 (tip 1089) and mines 400 blocks of its own: chain B, 1489.
#   The files that held A's blocks 1090..1100 are now more than 288 blocks behind P's tip and are pruned.
#   P is restarted (the failure mark must survive), then connected to W (which still has A, lighter than B).
#   reconsiderblock 1090: it succeeds, chain A becomes a valid fork again, P stays on B, a restart is clean.
#
# Not covered (a pruned node cannot do it, with or without invalidateblock): a reorganisation deeper than the 288 blocks it
# keeps, e.g. reconsidering block 1090 when chain A were HEAVIER than B by hundreds of blocks. The undo data of B1090..B1201 is
# gone, so the switch cannot be made; see the commit message.
#
# usage: prune_invalidate_reconsider.sh --bin <dir> --work <dir> [--base port]
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
rm -rf "$W"; mkdir -p "$W/w" "$W/p"; W=$(cd "$W" && pwd)
trap 'for d in w p; do [ -f "$W/$d/pid" ] && kill -9 "$(cat "$W/$d/pid")" 2>/dev/null; done' EXIT
for d in w p; do printf "rpcuser=u\nrpcpassword=p\n" > "$W/$d/zclassic.conf"; done
A0="-regtest -server=1 -showmetrics=0 -debuglogfile=1 -keypool=5 -nuparams=5ba81b19:1 -nuparams=76b809bb:1 -experimentalfeatures -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -dnsseed=0 -discover=0 -listenonion=0 -bootstrap=0"
port() { case $1 in w) echo $P ;; p) echo $((P + 1)) ;; esac; }
cli() { n=$1; shift; "$B/zclassic-cli" -regtest -datadir="$W/$n" -rpcport=$(port $n) -rpcuser=u -rpcpassword=p "$@"; }
st() { n=$1; shift; rm -f "$W/$n/regtest/.lock"; "$B/zclassicd" $A0 -datadir="$W/$n" -rpcport=$(port $n) "$@" >> "$W/$n/out.log" 2>&1 & echo $! > "$W/$n/pid"
    for k in $(seq 900); do cli $n getblockcount >/dev/null 2>&1 && return 0; kill -0 "$(cat "$W/$n/pid")" 2>/dev/null || return 1; sleep 0.1; done; return 1; }
sp() { cli $1 stop >/dev/null 2>&1; while kill -0 "$(cat "$W/$1/pid")" 2>/dev/null; do sleep 0.2; done; }
ok() { R=$((R + 1)); echo "ok   $1"; }
bad() { F=$((F + 1)); echo "FAIL $1"; }
# small block files, pruning at a 1 MB target (regtest-only options; -prune itself needs 550 MiB)
PR="$PX -disablewallet -testprunetarget=1000000 -testmaxblockfilesize=12000"
waitheight() { for k in $(seq ${3:-600}); do [ "$(cli $1 getblockcount 2>/dev/null)" = "$2" ] && return 0; sleep 0.2; done; return 1; }
status() { cli p getchaintips | jq -r --arg h "$1" '[.[] | select(.hash == $h)][0].status // "absent"'; }

# --- chain A on W, P follows to 1100
st w -listen=1 -port=$((P + 10)) || { echo "W start failed"; exit 1; }
ADDR=$(cli w getnewaddress)
for i in 1 2 3 4 5 6 7 8 9 10 11; do cli w generate 100 >/dev/null; done
[ "$(cli w getblockcount)" = 1100 ] || { echo "W height $(cli w getblockcount)"; exit 1; }
st p -listen=0 $PR -mineraddress=$ADDR -minetolocalwallet=0 -connect=127.0.0.1:$((P + 10)) || { echo "P start failed: $(tail -3 "$W/p/out.log")"; exit 1; }
waitheight p 1100 || { echo "P stuck at $(cli p getblockcount)"; exit 1; }
sp p

# --- P alone: invalidate 1090, mine chain B
st p -listen=0 $PR -mineraddress=$ADDR -minetolocalwallet=0 -connect=0 || { echo "P restart failed: $(tail -3 "$W/p/out.log")"; exit 1; }
H1=$(cli p getblockhash 1090); A1=$(cli p getblockhash 1100); cli p invalidateblock "$H1" >/dev/null
[ "$(cli p getblockcount)" = 1089 ] && ok "P invalidated block 1090: tip 1089" || bad "P tip after invalidateblock: $(cli p getblockcount)"
cnt=0; while [ $cnt -lt 4 ]; do cli p generate 100 >/dev/null || break; cnt=$((cnt + 1)); done
[ "$(cli p getblockcount)" = 1489 ] && ok "P mined chain B to 1489" || bad "P height $(cli p getblockcount) after mining B"
PRUNED=$(cli p getblockchaininfo | jq -r .pruned)
out=$(cli p getblock "$H1" 2>&1); case $out in *pruned*) ok "block 1090 of chain A is pruned on P (pruned=$PRUNED)" ;; *) bad "block 1090 still has data on P (pruned=$PRUNED): $(printf '%s' "$out" | head -c 100)" ;; esac
[ "$(status "$A1")" = invalid ] && ok "the tip of chain A (1100, a descendant of block 1090) is reported invalid after its data was pruned" || bad "block 1090 status: $(status "$A1")"
BTIP=$(cli p getbestblockhash)
sp p

# --- restart: the failure mark persists
st p -listen=0 $PR -mineraddress=$ADDR -minetolocalwallet=0 -connect=0 || { echo "P restart 2 failed: $(tail -3 "$W/p/out.log")"; exit 1; }
if [ "$(status "$A1")" = invalid ] && [ "$(cli p getbestblockhash)" = "$BTIP" ]; then ok "after a restart block 1090 is still invalid and P is still on chain B"; else bad "restart: status $(status "$A1"), tip $(cli p getbestblockhash)"; fi
sp p

# --- connected to W, which has A (1100, lighter than B): P stays on B and A stays invalid
st p -listen=0 $PR -mineraddress=$ADDR -minetolocalwallet=0 -connect=127.0.0.1:$((P + 10)) || { echo "P restart 3 failed"; exit 1; }
sleep 8
if [ "$(cli p getbestblockhash)" = "$BTIP" ] && [ "$(status "$A1")" = invalid ]; then ok "connected to W (chain A, lighter), P stays on B and chain A stays invalid"; else bad "P left chain B or lost the mark: tip height $(cli p getblockcount), 1090 is $(status "$A1")"; fi

# --- reconsiderblock after the pruning
cli p reconsiderblock "$H1" >/dev/null 2>&1; rc=$?
[ $rc = 0 ] && ok "reconsiderblock on the pruned block returned success" || bad "reconsiderblock rc=$rc"
sleep 3
[ "$(status "$A1")" = valid-fork ] && ok "the marks are cleared: chain A is a valid fork again, although its block files are gone" || bad "chain A tip status after reconsiderblock: $(status "$A1")"
[ "$(cli p getbestblockhash)" = "$BTIP" ] && ok "P stays on chain B (more work), no reorganisation attempted" || bad "P tip after reconsiderblock: $(cli p getblockcount)"
v=$(cli p verifychain 3 20 2>&1); [ "$v" = true ] && ok "verifychain passes on P" || bad "verifychain on P: $v"
sp p
st p -listen=0 $PR -mineraddress=$ADDR -minetolocalwallet=0 -connect=0 || { bad "P does not restart after reconsiderblock: $(tail -3 "$W/p/out.log")"; }
[ "$(cli p getbestblockhash)" = "$BTIP" ] && [ "$(status "$A1")" = valid-fork ] && ok "P restarted cleanly on chain B with the marks still cleared" || bad "restart after reconsiderblock: height $(cli p getblockcount), chain A tip $(status "$A1")"
# a new block on top still works
cli p generate 1 >/dev/null 2>&1; [ "$(cli p getblockcount)" = 1490 ] && ok "P mines and accepts a new block (1490)" || bad "P cannot mine after reconsiderblock: $(cli p getblockcount)"
sp p; sp w
if grep -qi "assertion\|AbortNode" "$W/p/out.log" "$W/p/regtest/debug.log" "$W/w/out.log" 2>/dev/null; then bad "a node logged an assertion or abort: $(grep -hi 'assertion\|AbortNode' "$W/p/out.log" "$W/p/regtest/debug.log" "$W/w/out.log" | head -2 | cut -c1-150)"; else ok "no assertion or abort in either node's log"; fi
echo "prune-invalidate-reconsider: $R ok, $F fail"
[ "$F" = 0 ] && [ "$R" -gt 0 ]
