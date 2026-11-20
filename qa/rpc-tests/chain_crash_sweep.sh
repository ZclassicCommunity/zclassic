#!/bin/sh
# Chain crash-point sweep: kill the node at every chain (and wallet) write hook it reaches while it
# accepts and connects new blocks, and prove it recovers to the same chain and UTXO set as a node
# that never crashed.
#
# Node R (the reference) mines 110 blocks with a few transparent transactions, then 3 more blocks
# (the "next blocks"), each with a transaction. Node V (the victim) gets R's first 110 blocks by
# submitblock and is stopped cleanly; that datadir is the seed. One cycle is: start V on a fresh
# copy of the seed, submitblock the 3 next blocks, stop V. For k = 1, 2, ... the cycle runs with
# -testcrashpoint=any:k, so V _exit(77)s at the k-th hook it reaches (any of them: the block write
# in AcceptBlock, the undo write and the tip update in ConnectBlock, the block index and coins
# writes in FlushStateToDisk, the wallet's chain-tip and checkpoint writes, at start-up, during
# the blocks or at shutdown). Then V restarts normally and must: start; pass verifychain 4 0;
# after R's blocks are submitted again, report R's getbestblockhash and R's gettxoutsetinfo
# hash_serialized. The sweep ends at the first k whose cycle completes without a crash: every hook
# of one cycle has then been swept (K = k - 1). -testblockindexinterval=0 makes every periodic
# flush write the block index, so the hook sequence does not depend on timing.
#
# usage: chain_crash_sweep.sh --bin <dir> --work <empty dir> [--base <port>] [--max K]
#   --max K  sweep at most the first K hooks (default: all hooks of one cycle)
# Exit: 0 every swept k recovered; 1 a k failed (its number and hook are printed); 2 broken
# (usage, setup failure, or no hook fired at all).
# Needs the Zcash parameters in ~/.zcash-params. Shell only, no Python.
B=""; W=""; P=""; MAX=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) B=$2; shift 2 ;; --work) W=$2; shift 2 ;; --base) P=$2; shift 2 ;; --max) MAX=$2; shift 2 ;;
        *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$B/zclassicd" ] && [ -x "$B/zclassic-cli" ] && [ -n "$W" ] || { echo "usage: $0 --bin DIR --work EMPTY_DIR [--base port] [--max K]" >&2; exit 2; }
case $MAX in ""|*[!0-9]*) [ -z "$MAX" ] || { echo "--max takes a number" >&2; exit 2; } ;; esac
mkdir -p "$W" || exit 2
W=$(cd "$W" && pwd)
[ -z "$(ls -A "$W")" ] || { echo "work directory $W is not empty" >&2; exit 2; }
. "$(dirname "$0")/../lib/isolation.sh"
iso_base P "$P" 16
PR=$P; PV=$((P + 2))
A0="-regtest -server=1 -listen=0 -showmetrics=0 -debuglogfile=1 -keypool=5 -nuparams=5ba81b19:1 -nuparams=76b809bb:1 -experimentalfeatures -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -dnsseed=0 -discover=0 -listenonion=0"
AV="-testblockindexinterval=0 -testsetchaininterval=100000"
NSEED=110; NNEXT=3
RD=$W/ref; VPID=""; RPID=""
trap '[ -n "$VPID" ] && kill -9 "$VPID" 2>/dev/null; [ -n "$RPID" ] && kill -9 "$RPID" 2>/dev/null' EXIT

clir() { "$B/zclassic-cli" -regtest -datadir="$RD" -rpcport=$PR -rpcuser=u -rpcpassword=p "$@"; }
cliv() { "$B/zclassic-cli" -regtest -datadir="$D" -rpcport=$PV -rpcuser=u -rpcpassword=p "$@"; }
mkdd() { mkdir -p "$1" && printf "rpcuser=u\nrpcpassword=p\n" > "$1/zclassic.conf"; }
# up <pid> <cli>: wait for RPC; 1 when the process exited first or it never answered
up() { n=0; while [ $n -lt 900 ]; do $2 getblockcount >/dev/null 2>&1 && return 0; kill -0 "$1" 2>/dev/null || return 1; n=$((n + 1)); sleep 0.1; done; return 1; }
# startv [args]: start V on $D in the background (VPID); 0 when RPC answers
startv() { rm -f "$D/regtest/.lock"; $ZCL_RUN "$B/zclassicd" $A0 $AV -rpcport=$PV -datadir="$D" "$@" >> "$D/out.log" 2>&1 & VPID=$!; up "$VPID" cliv; }
# reapv: wait for V to exit; sets VRC to its exit status
reapv() { wait "$VPID"; VRC=$?; VPID=""; }
stopv() { cliv stop >/dev/null 2>&1; reapv; }
field() { sed -n "s/.*\"$1\": *\"\([0-9a-f]*\)\".*/\1/p"; }
# submit <from> <to>: submitblock R's blocks in that height range to V (errors ignored: V may die)
submit() { h=$1; while [ "$h" -le "$2" ]; do cliv submitblock "$(cat "$W/blocks/$h.hex")" >/dev/null 2>&1; h=$((h + 1)); done; }
hookof() { sed -n 's/^testcrashpoint: exiting at \([^ ]*\) (hit.*/\1/p' "$1" | tail -n 1; }

# ---- reference node R: 110 seed blocks and 3 next blocks, with transparent transactions
mkdd "$RD"
$ZCL_RUN "$B/zclassicd" $A0 -rpcport=$PR -datadir="$RD" >> "$RD/out.log" 2>&1 & RPID=$!
up "$RPID" clir || { echo "BROKEN: reference node did not start: $(grep -m1 -i 'error' "$RD/out.log" | cut -c1-150)"; exit 2; }
clir generate 101 >/dev/null || { echo "BROKEN: generate failed on R"; exit 2; }
while [ "$(clir getblockcount)" -lt $NSEED ]; do
    clir sendtoaddress "$(clir getnewaddress)" 1 >/dev/null || { echo "BROKEN: sendtoaddress failed on R"; exit 2; }
    clir generate 1 >/dev/null
done
T=$((NSEED + NNEXT))
while [ "$(clir getblockcount)" -lt $T ]; do
    clir sendtoaddress "$(clir getnewaddress)" 2 >/dev/null || { echo "BROKEN: sendtoaddress failed on R"; exit 2; }
    clir generate 1 >/dev/null
done
mkdir -p "$W/blocks"
h=1; while [ $h -le $T ]; do clir getblock "$(clir getblockhash $h)" 0 > "$W/blocks/$h.hex"; h=$((h + 1)); done
RBEST=$(clir getbestblockhash); RUTXO=$(clir gettxoutsetinfo | field hash_serialized)
NTX=$(h=$((NSEED + 1)); while [ $h -le $T ]; do clir getblock "$(clir getblockhash $h)" | grep -c '^ *"[0-9a-f]\{64\}",\?$'; h=$((h + 1)); done | tr '\n' ' ')
[ -n "$RUTXO" ] && [ -n "$RBEST" ] || { echo "BROKEN: no reference tip or UTXO hash"; exit 2; }
echo "reference: height $T, best $RBEST, utxo $RUTXO, transactions in the next blocks: $NTX"

# ---- the seed: V with R's first 110 blocks, stopped cleanly
D=$W/vseed; mkdd "$D"
startv || { echo "BROKEN: victim seed node did not start"; exit 2; }
submit 1 $NSEED
[ "$(cliv getblockcount)" = $NSEED ] || { echo "BROKEN: seed node is at $(cliv getblockcount), not $NSEED"; exit 2; }
stopv; : > "$D/out.log"

# ---- the sweep
K=0; F=0; k=0
while :; do
    k=$((k + 1))
    if [ -n "$MAX" ] && [ $k -gt "$MAX" ]; then break; fi
    D=$W/v$k; cp -a "$W/vseed" "$D" || { echo "BROKEN: cannot copy the seed"; exit 2; }
    if startv -testcrashpoint=any:$k; then
        submit $((NSEED + 1)) $T
        stopv
    else
        kill -0 "$VPID" 2>/dev/null && kill -9 "$VPID" 2>/dev/null # alive but never answered
        reapv
    fi
    if [ "$VRC" = 0 ]; then
        echo "k=$k: the cycle completed without reaching a $k-th hook: all $K hooks swept"
        rm -rf "$D"; break
    fi
    hook=$(hookof "$D/out.log")
    if [ "$VRC" != 77 ] || [ -z "$hook" ]; then
        echo "FAIL k=$k hook=${hook:-none}: the node exited with $VRC instead of 77 at a crash point"
        F=$((F + 1)); break
    fi
    K=$k
    mv "$D/out.log" "$D/crash.log"
    if ! startv; then
        kill -0 "$VPID" 2>/dev/null && kill -9 "$VPID" 2>/dev/null
        reapv
        echo "FAIL k=$k hook=$hook: restart after the crash failed (exit $VRC): $(grep -m1 -i 'error\|assert' "$D/out.log" | cut -c1-150)"
        F=$((F + 1)); break
    fi
    hr=$(cliv getblockcount); v=$(cliv verifychain 4 0)
    submit 1 $T
    best=$(cliv getbestblockhash); utxo=$(cliv gettxoutsetinfo | field hash_serialized)
    stopv
    if [ "$v" = true ] && [ "$best" = "$RBEST" ] && [ "$utxo" = "$RUTXO" ]; then
        echo "ok   k=$k hook=$hook: restarted at height $hr, chain verifies, same tip and UTXO set as R"
        rm -rf "$D"
    else
        echo "FAIL k=$k hook=$hook: restarted at height $hr, verifychain $v, best $best (R $RBEST), utxo $utxo (R $RUTXO); datadir kept in $D"
        F=$((F + 1)); break
    fi
done
clir stop >/dev/null 2>&1; wait "$RPID"; RPID=""
echo "chain-crash-sweep: $K hooks swept, $F fail"
[ "$F" = 0 ] || exit 1
[ "$K" -gt 0 ] || { echo "BROKEN: no crash point fired (hollow sweep)"; exit 2; }
exit 0
