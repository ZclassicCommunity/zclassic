#!/bin/sh
# -mempoolmaxbytes on regtest: the minimum value is accepted, smaller values are
# refused at start-up, a full mempool makes sendtoaddress fail with "mempool full"
# (and leaves the wallet unchanged), and a mined block makes room again.
#
# usage: mempool_cap.sh --bin <dir with zclassicd and zclassic-cli> --work <dir> [--base port]
# Output: PASS/FAIL lines on stdout and <work>/results.txt; exit 0 only if nothing failed.
# Needs jq. POSIX sh, temp datadirs under --work, stops the daemon it starts.
BIN=""; WORK=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;;
        *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
iso_base BASE "${PORT_BASE:-}" 112
SD=$WORK/mempool_cap; rm -rf "$SD"; mkdir -p "$SD"
SCN_ID=mempool_cap; SCN_LOG=$WORK/mempool_cap.log; OBS_LOG=$WORK/obs.txt; : >"$SCN_LOG"; : >"$OBS_LOG"
trap 'stop_all' EXIT

CAP=5000000

# 1. values below the minimum are refused at start-up, 0 is not "unlimited"
for v in 0 4999999 -1; do
    d=$SD/bad$v; mkdir -p "$d"
    out=$("$BIN/zclassicd" -datadir="$d" -regtest -daemon=0 -listen=0 -dnsseed=0 -discover=0 -mempoolmaxbytes=$v 2>&1); rc=$?
    if [ $rc -ne 0 ] && printf '%s' "$out" | grep -q "mempoolmaxbytes.*too small"; then pass "start-up refuses -mempoolmaxbytes=$v"
    else bad "-mempoolmaxbytes=$v: rc=$rc out=[$(printf %s "$out" | tr '\n' ' ' | cut -c1-160)]"; fi
done
"$BIN/zclassicd" -help 2>&1 | grep -q -- "-mempoolmaxbytes=<n>" && pass "-help documents -mempoolmaxbytes" || bad "-help lacks -mempoolmaxbytes"

# 2. the minimum is accepted; fund the wallet
start 0 "$BIN" -mempoolmaxbytes=$CAP || { echo "FAIL cannot start"; exit 1; }
cli 0 generate 220 >/dev/null
ck "wallet funded" "$(cli 0 getbalance | awk '{ print ($1 > 100) ? "yes" : "no" }')" yes

# 3. a pool of many-output transactions (about 85 KB each) up to the cap
ADDRS=$SD/addrs.json
i=0; : >"$SD/addrs.txt"
while [ $i -lt 2500 ]; do cli 0 getnewaddress >>"$SD/addrs.txt"; i=$((i + 1)); done
jq -R -s -c 'split("\n") | map(select(length > 0)) | map({(.): 0.0005}) | add' "$SD/addrs.txt" >"$ADDRS"
BIG=$(cat "$ADDRS")
n=0; err=""
while [ $n -lt 150 ]; do
    if ! out=$(cli 0 sendmany "" "$BIG" 2>&1); then err=$out; break; fi
    n=$((n + 1))
done
obs big_txs_accepted "$n"
obs big_refusal "$(printf %s "$err" | cut -c1-200)"
case $err in *"mempool full"*) pass "large transaction refused with mempool full after $n accepted" ;; *) bad "large transaction loop ended after $n with [$(printf %s "$err" | cut -c1-160)]" ;; esac
# the pool is nearly full now: halve the output count until even a one-output
# transaction no longer fits, then sendtoaddress must be refused
k=1250; m=0; serr=""
while [ $k -ge 1 ]; do
    sub=$(jq -c --argjson k $k 'to_entries | .[:$k] | from_entries' "$ADDRS")
    while out=$(cli 0 sendmany "" "$sub" 2>&1); do m=$((m + 1)); [ $m -lt 400 ] || break; done
    k=$((k / 2))
done
serr=$(cli 0 sendtoaddress "$(sed -n 1p "$SD/addrs.txt")" 0.01 2>&1) && serr=""
obs small_txs_accepted "$m"
case $serr in *"mempool full"*) pass "sendtoaddress fails with the clear error: $(printf %s "$serr" | cut -c1-200)" ;; *) bad "sendtoaddress error [$(printf %s "$serr" | cut -c1-200)] lacks 'mempool full'" ;; esac
case $serr in *mempoolmaxbytes*) pass "error names -mempoolmaxbytes" ;; *) bad "error does not name -mempoolmaxbytes" ;; esac
bytes=$(cli 0 getmempoolinfo | jget bytes)
[ "$bytes" -le $CAP ] && pass "mempool bytes $bytes <= cap $CAP" || bad "mempool bytes $bytes exceeds cap $CAP"
cnt=$(cli 0 getmempoolinfo | jget size)

# a refused send leaves the mempool and wallet untouched (nothing evicted, nothing recorded)
tx0=$(cli 0 listtransactions "*" 1000000 | jlen)
cli 0 sendtoaddress "$(sed -n 2p "$SD/addrs.txt")" 0.01 >/dev/null 2>&1 && bad "send unexpectedly succeeded while full"
ck "mempool size unchanged by a refused send" "$(cli 0 getmempoolinfo | jget size)" "$cnt"
ck "wallet transaction list unchanged by a refused send" "$(cli 0 listtransactions "*" 1000000 | jlen)" "$tx0"
alive "while full"

# 4. a block frees the pool and sending works again
cli 0 generate 1 >/dev/null
after=$(cli 0 getmempoolinfo | jget size)
# a block holds at most 2 MB, so a 5 MB pool drains over several blocks: it must shrink
[ "$after" -lt "$cnt" ] && pass "block mined: mempool shrank from $cnt to $after transactions" || bad "mempool did not shrink after a block ($cnt -> $after)"
if t=$(cli 0 sendtoaddress "$(sed -n 3p "$SD/addrs.txt")" 0.01 2>&1) && [ ${#t} -eq 64 ]; then pass "sendtoaddress works again after a block"; else bad "send after block failed: [$t]"; fi

# 5. a reorg returns block transactions to the pool even past the cap (they were already
# in a block, so the cap must not drop them): refill the pool, then disconnect the block
blk=$(cli 0 getbestblockhash)
f=0; while cli 0 sendmany "" "$BIG" >/dev/null 2>&1; do f=$((f + 1)); [ $f -lt 150 ] || break; done
before=$(cli 0 getmempoolinfo | jget bytes)
cli 0 invalidateblock "$blk" >/dev/null 2>&1
back=$(cli 0 getmempoolinfo | jget bytes)
obs reorg_bytes "$before -> $back"
[ "$back" -gt "$CAP" ] && pass "reorg keeps resurrected transactions past the cap ($before -> $back > $CAP)" || bad "reorg bytes $before -> $back not above cap $CAP"
alive "after reorg"
stop 0

np=$(grep -c '^PASS' "$SCN_LOG"); nf=$(grep -c '^FAIL' "$SCN_LOG")
echo "mempool_cap|$np pass $nf fail" | tee "$WORK/results.txt"
[ "$nf" = 0 ] && [ "$np" -gt 0 ]
