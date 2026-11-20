#!/bin/sh
# z_sendmany with an idempotency_key under kill -9: every key is sent while the node is killed at random
# moments (while the call is answered, while the operation builds, after BUILT, after the broadcast, and
# during start-up), sometimes with two concurrent calls under the same key, then retried with the same key
# until the journal says committed. Afterwards: exactly one payment per key reached the payee (each key pays a
# distinct amount), the journal holds one committed record per key, and the balances equal those of a copy of
# the wallet started with -rescan.
#
# usage: wallet_send_once_kill9.sh --bin <dir> --work <dir> [--peer-bin <dir>] [--keys N] [--kills-per-key M] [--base port]
# Output: <work>/results.txt, <work>/kills.txt. Exit status 0 when every check passed. POSIX sh; no Python.
BIN=""; WORK=""; PEER_BIN=""; KEYS=25; KPK=4; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;;
        --keys) KEYS=$2; shift 2 ;; --kills-per-key) KPK=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;;
        *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--peer-bin DIR] [--keys N] [--kills-per-key M] [--base port]" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$BIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; OBS_LOG=$WORK/obs.txt; KLOG=$WORK/kills.txt; : >"$RESULTS"; : >"$OBS_LOG"; : >"$KLOG"
iso_base BASE "${PORT_BASE:-}" 112
SCN_ID=1; SCN_LOG=$WORK/scn1.log; SD=$WORK/s1; : >"$SCN_LOG"; rm -rf "$SD"; mkdir -p "$SD"
trap 'stop_all' EXIT
R1="-connect=127.0.0.1:$((BASE + 1))"
EXTRA="-disablesafemode"
KILLS=0

rnd() { od -An -N2 -tu2 /dev/urandom | tr -d ' \n'; }
msleep() { sleep "$(awk -v m="$1" 'BEGIN { printf "%.3f", m / 1000 }')"; }
amount() { awk -v i="$1" 'BEGIN { printf "%.8f", 0.1 + i / 1000 }'; }
rec() { printf '[{"address":"%s","amount":%s}]' "$ZB" "$(amount "$1")"; }
key() { printf 'kill9-key-%s' "$1"; }
# jent <opid> <field> <default>: the field of the first journal entry with that opid; the default when there is none or it is null
jent() {
    local d n i v; d=$(cli 0 z_listsendjournal 2>/dev/null); n=$(printf '%s' "$d" | jlen) || { echo "$3"; return; }; i=0
    while [ "$i" -lt "$n" ]; do
        if [ "$(printf '%s' "$d" | jget "[$i].opid")" = "$1" ]; then
            v=$(printf '%s' "$d" | jget "[$i].$2"); case $v in ""|null) echo "$3" ;; *) echo "$v" ;; esac; return
        fi
        i=$((i + 1))
    done
    echo "$3"
}
jstate() { jent "$1" state none; }
quiet_start() { ( SCN_LOG=/dev/null start 0 "$BIN" $R1 $EXTRA ) >/dev/null 2>&1; }

# one kill cycle for key $1
cycle() {
    local i=$1 d two o1 o2 p c1 c2
    rm -f "$WORK/o1" "$WORK/o2"
    cli 0 z_sendmany "$ZS" "$(rec "$i")" 1 "$FEE" "$(key "$i")" >"$WORK/o1" 2>&1 &
    c1=$!; c2=""
    two=$(( $(rnd) % 3 ))
    if [ "$two" = 0 ]; then cli 0 z_sendmany "$ZS" "$(rec "$i")" 1 "$FEE" "$(key "$i")" >"$WORK/o2" 2>&1 & c2=$!; fi
    d=$(( $(rnd) % 4000 ))
    msleep "$d"
    # only the calls: the nodes are children of this shell too
    kill9 0; KILLS=$((KILLS + 1)); wait $c1 $c2
    o1=$(cat "$WORK/o1" 2>/dev/null); o2=$(cat "$WORK/o2" 2>/dev/null)
    case $o1 in *"different parameters"*) bad "key $i: same request refused as different: $o1" ;; esac
    case $o2 in *"different parameters"*) bad "key $i: same request refused as different (concurrent): $o2" ;; esac
    case "$o1|$o2" in opid-*"|"opid-*) ck "key $i: two concurrent calls, one operation" "$o2" "$o1" ;; esac
    # sometimes kill again during start-up (before the RPC server answers)
    if [ $(( $(rnd) % 4 )) = 0 ]; then
        old=$(cat "$SD/node0/pid")
        quiet_start &
        p=$!
        t=0; while [ "$(cat "$SD/node0/pid")" = "$old" ] && [ $t -lt 100 ]; do sleep 0.1; t=$((t + 1)); done
        msleep $(( $(rnd) % 3000 ))
        kill9 0; KILLS=$((KILLS + 1)); wait "$p" 2>/dev/null
        echo "key $i: killed after ${d}ms (two=$two), then again during start-up" >>"$KLOG"
    else
        echo "key $i: killed after ${d}ms (two=$two)" >>"$KLOG"
    fi
    start 0 "$BIN" $R1 $EXTRA || return 1
    sync_to 0
    echo "   after restart: journal [$(cli 0 z_listsendjournal | jjoin state)]" >>"$KLOG"
}

# A kill between the BUILT record and the wallet write leaves a record whose transaction is nowhere
# (the journal cannot tell that from one broadcast and lost with the wallet write): by design the key is
# held, outcome_unknown, until the tip is more than SENDONCE_EXPIRY_MARGIN (100) blocks past the expiry
# height, then released. Mine to that point, which is the recovery path the journal documents.
release_unknown() {
    local i=$1 op=$2 eh h need
    eh=$(jent "$op" expiryheight 0)
    h=$(cli 0 getblockcount); need=$((eh + 101 - h))
    echo "key $i: outcome_unknown (BUILT, expiry $eh, tip $h): mining $need blocks past expiry + margin" >>"$KLOG"
    [ "$need" -gt 0 ] && mine "$need"
}

# send key $1 to completion with retries (no kills): prints the txid
settle() {
    local i=$1 n=0 op s t txid stuck=0
    while [ $n -lt 30 ]; do
        n=$((n + 1))
        op=$(cli 0 z_sendmany "$ZS" "$(rec "$i")" 1 "$FEE" "$(key "$i")" 2>&1)
        case $op in
            opid-*) ;;
            *"different parameters"*) bad "key $i: settle: refused as different: $op"; return 1 ;;
            *) sleep 2; continue ;;
        esac
        t=0
        while [ $t -lt 180 ]; do
            s=$(jstate "$op")
            case $s in
                committed) txid=$(jent "$op" txid null); echo "$txid"; return 0 ;;
                none|released|expired) break ;;     # nothing was sent under this operation: call again
                outcome_unknown) cli 0 resendwallettransactions >/dev/null 2>&1; stuck=$((stuck + 1)); [ $stuck -ge 2 ] && release_unknown "$i" "$op"; break ;;
            esac
            t=$((t + 1)); sleep 1
        done
    done
    bad "key $i: did not settle"; return 1
}

say "== kill -9 around keyed sends: $KEYS keys, $KPK kills each (plus start-up kills)"
setup2 $EXTRA || exit 1
ZS=$(cli 0 z_getnewaddress sapling); give_z 0 "$ZS" 30
ZB=$(cli 1 z_getnewaddress sapling)
ck "funded" "$(zbal 0 "$ZS")" 30.00000000
spent=0
i=1
while [ $i -le "$KEYS" ]; do
    k=1
    while [ $k -le "$KPK" ]; do cycle "$i" || break; k=$((k + 1)); done
    txid=$(settle "$i") || { bad "key $i: settle failed"; i=$((i + 1)); continue; }
    cli 0 resendwallettransactions >/dev/null 2>&1
    wait_mempool 1 "$txid"
    mine 1
    spent=$(add "$spent" "$(amount "$i")" "$FEE")
    say "  key $i settled: $txid (kills so far $KILLS)"
    i=$((i + 1))
done
cli 0 resendwallettransactions >/dev/null 2>&1; mine 2

say "== checks"
ck "at least 100 kills" "$([ "$KILLS" -ge 100 ] && echo yes)" yes
obs kills "$KILLS"
got=$(cli 1 z_listreceivedbyaddress "$ZB" 1)
ck "the payee received exactly one note per key" "$(echo "$got" | jlen)" "$KEYS"
sats=$(echo "$got" | jsatlist)
i=1; dup=0; miss=0
while [ $i -le "$KEYS" ]; do
    want=$(awk -v a="$(amount "$i")" 'BEGIN { printf "%d", a * 100000000 + 0.5 }')
    c=$(printf '%s\n' "$sats" | grep -cx "$want")
    [ "$c" = 1 ] || { [ "$c" -gt 1 ] && dup=$((dup + 1)) || miss=$((miss + 1)); say "  key $i: $c payments"; }
    i=$((i + 1))
done
ck "no key paid twice" "$dup" 0
ck "no key left unpaid" "$miss" 0
ck "journal: one committed record per key" "$(cli 0 z_listsendjournal | jpick state | LC_ALL=C sort -u | tr '\n' ',' | sed 's/,$//') $(cli 0 z_listsendjournal | jlen)" "committed $KEYS"
want=$(add 30 -"$spent")
ck "ZS balance: 30 minus one payment and one fee per key" "$(zbal 0 "$ZS")" "$want"
ref0=$(cli 0 z_gettotalbalance 1 | jarr transparent private total)
zs0=$(zbal 0 "$ZS"); nt0=$(cli 0 listtransactions "*" 10000 | jlen)
stop 0
rm -rf "$SD/node2"; cp -a "$SD/node0" "$SD/node2"; rm -f "$SD/node2/regtest/.lock"
start 2 "$BIN" -connect=0 -listen=0 -rescan $EXTRA || exit 1
ck "rescanned copy: same total balances" "$(cli 2 z_gettotalbalance 1 | jarr transparent private total)" "$ref0"
ck "rescanned copy: same ZS balance" "$(zbal 2 "$ZS")" "$zs0"
ck "rescanned copy: same number of wallet transactions" "$(cli 2 listtransactions "*" 10000 | jlen)" "$nt0"
stop 2

np=$(grep -c '^PASS' "$SCN_LOG"); nf=$(grep -c '^FAIL' "$SCN_LOG")
st=PASS; [ "$nf" = 0 ] && [ "$np" -gt 0 ] || st=FAIL
echo "1|kill -9 around keyed sends ($KEYS keys, $KILLS kills)|$st|$np pass $nf fail" >>"$RESULTS"
say; cat "$RESULTS"
! grep -q "|FAIL|" "$RESULTS"
