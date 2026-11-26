B=$work/b; mkdir_node "$B"; copy_chain "$A" "$B"; dd=$B; extra="-mocktime=$(($(date +%s) + 259200))"   # born 3 days after every block, as a new wallet on mainnet: a rescan that skips blocks older than the wallet finds nothing
start || { echo "recovery-phrase: node B did not start"; exit 1; }; extra=""
#!/bin/sh
# TEST-ONLY. The 24-word recovery phrase, against real regtest daemons in throwaway datadirs:
#   1. a new wallet's phrase covers every address it makes (z_getphraseinfo not_covered is empty);
#   2. z_getrecoveryphrase gives 24 words whose fingerprint is the wallet's seed;
#   3. a second, fresh wallet given the same chain and z_restorefromphrase finds the funded
#      transparent and Sapling addresses and the same balances; bad phrases are refused by name;
#   4. after the restore the fresh wallet's own earlier address is reported as not covered, the
#      seed survives a restart and the key pool is not rebuilt again;
#   5. a kill -9 during a second restore leaves a wallet that starts with one of the two seeds;
#   6. with --peer-bin (a previous release, e.g. v2.1.2-beta13): a wallet made by the old node gets
#      phrase-derived new addresses on the new node, its old address is reported as not covered,
#      and the old node still opens a wallet that went through a restore.
# Every node runs in its own directory under --work; nothing outside it is touched.
#
# usage: sh qa/rpc-tests/wallet_recovery_phrase.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--port-base <n>] [--peer-bin <dir with an older zclassicd>]
set -u
bin=""; work=""; base=""; peer=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        --peer-bin) peer=$2; shift 2 ;;
        *) echo "recovery-phrase: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: wallet_recovery_phrase.sh --bin <dir> --work <dir> [--port-base <n>] [--peer-bin <dir>]" >&2; exit 2; }
. "$(dirname "$0")/jsonq_lib.sh"
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
. "$(dirname "$0")/../lib/isolation.sh"
iso_base base "$base" 16
[ -z "$(ls -A "$work")" ] || { echo "recovery-phrase: $work is not empty" >&2; exit 2; }

failures=0
ok() { echo "recovery-phrase: PASS $*"; }
bad() { echo "recovery-phrase: FAIL $*"; failures=$((failures + 1)); }
ck() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: got [$2] want [$3]"; fi; }

dd=""; daemon="$bin/zclassicd"; extra=""
cli() { "$bin/zclassic-cli" -regtest -datadir="$dd" -rpcclienttimeout=600 "$@"; }
mkdir_node() { # <dir>
    mkdir -p "$1/regtest"
    printf 'rpcuser=rp\nrpcpassword=rp%s\nrpcport=%s\n' "$$" "$((base + 1))" >"$1/zclassic.conf"
}
start() {
    "$daemon" -regtest -dnsseed=0 -debuglogfile=1 -nuparams=5ba81b19:1 -nuparams=76b809bb:1 -upnp=0 -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 \
        -rpcallowip=127.0.0.1 -printtoconsole=0 -showmetrics=0 -bootstrap=0 \
        -datadir="$dd" -port=$base -listen=0 -connect=0 $extra -daemon >/dev/null 2>&1 || return 1
    i=0
    while [ $i -lt 120 ]; do cli getblockcount >/dev/null 2>&1 && return 0; sleep 1; i=$((i + 1)); done
    return 1
}
stop() {
    cli stop >/dev/null 2>&1
    i=0
    while [ $i -lt 90 ] && [ -f "$dd/regtest/zclassicd.pid" ]; do sleep 1; i=$((i + 1)); done
}
cleanup() {
    for d in "$work"/*/; do
        [ -f "$d/regtest/zclassicd.pid" ] && kill -9 "$(cat "$d/regtest/zclassicd.pid")" 2>/dev/null
    done
}
trap cleanup EXIT INT TERM

wait_op() { # <opid>: prints success or the failure message
    i=0
    while [ $i -lt 600 ]; do
        s=$(cli z_getoperationstatus "[\"$1\"]" | jget '[0].status')
        case $s in
            success) echo success; return 0 ;;
            failed) cli z_getoperationstatus "[\"$1\"]" | jget '[0].error.message'; return 0 ;;
        esac
        sleep 1; i=$((i + 1))
    done
    echo timeout
}
has() { # <json array> <value>: yes/no
    if printf '%s' "$1" | tr -d '[] "' | tr ',' '\n' | grep -Fx -- "$2" >/dev/null; then echo yes; else echo no; fi
}
ncov() { cli z_getphraseinfo | jraw not_covered | tr -d " \n"; }   # compact: [] or ["addr",...]
errtext() { cli "$@" 2>&1 >/dev/null | tr '\n' ' '; }
copy_chain() { # <from datadir> <to datadir>: blocks and chain state, no wallet
    cp -R "$1/regtest/blocks" "$1/regtest/chainstate" "$2/regtest/"
}

# ---- 1-2. a new wallet and its phrase -------------------------------------------------------
A=$work/a; mkdir_node "$A"; dd=$A
start || { echo "recovery-phrase: node A did not start"; exit 1; }
info=$(cli z_getphraseinfo)
ck "new wallet: phrase available" "$(printf '%s' "$info" | jget available)" true
ck "new wallet: every address covered" "$(ncov)" "[]"
rp=$(cli z_getrecoveryphrase)
phrase=$(printf '%s' "$rp" | jget phrase)
fp=$(printf '%s' "$rp" | jget fingerprint)
ck "phrase has 24 words" "$(printf '%s\n' $phrase | wc -l | tr -d ' ')" 24
ck "phrase fingerprint is the wallet's" "$fp" "$(printf '%s' "$info" | jget fingerprint)"

cli generate 101 >/dev/null
t1=$(cli getnewaddress)
z1=$(cli z_getnewaddress sapling)
z2=$(cli z_getnewaddress sapling)
cli sendtoaddress "$t1" 2.5 >/dev/null
tz=$(cli getnewaddress)
cli sendtoaddress "$tz" 3.1 >/dev/null
cli generate 1 >/dev/null
op=$(cli z_sendmany "$tz" "[{\"address\":\"$z1\",\"amount\":3.0}]" 1 0.0001)
ck "fund the Sapling address" "$(wait_op "$op")" success
cli generate 1 >/dev/null
ck "funded wallet: every address still covered" "$(ncov)" "[]"
bal_t1=$(cli z_getbalance "$t1"); bal_z1=$(cli z_getbalance "$z1")
total=$(cli z_gettotalbalance | jget total)
ck "Sapling address funded" "$bal_z1" "3.00000000"
stop

# ---- 3. restore into a fresh wallet ---------------------------------------------------------
B=$work/b; mkdir_node "$B"; copy_chain "$A" "$B"; dd=$B; extra="-mocktime=$(($(date +%s) + 259200))"   # born 3 days after every block, like a new wallet on mainnet: a rescan that skips blocks older than the wallet finds nothing
start || { echo "recovery-phrase: node B did not start"; exit 1; }; extra=""
own=$(cli getaddressesbyaccount "" | jget '[0]')
fpb=$(cli z_getphraseinfo | jget fingerprint)
[ "$fpb" != "$fp" ] && ok "fresh wallet has its own seed" || bad "fresh wallet has the same seed"
last=${phrase##* }; first23=${phrase% *}
case $(errtext z_restorefromphrase "$first23 abandon") in *typo*) ok "wrong checksum refused" ;; *) [ "$last" = abandon ] && ok "checksum case skipped" || bad "wrong checksum not refused" ;; esac
case $(errtext z_restorefromphrase "$first23 notaword") in *"word 24"*) ok "unknown word refused by position" ;; *) bad "unknown word not named" ;; esac
case $(errtext z_restorefromphrase "$first23") in *"24 words"*) ok "short phrase refused" ;; *) bad "short phrase not refused" ;; esac
ck "refused phrases left the seed alone" "$(cli z_getphraseinfo | jget fingerprint)" "$fpb"

res=$(cli z_restorefromphrase "$phrase")
ck "restore: fingerprint" "$(printf '%s' "$res" | jget fingerprint)" "$fp"
ck "restore: found the transparent address" "$(has "$(printf '%s' "$res" | jraw transparent)" "$t1")" yes
ck "restore: found the Sapling address" "$(has "$(printf '%s' "$res" | jraw sapling)" "$z1")" yes
ck "restore: unfunded Sapling address is back too" "$(has "$(cli z_listaddresses)" "$z2")" yes
ck "restore: transparent balance" "$(cli z_getbalance "$t1")" "$bal_t1"
ck "restore: Sapling balance" "$(cli z_getbalance "$z1")" "$bal_z1"
ck "restore: total balance" "$(cli z_gettotalbalance | jget total)" "$total"

# ---- 4. coverage, restart, key pool --------------------------------------------------------
nc=$(ncov)
ck "the fresh wallet's earlier address is not covered" "$nc" "[\"$own\"]"
tnew=$(cli getnewaddress); znew=$(cli z_getnewaddress sapling)
ck "new addresses come from the phrase" "$(ncov)" "[\"$own\"]"
[ "$tnew" != "$t1" ] && [ "$znew" != "$z1" ] && [ "$znew" != "$z2" ] && ok "new addresses are not reused" || bad "a new address repeats an old one"
pool=$(cli getwalletinfo | jget keypoolsize)
refills=$(grep -c "did not come from the seed" "$B/regtest/debug.log")
stop
start || { echo "recovery-phrase: node B did not restart"; exit 1; }
ck "seed survives a restart" "$(cli z_getphraseinfo | jget fingerprint)" "$fp"
ck "key pool size survives a restart" "$(cli getwalletinfo | jget keypoolsize)" "$pool"
ck "key pool not rebuilt at restart" "$(grep -c "did not come from the seed" "$B/regtest/debug.log")" "$refills"
ck "balances survive a restart" "$(cli z_gettotalbalance | jget total)" "$total"

# ---- 5. kill -9 during a restore -----------------------------------------------------------
zoo="zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
cli z_restorefromphrase "$zoo" >/dev/null 2>&1 &
sleep 1
kill -9 "$(cat "$B/regtest/zclassicd.pid")" 2>/dev/null
wait 2>/dev/null
rm -f "$B/regtest/zclassicd.pid"
start || { bad "wallet does not start after a kill during restore"; exit 1; }
after=$(cli z_getphraseinfo | jget fingerprint)
if [ "$after" = "$fp" ]; then ok "killed restore: old seed kept"
else
    ck "killed restore: new seed complete" "$(cli z_getrecoveryphrase | jget phrase)" "$zoo"
fi
ck "killed restore: phrase still available" "$(cli z_getphraseinfo | jget available)" true
stop

# ---- 6. old wallets and the previous release -----------------------------------------------
if [ -n "$peer" ] && [ -x "$peer/zclassicd" ]; then
    C=$work/c; mkdir_node "$C"; copy_chain "$A" "$C"; dd=$C
    daemon="$peer/zclassicd"
    start || { echo "recovery-phrase: old node did not start"; exit 1; }
    old=$(cli getnewaddress)
    stop
    daemon="$bin/zclassicd"
    start || { echo "recovery-phrase: new node did not open the old wallet"; exit 1; }
    ck "old wallet: pool refilled from the seed once" "$(grep -c "did not come from the seed" "$C/regtest/debug.log")" 1
    nc=$(ncov)
    ck "old wallet: its old address is not covered" "$(has "$nc" "$old")" yes
    new=$(cli getnewaddress)
    ck "old wallet: a new address is covered" "$(has "$(ncov)" "$new")" no
    stop
    dd=$B; daemon="$peer/zclassicd"
    start && ok "old release opens a restored wallet" || bad "old release cannot open a restored wallet"
    stop
    daemon="$bin/zclassicd"
else
    echo "recovery-phrase: SKIP previous-release checks (no --peer-bin)"
fi

if [ $failures -eq 0 ]; then echo "recovery-phrase: all checks passed"; exit 0; fi
echo "recovery-phrase: $failures check(s) failed"; exit 1
